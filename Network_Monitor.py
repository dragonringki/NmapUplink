import json
import logging
import os
import queue
import re
import subprocess
import threading
import time
import webbrowser
import http.server
import socketserver
from urllib.parse import urlparse, parse_qs
from datetime import datetime
from typing import Dict, List, Tuple, Any

import xml.etree.ElementTree as ET

# ----------------------- CONFIG -----------------------
INVENTORY_FILE = 'local_inventory.json'
LOG_FILE = 'network_events.log'
HTML_FILE = 'network_dashboard.html'
LIGHTWEIGHT_SCAN_INTERVAL = 60
AGGRESSIVE_SCAN_TIMEOUT = 600
NETWORK_CIDR = '192.168.68.0/24'
NMAP_TEMP_OUTPUT_BASE = '/tmp/nmap_scan_'
WEB_SERVER_PORT = 8888
MAX_PARALLEL_SCANS = 3

# ----------------------- STATE & QUEUES -----------------------
# Priority Queue stores tuples: (priority_int, mac_addr, ip_addr)
# Priority: 1=Manual/Critical, 3=Routine
deep_scan_queue = queue.PriorityQueue()
scanned_macs_session = set()

deep_scan_active = threading.Event()
deep_scan_active.set()
active_scans_counter = 0
active_scans_lock = threading.Lock()

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='\%Y-\%m-\%d \%H:\%M:\%S'
)

# ----------------------- INIT -----------------------
def init_files():
    if not os.path.exists(INVENTORY_FILE):
        with open(INVENTORY_FILE, 'w', encoding='utf-8') as f:
            f.write('[]')
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'w', encoding='utf-8') as f:
            f.write(f"--- Network Guardian Started {datetime.now()} ---\n")
    if not os.path.exists(HTML_FILE):
        with open(HTML_FILE, 'w', encoding='utf-8') as f:
            f.write("""
            <html>
            <head>
                <meta http-equiv="refresh" content="3">
                <script src="https://cdn.tailwindcss.com"></script>
                <style>body{font-family:sans-serif;text-align:center;padding:50px;background:#f8fafc;color:#334155;}</style>
            </head>
            <body>
                <h1 class="text-3xl font-bold text-slate-800">🛡️ Network Guardian Initializing...</h1>
                <p class="mt-4 text-slate-600">Please wait while the first scan completes. This page will refresh.</p>
            </body>
            </html>
            """)

# ----------------------- IO -----------------------
def load_inventory() -> List[Dict]:
    try:
        if os.path.exists(INVENTORY_FILE):
            with open(INVENTORY_FILE, encoding='utf-8') as f:
                return normalize_inventory(json.load(f))
    except Exception as exc:
        logging.warning("Failed to load inventory: %s", exc)
    return []

def save_inventory(inv: List[Dict]):
    normalized = normalize_inventory(inv)
    with open(INVENTORY_FILE, 'w', encoding='utf-8') as f:
        json.dump(normalized, f, indent=4)

def clean_mac(mac: str | None) -> str | None:
    if not mac: return None
    mac = mac.strip().upper().replace('-', ':')
    if re.fullmatch(r'([0-9A-F]{2}:){5}[0-9A-F]{2}', mac):
        return mac
    return None

def normalize_inventory(inv: List[Dict]) -> List[Dict]:
    deduped: Dict[str, Dict] = {}
    for d in inv:
        mac = clean_mac(d.get('macAddress'))
        if not mac: continue
        if mac not in deduped or d.get('lastSeen', '') > deduped[mac].get('lastSeen', ''):
            deduped[mac] = d.copy()
    return list(deduped.values())

# ----------------------- VENDOR -----------------------
def get_vendor(mac: str):
    oui = mac.replace(':', '').upper()[:6]
    vendors = {
        'D4909C': ('Apple', 'fa-apple'), '002500': ('Apple', 'fa-apple'),
        '306023': ('Samsung', 'fa-android'), 'A8BB50': ('Google', 'fa-google'),
        'B827EB': ('Raspberry Pi', 'fa-microchip'), 'DCA632': ('Raspberry Pi', 'fa-microchip'),
        '005056': ('VMware', 'fa-server'), 'A45E60': ('Ubiquiti', 'fa-broadcast-tower'),
        'F4F5E8': ('Google', 'fa-google'),
    }
    return vendors.get(oui, ('Unknown', 'fa-question-circle'))

# ----------------------- RUN COMMAND -----------------------
def run_cmd(cmd: List[str], timeout: int) -> str:
    import shutil
    if (cmd[0] == "nmap" or cmd[0] == shutil.which("nmap")) and cmd[0] != "sudo":
        if os.geteuid() != 0:
            cmd = ["sudo"] + cmd
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=True)
        return result.stdout
    except subprocess.TimeoutExpired:
        logging.warning("Command timed out: %s", ' '.join(cmd))
    except Exception as exc:
        logging.error("Command error for %s: %s", cmd, exc)
    return ""

# ----------------------- SCANS -----------------------
def fast_scan() -> str:
    return run_cmd(['nmap', '-sn', '-T4', '--max-retries', '1', NETWORK_CIDR], 30)

def deep_scan(ip: str) -> str:
    temp_file = f"{NMAP_TEMP_OUTPUT_BASE}{threading.get_ident()}.xml"
    run_cmd(['nmap', '-sV', '--script=vulners', '-p-', ip, '-oX', temp_file], AGGRESSIVE_SCAN_TIMEOUT)
    if os.path.exists(temp_file):
        with open(temp_file, encoding='utf-8') as f:
            data = f.read()
        os.remove(temp_file)
        return data
    return ""

# ----------------------- PARSING -----------------------
def parse_fast(output: str) -> List[Dict]:
    devices = []
    last_ip = None
    for line in output.splitlines():
        ip_match = re.search(r'Nmap scan report for (?:.+ )?(\d+\.\d+\.\d+\.\d+)', line)
        if ip_match: last_ip = ip_match.group(1)
        mac_match = re.search(r'MAC Address: ([0-9A-Fa-f:]{17})', line)
        if mac_match and last_ip:
            mac = clean_mac(mac_match.group(1))
            if not mac: continue
            name, icon = get_vendor(mac)
            devices.append({
                'ipAddress': last_ip, 'macAddress': mac, 'deviceName': name,
                'vendorIcon': icon, 'status': 'Online', 'ports': 'Unknown',
                'os': 'Unknown', 'vulnerabilities': 'None',
                'lastSeen': datetime.now().isoformat(), 'simulatedConcern': 'Low'
            })
            last_ip = None
    return devices

def parse_deep(xml: str) -> Tuple[str, str, str]:
    if not xml: return "Scan Failed", "Unknown", "Error"
    try:
        root = ET.fromstring(xml)
        os_elem = root.find(".//osmatch")
        os_name = os_elem.get('name') if os_elem is not None else "Unknown"
        ports, vulns = [], []
        for port in root.findall(".//port[@portid]"):
            if port.find('state').get('state') == 'open':
                pid = port.get('portid')
                svc = port.find('service').get('name') or 'unknown'
                ports.append(f"{pid}/{svc}")
                for script in port.findall("script[@id='vulners']"):
                    for line in script.get('output', '').splitlines():
                        if 'CVE-' in line or 'EDB-' in line:
                            vulns.append(line.strip().split()[0])
        return ', '.join(ports) or "None", os_name, ', '.join(sorted(set(vulns))) or "None"
    except Exception:
        return "Parse Error", "Unknown", "Error"

# ----------------------- LOGIC & QUEUE -----------------------
def get_risk(d: Dict) -> str:
    if d['vulnerabilities'] not in ('None', 'Error', 'Pending…'):
        return f"CRITICAL ({d['vulnerabilities'].split(',', 1)[0]})"
    if d['ports'] not in ('Unknown', 'None', 'Pending…') and not d['ports'].startswith('No open'):
        return "High (Open Ports)"
    if d['ipAddress'].endswith(('.1', '.254')): return "High (Gateway)"
    return "Low"

def update_inventory(new: List[Dict], old: List[Dict]) -> List[Dict]:
    inv = {clean_mac(d['macAddress']): d.copy() for d in old if clean_mac(d.get('macAddress'))}
    now = datetime.now().isoformat()
    
    for d in new:
        mac = clean_mac(d['macAddress'])
        if not mac: continue
        
        if mac in inv:
            if inv[mac]['status'] == 'Offline':
                logging.info(f"Reconnected: {d['deviceName']} ({mac})")
            
            d['ports'] = inv[mac].get('ports', 'Unknown')
            d['os'] = inv[mac].get('os', 'Unknown')
            d['vulnerabilities'] = inv[mac].get('vulnerabilities', 'None')
            
            if inv[mac]['status'] in ('Under Aggressive Review', 'Queued for Deep Scan'):
                d['status'] = inv[mac]['status']
            else:
                d['status'] = 'Online'
        else:
            logging.info(f"New Device: {d['deviceName']} ({mac})")
            d['status'] = 'New Device'
            d['ports'] = d['os'] = d['vulnerabilities'] = 'Pending…'
            
            deep_scan_queue.put((3, mac, d['ipAddress']))
            d['status'] = 'Queued for Deep Scan'

        d['lastSeen'] = now
        d['simulatedConcern'] = get_risk(d)
        inv[mac] = d

    current_macs = {clean_mac(d['macAddress']) for d in new if clean_mac(d.get('macAddress'))}
    for mac in inv:
        if mac not in current_macs and inv[mac]['status'] != 'Under Aggressive Review':
            inv[mac]['status'] = 'Offline'

    return list(inv.values())

# ----------------------- SERVER -----------------------
class RequestHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args): pass

    def do_GET(self):
        if self.path == '/' or self.path == '/index.html':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            with open(HTML_FILE, 'rb') as f:
                self.wfile.write(f.read())
            return
        
        if self.path == '/api/status':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            status = {
                "paused": not deep_scan_active.is_set(),
                "queue_size": deep_scan_queue.qsize(),
                "active_scans": active_scans_counter
            }
            self.wfile.write(json.dumps(status).encode())
            return

        if self.path == '/api/toggle_pause':
            if deep_scan_active.is_set():
                deep_scan_active.clear()
                logging.info("Deep scanning PAUSED by user")
            else:
                deep_scan_active.set()
                logging.info("Deep scanning RESUMED by user")
            self.send_response(200)
            self.end_headers()
            return

        if self.path.startswith('/api/trigger'):
            query = parse_qs(urlparse(self.path).query)
            mac = query.get('mac', [None])[0]
            ip = query.get('ip', [None])[0]
            if mac and ip:
                logging.info(f"Manual Deep Scan triggered for {mac}")
                deep_scan_queue.put((1, mac, ip))
                
                inv = load_inventory()
                for d in inv:
                    if d.get('macAddress') == mac:
                        d['status'] = 'Queued for Deep Scan'
                        d['ports'] = 'Pending (Manual)...'
                save_inventory(inv)
                render_html(inv)
                
            self.send_response(200)
            self.end_headers()
            return

def start_server():
    try:
        with socketserver.TCPServer(("", WEB_SERVER_PORT), RequestHandler) as httpd:
            print(f"Web Server running at http://localhost:{WEB_SERVER_PORT}")
            httpd.serve_forever()
    except OSError as e:
        print(f"Error starting web server on port {WEB_SERVER_PORT}: {e}")
        print("Try changing WEB_SERVER_PORT in the config section.")


# ----------------------- HTML GEN -----------------------
def render_html(inventory: List[Dict]):
    inventory = normalize_inventory(inventory)
    total = len(inventory)
    online = sum(1 for d in inventory if d['status'] != 'Offline')
    critical = sum(1 for d in inventory if 'CRITICAL' in d['simulatedConcern'])
    
    rows = ""
    for d in inventory:
        row_class = "hover:bg-indigo-50 transition border-b border-gray-100"
        badge_class = "bg-green-100 text-green-800"
        
        if 'CRITICAL' in d['simulatedConcern']:
            row_class += " bg-red-50 border-l-4 border-red-500"
            badge_class = "bg-red-600 text-white font-bold"
        elif 'High' in d['simulatedConcern']:
            row_class += " bg-orange-50 border-l-4 border-orange-400"
            badge_class = "bg-orange-100 text-orange-800"
            
        if d['status'] == 'Offline': 
            row_class += " opacity-60 bg-slate-50"
            badge_class = "bg-gray-200 text-gray-600"
        if 'Scanning' in d['status'] or 'Review' in d['status'] or 'Queued' in d['status']:
            badge_class = "bg-blue-100 text-blue-800 animate-pulse"

        json_data = json.dumps(d).replace('"', '&quot;')
        
        rows += f'''
        <tr class="{row_class}" data-device="{json_data}">
            <td class="px-4 py-3 font-medium text-slate-800">{d['ipAddress']}</td>
            <td class="px-4 py-3 text-slate-500 font-mono text-xs hidden sm:table-cell">{d['macAddress']}</td>
            <td class="px-4 py-3 flex items-center gap-2">
                <i class="fas {d.get('vendorIcon', 'fa-question')} text-indigo-500"></i> {d['deviceName']}
            </td>
            <td class="px-4 py-3"><span class="px-2 py-1 rounded-full text-xs {badge_class}">{d['status']}</span></td>
            <td class="px-4 py-3"><span class="px-2 py-1 rounded-full text-xs {badge_class}">{d['simulatedConcern']}</span></td>
            <td class="px-4 py-3 text-xs hidden lg:table-cell text-slate-600">{d['os']}</td>
            <td class="px-4 py-3 text-right">
                <button onclick="openModal(this)" class="text-indigo-600 hover:text-indigo-900 font-medium text-sm">Details</button>
            </td>
        </tr>'''

    empty_state_html = (
        '<div class="p-6 text-center text-slate-500">No devices found yet. Performing initial scan...</div>' 
        if total == 0 else ''
    )

    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Guardian</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        ::-webkit-scrollbar {{ width: 8px; }}
        ::-webkit-scrollbar-track {{ background: #f1f5f9; }}
        ::-webkit-scrollbar-thumb {{ background: #94a3b8; border-radius: 4px; }}
        ::-webkit-scrollbar-thumb:hover {{ background: #64748b; }}
    </style>
</head>
<body class="bg-slate-100 min-h-screen p-4 md:p-6 font-sans text-slate-800">
    <div class="max-w-7xl mx-auto space-y-6">
        <!-- Header -->
        <div class="bg-white rounded-xl shadow-lg p-6 flex flex-col md:flex-row justify-between items-center gap-4">
            <div>
                <h1 class="text-3xl font-extrabold text-slate-900 flex items-center gap-3">
                    <i class="fas fa-shield-halved text-indigo-600"></i> Network Guardian
                </h1>
                <p class="text-slate-500 text-sm mt-1">Monitoring {NETWORK_CIDR} • {total} Devices</p>
            </div>
            <div class="flex items-center gap-4">
                <button id="pauseBtn" onclick="togglePause()" class="px-4 py-2 rounded-lg font-semibold text-white bg-indigo-600 hover:bg-indigo-700 transition shadow-md">
                    <i class="fas fa-pause"></i> Pause Scans
                </button>
                <div class="bg-slate-100 px-4 py-2 rounded-lg text-sm font-mono text-slate-600 border border-slate-200">
                    Queue: <span id="queueCount" class="font-bold text-indigo-600">0</span> | Active: <span id="activeCount" class="font-bold text-indigo-600">0</span>
                </div>
            </div>
        </div>

        <!-- Stats -->
        <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div class="bg-white p-4 rounded-xl shadow-lg border-l-4 border-emerald-500">
                <div class="text-slate-500 text-xs uppercase font-bold">Total Devices</div>
                <div class="text-2xl font-bold text-slate-800">{total}</div>
            </div>
            <div class="bg-white p-4 rounded-xl shadow-lg border-l-4 border-emerald-500">
                <div class="text-slate-500 text-xs uppercase font-bold">Online</div>
                <div class="text-2xl font-bold text-emerald-600">{online}</div>
            </div>
            <div class="bg-white p-4 rounded-xl shadow-lg border-l-4 border-red-500">
                <div class="text-slate-500 text-xs uppercase font-bold">Critical Risk</div>
                <div class="text-2xl font-bold text-red-600">{critical}</div>
            </div>
            <div class="bg-white p-4 rounded-xl shadow-lg border-l-4 border-yellow-500">
                <div class="text-slate-500 text-xs uppercase font-bold">Next Scan In</div>
                <div id="countdown" class="text-2xl font-bold text-yellow-600"></div>
            </div>
        </div>

        <!-- Table -->
        <div class="bg-white rounded-xl shadow-lg overflow-x-auto">
            <table class="w-full text-sm text-left">
                <thead class="bg-slate-50 text-slate-500 uppercase font-semibold border-b border-slate-200">
                    <tr>
                        <th class="px-4 py-3 min-w-[120px]">IP</th>
                        <th class="px-4 py-3 hidden sm:table-cell min-w-[150px]">MAC</th>
                        <th class="px-4 py-3 min-w-[150px]">Device</th>
                        <th class="px-4 py-3 min-w-[120px]">Status</th>
                        <th class="px-4 py-3 min-w-[120px]">Risk</th>
                        <th class="px-4 py-3 hidden lg:table-cell min-w-[100px]">OS</th>
                        <th class="px-4 py-3 text-right min-w-[80px]">Actions</th>
                    </tr>
                </thead>
                <tbody class="divide-y divide-slate-100">{rows}</tbody>
            </table>
            <!-- Empty state -->
            {empty_state_html}
        </div>
    </div>

    <!-- Modal -->
    <div id="modal" class="fixed inset-0 bg-black/50 hidden items-center justify-center p-4 z-50 transition-opacity duration-300 ease-out opacity-0" onclick="if(event.target.id === 'modal') closeModal()">
        <div class="bg-white rounded-xl shadow-2xl max-w-2xl w-full overflow-hidden transform transition-transform duration-300 ease-out scale-95">
            <div class="p-6 border-b flex justify-between items-center bg-slate-50">
                <h2 id="m-title" class="text-xl font-bold flex items-center gap-2 text-slate-800"></h2>
                <button onclick="closeModal()" class="text-slate-400 hover:text-slate-600"><i class="fas fa-times text-xl"></i></button>
            </div>
            <div class="p-6 space-y-4 max-h-[70vh] overflow-y-auto">
                <div class="grid grid-cols-2 gap-4 text-sm">
                    <div><span class="text-slate-500 block">IP Address</span><code id="m-ip" class="font-mono bg-slate-100 px-1 rounded text-slate-700"></code></div>
                    <div><span class="text-slate-500 block">MAC Address</span><code id="m-mac" class="font-mono bg-slate-100 px-1 rounded text-slate-700"></code></div>
                    <div><span class="text-slate-500 block">Last Seen</span><span id="m-seen" class="text-slate-700"></span></div>
                    <div><span class="text-slate-500 block">Status</span><span id="m-status" class="text-slate-700 font-medium"></span></div>
                </div>
                <div>
                    <h3 class="font-bold text-slate-700 mb-2">Open Ports</h3>
                    <pre id="m-ports" class="bg-slate-900 text-emerald-400 p-3 rounded-lg text-xs overflow-x-auto font-mono whitespace-pre-wrap max-h-32"></pre>
                </div>
                <div>
                    <h3 class="font-bold text-slate-700 mb-2">Vulnerabilities</h3>
                    <pre id="m-vulns" class="bg-red-50 text-red-700 p-3 rounded-lg text-xs overflow-x-auto border border-red-100 whitespace-pre-wrap max-h-32"></pre>
                </div>
                <button id="m-scanbtn" onclick="triggerScan()" class="w-full py-3 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg font-bold shadow-lg transition flex justify-center items-center gap-2">
                    <i class="fas fa-bolt"></i> Trigger High Priority Deep Scan
                </button>
                <div id="scan-message" class="hidden text-center p-2 text-sm text-emerald-700 bg-emerald-100 rounded-lg"></div>
            </div>
        </div>
    </div>

    <script>
        let currentDevice = null;
        const scanInterval = {LIGHTWEIGHT_SCAN_INTERVAL * 1000};
        let countdown = {LIGHTWEIGHT_SCAN_INTERVAL};

        function updateCountdown() {{
            countdown--;
            document.getElementById('countdown').textContent = countdown + 's';
            if (countdown <= 0) {{
                countdown = {LIGHTWEIGHT_SCAN_INTERVAL};
                setTimeout(() => window.location.reload(), 1000); 
            }}
        }}

        function refreshStatus() {{
            fetch('/api/status').then(r => r.json()).then(data => {{
                document.getElementById('queueCount').textContent = data.queue_size;
                document.getElementById('activeCount').textContent = data.active_scans;
                const btn = document.getElementById('pauseBtn');
                if (data.paused) {{
                    btn.innerHTML = '<i class="fas fa-play"></i> Resume Scans';
                    btn.classList.add('bg-emerald-600', 'hover:bg-emerald-700'); btn.classList.remove('bg-indigo-600', 'hover:bg-indigo-700');
                }} else {{
                    btn.innerHTML = '<i class="fas fa-pause"></i> Pause Scans';
                    btn.classList.add('bg-indigo-600', 'hover:bg-indigo-700'); btn.classList.remove('bg-emerald-600', 'hover:bg-emerald-700');
                }}
            }});
        }}
        
        setInterval(refreshStatus, 2000);
        setInterval(updateCountdown, 1000);
        
        function togglePause() {{ fetch('/api/toggle_pause').then(refreshStatus); }}

        function triggerScan() {{
            if(!currentDevice) return;
            document.getElementById('m-scanbtn').disabled = true;
            document.getElementById('m-scanbtn').innerHTML = '<i class="fas fa-circle-notch fa-spin"></i> Queuing...';
            
            fetch(`/api/trigger?mac=${{currentDevice.macAddress}}&ip=${{currentDevice.ipAddress}}`)
                .then(() => {{
                    const msgEl = document.getElementById('scan-message');
                    msgEl.textContent = 'Priority Deep Scan Queued! Status will update shortly.';
                    msgEl.classList.remove('hidden');
                    
                    setTimeout(() => {{
                        closeModal();
                        window.location.reload(); 
                    }}, 1500);
                }})
                .catch(() => {{
                    const msgEl = document.getElementById('scan-message');
                    msgEl.textContent = 'Error queuing scan. See console for details.';
                    msgEl.classList.remove('hidden');
                }});
        }}

        function openModal(btn) {{
            const d = JSON.parse(btn.closest('tr').dataset.device.replace(/&quot;/g, '"'));
            currentDevice = d;
            
            // Populate Modal
            document.getElementById('m-title').innerHTML = `<i class="fas ${{d.vendorIcon}}"></i> ${{d.deviceName}}`;
            document.getElementById('m-ip').textContent = d.ipAddress;
            document.getElementById('m-mac').textContent = d.macAddress;
            document.getElementById('m-seen').textContent = new Date(d.lastSeen).toLocaleDateString() + ' ' + new Date(d.lastSeen).toLocaleTimeString();
            document.getElementById('m-status').textContent = d.status;
            document.getElementById('m-ports').textContent = d.ports.replace(/, /g, '\\n') || "None";
            document.getElementById('m-vulns').textContent = d.vulnerabilities.replace(/, /g, '\\n') || "None";
            
            // Reset scan button/message
            document.getElementById('m-scanbtn').disabled = false;
            document.getElementById('m-scanbtn').innerHTML = '<i class="fas fa-bolt"></i> Trigger High Priority Deep Scan';
            document.getElementById('scan-message').classList.add('hidden');
            
            // Show Modal with transition
            const modalEl = document.getElementById('modal');
            const modalContent = modalEl.querySelector('div:last-child');
            modalEl.classList.remove('hidden', 'opacity-0');
            modalEl.classList.add('flex', 'opacity-100');
            modalContent.classList.remove('scale-95');
            modalContent.classList.add('scale-100');
        }}

        function closeModal() {{
            const modalEl = document.getElementById('modal');
            const modalContent = modalEl.querySelector('div:last-child');
            
            modalEl.classList.remove('opacity-100');
            modalContent.classList.remove('scale-100');
            modalEl.classList.add('opacity-0');
            modalContent.classList.add('scale-95');

            setTimeout(() => {{
                modalEl.classList.remove('flex');
                modalEl.classList.add('hidden');
            }}, 300);
        }}
    </script>
</body>
</html>'''
    with open(HTML_FILE, 'w', encoding='utf-8') as f: f.write(html)

# ----------------------- WORKER -----------------------
def deep_scan_worker():
    global active_scans_counter
    while True:
        try:
            if not deep_scan_active.is_set():
                time.sleep(1)
                continue

            try:
                priority, mac, ip = deep_scan_queue.get(timeout=2)
            except queue.Empty:
                continue

            with active_scans_lock: active_scans_counter += 1
            
            logging.info(f"Starting Deep Scan: {ip} (Priority {priority})")
            
            inv = load_inventory()
            for d in inv:
                if d.get('macAddress') == mac:
                    d['status'] = 'Under Aggressive Review'
            save_inventory(inv)
            render_html(inv)

            xml = deep_scan(ip)
            ports, os_det, vulns = parse_deep(xml)

            inv = load_inventory()
            for d in inv:
                if d.get('macAddress') == mac:
                    d.update({
                        'ports': ports, 'os': os_det, 'vulnerabilities': vulns,
                        'status': 'Online', 'lastSeen': datetime.now().isoformat(),
                        'simulatedConcern': get_risk(d)
                    })
                    if "CRITICAL" in d['simulatedConcern']:
                        logging.warning(f"CRITICAL FOUND: {ip} -> {vulns}")
            
            save_inventory(inv)
            render_html(inv)
            
            with active_scans_lock: active_scans_counter -= 1
            deep_scan_queue.task_done()

        except Exception as e:
            logging.error(f"Worker Error: {e}")
            with active_scans_lock: 
                if active_scans_counter > 0: active_scans_counter -= 1

# ----------------------- MAIN -----------------------
def main():
    init_files()
    
    server_thread = threading.Thread(target=start_server, daemon=True)
    server_thread.start()
    
    time.sleep(1)
    
    for _ in range(MAX_PARALLEL_SCANS):
        threading.Thread(target=deep_scan_worker, daemon=True).start()

    print(f"--- 🛡️ Network Guardian Running 🛡️ ---")
    print(f"Dashboard: http://localhost:{WEB_SERVER_PORT}")
    print(f"Deep Scans: {MAX_PARALLEL_SCANS} threads")
    
    try:
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex(('localhost', WEB_SERVER_PORT))
        if result == 0:
            print("Opening in existing browser session.")
            webbrowser.open(f'http://localhost:{WEB_SERVER_PORT}')
        else:
            print(f"Warning: Web server port {WEB_SERVER_PORT} not open yet. Please open manually.")
        sock.close()
    except: 
        print("Warning: Could not check socket status or open browser.")


    while True:
        try:
            raw = fast_scan()
            if raw:
                devices = parse_fast(raw)
                inv = update_inventory(devices, load_inventory())
                save_inventory(inv)
                render_html(inv)
                print(f"[{datetime.now():%H:%M:%S}] Scan Complete. Devices: {len(devices)}")
            time.sleep(LIGHTWEIGHT_SCAN_INTERVAL)
        except KeyboardInterrupt:
            print("\nShutting down...")
            break
        except Exception as e:
            logging.error(f"Main Loop Error: {e}")
            time.sleep(10)

if __name__ == '__main__':
    main()
