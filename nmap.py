import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import subprocess
import threading
import sys
import datetime
import xml.etree.ElementTree as ET
import os
import random
import math
import time

# --- Sound Playback Function ---
if sys.platform == 'win32':
    import winsound
    def play_sound(file=None):
        if file:
            winsound.PlaySound(file, winsound.SND_ASYNC)
        else:
            winsound.Beep(1000, 200)
elif sys.platform == 'darwin':
    import os
    def play_sound(file=None):
        if file:
            os.system(f"afplay '{file}'&")
        else:
            os.system("afplay /System/Library/Sounds/Tink.aiff&")
else: # Linux
    import os
    def play_sound(file=None):
        if file:
            # Try to use paplay first, then aplay, then terminal bell
            try:
                subprocess.run(['paplay', file], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except (FileNotFoundError, subprocess.CalledProcessError):
                try:
                    subprocess.run(['aplay', file], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                except (FileNotFoundError, subprocess.CalledProcessError):
                    os.system("echo -e '\\a'")
        else:
            # Fallback to a common system sound file
            sound_file_paths = [
                "/usr/share/sounds/gnome/default/alerts/glass.ogg",
                "/usr/share/sounds/freedesktop/stereo/bell.oga"
            ]
            played = False
            for sound_file in sound_file_paths:
                if os.path.exists(sound_file):
                    try:
                        subprocess.run(['paplay', sound_file], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        played = True
                        break
                    except (FileNotFoundError, subprocess.CalledProcessError):
                        try:
                            subprocess.run(['aplay', sound_file], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                            played = True
                            break
                        except (FileNotFoundError, subprocess.CalledProcessError):
                            continue
            if not played:
                os.system("echo -e '\\a'")

# --- Custom Popup Window ---
class ScanCompletePopup(tk.Toplevel):
    """
    A custom, non-blocking popup window to notify the user that the scan is complete.
    """
    def __init__(self, parent):
        super().__init__(parent.window)
        self.parent = parent
        self.title("Scan Complete")
        self.geometry("300x150")
        self.configure(background='#1a1a1a')
        self.resizable(False, False)
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f'{width}x{height}+{x}+{y}')

        label = ttk.Label(self, text="The Nmap scan has finished.", font=("Helvetica", 14, 'bold'), anchor='center', foreground='#00BFFF', background='#1a1a1a')
        label.pack(expand=True, fill='both', padx=20, pady=20)

        close_button = ttk.Button(self, text="OK", command=self.on_close, cursor="hand2")
        close_button.pack(pady=(0, 15))
        close_button.focus_set()

    def on_close(self):
        """
        Stops the repeating sound loop and destroys the popup.
        """
        self.parent.stop_sound_loop()
        self.destroy()

class Tooltip:
    """
    A simple tooltip class to display a hint when hovering over a widget.
    """
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tooltip_window = None
        self.widget.bind("<Enter>", self.show_tooltip)
        self.widget.bind("<Leave>", self.hide_tooltip)

    def show_tooltip(self, event=None):
        """Creates the tooltip window and displays the text."""
        x = y = 0
        x, y, _, _ = self.widget.bbox("insert")
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + 25

        self.tooltip_window = tk.Toplevel(self.widget)
        self.tooltip_window.wm_overrideredirect(True)
        self.tooltip_window.wm_geometry(f"+{x}+{y}")
        
        label = tk.Label(self.tooltip_window, text=self.text, background="#1a1a1a", foreground="#00BFFF", relief="solid", borderwidth=1,
                         font=("Helvetica", 10))
        label.pack(padx=1, pady=1)

    def hide_tooltip(self, event=None):
        """Hides and destroys the tooltip window."""
        if self.tooltip_window:
            self.tooltip_window.destroy()
            self.tooltip_window = None

class InfoProfileWindow(tk.Toplevel):
    """
    A window to display detailed information about a selected node.
    """
    def __init__(self, master, title, content):
        super().__init__(master)
        self.title(title)
        self.geometry("400x300")
        self.configure(background='#1a1a1a')
        
        text_area = scrolledtext.ScrolledText(self, wrap=tk.WORD, bg='#0d0d0d', fg='#00FFFF', font=("Courier", 10), relief='flat', borderwidth=0)
        text_area.pack(expand=True, fill='both', padx=10, pady=10)
        text_area.insert(tk.END, content)
        text_area.config(state=tk.DISABLED)

class SpiderGraphVisualizer(tk.Toplevel):
    """
    A separate window for the network visualizer as a spider graph.
    Nodes and the entire graph can be dragged and zoomed by the user.
    """
    def __init__(self, master, xml_data):
        super().__init__(master)
        self.title("Network Visualizer (Spider Graph)")
        self.geometry("800x600")
        self.configure(background='#1a1a1a')
        self.xml_data = xml_data
        self.nodes = {}
        self.lines = []
        self.drag_data = {"item": None, "x": 0, "y": 0, "mode": None}
        self.info_profiles = {}
        self.draw_job = None
        self.canvas_ready = False

        self.canvas = tk.Canvas(self, bg='#1a1a1a', highlightthickness=0)
        self.canvas.pack(expand=True, fill='both', padx=10, pady=10)
        
        self.canvas.bind("<ButtonPress-1>", self.on_press)
        self.canvas.bind("<B1-Motion>", self.on_drag)
        self.canvas.bind("<ButtonRelease-1>", self.on_release)
        self.canvas.bind("<ButtonPress-3>", self.on_right_click)
        self.canvas.bind("<MouseWheel>", self.on_mouse_wheel)
        self.canvas.bind("<Button-4>", self.on_mouse_wheel)
        self.canvas.bind("<Button-5>", self.on_mouse_wheel)
        self.canvas.bind("<Configure>", self.on_canvas_configure)

    def on_canvas_configure(self, event):
        if not self.canvas_ready:
            self.canvas_ready = True
            self.draw_graph()

    def draw_graph(self):
        """
        Parses the XML data and draws the spider graph on the canvas with a host/service hierarchy
        using a non-overlapping circular layout.
        """
        self.canvas.delete("all")
        self.nodes = {}
        self.lines = []
        self.info_profiles = {}
        
        width = self.canvas.winfo_width()
        height = self.canvas.winfo_height()

        if width <= 1 or height <= 1 or not self.xml_data.strip():
            if not self.xml_data.strip():
                self.canvas.create_text(width / 2, height / 2, text="No scan results to visualize.", fill='#00BFFF', font=("Helvetica", 16))
            return

        try:
            root = ET.fromstring(self.xml_data)
            hosts_xml = root.findall('host')
            
            if not hosts_xml:
                self.canvas.create_text(width / 2, height / 2, text="No hosts found in the scan results.", fill='#00BFFF', font=("Helvetica", 16))
                return

            self.nodes_to_draw = []
            
            main_host_xml = hosts_xml[0]
            main_ip_addr = main_host_xml.find('address').get('addr') if main_host_xml.find('address') is not None else "N/A"
            main_host_x, main_host_y = width / 2, height / 2
            
            self.nodes_to_draw.append({"type": "host", "x": main_host_x, "y": main_host_y, "data": main_host_xml, "is_main": True})

            other_hosts_xml = hosts_xml[1:]
            if other_hosts_xml:
                num_other_hosts = len(other_hosts_xml)
                host_spacing_angle = 2 * math.pi / num_other_hosts
                host_radius = min(width, height) / 3
                
                for i, host_xml in enumerate(other_hosts_xml):
                    angle = i * host_spacing_angle
                    x = main_host_x + host_radius * math.cos(angle)
                    y = main_host_y + host_radius * math.sin(angle)
                    self.nodes_to_draw.append({"type": "host", "x": x, "y": y, "data": host_xml, "is_main": False, "parent_node_index": 0})
            
            for i, host_info in enumerate(self.nodes_to_draw):
                ports_elem = host_info['data'].find('ports')
                if ports_elem is not None:
                    open_ports = [p for p in ports_elem.findall('port') if p.find('state') is not None and p.find('state').get('state') == 'open']
                    if open_ports:
                        num_ports = len(open_ports)
                        service_spacing_angle = 2 * math.pi / num_ports
                        service_radius = 80 + (num_ports * 2)
                        
                        for j, port in enumerate(open_ports):
                            angle = j * service_spacing_angle
                            x = host_info['x'] + service_radius * math.cos(angle)
                            y = host_info['y'] + service_radius * math.sin(angle)
                            self.nodes_to_draw.append({"type": "service", "x": x, "y": y, "data": port, "parent_node_index": i})

            self.animate_graph_draw()

        except ET.ParseError as e:
            self.canvas.create_text(width / 2, height / 2, text=f"Error parsing XML: {e}", fill='#FF6347', font=("Helvetica", 14))
        except Exception as e:
            self.canvas.create_text(width / 2, height / 2, text=f"An unexpected error occurred: {e}", fill='#FF6347', font=("Helvetica", 14))

    def animate_graph_draw(self, step=0):
        if step >= len(self.nodes_to_draw):
            return

        node_info = self.nodes_to_draw[step]
        
        x, y = node_info['x'], node_info['y']
        is_main = node_info.get("is_main", False)
        
        if node_info['type'] == 'host':
            ip_addr = node_info['data'].find('address').get('addr') if node_info['data'].find('address') is not None else "N/A"
            text = "Host: " + ip_addr
            size = 15 if is_main else 10
            color = '#00FFFF' if is_main else '#00BFFF'
            tag = "host_node"
            profile = self.get_host_info(node_info['data'])
        else: # service
            port_id = node_info['data'].get('portid')
            protocol = node_info['data'].get('protocol')
            text = f"{port_id}/{protocol}"
            size = 5
            color = '#FF5722'
            tag = "service_node"
            parent_host_xml = self.nodes_to_draw[node_info['parent_node_index']]['data']
            profile = self.get_service_info(node_info['data'], parent_host_xml)
        
        node_id = self.create_node_with_animation(x, y, text, size, color, tag)
        self.nodes[node_id] = {"x": x, "y": y, "type": node_info['type']}
        self.info_profiles[node_id] = profile

        if 'parent_node_index' in node_info:
            parent_node_id = list(self.nodes.keys())[node_info['parent_node_index']]
            self.create_line(parent_node_id, node_id)
        
        self.after(50, self.animate_graph_draw, step + 1)

    def create_node_with_animation(self, x, y, text, size, color, tag):
        start_size = 1
        oval_id = self.canvas.create_oval(x - start_size, y - start_size, x + start_size, y + start_size, 
                                          fill=color, outline='#FFFFFF', width=2, tags=(tag,))
        text_id = self.canvas.create_text(x, y + size + 10, text="", fill='#FFFFFF', font=("Helvetica", 10), justify='center', tags=(tag,))
        self.canvas.itemconfigure(oval_id, tags=(tag, f"id_{oval_id}"))
        self.canvas.itemconfigure(text_id, tags=(tag, f"id_{oval_id}"))

        def grow(current_size):
            if current_size < size:
                self.canvas.coords(oval_id, x - current_size, y - current_size, x + current_size, y + current_size)
                self.after(5, grow, current_size + 1)
            else:
                self.canvas.itemconfig(text_id, text=text)

        grow(start_size)
        return oval_id


    def get_host_info(self, host_xml):
        """Extracts and formats detailed host information."""
        info = ""
        ip_addr_elem = host_xml.find('address')
        ip_addr = ip_addr_elem.get('addr') if ip_addr_elem is not None else "N/A"
        info += f"Host IP Address: {ip_addr}\n"
        
        hostnames = host_xml.find('hostnames')
        if hostnames:
            for hn in hostnames.findall('hostname'):
                info += f"Hostname: {hn.get('name')} ({hn.get('type')})\n"
        
        status = host_xml.find('status')
        if status:
            info += f"Host Status: {status.get('state')}\n"
            
        os_elem = host_xml.find('os')
        if os_elem:
            os_match = os_elem.find('osmatch')
            if os_match:
                info += f"OS: {os_match.get('name')}\n"
                accuracy = os_match.get('accuracy')
                info += f"Accuracy: {accuracy}%\n" if accuracy else "Accuracy: N/A\n"
            
        return info

    def get_service_info(self, port_xml, host_xml):
        """Extracts and formats detailed service information."""
        info = ""
        host_ip_addr = host_xml.find('address').get('addr') if host_xml.find('address') is not None else "N/A"
        info += f"Host: {host_ip_addr}\n"
        
        port_id = port_xml.get('portid')
        protocol = port_xml.get('protocol')
        info += f"Port: {port_id}\n"
        info += f"Protocol: {protocol}\n"
        
        state_elem = port_xml.find('state')
        if state_elem:
            info += f"State: {state_elem.get('state')}\n"
            
        service_elem = port_xml.find('service')
        if service_elem is not None:
            info += f"Service: {service_elem.get('name') or 'N/A'}\n"
            info += f"Product: {service_elem.get('product') or 'N/A'}\n"
            info += f"Version: {service_elem.get('version') or 'N/A'}\n"
            
        for script in port_xml.findall('script'):
            info += f"\nScript: {script.get('id')}\n"
            info += f"Output:\n{script.get('output')}\n"
            
        return info

    def create_line(self, start_node_id, end_node_id):
        """Creates a line between two nodes with a short delay for animation."""
        line_id = self.canvas.create_line(
            self.nodes[start_node_id]['x'], self.nodes[start_node_id]['y'],
            self.nodes[start_node_id]['x'], self.nodes[start_node_id]['y'],
            fill='#00BFFF', width=1
        )
        self.lines.append({"id": line_id, "start": start_node_id, "end": end_node_id})

        end_x = self.nodes[end_node_id]['x']
        end_y = self.nodes[end_node_id]['y']
        
        def animate_line(x1, y1, x2, y2, dx, dy, steps=50):
            current_x, current_y = self.canvas.coords(line_id)[2:]
            
            if abs(current_x - x2) > abs(dx) or abs(current_y - y2) > abs(dy):
                self.canvas.coords(line_id, x1, y1, current_x + dx, current_y + dy)
                self.after(5, animate_line, x1, y1, x2, y2, dx, dy, steps)
            else:
                self.canvas.coords(line_id, x1, y1, x2, y2)

        start_x, start_y = self.nodes[start_node_id]['x'], self.nodes[start_node_id]['y']
        total_dx = end_x - start_x
        total_dy = end_y - start_y
        animate_line(start_x, start_y, end_x, end_y, total_dx/50, total_dy/50)


    def on_press(self, event):
        """Called when a mouse button is pressed."""
        item = self.canvas.find_closest(event.x, event.y)[0]
        if item in self.nodes:
            self.drag_data["mode"] = "node"
            self.drag_data["item"] = item
        else:
            self.drag_data["mode"] = "pan"
            self.drag_data["item"] = "all"

        self.drag_data["x"] = event.x
        self.drag_data["y"] = event.y

    def on_right_click(self, event):
        """Displays a profile of information for the clicked node."""
        item = self.canvas.find_closest(event.x, event.y)[0]
        if item in self.info_profiles:
            profile_title = "Host Profile" if item in self.nodes and self.nodes[item]['type'] == 'host' else "Service Profile"
            InfoProfileWindow(self, profile_title, self.info_profiles[item])

    def on_drag(self, event):
        """Called when a mouse is dragged."""
        dx = event.x - self.drag_data["x"]
        dy = event.y - self.drag_data["y"]
        
        if self.drag_data["mode"] == "node" and self.drag_data["item"] in self.nodes:
            item_id = self.drag_data["item"]
            
            self.canvas.move(item_id, dx, dy)
            self.canvas.move(f"id_{item_id}", dx, dy) # Move the associated text
            
            self.nodes[item_id]['x'] += dx
            self.nodes[item_id]['y'] += dy
            self.update_lines()
        
        elif self.drag_data["mode"] == "pan":
            self.canvas.move("all", dx, dy)
        
        self.drag_data["x"] = event.x
        self.drag_data["y"] = event.y

    def on_release(self, event):
        """Called when a mouse button is released."""
        self.drag_data = {"item": None, "x": 0, "y": 0, "mode": None}
    
    def on_mouse_wheel(self, event):
        """Handles zooming with the mouse wheel."""
        factor = 1.1
        if event.delta > 0 or event.num == 4:
            self.canvas.scale("all", event.x, event.y, factor, factor)
        else:
            self.canvas.scale("all", event.x, event.y, 1/factor, 1/factor)
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def update_lines(self):
        """Redraws all lines based on current node positions."""
        for line in self.lines:
            if line['start'] in self.nodes and line['end'] in self.nodes:
                self.canvas.coords(line['id'], 
                    self.nodes[line['start']]['x'], self.nodes[line['start']]['y'], 
                    self.nodes[line['end']]['x'], self.nodes[line['end']]['y'])


class NmapUplink:
    """
    An advanced Tkinter GUI for performing Nmap scans with multiple options,
    script selection, a dynamic progress bar, and report generation. The scans
    are run in a separate thread to keep the GUI responsive.
    """
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("Nmap Uplink")
        self.window.configure(background='#1a1a1a')
        self.window.geometry("900x650")

        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TFrame', background='#1a1a1a')
        style.configure('TLabel', background='#1a1a1a', foreground='#00BFFF', font=("Helvetica", 12))
        style.configure('TButton', background='#333333', foreground='#00FFFF', font=("Helvetica", 12, 'bold'), relief='flat', borderwidth=0)
        style.map('TButton', background=[('active', '#0d0d0d'), ('selected', '#B33A3A'), ('!disabled', '#333333')])
        style.configure('TCheckbutton', background='#1a1a1a', foreground='#00BFFF', font=("Helvetica", 10))
        style.map('TCheckbutton', background=[('selected', '#B33A3A')])
        style.configure('TEntry', fieldbackground='#0d0d0d', foreground='#00BFFF', borderwidth=0, relief='flat')
        style.configure('TProgressbar', thickness=10, background='#00BFFF', troughcolor='#0d0d0d', borderwidth=0, relief='flat')
        style.configure('TNotebook', background='#1a1a1a', borderwidth=0)
        style.configure('TNotebook.Tab', background='#333333', foreground='#00FFFF')
        style.map('TNotebook.Tab', background=[('selected', '#007BFF')], foreground=[('selected', '#FFFFFF')])
        
        self.main_frame = ttk.Frame(self.window, padding="20 20 20 20")
        self.main_frame.pack(expand=True, fill='both')

        self.label_ip = ttk.Label(self.main_frame, text="Target IP:", font=("Helvetica", 14, 'bold'))
        self.label_ip.grid(row=0, column=0, sticky='w', pady=(0, 5))
        self.input_ip = ttk.Entry(self.main_frame, font=("Helvetica", 12))
        self.input_ip.grid(row=1, column=0, sticky='ew', pady=(0, 15))

        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.grid(row=2, column=0, sticky='ew')

        self.options_tab = ttk.Frame(self.notebook, style='TFrame')
        self.notebook.add(self.options_tab, text="Options")
        self.options_tab.columnconfigure(0, weight=1)
        self.options_tab.columnconfigure(1, weight=1)

        # Create frames for a two-column layout
        options_left_frame = ttk.Frame(self.options_tab, style='TFrame')
        options_left_frame.grid(row=0, column=0, sticky='new', padx=(0, 10))
        options_right_frame = ttk.Frame(self.options_tab, style='TFrame')
        options_right_frame.grid(row=0, column=1, sticky='new', padx=(10, 0))
        
        options_left_frame.columnconfigure(0, weight=1)
        options_right_frame.columnconfigure(0, weight=1)

        self.options_vars = {}
        self.all_options = {
            'Scan Type': {
                '-sS': 'TCP SYN Scan: Stealthy, fast, and often blocked.',
                '-sT': 'TCP Connect Scan: The default, but noisier.',
                '-sU': 'UDP Scan: Slower, but used for services like DNS.',
                '-sV': 'Version Detection: Probes open ports to determine service and version information.',
                '-sC': 'Default Script Scan: Runs a set of common, safe scripts.',
                '-A': 'Aggressive Scan: Combines OS detection, version detection, script scanning, and traceroute.'
            },
            'Host Discovery': {
                '-Pn': 'Treat all hosts as online: Skips the host discovery phase.',
                '-n': 'No DNS Resolution: Faster scanning without DNS lookups.',
                '-F': 'Fast Scan: Scans fewer ports than the default scan.'
            },
            'OS Detection': {
                '-O': 'Enable OS Detection: Attempts to identify the operating system of the target.'
            },
            'Timing & Performance': {
                '-T4': 'Aggressive Timing: Faster, but may be detected.',
                '-T5': 'Insane Timing: Very fast, but high chance of missing ports.',
                '-T1': 'Slower Timing: Less aggressive, for fragile systems.'
            }
        }
        
        # Function to populate a frame with options
        def populate_options_frame(frame, categories):
            frame_row = 0
            for category, options in categories:
                ttk.Label(frame, text=f"{category}:", font=("Helvetica", 12, 'bold')).grid(row=frame_row, column=0, sticky='w', pady=(10, 5))
                frame_row += 1
                for option_name, description in options.items():
                    var = tk.BooleanVar(value=False)
                    self.options_vars[option_name] = var
                    chk = ttk.Checkbutton(frame, text=f"{option_name} ({description})", variable=var, style='TButton')
                    chk.grid(row=frame_row, column=0, sticky='w', padx=15, pady=2)
                    Tooltip(chk, description)
                    frame_row += 1
        
        # Split categories for two columns
        categories_list = list(self.all_options.items())
        left_cats = [categories_list[0], categories_list[1]]
        right_cats = [categories_list[2], categories_list[3]]
        
        populate_options_frame(options_left_frame, left_cats)
        populate_options_frame(options_right_frame, right_cats)
        
        self.enable_alarm_var = tk.BooleanVar(value=False)
        alarm_frame = ttk.Frame(self.options_tab, style='TFrame')
        alarm_frame.grid(row=1, column=0, columnspan=2, sticky='ew', pady=(20, 0))
        self.alarm_chk = ttk.Checkbutton(alarm_frame, text="Enable Scan Complete Alarm", variable=self.enable_alarm_var, style='TButton')
        self.alarm_chk.pack()
        Tooltip(self.alarm_chk, "Plays a sound and shows a pop-up when the scan is finished.")


        self.scripts_tab = ttk.Frame(self.notebook, style='TFrame')
        self.notebook.add(self.scripts_tab, text="Scripts")
        self.scripts_tab.columnconfigure(0, weight=1)
        
        self.script_vars = {}
        self.common_scripts = {
            'Vulnerability': {
                'vuln': 'Checks for common vulnerabilities.',
                'cve-2009-3103': 'Tests for the ProFTPD 1.3.2 exploit.',
                'smb-vuln-ms17-010': 'Checks for the EternalBlue vulnerability (WannaCry).'
            },
            'Discovery': {
                'dns-brute': 'Performs DNS zone brute-forcing.',
                'http-title': 'Gets the title of web pages on HTTP servers.',
                'smb-enum-shares': 'Enumerates SMB shares on a target.'
            },
            'Authentication': {
                'ftp-anon': 'Checks if an FTP server allows anonymous login.',
                'ssh-brute': 'Attempts to brute-force SSH credentials.'
            }
        }

        row = 0
        for category, scripts in self.common_scripts.items():
            ttk.Label(self.scripts_tab, text=f"  {category}:", font=("Helvetica", 12, 'bold')).grid(row=row, column=0, sticky='w', padx=5, pady=5)
            row += 1
            for script_name, description in scripts.items():
                var = tk.BooleanVar(value=False)
                self.script_vars[script_name] = var
                chk = ttk.Checkbutton(self.scripts_tab, text=script_name, variable=var, style='TButton')
                chk.grid(row=row, column=0, sticky='w', padx=15, pady=2)
                Tooltip(chk, description)
                row += 1

        self.custom_args_tab = ttk.Frame(self.notebook, style='TFrame')
        self.notebook.add(self.custom_args_tab, text="Custom")

        self.label_custom_args = ttk.Label(self.custom_args_tab, text="Custom Arguments (e.g., -p 22,80,443)")
        self.label_custom_args.pack(pady=5)
        self.input_custom_args = ttk.Entry(self.custom_args_tab)
        self.input_custom_args.pack(pady=5, fill='x', padx=10)
        Tooltip(self.input_custom_args, "Enter any valid Nmap argument here. Separate with spaces.")

        self.post_scan_tab = ttk.Frame(self.notebook, style='TFrame')
        self.notebook.add(self.post_scan_tab, text="Actions")
        self.notebook.tab(3, state='disabled')

        self.post_scan_text = scrolledtext.ScrolledText(self.post_scan_tab, wrap=tk.WORD, bg='#0d0d0d', fg='#00BFFF', font=("Courier", 10), relief='flat', borderwidth=0)
        self.post_scan_text.pack(expand=True, fill='both', padx=10, pady=10)
        self.post_scan_text.insert(tk.END, "Scan a target to enable these actions.")
        self.post_scan_text.config(state='disabled')

        self.button_frame = ttk.Frame(self.main_frame, style='TFrame')
        self.button_frame.grid(row=3, column=0, sticky='ew', pady=(20, 10))

        self.button_scan = ttk.Button(self.button_frame, text="Run Scan", command=self.start_scan_thread, cursor="hand2")
        self.button_scan.pack(side='left', expand=True, fill='x', padx=(0, 5))
        Tooltip(self.button_scan, "Starts the Nmap scan.")

        self.button_stop = ttk.Button(self.button_frame, text="Stop Scan", command=self.stop_scan, cursor="hand2", state='disabled')
        self.button_stop.pack(side='left', expand=True, fill='x', padx=(5, 0))
        Tooltip(self.button_stop, "Terminates the running scan process.")
        
        self.progress = ttk.Progressbar(self.main_frame, orient="horizontal", length=200, mode="indeterminate", style='TProgressbar')
        self.progress.grid(row=4, column=0, sticky='ew', pady=5)
        
        self.output_notebook = ttk.Notebook(self.main_frame)
        self.output_notebook.grid(row=5, column=0, sticky='nsew', pady=(10, 0))
        
        self.output_tab = ttk.Frame(self.output_notebook, style='TFrame')
        self.output_notebook.add(self.output_tab, text="Output")
        
        self.output_text = tk.Text(self.output_tab, bg='#0d0d0d', fg='#00BFFF', font=("Courier", 10), relief='flat', borderwidth=0)
        self.output_text.pack(expand=True, fill='both')

        self.visualizer_window = None
        self.proc = None
        self.scan_thread = None
        self.xml_output = ""
        self.output_reader_thread = None
        self.sound_job = None
        self.scanned_ip = ""
        self.post_scan_button_frame = None # Frame for post-scan buttons

        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(5, weight=1)

    def setup_post_scan_actions(self):
        """
        Populates the Post-Scan Actions tab with useful buttons and data.
        This function is now safe to call multiple times.
        """
        # FIX: Explicitly destroy the old button frame if it exists from a previous scan.
        if self.post_scan_button_frame and self.post_scan_button_frame.winfo_exists():
            self.post_scan_button_frame.destroy()

        # Prepare the text area for new content
        self.post_scan_text.config(state='normal')
        self.post_scan_text.delete('1.0', tk.END)

        # Create a new frame for the buttons and store a reference to it.
        self.post_scan_button_frame = ttk.Frame(self.post_scan_tab)
        # Pack the button frame above the text area by packing the text area again.
        self.post_scan_button_frame.pack(pady=10)
        self.post_scan_text.pack(expand=True, fill='both', padx=10, pady=10) # Re-pack to ensure order
        
        self.button_open_visualizer = ttk.Button(self.post_scan_button_frame, text="Open Visualizer", command=self.open_visualizer)
        self.button_open_visualizer.pack(side='left', padx=5)
        Tooltip(self.button_open_visualizer, "Opens a new window to visualize scan results.")

        self.button_report = ttk.Button(self.post_scan_button_frame, text="Save Report", command=self.save_report)
        self.button_report.pack(side='left', padx=5)
        Tooltip(self.button_report, "Saves the output to a text and XML file.")
        
        self.button_ping = ttk.Button(self.post_scan_button_frame, text=f"Ping {self.scanned_ip}", command=self.run_ping)
        self.button_ping.pack(side='left', padx=5)
        Tooltip(self.button_ping, f"Performs a quick ping on {self.scanned_ip}.")
        
        self.button_traceroute = ttk.Button(self.post_scan_button_frame, text=f"Traceroute {self.scanned_ip}", command=self.run_traceroute)
        self.button_traceroute.pack(side='left', padx=5)
        Tooltip(self.button_traceroute, f"Performs a traceroute to {self.scanned_ip}.")
        
        self.post_scan_text.insert(tk.END, "--- Scan Summary & Post-Scan Actions ---\n\n")
        
        try:
            root = ET.fromstring(self.xml_output)
            hosts = root.findall('host')
            
            for host in hosts:
                ip_addr = host.find('address').get('addr') if host.find('address') is not None else "N/A"
                self.post_scan_text.insert(tk.END, f"Host: {ip_addr}\n\n")
                
                ports = host.findall('.//port')
                if not ports:
                    self.post_scan_text.insert(tk.END, "  No open ports found.\n\n")
                    continue
                
                for port in ports:
                    state = port.find('state').get('state') if port.find('state') is not None else ""
                    if state == "open":
                        port_id = port.get('portid')
                        service_name = port.find('service').get('name') if port.find('service') is not None else "Unknown"
                        product = port.find('service').get('product') if port.find('service') is not None else ""
                        version = port.find('service').get('version') if port.find('service') is not None else ""
                        
                        self.post_scan_text.insert(tk.END, f"  Port: {port_id}/{port.get('protocol')} - Service: {service_name}\n")
                        if product:
                            self.post_scan_text.insert(tk.END, f"    Product: {product} {version}\n")
                        
                        if service_name.lower() == "ssh":
                            self.post_scan_text.insert(tk.END, "    > Recommended Action: Try common credentials or a brute-force attack.\n\n")
                        elif service_name.lower() in ["http", "https"]:
                            self.post_scan_text.insert(tk.END, "    > Recommended Action: Check for common directories or run a vulnerability scanner.\n\n")
                        elif service_name.lower() == "ftp":
                            self.post_scan_text.insert(tk.END, "    > Recommended Action: Test for anonymous login.\n\n")
                        
        except ET.ParseError:
            self.post_scan_text.insert(tk.END, "Failed to parse XML output. Summary unavailable.")
        
        self.post_scan_text.config(state='disabled')
        self.notebook.tab(3, state='normal')
        
    def open_visualizer(self):
        """
        Creates and shows the SpiderGraphVisualizer.
        """
        if self.visualizer_window is None or not self.visualizer_window.winfo_exists():
            self.visualizer_window = SpiderGraphVisualizer(self.window, self.xml_output)
            self.visualizer_window.protocol("WM_DELETE_WINDOW", self.on_visualizer_close)
        else:
            messagebox.showinfo("Visualizer", "The visualizer window is already open.")

    def on_visualizer_close(self):
        """
        Callback for when the visualizer window is closed.
        """
        self.visualizer_window.destroy()
        self.visualizer_window = None

    def build_command(self):
        """
        Builds the nmap command from the GUI options.
        """
        ip = self.input_ip.get().strip()
        if not ip:
            messagebox.showerror("Error", "Please enter a target IP address.")
            return None

        command = ["nmap", ip, "-oX", "-"]
        self.scanned_ip = ip

        for option_name, var in self.options_vars.items():
            if var.get():
                command.append(option_name)

        selected_scripts = []
        for script_name, var in self.script_vars.items():
            if var.get():
                command.append(f"--script={script_name}")
        
        custom_args = self.input_custom_args.get().strip()
        if custom_args:
            command.extend(custom_args.split())

        return command
    
    def start_scan_thread(self):
        """
        Starts the scan in a separate thread to prevent the GUI from freezing.
        """
        if self.scan_thread and self.scan_thread.is_alive():
            messagebox.showwarning("Warning", "A scan is already in progress.")
            return

        command = self.build_command()
        if not command:
            return

        privileged_options = ['-sS', '-O', '-sU']
        # FIX: Correctly check the value of the BooleanVar for script privileges.
        requires_privilege = any(option in command for option in privileged_options) or any(var.get() for var in self.script_vars.values())

        if requires_privilege:
            if sys.platform.startswith('linux') and os.geteuid() != 0:
                command.insert(0, 'sudo')
            elif sys.platform == 'win32':
                messagebox.showwarning("Permission Warning", "You are attempting a privileged scan on Windows. Please ensure you are running this script as an Administrator.")

        self.xml_output = ""
        self.output_text.delete('1.0', tk.END)
        self.output_text.insert(tk.END, f"Executing command: {' '.join(command)}\n\n")
            
        self.button_scan.config(state='disabled')
        self.button_stop.config(state='normal')
        self.notebook.tab(3, state='disabled')
        
        self.progress.start()
        
        self.scan_thread = threading.Thread(target=self.run_scan, args=(command,))
        self.scan_thread.daemon = True
        self.scan_thread.start()
    
    def stop_scan(self):
        """
        Terminates the running Nmap subprocess.
        """
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            self.update_output("\nScan terminated by user.\n")
            self.button_scan.config(state='normal')
            self.button_stop.config(state='disabled')
            self.progress.stop()

    def run_scan(self, command):
        """
        Executes the nmap command and updates the GUI with output in real-time.
        This function runs in a separate thread.
        """
        try:
            self.proc = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            
            stderr_thread = threading.Thread(target=self.read_stderr, args=(self.proc.stderr,))
            stderr_thread.daemon = True
            stderr_thread.start()

            stdout_data, _ = self.proc.communicate()
            
            self.xml_output = stdout_data

        except FileNotFoundError:
            self.window.after(0, self.update_output, "Error: Nmap not found. Please ensure it is installed and in your system's PATH.\n")
        except Exception as e:
            self.window.after(0, self.update_output, f"An unexpected error occurred: {e}\n")
        finally:
            self.window.after(0, self.button_scan.config, {'state': 'normal'})
            self.window.after(0, self.button_stop.config, {'state': 'disabled'})
            self.window.after(0, self.progress.stop)
            self.window.after(0, self.update_output, "\n--- Scan Complete ---")
            self.window.after(0, self.setup_post_scan_actions)

            if self.enable_alarm_var.get():
                self.window.after(100, self.start_sound_and_popup)
    
    def run_ping(self):
        self.post_scan_text.config(state='normal')
        self.post_scan_text.insert(tk.END, f"\n\n--- Pinging {self.scanned_ip} ---\n")
        self.post_scan_text.config(state='disabled')
        command = ["ping", "-c", "4", self.scanned_ip] if sys.platform != 'win32' else ["ping", "-n", "4", self.scanned_ip]
        self.execute_utility_command(command)

    def run_traceroute(self):
        self.post_scan_text.config(state='normal')
        self.post_scan_text.insert(tk.END, f"\n\n--- Tracerouting {self.scanned_ip} ---\n")
        self.post_scan_text.config(state='disabled')
        command = ["traceroute", self.scanned_ip] if sys.platform != 'win32' else ["tracert", self.scanned_ip]
        self.execute_utility_command(command)

    def execute_utility_command(self, command):
        threading.Thread(target=self.run_background_command, args=(command,)).start()
        
    def run_background_command(self, command):
        try:
            proc = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            for line in iter(proc.stdout.readline, ''):
                self.window.after(0, self.update_post_scan_text, line)
            for line in iter(proc.stderr.readline, ''):
                self.window.after(0, self.update_post_scan_text, line)
            
        except FileNotFoundError:
            self.window.after(0, self.update_post_scan_text, "Error: Command not found. Please ensure it is installed and in your system's PATH.\n")
        except Exception as e:
            self.window.after(0, self.update_post_scan_text, f"An unexpected error occurred: {e}\n")

    def start_sound_and_popup(self):
        """
        Initializes the sound loop and opens the non-blocking popup.
        """
        self.popup = ScanCompletePopup(self)
        self.play_sound_loop()

    def play_sound_loop(self):
        """
        Plays a single sound and schedules the next one.
        """
        play_sound()
        self.sound_job = self.window.after(500, self.play_sound_loop)

    def stop_sound_loop(self):
        """
        Cancels the repeating sound loop.
        """
        if self.sound_job:
            self.window.after_cancel(self.sound_job)
            self.sound_job = None
        
    def read_stderr(self, stderr):
        """
        Reads stderr and updates the UI in real-time.
        """
        for line in iter(stderr.readline, ''):
            if line:
                self.window.after(0, self.update_output, line)
        
    def save_report(self):
        """
        Saves the raw XML to a timestamped file.
        """
        if not self.xml_output.strip():
            messagebox.showwarning("Empty Report", "There is no scan data to save. Please run a scan first.")
            return
        
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        md_filename = f"nmap_report_{timestamp}.md"

        try:
            root = ET.fromstring(self.xml_output)
            report_content = self.generate_markdown_report(root)

            with open(md_filename, 'w') as f:
                f.write(report_content)
            
            messagebox.showinfo("Report Saved", f"Scan report saved to:\n{md_filename}")
        
        except ET.ParseError as e:
            messagebox.showerror("XML Parsing Error", f"Failed to parse Nmap's XML output: {e}. Cannot generate report.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save report: {e}")
    
    def generate_markdown_report(self, root):
        """Generates a markdown-formatted report from the parsed XML tree."""
        markdown_text = "# Nmap Scan Report\n\n"
        markdown_text += f"**Scan Date:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        
        hosts_xml = root.findall('host')
        for host in hosts_xml:
            ip_addr_elem = host.find('address')
            ip_addr = ip_addr_elem.get('addr') if ip_addr_elem is not None else "N/A"
            markdown_text += f"--- \n\n## Host: `{ip_addr}`\n\n"
            
            status_elem = host.find('status')
            if status_elem is not None:
                markdown_text += f"- **Status:** `{status_elem.get('state')}`\n"
            
            hostnames_elem = host.find('hostnames')
            if hostnames_elem:
                hostnames = [hn.get('name') for hn in hostnames_elem.findall('hostname')]
                if hostnames:
                    markdown_text += f"- **Hostnames:** {', '.join(hostnames)}\n"

            os_elem = host.find('os')
            if os_elem is not None:
                os_match = os_elem.find('osmatch')
                if os_match is not None:
                    markdown_text += f"- **OS:** {os_match.get('name')}\n"
                    accuracy = os_match.get('accuracy')
                    markdown_text += f"  - **Accuracy:** {accuracy}%\n" if accuracy else "  - **Accuracy:** N/A\n"
            
            ports_elem = host.find('ports')
            if ports_elem is not None:
                open_ports = [p for p in ports_elem.findall('port') if p.find('state') is not None and p.find('state').get('state') == 'open']
                if open_ports:
                    markdown_text += f"\n### Open Ports & Services\n\n"
                    for port in open_ports:
                        port_id = port.get('portid')
                        protocol = port.get('protocol')
                        service_elem = port.find('service')
                        service_name = service_elem.get('name') if service_elem is not None else "Unknown"
                        product = service_elem.get('product') if service_elem is not None else "N/A"
                        version = service_elem.get('version') if service_elem is not None else "N/A"
                        markdown_text += f"- **Port:** `{port_id}/{protocol}`\n"
                        markdown_text += f"  - **Service:** {service_name}\n"
                        if product != "N/A":
                            markdown_text += f"  - **Product:** {product}\n"
                        if version != "N/A":
                            markdown_text += f"  - **Version:** {version}\n"

                        scripts = port.findall('script')
                        if scripts:
                            markdown_text += f"  - **Scripts:**\n"
                            for script in scripts:
                                script_id = script.get('id')
                                output = script.get('output')
                                markdown_text += f"    - **{script_id}**\n"
                                if output:
                                    markdown_text += f"      ```\n      {output.strip()}\n      ```\n"

        return markdown_text

    def update_output(self, text):
        """
        Inserts text into the output widget and scrolls to the bottom.
        This function is called from the main thread using `after`.
        """
        self.output_text.insert(tk.END, text)
        self.output_text.see(tk.END)
    
    def update_post_scan_text(self, text):
        """
        Inserts text into the post-scan widget and scrolls to the bottom.
        """
        self.post_scan_text.config(state='normal')
        self.post_scan_text.insert(tk.END, text)
        self.post_scan_text.see(tk.END)
        self.post_scan_text.config(state='disabled')

    def run(self):
        """
        Starts the Tkinter event loop.
        """
        self.window.mainloop()

if __name__ == "__main__":
    nmap_uplink = NmapUplink()
    nmap_uplink.run()


