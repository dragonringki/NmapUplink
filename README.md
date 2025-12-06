🛡️ Network Guardian: A Persistent Scanner for Local Network Insight

Network Guardian is a personal project I built to keep tabs on my local network. It’s a persistent tool that runs Nmap scans on a loop, builds a running inventory of devices, and flags anything that looks like a potential security concern, like open ports or easily found vulnerabilities.

The whole thing is accessible via a simple web view—no complicated interface needed.

🔄 Project Evolution: Moving from GUI to Headless Service

This tool started out as Nmap Uplink, a simple Python/Tkinter GUI. The idea was to make it easier to run customized Nmap commands without having to memorize flags.

However, after building it, I realized I was running the same scans repeatedly, and the overhead of a desktop GUI wasn't really practical for what I wanted: a continuous security overview instead of a pentest tool.

So, I shifted the project's direction entirely:

What Changed

The Old Way (Nmap Uplink)

The New Way (Network Guardian)

Main Goal

A one-time helper for Nmap syntax.

A persistent tool that monitors and inventories the network over time.

Interface

A Python desktop GUI (Tkinter).

A basic, responsive HTML dashboard served locally.

Operation

Starts, runs one scan, and exits.

Runs as a background service, checking the network every minute.

Data Storage

A single Markdown report.

Saves all device history and scan data to local_inventory.json.

This change was driven by the goal of learning how to build a persistent, threaded service that manages long-running processes (like deep Nmap scans) and provides a clean, real-time web interface.

✨ What It Does

Regular Check-ins: It runs a fast, non-intrusive scan (nmap -sn) every 60 seconds (customizable) to see which devices are currently online.

Live Web View: All the data is displayed on a simple, live dashboard at http://localhost:8888.

Automated Deep Scans: When a new device shows up, the tool queues it for an intensive scan (nmap -sV --script=vulners) to grab open port details, OS fingerprinting, and check for known CVEs against its services.

Risk Flagging: Devices with open ports or identified vulnerabilities are flagged, helping me quickly identify potential risks. Anything with a confirmed vulnerability gets the CRITICAL tag.

Manual Control: I can manually force a high-priority deep scan on any device right from the dashboard if I want an immediate check. The system handles the scan scheduling and parallel processing behind the scenes.

Persistent Data: The device inventory isn't lost when the script stops. It's all saved in local_inventory.json.

🚀 Get Started

Dependencies

Python 3: You'll need a modern Python version.

Nmap: The scanning engine must be installed and available in your terminal path.

Linux/macOS: sudo apt-get install nmap or brew install nmap

Windows: Install from the official Nmap site.

Running the Tool

Place the network_monitor.py file somewhere convenient.

Open your terminal in that location.

Run the script:

python3 network_monitor.py





Heads Up: Since Nmap does low-level network probing, you might need elevated privileges (root/Administrator) for certain scans to work correctly. If you get errors, try running with sudo:

sudo python network_monitor.py





Viewing the Dashboard

The script will usually pop open the dashboard in your browser, but if not: http://localhost:8888 or open the html file that gets created in the same folder.

⚙️ Quick Configuration

If you want to play around with the scan timing or the network range, you can easily change these constants at the very top of the network_monitor.py file:

Constant

What it Controls

Default Value

NETWORK_CIDR

The network range (in CIDR format) to scan.

192.168.68.0/24

LIGHTWEIGHT_SCAN_INTERVAL

Seconds to wait between quick network checks.

60

AGGRESSIVE_SCAN_TIMEOUT

Max time (seconds) allowed for a single, intensive deep scan.

600

WEB_SERVER_PORT

The local port used for the dashboard.

8888

MAX_PARALLEL_SCANS

How many simultaneous deep scan threads can run.

3
