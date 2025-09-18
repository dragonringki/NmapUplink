Nmap Uplink
This is a graphical user interface (GUI) tool built with Python and Tkinter that makes it easier to run Nmap scans. It's not meant for professionals; it's a simple project to help people run basic network scans without memorizing every Nmap command.

Features
Simple UI: A straightforward interface for entering a target IP.

Pre-set Options: Quickly select common scan types and options like SYN scans, version detection, and aggressive mode.

Script Selection: Choose from a list of popular Nmap scripts for vulnerability checks, discovery, and more.

Real-time Output: See the scan progress directly in the terminal output tab.

Post-Scan Actions: After a scan, the "Actions" tab is enabled, allowing you to:

View a summary of the results.

Ping the target.

Run a traceroute.

Save a Markdown report of the findings.

Visualize the network as a cool "spider graph."

Scan Complete Alarm: Get a pop-up and sound notification when your scan finishes.

How to Use
Dependencies: Make sure you have Python 3 and Nmap installed on your system.

On Linux (Debian/Ubuntu): sudo apt-get install nmap

On Windows: Download the installer from the official Nmap website.

Run the script: Just execute the Python file from your terminal.

python nmap.py
Enter a Target: Type the IP address of the device or network you want to scan.

Choose Options: Select the scan options you want from the tabs.

Hit "Run Scan": The scan will start. Depending on the options and target, this could take anywhere from a few seconds to several minutes.

Check the Results: Once the scan is complete, review the "Output" tab for the raw log and the "Actions" tab for a formatted summary and other tools.

Important Notes
Permissions: Some scans (like SYN scans or OS detection) require root/administrator privileges. If the scan fails to run, try running the script with sudo on Linux or as an administrator on Windows.

For Fun and Learning: This tool is for educational purposes and personal use on networks you own or have permission to scan. Don't use it for malicious purposes.
