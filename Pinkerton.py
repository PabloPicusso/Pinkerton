import socket
import threading
import networkx as nx
import tkinter as tk
from tkinter import ttk, messagebox, font as tkfont, filedialog
import uuid
import json
import requests
import platform
import psutil
import time
import sys
import os
import subprocess
import whois
import dns.resolver
from datetime import datetime
from PIL import Image, ImageTk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import numpy as np
from ttkthemes import ThemedStyle
import logging
from scapy.all import *

# Configure logging
logging.basicConfig(
    filename='pinkerton.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# ASCII Art Banner
BANNER = """
██████╗ ██╗███╗   ██╗██╗  ██╗███████╗██████╗ ████████╗ ██████╗ ███╗   ██╗
██╔══██╗██║████╗  ██║██║ ██╔╝██╔════╝██╔══██╗╚══██╔══╝██╔═══██╗████╗  ██║
██████╔╝██║██╔██╗ ██║█████╔╝ █████╗  ██████╔╝   ██║   ██║   ██║██╔██╗ ██║
██╔═══╝ ██║██║╚██╗██║██╔═██╗ ██╔══╝  ██╔══██╗   ██║   ██║   ██║██║╚██╗██║
██║     ██║██║ ╚████║██║  ██╗███████╗██║  ██║   ██║   ╚██████╔╝██║ ╚████║
╚═╝     ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═══╝
                        Network Intelligence Suite
                        By : Daniel Goldstein 
                        07/11/2024
"""

# Color schemes
THEMES = {
    'cyberpunk': {
        'bg': '#0a0a0a',
        'fg': '#00ff00',
        'accent1': '#ff00ff',
        'accent2': '#00ffff',
        'warning': '#ff0000',
        'success': '#00ff00'
    },
    'matrix': {
        'bg': '#000000',
        'fg': '#008f11',
        'accent1': '#00ff00',
        'accent2': '#003b00',
        'warning': '#ff0000',
        'success': '#00ff00'
    },
    'neon': {
        'bg': '#1a1a1a',
        'fg': '#ff00ff',
        'accent1': '#00ffff',
        'accent2': '#ff00aa',
        'warning': '#ff0000',
        'success': '#00ff00'
    }
}

# Common ports and their services
COMMON_PORTS = {
    20: ("FTP Data", "File Transfer Protocol Data Connection"),
    21: ("FTP Control", "File Transfer Protocol Control Connection"),
    22: ("SSH", "Secure Shell"),
    23: ("Telnet", "Telnet protocol"),
    25: ("SMTP", "Simple Mail Transfer Protocol"),
    53: ("DNS", "Domain Name System"),
    80: ("HTTP", "Hypertext Transfer Protocol"),
    110: ("POP3", "Post Office Protocol v3"),
    143: ("IMAP", "Internet Message Access Protocol"),
    443: ("HTTPS", "HTTP Secure"),
    445: ("Microsoft-DS", "Microsoft Directory Services"),
    3306: ("MySQL", "MySQL Database"),
    3389: ("RDP", "Remote Desktop Protocol"),
    5432: ("PostgreSQL", "PostgreSQL Database"),
    8080: ("HTTP Proxy", "HTTP Proxy"),
    8443: ("HTTPS Alt", "HTTPS Alternate"),
    27017: ("MongoDB", "MongoDB Database"),
    6379: ("Redis", "Redis Database"),
    9200: ("Elasticsearch", "Elasticsearch"),
    5601: ("Kibana", "Kibana Analytics"),
}

# Vulnerability database (simplified)
VULNERABILITIES = {
    21: [
        "FTP Anonymous Access",
        "FTP Bounce Attack",
        "Clear-text Authentication"
    ],
    23: [
        "Clear-text Authentication",
        "Brute Force Attack",
        "Traffic Sniffing"
    ],
    80: [
        "SQL Injection",
        "Cross-site Scripting (XSS)",
        "Directory Traversal"
    ],
    445: [
        "EternalBlue (MS17-010)",
        "SMB Relay Attack",
        "Remote Code Execution"
    ]
}

class NetworkUtils:
    @staticmethod
    def ping(host, count=4):
        try:
            if platform.system().lower() == "windows":
                cmd = f"ping -n {count} {host}"
            else:
                cmd = f"ping -c {count} {host}"
            
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            return result.stdout
        except Exception as e:
            return f"Error: {str(e)}"

    @staticmethod
    def traceroute(host):
        try:
            if platform.system().lower() == "windows":
                cmd = f"tracert {host}"
            else:
                cmd = f"traceroute {host}"
            
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            return result.stdout
        except Exception as e:
            return f"Error: {str(e)}"

    @staticmethod
    def dns_lookup(domain):
        results = []
        try:
            for qtype in ['A', 'AAAA', 'MX', 'NS', 'TXT']:
                try:
                    answers = dns.resolver.resolve(domain, qtype)
                    for rdata in answers:
                        results.append(f"{qtype}: {rdata}")
                except Exception:
                    continue
            return results
        except Exception as e:
            return [f"Error: {str(e)}"]

    @staticmethod
    def whois_lookup(domain):
        try:
            w = whois.whois(domain)
            return w
        except Exception as e:
            return f"Error: {str(e)}"

class SpeedTester:
    def __init__(self):
        self.results = None
        self.stop_test = False

    def test_speed(self, progress_callback=None):
        """Test internet connection speed"""
        try:
            if progress_callback:
                progress_callback("Testing download speed...")
            
            # Test download speed using a sample file
            download_speed = self._test_download()
            
            if progress_callback:
                progress_callback("Testing upload speed...")
            
            # Test upload speed
            upload_speed = self._test_upload()
            
            # Test ping
            ping = self._test_ping()
            
            self.results = {
                'download': download_speed,
                'upload': upload_speed,
                'ping': ping
            }
            return self.results
            
        except Exception as e:
            return f"Error: {str(e)}"

    def _test_download(self):
        """Test download speed using a sample file"""
        try:
            # Use a reliable speed test server
            url = "http://speedtest.ftp.otenet.gr/files/test100k.db"
            start_time = time.time()
            
            response = requests.get(url, stream=True)
            downloaded = 0
            
            for chunk in response.iter_content(chunk_size=8192):
                if self.stop_test:
                    return 0
                if chunk:
                    downloaded += len(chunk)
            
            duration = time.time() - start_time
            speed_mbps = (downloaded * 8) / (1000000 * duration)  # Convert to Mbps
            return speed_mbps
            
        except:
            return 0

    def _test_upload(self):
        """Test upload speed"""
        try:
            # Generate sample data (1MB)
            data = b'0' * 1000000
            
            # Use a test server that accepts uploads
            url = "https://httpbin.org/post"
            start_time = time.time()
            
            response = requests.post(url, data=data)
            
            duration = time.time() - start_time
            speed_mbps = (len(data) * 8) / (1000000 * duration)  # Convert to Mbps
            return speed_mbps
            
        except:
            return 0

    def _test_ping(self):
        """Test ping to a reliable server"""
        try:
            host = "8.8.8.8"  # Google DNS
            start_time = time.time()
            
            if platform.system().lower() == "windows":
                ping = subprocess.Popen(["ping", "-n", "1", host], 
                                     stdout=subprocess.PIPE, 
                                     stderr=subprocess.PIPE)
            else:
                ping = subprocess.Popen(["ping", "-c", "1", host], 
                                     stdout=subprocess.PIPE, 
                                     stderr=subprocess.PIPE)
            
            ping.communicate()
            duration = time.time() - start_time
            return round(duration * 1000)  # Convert to milliseconds
            
        except:
            return 0
        
class SystemMonitor:
    def __init__(self):
        self.history = {
            'cpu': [],
            'memory': [],
            'network': []
        }
        self.max_history = 60  # Keep 60 seconds of history
    def get_cpu_usage(self):
        return psutil.cpu_percent(interval=1)

    def get_memory_usage(self):
        mem = psutil.virtual_memory()
        return {
            'total': mem.total,
            'available': mem.available,
            'percent': mem.percent,
            'used': mem.used,
            'free': mem.free
        }

    def get_network_usage(self):
        net_io = psutil.net_io_counters()
        return {
            'bytes_sent': net_io.bytes_sent,
            'bytes_recv': net_io.bytes_recv,
            'packets_sent': net_io.packets_sent,
            'packets_recv': net_io.packets_recv
        }

    def update_history(self):
        cpu = self.get_cpu_usage()
        mem = self.get_memory_usage()['percent']
        net = self.get_network_usage()

        self.history['cpu'].append(cpu)
        self.history['memory'].append(mem)
        self.history['network'].append(net['bytes_sent'] + net['bytes_recv'])

        # Keep only last max_history values
        for key in self.history:
            if len(self.history[key]) > self.max_history:
                self.history[key].pop(0)

# Remove this line:
# import nmap

# Replace NetworkMapper class with custom scanner
class NetworkMapper:
    def __init__(self):
        self.current_scan = None
        self.os_hints = {}

    def scan_network(self, target, ports=None, arguments=None):
        try:
            results = {}
            if ports:
                port_list = self._parse_ports(ports)
            else:
                port_list = range(1, 1025)  # Default scan first 1024 ports
                
            for port in port_list:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((target, port))
                    if result == 0:
                        service = self._get_service_info(target, port)
                        results[port] = {
                            'state': 'open',
                            'name': service.get('name', 'unknown'),
                            'product': service.get('product', ''),
                            'version': service.get('version', '')
                        }
                    sock.close()
                except:
                    continue

            self.current_scan = {target: {'tcp': results}}
            return self.current_scan
        except Exception as e:
            return f"Error: {str(e)}"

    def _parse_ports(self, ports):
        """Parse port string into list of ports"""
        if isinstance(ports, str):
            ports = ports.split(',')
            result = []
            for port in ports:
                if '-' in port:
                    start, end = map(int, port.split('-'))
                    result.extend(range(start, end + 1))
                else:
                    result.append(int(port))
            return result
        return ports

    def _get_service_info(self, target, port):
        """Get service information for open port"""
        try:
            service_name = socket.getservbyport(port)
            info = {'name': service_name, 'product': '', 'version': ''}
            
            # Try to get banner
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((target, port))
                sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                sock.close()
                
                if banner:
                    info['product'] = banner.split('\r\n')[0]
                    if 'Server:' in banner:
                        info['version'] = banner.split('Server:')[1].split('\r\n')[0].strip()
            except:
                pass
                
            return info
        except:
            return {'name': 'unknown', 'product': '', 'version': ''}

    def get_os_details(self, target):
        """Get OS details through TCP/IP fingerprinting"""
        try:
            if target not in self.os_hints:
                # Simple OS detection based on TTL
                ttl = self._get_ttl(target)
                if ttl:
                    if ttl <= 64:
                        os_type = "Linux/Unix"
                    elif ttl <= 128:
                        os_type = "Windows"
                    else:
                        os_type = "Unknown"
                    
                    self.os_hints[target] = [{
                        'name': os_type,
                        'accuracy': '60'
                    }]
            
            return self.os_hints.get(target, [])
        except:
            return []

    def _get_ttl(self, target):
        """Get TTL value through ICMP echo"""
        try:
            if platform.system().lower() == "windows":
                ping = subprocess.Popen(["ping", "-n", "1", target], stdout=subprocess.PIPE)
            else:
                ping = subprocess.Popen(["ping", "-c", "1", target], stdout=subprocess.PIPE)
            
            output = ping.communicate()[0].decode()
            if "TTL=" in output:
                ttl = int(output.split("TTL=")[1].split()[0])
                return ttl
        except:
            pass
        return None

class VulnerabilityScanner:
    def __init__(self):
        self.vulnerabilities = VULNERABILITIES

    def check_port_vulnerabilities(self, port):
        return self.vulnerabilities.get(port, [])

    def check_service_vulnerabilities(self, service_name):
        all_vulns = []
        service_name = service_name.lower()
        for port, vulns in self.vulnerabilities.items():
            if service_name in COMMON_PORTS.get(port, [''])[0].lower():
                all_vulns.extend(vulns)
        return all_vulns

class CustomNotebook(ttk.Notebook):
    """A custom Notebook with close buttons on tabs"""
    def __init__(self, *args, **kwargs):
        ttk.Notebook.__init__(self, *args, **kwargs)
        self.active = None
        self.bind('<ButtonPress-1>', self.on_close_press)
        self.bind('<ButtonRelease-1>', self.on_close_release)

    def on_close_press(self, event):
        element = self.identify(event.x, event.y)
        if "close" in str(element):
            index = self.index("@%d,%d" % (event.x, event.y))
            self.state(['pressed'])
            self.active = index

    def on_close_release(self, event):
        if not self.active:
            return
        
        element = self.identify(event.x, event.y)
        if "close" in str(element):
            index = self.index("@%d,%d" % (event.x, event.y))
            if self.active == index:
                self.forget(index)
        self.active = None

class AnimatedLabel(tk.Label):
    """A label with loading animation capability"""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.frames = ["|", "/", "─", "\\"]
        self.current_frame = 0
        self.is_animating = False

    def start_animation(self):
        self.is_animating = True
        self.animate()

    def stop_animation(self):
        self.is_animating = False
        self.config(text="")

    def animate(self):
        if self.is_animating:
            self.current_frame = (self.current_frame + 1) % len(self.frames)
            self.config(text=self.frames[self.current_frame])
            self.after(100, self.animate)

class ResultsExporter:
    @staticmethod
    def export_to_txt(filename, data):
        with open(filename, 'w') as f:
            f.write(data)

    @staticmethod
    def export_to_json(filename, data):
        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)

    @staticmethod
    def export_to_html(filename, data):
        html_content = f"""
        <html>
        <head>
            <title>Pinkerton Scan Results</title>
            <style>
                body {{ font-family: Arial, sans-serif; background-color: #1a1a1a; color: #00ff00; }}
                .container {{ max-width: 800px; margin: 0 auto; padding: 20px; }}
                .header {{ text-align: center; color: #ff00ff; }}
                .results {{ background-color: #2a2a2a; padding: 20px; border-radius: 5px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Pinkerton Scan Results</h1>
                    <p>Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                </div>
                <div class="results">
                    <pre>{data}</pre>
                </div>
            </div>
        </body>
        </html>
        """
        with open(filename, 'w') as f:
            f.write(html_content)

class ScanProfile:
    def __init__(self, name, target, start_port, end_port, options=None):
        self.name = name
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.options = options or {}

    @staticmethod
    def save_profile(profile, filename):
        data = {
            'name': profile.name,
            'target': profile.target,
            'start_port': profile.start_port,
            'end_port': profile.end_port,
            'options': profile.options
        }
        with open(filename, 'w') as f:
            json.dump(data, f)

    @staticmethod
    def load_profile(filename):
        with open(filename, 'r') as f:
            data = json.load(f)
        return ScanProfile(
            data['name'],
            data['target'],
            data['start_port'],
            data['end_port'],
            data['options']
        )
class NetworkGraphVisualizer:
    def __init__(self, master):
        self.master = master
        self.figure, self.ax = plt.subplots(figsize=(8, 6))
        self.figure.patch.set_facecolor('#2c3e50')
        self.ax.set_facecolor('#2c3e50')
        self.canvas = FigureCanvasTkAgg(self.figure, master=master)
        self.nodes = {}
        self.edges = []

    def update_graph(self, network_data):
        self.ax.clear()
        # Create network visualization using networkx
        G = nx.Graph()
        
        # Add nodes and edges based on network_data
        for node in network_data['nodes']:
            G.add_node(node['ip'], type=node['type'])
            
        for edge in network_data['edges']:
            G.add_edge(edge['source'], edge['target'])

        # Draw the network
        pos = nx.spring_layout(G)
        nx.draw(G, pos, ax=self.ax, 
                node_color='#00ff00',
                edge_color='#00ffff',
                with_labels=True,
                font_color='white')
        
        self.canvas.draw()

class PinkertonGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("PINKERTON - Network Intelligence Suite")
        
        # Initialize all attributes first
        self.initialize_attributes()
        
        # Setup GUI components in correct order
        self.setup_gui()
        self.create_dashboard_tab()
        self.start_monitoring()
    
    def initialize_attributes(self):
        """Initialize all attributes first"""
        self.running = True
        self.scanning = False
        self.update_id = None
        self.system_info_update_id = None
        self.notebook = None
        self.status_label = None
        self.system_info_label = None
        
        # Initialize monitoring components
        self.system_monitor = SystemMonitor()
        self.network_mapper = NetworkMapper()
        self.vulnerability_scanner = VulnerabilityScanner()
        self.speed_tester = SpeedTester()
        self.current_theme = 'cyberpunk'


    def create_status_bar(self):
        """Create status bar"""
        status_frame = ttk.Frame(self.main_container)
        status_frame.pack(fill=tk.X, side=tk.BOTTOM, pady=5)
        
        self.status_label = ttk.Label(status_frame, text="Ready")
        self.status_label.pack(side=tk.LEFT, padx=5)
        
        self.system_info_label = ttk.Label(status_frame, text="")
        self.system_info_label.pack(side=tk.RIGHT, padx=5)

    // ... existing code ...
def start_monitoring(self):
    """Start system monitoring"""
    try:
        if not hasattr(self, 'cpu_progress') or not self.cpu_progress:
            logging.error("GUI components not properly initialized")
            return False

        # Start system info updates
        self.update_system_info()
        
        # Start graph updates
        self.start_system_monitoring()
        
        logging.info("System monitoring started successfully")
        return True
    except Exception as e:
        logging.error(f"Error starting monitoring: {str(e)}")
        return False
// ... existing code ...

    def update_graphs(self):
       """Update system monitoring graphs"""
    try:
        if not all([self.cpu_ax, self.memory_ax, self.network_ax,
                   self.cpu_canvas, self.memory_canvas, self.network_canvas]):
            logging.error("Graph components not properly initialized")
            return False

        # Update CPU graph
        cpu_percent = psutil.cpu_percent()
        if hasattr(self, 'cpu_progress'):
            self.cpu_progress['value'] = cpu_percent
        
        self.system_monitor.history['cpu'].append(cpu_percent)
        if len(self.system_monitor.history['cpu']) > 60:
            self.system_monitor.history['cpu'].pop(0)
        
        self.cpu_ax.clear()
        self.cpu_ax.plot(self.system_monitor.history['cpu'], 
                       color=THEMES[self.current_theme]['accent1'])
        self.cpu_ax.set_ylim(0, 100)
        self.cpu_ax.set_title("CPU Usage %")
        self.cpu_canvas.draw()

        # Update Memory and Network graphs similarly...
        return True
    except Exception as e:
        logging.error(f"Error updating graphs: {str(e)}")
        return False 


    def create_dashboard_tab(self):
        """Create dashboard tab with monitoring widgets"""
        dashboard_frame = ttk.Frame(self.notebook)
        self.notebook.add(dashboard_frame, text="Dashboard")

        # Create progress bars
        progress_frame = ttk.LabelFrame(dashboard_frame, text="System Resources")
        progress_frame.pack(fill=tk.X, padx=5, pady=5)

        # CPU Progress
        ttk.Label(progress_frame, text="CPU Usage:").pack(side=tk.LEFT, padx=5)
        self.cpu_progress = ttk.Progressbar(progress_frame, length=200, mode='determinate')
        self.cpu_progress.pack(side=tk.LEFT, padx=5)

        # Memory Progress
        ttk.Label(progress_frame, text="Memory Usage:").pack(side=tk.LEFT, padx=5)
        self.memory_progress = ttk.Progressbar(progress_frame, length=200, mode='determinate')
        self.memory_progress.pack(side=tk.LEFT, padx=5)

        # Network Progress
        ttk.Label(progress_frame, text="Network Usage:").pack(side=tk.LEFT, padx=5)
        self.network_progress = ttk.Progressbar(progress_frame, length=200, mode='determinate')
        self.network_progress.pack(side=tk.LEFT, padx=5)

        # Create graphs
        graphs_frame = ttk.Frame(dashboard_frame)
        graphs_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # CPU Graph
        cpu_frame = ttk.LabelFrame(graphs_frame, text="CPU History")
        cpu_frame.pack(fill=tk.BOTH, expand=True, side=tk.LEFT, padx=5)
        
        figure1, self.cpu_ax = plt.subplots(figsize=(4, 3))
        self.cpu_canvas = FigureCanvasTkAgg(figure1, cpu_frame)
        self.cpu_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        # Memory Graph
        memory_frame = ttk.LabelFrame(graphs_frame, text="Memory History")
        memory_frame.pack(fill=tk.BOTH, expand=True, side=tk.LEFT, padx=5)
        
        figure2, self.memory_ax = plt.subplots(figsize=(4, 3))
        self.memory_canvas = FigureCanvasTkAgg(figure2, memory_frame)
        self.memory_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        # Network Graph
        network_frame = ttk.LabelFrame(graphs_frame, text="Network History")
        network_frame.pack(fill=tk.BOTH, expand=True, side=tk.LEFT, padx=5)
        
        figure3, self.network_ax = plt.subplots(figsize=(4, 3))
        self.network_canvas = FigureCanvasTkAgg(figure3, network_frame)
        self.network_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)



    def start_update_threads(self):
        """Start update threads"""
        self.update_thread = threading.Thread(target=self.update_loop, daemon=True)
        self.system_info_thread = threading.Thread(target=self.system_info_loop, daemon=True)
        
        self.update_thread.start()
        self.system_info_thread.start()

    def update_loop(self):
        """Main update loop for graphs"""
        while self.running:
            try:
                if not hasattr(self, 'master') or not self.master.winfo_exists():
                    break

                self.master.after(0, self.update_graphs)
                time.sleep(1)  # Update every second
            except Exception as e:
                logging.error(f"Error in update loop: {str(e)}")
                time.sleep(1)  # Wait before retrying

    def system_info_loop(self):
        """System info update loop"""
        while self.running:
            try:
                if not hasattr(self, 'master') or not self.master.winfo_exists():
                    break

                self.master.after(0, self.update_system_info_safe)
                time.sleep(1)  # Update every second
            except Exception as e:
                logging.error(f"Error in system info loop: {str(e)}")
                time.sleep(1)  # Wait before retrying

    def update_graphs(self):
        """Update graphs (called from main thread)"""
        try:
            if not hasattr(self, 'master') or not self.master.winfo_exists():
                return

            # Update CPU graph
            cpu_percent = psutil.cpu_percent()
            self.system_monitor.history['cpu'].append(cpu_percent)
            if len(self.system_monitor.history['cpu']) > 60:
                self.system_monitor.history['cpu'].pop(0)
            
            self.cpu_ax.clear()
            self.cpu_ax.plot(self.system_monitor.history['cpu'], 
                           color=THEMES[self.current_theme]['accent1'])
            self.cpu_ax.set_ylim(0, 100)
            self.cpu_ax.set_title("CPU Usage %")
            self.cpu_canvas.draw()

            # Update Memory graph
            memory = psutil.virtual_memory()
            self.system_monitor.history['memory'].append(memory.percent)
            if len(self.system_monitor.history['memory']) > 60:
                self.system_monitor.history['memory'].pop(0)
            
            self.memory_ax.clear()
            self.memory_ax.plot(self.system_monitor.history['memory'], 
                              color=THEMES[self.current_theme]['accent2'])
            self.memory_ax.set_ylim(0, 100)
            self.memory_ax.set_title("Memory Usage %")
            self.memory_canvas.draw()

            # Update Network graph
            net_io = psutil.net_io_counters()
            bytes_total = net_io.bytes_sent + net_io.bytes_recv
            self.system_monitor.history['network'].append(bytes_total / 1024 / 1024)
            if len(self.system_monitor.history['network']) > 60:
                self.system_monitor.history['network'].pop(0)
            
            self.network_ax.clear()
            self.network_ax.plot(self.system_monitor.history['network'], 
                               color=THEMES[self.current_theme]['accent1'])
            self.network_ax.set_title("Network Usage (MB)")
            self.network_canvas.draw()

            # Update process list
            self.update_process_list()

        except Exception as e:
            logging.error(f"Error updating graphs: {str(e)}")

    def update_system_info_safe(self):
        """Update system info (called from main thread)"""
        try:
            if not hasattr(self, 'master') or not self.master.winfo_exists():
                return
                
            cpu = psutil.cpu_percent()
            ram = psutil.virtual_memory().percent
            self.system_info_label.config(
                text=f"CPU: {cpu}% | RAM: {ram}%"
            )
        except Exception as e:
            logging.error(f"Error updating system info: {str(e)}")
            self.system_info_label.config(text="System info unavailable")

    def stop_monitoring(self):
        """Stop all monitoring"""
        self.running = False
        if self.update_thread and self.update_thread.is_alive():
            self.update_thread.join(timeout=1)
        if self.system_info_thread and self.system_info_thread.is_alive():
            self.system_info_thread.join(timeout=1)

    def __del__(self):
        """Cleanup when the object is destroyed"""
        self.stop_monitoring()    



    def start_system_monitoring(self):
        """Start system monitoring updates"""
        def update_graphs():
            try:
                if not hasattr(self, 'master') or not self.master.winfo_exists():
                    return  # Stop updates if window is closed
                
                # Update CPU graph
                cpu_percent = psutil.cpu_percent(interval=1)
                self.system_monitor.history['cpu'].append(cpu_percent)
                if len(self.system_monitor.history['cpu']) > 60:
                    self.system_monitor.history['cpu'].pop(0)
                
                self.cpu_ax.clear()
                self.cpu_ax.plot(self.system_monitor.history['cpu'], 
                               color=THEMES[self.current_theme]['accent1'])
                self.cpu_ax.set_ylim(0, 100)
                self.cpu_ax.set_title("CPU Usage %")
                self.cpu_canvas.draw()

                # Update Memory graph
                memory = psutil.virtual_memory()
                self.system_monitor.history['memory'].append(memory.percent)
                if len(self.system_monitor.history['memory']) > 60:
                    self.system_monitor.history['memory'].pop(0)
                
                self.memory_ax.clear()
                self.memory_ax.plot(self.system_monitor.history['memory'], 
                                  color=THEMES[self.current_theme]['accent2'])
                self.memory_ax.set_ylim(0, 100)
                self.memory_ax.set_title("Memory Usage %")
                self.memory_canvas.draw()

                # Update Network graph
                net_io = psutil.net_io_counters()
                bytes_total = net_io.bytes_sent + net_io.bytes_recv
                self.system_monitor.history['network'].append(bytes_total / 1024 / 1024)
                if len(self.system_monitor.history['network']) > 60:
                    self.system_monitor.history['network'].pop(0)
                
                self.network_ax.clear()
                self.network_ax.plot(self.system_monitor.history['network'], 
                                   color=THEMES[self.current_theme]['accent1'])
                self.network_ax.set_title("Network Usage (MB)")
                self.network_canvas.draw()

                # Update process list
                self.update_process_list()

                # Schedule next update
                self.update_id = self.master.after(1000, update_graphs)
            except Exception as e:
                logging.error(f"Error updating system monitor: {str(e)}")

        # Start the update cycle
        update_graphs()

    def update_system_info(self):
        """Update system information in status bar"""
        try:
            if not hasattr(self, 'master') or not self.master.winfo_exists():
                return  # Stop updates if window is closed
                
            cpu = psutil.cpu_percent()
            ram = psutil.virtual_memory().percent
            self.system_info_label.config(
                text=f"CPU: {cpu}% | RAM: {ram}%"
            )
            
            # Schedule next update
            self.system_info_update_id = self.master.after(1000, self.update_system_info)
        except Exception as e:
            logging.error(f"Error updating system info: {str(e)}")
            self.system_info_label.config(text="System info unavailable")

    def stop_monitoring(self):
        """Stop all monitoring updates"""
        if self.update_id:
            self.master.after_cancel(self.update_id)
            self.update_id = None
            
        if self.system_info_update_id:
            self.master.after_cancel(self.system_info_update_id)
            self.system_info_update_id = None

    def __del__(self):
        """Cleanup when the object is destroyed"""
        self.stop_monitoring()

    def stop_scan(self):
        """Stop the current scan"""
        try:
            self.scanning = False
            self.scan_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.update_status("Scan stopped")
            self.update_progress(0)
        except Exception as e:
            logging.error(f"Error stopping scan: {str(e)}")

    def update_status(self, message):
        """Update status bar message"""
        try:
            self.status_label.config(text=message)
        except Exception as e:
            logging.error(f"Error updating status: {str(e)}")

    def update_progress(self, value):
        """Update progress bar"""
        try:
            self.progress_bar['value'] = value
            self.master.update_idletasks()
        except Exception as e:
            logging.error(f"Error updating progress: {str(e)}")

    def scan_completed(self):
        """Handle scan completion"""
        try:
            self.scanning = False
            self.scan_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.update_status("Scan completed")
            self.update_progress(0)
        except Exception as e:
            logging.error(f"Error in scan completion: {str(e)}")

    def setup_gui(self):
        # Configure the main window
        self.master.configure(bg=THEMES[self.current_theme]['bg'])
        self.master.geometry("1200x800")
        
        # Create main container
        self.main_container = ttk.Frame(self.master)
        self.main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Create banner
        self.create_banner()
        
        # Create notebook for tabs
        self.notebook = CustomNotebook(self.main_container)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Create various tabs
        self.create_dashboard_tab()
        self.create_scanner_tab()
        self.create_network_tools_tab()
        self.create_system_monitor_tab()
        self.create_vulnerability_tab()
        
        # Create status bar
        self.create_status_bar()

    
    def execute_speed_test(self):
        """Execute internet speed test"""
        self.speedtest_button.config(state=tk.DISABLED)
        self.download_label.config(text="Download: Testing...")
        self.upload_label.config(text="Upload: Testing...")
        self.ping_label.config(text="Ping: Testing...")
        self.speedtest_progress['value'] = 0

        def update_progress(message):
            if "download" in message.lower():
                self.speedtest_progress['value'] = 33
            elif "upload" in message.lower():
                self.speedtest_progress['value'] = 66
            self.master.update_idletasks()

        def speed_test_thread():
            try:
                results = self.speed_tester.test_speed(progress_callback=update_progress)
                
                if isinstance(results, str):  # Error occurred
                    messagebox.showerror("Error", results)
                    self.download_label.config(text="Download: -- Mbps")
                    self.upload_label.config(text="Upload: -- Mbps")
                    self.ping_label.config(text="Ping: -- ms")
                else:
                    # Update results
                    self.download_label.config(
                        text=f"Download: {results['download']:.2f} Mbps"
                    )
                    self.upload_label.config(
                        text=f"Upload: {results['upload']:.2f} Mbps"
                    )
                    self.ping_label.config(
                        text=f"Ping: {results['ping']:.0f} ms"
                    )
                    self.speedtest_progress['value'] = 100

            except Exception as e:
                messagebox.showerror(
                    "Error", 
                    f"Failed to complete speed test: {str(e)}"
                )
                self.download_label.config(text="Download: Error")
                self.upload_label.config(text="Upload: Error")
                self.ping_label.config(text="Ping: Error")
            finally:
                self.speedtest_button.config(state=tk.NORMAL)
                self.speedtest_progress['value'] = 0

        # Run speed test in separate thread
        threading.Thread(target=speed_test_thread).start()

    def update_speed_test_progress(self, progress):
        """Update speed test progress bar"""
        try:
            self.speedtest_progress['value'] = progress
            self.master.update_idletasks()
        except Exception as e:
            logging.error(f"Error updating speed test progress: {str(e)}")

    def format_speed(self, speed_bps):
        """Format speed in bits per second to appropriate unit"""
        units = ['bps', 'Kbps', 'Mbps', 'Gbps']
        unit_index = 0
        
        while speed_bps >= 1000 and unit_index < len(units) - 1:
            speed_bps /= 1000
            unit_index += 1
            
        return f"{speed_bps:.2f} {units[unit_index]}"
    

    def start_ping(self):
        """Execute ping command"""
        target = self.ping_target.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target")
            return

        try:
            count = int(self.ping_count.get())
        except ValueError:
            count = 4

        self.ping_button.config(state=tk.DISABLED)
        self.ping_results.delete(1.0, tk.END)
        self.ping_results.insert(tk.END, f"Pinging {target}...\n\n")

        def ping_thread():
            try:
                result = NetworkUtils.ping(target, count)
                self.ping_results.insert(tk.END, result)
            except Exception as e:
                self.ping_results.insert(tk.END, f"Error: {str(e)}")
            finally:
                self.ping_button.config(state=tk.NORMAL)

        threading.Thread(target=ping_thread).start()

    def start_traceroute(self):
        """Execute traceroute command"""
        target = self.traceroute_target.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target")
            return

        self.traceroute_button.config(state=tk.DISABLED)
        self.traceroute_results.delete(1.0, tk.END)
        self.traceroute_results.insert(tk.END, f"Tracing route to {target}...\n\n")

        def traceroute_thread():
            try:
                result = NetworkUtils.traceroute(target)
                self.traceroute_results.insert(tk.END, result)
            except Exception as e:
                self.traceroute_results.insert(tk.END, f"Error: {str(e)}")
            finally:
                self.traceroute_button.config(state=tk.NORMAL)

        threading.Thread(target=traceroute_thread).start()

    def start_dns_lookup(self):
        """Execute DNS lookup"""
        domain = self.dns_domain.get().strip()
        if not domain:
            messagebox.showerror("Error", "Please enter a domain")
            return

        self.dns_button.config(state=tk.DISABLED)
        self.dns_results.delete(1.0, tk.END)
        self.dns_results.insert(tk.END, f"Looking up DNS records for {domain}...\n\n")

        def dns_thread():
            try:
                results = NetworkUtils.dns_lookup(domain)
                for result in results:
                    self.dns_results.insert(tk.END, f"{result}\n")
            except Exception as e:
                self.dns_results.insert(tk.END, f"Error: {str(e)}")
            finally:
                self.dns_button.config(state=tk.NORMAL)

        threading.Thread(target=dns_thread).start()

    def start_whois_lookup(self):
        """Execute WHOIS lookup"""
        domain = self.whois_domain.get().strip()
        if not domain:
            messagebox.showerror("Error", "Please enter a domain")
            return

        self.whois_button.config(state=tk.DISABLED)
        self.whois_results.delete(1.0, tk.END)
        self.whois_results.insert(tk.END, f"Looking up WHOIS information for {domain}...\n\n")

        def whois_thread():
            try:
                result = NetworkUtils.whois_lookup(domain)
                if isinstance(result, dict):
                    for key, value in result.items():
                        if value:
                            self.whois_results.insert(tk.END, f"{key}: {value}\n")
                else:
                    self.whois_results.insert(tk.END, str(result))
            except Exception as e:
                self.whois_results.insert(tk.END, f"Error: {str(e)}")
            finally:
                self.whois_button.config(state=tk.NORMAL)

        threading.Thread(target=whois_thread).start()

    def start_scan(self):
        """Start network scan"""
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target")
            return

        try:
            start_port = int(self.start_port.get())
            end_port = int(self.end_port.get())
        except ValueError:
            messagebox.showerror("Error", "Invalid port numbers")
            return

        self.scan_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        self.progress_bar['value'] = 0
        self.scanning = True

        def scan_thread():
            try:
                self.results_text.insert(tk.END, f"Starting scan of {target}...\n\n")
                
                # Configure scan options
                arguments = []
                if self.os_detection.get():
                    arguments.append('-O')
                if self.service_detection.get():
                    arguments.append('-sV')
                if self.aggressive_scan.get():
                    arguments.append('-T4')

                # Start scan
                results = self.network_mapper.scan_network(
                    target,
                    f"{start_port}-{end_port}",
                    ' '.join(arguments)
                )

                # Display results
                if isinstance(results, str):  # Error occurred
                    self.results_text.insert(tk.END, results)
                else:
                    self.display_scan_results(results)

            except Exception as e:
                self.results_text.insert(tk.END, f"Error: {str(e)}")
            finally:
                self.scan_completed()

    def create_system_monitor_tab(self):
        """Create system monitor tab"""
        monitor_frame = ttk.Frame(self.notebook)
        self.notebook.add(monitor_frame, text="System Monitor")

        # Create left and right frames
        left_frame = ttk.Frame(monitor_frame)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        right_frame = ttk.Frame(monitor_frame)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        # CPU Usage Graph
        cpu_frame = ttk.LabelFrame(left_frame, text="CPU Usage", padding=10)
        cpu_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        self.cpu_figure, self.cpu_ax = plt.subplots(figsize=(6, 3))
        self.cpu_figure.patch.set_facecolor(THEMES[self.current_theme]['bg'])
        self.cpu_ax.set_facecolor(THEMES[self.current_theme]['bg'])
        self.cpu_ax.tick_params(colors=THEMES[self.current_theme]['fg'])
        
        self.cpu_canvas = FigureCanvasTkAgg(self.cpu_figure, master=cpu_frame)
        self.cpu_canvas.draw()
        self.cpu_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        # Memory Usage Graph
        memory_frame = ttk.LabelFrame(left_frame, text="Memory Usage", padding=10)
        memory_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        self.memory_figure, self.memory_ax = plt.subplots(figsize=(6, 3))
        self.memory_figure.patch.set_facecolor(THEMES[self.current_theme]['bg'])
        self.memory_ax.set_facecolor(THEMES[self.current_theme]['bg'])
        self.memory_ax.tick_params(colors=THEMES[self.current_theme]['fg'])
        
        self.memory_canvas = FigureCanvasTkAgg(self.memory_figure, master=memory_frame)
        self.memory_canvas.draw()
        self.memory_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        # Network Usage Graph
        network_frame = ttk.LabelFrame(right_frame, text="Network Usage", padding=10)
        network_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        self.network_figure, self.network_ax = plt.subplots(figsize=(6, 3))
        self.network_figure.patch.set_facecolor(THEMES[self.current_theme]['bg'])
        self.network_ax.set_facecolor(THEMES[self.current_theme]['bg'])
        self.network_ax.tick_params(colors=THEMES[self.current_theme]['fg'])
        
        self.network_canvas = FigureCanvasTkAgg(self.network_figure, master=network_frame)
        self.network_canvas.draw()
        self.network_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        # Process List
        process_frame = ttk.LabelFrame(right_frame, text="Process List", padding=10)
        process_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        # Create treeview for processes
        columns = ("PID", "Name", "CPU %", "Memory %", "Status")
        self.process_tree = ttk.Treeview(
            process_frame,
            columns=columns,
            show="headings",
            height=10
        )

        # Configure columns
        for col in columns:
            self.process_tree.heading(col, text=col)
            self.process_tree.column(col, width=80)

        # Add scrollbar
        scrollbar = ttk.Scrollbar(
            process_frame,
            orient=tk.VERTICAL,
            command=self.process_tree.yview
        )
        self.process_tree.configure(yscrollcommand=scrollbar.set)

        # Pack elements
        self.process_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Start monitoring
        self.start_system_monitoring()

    def start_system_monitoring(self):
        """Start system monitoring updates"""
        def update_graphs():
            try:
                # Update CPU graph
                cpu_percent = psutil.cpu_percent(interval=1)
                self.system_monitor.history['cpu'].append(cpu_percent)
                if len(self.system_monitor.history['cpu']) > 60:
                    self.system_monitor.history['cpu'].pop(0)
                
                self.cpu_ax.clear()
                self.cpu_ax.plot(self.system_monitor.history['cpu'], 
                               color=THEMES[self.current_theme]['accent1'])
                self.cpu_ax.set_ylim(0, 100)
                self.cpu_ax.set_title("CPU Usage %")
                self.cpu_canvas.draw()

                # Update Memory graph
                memory = psutil.virtual_memory()
                self.system_monitor.history['memory'].append(memory.percent)
                if len(self.system_monitor.history['memory']) > 60:
                    self.system_monitor.history['memory'].pop(0)
                
                self.memory_ax.clear()
                self.memory_ax.plot(self.system_monitor.history['memory'], 
                                  color=THEMES[self.current_theme]['accent2'])
                self.memory_ax.set_ylim(0, 100)
                self.memory_ax.set_title("Memory Usage %")
                self.memory_canvas.draw()

                # Update Network graph
                net_io = psutil.net_io_counters()
                bytes_total = net_io.bytes_sent + net_io.bytes_recv
                self.system_monitor.history['network'].append(bytes_total / 1024 / 1024)  # Convert to MB
                if len(self.system_monitor.history['network']) > 60:
                    self.system_monitor.history['network'].pop(0)
                
                self.network_ax.clear()
                self.network_ax.plot(self.system_monitor.history['network'], 
                                   color=THEMES[self.current_theme]['accent1'])
                self.network_ax.set_title("Network Usage (MB)")
                self.network_canvas.draw()

                # Update process list
                self.update_process_list()

                # Schedule next update
                self.master.after(1000, update_graphs)
            except Exception as e:
                logging.error(f"Error updating system monitor: {str(e)}")

        update_graphs()

    def update_process_list(self):
        """Update the process list"""
        try:
            # Clear current items
            for item in self.process_tree.get_children():
                self.process_tree.delete(item)

            # Get process information
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'status']):
                try:
                    info = proc.info
                    self.process_tree.insert('', tk.END, values=(
                        info['pid'],
                        info['name'],
                        f"{info['cpu_percent']:.1f}",
                        f"{info['memory_percent']:.1f}",
                        info['status']
                    ))
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        except Exception as e:
            logging.error(f"Error updating process list: {str(e)}")


    def create_vulnerability_tab(self):
        """Create vulnerability scanner tab"""
        vuln_frame = ttk.Frame(self.notebook)
        self.notebook.add(vuln_frame, text="Vulnerability Scanner")

        # Create left and right panes
        left_pane = ttk.Frame(vuln_frame)
        left_pane.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        right_pane = ttk.Frame(vuln_frame)
        right_pane.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Scan Configuration (Left Pane)
        config_frame = ttk.LabelFrame(left_pane, text="Scan Configuration", padding=10)
        config_frame.pack(fill=tk.X, pady=5)

        # Target input
        ttk.Label(config_frame, text="Target:").pack(fill=tk.X, pady=2)
        self.vuln_target = ttk.Entry(config_frame)
        self.vuln_target.pack(fill=tk.X, pady=2)

        # Scan type selection
        ttk.Label(config_frame, text="Scan Type:").pack(fill=tk.X, pady=2)
        self.scan_type = ttk.Combobox(config_frame, 
            values=["Quick Scan", "Full Scan", "Custom Scan"])
        self.scan_type.pack(fill=tk.X, pady=2)
        self.scan_type.set("Quick Scan")

        # Vulnerability categories
        categories_frame = ttk.LabelFrame(left_pane, text="Vulnerability Categories", padding=10)
        categories_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        # Checkboxes for different vulnerability types
        self.vuln_categories = {
            'web_vulns': tk.BooleanVar(value=True),
            'network_vulns': tk.BooleanVar(value=True),
            'service_vulns': tk.BooleanVar(value=True),
            'auth_vulns': tk.BooleanVar(value=True),
            'malware': tk.BooleanVar(value=True)
        }

        for category, var in self.vuln_categories.items():
            ttk.Checkbutton(
                categories_frame, 
                text=category.replace('_', ' ').title(),
                variable=var
            ).pack(fill=tk.X, pady=2)

        # Control buttons
        button_frame = ttk.Frame(left_pane)
        button_frame.pack(fill=tk.X, pady=5)

        self.start_vuln_scan = ttk.Button(
            button_frame,
            text="Start Scan",
            command=self.start_vulnerability_scan
        )
        self.start_vuln_scan.pack(side=tk.LEFT, padx=5)

        self.stop_vuln_scan = ttk.Button(
            button_frame,
            text="Stop Scan",
            command=self.stop_vulnerability_scan,
            state=tk.DISABLED
        )
        self.stop_vuln_scan.pack(side=tk.LEFT, padx=5)

        # Results Area (Right Pane)
        results_frame = ttk.LabelFrame(right_pane, text="Scan Results", padding=10)
        results_frame.pack(fill=tk.BOTH, expand=True)

        # Create treeview for vulnerabilities
        columns = ("Severity", "Type", "Description", "Solution")
        self.vuln_tree = ttk.Treeview(
            results_frame,
            columns=columns,
            show="headings",
            height=20
        )

        # Configure columns
        for col in columns:
            self.vuln_tree.heading(col, text=col)
            self.vuln_tree.column(col, width=100)

        # Add scrollbar
        scrollbar = ttk.Scrollbar(
            results_frame,
            orient=tk.VERTICAL,
            command=self.vuln_tree.yview
        )
        self.vuln_tree.configure(yscrollcommand=scrollbar.set)

        # Pack elements
        self.vuln_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Progress frame
        progress_frame = ttk.Frame(right_pane)
        progress_frame.pack(fill=tk.X, pady=5)

        self.vuln_progress = ttk.Progressbar(
            progress_frame,
            mode='determinate',
            length=200
        )
        self.vuln_progress.pack(fill=tk.X)

        self.vuln_status = ttk.Label(
            progress_frame,
            text="Ready to scan"
        )
        self.vuln_status.pack(fill=tk.X)

    def start_vulnerability_scan(self):
        """Start vulnerability scan"""
        target = self.vuln_target.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target")
            return

        # Update UI
        self.start_vuln_scan.config(state=tk.DISABLED)
        self.stop_vuln_scan.config(state=tk.NORMAL)
        self.vuln_progress['value'] = 0
        self.vuln_status.config(text="Scanning...")

        # Clear previous results
        for item in self.vuln_tree.get_children():
            self.vuln_tree.delete(item)

        def scan_thread():
            try:
                # Get selected categories
                categories = [cat for cat, var in self.vuln_categories.items() 
                            if var.get()]

                # Perform scan based on type
                scan_type = self.scan_type.get()
                if scan_type == "Quick Scan":
                    self.quick_vulnerability_scan(target, categories)
                elif scan_type == "Full Scan":
                    self.full_vulnerability_scan(target, categories)
                else:
                    self.custom_vulnerability_scan(target, categories)

            except Exception as e:
                messagebox.showerror("Error", f"Scan failed: {str(e)}")
                self.vuln_status.config(text="Scan failed")
            finally:
                self.start_vuln_scan.config(state=tk.NORMAL)
                self.stop_vuln_scan.config(state=tk.DISABLED)

        threading.Thread(target=scan_thread).start()

    def stop_vulnerability_scan(self):
        """Stop vulnerability scan"""
        self.scanning = False
        self.vuln_status.config(text="Scan stopped")
        self.start_vuln_scan.config(state=tk.NORMAL)
        self.stop_vuln_scan.config(state=tk.DISABLED)

    def add_vulnerability(self, severity, vuln_type, description, solution):
        """Add vulnerability to results tree"""
        self.vuln_tree.insert('', tk.END, values=(
            severity,
            vuln_type,
            description,
            solution
        ))        



    def create_status_bar(self):
        """Create application status bar"""
        status_frame = ttk.Frame(self.main_container)
        status_frame.pack(fill=tk.X, side=tk.BOTTOM, pady=(5, 0))

        # Status label
        self.status_label = ttk.Label(
            status_frame,
            text="Ready",
            padding=(5, 2)
        )
        self.status_label.pack(side=tk.LEFT)

        # Progress bar
        self.progress_bar = ttk.Progressbar(
            status_frame,
            mode='determinate',
            length=200
        )
        self.progress_bar.pack(side=tk.RIGHT, padx=5)

        # System info
        self.system_info_label = ttk.Label(
            status_frame,
            text=f"CPU: {psutil.cpu_percent()}% | RAM: {psutil.virtual_memory().percent}%",
            padding=(5, 2)
        )
        self.system_info_label.pack(side=tk.RIGHT, padx=10)

        # Start system info updates
        self.update_system_info()

    def update_system_info(self):
        """Update system information in status bar"""
        try:
            cpu = psutil.cpu_percent()
            ram = psutil.virtual_memory().percent
            self.system_info_label.config(
                text=f"CPU: {cpu}% | RAM: {ram}%"
            )
        except Exception as e:
            logging.error(f"Error updating system info: {str(e)}")
            self.system_info_label.config(text="System info unavailable")

        # Schedule next update
        self.master.after(1000, self.update_system_info)

    def update_status(self, message):
        """Update status bar message"""
        try:
            self.status_label.config(text=message)
        except Exception as e:
            logging.error(f"Error updating status: {str(e)}")

    def update_progress(self, value):
        """Update progress bar value"""
        try:
            self.progress_bar['value'] = value
            self.master.update_idletasks()
        except Exception as e:
            logging.error(f"Error updating progress: {str(e)}")




    



    


    def create_system_status_widget(self, parent, row, column):
        """Create system status widget"""
        frame = ttk.LabelFrame(
            parent,
            text="System Status",
            padding=10
        )
        frame.grid(row=row, column=column, padx=5, pady=5, sticky='nsew')

        # CPU Usage
        ttk.Label(frame, text="CPU Usage:").pack(fill=tk.X)
        self.cpu_progress = ttk.Progressbar(frame, mode='determinate')
        self.cpu_progress.pack(fill=tk.X, pady=(0, 10))

        # Memory Usage
        ttk.Label(frame, text="Memory Usage:").pack(fill=tk.X)
        self.memory_progress = ttk.Progressbar(frame, mode='determinate')
        self.memory_progress.pack(fill=tk.X, pady=(0, 10))

        # Network Usage
        ttk.Label(frame, text="Network Usage:").pack(fill=tk.X)
        self.network_progress = ttk.Progressbar(frame, mode='determinate')
        self.network_progress.pack(fill=tk.X)

    def create_scanner_tab(self):
        """Create network scanner tab"""
        scanner_frame = ttk.Frame(self.notebook)
        self.notebook.add(scanner_frame, text="Network Scanner")

        # Target configuration
        target_frame = ttk.LabelFrame(scanner_frame, text="Target Configuration", padding=10)
        target_frame.pack(fill=tk.X, padx=5, pady=5)

        # Target input
        ttk.Label(target_frame, text="Target:").grid(row=0, column=0, padx=5, pady=5)
        self.target_entry = ttk.Entry(target_frame, width=40)
        self.target_entry.grid(row=0, column=1, padx=5, pady=5)
        self.target_entry.insert(0, "192.168.1.0/24")  # Default value

        # Port range
        ttk.Label(target_frame, text="Port Range:").grid(row=1, column=0, padx=5, pady=5)
        port_frame = ttk.Frame(target_frame)
        port_frame.grid(row=1, column=1, sticky='w')

        self.start_port = ttk.Entry(port_frame, width=10)
        self.start_port.pack(side=tk.LEFT, padx=5)
        self.start_port.insert(0, "1")

        ttk.Label(port_frame, text="-").pack(side=tk.LEFT)

        self.end_port = ttk.Entry(port_frame, width=10)
        self.end_port.pack(side=tk.LEFT, padx=5)
        self.end_port.insert(0, "1024")

        # Scan options
        options_frame = ttk.LabelFrame(scanner_frame, text="Scan Options", padding=10)
        options_frame.pack(fill=tk.X, padx=5, pady=5)

        # Checkboxes for scan options
        self.os_detection = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="OS Detection", 
                       variable=self.os_detection).pack(side=tk.LEFT, padx=5)

        self.service_detection = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Service Detection", 
                       variable=self.service_detection).pack(side=tk.LEFT, padx=5)

        self.aggressive_scan = tk.BooleanVar(value=False)
        ttk.Checkbutton(options_frame, text="Aggressive Scan", 
                       variable=self.aggressive_scan).pack(side=tk.LEFT, padx=5)

        # Control buttons
        button_frame = ttk.Frame(scanner_frame)
        button_frame.pack(fill=tk.X, padx=5, pady=5)

        self.scan_button = ttk.Button(button_frame, text="Start Scan", 
                                    command=self.start_scan)
        self.scan_button.pack(side=tk.LEFT, padx=5)

        self.stop_button = ttk.Button(button_frame, text="Stop", 
                                    command=self.stop_scan,
                                    state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        # Progress bar
        self.progress_bar = ttk.Progressbar(scanner_frame, mode='determinate')
        self.progress_bar.pack(fill=tk.X, padx=5, pady=5)

        # Results area
        self.results_text = tk.Text(scanner_frame, height=20, wrap=tk.WORD,
                                  bg=THEMES[self.current_theme]['bg'],
                                  fg=THEMES[self.current_theme]['fg'])
        self.results_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Add scrollbar to results
        scrollbar = ttk.Scrollbar(scanner_frame, command=self.results_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.results_text.configure(yscrollcommand=scrollbar.set)



    def create_network_tools_tab(self):
        """Create network tools tab"""
        tools_frame = ttk.Frame(self.notebook)
        self.notebook.add(tools_frame, text="Network Tools")

        # Create notebook for different tools
        tools_notebook = ttk.Notebook(tools_frame)
        tools_notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Create tabs for different tools
        self.create_ping_tool(tools_notebook)
        self.create_traceroute_tool(tools_notebook)
        self.create_dns_tool(tools_notebook)
        self.create_whois_tool(tools_notebook)
        self.create_speed_test_tool(tools_notebook)

    def create_ping_tool(self, parent):
        """Create ping tool interface"""
        ping_frame = ttk.Frame(parent)
        parent.add(ping_frame, text="Ping")

        # Target input
        ttk.Label(ping_frame, text="Target:").pack(fill=tk.X, padx=5, pady=5)
        self.ping_target = ttk.Entry(ping_frame)
        self.ping_target.pack(fill=tk.X, padx=5)

        # Options frame
        options_frame = ttk.Frame(ping_frame)
        options_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(options_frame, text="Count:").pack(side=tk.LEFT, padx=5)
        self.ping_count = ttk.Entry(options_frame, width=5)
        self.ping_count.pack(side=tk.LEFT, padx=5)
        self.ping_count.insert(0, "4")

        # Start button
        self.ping_button = ttk.Button(ping_frame, text="Start Ping",
                                    command=self.start_ping)
        self.ping_button.pack(fill=tk.X, padx=5, pady=5)

        # Results area
        self.ping_results = tk.Text(ping_frame, height=15, wrap=tk.WORD,
                                  bg=THEMES[self.current_theme]['bg'],
                                  fg=THEMES[self.current_theme]['fg'])
        self.ping_results.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def create_traceroute_tool(self, parent):
        """Create traceroute tool interface"""
        traceroute_frame = ttk.Frame(parent)
        parent.add(traceroute_frame, text="Traceroute")

        # Target input
        ttk.Label(traceroute_frame, text="Target:").pack(fill=tk.X, padx=5, pady=5)
        self.traceroute_target = ttk.Entry(traceroute_frame)
        self.traceroute_target.pack(fill=tk.X, padx=5)

        # Start button
        self.traceroute_button = ttk.Button(traceroute_frame, text="Start Traceroute",
                                          command=self.start_traceroute)
        self.traceroute_button.pack(fill=tk.X, padx=5, pady=5)

        # Results area
        self.traceroute_results = tk.Text(traceroute_frame, height=15, wrap=tk.WORD,
                                        bg=THEMES[self.current_theme]['bg'],
                                        fg=THEMES[self.current_theme]['fg'])
        self.traceroute_results.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def create_dns_tool(self, parent):
        """Create DNS lookup tool interface"""
        dns_frame = ttk.Frame(parent)
        parent.add(dns_frame, text="DNS Lookup")

        # Domain input
        ttk.Label(dns_frame, text="Domain:").pack(fill=tk.X, padx=5, pady=5)
        self.dns_domain = ttk.Entry(dns_frame)
        self.dns_domain.pack(fill=tk.X, padx=5)

        # Record type selection
        ttk.Label(dns_frame, text="Record Type:").pack(fill=tk.X, padx=5, pady=5)
        self.dns_record_type = ttk.Combobox(dns_frame, 
                                          values=["A", "AAAA", "MX", "NS", "TXT", "ALL"])
        self.dns_record_type.pack(fill=tk.X, padx=5)
        self.dns_record_type.set("ALL")

        # Start button
        self.dns_button = ttk.Button(dns_frame, text="Lookup",
                                   command=self.start_dns_lookup)
        self.dns_button.pack(fill=tk.X, padx=5, pady=5)

        # Results area
        self.dns_results = tk.Text(dns_frame, height=15, wrap=tk.WORD,
                                 bg=THEMES[self.current_theme]['bg'],
                                 fg=THEMES[self.current_theme]['fg'])
        self.dns_results.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def create_whois_tool(self, parent):
        """Create WHOIS lookup tool interface"""
        whois_frame = ttk.Frame(parent)
        parent.add(whois_frame, text="WHOIS")

        # Domain input
        ttk.Label(whois_frame, text="Domain:").pack(fill=tk.X, padx=5, pady=5)
        self.whois_domain = ttk.Entry(whois_frame)
        self.whois_domain.pack(fill=tk.X, padx=5)

        # Start button
        self.whois_button = ttk.Button(whois_frame, text="Lookup",
                                     command=self.start_whois_lookup)
        self.whois_button.pack(fill=tk.X, padx=5, pady=5)

        # Results area
        self.whois_results = tk.Text(whois_frame, height=15, wrap=tk.WORD,
                                   bg=THEMES[self.current_theme]['bg'],
                                   fg=THEMES[self.current_theme]['fg'])
        self.whois_results.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def create_speed_test_tool(self, parent):
        """Create speed test tool interface"""
        speed_frame = ttk.Frame(parent)
        parent.add(speed_frame, text="Speed Test")

        # Start button
        self.speedtest_button = ttk.Button(speed_frame, text="Start Speed Test",
                                         command=self.execute_speed_test)
        self.speedtest_button.pack(fill=tk.X, padx=5, pady=5)

        # Progress bar
        self.speedtest_progress = ttk.Progressbar(speed_frame, mode='determinate')
        self.speedtest_progress.pack(fill=tk.X, padx=5, pady=5)

        # Results labels
        self.download_label = ttk.Label(speed_frame, text="Download: -- Mbps")
        self.download_label.pack(fill=tk.X, padx=5, pady=5)

        self.upload_label = ttk.Label(speed_frame, text="Upload: -- Mbps")
        self.upload_label.pack(fill=tk.X, padx=5, pady=5)

        self.ping_label = ttk.Label(speed_frame, text="Ping: -- ms")
        self.ping_label.pack(fill=tk.X, padx=5, pady=5)



    def create_dashboard_tab(self):
        """Create the main dashboard tab"""
        dashboard_frame = ttk.Frame(self.notebook)
        self.notebook.add(dashboard_frame, text="Dashboard")

        # Create grid layout
        dashboard_frame.columnconfigure(0, weight=1)
        dashboard_frame.columnconfigure(1, weight=1)

        # Create dashboard widgets
        self.create_quick_scan_widget(dashboard_frame, 0, 0)
        self.create_system_status_widget(dashboard_frame, 0, 1)
        self.create_network_activity_widget(dashboard_frame, 1, 0)
        self.create_recent_scans_widget(dashboard_frame, 1, 1)

        # Initialize data
        self.update_dashboard()

    def update_dashboard(self):
        """Update dashboard data periodically"""
        try:
            # Update system status
            cpu_usage = psutil.cpu_percent()
            memory = psutil.virtual_memory()
            self.cpu_progress['value'] = cpu_usage
            self.memory_progress['value'] = memory.percent

            # Update network activity
            net_io = psutil.net_io_counters()
            self.network_progress['value'] = (net_io.bytes_sent + net_io.bytes_recv) % 100

            # Schedule next update
            self.master.after(1000, self.update_dashboard)
        except Exception as e:
            logging.error(f"Error updating dashboard: {str(e)}")
    

    def create_banner(self):
        """Create the application banner"""
        banner_frame = ttk.Frame(self.main_container)
        banner_frame.pack(fill=tk.X, pady=(0, 10))

        # ASCII Art Banner
        banner_text = tk.Text(
            banner_frame,
            height=10,
            width=80,
            font=('Courier', 10, 'bold'),
            bg=THEMES[self.current_theme]['bg'],
            fg=THEMES[self.current_theme]['accent1'],
            relief=tk.FLAT,
            padx=10,
            pady=10
        )
        banner_text.pack(fill=tk.X)
        banner_text.insert('1.0', BANNER)
        banner_text.configure(state='disabled')

        # Version and author info
        info_frame = ttk.Frame(banner_frame)
        info_frame.pack(fill=tk.X, padx=10)

        version_label = ttk.Label(
            info_frame,
            text="Version 1.0",
            font=('Arial', 8)
        )
        version_label.pack(side=tk.LEFT)

        author_label = ttk.Label(
            info_frame,
            text="By Daniel Goldstein",
            font=('Arial', 8)
        )
        author_label.pack(side=tk.RIGHT)

        # Add separator
        ttk.Separator(banner_frame, orient='horizontal').pack(
            fill=tk.X, 
            padx=10, 
            pady=(5, 0)
        )

def create_quick_scan_widget(self, parent, row, column):
        """Create quick scan widget"""
        frame = ttk.LabelFrame(
            parent,
            text="Quick Scan",
            padding=10
        )
        frame.grid(row=row, column=column, padx=5, pady=5, sticky='nsew')

        # Target input
        ttk.Label(frame, text="Target:").pack(fill=tk.X, pady=(0, 5))
        self.quick_scan_entry = ttk.Entry(frame)
        self.quick_scan_entry.pack(fill=tk.X, pady=(0, 10))

        # Scan button
        self.quick_scan_button = ttk.Button(
            frame,
            text="Start Quick Scan",
            command=self.start_quick_scan
        )
        self.quick_scan_button.pack(fill=tk.X)

def create_system_status_widget(self, parent, row, column):
        """Create system status widget"""
        frame = ttk.LabelFrame(
            parent,
            text="System Status",
            padding=10
        )
        frame.grid(row=row, column=column, padx=5, pady=5, sticky='nsew')

        # CPU Usage
        ttk.Label(frame, text="CPU Usage:").pack(fill=tk.X)
        self.cpu_progress = ttk.Progressbar(frame, mode='determinate')
        self.cpu_progress.pack(fill=tk.X, pady=(0, 10))

        # Memory Usage
        ttk.Label(frame, text="Memory Usage:").pack(fill=tk.X)
        self.memory_progress = ttk.Progressbar(frame, mode='determinate')
        self.memory_progress.pack(fill=tk.X, pady=(0, 10))

        # Network Usage
        ttk.Label(frame, text="Network Usage:").pack(fill=tk.X)
        self.network_progress = ttk.Progressbar(frame, mode='determinate')
        self.network_progress.pack(fill=tk.X)

def create_network_activity_widget(self, parent, row, column):
        """Create network activity widget"""
        frame = ttk.LabelFrame(
            parent,
            text="Network Activity",
            padding=10
        )
        frame.grid(row=row, column=column, padx=5, pady=5, sticky='nsew')

        # Network graph
        self.network_figure, self.network_ax = plt.subplots(figsize=(6, 3))
        self.network_figure.patch.set_facecolor(THEMES[self.current_theme]['bg'])
        self.network_ax.set_facecolor(THEMES[self.current_theme]['bg'])
        self.network_ax.tick_params(colors=THEMES[self.current_theme]['fg'])
        
        self.network_canvas = FigureCanvasTkAgg(self.network_figure, master=frame)
        self.network_canvas.draw()
        self.network_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

def create_recent_scans_widget(self, parent, row, column):
        """Create recent scans widget"""
        frame = ttk.LabelFrame(
            parent,
            text="Recent Scans",
            padding=10
        )
        frame.grid(row=row, column=column, padx=5, pady=5, sticky='nsew')

        # Create treeview for recent scans
        columns = ("Time", "Target", "Type", "Results")
        self.recent_scans_tree = ttk.Treeview(
            frame,
            columns=columns,
            show="headings",
            height=6
        )

        # Configure columns
        for col in columns:
            self.recent_scans_tree.heading(col, text=col)
            self.recent_scans_tree.column(col, width=100)

        # Add scrollbar
        scrollbar = ttk.Scrollbar(
            frame,
            orient=tk.VERTICAL,
            command=self.recent_scans_tree.yview
        )
        self.recent_scans_tree.configure(yscrollcommand=scrollbar.set)

        # Pack elements
        self.recent_scans_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    
def stop_vuln_scan(self):
        """Stop vulnerability scan"""
        try:
            self.scanning = False
            self.vuln_scan_button.config(state=tk.NORMAL)
            self.vuln_stop_button.config(state=tk.DISABLED)
            self.update_status("Vulnerability scan stopped")
            self.vuln_progress['value'] = 0
        except Exception as e:
            logging.error(f"Error stopping vulnerability scan: {str(e)}")

def create_vuln_scanner_interface(self, parent):
        """Create vulnerability scanner interface"""
        # Target configuration
        target_frame = ttk.LabelFrame(parent, text="Target Configuration", padding=10)
        target_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(target_frame, text="Target:").grid(row=0, column=0, padx=5, pady=5)
        self.vuln_target_entry = ttk.Entry(target_frame, width=40)
        self.vuln_target_entry.grid(row=0, column=1, padx=5, pady=5)

        # Scan options
        options_frame = ttk.LabelFrame(parent, text="Scan Options", padding=10)
        options_frame.pack(fill=tk.X, padx=5, pady=5)

        self.check_ports = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Port Vulnerabilities", 
                       variable=self.check_ports).pack(side=tk.LEFT, padx=5)

        self.check_services = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Service Vulnerabilities", 
                       variable=self.check_services).pack(side=tk.LEFT, padx=5)

        self.check_web = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Web Vulnerabilities", 
                       variable=self.check_web).pack(side=tk.LEFT, padx=5)

        # Control buttons
        button_frame = ttk.Frame(parent)
        button_frame.pack(fill=tk.X, padx=5, pady=5)

        self.vuln_scan_button = ttk.Button(button_frame, text="Start Scan", 
                                         command=self.start_vuln_scan)
        self.vuln_scan_button.pack(side=tk.LEFT, padx=5)

        self.vuln_stop_button = ttk.Button(button_frame, text="Stop", 
                                         command=self.stop_vuln_scan,
                                         state=tk.DISABLED)
        self.vuln_stop_button.pack(side=tk.LEFT, padx=5)

        # Progress bar
        self.vuln_progress = ttk.Progressbar(parent, mode='determinate')
        self.vuln_progress.pack(fill=tk.X, padx=5, pady=5)

        # Results area
        self.vuln_results = tk.Text(parent, height=20, wrap=tk.WORD,
                                  bg=THEMES[self.current_theme]['bg'],
                                  fg=THEMES[self.current_theme]['fg'])
        self.vuln_results.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
 
def start_vuln_scan(self):
        """Start vulnerability scan"""
        target = self.vuln_target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target")
            return

        self.vuln_scan_button.config(state=tk.DISABLED)
        self.vuln_stop_button.config(state=tk.NORMAL)
        self.vuln_results.delete(1.0, tk.END)
        self.vuln_progress['value'] = 0
        self.scanning = True

        def scan_thread():
            try:
                self.update_vuln_status("Starting vulnerability scan...")
                total_steps = sum([
                    self.check_ports.get(),
                    self.check_services.get(),
                    self.check_web.get()
                ])
                current_step = 0

                if self.check_ports.get() and self.scanning:
                    self.scan_port_vulnerabilities(target)
                    current_step += 1
                    self.update_vuln_progress(
                        (current_step / total_steps) * 100
                    )

                if self.check_services.get() and self.scanning:
                    self.scan_service_vulnerabilities(target)
                    current_step += 1
                    self.update_vuln_progress(
                        (current_step / total_steps) * 100
                    )

                if self.check_web.get() and self.scanning:
                    self.scan_web_vulnerabilities(target)
                    current_step += 1
                    self.update_vuln_progress(
                        (current_step / total_steps) * 100
                    )

                if self.scanning:
                    self.update_vuln_status("Scan completed")
                    self.vuln_results.insert(tk.END, "\nVulnerability scan completed.\n")
                else:
                    self.update_vuln_status("Scan stopped")
                    self.vuln_results.insert(tk.END, "\nVulnerability scan stopped.\n")

            except Exception as e:
                self.vuln_results.insert(
                    tk.END, 
                    f"\nError during vulnerability scan: {str(e)}\n"
                )
            finally:
                self.scanning = False
                self.vuln_scan_button.config(state=tk.NORMAL)
                self.vuln_stop_button.config(state=tk.DISABLED)

        threading.Thread(target=scan_thread).start()

def update_vuln_status(self, message):
        """Update vulnerability scan status"""
        try:
            self.update_status(message)
            self.vuln_results.insert(tk.END, f"\n{message}\n")
            self.vuln_results.see(tk.END)
        except Exception as e:
            logging.error(f"Error updating vulnerability status: {str(e)}")

def update_vuln_progress(self, value):
        """Update vulnerability scan progress"""
        try:
            self.vuln_progress['value'] = value
            self.master.update_idletasks()
        except Exception as e:
            logging.error(f"Error updating vulnerability progress: {str(e)}")

def scan_port_vulnerabilities(self, target):
        """Scan for port-based vulnerabilities"""
        self.update_vuln_status("Scanning port vulnerabilities...")
        for port, vulns in VULNERABILITIES.items():
            if not self.scanning:
                break
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                if result == 0:
                    self.vuln_results.insert(
                        tk.END,
                        f"\nPort {port} is open and may be vulnerable to:\n"
                    )
                    for vuln in vulns:
                        self.vuln_results.insert(tk.END, f"  - {vuln}\n")
                sock.close()
            except:
                continue

def scan_service_vulnerabilities(self, target):
        """Scan for service-based vulnerabilities"""
        self.update_vuln_status("Scanning service vulnerabilities...")
        # Add your service vulnerability scanning logic here

def scan_web_vulnerabilities(self, target):
        """Scan for web-based vulnerabilities"""
        self.update_vuln_status("Scanning web vulnerabilities...")
        # Add your web vulnerability scanning logic here


def create_cpu_monitor(self, parent):
        """Create CPU monitoring interface"""
        frame = ttk.LabelFrame(parent, text="CPU Monitor", padding=10)
        frame.pack(fill=tk.X, padx=5, pady=5)

        # CPU Usage Graph
        self.cpu_figure, self.cpu_ax = plt.subplots(figsize=(8, 3))
        self.cpu_figure.patch.set_facecolor(THEMES[self.current_theme]['bg'])
        self.cpu_ax.set_facecolor(THEMES[self.current_theme]['bg'])
        self.cpu_ax.tick_params(colors=THEMES[self.current_theme]['fg'])
        self.cpu_ax.set_title('CPU Usage', color=THEMES[self.current_theme]['fg'])
        self.cpu_ax.set_ylim(0, 100)
        self.cpu_ax.grid(True, linestyle='--', alpha=0.7)
        
        self.cpu_canvas = FigureCanvasTkAgg(self.cpu_figure, master=frame)
        self.cpu_canvas.draw()
        self.cpu_canvas.get_tk_widget().pack(fill=tk.X, expand=True)

        # CPU Info
        info_frame = ttk.Frame(frame)
        info_frame.pack(fill=tk.X, pady=5)

        self.cpu_usage_label = ttk.Label(info_frame, text="Current Usage: 0%")
        self.cpu_usage_label.pack(side=tk.LEFT, padx=5)

        self.cpu_cores_label = ttk.Label(
            info_frame, 
            text=f"Cores: {psutil.cpu_count()}"
        )
        self.cpu_cores_label.pack(side=tk.LEFT, padx=5)

        self.cpu_freq_label = ttk.Label(info_frame, text="Frequency: -- MHz")
        self.cpu_freq_label.pack(side=tk.LEFT, padx=5)

def create_memory_monitor(self, parent):
        """Create memory monitoring interface"""
        frame = ttk.LabelFrame(parent, text="Memory Monitor", padding=10)
        frame.pack(fill=tk.X, padx=5, pady=5)

        # Memory Usage Graph
        self.memory_figure, self.memory_ax = plt.subplots(figsize=(8, 3))
        self.memory_figure.patch.set_facecolor(THEMES[self.current_theme]['bg'])
        self.memory_ax.set_facecolor(THEMES[self.current_theme]['bg'])
        self.memory_ax.tick_params(colors=THEMES[self.current_theme]['fg'])
        self.memory_ax.set_title('Memory Usage', color=THEMES[self.current_theme]['fg'])
        self.memory_ax.set_ylim(0, 100)
        self.memory_ax.grid(True, linestyle='--', alpha=0.7)
        
        self.memory_canvas = FigureCanvasTkAgg(self.memory_figure, master=frame)
        self.memory_canvas.draw()
        self.memory_canvas.get_tk_widget().pack(fill=tk.X, expand=True)

        # Memory Info
        info_frame = ttk.Frame(frame)
        info_frame.pack(fill=tk.X, pady=5)

        self.memory_usage_label = ttk.Label(info_frame, text="Used: 0%")
        self.memory_usage_label.pack(side=tk.LEFT, padx=5)

        self.memory_total_label = ttk.Label(info_frame, text="Total: -- GB")
        self.memory_total_label.pack(side=tk.LEFT, padx=5)

        self.memory_available_label = ttk.Label(info_frame, text="Available: -- GB")
        self.memory_available_label.pack(side=tk.LEFT, padx=5)

def create_network_monitor(self, parent):
        """Create network monitoring interface"""
        frame = ttk.LabelFrame(parent, text="Network Monitor", padding=10)
        frame.pack(fill=tk.X, padx=5, pady=5)

        # Network Usage Graph
        self.network_figure, self.network_ax = plt.subplots(figsize=(8, 3))
        self.network_figure.patch.set_facecolor(THEMES[self.current_theme]['bg'])
        self.network_ax.set_facecolor(THEMES[self.current_theme]['bg'])
        self.network_ax.tick_params(colors=THEMES[self.current_theme]['fg'])
        self.network_ax.set_title('Network Usage', color=THEMES[self.current_theme]['fg'])
        self.network_ax.grid(True, linestyle='--', alpha=0.7)
        
        self.network_canvas = FigureCanvasTkAgg(self.network_figure, master=frame)
        self.network_canvas.draw()
        self.network_canvas.get_tk_widget().pack(fill=tk.X, expand=True)

        # Network Info
        info_frame = ttk.Frame(frame)
        info_frame.pack(fill=tk.X, pady=5)

        self.network_sent_label = ttk.Label(info_frame, text="Sent: 0 B/s")
        self.network_sent_label.pack(side=tk.LEFT, padx=5)

        self.network_recv_label = ttk.Label(info_frame, text="Received: 0 B/s")
        self.network_recv_label.pack(side=tk.LEFT, padx=5)

def create_process_monitor(self, parent):
        """Create process monitoring interface"""
        frame = ttk.LabelFrame(parent, text="Process Monitor", padding=10)
        frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Process list
        columns = ("PID", "Name", "CPU %", "Memory %", "Status")
        self.process_tree = ttk.Treeview(
            frame, 
            columns=columns, 
            show="headings", 
            height=10
        )

        # Configure columns
        for col in columns:
            self.process_tree.heading(col, text=col)
            self.process_tree.column(col, width=100)

        # Add scrollbar
        scrollbar = ttk.Scrollbar(
            frame, 
            orient=tk.VERTICAL, 
            command=self.process_tree.yview
        )
        self.process_tree.configure(yscrollcommand=scrollbar.set)

        # Pack elements
        self.process_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

def update_monitors(self):
        """Update all monitoring displays"""
        try:
            # Update CPU monitor
            cpu_percent = psutil.cpu_percent()
            self.system_monitor.history['cpu'].append(cpu_percent)
            if len(self.system_monitor.history['cpu']) > 60:
                self.system_monitor.history['cpu'].pop(0)

            self.cpu_ax.clear()
            self.cpu_ax.plot(
                self.system_monitor.history['cpu'], 
                color=THEMES[self.current_theme]['accent1']
            )
            self.cpu_ax.set_ylim(0, 100)
            self.cpu_ax.set_title('CPU Usage', color=THEMES[self.current_theme]['fg'])
            self.cpu_canvas.draw()

            # Update memory monitor
            memory = psutil.virtual_memory()
            self.system_monitor.history['memory'].append(memory.percent)
            if len(self.system_monitor.history['memory']) > 60:
                self.system_monitor.history['memory'].pop(0)

            self.memory_ax.clear()
            self.memory_ax.plot(
                self.system_monitor.history['memory'], 
                color=THEMES[self.current_theme]['accent2']
            )
            self.memory_ax.set_ylim(0, 100)
            self.memory_ax.set_title('Memory Usage', color=THEMES[self.current_theme]['fg'])
            self.memory_canvas.draw()

            # Update labels
            self.update_monitor_labels()

            # Schedule next update
            self.master.after(1000, self.update_monitors)

        except Exception as e:
            logging.error(f"Error updating monitors: {str(e)}")

def update_monitor_labels(self):
        """Update monitoring information labels"""
        try:
            # CPU info
            cpu_percent = psutil.cpu_percent()
            cpu_freq = psutil.cpu_freq()
            self.cpu_usage_label.config(text=f"Current Usage: {cpu_percent}%")
            self.cpu_freq_label.config(
                text=f"Frequency: {cpu_freq.current:.0f} MHz"
            )

            # Memory info
            memory = psutil.virtual_memory()
            self.memory_usage_label.config(text=f"Used: {memory.percent}%")
            self.memory_total_label.config(
                text=f"Total: {memory.total / (1024**3):.1f} GB"
            )
            self.memory_available_label.config(
                text=f"Available: {memory.available / (1024**3):.1f} GB"
            )

            # Network info
            net_io = psutil.net_io_counters()
            self.network_sent_label.config(
                text=f"Sent: {self.format_bytes(net_io.bytes_sent)}/s"
            )
            self.network_recv_label.config(
                text=f"Received: {self.format_bytes(net_io.bytes_recv)}/s"
            )

            # Update process list
            self.update_process_list()

        except Exception as e:
            logging.error(f"Error updating monitor labels: {str(e)}")

def format_bytes(self, bytes):
        """Format bytes to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes < 1024:
                return f"{bytes:.1f} {unit}"
            bytes /= 1024
        return f"{bytes:.1f} TB"


def create_whois_tool(self, parent):
        """Create WHOIS lookup tool interface"""
        frame = ttk.LabelFrame(parent, text="WHOIS Lookup", padding=10)
        frame.pack(fill=tk.X, padx=5, pady=5)

        # Domain input
        input_frame = ttk.Frame(frame)
        input_frame.pack(fill=tk.X, pady=5)

        ttk.Label(input_frame, text="Domain:").pack(side=tk.LEFT, padx=5)
        self.whois_domain = ttk.Entry(input_frame, width=30)
        self.whois_domain.pack(side=tk.LEFT, padx=5)

        # Lookup button
        self.whois_button = ttk.Button(
            input_frame, 
            text="Lookup", 
            command=self.execute_whois_lookup
        )
        self.whois_button.pack(side=tk.LEFT, padx=5)

        # Results
        self.whois_results = tk.Text(
            frame, 
            height=10, 
            width=60,
            bg=THEMES[self.current_theme]['bg'],
            fg=THEMES[self.current_theme]['fg'],
            font=('Courier', 10)
        )
        self.whois_results.pack(fill=tk.X, pady=5)

def execute_whois_lookup(self):
        """Execute WHOIS lookup"""
        domain = self.whois_domain.get().strip()
        if not domain:
            messagebox.showerror("Error", "Please enter a domain")
            return

        self.whois_button.config(state=tk.DISABLED)
        self.whois_results.delete(1.0, tk.END)
        self.whois_results.insert(tk.END, "Looking up WHOIS information...\n")

        def whois_thread():
            try:
                result = NetworkUtils.whois_lookup(domain)
                if isinstance(result, str):
                    # Error occurred
                    self.whois_results.delete(1.0, tk.END)
                    self.whois_results.insert(tk.END, f"Error: {result}\n")
                else:
                    # Format and display results
                    self.whois_results.delete(1.0, tk.END)
                    self.whois_results.insert(tk.END, "WHOIS Information:\n\n")
                    
                    for key, value in result.items():
                        if value and key not in ['raw']:
                            if isinstance(value, list):
                                value = ', '.join(str(v) for v in value)
                            self.whois_results.insert(
                                tk.END, 
                                f"{key.replace('_', ' ').title()}: {value}\n"
                            )
            except Exception as e:
                self.whois_results.delete(1.0, tk.END)
                self.whois_results.insert(
                    tk.END, 
                    f"Error performing WHOIS lookup: {str(e)}\n"
                )
            finally:
                self.whois_button.config(state=tk.NORMAL)

        threading.Thread(target=whois_thread).start()

def create_banner(self):
        banner_frame = ttk.Frame(self.main_container)
        banner_frame.pack(fill=tk.X, pady=(0, 10))
        
        banner_label = tk.Label(
            banner_frame,
            text=BANNER,
            font=('Courier', 10),
            fg=THEMES[self.current_theme]['accent1'],
            bg=THEMES[self.current_theme]['bg']
        )
        banner_label.pack()

def create_dashboard_tab(self):
        dashboard = ttk.Frame(self.notebook)
        self.notebook.add(dashboard, text="Dashboard")

        # Create grid layout
        for i in range(2):
            dashboard.grid_columnconfigure(i, weight=1)
        for i in range(2):
            dashboard.grid_rowconfigure(i, weight=1)

        # Quick scan widget
        self.create_quick_scan_widget(dashboard, 0, 0)
        
        # System status widget
        self.create_system_status_widget(dashboard, 0, 1)
        
        # Network activity widget
        self.create_network_activity_widget(dashboard, 1, 0)
        
        # Recent scans widget
        self.create_recent_scans_widget(dashboard, 1, 1)

def create_scanner_tab(self):
        scanner = ttk.Frame(self.notebook)
        self.notebook.add(scanner, text="Port Scanner")

        # Target input frame
        target_frame = ttk.LabelFrame(scanner, text="Target Configuration", padding=10)
        target_frame.pack(fill=tk.X, padx=5, pady=5)

        # Target IP/Domain
        ttk.Label(target_frame, text="Target:").grid(row=0, column=0, padx=5, pady=5)
        self.target_entry = ttk.Entry(target_frame, width=40)
        self.target_entry.grid(row=0, column=1, padx=5, pady=5)

        # Port range
        ttk.Label(target_frame, text="Port Range:").grid(row=1, column=0, padx=5, pady=5)
        port_frame = ttk.Frame(target_frame)
        port_frame.grid(row=1, column=1, sticky='w')
        
        self.start_port = ttk.Entry(port_frame, width=10)
        self.start_port.pack(side=tk.LEFT, padx=5)
        ttk.Label(port_frame, text="-").pack(side=tk.LEFT)
        self.end_port = ttk.Entry(port_frame, width=10)
        self.end_port.pack(side=tk.LEFT, padx=5)

        # Scan options
        options_frame = ttk.LabelFrame(scanner, text="Scan Options", padding=10)
        options_frame.pack(fill=tk.X, padx=5, pady=5)

        self.service_detection = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Service Detection", 
                       variable=self.service_detection).pack(side=tk.LEFT, padx=5)

        self.os_detection = tk.BooleanVar(value=False)
        ttk.Checkbutton(options_frame, text="OS Detection", 
                       variable=self.os_detection).pack(side=tk.LEFT, padx=5)

        self.vuln_check = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Vulnerability Check", 
                       variable=self.vuln_check).pack(side=tk.LEFT, padx=5)

        # Control buttons
        button_frame = ttk.Frame(scanner)
        button_frame.pack(fill=tk.X, padx=5, pady=5)

        self.scan_button = ttk.Button(button_frame, text="Start Scan", 
                                    command=self.start_scan)
        self.scan_button.pack(side=tk.LEFT, padx=5)

        self.stop_button = ttk.Button(button_frame, text="Stop", 
                                    command=self.stop_scan, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        # Results area
        results_frame = ttk.LabelFrame(scanner, text="Scan Results", padding=10)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.results_text = tk.Text(results_frame, wrap=tk.WORD, 
                                  bg=THEMES[self.current_theme]['bg'],
                                  fg=THEMES[self.current_theme]['fg'],
                                  font=('Courier', 10))
        self.results_text.pack(fill=tk.BOTH, expand=True)

def create_network_tools_tab(self):
        tools = ttk.Frame(self.notebook)
        self.notebook.add(tools, text="Network Tools")

        # Create tool sections
        self.create_ping_tool(tools)
        self.create_traceroute_tool(tools)
        self.create_dns_tool(tools)
        self.create_whois_tool(tools)
        self.create_speed_test_tool(tools)

def create_system_monitor_tab(self):
        monitor = ttk.Frame(self.notebook)
        self.notebook.add(monitor, text="System Monitor")

        # Create monitoring widgets
        self.create_cpu_monitor(monitor)
        self.create_memory_monitor(monitor)
        self.create_network_monitor(monitor)
        self.create_process_monitor(monitor)

def create_vulnerability_tab(self):
        vuln = ttk.Frame(self.notebook)
        self.notebook.add(vuln, text="Vulnerability Scanner")

        # Create vulnerability scanning interface
        self.create_vuln_scanner_interface(vuln)
        self.create_vuln_results_area(vuln)
        self.create_vuln_database_viewer(vuln)

def create_status_bar(self):
        self.status_bar = ttk.Frame(self.main_container)
        self.status_bar.pack(fill=tk.X, side=tk.BOTTOM, pady=(5, 0))

        self.status_label = ttk.Label(self.status_bar, text="Ready")
        self.status_label.pack(side=tk.LEFT)

        self.progress_bar = ttk.Progressbar(self.status_bar, length=200, mode='determinate')
        self.progress_bar.pack(side=tk.RIGHT)



def monitor_loop(self):
        while self.monitoring:
            self.system_monitor.update_history()
            self.update_monitoring_graphs()
            time.sleep(1)

def update_monitoring_graphs(self):
        """Update all monitoring graphs with new data"""
        if hasattr(self, 'cpu_graph'):
            self.update_cpu_graph()
        if hasattr(self, 'memory_graph'):
            self.update_memory_graph()
        if hasattr(self, 'network_graph'):
            self.update_network_graph()

def start_scan(self):
        """Start port scanning process"""
        target = self.target_entry.get().strip()
        try:
            start_port = int(self.start_port.get())
            end_port = int(self.end_port.get())
        except ValueError:
            messagebox.showerror("Error", "Invalid port numbers")
            return

        # Validate input
        if not target or not (0 <= start_port <= 65535) or not (0 <= end_port <= 65535):
            messagebox.showerror("Error", "Invalid input parameters")
            return

        # Prepare scan
        self.scan_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        self.update_status("Scanning...")

        # Start scan in separate thread
        self.scanning = True
        threading.Thread(target=self.perform_scan, 
                        args=(target, start_port, end_port)).start()

def perform_scan(self, target, start_port, end_port):
        """Execute the port scan"""
        try:
            total_ports = end_port - start_port + 1
            ports_scanned = 0
            open_ports = []

            # Initial target information
            self.update_results(f"Starting scan of {target}\n")
            self.update_results(f"Port range: {start_port}-{end_port}\n\n")

            # Perform DNS lookup if target is a domain
            try:
                ip = socket.gethostbyname(target)
                if ip != target:
                    self.update_results(f"Resolved {target} to {ip}\n\n")
            except:
                pass

            # Scan each port
            for port in range(start_port, end_port + 1):
                if not self.scanning:
                    self.update_results("\nScan stopped by user.")
                    break

                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(0.5)
                        result = s.connect_ex((target, port))
                        if result == 0:
                            service = COMMON_PORTS.get(port, ("Unknown", ""))[0]
                            open_ports.append(port)
                            self.update_results(f"Port {port}: OPEN - {service}\n")
                            
                            # Check for vulnerabilities if enabled
                            if self.vuln_check.get():
                                vulns = self.vulnerability_scanner.check_port_vulnerabilities(port)
                                if vulns:
                                    self.update_results("  Potential vulnerabilities:\n")
                                    for vuln in vulns:
                                        self.update_results(f"    - {vuln}\n")

                except Exception as e:
                    self.update_results(f"Error scanning port {port}: {str(e)}\n")

                ports_scanned += 1
                progress = (ports_scanned / total_ports) * 100
                self.update_progress(progress)

            # Scan summary
            self.update_results(f"\nScan completed. Found {len(open_ports)} open ports.\n")
            
            # Additional information if requested
            if self.os_detection.get():
                self.perform_os_detection(target)
            
            if self.service_detection.get():
                self.perform_service_detection(target, open_ports)

        except Exception as e:
            self.update_results(f"\nError during scan: {str(e)}")
        finally:
            self.scan_completed()

def perform_os_detection(self, target):
        """Perform OS detection using nmap"""
        try:
            self.update_results("\nPerforming OS Detection...\n")
            os_matches = self.network_mapper.get_os_details(target)
            if os_matches:
                self.update_results("OS Detection Results:\n")
                for match in os_matches[:3]:  # Show top 3 matches
                    self.update_results(f"  - {match['name']} "
                                     f"(Accuracy: {match['accuracy']}%)\n")
            else:
                self.update_results("No OS information found.\n")
        except Exception as e:
            self.update_results(f"OS detection error: {str(e)}\n")

def perform_service_detection(self, target, open_ports):
        """Perform service version detection"""
        try:
            self.update_results("\nPerforming Service Detection...\n")
            for port in open_ports:
                service_info = self.network_mapper.get_service_versions(target, port)
                if service_info:
                    self.update_results(
                        f"Port {port}: {service_info.get('name', 'Unknown')} "
                        f"({service_info.get('product', 'Unknown')} "
                        f"{service_info.get('version', '')})\n"
                    )
        except Exception as e:
            self.update_results(f"Service detection error: {str(e)}\n")

def create_quick_scan_widget(self, parent, row, column):
        """Create quick scan widget for dashboard"""
        frame = ttk.LabelFrame(parent, text="Quick Scan", padding=10)
        frame.grid(row=row, column=column, padx=5, pady=5, sticky="nsew")

        ttk.Label(frame, text="Target:").pack(side=tk.LEFT, padx=5)
        quick_target = ttk.Entry(frame, width=20)
        quick_target.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(frame, text="Scan Common Ports", 
                  command=lambda: self.quick_scan(quick_target.get())).pack(side=tk.LEFT, padx=5)

def create_system_status_widget(self, parent, row, column):
        """Create system status widget for dashboard"""
        frame = ttk.LabelFrame(parent, text="System Status", padding=10)
        frame.grid(row=row, column=column, padx=5, pady=5, sticky="nsew")

        # CPU Usage
        self.cpu_label = ttk.Label(frame, text="CPU: 0%")
        self.cpu_label.pack(fill=tk.X, pady=2)
        
        # Memory Usage
        self.memory_label = ttk.Label(frame, text="Memory: 0%")
        self.memory_label.pack(fill=tk.X, pady=2)
        
        # Network Usage
        self.network_label = ttk.Label(frame, text="Network: 0 B/s")
        self.network_label.pack(fill=tk.X, pady=2)

def create_network_activity_widget(self, parent, row, column):
        """Create network activity visualization widget"""
        frame = ttk.LabelFrame(parent, text="Network Activity", padding=10)
        frame.grid(row=row, column=column, padx=5, pady=5, sticky="nsew")

        self.network_canvas = tk.Canvas(frame, bg=THEMES[self.current_theme]['bg'],
                                      height=200)
        self.network_canvas.pack(fill=tk.BOTH, expand=True)

def create_recent_scans_widget(self, parent, row, column):
        """Create recent scans widget"""
        frame = ttk.LabelFrame(parent, text="Recent Scans", padding=10)
        frame.grid(row=row, column=column, padx=5, pady=5, sticky="nsew")

        self.recent_scans_text = tk.Text(frame, height=10, width=40,
                                       bg=THEMES[self.current_theme]['bg'],
                                       fg=THEMES[self.current_theme]['fg'])
        self.recent_scans_text.pack(fill=tk.BOTH, expand=True)


def create_ping_tool(self, parent):
        """Create ping tool interface"""
        frame = ttk.LabelFrame(parent, text="Ping Tool", padding=10)
        frame.pack(fill=tk.X, padx=5, pady=5)

        # Host input
        ttk.Label(frame, text="Host:").pack(side=tk.LEFT, padx=5)
        self.ping_host = ttk.Entry(frame, width=30)
        self.ping_host.pack(side=tk.LEFT, padx=5)

        # Count input
        ttk.Label(frame, text="Count:").pack(side=tk.LEFT, padx=5)
        self.ping_count = ttk.Spinbox(frame, from_=1, to=100, width=5)
        self.ping_count.pack(side=tk.LEFT, padx=5)
        self.ping_count.set(4)

        # Ping button
        self.ping_button = ttk.Button(frame, text="Ping", 
                                    command=self.execute_ping)
        self.ping_button.pack(side=tk.LEFT, padx=5)

        # Results
        self.ping_results = tk.Text(frame, height=6, width=60,
                                  bg=THEMES[self.current_theme]['bg'],
                                  fg=THEMES[self.current_theme]['fg'])
        self.ping_results.pack(fill=tk.X, pady=5)

def create_traceroute_tool(self, parent):
        """Create traceroute tool interface"""
        frame = ttk.LabelFrame(parent, text="Traceroute", padding=10)
        frame.pack(fill=tk.X, padx=5, pady=5)

        # Host input
        ttk.Label(frame, text="Host:").pack(side=tk.LEFT, padx=5)
        self.traceroute_host = ttk.Entry(frame, width=30)
        self.traceroute_host.pack(side=tk.LEFT, padx=5)

        # Traceroute button
        self.traceroute_button = ttk.Button(frame, text="Trace", 
                                          command=self.execute_traceroute)
        self.traceroute_button.pack(side=tk.LEFT, padx=5)

        # Results
        self.traceroute_results = tk.Text(frame, height=10, width=60,
                                        bg=THEMES[self.current_theme]['bg'],
                                        fg=THEMES[self.current_theme]['fg'])
        self.traceroute_results.pack(fill=tk.X, pady=5)

def create_dns_tool(self, parent):
        """Create DNS lookup tool interface"""
        frame = ttk.LabelFrame(parent, text="DNS Lookup", padding=10)
        frame.pack(fill=tk.X, padx=5, pady=5)

        # Domain input
        ttk.Label(frame, text="Domain:").pack(side=tk.LEFT, padx=5)
        self.dns_domain = ttk.Entry(frame, width=30)
        self.dns_domain.pack(side=tk.LEFT, padx=5)

        # Record type selection
        self.dns_record_type = ttk.Combobox(frame, values=['A', 'AAAA', 'MX', 'NS', 'TXT', 'ALL'])
        self.dns_record_type.pack(side=tk.LEFT, padx=5)
        self.dns_record_type.set('ALL')

        # Lookup button
        self.dns_button = ttk.Button(frame, text="Lookup", 
                                   command=self.execute_dns_lookup)
        self.dns_button.pack(side=tk.LEFT, padx=5)

        # Results
        self.dns_results = tk.Text(frame, height=8, width=60,
                                 bg=THEMES[self.current_theme]['bg'],
                                 fg=THEMES[self.current_theme]['fg'])
        self.dns_results.pack(fill=tk.X, pady=5)

def create_speed_test_tool(self, parent):
        """Create speed test tool interface"""
        frame = ttk.LabelFrame(parent, text="Speed Test", padding=10)
        frame.pack(fill=tk.X, padx=5, pady=5)

        # Control frame
        control_frame = ttk.Frame(frame)
        control_frame.pack(fill=tk.X)

        # Start button
        self.speedtest_button = ttk.Button(control_frame, text="Start Speed Test", 
                                         command=self.execute_speed_test)
        self.speedtest_button.pack(side=tk.LEFT, padx=5)

        # Progress bar
        self.speedtest_progress = ttk.Progressbar(control_frame, length=300, 
                                                mode='determinate')
        self.speedtest_progress.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)

        # Results frame
        results_frame = ttk.Frame(frame)
        results_frame.pack(fill=tk.X, pady=5)

        # Results labels
        self.download_label = ttk.Label(results_frame, text="Download: -- Mbps")
        self.download_label.pack(side=tk.LEFT, padx=20)

        self.upload_label = ttk.Label(results_frame, text="Upload: -- Mbps")
        self.upload_label.pack(side=tk.LEFT, padx=20)

        self.ping_label = ttk.Label(results_frame, text="Ping: -- ms")
        self.ping_label.pack(side=tk.LEFT, padx=20)

def create_network_map(self, parent):
        """Create network mapping visualization"""
        frame = ttk.LabelFrame(parent, text="Network Map", padding=10)
        frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Control frame
        control_frame = ttk.Frame(frame)
        control_frame.pack(fill=tk.X)

        ttk.Label(control_frame, text="Network:").pack(side=tk.LEFT, padx=5)
        self.network_range = ttk.Entry(control_frame, width=20)
        self.network_range.pack(side=tk.LEFT, padx=5)
        self.network_range.insert(0, "192.168.1.0/24")

        self.map_button = ttk.Button(control_frame, text="Map Network",
                                   command=self.execute_network_mapping)
        self.map_button.pack(side=tk.LEFT, padx=5)

        # Network visualization area
        self.network_visualizer = NetworkGraphVisualizer(frame)
        self.network_visualizer.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

def execute_ping(self):
        """Execute ping command"""
        host = self.ping_host.get().strip()
        count = int(self.ping_count.get())
        
        self.ping_button.config(state=tk.DISABLED)
        self.ping_results.delete(1.0, tk.END)
        
        def ping_thread():
            result = NetworkUtils.ping(host, count)
            self.ping_results.insert(tk.END, result)
            self.ping_button.config(state=tk.NORMAL)
        
        threading.Thread(target=ping_thread).start()

def execute_traceroute(self):
        """Execute traceroute command"""
        host = self.traceroute_host.get().strip()
        
        self.traceroute_button.config(state=tk.DISABLED)
        self.traceroute_results.delete(1.0, tk.END)
        
        def traceroute_thread():
            result = NetworkUtils.traceroute(host)
            self.traceroute_results.insert(tk.END, result)
            self.traceroute_button.config(state=tk.NORMAL)
        
        threading.Thread(target=traceroute_thread).start()

def execute_dns_lookup(self):
        """Execute DNS lookup"""
        domain = self.dns_domain.get().strip()
        record_type = self.dns_record_type.get()
        
        self.dns_button.config(state=tk.DISABLED)
        self.dns_results.delete(1.0, tk.END)
        
        def dns_thread():
            results = NetworkUtils.dns_lookup(domain)
            for result in results:
                self.dns_results.insert(tk.END, f"{result}\n")
            self.dns_button.config(state=tk.NORMAL)
        
        threading.Thread(target=dns_thread).start()


def create_vuln_scanner_interface(self, parent):
        """Create vulnerability scanner interface"""
        frame = ttk.LabelFrame(parent, text="Vulnerability Scanner", padding=10)
        frame.pack(fill=tk.X, padx=5, pady=5)

        # Scan configuration
        config_frame = ttk.Frame(frame)
        config_frame.pack(fill=tk.X, pady=5)

        # Target input
        ttk.Label(config_frame, text="Target:").grid(row=0, column=0, padx=5, pady=5)
        self.vuln_target = ttk.Entry(config_frame, width=40)
        self.vuln_target.grid(row=0, column=1, padx=5, pady=5)

        # Scan options
        options_frame = ttk.LabelFrame(frame, text="Scan Options", padding=5)
        options_frame.pack(fill=tk.X, pady=5)

        # Checkboxes for different vulnerability types
        self.check_web_vulns = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Web Vulnerabilities", 
                       variable=self.check_web_vulns).pack(side=tk.LEFT, padx=5)

        self.check_network_vulns = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Network Vulnerabilities", 
                       variable=self.check_network_vulns).pack(side=tk.LEFT, padx=5)

        self.check_service_vulns = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Service Vulnerabilities", 
                       variable=self.check_service_vulns).pack(side=tk.LEFT, padx=5)

        # Scan depth
        depth_frame = ttk.Frame(frame)
        depth_frame.pack(fill=tk.X, pady=5)

        ttk.Label(depth_frame, text="Scan Depth:").pack(side=tk.LEFT, padx=5)
        self.scan_depth = ttk.Combobox(depth_frame, 
                                     values=["Quick", "Normal", "Deep"],
                                     state="readonly", width=10)
        self.scan_depth.set("Normal")
        self.scan_depth.pack(side=tk.LEFT, padx=5)

        # Control buttons
        button_frame = ttk.Frame(frame)
        button_frame.pack(fill=tk.X, pady=5)

        self.vuln_scan_button = ttk.Button(button_frame, text="Start Scan",
                                         command=self.start_vuln_scan)
        self.vuln_scan_button.pack(side=tk.LEFT, padx=5)

        self.vuln_stop_button = ttk.Button(button_frame, text="Stop",
                                         command=self.stop_vuln_scan,
                                         state=tk.DISABLED)
        self.vuln_stop_button.pack(side=tk.LEFT, padx=5)

def create_vuln_results_area(self, parent):
        """Create vulnerability results display area"""
        frame = ttk.LabelFrame(parent, text="Scan Results", padding=10)
        frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Results notebook for different categories
        self.vuln_results_notebook = ttk.Notebook(frame)
        self.vuln_results_notebook.pack(fill=tk.BOTH, expand=True)

        # Create tabs for different result categories
        self.create_vuln_result_tab("Summary")
        self.create_vuln_result_tab("High Risk")
        self.create_vuln_result_tab("Medium Risk")
        self.create_vuln_result_tab("Low Risk")
        self.create_vuln_result_tab("Details")

def create_vuln_result_tab(self, name):
        """Create a tab for vulnerability results"""
        frame = ttk.Frame(self.vuln_results_notebook)
        self.vuln_results_notebook.add(frame, text=name)

        text_widget = tk.Text(frame, wrap=tk.WORD,
                            bg=THEMES[self.current_theme]['bg'],
                            fg=THEMES[self.current_theme]['fg'],
                            height=15)
        text_widget.pack(fill=tk.BOTH, expand=True)

        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL,
                                command=text_widget.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        text_widget.config(yscrollcommand=scrollbar.set)

        setattr(self, f'vuln_text_{name.lower()}', text_widget)

def create_vuln_database_viewer(self, parent):
        """Create vulnerability database viewer"""
        frame = ttk.LabelFrame(parent, text="Vulnerability Database", padding=10)
        frame.pack(fill=tk.X, padx=5, pady=5)

        # Search frame
        search_frame = ttk.Frame(frame)
        search_frame.pack(fill=tk.X, pady=5)

        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT, padx=5)
        self.vuln_search = ttk.Entry(search_frame, width=40)
        self.vuln_search.pack(side=tk.LEFT, padx=5)
        self.vuln_search.bind('<KeyRelease>', self.filter_vuln_database)

        # Category filter
        ttk.Label(search_frame, text="Category:").pack(side=tk.LEFT, padx=5)
        self.vuln_category = ttk.Combobox(search_frame, 
                                        values=["All", "Network", "Web", "Service"],
                                        state="readonly", width=10)
        self.vuln_category.set("All")
        self.vuln_category.pack(side=tk.LEFT, padx=5)
        self.vuln_category.bind('<<ComboboxSelected>>', self.filter_vuln_database)

        # Vulnerability list
        self.vuln_tree = ttk.Treeview(frame, columns=("ID", "Name", "Severity", "Category"),
                                    show="headings", height=6)
        self.vuln_tree.pack(fill=tk.X, pady=5)

        # Configure columns
        self.vuln_tree.heading("ID", text="ID")
        self.vuln_tree.heading("Name", text="Name")
        self.vuln_tree.heading("Severity", text="Severity")
        self.vuln_tree.heading("Category", text="Category")

        # Column widths
        self.vuln_tree.column("ID", width=100)
        self.vuln_tree.column("Name", width=300)
        self.vuln_tree.column("Severity", width=100)
        self.vuln_tree.column("Category", width=100)

def start_vuln_scan(self):
        """Start vulnerability scanning process"""
        target = self.vuln_target.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target")
            return

        # Update UI
        self.vuln_scan_button.config(state=tk.DISABLED)
        self.vuln_stop_button.config(state=tk.NORMAL)
        self.clear_vuln_results()

        # Start scan in separate thread
        self.scanning_vulns = True
        threading.Thread(target=self.perform_vuln_scan, args=(target,)).start()

def perform_vuln_scan(self, target):
        """Execute vulnerability scan"""
        try:
            self.update_vuln_text("summary", "Starting vulnerability scan...\n")
            
            # Perform initial reconnaissance
            self.update_vuln_text("summary", "Performing initial reconnaissance...\n")
            self.perform_recon(target)

            # Scan for vulnerabilities based on selected options
            if self.check_network_vulns.get():
                self.scan_network_vulnerabilities(target)
            
            if self.check_web_vulns.get():
                self.scan_web_vulnerabilities(target)
            
            if self.check_service_vulns.get():
                self.scan_service_vulnerabilities(target)

            # Generate final report
            self.generate_vuln_report()

        except Exception as e:
            self.update_vuln_text("summary", f"Error during scan: {str(e)}\n")
        finally:
            self.vuln_scan_completed()

def perform_recon(self, target):
        """Perform initial reconnaissance"""
        self.update_vuln_text("details", "Performing port scan...\n")
        # Add reconnaissance logic here
        pass

def scan_network_vulnerabilities(self, target):
        """Scan for network-level vulnerabilities"""
        self.update_vuln_text("details", "Scanning network vulnerabilities...\n")
        # Add network vulnerability scanning logic here
        pass

def scan_web_vulnerabilities(self, target):
        """Scan for web-based vulnerabilities"""
        self.update_vuln_text("details", "Scanning web vulnerabilities...\n")
        # Add web vulnerability scanning logic here
        pass

def scan_service_vulnerabilities(self, target):
        """Scan for service-specific vulnerabilities"""
        self.update_vuln_text("details", "Scanning service vulnerabilities...\n")
        # Add service vulnerability scanning logic here
        pass


def create_report_generator(self, parent):
        """Create report generation interface"""
        frame = ttk.LabelFrame(parent, text="Report Generator", padding=10)
        frame.pack(fill=tk.X, padx=5, pady=5)

        # Report options
        options_frame = ttk.Frame(frame)
        options_frame.pack(fill=tk.X, pady=5)

        # Report type selection
        ttk.Label(options_frame, text="Report Type:").grid(row=0, column=0, padx=5, pady=5)
        self.report_type = ttk.Combobox(options_frame, 
                                      values=["Executive Summary", "Technical Detail", 
                                             "Vulnerability Assessment", "Full Report"],
                                      state="readonly", width=20)
        self.report_type.set("Full Report")
        self.report_type.grid(row=0, column=1, padx=5, pady=5)

        # Format selection
        ttk.Label(options_frame, text="Format:").grid(row=1, column=0, padx=5, pady=5)
        self.report_format = ttk.Combobox(options_frame,
                                        values=["PDF", "HTML", "JSON", "Text"],
                                        state="readonly", width=20)
        self.report_format.set("PDF")
        self.report_format.grid(row=1, column=1, padx=5, pady=5)

        # Generate button
        self.generate_report_button = ttk.Button(frame, text="Generate Report",
                                               command=self.generate_report)
        self.generate_report_button.pack(pady=5)

def create_data_visualizer(self, parent):
        """Create data visualization interface"""
        frame = ttk.LabelFrame(parent, text="Data Visualization", padding=10)
        frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Control frame
        control_frame = ttk.Frame(frame)
        control_frame.pack(fill=tk.X, pady=5)

        # Visualization type selection
        ttk.Label(control_frame, text="Visualization:").pack(side=tk.LEFT, padx=5)
        self.viz_type = ttk.Combobox(control_frame,
                                   values=["Network Map", "Port Distribution", 
                                          "Vulnerability Heatmap", "Traffic Analysis"],
                                   state="readonly", width=20)
        self.viz_type.set("Network Map")
        self.viz_type.pack(side=tk.LEFT, padx=5)
        self.viz_type.bind('<<ComboboxSelected>>', self.update_visualization)

        # Plot frame
        self.plot_frame = ttk.Frame(frame)
        self.plot_frame.pack(fill=tk.BOTH, expand=True, pady=5)

def generate_report(self):
    """Generate comprehensive security report"""
    try:
        if not os.path.exists('reports'):
            os.makedirs('reports')
            
        data = self.collect_report_data()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"reports/pinkerton_report_{timestamp}.pdf"
        
        self.advanced_reporting.generate_pdf_report(data, filename)
        logging.info(f"Generated report: {filename}")
        return filename  # Add return value
    except Exception as e:
        logging.error(f"Error generating report: {str(e)}")
        return None  # Add return value for error case

def collect_report_data(self):
        """Collect all data for report generation"""
        return {
            "scan_results": self.get_scan_results(),
            "vulnerability_assessment": self.get_vulnerability_data(),
            "system_info": self.get_system_info(),
            "network_analysis": self.get_network_analysis(),
            "timestamp": datetime.now().isoformat(),
            "scan_duration": self.get_scan_duration(),
            "recommendations": self.generate_recommendations()
        }

def generate_pdf_report(self, data, filename):
        """Generate PDF report"""
        # Implementation would go here
        # Requires additional PDF generation library
        pass

def generate_html_report(self, data, filename):
        """Generate HTML report"""
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Pinkerton Security Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                .header { text-align: center; color: #333; }
                .section { margin: 20px 0; padding: 20px; background: #f5f5f5; }
                .vulnerability { color: #d9534f; }
                .recommendation { color: #5bc0de; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Pinkerton Security Report</h1>
                <p>Generated on: {timestamp}</p>
            </div>
            {content}
        </body>
        </html>
        """

        # Generate content sections
        content = self.generate_html_content(data)
        
        # Create complete HTML
        html_content = html_template.format(
            timestamp=data['timestamp'],
            content=content
        )

        # Write to file
        with open(filename, 'w') as f:
            f.write(html_content)

def generate_json_report(self, data, filename):
        """Generate JSON report"""
        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)

def generate_text_report(self, data, filename):
        """Generate text report"""
        with open(filename, 'w') as f:
            f.write("=== Pinkerton Security Report ===\n")
            f.write(f"Generated on: {data['timestamp']}\n\n")

            # Write each section
            for section, content in data.items():
                f.write(f"\n=== {section.upper()} ===\n")
                f.write(str(content))
                f.write("\n" + "="*40 + "\n")

def update_visualization(self, event=None):
        """Update visualization based on selected type"""
        viz_type = self.viz_type.get()

        # Clear previous visualization
        for widget in self.plot_frame.winfo_children():
            widget.destroy()

        # Create new visualization
        if viz_type == "Network Map":
            self.create_network_map_viz()
        elif viz_type == "Port Distribution":
            self.create_port_distribution_viz()
        elif viz_type == "Vulnerability Heatmap":
            self.create_vulnerability_heatmap()
        elif viz_type == "Traffic Analysis":
            self.create_traffic_analysis_viz()

def create_network_map_viz(self):
        """Create network map visualization"""
        fig, ax = plt.subplots(figsize=(8, 6))
        fig.patch.set_facecolor(THEMES[self.current_theme]['bg'])
        ax.set_facecolor(THEMES[self.current_theme]['bg'])

        # Create network visualization
        # Implementation would go here

        canvas = FigureCanvasTkAgg(fig, master=self.plot_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

def create_port_distribution_viz(self):
        """Create port distribution visualization"""
        fig, ax = plt.subplots(figsize=(8, 6))
        fig.patch.set_facecolor(THEMES[self.current_theme]['bg'])
        ax.set_facecolor(THEMES[self.current_theme]['bg'])

        # Create port distribution chart
        # Implementation would go here

        canvas = FigureCanvasTkAgg(fig, master=self.plot_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

class PacketAnalyzer:
    def __init__(self):
        self.initialize_attributes()
        self.setup_sockets()
    
    def initialize_attributes(self):
        """Initialize basic attributes"""
        self.filters = []
        self.callbacks = []
        self.capture_thread = None
        self.capturing = False
    
    def setup_sockets(self):
        """Setup appropriate socket type"""
        try:
            from scapy.config import conf
            self.socket_type = conf.L3socket if platform.system().lower() == "windows" else conf.L2socket
        except Exception as e:
            logging.error(f"Error setting up packet analyzer: {str(e)}")
            self.socket_type = None

    def start_capture(self, interface=None):
        """Start packet capture"""
        try:
            if not interface:
                interface = self.get_default_interface()
                
            self.capturing = True
            self.capture_thread = threading.Thread(
                target=self._capture_packets,
                args=(interface,),
                daemon=True
            )
            self.capture_thread.start()
            logging.info(f"Started packet capture on interface {interface}")
        except Exception as e:
            logging.error(f"Packet capture error: {str(e)}")

    def get_default_interface(self):
        """Get default network interface"""
        from scapy.arch import get_windows_if_list
        
        try:
            if platform.system().lower() == "windows":
                interfaces = get_windows_if_list()
                # Get the first active interface
                for interface in interfaces:
                    if interface.get('name'):
                        return interface['name']
            return None
        except Exception as e:
            logging.error(f"Error getting default interface: {str(e)}")
            return None

    def _capture_packets(self, interface):
        """Capture packets using appropriate socket type"""
        try:
            sniff(
                iface=interface,
                prn=self._process_packet,
                store=0,
                stop_filter=lambda _: not self.capturing,
                L3socket=self.socket_type
            )
        except Exception as e:
            logging.error(f"Packet capture error: {str(e)}")

    def start_capture(self, interface=None):
        """Start packet capture"""
        self.capture_active = True
        threading.Thread(target=self.capture_packets, args=(interface,), daemon=True).start()

    def stop_capture(self):
        """Stop packet capture"""
        self.capture_active = False

    def capture_packets(self, interface):
        """Capture and analyze network packets"""
        try:
            sniff(iface=interface, 
                  prn=self.process_packet,
                  stop_filter=lambda _: not self.capture_active)
        except Exception as e:
            logging.error(f"Packet capture error: {str(e)}")

    def process_packet(self, packet):
        """Process captured packet"""
        try:
            packet_info = self.analyze_packet(packet)
            self.packets.append(packet_info)
            
            # Apply filters
            if self.should_display_packet(packet_info):
                # Notify callbacks
                for callback in self.callbacks:
                    callback(packet_info)

        except Exception as e:
            logging.error(f"Packet processing error: {str(e)}")

    def analyze_packet(self, packet):
        """Analyze packet and extract relevant information"""
        packet_info = {
            'timestamp': datetime.now(),
            'length': len(packet),
            'protocol': None,
            'src_ip': None,
            'dst_ip': None,
            'src_port': None,
            'dst_port': None,
            'payload': None
        }

        # IP layer analysis
        if IP in packet:
            packet_info['src_ip'] = packet[IP].src
            packet_info['dst_ip'] = packet[IP].dst
            packet_info['protocol'] = packet[IP].proto

        # TCP/UDP layer analysis
        if TCP in packet:
            packet_info['src_port'] = packet[TCP].sport
            packet_info['dst_port'] = packet[TCP].dport
            packet_info['protocol'] = 'TCP'
        elif UDP in packet:
            packet_info['src_port'] = packet[UDP].sport
            packet_info['dst_port'] = packet[UDP].dport
            packet_info['protocol'] = 'UDP'

        return packet_info

    def add_filter(self, filter_func):
        """Add packet filter"""
        self.filters.append(filter_func)

    def should_display_packet(self, packet_info):
     """Check if packet matches filters"""
     return all(f(packet_info) for f in self.filters)

class NetworkMonitor:
    def __init__(self):
        self.monitoring = False
        self.interfaces = {}
        self.bandwidth_history = {}
        self.alerts = []
        self.alert_callbacks = []


    def stop_monitoring(self):
        """Stop network monitoring"""
        self.monitoring = False

    def monitor_loop(self):
        """Main monitoring loop"""
        while self.monitoring:
            try:
                self.update_interface_stats()
                self.check_alerts()
                time.sleep(1)
            except Exception as e:
                logging.error(f"Monitoring error: {str(e)}")

    def update_interface_stats(self):
        """Update network interface statistics"""
        for interface in psutil.net_if_stats().keys():
            try:
                stats = psutil.net_io_counters(pernic=True)[interface]
                if interface not in self.bandwidth_history:
                    self.bandwidth_history[interface] = []
                
                self.bandwidth_history[interface].append({
                    'timestamp': datetime.now(),
                    'bytes_sent': stats.bytes_sent,
                    'bytes_recv': stats.bytes_recv,
                    'packets_sent': stats.packets_sent,
                    'packets_recv': stats.packets_recv,
                    'errin': stats.errin,
                    'errout': stats.errout,
                    'dropin': stats.dropin,
                    'dropout': stats.dropout
                })

                # Keep only last hour of history
                if len(self.bandwidth_history[interface]) > 3600:
                    self.bandwidth_history[interface].pop(0)

            except Exception as e:
                logging.error(f"Error updating interface {interface}: {str(e)}")

    def check_alerts(self):
        """Check for network anomalies and generate alerts"""
        for interface, history in self.bandwidth_history.items():
            if len(history) < 2:
                continue

            current = history[-1]
            previous = history[-2]

            # Check for sudden bandwidth spikes
            bytes_delta = (current['bytes_sent'] + current['bytes_recv'] -
                         previous['bytes_sent'] - previous['bytes_recv'])
            
            if bytes_delta > 1000000:  # More than 1MB/s
                self.generate_alert(f"High bandwidth usage on {interface}: {bytes_delta/1000000:.2f} MB/s")

            # Check for high error rates
            error_rate = (current['errin'] + current['errout'] -
                         previous['errin'] - previous['errout'])
            
            if error_rate > 0:
                self.generate_alert(f"Network errors detected on {interface}: {error_rate} errors")

    def generate_alert(self, message):
        """Generate network alert"""
        alert = {
            'timestamp': datetime.now(),
            'message': message,
            'severity': 'warning'
        }
        self.alerts.append(alert)
        
        # Notify callbacks
        for callback in self.alert_callbacks:
            callback(alert)


    def create_packet_analyzer_tab(self):
        """Create packet analyzer interface"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Packet Analyzer")

        # Control frame
        control_frame = ttk.Frame(frame)
        control_frame.pack(fill=tk.X, padx=5, pady=5)

        # Interface selection
        ttk.Label(control_frame, text="Interface:").pack(side=tk.LEFT, padx=5)
        self.interface_combo = ttk.Combobox(control_frame, values=self.get_interfaces())
        self.interface_combo.pack(side=tk.LEFT, padx=5)

        # Control buttons
        self.capture_button = ttk.Button(control_frame, text="Start Capture",
                                       command=self.toggle_capture)
        self.capture_button.pack(side=tk.LEFT, padx=5)

        self.clear_button = ttk.Button(control_frame, text="Clear",
                                     command=self.clear_packets)
        self.clear_button.pack(side=tk.LEFT, padx=5)

        # Filter frame
        filter_frame = ttk.LabelFrame(frame, text="Filters", padding=5)
        filter_frame.pack(fill=tk.X, padx=5, pady=5)

        # Protocol filter
        ttk.Label(filter_frame, text="Protocol:").pack(side=tk.LEFT, padx=5)
        self.protocol_filter = ttk.Combobox(filter_frame, 
                                          values=["All", "TCP", "UDP", "ICMP"])
        self.protocol_filter.set("All")
        self.protocol_filter.pack(side=tk.LEFT, padx=5)

        # Port filter
        ttk.Label(filter_frame, text="Port:").pack(side=tk.LEFT, padx=5)
        self.port_filter = ttk.Entry(filter_frame, width=10)
        self.port_filter.pack(side=tk.LEFT, padx=5)

        # Packet list
        self.packet_tree = ttk.Treeview(frame, 
                                      columns=("Time", "Protocol", "Source", 
                                              "Destination", "Length"),
                                      show="headings")
        self.packet_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Configure columns
        for col in self.packet_tree["columns"]:
            self.packet_tree.heading(col, text=col)
            self.packet_tree.column(col, width=100)

        # Packet details
        self.packet_details = tk.Text(frame, height=10, wrap=tk.WORD,
                                    bg=THEMES[self.current_theme]['bg'],
                                    fg=THEMES[self.current_theme]['fg'])
        self.packet_details.pack(fill=tk.X, padx=5, pady=5) 

class ThreatDetector:
    def __init__(self):
        self.signatures = self.load_threat_signatures()
        self.detected_threats = []
        self.callbacks = []
        self.whitelist = set()
        self.blacklist = set()

    def load_threat_signatures(self):
        """Load threat signatures from database"""
        signatures = {
            'port_scan': {
                'pattern': r'multiple_ports_single_source',
                'threshold': 10,
                'severity': 'high'
            },
            'brute_force': {
                'pattern': r'multiple_failed_auth',
                'threshold': 5,
                'severity': 'high'
            },
            'ddos': {
                'pattern': r'high_traffic_rate',
                'threshold': 1000,
                'severity': 'critical'
            },
            'sql_injection': {
                'pattern': r'sql_keywords',
                'threshold': 1,
                'severity': 'critical'
            },
            'malware': {
                'pattern': r'known_malware_signatures',
                'threshold': 1,
                'severity': 'critical'
            }
        }
        return signatures

    def analyze_traffic(self, packet_data):
        """Analyze network traffic for threats"""
        for signature_name, signature in self.signatures.items():
            if self.match_signature(packet_data, signature):
                threat = self.create_threat_event(signature_name, packet_data)
                self.handle_threat(threat)

    def match_signature(self, packet_data, signature):
        """Match packet against threat signature"""
        if signature['pattern'] == 'multiple_ports_single_source':
            return self.detect_port_scan(packet_data)
        elif signature['pattern'] == 'multiple_failed_auth':
            return self.detect_brute_force(packet_data)
        elif signature['pattern'] == 'high_traffic_rate':
            return self.detect_ddos(packet_data)
        elif signature['pattern'] == 'sql_keywords':
            return self.detect_sql_injection(packet_data)
        elif signature['pattern'] == 'known_malware_signatures':
            return self.detect_malware(packet_data)
        return False

    def create_threat_event(self, signature_name, packet_data):
        """Create threat event object"""
        return {
            'timestamp': datetime.now(),
            'type': signature_name,
            'severity': self.signatures[signature_name]['severity'],
            'source_ip': packet_data.get('src_ip'),
            'destination_ip': packet_data.get('dst_ip'),
            'details': packet_data,
            'status': 'detected'
        }

    def handle_threat(self, threat):
        """Handle detected threat"""
        self.detected_threats.append(threat)
        self.notify_callbacks(threat)
        self.automated_response(threat)

    def automated_response(self, threat):
        """Implement automated response to threats"""
        if threat['severity'] == 'critical':
            self.blacklist.add(threat['source_ip'])
            self.block_ip(threat['source_ip'])
        
        if threat['type'] == 'port_scan':
            self.enable_port_scan_protection()
        elif threat['type'] == 'ddos':
            self.enable_ddos_protection()
        elif threat['type'] == 'brute_force':
            self.enable_brute_force_protection()

    def block_ip(self, ip):
        """Block malicious IP address"""
        try:
            if platform.system().lower() == "windows":
                subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule",
                              f"name=Block_{ip}", "dir=in", "action=block",
                              f"remoteip={ip}"])
            else:
                subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
        except Exception as e:
            logging.error(f"Failed to block IP {ip}: {str(e)}")

class AutomatedResponse:
    def __init__(self):
        self.active_responses = {}
        self.response_rules = self.load_response_rules()

    def load_response_rules(self):
        """Load automated response rules"""
        return {
            'port_scan': {
                'actions': ['block_source', 'increase_logging', 'notify_admin'],
                'duration': 3600  # 1 hour
            },
            'brute_force': {
                'actions': ['block_source', 'lockout_account', 'notify_admin'],
                'duration': 7200  # 2 hours
            },
            'ddos': {
                'actions': ['enable_rate_limiting', 'block_source', 'notify_admin'],
                'duration': 86400  # 24 hours
            },
            'sql_injection': {
                'actions': ['block_source', 'enable_waf', 'notify_admin'],
                'duration': 86400  # 24 hours
            }
        }

    def execute_response(self, threat):
        """Execute automated response based on threat"""
        rule = self.response_rules.get(threat['type'])
        if not rule:
            return

        response_id = f"{threat['type']}_{threat['source_ip']}_{datetime.now().timestamp()}"
        
        for action in rule['actions']:
            try:
                if action == 'block_source':
                    self.block_source(threat['source_ip'])
                elif action == 'increase_logging':
                    self.increase_logging(threat['source_ip'])
                elif action == 'notify_admin':
                    self.notify_admin(threat)
                elif action == 'enable_rate_limiting':
                    self.enable_rate_limiting(threat['source_ip'])
                elif action == 'enable_waf':
                    self.enable_waf()
                elif action == 'lockout_account':
                    self.lockout_account(threat['details'].get('username'))

                self.active_responses[response_id] = {
                    'threat': threat,
                    'actions': rule['actions'],
                    'start_time': datetime.now(),
                    'duration': rule['duration']
                }

            except Exception as e:
                logging.error(f"Failed to execute response action {action}: {str(e)}")

    def check_expired_responses(self):
        """Check and remove expired responses"""
        current_time = datetime.now()
        expired = []

        for response_id, response in self.active_responses.items():
            elapsed = (current_time - response['start_time']).total_seconds()
            if elapsed >= response['duration']:
                expired.append(response_id)
                self.remove_response(response)

        for response_id in expired:
            del self.active_responses[response_id]

    def remove_response(self, response):
        """Remove active response measures"""
        threat = response['threat']
        try:
            if 'block_source' in response['actions']:
                self.unblock_source(threat['source_ip'])
            if 'rate_limiting' in response['actions']:
                self.disable_rate_limiting(threat['source_ip'])
            # Add other cleanup actions as needed
        except Exception as e:
            logging.error(f"Failed to remove response: {str(e)}")


    def create_threat_detection_tab(self):
        """Create threat detection interface"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Threat Detection")

        # Threat monitoring section
        monitor_frame = ttk.LabelFrame(frame, text="Threat Monitoring", padding=10)
        monitor_frame.pack(fill=tk.X, padx=5, pady=5)

        # Status indicators
        self.create_threat_status_indicators(monitor_frame)

        # Threat list
        self.create_threat_list(frame)

        # Response actions
        self.create_response_actions(frame)

    def create_threat_status_indicators(self, parent):
        """Create threat status indicators"""
        status_frame = ttk.Frame(parent)
        status_frame.pack(fill=tk.X, pady=5)

        # Create indicators for different threat types
        self.threat_indicators = {}
        for threat_type in ['Port Scan', 'Brute Force', 'DDoS', 'SQL Injection']:
            indicator = ttk.Label(status_frame, text="●", 
                                foreground='green', font=('Arial', 12))
            indicator.pack(side=tk.LEFT, padx=5)
            ttk.Label(status_frame, text=threat_type).pack(side=tk.LEFT, padx=5)
            self.threat_indicators[threat_type] = indicator


            import sklearn
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import numpy as np
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

class MLThreatDetector:
    def __init__(self):
        self.scaler = StandardScaler()
        self.model = IsolationForest(contamination=0.1, random_state=42)
        self.training_data = []
        self.is_trained = False

    def prepare_features(self, packet_data):
        """Extract features from packet data"""
        features = [
            packet_data.get('length', 0),
            packet_data.get('port_frequency', 0),
            packet_data.get('packet_rate', 0),
            packet_data.get('byte_rate', 0),
            packet_data.get('unique_ips', 0)
        ]
        return features

    def train(self, training_data):
        """Train the anomaly detection model"""
        if len(training_data) < 100:
            return False

        try:
            features = [self.prepare_features(data) for data in training_data]
            scaled_features = self.scaler.fit_transform(features)
            self.model.fit(scaled_features)
            self.is_trained = True
            return True
        except Exception as e:
            logging.error(f"Model training error: {str(e)}")
            return False

    def detect_anomaly(self, packet_data):
        """Detect anomalies in network traffic"""
        if not self.is_trained:
            return False

        try:
            features = self.prepare_features(packet_data)
            scaled_features = self.scaler.transform([features])
            prediction = self.model.predict(scaled_features)
            return prediction[0] == -1  # -1 indicates anomaly
        except Exception as e:
            logging.error(f"Anomaly detection error: {str(e)}")
            return False

class AdvancedReporting:
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self.create_custom_styles()

    def create_custom_styles(self):
        """Create custom styles for the report"""
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            textColor=colors.HexColor('#1a1a1a')
        ))
        
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=16,
            spaceAfter=12,
            textColor=colors.HexColor('#2c3e50')
        ))

    def generate_pdf_report(self, data, filename):
        """Generate detailed PDF report"""
        doc = SimpleDocTemplate(filename, pagesize=letter,
                              rightMargin=72, leftMargin=72,
                              topMargin=72, bottomMargin=72)

        story = []
        
        # Title
        story.append(Paragraph("Pinkerton Security Report", self.styles['CustomTitle']))
        story.append(Spacer(1, 12))
        
        # Executive Summary
        story.append(Paragraph("Executive Summary", self.styles['SectionHeader']))
        story.append(Paragraph(self.generate_executive_summary(data), 
                             self.styles['Normal']))
        story.append(Spacer(1, 12))

        # Threat Analysis
        story.append(Paragraph("Threat Analysis", self.styles['SectionHeader']))
        story.extend(self.create_threat_analysis_section(data))
        story.append(Spacer(1, 12))

        # Network Statistics
        story.append(Paragraph("Network Statistics", self.styles['SectionHeader']))
        story.extend(self.create_network_statistics_section(data))
        story.append(Spacer(1, 12))

        # Recommendations
        story.append(Paragraph("Security Recommendations", self.styles['SectionHeader']))
        story.extend(self.create_recommendations_section(data))

        # Build the PDF
        doc.build(story)

    def generate_executive_summary(self, data):
        """Generate executive summary"""
        threats = data.get('detected_threats', [])
        high_severity = sum(1 for t in threats if t['severity'] == 'high')
        medium_severity = sum(1 for t in threats if t['severity'] == 'medium')
        
        summary = f"""
        During the monitoring period, Pinkerton detected {len(threats)} potential security threats,
        including {high_severity} high-severity and {medium_severity} medium-severity incidents.
        The system automatically responded to {data.get('automated_responses', 0)} threats and
        blocked {data.get('blocked_ips', 0)} malicious IP addresses.
        """
        return summary

    def create_threat_analysis_section(self, data):
        """Create threat analysis section"""
        elements = []
        
        threats = data.get('detected_threats', [])
        if not threats:
            elements.append(Paragraph("No threats detected during this period.",
                                   self.styles['Normal']))
            return elements

        # Create threat summary table
        threat_data = [['Threat Type', 'Severity', 'Count', 'Status']]
        threat_summary = {}
        
        for threat in threats:
            key = (threat['type'], threat['severity'])
            if key not in threat_summary:
                threat_summary[key] = {'count': 0, 'resolved': 0}
            threat_summary[key]['count'] += 1
            if threat.get('status') == 'resolved':
                threat_summary[key]['resolved'] += 1

        for (threat_type, severity), stats in threat_summary.items():
            status = f"{stats['resolved']}/{stats['count']} resolved"
            threat_data.append([threat_type, severity, stats['count'], status])

        table = Table(threat_data)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 14),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        elements.append(table)
        return elements

    def create_network_statistics_section(self, data):
        """Create network statistics section"""
        elements = []
        
        # Add network traffic graph
        if 'traffic_data' in data:
            elements.extend(self.create_traffic_graph(data['traffic_data']))

        # Add port statistics
        if 'port_statistics' in data:
            elements.extend(self.create_port_statistics(data['port_statistics']))

        return elements

    def create_recommendations_section(self, data):
        """Create security recommendations section"""
        elements = []
        
        recommendations = self.generate_recommendations(data)
        for rec in recommendations:
            elements.append(Paragraph(f"• {rec}", self.styles['Normal']))
            elements.append(Spacer(1, 6))

        return elements

    def generate_recommendations(self, data):
        """Generate security recommendations based on analysis"""
        recommendations = []
        threats = data.get('detected_threats', [])
        
        # Analyze threats and generate specific recommendations
        if any(t['type'] == 'port_scan' for t in threats):
            recommendations.append(
                "Implement port scan detection and prevention mechanisms.")
        
        if any(t['type'] == 'brute_force' for t in threats):
            recommendations.append(
                "Strengthen password policies and implement account lockout mechanisms.")
        
        if any(t['type'] == 'ddos' for t in threats):
            recommendations.append(
                "Deploy DDoS protection and traffic filtering solutions.")
        
        # Add general recommendations
        recommendations.extend([
            "Regularly update and patch all systems and applications.",
            "Implement network segmentation and access controls.",
            "Enable comprehensive logging and monitoring.",
            "Conduct regular security audits and penetration testing."
        ])
        
        return recommendations
    
class PinkertonIntegration:
    def initialize_components(self):
        """Initialize all components with proper integration"""
        # Set up callbacks
        self.packet_analyzer.callbacks.append(self.on_packet_captured)
        self.threat_detector.callbacks.append(self.on_threat_detected)
        self.network_monitor.alert_callbacks.append(self.on_network_alert)
        self.settings = self.load_settings()
        self.packet_analyzer = PacketAnalyzer()
        self.threat_detector = ThreatDetector()
        self.network_monitor = NetworkMonitor()
        self.ml_detector = MLThreatDetector()
        self.automated_response = AutomatedResponse()
        self.advanced_reporting = AdvancedReporting()
    
        self.initialize_components()

        # Initialize ML detector with historical data
        if self.settings['monitoring']['ml_detection']:
            self.train_ml_detector()


    def schedule_report_generation(self):
        """Schedule periodic report generation"""
        try:
            # Generate initial report
            self.generate_report()

            # Schedule next report based on settings
            interval = self.settings['reporting'].get('report_interval', 86400)  # Default 24 hours
            threading.Timer(interval, self.schedule_report_generation).start()
            
            logging.info(f"Scheduled next report generation in {interval} seconds")
        except Exception as e:
            logging.error(f"Error scheduling report generation: {str(e)}")

    def quick_vulnerability_scan(self, target, categories):
        """Perform quick vulnerability scan"""
        try:
            self.scanning = True
            self.vuln_status.config(text="Performing quick scan...")
            
            # Scan common ports and services
            ports = "21-23,25,53,80,110,143,443,445,3306,3389"
            results = self.network_mapper.scan_network(target, ports)
            
            if isinstance(results, str):
                self.vuln_status.config(text="Scan failed")
                return
                
            # Check for vulnerabilities
            for port in results.get(target, {}).get('tcp', {}):
                service = results[target]['tcp'][port]
                vulns = self.vulnerability_scanner.check_service_vulnerabilities(
                    service.get('name', '')
                )
                
                for vuln in vulns:
                    self.add_vulnerability(
                        "Medium",
                        "Service Vulnerability",
                        f"Port {port} ({service.get('name', 'unknown')}): {vuln}",
                        "Update service to latest version and apply security patches"
                    )
                    
            self.vuln_status.config(text="Quick scan completed")
            
        except Exception as e:
            logging.error(f"Quick scan error: {str(e)}")
            self.vuln_status.config(text="Scan failed")
        finally:
            self.scanning = False

    def full_vulnerability_scan(self, target, categories):
        """Perform full vulnerability scan"""
        try:
            self.scanning = True
            self.vuln_status.config(text="Performing full scan...")
            
            # Scan all ports
            results = self.network_mapper.scan_network(target, "1-65535")
            
            if isinstance(results, str):
                self.vuln_status.config(text="Scan failed")
                return
                
            # Check for vulnerabilities
            total_ports = len(results.get(target, {}).get('tcp', {}))
            for i, port in enumerate(results.get(target, {}).get('tcp', {})):
                if not self.scanning:
                    break
                    
                service = results[target]['tcp'][port]
                vulns = self.vulnerability_scanner.check_service_vulnerabilities(
                    service.get('name', '')
                )
                
                for vuln in vulns:
                    severity = "High" if "Remote Code Execution" in vuln else "Medium"
                    self.add_vulnerability(
                        severity,
                        "Service Vulnerability",
                        f"Port {port} ({service.get('name', 'unknown')}): {vuln}",
                        "Update service to latest version and apply security patches"
                    )
                
                # Update progress
                progress = ((i + 1) / total_ports) * 100
                self.vuln_progress['value'] = progress
                
            self.vuln_status.config(text="Full scan completed")
            
        except Exception as e:
            logging.error(f"Full scan error: {str(e)}")
            self.vuln_status.config(text="Scan failed")
        finally:
            self.scanning = False

    def custom_vulnerability_scan(self, target, categories):
        """Perform custom vulnerability scan"""
        try:
            self.scanning = True
            self.vuln_status.config(text="Performing custom scan...")
            
            # Scan based on selected categories
            if 'network_vulns' in categories:
                self.scan_network_vulnerabilities(target)
            if 'service_vulns' in categories:
                self.scan_service_vulnerabilities(target)
            if 'web_vulns' in categories:
                self.scan_web_vulnerabilities(target)
            if 'auth_vulns' in categories:
                self.scan_auth_vulnerabilities(target)
            if 'malware' in categories:
                self.scan_malware_indicators(target)
                
            self.vuln_status.config(text="Custom scan completed")
            
        except Exception as e:
            logging.error(f"Custom scan error: {str(e)}")
            self.vuln_status.config(text="Scan failed")
        finally:
            self.scanning = False    

    def load_settings(self):
        """Load application settings"""
        try:
            with open('pinkerton_settings.json', 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return self.create_default_settings()
        
    def initialize_components(self):
        """Initialize all components with proper integration"""
        # Set up callbacks
        self.packet_analyzer.callbacks.append(self.on_packet_captured)
        self.threat_detector.callbacks.append(self.on_threat_detected)
        self.network_monitor.alert_callbacks.append(self.on_network_alert)

        # Initialize ML detector with historical data
        if self.settings['monitoring']['ml_detection']:
            self.train_ml_detector()

    # Add these three new methods here
    def train_ml_detector(self):
        """Train the ML detector with historical data"""
        try:
            # Load or create training data
            training_data = self.load_training_data()
            if len(training_data) > 0:
                success = self.ml_detector.train(training_data)
                if success:
                    logging.info("ML detector trained successfully")
                else:
                    logging.warning("Not enough data to train ML detector")
            else:
                logging.warning("No training data available")
        except Exception as e:
            logging.error(f"Error training ML detector: {str(e)}")



    def load_training_data(self):
        """Load historical network data for training"""
        try:
            if os.path.exists('training_data.json'):
                with open('training_data.json', 'r') as f:
                    return json.load(f)
            return []
        except Exception as e:
            logging.error(f"Error loading training data: {str(e)}")
            return []

    def schedule_ml_retraining(self):
        """Schedule periodic retraining of ML model"""
        # Retrain every 24 hours
        threading.Timer(86400, self.train_ml_detector).start()

    def create_default_settings(self):
        """Create default settings"""
        settings = {
            'monitoring': {
                'packet_capture': True,
                'threat_detection': True,
                'ml_detection': True,
                'automated_response': True
            },
            'thresholds': {
                'port_scan': 10,
                'brute_force': 5,
                'ddos': 1000,
                'anomaly_score': 0.8
            },
            'reporting': {
                'auto_generate': True,
                'report_interval': 86400,  # 24 hours
                'save_path': 'reports/'
            },
            'notifications': {
                'email': False,
                'desktop': True,
                'log': True
            }
        }
        
        # Save default settings
        with open('pinkerton_settings.json', 'w') as f:
            json.dump(settings, f, indent=4)
        
        return settings

    def initialize_components(self):
        """Initialize all components with proper integration"""
        # Set up callbacks
        self.packet_analyzer.callbacks.append(self.on_packet_captured)
        self.threat_detector.callbacks.append(self.on_threat_detected)
        self.network_monitor.alert_callbacks.append(self.on_network_alert)

        # Initialize ML detector with historical data
        if self.settings['monitoring']['ml_detection']:
            self.train_ml_detector()


    def stop_monitoring(self):
        """Stop all monitoring components"""
        self.packet_analyzer.stop_capture()
        self.network_monitor.stop_monitoring()

    def start_periodic_tasks(self):
        """Start periodic maintenance tasks"""
        # Schedule report generation
        if self.settings['reporting']['auto_generate']:
            self.schedule_report_generation()

        # Schedule ML model retraining
        if self.settings['monitoring']['ml_detection']:
            self.schedule_ml_retraining()

    def on_packet_captured(self, packet_data):
        """Handle captured packet"""
        # Analyze packet with ML detector
        if self.settings['monitoring']['ml_detection']:
            is_anomaly = self.ml_detector.detect_anomaly(packet_data)
            if is_anomaly:
                self.handle_anomaly(packet_data)

        # Standard threat detection
        if self.settings['monitoring']['threat_detection']:
            self.threat_detector.analyze_traffic(packet_data)

    def on_threat_detected(self, threat):
        """Handle detected threat"""
        # Log threat
        logging.warning(f"Threat detected: {threat['type']} from {threat['source_ip']}")

        # Automated response
        if self.settings['monitoring']['automated_response']:
            self.automated_response.execute_response(threat)

        # Notifications
        self.send_notifications(threat)

    def on_network_alert(self, alert):
        """Handle network alert"""
        logging.info(f"Network alert: {alert['message']}")
        if alert['severity'] == 'high':
            self.send_notifications(alert)

    def handle_anomaly(self, packet_data):
        """Handle ML-detected anomaly"""
        threat = {
            'type': 'ml_anomaly',
            'severity': 'medium',
            'source_ip': packet_data.get('src_ip'),
            'details': packet_data
        }
        self.on_threat_detected(threat)

    def send_notifications(self, event):
        """Send notifications based on settings"""
        if self.settings['notifications']['email']:
            self.send_email_notification(event)
        
        if self.settings['notifications']['desktop']:
            self.send_desktop_notification(event)
        
        if self.settings['notifications']['log']:
            self.log_event(event)


    def collect_report_data(self):
        """Collect data for report generation"""
        return {
            'detected_threats': self.threat_detector.detected_threats,
            'network_statistics': self.network_monitor.bandwidth_history,
            'automated_responses': len(self.automated_response.active_responses),
            'blocked_ips': len(self.threat_detector.blacklist),
            'ml_anomalies': self.ml_detector.training_data[-1000:],  # Last 1000 records
            'system_info': SystemInfo.get_system_info()
        }
    
class SystemInfo:
    @staticmethod
    def get_system_info():
        return {
            'platform': platform.platform(),
            'processor': platform.processor(),
            'memory': psutil.virtual_memory()._asdict(),
            'disk': psutil.disk_usage('/')._asdict(),
            'python_version': platform.python_version()
        }

class PinkertonApp:
    """Main application class"""
    def __init__(self):
        self.root = tk.Tk()
        self.integration = PinkertonIntegration()
        self.gui = PinkertonGUI(self.root)
        
        # Connect GUI with integration
        self.connect_gui_callbacks()
        
        # Set up application closing handler
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def connect_gui_callbacks(self):
        """Connect GUI callbacks with integration layer"""
        self.gui.start_monitoring = self.integration.start_monitoring
        self.gui.stop_monitoring = self.integration.stop_monitoring
        self.gui.generate_report = self.integration.generate_report

    def run(self):
        """Run the application"""
        try:
            # Display startup banner
            print(BANNER)
            
            # Start integration components
            self.integration.start_monitoring()
            
            # Start GUI main loop
            self.root.mainloop()
        except Exception as e:
            logging.error(f"Application error: {str(e)}")
            raise

    def on_closing(self):
        """Handle application closing"""
        try:
            # Stop monitoring
            self.integration.stop_monitoring()
            
            # Generate final report
            self.integration.generate_report()
            
            # Save settings
            with open('pinkerton_settings.json', 'w') as f:
                json.dump(self.integration.settings, f, indent=4)
            
            # Close application
            self.root.destroy()
        except Exception as e:
            logging.error(f"Error during shutdown: {str(e)}")

def main():
    """Main entry point"""
    try:
        # Configure logging
        logging.basicConfig(
            filename='pinkerton.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        
        # Create reports directory
        os.makedirs('reports', exist_ok=True)
        
        # Start application
        app = PinkertonApp()
        app.run()
    except Exception as e:
        logging.critical(f"Fatal error: {str(e)}")
        print(f"Fatal error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
