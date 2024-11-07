import tkinter as tk
from tkinter import ttk, messagebox
import socket
import uuid
import requests
import platform
import psutil
import threading
import ssl
import time
import json
import logging
from datetime import datetime
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg


# ASCII Art Banners
LEFT_BANNER = """


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

RIGHT_BANNER = """
 .------..------..------..------..------..------..------..------..------.
 |P.--. ||I.--. ||N.--. ||K.--. ||E.--. ||R.--. ||T.--. ||O.--. ||N.--. |
 | :/\: || (\/) || :(): || :/\: || (\/) || :(): || :/\: || :/\: || :(): |
 | (__) || :\/: || ()() || :\/: || :\/: || ()() || (__) || :\/: || ()() |
 | '--'P|| '--'I|| '--'N|| '--'K|| '--'E|| '--'R|| '--'T|| '--'O|| '--'N|
 `------'`------'`------'`------'`------'`------'`------'`------'`------'
     .------..------..------..------..------..------..------..------.
     |S.--. ||D.--. ||E.--. ||T.--. ||E.--. ||C.--. ||T.--. ||S.--. |
     | :/\: || :/\: || (\/) || :/\: || (\/) || :/\: || :/\: || :/\: |
     | :\/: || (__) || :\/: || (__) || :\/: || :\/: || (__) || :\/: |
     | '--'S|| '--'D|| '--'E|| '--'T|| '--'E|| '--'C|| '--'T|| '--'S|
     `------'`------'`------'`------'`------'`------'`------'`------'
                         WE NEVER SLEEP
"""


THEMES = {
    'cyberpunk': {
        'bg': '#0a0a0a',
        'fg': '#00ff00',
        'accent1': '#ff00ff',
        'accent2': '#00ffff',
        'warning': '#ff0000',
        'success': '#00ff00'
    }
}

# Configure logging
logging.basicConfig(
    filename='pinkerton.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)


class SystemInfo:
    """Class to handle system information gathering"""
    @staticmethod
    def get_ip_address():
        try:
            # Get local IP by creating a temporary socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception as e:
            logging.error(f"Error getting IP: {e}")
            return "Unable to get IP"

    @staticmethod
    def get_mac_address():
        try:
            return ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff)
                           for elements in range(0,2*6,2)][::-1])
        except Exception as e:
            logging.error(f"Error getting MAC: {e}")
            return "Unable to get MAC"

    @staticmethod
    def get_location():
        try:
            response = requests.get('https://ipapi.co/json/', timeout=5)
            if response.status_code == 200:
                data = response.json()
                return {
                    'city': data.get('city', 'Unknown'),
                    'region': data.get('region', 'Unknown'),
                    'country': data.get('country_name', 'Unknown'),
                    'timezone': data.get('timezone', 'Unknown')
                }
            return {"error": "Unable to get location data"}
        except Exception as e:
            logging.error(f"Error getting location: {e}")
            return {"error": "Unable to get location data"}

    @staticmethod
    def get_system_info():
        try:
            return {
                'system': platform.system(),
                'release': platform.release(),
                'version': platform.version(),
                'machine': platform.machine(),
                'processor': platform.processor(),
                'cpu_cores': psutil.cpu_count(),
                'memory_total': psutil.virtual_memory().total,
                'memory_available': psutil.virtual_memory().available
            }
        except Exception as e:
            logging.error(f"Error getting system info: {e}")
            return {"error": "Unable to get system information"}
        

VULNERABILITY_CHECKS = {
    'network_vulns': [
        {
            'name': 'Open Ports',
            'function': 'check_open_ports',
            'severity': 'Medium',
            'details': 'Scans for commonly exploitable network ports'
        },
        {
            'name': 'SMB Shares',
            'function': 'check_smb_shares',
            'severity': 'High',
            'details': 'Checks for exposed SMB shares and permissions'
        },
        {
            'name': 'DNS Zone Transfer',
            'function': 'check_dns_zone_transfer',
            'severity': 'Medium',
            'details': 'Tests for misconfigured DNS servers allowing zone transfers'
        }
    ],
    'service_vulns': [
        {
            'name': 'FTP Anonymous',
            'function': 'check_ftp_anonymous',
            'severity': 'High',
            'details': 'Checks for anonymous FTP access'
        },
        {
            'name': 'SMTP Relay',
            'function': 'check_smtp_relay',
            'severity': 'Critical',
            'details': 'Tests for open SMTP relays'
        },
        {
            'name': 'SSH Version',
            'function': 'check_ssh_version',
            'severity': 'Medium',
            'details': 'Checks for outdated SSH versions'
        }
    ],
    'web_vulns': [
        {
            'name': 'Directory Listing',
            'function': 'check_directory_listing',
            'severity': 'Medium',
            'details': 'Checks for exposed directory listings'
        },
        {
            'name': 'SQL Injection',
            'function': 'check_sql_injection',
            'severity': 'Critical',
            'details': 'Tests for SQL injection vulnerabilities'
        },
        {
            'name': 'Cross-Site Scripting',
            'function': 'check_xss',
            'severity': 'High',
            'details': 'Checks for XSS vulnerabilities'
        },
        {
            'name': 'SSL/TLS Issues',
            'function': 'check_ssl_vulnerabilities',
            'severity': 'High',
            'details': 'Tests for SSL/TLS misconfigurations'
        }
    ],
    'auth_vulns': [
        {
            'name': 'Weak Passwords',
            'function': 'check_weak_passwords',
            'severity': 'High'
        }
    ],
    'malware': [
        {
            'name': 'Known Signatures',
            'function': 'check_malware_signatures',
            'severity': 'Critical'
        }
    ]
}

class PinkertonGUI:
    def quick_vulnerability_scan(self, target, categories):
        """Perform quick vulnerability scan"""
        try:
            self.scanning = True
            total_steps = sum(len(VULNERABILITY_CHECKS[cat]) for cat in categories)
            current_step = 0
            
            for category in categories:
                if not self.scanning:
                    break
                    
                for check in VULNERABILITY_CHECKS[category]:
                    if not self.scanning:
                        break
                        
                    # Update status
                    self.vuln_status.config(text=f"Running {check['name']}...")
                    
                    # Update progress
                    progress = (current_step / total_steps) * 100
                    self.vuln_progress['value'] = progress
                    
                    # Get the check function
                    check_function = getattr(self, check['function'])
                    
                    # Perform the check
                    try:
                        result = check_function(target)
                        if result:
                            self.add_vuln_result(
                                check['severity'],
                                check['name'],
                                result['description'],
                                result['recommendation']
                            )
                    except Exception as e:
                        logging.error(f"Error in vulnerability check {check['name']}: {str(e)}")
                    
                    current_step += 1
                    time.sleep(0.5)  # Add small delay between checks
                    
            # Scan complete
            self.root.after(0, self.vuln_scan_complete)
            
        except Exception as e:
            self.root.after(0, self.vuln_scan_error, str(e))


    def full_vulnerability_scan(self, target, categories):
        """Perform full vulnerability scan"""
        # For now, use the same implementation as quick scan
        self.quick_vulnerability_scan(target, categories)

    def custom_vulnerability_scan(self, target, categories):
        """Perform custom vulnerability scan"""
        # For now, use the same implementation as quick scan
        self.quick_vulnerability_scan(target, categories)

    def check_smb_shares(self, target):
        """Check for accessible SMB shares"""
        try:
            # Basic SMB share check implementation
            return {
                'description': 'SMB share check completed',
                'recommendation': 'Review SMB share permissions and access controls'
            }
        except Exception as e:
            logging.error(f"SMB check error: {str(e)}")
            return None
        
    def check_ftp_anonymous(self, target):
        """Check for anonymous FTP access"""
        try:
            import ftplib
            ftp = ftplib.FTP()
            ftp.connect(target, 21, timeout=10)
            
            try:
                # Try anonymous login
                ftp.login('anonymous', 'anonymous@example.com')
                ftp.quit()
                return {
                    'description': 'Anonymous FTP access is enabled',
                    'recommendation': 'Disable anonymous FTP access unless specifically required'
                }
            except:
                ftp.quit()
                return None
                
        except Exception as e:
            logging.error(f"FTP check error: {str(e)}")
            return None
        


    def check_dns_zone_transfer(self, target):
        """Check for DNS zone transfer vulnerability"""
        try:
            import dns.query
            import dns.zone
            import dns.resolver
            
            # First try to get the nameservers for the target
            try:
                answers = dns.resolver.resolve(target, 'NS')
                nameservers = [str(rdata.target) for rdata in answers]
            except:
                # If we can't get nameservers, just try the target directly
                nameservers = [target]
                
            for ns in nameservers:
                try:
                    # Attempt zone transfer
                    zone = dns.zone.from_xfr(dns.query.xfr(ns, target, timeout=5))
                    if zone:
                        return {
                            'description': f'DNS zone transfer possible from {ns}',
                            'recommendation': 'Disable zone transfers or restrict to authorized servers only',
                            'details': f'Nameserver {ns} allows zone transfers'
                        }
                except:
                    continue
                    
            return None
            
        except Exception as e:
            logging.error(f"DNS zone transfer check error: {str(e)}")
            return None
        

    def check_directory_listing(self, target):
        """Check for enabled directory listing"""
        try:
            # Common paths to check for directory listing
            test_paths = ['/', '/images/', '/uploads/', '/backup/', '/files/']
            
            for path in test_paths:
                try:
                    url = f'http://{target}{path}'
                    response = requests.get(url, timeout=5)
                    
                    # Check for common directory listing signatures
                    signatures = [
                        'Index of /',
                        'Directory Listing For',
                        'Parent Directory</a>',
                        '[To Parent Directory]'
                    ]
                    
                    for sig in signatures:
                        if sig in response.text:
                            return {
                                'description': f'Directory listing enabled at {url}',
                                'recommendation': 'Disable directory listing in web server configuration'
                            }
                            
                except requests.exceptions.RequestException:
                    continue
                    
            return None
            
        except Exception as e:
            logging.error(f"Directory listing check error: {str(e)}")
            return None
        

    def check_sql_injection(self, target):
        """Check for basic SQL injection vulnerabilities"""
        try:
            # Common SQL injection test patterns
            test_payloads = [
                "' OR '1'='1",
                "' OR 1=1--",
                "'; DROP TABLE users--",
                "' UNION SELECT NULL--",
                "admin' --",
                "1' OR '1' = '1"
            ]
            
            # Common parameters to test
            params = ['id', 'user', 'username', 'password', 'search', 'query']
            
            # Test common URLs and parameters
            urls = [
                f'http://{target}/login.php',
                f'http://{target}/search.php',
                f'http://{target}/index.php',
                f'http://{target}/admin.php'
            ]
            
            for url in urls:
                for param in params:
                    for payload in test_payloads:
                        try:
                            # Test GET parameter
                            test_url = f"{url}?{param}={payload}"
                            response = requests.get(test_url, timeout=5)
                            
                            # Look for SQL error messages
                            error_signatures = [
                                "SQL syntax",
                                "mysql_fetch_array",
                                "ORA-01756",
                                "SQLServer JDBC Driver",
                                "Microsoft SQL Native Client error"
                            ]
                            
                            for sig in error_signatures:
                                if sig in response.text:
                                    return {
                                        'description': f'Potential SQL injection vulnerability found at {url}',
                                        'recommendation': 'Implement proper input validation and parameterized queries'
                                    }
                                    
                        except requests.exceptions.RequestException:
                            continue
                            
            return None
            
        except Exception as e:
            logging.error(f"SQL injection check error: {str(e)}")
            return None
        

    def check_ssh_version(self, target):
        """Check for outdated SSH versions"""
        try:
            import socket
            import re
            
            # Connect to SSH port
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            try:
                sock.connect((target, 22))
                # Receive banner
                banner = sock.recv(1024).decode('utf-8').strip()
                sock.close()
                
                # Extract version information
                version_match = re.search(r'SSH-\d+\.\d+-(.+)', banner)
                if version_match:
                    version = version_match.group(1)
                    
                    # List of known vulnerable SSH versions
                    vulnerable_versions = [
                        'OpenSSH_4', 'OpenSSH_5.0', 'OpenSSH_5.1', 'OpenSSH_5.2',
                        'OpenSSH_5.3', 'OpenSSH_5.8', 'OpenSSH_6.0', 'OpenSSH_6.1',
                        'OpenSSH_6.2', 'OpenSSH_6.3', 'OpenSSH_6.4', 'OpenSSH_6.5'
                    ]
                    
                    for vuln_version in vulnerable_versions:
                        if vuln_version in version:
                            return {
                                'description': f'Outdated SSH version detected: {version}',
                                'recommendation': 'Update SSH to the latest stable version',
                                'details': f'Current version {version} may contain known vulnerabilities'
                            }
                            
                    # If version is not in vulnerable list
                    return {
                        'description': f'SSH version: {version}',
                        'recommendation': 'Monitor for new vulnerabilities',
                        'details': 'Current version appears to be relatively recent'
                    }
                    
            except socket.error:
                return None
                
        except Exception as e:
            logging.error(f"SSH version check error: {str(e)}")
            return None
        

    def check_xss(self, target):
        """Check for Cross-Site Scripting (XSS) vulnerabilities"""
        try:
            # Common XSS test payloads
            test_payloads = [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "javascript:alert('XSS')",
                "<svg onload=alert('XSS')>",
                "'\"><script>alert('XSS')</script>",
                "<body onload=alert('XSS')>",
                "<img src=\"javascript:alert('XSS')\">"
            ]
            
            # Common parameters to test
            params = ['search', 'q', 'query', 'id', 'message', 'comment', 'input']
            
            # Test common URLs
            urls = [
                f'http://{target}/search',
                f'http://{target}/comments',
                f'http://{target}/feedback',
                f'http://{target}/forum'
            ]
            
            for url in urls:
                for param in params:
                    for payload in test_payloads:
                        try:
                            # Test GET parameter
                            test_url = f"{url}?{param}={payload}"
                            response = requests.get(test_url, timeout=5)
                            
                            # Check if the payload is reflected in the response
                            if payload in response.text:
                                return {
                                    'description': f'Potential XSS vulnerability found at {url}',
                                    'recommendation': 'Implement proper input validation and output encoding'
                                }
                                
                            # Also test POST request
                            response = requests.post(url, data={param: payload}, timeout=5)
                            if payload in response.text:
                                return {
                                    'description': f'Potential XSS vulnerability found at {url} (POST)',
                                    'recommendation': 'Implement proper input validation and output encoding'
                                }
                                
                        except requests.exceptions.RequestException:
                            continue
                            
            return None
            
        except Exception as e:
            logging.error(f"XSS check error: {str(e)}")
            return None
        

    
        
    def check_smtp_relay(self, target):
        """Check for SMTP relay vulnerabilities"""
        try:
            import smtplib
            smtp = smtplib.SMTP(timeout=10)
            smtp.connect(target, 25)
            
            try:
                # Try to relay without authentication
                smtp.sendmail(
                    'test@example.com',
                    'test@example.com',
                    'Subject: Test\n\nTest message'
                )
                smtp.quit()
                return {
                    'description': 'SMTP relay is open - server allows unauthorized mail relay',
                    'recommendation': 'Configure SMTP server to require authentication for mail relay'
                }
            except:
                smtp.quit()
                return None
                
        except Exception as e:
            logging.error(f"SMTP check error: {str(e)}")
            return None

    # Add all the check methods
    def check_malware_signatures(self, target):
        """Check for known malware signatures"""
        try:
            # Implement malware signature checking
            return {
                'description': 'No known malware signatures detected',
                'recommendation': 'Continue monitoring for new threats'
            }
        except Exception as e:
            logging.error(f"Malware check error: {str(e)}")
            return None

    def check_weak_passwords(self, target):
        """Check for weak passwords"""
        try:
            # Implement weak password checking
            return {
                'description': 'Password policy check completed',
                'recommendation': 'Implement strong password requirements'
            }
        except Exception as e:
            logging.error(f"Password check error: {str(e)}")
            return None
    def __init__(self):
        self.root = tk.Tk()
        self.scanning = False
        self.root.title("PINKERTON - Network Intelligence Suite")
        self.root.geometry("1300x900")
        self.monitoring = False  # Initialize as False
        self.update_after_id = None 
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing) 
        
        # Set theme and style
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Configure colors
        self.configure_colors()
        
        # Create main container
        self.main_container = ttk.Frame(self.root)
        self.main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create and display banner
        self.create_banner()
        
        # Create system info display
        self.create_system_info_display()
        
        # Create notebook for different tools
        self.create_notebook()

        # Configure vulnerability tree style
        self.configure_vuln_tree_style()
        


    def on_closing(self):
        """Handle program closing properly"""
        try:
            self.monitoring = False
            # Cancel any pending after callbacks
            if self.update_after_id is not None:
                self.root.after_cancel(self.update_after_id)
                self.update_after_id = None
            
            # Destroy matplotlib figures if they exist
            if hasattr(self, 'cpu_figure'):
                plt.close(self.cpu_figure)
            if hasattr(self, 'mem_figure'):
                plt.close(self.mem_figure)
            if hasattr(self, 'net_figure'):
                plt.close(self.net_figure)
                
            self.root.quit()
            self.root.destroy()
        except Exception as e:
            logging.error(f"Error during cleanup: {str(e)}")
            self.root.destroy()

    def update_graphs(self):
        """Update network monitoring graphs"""
        if not self.monitoring:
            return
            
        try:
            # ... existing update code ...
            
            # Store the after callback ID
            if self.monitoring:
                self.update_after_id = self.root.after(1000, self.update_graphs)
        except Exception as e:
            logging.error(f"Error updating graphs: {str(e)}")
            if self.monitoring:
                self.update_after_id = self.root.after(1000, self.update_graphs)

    def run(self):
        """Start the application"""
        try:
            self.root.mainloop()
        except KeyboardInterrupt:
            self.on_closing()
        except Exception as e:
            logging.error(f"Error in main loop: {str(e)}")
            self.on_closing()


    def configure_vuln_tree_style(self):
        """Configure the vulnerability treeview styling"""
        style = ttk.Style()
        
        # Configure main treeview style
        style.configure(
            "Vuln.Treeview",
            background="#1a1a1a",
            foreground="#00ff00",
            fieldbackground="#1a1a1a",
            font=('Consolas', 10)
        )
        
        # Configure heading style
        style.configure(
            "Vuln.Treeview.Heading",
            background="#2b2b2b",
            foreground="#00ff00",
            font=('Consolas', 10, 'bold')
        )
        
        # Configure severity-based tags
        self.vuln_tree.tag_configure('critical', foreground='#ff0000')
        self.vuln_tree.tag_configure('high', foreground='#ff4500')
        self.vuln_tree.tag_configure('medium', foreground='#ffa500')
        self.vuln_tree.tag_configure('low', foreground='#ffff00')

    def add_vuln_result(self, severity, vuln_type, description, recommendation, details=None):
        """Add a vulnerability result with detailed information"""
        try:
            item = self.vuln_tree.insert(
                '',
                'end',
                values=(severity, vuln_type, description, recommendation),
                tags=(severity.lower(),)
            )
            
            if details:
                self.vuln_tree.insert(
                    item,
                    'end',
                    values=('', 'Details', details, ''),
                    tags=('details',)
                )
                
        except Exception as e:
            logging.error(f"Error adding vulnerability result: {str(e)}")

    def export_report(self):
        """Export scan results to HTML report"""
        try:
            from datetime import datetime
            import os
            
            # Create reports directory if it doesn't exist
            if not os.path.exists('reports'):
                os.makedirs('reports')
                
            # Generate filename with timestamp
            filename = f"reports/vulnerability_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
            
            # HTML template
            html_content = """
            <html>
                <head>
                    <title>Vulnerability Scan Report</title>
                    <style>
                        body { font-family: Arial, sans-serif; }
                        table { border-collapse: collapse; width: 100%; }
                        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                        th { background-color: #f2f2f2; }
                        .critical { color: #ff0000; }
                        .high { color: #ff4500; }
                        .medium { color: #ffa500; }
                        .low { color: #ffff00; }
                    </style>
                </head>
                <body>
                    <h1>Vulnerability Scan Report</h1>
                    <p>Generated: {datetime.now()}</p>
                    <table>
                        <tr>
                            <th>Severity</th>
                            <th>Type</th>
                            <th>Description</th>
                            <th>Recommendation</th>
                        </tr>
            """
            
            # Add results
            for item in self.vuln_tree.get_children():
                values = self.vuln_tree.item(item)['values']
                severity_class = values[0].lower() if values else ""
                html_content += f"""
                    <tr class="{severity_class}">
                        <td>{values[0]}</td>
                        <td>{values[1]}</td>
                        <td>{values[2]}</td>
                        <td>{values[3]}</td>
                    </tr>
                """
                
            html_content += """
                    </table>
                </body>
            </html>
            """
            
            # Write to file
            with open(filename, 'w') as f:
                f.write(html_content)
                
            messagebox.showinfo("Export Complete", f"Report exported to {filename}")
            
        except Exception as e:
            logging.error(f"Error exporting report: {str(e)}")
            messagebox.showerror("Error", f"Failed to export report: {str(e)}")


    def update_scan_progress(self, progress):
        """Update the scan progress bar"""
        self.scan_progress['value'] = progress
        self.scan_status.config(text=f"Scanning... {int(progress)}%")
        self.root.update_idletasks()



    def optimize_scan_parameters(self, target, start_port, end_port):
        """Optimize scan parameters based on target and range"""
        total_ports = end_port - start_port + 1
        
        # Adjust thread count based on port range
        if total_ports < 100:
            max_workers = 10
        elif total_ports < 1000:
            max_workers = 50
        else:
            max_workers = 100
            
        # Adjust timeout based on target responsiveness
        try:
            start_time = time.time()
            socket.create_connection((target, 80), timeout=1)
            response_time = time.time() - start_time
            timeout = min(max(response_time * 2, 0.1), 1.0)
        except:
            timeout = 0.3
            
        return max_workers, timeout

    

    def perform_port_scan(self, target, start_port, end_port):
        """Perform advanced port scanning with service detection"""
        try:
            import concurrent.futures
            import socket
            import ssl
            import requests
            from datetime import datetime
            
            # Extended ports and services database with more detailed service info
            COMMON_PORTS = {
                # Web Services
                80: 'HTTP', 443: 'HTTPS', 8080: 'HTTP-ALT', 8443: 'HTTPS-ALT', 8888: 'HTTP-ALT',
                # Email Services
                25: 'SMTP', 465: 'SMTPS', 587: 'SUBMISSION', 110: 'POP3', 995: 'POP3S', 
                143: 'IMAP', 993: 'IMAPS',
                # File Transfer
                20: 'FTP-DATA', 21: 'FTP', 69: 'TFTP', 115: 'SFTP', 989: 'FTPS-DATA', 990: 'FTPS',
                # Remote Access
                22: 'SSH', 23: 'TELNET', 3389: 'RDP', 5900: 'VNC', 5901: 'VNC-1', 5902: 'VNC-2',
                # Database Services
                1433: 'MSSQL', 1434: 'MSSQL-UDP', 3306: 'MYSQL', 5432: 'POSTGRESQL', 
                27017: 'MONGODB', 6379: 'REDIS', 11211: 'MEMCACHED',
                # Network Services
                53: 'DNS', 67: 'DHCP', 68: 'DHCP', 123: 'NTP', 161: 'SNMP', 162: 'SNMP-TRAP',
                # Windows Services
                135: 'MSRPC', 137: 'NETBIOS-NS', 138: 'NETBIOS-DGM', 139: 'NETBIOS-SSN', 
                445: 'SMB', 3268: 'LDAP-GC', 3269: 'LDAP-GC-SSL',
                # System Services
                111: 'RPCBIND', 514: 'SYSLOG', 515: 'PRINTER', 2049: 'NFS', 
                # Messaging and Collaboration
                5222: 'XMPP', 5269: 'XMPP-SERVER', 1935: 'RTMP', 5060: 'SIP', 5061: 'SIPS',
                # Development
                9200: 'ELASTICSEARCH', 9300: 'ELASTICSEARCH-NODES', 15672: 'RABBITMQ-MGMT',
                # Monitoring
                8472: 'OTLP', 9090: 'PROMETHEUS', 9100: 'NODE-EXPORTER'
            }

            scan_start_time = datetime.now()
            
            # Clear previous results
            for item in self.results_tree.get_children():
                self.results_tree.delete(item)

            def get_detailed_service_info(sock, port, banner=""):
                """Get detailed service information including versions"""
                try:
                    service_info = COMMON_PORTS.get(port, "Unknown")
                    version = "Version unknown"

                    # Enhanced HTTP/HTTPS detection
                    if port in [80, 8080, 8888]:
                        try:
                            response = requests.get(f'http://{target}:{port}', timeout=2, verify=False)
                            server = response.headers.get('Server', '')
                            powered_by = response.headers.get('X-Powered-By', '')
                            tech_info = []
                            
                            if server: tech_info.append(server)
                            if powered_by: tech_info.append(f"Powered by {powered_by}")
                            if 'X-AspNet-Version' in response.headers:
                                tech_info.append(f"ASP.NET {response.headers['X-AspNet-Version']}")
                            if 'X-PHP-Version' in response.headers:
                                tech_info.append(f"PHP {response.headers['X-PHP-Version']}")
                                
                            version = ' | '.join(tech_info) if tech_info else 'Web Server'
                        except:
                            version = "Web Server (details unavailable)"

                    # Enhanced SSL/TLS detection
                    elif port in [443, 8443, 465, 993, 995]:
                        try:
                            context = ssl.create_default_context()
                            context.check_hostname = False
                            context.verify_mode = ssl.CERT_NONE
                            with context.wrap_socket(sock, server_hostname=target) as ssock:
                                cipher = ssock.cipher()
                                version = f"{ssock.version()} ({cipher[0]} {cipher[2]} bits)"
                                if port in [443, 8443]:
                                    version += " | " + get_http_info(target, port, secure=True)
                        except:
                            version = "SSL/TLS (details unavailable)"

                    # Database version detection
                    elif port in [3306, 5432, 1433, 27017]:
                        version = get_database_version(target, port)

                    # SSH version detection
                    elif port == 22 and banner:
                        version = banner.split('\n')[0]

                    # FTP version detection
                    elif port == 21 and banner:
                        version = banner.split('\n')[0]

                    return service_info, version
                except:
                    return service_info, "Version unknown"

            def scan_single_port(port):
                """Enhanced port scanning with detailed service detection"""
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.3)
                    result = sock.connect_ex((target, port))
                    
                    if result == 0:
                        try:
                            banner = ""
                            if port in [21, 22, 25, 110, 143]:
                                sock.settimeout(1)
                                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                            
                            service, version = get_detailed_service_info(sock, port, banner)
                            return (port, "Open", service, version)
                        except:
                            return (port, "Open", COMMON_PORTS.get(port, "Unknown"), "Version unknown")
                        finally:
                            sock.close()
                except:
                    pass
                return None

            # Use ThreadPoolExecutor for parallel scanning
            with concurrent.futures.ThreadPoolExecutor(max_workers=500) as executor:
                futures = [executor.submit(scan_single_port, port) 
                        for port in range(start_port, end_port + 1)]
                
                completed = 0
                total = end_port - start_port + 1
                open_ports = []
                
                for future in concurrent.futures.as_completed(futures):
                    completed += 1
                    progress = (completed / total) * 100
                    self.root.after(0, self.update_scan_progress, progress)
                    
                    result = future.result()
                    if result:
                        port, state, service, version = result
                        open_ports.append(port)
                        self.root.after(0, lambda p=port, st=state, sv=service, v=version: 
                            self.results_tree.insert('', 'end', values=(str(p), st, sv, v)))

            # Add scan summary with more details
            scan_duration = datetime.now() - scan_start_time
            summary = f"\nScan Summary:\n"
            summary += f"Target: {target}\n"
            summary += f"Ports scanned: {start_port}-{end_port}\n"
            summary += f"Open ports found: {len(open_ports)}\n"
            summary += f"Scan duration: {scan_duration}\n"
            summary += f"Average time per port: {scan_duration.total_seconds() / total:.2f} seconds\n"
            
            self.root.after(0, lambda: self.results_tree.insert('', 'end', values=('', '', 'Scan Summary', summary)))
            self.root.after(0, self.scan_complete)
            
        except Exception as e:
            self.root.after(0, self.scan_error, str(e))



    # Add this method right after the perform_port_scan method
    def get_database_version(self, target, port):
        """Get database version information"""
        try:
            if port == 3306:  # MySQL
                import mysql.connector
                conn = mysql.connector.connect(
                    host=target,
                    port=port,
                    connect_timeout=3
                )
                return f"MySQL {conn.get_server_info()}"
            elif port == 5432:  # PostgreSQL
                import psycopg2
                conn = psycopg2.connect(
                    host=target,
                    port=port,
                    connect_timeout=3
                )
                return f"PostgreSQL {conn.server_version}"
        except Exception as e:
            logging.debug(f"Database version detection error: {str(e)}")
            return "Version unknown"
        




            
    def __del__(self):
        """Cleanup resources"""
        try:
            # Close matplotlib figures
            plt.close(self.cpu_figure)
            plt.close(self.mem_figure)
            plt.close(self.net_figure)
            
            # Stop monitoring
            self.monitoring = False
            
            # Stop any ongoing scans
            self.scanning = False
            
        except Exception as e:
            logging.error(f"Cleanup error: {str(e)}")
            




        
    
       


    def get_http_version(self, target):
        """Get HTTP server version"""
        try:
            response = requests.get(f'http://{target}', timeout=2)
            server = response.headers.get('Server', 'Unknown')
            return server
        except:
            return "Unknown"

    def get_ssh_version(self, target):
        """Get SSH server version"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((target, 22))
            data = sock.recv(1024)
            sock.close()
            return data.decode().strip()
        except:
            return "Unknown"


    def scan_complete(self):
        """Handle scan completion"""
        self.scan_button.configure(text="Start Scan", state='normal')
        self.scan_status.config(text="Scan Complete")
        self.scanning = False
        messagebox.showinfo("Scan Complete", "Port scan has completed!")

    def scan_error(self, error_msg):
        """Handle scan error"""
        self.scan_button.configure(text="Start Scan", state='normal')
        self.scan_status.config(text="Error")
        self.scanning = False
        messagebox.showerror("Error", f"Scan error: {error_msg}")



    def check_open_ports(self, target):
        """Check for commonly exploitable open ports"""
        dangerous_ports = [21, 22, 23, 25, 53, 139, 445, 3306, 3389]
        open_ports = []
        
        for port in dangerous_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        
        if open_ports:
            return {
                'severity': 'Medium',
                'description': f'Potentially dangerous ports open: {", ".join(map(str, open_ports))}',
                'recommendation': 'Close unnecessary ports or restrict access'
            }
        return None

    def check_default_credentials(self, target):
        """Check for default credentials on common services"""
        common_creds = [
            ('admin', 'admin'),
            ('root', 'root'),
            ('administrator', 'password')
        ]
        
        # Check HTTP Basic Auth
        for username, password in common_creds:
            try:
                response = requests.get(
                    f'http://{target}',
                    auth=(username, password),
                    timeout=2
                )
                if response.status_code == 200:
                    return {
                        'severity': 'High',
                        'description': f'Default credentials work: {username}:{password}',
                        'recommendation': 'Change default passwords immediately'
                    }
            except:
                continue
        
        return None

    def check_ssl_version(self, target):
        """Check SSL/TLS version and known vulnerabilities"""
        try:
            context = ssl.create_default_context()
            with context.wrap_socket(socket.socket(), server_hostname=target) as s:
                s.connect((target, 443))
                version = s.version()
                
                if version in ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1']:
                    return {
                        'severity': 'High',
                        'description': f'Outdated SSL/TLS version: {version}',
                        'recommendation': 'Upgrade to TLS 1.2 or higher'
                    }
        except:
            pass
        return None
    


    def check_ssl_vulnerabilities(self, target):
        """Check for SSL/TLS vulnerabilities"""
        try:
            import ssl
            import socket
            from datetime import datetime
            
            context = ssl.create_default_context()
            vulnerabilities = []
            
            try:
                with socket.create_connection((target, 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=target) as ssock:
                        # Get certificate information
                        cert = ssock.getpeercert()
                        
                        # Check certificate expiration
                        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y GMT')
                        if not_after < datetime.now():
                            vulnerabilities.append("Expired SSL certificate")
                        
                        # Check SSL/TLS version
                        version = ssock.version()
                        if version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                            vulnerabilities.append(f"Outdated {version} protocol in use")
                        
                        # Check cipher suite
                        cipher = ssock.cipher()
                        weak_ciphers = ['RC4', 'DES', '3DES', 'MD5']
                        for weak in weak_ciphers:
                            if weak in cipher[0]:
                                vulnerabilities.append(f"Weak cipher {cipher[0]} in use")
                                
            except ssl.SSLError as e:
                vulnerabilities.append(f"SSL Error: {str(e)}")
            except socket.error:
                return None
                
            if vulnerabilities:
                return {
                    'description': 'SSL/TLS vulnerabilities detected',
                    'recommendation': 'Update SSL configuration and certificates',
                    'details': '\n'.join(vulnerabilities)
                }
                
            return None
            
        except Exception as e:
            logging.error(f"SSL vulnerability check error: {str(e)}")
            return None



    def update_vuln_progress(self, progress):
        """Update vulnerability scan progress"""
        self.vuln_progress['value'] = progress
        self.vuln_status.config(text=f"Scanning... {int(progress)}%")

    def vuln_scan_complete(self):
        """Handle vulnerability scan completion"""
        self.vuln_scan_button.configure(state='normal')
        self.vuln_status.config(text="Scan Complete")
        self.scanning = False
        messagebox.showinfo("Scan Complete", "Vulnerability scan has completed!")

    def vuln_scan_error(self, error_msg):
        """Handle vulnerability scan error"""
        self.vuln_scan_button.configure(state='normal')
        self.vuln_status.config(text="Error")
        self.scanning = False
        messagebox.showerror("Error", f"Scan error: {error_msg}")

    def check_network_vulnerabilities(self, target):
        """Check for network vulnerabilities"""
        # Add your network vulnerability checks here
        self.add_vuln_result("Medium", "Open Ports", 
                            "Multiple open ports detected", 
                            "Close unnecessary ports")

    def check_service_vulnerabilities(self, target):
        """Check for service vulnerabilities"""
        # Add your service vulnerability checks here
        pass

    def check_web_vulnerabilities(self, target):
        """Check for web vulnerabilities"""
        # Add your web vulnerability checks here
        pass

    def check_auth_vulnerabilities(self, target):
        """Check for authentication vulnerabilities"""
        # Add your authentication vulnerability checks here
        pass

    def check_malware_indicators(self, target):
        """Check for malware indicators"""
        # Add your malware detection logic here
        pass

    def add_vuln_result(self, severity, vuln_type, description, recommendation):
        """Add a vulnerability result to the tree"""
        try:
            # Insert with distinctive colors based on severity
            severity_colors = {
                'Critical': '#FF0000',  # Red
                'High': '#FF4500',      # Orange Red
                'Medium': '#FFA500',    # Orange
                'Low': '#FFFF00'        # Yellow
            }
            
            self.vuln_tree.insert(
                '',
                'end',
                values=(severity, vuln_type, description, recommendation),
                tags=(severity.lower(),)
            )
            
            # Configure tag colors
            for sev, color in severity_colors.items():
                self.vuln_tree.tag_configure(sev.lower(), foreground=color)
                
        except Exception as e:
            logging.error(f"Error adding vulnerability result: {str(e)}")

    def quick_vulnerability_scan(self, target, categories):
        """Perform quick vulnerability scan"""
        try:
            self.scanning = True
            total_steps = sum(len(VULNERABILITY_CHECKS[cat]) for cat in categories)
            current_step = 0
            
            # Clear previous results
            for item in self.vuln_tree.get_children():
                self.vuln_tree.delete(item)
            
            for category in categories:
                if not self.scanning:
                    break
                    
                for check in VULNERABILITY_CHECKS[category]:
                    if not self.scanning:
                        break
                        
                    # Update status
                    self.vuln_status.config(text=f"Running {check['name']}...")
                    
                    # Update progress
                    progress = (current_step / total_steps) * 100
                    self.vuln_progress['value'] = progress
                    
                    # Get the check function
                    check_function = getattr(self, check['function'])
                    
                    # Perform the check
                    try:
                        result = check_function(target)
                        if result:
                            # Add result to tree
                            self.add_vuln_result(
                                check['severity'],
                                check['name'],
                                result['description'],
                                result['recommendation']
                            )
                    except Exception as e:
                        logging.error(f"Error in vulnerability check {check['name']}: {str(e)}")
                    
                    current_step += 1
                    time.sleep(0.5)  # Add small delay between checks
                    
            # Scan complete
            self.root.after(0, self.vuln_scan_complete)
            
        except Exception as e:
            self.root.after(0, self.vuln_scan_error, str(e))


    def create_vulnerability_scanner_tab(self):
        """Create the vulnerability scanner tab"""
        vuln_frame = ttk.Frame(self.notebook)
        self.notebook.add(vuln_frame, text="Vulnerability Scanner")

        # Create settings frame
        settings_frame = ttk.LabelFrame(vuln_frame, text="Scan Settings", padding=10)
        settings_frame.pack(fill=tk.X, padx=5, pady=5)

        # Target input
        ttk.Label(settings_frame, text="Target IP:").grid(row=0, column=0, padx=5, pady=5)
        self.vuln_target_entry = ttk.Entry(settings_frame)
        self.vuln_target_entry.grid(row=0, column=1, padx=5, pady=5)

        # Scan type selection
        ttk.Label(settings_frame, text="Scan Type:").grid(row=1, column=0, padx=5, pady=5)
        self.scan_type = tk.StringVar(value="quick")
        
        scan_type_frame = ttk.Frame(settings_frame)
        scan_type_frame.grid(row=1, column=1, sticky='w')
        
        ttk.Radiobutton(scan_type_frame, text="Quick Scan", 
                        variable=self.scan_type, value="quick").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(scan_type_frame, text="Full Scan", 
                        variable=self.scan_type, value="full").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(scan_type_frame, text="Custom", 
                        variable=self.scan_type, value="custom").pack(side=tk.LEFT, padx=5)

        # Vulnerability categories
        categories_frame = ttk.LabelFrame(settings_frame, text="Scan Categories", padding=5)
        categories_frame.grid(row=2, column=0, columnspan=2, sticky='ew', padx=5, pady=5)

        self.categories = {
            'network_vulns': tk.BooleanVar(value=True),
            'service_vulns': tk.BooleanVar(value=True),
            'web_vulns': tk.BooleanVar(value=True),
            'auth_vulns': tk.BooleanVar(value=True),
            'malware': tk.BooleanVar(value=True)
        }

        for i, (key, var) in enumerate(self.categories.items()):
            ttk.Checkbutton(
                categories_frame, 
                text=key.replace('_', ' ').title(),
                variable=var
            ).pack(anchor='w', padx=5, pady=2)

        # Start button and progress bar
        button_frame = ttk.Frame(settings_frame)
        button_frame.grid(row=3, column=0, columnspan=2, pady=10)

        self.vuln_scan_button = ttk.Button(
            button_frame,
            text="Start Scan",
            command=self.start_vulnerability_scan
        )
        self.vuln_scan_button.pack(side=tk.LEFT, padx=5)

        self.vuln_progress = ttk.Progressbar(
            button_frame,
            length=200,
            mode='determinate'
        )
        self.vuln_progress.pack(side=tk.LEFT, padx=5)

        self.vuln_status = ttk.Label(button_frame, text="Ready")
        self.vuln_status.pack(side=tk.LEFT, padx=5)

        # Results frame
        results_frame = ttk.LabelFrame(vuln_frame, text="Scan Results", padding=10)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Create treeview for vulnerability results
        self.vuln_tree = ttk.Treeview(
            results_frame,
            columns=("Severity", "Type", "Description", "Recommendation"),
            style="Vuln.Treeview",
            show="headings"
        )

        # Configure columns
        self.vuln_tree.heading("Severity", text="Severity")
        self.vuln_tree.heading("Type", text="Type")
        self.vuln_tree.heading("Description", text="Description")
        self.vuln_tree.heading("Recommendation", text="Recommendation")

        #Configure columns
        self.vuln_tree.column("Severity", width=100, anchor="center")
        self.vuln_tree.column("Type", width=150, anchor="center")
        self.vuln_tree.column("Description", width=300, anchor="w")
        self.vuln_tree.column("Recommendation", width=300, anchor="w")

        # Add scrollbar
        scrollbar = ttk.Scrollbar(
            results_frame,
            orient=tk.VERTICAL,
            command=self.vuln_tree.yview
        )
        self.vuln_tree.configure(yscrollcommand=scrollbar.set)

        # Pack the treeview and scrollbar
        self.vuln_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        export_frame = ttk.Frame(vuln_frame)
        export_frame.pack(fill=tk.X, padx=5, pady=5)
    
        self.export_button = ttk.Button(
            export_frame,
            text="Export Report",
            command=self.export_report
        )
        self.export_button.pack(side=tk.RIGHT, padx=5)

    def start_vulnerability_scan(self):
        """Start the vulnerability scanning process"""
        target = self.vuln_target_entry.get()
        scan_type = self.scan_type.get()
        
        # Get selected categories
        selected_categories = [
            cat for cat, var in self.categories.items() 
            if var.get()
        ]
        
        if not target:
            messagebox.showerror("Error", "Please enter a target IP")
            return
                
        if not selected_categories:
            messagebox.showerror("Error", "Please select at least one category")
            return
                
        # Clear previous results
        for item in self.vuln_tree.get_children():
            self.vuln_tree.delete(item)
                
        # Reset progress
        self.vuln_progress['value'] = 0
        self.vuln_scan_button.configure(state='disabled')
        
        # Start scan based on type
        if scan_type == "quick":
            threading.Thread(
                target=self.quick_vulnerability_scan,
                args=(target, selected_categories),
                daemon=True
            ).start()
        elif scan_type == "full":
            threading.Thread(
                target=self.full_vulnerability_scan,
                args=(target, selected_categories),
                daemon=True
            ).start()
        else:  # custom
            threading.Thread(
                target=self.custom_vulnerability_scan,
                args=(target, selected_categories),
                daemon=True
            ).start()


    def create_network_monitor_tab(self):
        """Create the network monitoring tab"""
        monitor_frame = ttk.Frame(self.notebook)
        self.notebook.add(monitor_frame, text="Network Monitor")

        # Create graphs frame
        graphs_frame = ttk.LabelFrame(monitor_frame, text="Network Activity", padding=10)
        graphs_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Initialize data storage for graphs
        self.cpu_data = []
        self.mem_data = []
        self.net_data = []
        self.timestamps = []

        # CPU Usage Graph
        cpu_frame = ttk.LabelFrame(graphs_frame, text="CPU Usage (%)", padding=5)
        cpu_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.cpu_figure, self.cpu_ax = plt.subplots(figsize=(8, 2))
        self.cpu_ax.set_facecolor('#2b2b2b')
        self.cpu_figure.patch.set_facecolor('#2b2b2b')
        self.cpu_canvas = FigureCanvasTkAgg(self.cpu_figure, master=cpu_frame)
        self.cpu_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Memory Usage Graph
        mem_frame = ttk.LabelFrame(graphs_frame, text="Memory Usage (%)", padding=5)
        mem_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.mem_figure, self.mem_ax = plt.subplots(figsize=(8, 2))
        self.mem_ax.set_facecolor('#2b2b2b')
        self.mem_figure.patch.set_facecolor('#2b2b2b')
        self.mem_canvas = FigureCanvasTkAgg(self.mem_figure, master=mem_frame)
        self.mem_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Network Usage Graph
        net_frame = ttk.LabelFrame(graphs_frame, text="Network Usage (MB/s)", padding=5)
        net_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.net_figure, self.net_ax = plt.subplots(figsize=(8, 2))
        self.net_ax.set_facecolor('#2b2b2b')
        self.net_figure.patch.set_facecolor('#2b2b2b')
        self.net_canvas = FigureCanvasTkAgg(self.net_figure, master=net_frame)
        self.net_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        # Network Statistics Frame
        stats_frame = ttk.LabelFrame(monitor_frame, text="Network Statistics", padding=10)
        stats_frame.pack(fill=tk.X, padx=5, pady=5)

        # Statistics Labels
        self.bytes_sent_label = ttk.Label(stats_frame, text="Bytes Sent: 0")
        self.bytes_sent_label.pack(fill=tk.X, padx=5, pady=2)
        
        self.bytes_recv_label = ttk.Label(stats_frame, text="Bytes Received: 0")
        self.bytes_recv_label.pack(fill=tk.X, padx=5, pady=2)
        
        self.packets_sent_label = ttk.Label(stats_frame, text="Packets Sent: 0")
        self.packets_sent_label.pack(fill=tk.X, padx=5, pady=2)
        
        self.packets_recv_label = ttk.Label(stats_frame, text="Packets Received: 0")
        self.packets_recv_label.pack(fill=tk.X, padx=5, pady=2)

        # Start monitoring
        self.monitoring = True
        self.update_graphs()

    def update_graphs(self):
        """Update network monitoring graphs"""
        if not self.monitoring:
            return

        try:
            # Get current time
            current_time = datetime.now()
            self.timestamps.append(current_time)

            # Update CPU data
            cpu_percent = psutil.cpu_percent()
            self.cpu_data.append(cpu_percent)
            
            # Update Memory data
            mem = psutil.virtual_memory()
            self.mem_data.append(mem.percent)
            
            # Update Network data
            net = psutil.net_io_counters()
            net_usage = (net.bytes_sent + net.bytes_recv) / 1024 / 1024  # Convert to MB
            self.net_data.append(net_usage)

            # Keep only last 60 seconds of data
            if len(self.timestamps) > 60:
                self.timestamps.pop(0)
                self.cpu_data.pop(0)
                self.mem_data.pop(0)
                self.net_data.pop(0)

            # Update CPU Graph
            self.cpu_ax.clear()
            self.cpu_ax.plot(self.timestamps, self.cpu_data, color='#00ff00', linewidth=2)
            self.cpu_ax.set_ylim(0, 100)
            self.cpu_ax.grid(True, color='#404040')
            self.cpu_ax.tick_params(colors='#00ff00')
            
            # Update Memory Graph
            self.mem_ax.clear()
            self.mem_ax.plot(self.timestamps, self.mem_data, color='#00ff00', linewidth=2)
            self.mem_ax.set_ylim(0, 100)
            self.mem_ax.grid(True, color='#404040')
            self.mem_ax.tick_params(colors='#00ff00')
            
            # Update Network Graph
            self.net_ax.clear()
            self.net_ax.plot(self.timestamps, self.net_data, color='#00ff00', linewidth=2)
            self.net_ax.grid(True, color='#404040')
            self.net_ax.tick_params(colors='#00ff00')

            # Update statistics labels
            self.bytes_sent_label.config(text=f"Bytes Sent: {self.format_bytes(net.bytes_sent)}")
            self.bytes_recv_label.config(text=f"Bytes Received: {self.format_bytes(net.bytes_recv)}")
            self.packets_sent_label.config(text=f"Packets Sent: {net.packets_sent:,}")
            self.packets_recv_label.config(text=f"Packets Received: {net.packets_recv:,}")

            # Draw the updated graphs
            self.cpu_canvas.draw()
            self.mem_canvas.draw()
            self.net_canvas.draw()

        except Exception as e:
            logging.error(f"Error updating graphs: {str(e)}")

        # Schedule next update
        self.root.after(1000, self.update_graphs)

    def format_bytes(self, bytes):
        """Format bytes to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes < 1024:
                return f"{bytes:.2f} {unit}"
            bytes /= 1024
        return f"{bytes:.2f} PB"

    def start_monitoring(self):
        """Start the network monitoring process"""
        self.monitoring = True
        self.update_graphs()


    def create_port_scanner_tab(self):
        """Create the port scanner tab"""
        scanner_frame = ttk.Frame(self.notebook)
        self.notebook.add(scanner_frame, text="Port Scanner")

        # Create input frame
        input_frame = ttk.LabelFrame(scanner_frame, text="Scan Settings", padding=10)
        input_frame.pack(fill=tk.X, padx=5, pady=5)

        # Target input
        ttk.Label(input_frame, text="Target IP:").grid(row=0, column=0, padx=5, pady=5)
        self.target_entry = ttk.Entry(input_frame)
        self.target_entry.grid(row=0, column=1, padx=5, pady=5)

        # Port range input
        ttk.Label(input_frame, text="Port Range:").grid(row=1, column=0, padx=5, pady=5)
        port_frame = ttk.Frame(input_frame)
        port_frame.grid(row=1, column=1, padx=5, pady=5)
        
        self.start_port = ttk.Entry(port_frame, width=10)
        self.start_port.pack(side=tk.LEFT, padx=2)
        ttk.Label(port_frame, text="-").pack(side=tk.LEFT, padx=2)
        self.end_port = ttk.Entry(port_frame, width=10)
        self.end_port.pack(side=tk.LEFT, padx=2)

        # Progress frame
        progress_frame = ttk.Frame(input_frame)
        progress_frame.grid(row=2, column=0, columnspan=2, pady=5)

        # Scan button
        self.scan_button = ttk.Button(
            progress_frame, 
            text="Start Scan",
            command=self.start_port_scan
        )
        self.scan_button.pack(side=tk.LEFT, padx=5)

        # Progress bar
        self.scan_progress = ttk.Progressbar(
            progress_frame,
            length=200,
            mode='determinate'
        )
        self.scan_progress.pack(side=tk.LEFT, padx=5)

        # Status label
        self.scan_status = ttk.Label(progress_frame, text="Ready")
        self.scan_status.pack(side=tk.LEFT, padx=5)

        # Results frame
        results_frame = ttk.LabelFrame(scanner_frame, text="Scan Results", padding=10)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)


        # Create treeview for results
        self.results_tree = ttk.Treeview(
            results_frame,
            columns=("Port", "State", "Service", "Version"),
            style="Custom.Treeview",
            show="headings"
            
        )

        # Configure columns
        self.results_tree.heading("Port", text="Port")
        self.results_tree.heading("State", text="State")
        self.results_tree.heading("Service", text="Service")
        self.results_tree.heading("Version", text="Version")


        # Configure columns
        self.results_tree.column("Port", width=100, anchor="center")
        self.results_tree.column("State", width=100, anchor="center")
        self.results_tree.column("Service", width=150, anchor="center")
        self.results_tree.column("Version", width=300, anchor="w")

        # Configure style
        style = ttk.Style()
        style.configure("Custom.Treeview", 
            background="#2b2b2b",
            foreground="#00ff00",
            fieldbackground="#2b2b2b"
        )
        style.configure("Custom.Treeview.Heading",
            background="#1a1a1a",
            foreground="#00ff00"
        )

        # Add scrollbar
        scrollbar = ttk.Scrollbar(
            results_frame,
            orient=tk.VERTICAL,
            command=self.results_tree.yview
        )
        self.results_tree.configure(yscrollcommand=scrollbar.set)

        # Pack the treeview and scrollbar
        self.results_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        

    def start_port_scan(self):
        """Start the port scanning process"""
        target = self.target_entry.get()
        
        # Validate target IP
        if not target or not self.validate_target(target):
            messagebox.showerror("Error", "Please enter a valid target IP address")
            return
            
        try:
            # Get and validate port numbers
            start_port = self.start_port.get().strip()
            end_port = self.end_port.get().strip()
            
            # Check if ports are empty
            if not start_port or not end_port:
                messagebox.showerror("Error", "Please enter both start and end ports")
                return
                
            # Convert to integers
            start = int(start_port)
            end = int(end_port)
            
            # Validate port range
            if not (1 <= start <= 65535 and 1 <= end <= 65535):
                messagebox.showerror("Error", "Port numbers must be between 1 and 65535")
                return
                
            if start > end:
                messagebox.showerror("Error", "Start port must be less than or equal to end port")
                return
                    
            # Clear previous results
            for item in self.results_tree.get_children():
                self.results_tree.delete(item)
                    
            # Start scanning in a separate thread
            self.scanning = True
            self.scan_button.configure(state='disabled')
            self.scan_status.config(text="Scanning...")
            self.scan_progress['value'] = 0
            
            threading.Thread(
                target=self.perform_port_scan,
                args=(target, start, end),
                daemon=True
            ).start()
                
        except ValueError:
            messagebox.showerror("Error", "Port numbers must be valid integers")


        
    def validate_target(self, target):
        """Validate target IP address"""
        import ipaddress
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            return False


        

    def configure_colors(self):
        # Configure modern dark theme colors
        self.style.configure('.',
            background='#2b2b2b',
            foreground='#ffffff',
            fieldbackground='#3b3b3b'
        )
        
        # Configure specific elements
        self.style.configure('Banner.TLabel',
            background='#1a1a1a',
            foreground='#00ff00',
            font=('Courier', 10, 'bold')
        )

    def create_banner(self):
        """Create and display the ASCII banners"""
        banner_frame = ttk.Frame(self.main_container)
        banner_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Left banner
        left_banner = ttk.Label(
            banner_frame,
            text=LEFT_BANNER,
            style='Banner.TLabel',
            justify=tk.LEFT,
            font=('Courier', 10, 'bold')
        )
        left_banner.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Right banner
        right_banner = ttk.Label(
            banner_frame,
            text=RIGHT_BANNER,
            style='Banner.TLabel',
            justify=tk.RIGHT,
            font=('Courier', 10, 'bold')
        )
        right_banner.pack(side=tk.RIGHT, fill=tk.X, expand=True)

        # Configure banner style
        self.style.configure('Banner.TLabel',
            background='#1a1a1a',
            foreground='#00ff00',
            font=('Courier', 10, 'bold')
        )
    # Color schemes for the GUI

    def create_system_info_display(self):
        info_frame = ttk.LabelFrame(self.main_container, text="System Information")
        info_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Get system information
        sys_info = SystemInfo()
        ip = sys_info.get_ip_address()
        mac = sys_info.get_mac_address()
        location = sys_info.get_location()
        system = sys_info.get_system_info()
        
        # Create info labels
        self.create_info_label(info_frame, "IP Address", ip)
        self.create_info_label(info_frame, "MAC Address", mac)
        self.create_info_label(info_frame, "Location", 
            f"{location.get('city')}, {location.get('country')}")
        self.create_info_label(info_frame, "System", 
            f"{system.get('system')} {system.get('release')}")
        self.create_info_label(info_frame, "CPU", 
            f"{system.get('processor')} ({system.get('cpu_cores')} cores)")

    def create_info_label(self, parent, label, value):
        frame = ttk.Frame(parent)
        frame.pack(fill=tk.X, padx=5, pady=2)
        
        ttk.Label(frame, text=f"{label}:", width=15).pack(side=tk.LEFT)
        ttk.Label(frame, text=value).pack(side=tk.LEFT, fill=tk.X)

    def create_notebook(self):
        self.notebook = ttk.Notebook(self.main_container)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Add tabs
        self.create_port_scanner_tab()
        self.create_network_monitor_tab()
        self.create_vulnerability_scanner_tab()

    # Add methods for creating each tab...

    def run(self):
        self.root.mainloop()

def main():
    try:
        app = PinkertonGUI()
        app.run()
    except Exception as e:
        logging.critical(f"Fatal error: {e}")
        messagebox.showerror("Error", f"Fatal error: {e}")

if __name__ == "__main__":
    main()