"""
NETSCAN-2 - Network Scanner & Packet Sniffer
Day 2 of 100
"""

import socket
import threading
import concurrent.futures
import ipaddress
import argparse
import sys
import time
from datetime import datetime
from typing import List, Dict, Tuple

# Optional imports with fallbacks
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    COLOR = True
except ImportError:
    COLOR = False
    class Fore:
        GREEN = YELLOW = RED = CYAN = MAGENTA = BLUE = RESET = ''
    Style = Fore

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("[!] Scapy not installed. Packet sniffing disabled.")
    print("[!] Install: pip install scapy")

class NetScan2:
    def __init__(self):
        self.common_ports = {
            20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET",
            25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
            80: "HTTP", 110: "POP3", 123: "NTP", 135: "RPC",
            139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
            465: "SMTPS", 587: "SMTP", 993: "IMAPS", 995: "POP3S",
            1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
            5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-ALT",
            8443: "HTTPS-ALT", 27017: "MongoDB"
        }
        self.results = []
        self.live_hosts = []
        self.lock = threading.Lock()
    
    def scan_port(self, target: str, port: int, timeout: float = 1.0) -> Tuple[int, str, bool]:
        """Scan a single port on target host."""
        service_name = self.common_ports.get(port, "Unknown")

        try:
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)

            # Try to connect
            result = sock.connect_ex((target, port))

            if result == 0:
                # Port is open
                try:
                    # Try to grab banner
                    sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()[:100]
                except:
                    banner = ""

                sock.close()
                return (port, service_name, True, banner)
            
            sock.close()
            return (port, service_name, False, "")
        
        except Exception as e:
            return (port, service_name, False, f"Error: {str(e)}")
        
    def scan_target(self, target: str, ports: List[int] = None, max_threads: int = 100) -> Dict:
        """Scan multiple ports on a single target."""
        if ports is None:
            ports = list(self.common_ports.keys())

        results = {
            "target": target,
            "open_ports": [],
            "start_time": datetime.now(),
            "total_ports": len(ports)
        }

        print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Scanning {target} ({len(ports)} ports)...")

        # Use ThreadPoolExecutor for parallel scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
            # Submit all port scans
            future_to_port = {executor.submit(self.scan_port, target, port): port for port in ports}

            # Process results as they complete
            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    port_num, service, is_open, banner = future.result()
                    if is_open:
                        with self.lock:
                            results["open_ports"].append({
                                "port": port_num,
                                "service": service,
                                "banner": banner
                            })
                        
                        status = f"{Fore.GREEN}[+]{Style.RESET_ALL}"
                        print(f"{status} {target}:{port_num} ({service}) OPEN {banner}")

                except Exception as e:
                    print(f"{Fore.RED}[!]{Style.RESET_ALL} Error Scanning {target}:{port} - {e}")

        