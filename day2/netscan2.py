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
        
        results["end_time"] = datetime.now()
        results["scan_duration"] = (results["end_time"] - results["start_time"]).total_seconds()
        results["open_count"] = len(results["open_ports"])

        print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Scan completed in {results['scan_duration']:.2f}s")
        print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Found {results['open_count']} open ports on {target}")

        return results

    def scan_network(self, network: str, ports: List[int] = None):
        """Scan multiple hosts in a network range."""
        try:
            # Parse network range
            network_obj = ipaddress.ip_network(network, strict=False)
            hosts = list(network_obj.hosts())

            print(f"{Fore.MAGENTA}[*]{Style.RESET_ALL} Scanning network: {network}")
            print(f"{Fore.MAGENTA}[*]{Style.RESET_ALL} Total hosts: {len(hosts)}")

            for i, host in enumerate(hosts[:50]): # Limit to first 50 hosts for demo
                target = str(host)
                print(f"{Fore.YELLOW}[*]{Style.RESET_ALL} Scanning host {i+1}/{min(50, len(hosts))}: {target}")

                try:
                   # Quick ping check (ICMP echo)
                   sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                   sock.settimeout(0.5)
                   # Note: Raw sockets require admin/root privileges
                   # This is simplified - in reality use scapy for proper ping
                   sock.close()

                   # For demo, we'll just scan common ports
                   result = self.scan_target(target, [22, 80, 443, 3389] if ports is None else ports, max_threads=50) 
                   
                   if result["open_count"] > 0:
                       self.live_hosts.append(result)

                except Exception as e:
                    continue

        except ValueError as e:
            print(f"{Fore.RED}[!]{Style.RESET_ALL} Invalid network range: {e}")

    def packet_sniffer(self, interface: str = None, count: int = 20, filter: str = "tcp"):
        """Sniff network packets (requires scapy and appropriate privileges)."""
        if not SCAPY_AVAILABLE:
            print(f"{Fore.RED}[!]{Style.RESET_ALL} Scapy not available. Cannot sniff packets.")
            return
        
        print(f"{Fore.BLUE}[*]{Style.RESET_ALL} Starting packet sniffer...")
        print(f"{Fore.BLUE}[*]{Style.RESET_ALL} Filter: {filter} | Count: {count}")
        print(f"{Fore.BLUE}[*]{Style.RESET_ALL} Press Ctrl+C to stop\n")

        def packet_callback(packet):
            timestamp = datetime.now().strftime("%H:%M:%S")

            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                proto = packet[IP].proto

                info = f"{timestamp} {src_ip} -> {dst_ip}"

                if TCP in packet:
                    info += f" TCP {packet[TCP].sport}->{packet[TCP].dport}"
                    if packet[TCP].flags == 2: # SYN
                        info += " [SYN]"
                    elif packet[TCP].flags == 18: # SYN-ACK
                        info += " [SYN-ACK]"
                    elif packet[TCP].flags == 16: # ACK
                        info += " [ACK]"

                elif UDP in packet:
                    info += f" UDP {packet[UDP].sport}->{packet[UDP].dport}"

                elif ICMP in packet:
                    info += f" ICMP type:{packet[ICMP].type}"

                print(f"{Fore.GREEN}[PACKET]{Style.RESET_ALL} {info}")

                # Show payload for interesting packets
                if hasattr(packet, 'load') and packet.load:
                    try:
                        payload = packet.load.decode('utf-8', errors='ignore')[:50]
                        if payload.strip():
                            print(f"{Fore.YELLOW}[PAYLOAD]{Style.RESET_ALL} {payload}...")

                    except:
                        pass

                print() # Empty line between packets

        try:
            sniff(iface=interface, prn=packet_callback, count=count, filter=filter, store=False)
        except PermissionError:
            print(f"{Fore.RED}[!]{Style.RESET_ALL} Need root/admin privileges for packet sniffing!")
        except Exception as e:
            print(f"{Fore.RED}[!]{Style.RESET_ALL} Sniffing error: {e}")

    def service_detection(self, target: str, port: int):
        """Attempt to detect service version."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((target, port))

            # Send generic probe
            sock.send(b"\r\n\r\n")
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()

            return banner.strip()
        except:
            return ""
        
def main():
    parser = argparse.ArgumentParser(description="NETSCAN-2: Network Reconnaissance Tool")
    parser.add_argument('-t', '--target', type=str, help='Single target IP or hostname')
    parser.add_argument('-p', '--ports', type=str, help='Ports to scan (e.g., "80,443,8080" or "1-1000")')
    parser.add_argument('-n', '--network', type=str, help='Network range to scan (e.g., 192.168.1.0/24)')
    parser.add_argument('-s', '--sniff', action='store_true', help='Start packet sniffer')
    parser.add_argument('-c', '--count', type=int, default=20, help="Number of packets to sniff")
    parser.add_argument('-f', '--filter', type=str, help='BPF filter or sniffing')
    parser.add_argument('-T', '--threads', type=int, default=100, help='Max scanning threads')
    parser.add_argument('-q', '--quick', action='store_true', help='Quick scan (top 20 ports only)')

    args = parser.parse_args()
    scanner = NetScan2()

    # Parse ports
    port_list = []
    if args.ports:
        if ',' in args.ports:
            port_list = [int(p.strip()) for p in args.ports.split(',')]
        elif '-' in args.ports:
            start, end = map(int, args.ports.split('-'))
            port_list = list(range(start, end + 1))
        else:
            port_list = [int(args.ports)]
    elif args.quick:
        # Top 20 most common ports
        port_list = list(scanner.common_ports.keys())[:20]
    else:
        # All common ports
        port_list = list(scanner.common_ports.keys())

    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}      NETSCAN-2 - Network Reconnaissance{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")

    if args.sniff:
        scanner.packet_sniffer(count=args.count, filter=args.filter)

    elif args.network:
        scanner.scan_network(args.network, port_list)

        if scanner.live_hosts:
            print(f"\n{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] LIVE HOSTS SUMMARY:{Style.RESET_ALL}")
            for host in scanner.live_hosts:
                print(f"\n{Fore.YELLOW}Host: {host['target']}{Style.RESET_ALL}")
                for port_info in host['open_ports']:
                    print(f"    {port_info['port']}/tcp - {port_info['service']}")

    elif args.target:
        result = scanner.scan_target(args.target, port_list, args.threads)    

        # Print summary
        if result['open_ports']:
            print(f"\n{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] SCAN SUMMARY for {args.target}:{Style.RESET_ALL}")
            print(f"{Fore.GREEN}{'='*60}{Style.RESET_ALL}")

            for port_info in result['open_ports']:
                print(f"{Fore.GREEN}[+] {port_info['port']}/tcp - {port_info['service']}{Style.RESET_ALL}")
                if port_info['banner']:
                    print(f"    Banner: {port_info['banner'][:100]}")
            
            print(f"\n{Fore.CYAN}[*] Total: {result['open_count']} open ports{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Duration: {result['scan_duration']:.2f} seconds{Style.RESET_ALL}")

    else:
        # Interactive mode
        print(f"\n{Fore.YELLOW}[!] No target specified. Running in demo mode.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[!] Example usage:{Style.RESET_ALL}")
        print(f"    python {sys.argv[0]} -t 127.0.0.1")
        print(f"    python {sys.argv[0]} -n 192.168.1.0/24 -q")
        print(f"    python {sys.argv[0]} -s -c 50")

        # Demo scan on localhost
        print(f"\n{Fore.CYAN}[*] Running demo scan on localhost...{Style.RESET_ALL}")
        result = scanner.scan_target("127.0.0.1", [80, 443, 8080, 22, 21], max_threads=50)

if __name__ == "__main__":
    main()
    
        