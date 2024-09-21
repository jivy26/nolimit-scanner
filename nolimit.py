import asyncio
import argparse
import json
import logging
import os
import pwd
import random
import resource
import signal
import subprocess
import tempfile
import sys
import time
from functools import lru_cache
import aiofiles
import warnings
from cryptography.utils import CryptographyDeprecationWarning
from colorama import init, Fore
from rich.console import Console
from rich.table import Table
from scapy.all import *
from tqdm import tqdm
from datetime import datetime
from collections import deque

## Start Utility Functions Section
init(autoreset=True)

warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

logging.basicConfig(filename='nmap_service_detection.log', level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s')

logging.basicConfig(filename='nolimit_scan.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

REQUIRED_PACKAGES = ['tqdm', 'colorama', 'rich', 'aiofiles', 'scapy']

def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")

@lru_cache(maxsize=None)
def check_package_installed(package):
    try:
        __import__(package)
        return True
    except ImportError:
        return False

def install_missing_packages():
    for package in REQUIRED_PACKAGES:
        if not check_package_installed(package):
            print(f"Installing missing package: {package}...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])

def check_system_dependencies():
    try:
        subprocess.check_call(["nmap", "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("Error: nmap is not installed or not in PATH. Please install nmap.")
        sys.exit(1)

def check_scapy_flag(args):
    if args.scapy:
        print(f"{Fore.YELLOW}Scapy mode enabled. Lower worker count is recommended to avoid 'Too many open files' errors.")
        if not check_package_installed('scapy'):
            print(f"{Fore.RED}Error: Scapy is not installed. Install it with 'pip install scapy'.")
            sys.exit(1)
        return True
    return False

def shuffle_ips(ips):
    return random.sample(ips, len(ips))

async def run_scapy_scan(command):
    """Run Scapy-related functions with sudo in a separate subprocess."""
    cmd = ['sudo', "-n",sys.executable, '-c', command]
    proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    stdout, stderr = await proc.communicate()
    if stderr:
        print(f"{Fore.RED}Scapy command error: {stderr.decode()}")
    return stdout.decode()

async def load_ips(ip_input):
    if os.path.isfile(ip_input):
        try:
            async with aiofiles.open(ip_input, 'r') as f:
                return [line.strip() for line in await f.readlines()]
        except IOError as e:
            print(f"{Fore.RED}Error reading IP file: {e}")
            sys.exit(1)
    else:
        return [ip_input]

def parse_ports(ports_arg):
    if '-' in ports_arg:
        start, end = map(int, ports_arg.split('-'))
        return list(range(start, end + 1))
    else:
        return list(map(int, ports_arg.split(',')))

async def save_open_ports(open_ports, protocol):
    folder_name = f"{protocol}_{random.randint(1000, 9999)}"
    os.makedirs(folder_name, exist_ok=True)
    
    common_ports = {
        21: "ftp-hosts.txt",
        22: "ssh-hosts.txt",        
        23: "telnet-hosts.txt",        
        25: "smtp-hosts.txt",
        53: "dns-hosts.txt",      
        80: "http-hosts.txt",          
        110: "pop3-hosts.txt",
        143: "imap-hosts.txt",
        443: "https-hosts.txt",        
        445: "smb-hosts.txt",
        500: "ike-hosts.txt",        
        3306: "mysql-hosts.txt",
        3389: "rdp-hosts.txt",
        5432: "postgresql-hosts.txt",        
        8080: "http-alt-hosts.txt",
        8443: "https-alt-hosts.txt",
        10443: "10443-hosts.txt"
    }

    web_ports = {80, 443, 8080, 8443, 10443}

    port_files = {}
    other_ports_file = os.path.join(folder_name, f"{protocol}_other_ports.txt")
    web_urls_file = os.path.join(folder_name, "web-urls.txt")
    web_urls = set()

    for ip, port, proto, technique in sorted(open_ports, key=lambda x: (x[0], x[1])):
        if proto == protocol:
            try:
                if port in common_ports:
                    filename = os.path.join(folder_name, common_ports[port])
                    if filename not in port_files:
                        port_files[filename] = set()
                    port_files[filename].add(f"{ip} (Technique: {technique})")
                else:
                    if other_ports_file not in port_files:
                        port_files[other_ports_file] = set()
                    port_files[other_ports_file].add(f"{ip}:{port} (Technique: {technique})")
                
                if port in web_ports:
                    protocol_prefix = "https" if port in {443, 8443, 10443} else "http"
                    web_urls.add(f"{protocol_prefix}://{ip}:{port}")
            except Exception as e:
                print(f"Error processing open port {ip}:{port}: {str(e)}")

    for filename, ips in port_files.items():
        async with aiofiles.open(filename, 'w') as f:
            await f.write("\n".join(sorted(ips)) + "\n")

    if web_urls:
        async with aiofiles.open(web_urls_file, 'w') as f:
            await f.write("\n".join(sorted(web_urls)) + "\n")

    print(f"{Fore.YELLOW}Open ports saved to folder: {folder_name}")
    if web_urls:
        print(f"{Fore.YELLOW}Web URLs saved to: {web_urls_file}")
    
    return folder_name

async def save_progress(ips, ports, open_ports, current_ip_index, current_port_index):
    progress_data = {
        'ips': ips,
        'ports': ports,
        'open_ports': open_ports,
        'current_ip_index': current_ip_index,
        'current_port_index': current_port_index
    }
    async with aiofiles.open('scan_progress.json', 'w') as f:
        await f.write(json.dumps(progress_data))

async def load_progress():
    try:
        async with aiofiles.open('scan_progress.json', 'r') as f:
            return json.loads(await f.read())
    except FileNotFoundError:
        return None

## End of Utility Functions Section

## Evasion Script Creation Section
async def create_evasion_script(open_ports, folder_name):
    script_content = """
from scapy.all import *
import asyncio
import subprocess

async def run_nmap_scan(ip, port):
    cmd = ["sudo", "nmap", "-sV", "-p", str(port), ip, "-Pn", "-T4"]
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await proc.communicate()
    return stdout.decode()

async def evasion_scan(ip, port, technique):
    print(f"Scanning {ip}:{port} using {technique}")
    
    if technique == "os_fingerprint_spoof_scan":
        packet = IP(dst=ip) / TCP(dport=port, flags='S', window=64240, options=[('MSS', 1460), ('NOP', None), ('WScale', 8), ('NOP', None), ('NOP', None), ('Timestamp', (0, 0))])
    elif technique == "polymorphic_payload_scan":
        payload = b"GET / HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n"
        packet = IP(dst=ip) / TCP(dport=port, flags='S') / Raw(load=payload)
    elif technique == "timing_based_evasion_scan":
        packet = IP(dst=ip) / TCP(dport=port, flags='S')
        time.sleep(random.uniform(0.1, 1.0))
    elif technique == "fragmentation_scan":
        packet = IP(dst=ip) / TCP(dport=port, flags='S')
        frags = fragment(packet, fragsize=8)
        for frag in frags:
            send(frag, verbose=0)
        return
    elif technique == "covert_channel_scan":
        covert_data = os.urandom(16)
        packet = IP(dst=ip) / TCP(dport=port, flags='S', options=[('Timestamp', (int.from_bytes(covert_data[:4], 'big'), int.from_bytes(covert_data[4:8], 'big')))])
    else:
        packet = IP(dst=ip) / TCP(dport=port, flags='S')
    
    response = sr1(packet, timeout=2, verbose=0)
    
    if response and response.haslayer(TCP) and response[TCP].flags & 0x12:
        print(f"Port {port} is open")
        nmap_result = await run_nmap_scan(ip, port)
        print(f"Nmap result:\\n{nmap_result}")
    else:
        print(f"Port {port} is closed or filtered")

async def main():
    tasks = [
{tasks}
    ]
    await asyncio.gather(*tasks)

if __name__ == "__main__":
    asyncio.run(main())
"""
    
    tasks = []
    for ip, port, protocol, technique in open_ports:
        if protocol == 'tcp':
            tasks.append(f"        evasion_scan('{ip}', {port}, '{technique}')")
    
    script_content = script_content.replace("{tasks}", ",\n".join(tasks))
    
    script_file = os.path.join(folder_name, "evasion_script.py")
    async with aiofiles.open(script_file, 'w') as f:
        await f.write(script_content)
    
    print(f"{Fore.YELLOW}Evasion script created: {script_file}")
    print(f"{Fore.YELLOW}Run it with: sudo python3 {script_file}")
## End of Evasion Script Creation Section

## Scapy and Standard Port Scanning Section
class AdaptiveScanner:
    def __init__(self, max_history=100):
        self.technique_history = deque(maxlen=max_history)
        self.successful_techniques = {}
        self.technique_weights = {
            'timing_scan': 1.0,
            'protocol_manipulation_scan': 1.0,
            'decoy_scan': 1.0,
            'os_fingerprint_spoof_scan': 1.0,
            'polymorphic_payload_scan': 1.0,
            'timing_based_evasion_scan': 1.0,
            'fragmentation_scan': 1.0,
            'covert_channel_scan': 1.0
        }
        self.last_adjustment_time = time.time()
        self.adjustment_interval = 60  # Adjust weights every 60 seconds

    async def adaptive_scan(self, ip, port):
        techniques = [
            self.timing_scan,
            self.protocol_manipulation_scan,
            self.decoy_scan,
            self.os_fingerprint_spoof_scan,
            self.polymorphic_payload_scan,
            self.timing_based_evasion_scan,
            self.fragmentation_scan,
            self.covert_channel_scan
        ]
        
        chosen_technique = random.choices(techniques, 
                                        weights=[self.technique_weights[t.__name__] for t in techniques],
                                        k=1)[0]
        
        try:
            is_open, responses = await chosen_technique(ip, port)
            if is_open:
                self.successful_techniques[(ip, port)] = chosen_technique.__name__
            
            self.technique_history.append((chosen_technique.__name__, is_open))
            
            if time.time() - self.last_adjustment_time > self.adjustment_interval:
                self.adjust_techniques()
                self.last_adjustment_time = time.time()

            return is_open, responses
        except Exception as e:
            logging.error(f"Error in adaptive_scan for {ip}:{port}: {str(e)}")
            return False, []

    async def send_probe(self, ip, port, packet=None):
        if packet is None:
            packet = IP(dst=ip) / TCP(dport=port, flags='S')
        
        try:
            response = await asyncio.get_event_loop().run_in_executor(
                None, lambda: sr1(packet, timeout=2, verbose=0)
            )
            if isinstance(response, Packet):
                is_open = response.haslayer(TCP) and response[TCP].flags & 0x12
            else:
                is_open = False
            return is_open, response
        except Exception as e:
            logging.error(f"Error in send_probe: {e}")
            return False, None

    async def timing_scan(self, ip, port):
        delay = random.expovariate(1/2)
        await asyncio.sleep(delay)
        is_open, response = await self.send_probe(ip, port)
        return is_open, [response] if response else []

    async def protocol_manipulation_scan(self, ip, port):
        http_methods = ['GET', 'POST', 'HEAD', 'PUT', 'DELETE', 'OPTIONS']
        method = random.choice(http_methods)
        paths = ['/', '/index.html', '/api', '/login', '/about']
        path = random.choice(paths)
        host = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
        packet = IP(dst=ip) / TCP(sport=RandShort(), dport=port, flags='PA') / \
                 Raw(f"{method} {path} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())
        is_open, response = await self.send_probe(ip, port, packet)
        return is_open, [response] if response else []

    async def decoy_scan(self, ip, port):
        decoys = [RandIP() for _ in range(5)]
        target = IP(dst=ip)
        packets = [target/TCP(sport=random.randint(1024, 65535), dport=port, flags="S") for _ in range(len(decoys) + 1)]
        for i, p in enumerate(packets):
            if i < len(decoys):
                p[IP].src = decoys[i]
        
        loop = asyncio.get_event_loop()
        try:
            ans, unans = await loop.run_in_executor(None, lambda: sr(packets, timeout=2, verbose=0))
            is_open = any(isinstance(r, Packet) and r.haslayer(TCP) and r[TCP].flags & 0x12 == 0x12 for _, r in ans)
            return is_open, ans
        except Exception as e:
            logging.error(f"Error in decoy_scan for {ip}:{port}: {str(e)}")
            return False, []

    async def os_fingerprint_spoof_scan(self, ip, port):
        os_fingerprints = [
            # Windows 10
            dict(window=64240, options=[('MSS', 1460), ('NOP', None), ('WScale', 8), ('NOP', None), ('NOP', None), ('Timestamp', (0, 0))]),
            # Linux (Ubuntu)
            dict(window=29200, options=[('MSS', 1460), ('SAckOK', ''), ('Timestamp', (0, 0)), ('NOP', None), ('WScale', 7)]),
            # macOS
            dict(window=65535, options=[('MSS', 1460), ('NOP', None), ('WScale', 6), ('NOP', None), ('NOP', None), ('Timestamp', (0, 0))])
        ]
        chosen_fingerprint = random.choice(os_fingerprints)
        packet = IP(dst=ip) / TCP(dport=port, flags='S', **chosen_fingerprint)
        is_open, response = await self.send_probe(ip, port, packet)
        return is_open, [response] if response else []

    async def polymorphic_payload_scan(self, ip, port):
        payload = self.generate_polymorphic_payload()
        packet = IP(dst=ip) / TCP(dport=port, flags='S') / Raw(load=payload)
        is_open, response = await self.send_probe(ip, port, packet)
        return is_open, [response] if response else []

    def generate_polymorphic_payload(self):
        base_payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        mutations = [
            lambda p: p.replace(b"GET", b"POST"),
            lambda p: p.replace(b"HTTP/1.1", b"HTTP/1.0"),
            lambda p: p + b"X-Custom-Header: " + os.urandom(10) + b"\r\n",
            lambda p: p.replace(b"Host:", b"User-Agent:"),
        ]
        payload = base_payload
        for _ in range(random.randint(1, len(mutations))):
            mutation = random.choice(mutations)
            payload = mutation(payload)
        return payload

    async def timing_based_evasion_scan(self, ip, port):
        delays = [0.1, 0.5, 1.0, 2.0, 5.0]
        for delay in delays:
            await asyncio.sleep(delay)
            packet = IP(dst=ip) / TCP(dport=port, flags='S')
            is_open, response = await self.send_probe(ip, port, packet)
            if is_open:
                return True, [response]
        return False, []

    async def fragmentation_scan(self, ip, port):
        packet = IP(dst=ip) / TCP(dport=port, flags='S')
        frags = fragment(packet, fragsize=8)
        responses = []
        for frag in frags:
            is_open, response = await self.send_probe(ip, port, frag)
            if response:
                responses.append(response)
        is_open = any(r.haslayer(TCP) and r[TCP].flags & 0x12 == 0x12 for r in responses if r)
        return is_open, responses

    async def covert_channel_scan(self, ip, port):
        covert_data = os.urandom(16)  # Random data to embed
        packet = IP(dst=ip) / TCP(dport=port, flags='S', options=[('Timestamp', (int.from_bytes(covert_data[:4], 'big'), int.from_bytes(covert_data[4:8], 'big')))])
        packet[IP].id = int.from_bytes(covert_data[8:10], 'big')
        packet[TCP].seq = int.from_bytes(covert_data[10:14], 'big')
        packet[TCP].window = int.from_bytes(covert_data[14:16], 'big')
        is_open, response = await self.send_probe(ip, port, packet)
        return is_open, [response] if response else []

    def adjust_techniques(self):
        if not self.technique_history:
            return

        success_rates = {}
        for technique in self.technique_weights.keys():
            successes = sum(1 for t, result in self.technique_history if t == technique and result)
            attempts = sum(1 for t, _ in self.technique_history if t == technique)
            success_rates[technique] = successes / attempts if attempts > 0 else 0

        total_success_rate = sum(success_rates.values())
        if total_success_rate > 0:
            for technique, rate in success_rates.items():
                self.technique_weights[technique] = (rate / total_success_rate) + 0.1

        total_weight = sum(self.technique_weights.values())
        for technique in self.technique_weights:
            self.technique_weights[technique] /= total_weight

        logging.info(f"Adjusted technique weights: {self.technique_weights}")

async def check_tcp_port_scapy(ip, port, open_ports, adaptive_scanner):
    if await adaptive_scanner.adaptive_scan(ip, port):
        open_ports.append((ip, port, 'tcp'))
        tqdm.write(f"{Fore.GREEN}TCP {ip}:{port} is open")
        logging.info(f"TCP {ip}:{port} is open.")

async def check_udp_port_scapy(ip, port, open_ports, adaptive_scanner):
    if await adaptive_scanner.adaptive_scan(ip, port):
        open_ports.append((ip, port, 'udp'))
        tqdm.write(f"{Fore.GREEN}UDP {ip}:{port} is open")
        logging.info(f"UDP {ip}:{port} is open.")

async def check_tcp_port(ip, port, open_ports):
    try:
        conn = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(conn, timeout=1.0)
        open_ports.append((ip, port, 'tcp'))
        tqdm.write(f"{Fore.GREEN}TCP {ip}:{port} is open")
        logging.info(f"TCP {ip}:{port} is open. Connection established successfully.")
        writer.close()
        await writer.wait_closed()
    except (asyncio.TimeoutError, ConnectionRefusedError):
        pass
    except Exception as e:
        tqdm.write(f"{Fore.RED}Error checking TCP {ip}:{port} - {e}")

class UDPProtocol(asyncio.DatagramProtocol):
    def __init__(self):
        self.transport = None
        self.received_data = asyncio.Event()

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.received_data.set()

async def check_udp_port(ip, port, open_ports):
    try:
        loop = asyncio.get_event_loop()
        protocol = UDPProtocol()
        await loop.create_datagram_endpoint(
            lambda: protocol,
            remote_addr=(ip, port)
        )
        protocol.transport.sendto(b'')
        try:
            await asyncio.wait_for(protocol.received_data.wait(), timeout=1.0)
            open_ports.append((ip, port, 'udp'))
            tqdm.write(f"{Fore.GREEN}UDP {ip}:{port} is open")
            logging.info(f"UDP {ip}:{port} is open. Received response from server.")
        except asyncio.TimeoutError:
            pass  # Port is likely closed or filtered
        finally:
            protocol.transport.close()
    except Exception as e:
        tqdm.write(f"{Fore.RED}Error checking UDP {ip}:{port} - {e}")

async def scan_ports(ip, ports, protocol, progress, open_ports, max_workers, use_scapy=False, use_adaptive=False, rate_limit=None):
    sem = asyncio.Semaphore(max_workers)

    if use_scapy and use_adaptive:
        adaptive_scanner = AdaptiveScanner()
    else:
        adaptive_scanner = None

    async def scan_with_semaphore(port):
        async with sem:
            try:
                if use_scapy:
                    if use_adaptive:
                        is_open, responses = await adaptive_scanner.adaptive_scan(ip, port)
                    else:
                        is_open, responses = await adaptive_scanner.decoy_scan(ip, port)
                    
                    if is_open:
                        technique = adaptive_scanner.successful_techniques.get((ip, port), "Unknown") if use_adaptive else "decoy_scan"
                        open_ports.append((ip, port, protocol, technique))
                        logging.info(f"{protocol.upper()} {ip}:{port} is open (Technique: {technique})")
                else:
                    if protocol == 'tcp':
                        is_open = await check_tcp_port(ip, port, open_ports)
                    elif protocol == 'udp':
                        is_open = await check_udp_port(ip, port, open_ports)
                    
                    if is_open:
                        open_ports.append((ip, port, protocol, "standard"))
                        logging.info(f"{protocol.upper()} {ip}:{port} is open")
                
                progress.update(1)
                if rate_limit:
                    await asyncio.sleep(1 / rate_limit)
            except Exception as e:
                logging.error(f"Error scanning {ip}:{port} - {str(e)}")

    await asyncio.gather(*[scan_with_semaphore(port) for port in ports])

    if use_scapy and use_adaptive:
        adaptive_scanner.adjust_techniques()

## End of Scapy and Standard Port Scanning Section

## Nmap Service Detection Section
async def nmap_service_detection(open_ports, protocol, folder_name):
    if not open_ports:
        print(f"{Fore.YELLOW}No open ports found. Skipping service detection.")
        return

    clear_screen()
    console = Console()
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("HOST", style="dim")
    table.add_column("PORT")
    table.add_column("STATE")
    table.add_column("SERVICE VERSION")

    protocol_name = "TCP" if protocol == "tcp" else "UDP"
    console.print(f"{Fore.CYAN}\nStarting Nmap service detection for {protocol_name} ports...")

    total_ports = sum(1 for _, _, proto in open_ports if proto == protocol)

    summary_data = []

    async def scan_and_update(ip, port):
        result = await run_nmap_scan(ip, port)
        table.add_row(result[0], str(result[1]), result[2], result[3])
        summary_data.append(result)
        progress.update(1)
        console.clear()
        console.print(table)

    with tqdm(total=total_ports, desc="Service Detection Progress", unit="port", leave=True) as progress:
        tasks = []
        for ip, port, proto in open_ports:
            if proto == protocol:
                tasks.append(scan_and_update(ip, port))
        
        await asyncio.gather(*tasks)

    summary_file = os.path.join(folder_name, "summary.txt")
    
    async with aiofiles.open(summary_file, 'w') as f:
        await f.write(f"{protocol.upper()} Service Detection Summary\n")
        await f.write("=" * 50 + "\n\n")
        
        # Adjust column widths based on the longest entries
        host_width = max(len("HOST"), max(len(result[0]) for result in summary_data))
        port_width = max(len("PORT"), max(len(str(result[1])) for result in summary_data))
        state_width = max(len("STATE"), max(len(result[2]) for result in summary_data))
        
        # Create the header
        header = f"{'HOST':<{host_width}}  {'PORT':<{port_width}}  {'STATE':<{state_width}}  SERVICE VERSION\n"
        separator = f"{'-'*host_width}  {'-'*port_width}  {'-'*state_width}  ---------------\n"
        
        await f.write(header)
        await f.write(separator)
        
        # Write the data
        for result in summary_data:
            line = f"{result[0]:<{host_width}}  {str(result[1]):<{port_width}}  {result[2]:<{state_width}}  {result[3]}\n"
            await f.write(line)
    
    print(f"{Fore.YELLOW}Summary saved to: {summary_file}")

async def run_nmap_scan(ip, port):
    cmd = ["sudo", "-n", "nmap", "-sV", "-p", str(port), ip, "-Pn", "-T4"]
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await proc.communicate()
    nmap_output = stdout.decode()
    return parse_nmap_output(nmap_output, ip, port)

def parse_nmap_output(nmap_output, ip, port):
    state = "closed"
    service = "unknown"
    for line in nmap_output.splitlines():
        if f"{port}/" in line:
            parts = line.split()
            if len(parts) >= 3:
                state = parts[1]
                service = " ".join(parts[2:])
                break
    return ip, port, state, service

## End of Nmap Service Detection Section

## Adaptive Scanning Section
async def adaptive_scan(ip, ports, protocol, progress, open_ports, max_workers, use_scapy=False, rate_limit=None):
    chunk_size = 100
    for i in range(0, len(ports), chunk_size):
        chunk = ports[i:i+chunk_size]
        await scan_ports(ip, chunk, protocol, progress, open_ports, max_workers, use_scapy, rate_limit=rate_limit)
        if len(open_ports) > 0 and len(open_ports) % 10 == 0:
            max_workers = min(max_workers * 2, 1000)
            print(f"{Fore.YELLOW}Adapting worker count to: {max_workers}")

## End of Adaptive Scanning Section

## Utilize NMAP Top Ports 

def load_top_ports(n):
    nmap_services_path = "/usr/share/nmap/nmap-services"
    if not os.path.exists(nmap_services_path):
        print(f"{Fore.RED}Error: Nmap services file not found at {nmap_services_path}")
        print(f"{Fore.RED}Make sure Nmap is installed and the file exists.")
        sys.exit(1)
    
    ports = []
    with open(nmap_services_path, 'r') as f:
        for line in f:
            if line.startswith('#'):
                continue
            parts = line.split()
            if len(parts) >= 3:
                port, proto = parts[1].split('/')
                if proto == 'tcp':
                    frequency = float(parts[2])
                    ports.append((int(port), frequency))
    
    top_ports = sorted(ports, key=lambda x: x[1], reverse=True)[:n]
    return [port for port, _ in top_ports]


## End of Utilize NMAP Top Ports 

def schedule_scan(args, schedule_time):
    try:
        script_path = os.path.abspath(__file__)
        current_dir = os.getcwd()
        current_user = pwd.getpwuid(os.getuid()).pw_name
        
        # Get the full path of the ips.txt file
        ips_file_path = os.path.abspath(args.ip)
        
        # Escape special characters in the command and quote the entire argument string
        escaped_args = ' '.join(f"'{arg}'" if arg != args.ip else f"'{ips_file_path}'" for arg in sys.argv[1:])
        command = f"python3 '{script_path}' {escaped_args}"
        
        job_name = f"nolimit_scan_{int(time.time())}"
        
        logging.info(f"Current user: {current_user}")
        
        service_content = f"""[Unit]
Description=NoLimit Port Scanner Job

[Service]
Type=oneshot
ExecStart={command}
User={current_user}
WorkingDirectory={current_dir}
Environment="PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Environment="PYTHONUNBUFFERED=1"

[Install]
WantedBy=multi-user.target
"""
        
        timer_content = f"""[Unit]
Description=Timer for NoLimit Port Scanner Job

[Timer]
OnCalendar={schedule_time}
Unit={job_name}.service

[Install]
WantedBy=timers.target
"""
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.service') as service_file, \
             tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.timer') as timer_file:
            service_file.write(service_content)
            timer_file.write(timer_content)
            service_file_path = service_file.name
            timer_file_path = timer_file.name
        
        try:
            print(f"{Fore.YELLOW}Attempting to schedule the scan. You may be prompted for your sudo password.")
            subprocess.run(['sudo', 'cp', service_file_path, f'/etc/systemd/system/{job_name}.service'], check=True)
            subprocess.run(['sudo', 'cp', timer_file_path, f'/etc/systemd/system/{job_name}.timer'], check=True)
            
            subprocess.run(['sudo', 'systemctl', 'daemon-reload'], check=True)
            subprocess.run(['sudo', 'systemctl', 'enable', f'{job_name}.timer'], check=True)
            subprocess.run(['sudo', 'systemctl', 'start', f'{job_name}.timer'], check=True)
            
            print(f"{Fore.GREEN}Scan scheduled for {schedule_time}")
            print(f"{Fore.YELLOW}To check status, run: sudo systemctl status {job_name}.timer")
            print(f"{Fore.YELLOW}To see all scheduled scans, run: sudo systemctl list-timers")
            print(f"{Fore.YELLOW}To manually start the service, run: sudo systemctl start {job_name}.service")
            print(f"{Fore.YELLOW}To view service logs, run: sudo journalctl -u {job_name}.service")
            print(f"{Fore.YELLOW}To view script output, run: cat {os.path.join(current_dir, 'nolimit_scan.log')}")
            print(f"{Fore.YELLOW}Output files will be generated in: {current_dir}")
            
            logging.info(f"Scan scheduled for {schedule_time}")
            logging.info(f"Job name: {job_name}")
            logging.info(f"Working directory: {current_dir}")
            logging.info(f"Service file: /etc/systemd/system/{job_name}.service")
            logging.info(f"Timer file: /etc/systemd/system/{job_name}.timer")
        except subprocess.CalledProcessError as e:
            error_message = f"Failed to schedule the scan. Error: {str(e)}"
            print(f"{Fore.RED}{error_message}")
            logging.error(error_message)
            print(f"{Fore.YELLOW}If you're having permission issues, try running the entire script with sudo:")
            print(f"{Fore.YELLOW}sudo python3 {script_path} {' '.join(sys.argv[1:])}")
            raise
        finally:
            os.unlink(service_file_path)
            os.unlink(timer_file_path)
    
    except Exception as e:
        error_message = f"An error occurred while scheduling the scan: {str(e)}"
        print(f"{Fore.RED}{error_message}")
        logging.error(error_message)
        logging.exception("Exception details:")
        sys.exit(1)

async def main():
    is_scheduled_run = os.environ.get('NOLIMIT_SCHEDULED_RUN') == 'true'
    ascii_logo = '''
    _   _       _     _           _ _   
   | \ | |     | |   (_)         (_) |  
   |  \| | ___ | |    _ _ __ ___  _| |_ 
   | . ` |/ _ \| |   | | '_ ` _ \| | __|
   | |\  | (_) | |___| | | | | | | | |_ 
   |_| \_|\___/|_____|_|_| |_| |_|_|\__|
                        v1.0 by jivy26    
    '''
    parser = argparse.ArgumentParser(
        description=f'''{ascii_logo}
    MakeEmSayUhhh: Advanced Python Port Scanner with Service Enumeration inspired by Masscan...nuh nah nah nah nuh nah nah nah
    {Fore.RED}WARNING: Not for use on internal networks as it might cause network disruption.{Fore.RESET}''',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f'''
    Example usage:
    python nolimit.py -p 1-4000 -i ips.txt -t -w 1000 -srv
    - This example scans TCP ports 1-4000 for IPs listed in ips.txt, using 1000 workers and enabling nmap service detection.

    python nolimit.py --top-ports 4000 -i ips.txt -t -w 1000 -srv --schedule "05/15 12:00"
    - This example scans top 4000 TCP ports for IPs listed in ips.txt, using 1000 workers and enabling nmap service detection,
    schedules the scan for May 15 at 12:00 PM.
    ''',
    usage="python nolimit.py [options]"
    )
    parser.add_argument('-p', '--ports', nargs='?', const='1-65535', type=str, help='Ports to scan, e.g., "80,443" or "1-1024". If not specified, all ports will be scanned.')
    parser.add_argument('--top-ports', type=int, help='Scan only the top N most common ports')    
    parser.add_argument('-i', '--ip', type=str, required=True, help='[Required] Single IP or file with list of IPs to scan')
    parser.add_argument('-t', '--tcp', action='store_true', help='TCP Port Scans')
    parser.add_argument('-u', '--udp', action='store_true', help='UDP Port Scans')
    parser.add_argument('-srv', '--service', action='store_true', help='Enable service detection with Nmap')
    parser.add_argument('-w', '--workers', type=int, default=500, help='Number of concurrent workers (default: 500)')
    parser.add_argument('--scapy', action='store_true', help='Use Scapy for scanning. Helps evade firewalls by customizing packets.')
    parser.add_argument('--resume', action='store_true', help='Resume from the last saved progress')
    parser.add_argument('--adaptive', action='store_true', help='Use adaptive scanning. Automatically adjusts worker count based on open ports found.')
    parser.add_argument('--rate-limit', type=float, help='Rate limit in packets per second')
    parser.add_argument('--schedule', type=str, help='Schedule the scan for a future time (format: "MM/DD HH:MM")')


    args = parser.parse_args()

    if args.schedule and not is_scheduled_run:
        try:
            schedule_datetime = datetime.strptime(args.schedule, "%m/%d %H:%M")
            current_year = datetime.now().year
            schedule_datetime = schedule_datetime.replace(year=current_year)
            
            if schedule_datetime <= datetime.now():
                schedule_datetime = schedule_datetime.replace(year=current_year + 1)
            
            schedule_time = schedule_datetime.strftime("%Y-%m-%d %H:%M:00")
            schedule_scan(args, schedule_time)
            return
        except ValueError:
            print(f"{Fore.RED}Invalid date format. Please use MM/DD HH:MM")
            sys.exit(1)

    use_scapy = check_scapy_flag(args)

    if not args.tcp and not args.udp:
        print(f"{Fore.RED}Error: Please specify either -t (TCP) or -u (UDP) for scanning.")
        return

    current_ulimit = resource.getrlimit(resource.RLIMIT_NOFILE)[0]

    print(f"{Fore.CYAN}Current ulimit: {current_ulimit}")
    print(f"{Fore.CYAN}Requested workers: {args.workers}")

    if args.workers > current_ulimit:
        args.workers = current_ulimit
        print(f"{Fore.YELLOW}Adjusting workers to: {args.workers}")

    if args.top_ports:
        ports = load_top_ports(args.top_ports)
        print(f"{Fore.CYAN}Scanning top {args.top_ports} ports")
    elif args.ports:
        ports = parse_ports(args.ports)
    else:
        ports = list(range(1, 65536))

    if not os.path.isfile(args.ip):
        print(f"{Fore.RED}Error: The specified IP file '{args.ip}' does not exist in the current working directory.")
        sys.exit(1)

    ips = shuffle_ips(await load_ips(args.ip))
    open_ports = []

    if args.resume:
        progress_data = await load_progress()
        if progress_data:
            ips = progress_data['ips']
            ports = progress_data['ports']
            open_ports = progress_data['open_ports']
            current_ip_index = progress_data['current_ip_index']
            current_port_index = progress_data['current_port_index']
            print(f"{Fore.YELLOW}Resuming scan from IP {ips[current_ip_index]} and port {ports[current_port_index]}")
        else:
            print(f"{Fore.YELLOW}No previous progress found. Starting a new scan.")
            current_ip_index = current_port_index = 0
    else:
        current_ip_index = current_port_index = 0

    total_scans = len(ips) * len(ports) * (2 if args.tcp and args.udp else 1)

    def signal_handler(sig, frame):
        print(f"\n{Fore.YELLOW}Received interrupt signal. Gracefully exiting...")
        if args.tcp:
            asyncio.create_task(save_open_ports(open_ports, 'tcp'))
        if args.udp:
            asyncio.create_task(save_open_ports(open_ports, 'udp'))
        asyncio.create_task(save_progress(ips, ports, open_ports, current_ip_index, current_port_index))
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        with tqdm(total=total_scans, desc="Scanning Progress", unit="scan", leave=True, position=1) as progress:
            for ip in ips:
                if args.tcp:
                    await scan_ports(ip, ports, 'tcp', progress, open_ports, args.workers, use_scapy, args.adaptive, args.rate_limit)
                if args.udp: 
                    await scan_ports(ip, ports, 'udp', progress, open_ports, args.workers, use_scapy, args.adaptive, args.rate_limit)

        tcp_folder = None
        udp_folder = None

        if args.tcp:
            tcp_folder = await save_open_ports(open_ports, 'tcp')
        if args.udp:
            udp_folder = await save_open_ports(open_ports, 'udp')

        if args.scapy and args.adaptive:
            folder_name = tcp_folder if tcp_folder else udp_folder
            await create_evasion_script(open_ports, folder_name)

        if args.service:
            if args.tcp:

                print(f"{Fore.CYAN}\nStarting TCP service detection...")
                await nmap_service_detection(open_ports, 'tcp', tcp_folder)
                
                if args.udp:
                    input(f"{Fore.YELLOW}\nPress Enter to proceed with UDP service detection...")
            
            if args.udp:
                print(f"{Fore.CYAN}\nStarting UDP service detection...")
                await nmap_service_detection(open_ports, 'udp', udp_folder)

        print(f"{Fore.GREEN}\nScan completed.")
        print(f"{Fore.YELLOW}Open ports found: {len(open_ports)}")
        for ip, port, protocol, technique in open_ports:
            print(f"{Fore.CYAN}{protocol.upper()} {ip}:{port} - Technique: {technique}")

    except Exception as e:
        print(f"{Fore.RED}\nAn error occurred: {str(e)}")
        print(f"{Fore.YELLOW}Attempting to save partial results...")
        if args.tcp:
            await save_open_ports(open_ports, 'tcp')
        if args.udp:
            await save_open_ports(open_ports, 'udp')
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
