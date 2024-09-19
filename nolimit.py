import asyncio
import argparse
import json
import logging
import os
import random
import resource
import signal
import subprocess
import sys
import time
from functools import lru_cache
import aiofiles
import warnings
from cryptography.utils import CryptographyDeprecationWarning
from colorama import init, Fore
from rich.console import Console
from rich.table import Table
from scapy.all import sr1, IP, TCP, UDP, fragment
from tqdm import tqdm

## Start Utility Functions Section
init(autoreset=True)

warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

logging.basicConfig(filename='nmap_service_detection.log', level=logging.DEBUG,
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

# async def check_and_add_alias():
#     home = os.path.expanduser("~")
#     zshrc_path = os.path.join(home, ".zshrc")
    
#     if not os.path.exists(zshrc_path):
#         return
    
#     async with aiofiles.open(zshrc_path, 'r') as file:
#         content = await file.read()
    
#     if "nolimit.py" not in content:
#         response = input("Would you like to add a 'nolimit' alias to your .zshrc file? (y/n): ").lower()
#         if response == 'y':
#             script_path = os.path.abspath(__file__)
#             alias_line = f"\nalias nolimit='python {script_path}'\n"
            
#             async with aiofiles.open(zshrc_path, 'a') as file:
#                 await file.write(alias_line)
            
#             print(f"{Fore.GREEN}Alias added to {zshrc_path}. Please restart your terminal or run 'source ~/.zshrc' to apply changes.")
#         else:
#             print("Alias not added.")
#     else:
#         print(f"{Fore.YELLOW}The 'nolimit' alias is already in your .zshrc file.")

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
    cmd = ['sudo', sys.executable, '-c', command]
    proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    stdout, stderr = await proc.communicate()
    if stderr:
        print(f"{Fore.RED}Scapy command error: {stderr.decode()}")
    return stdout.decode()

async def load_ips(ip_input):
    try:
        async with aiofiles.open(ip_input, 'r') as f:
            return [line.strip() for line in await f.readlines()]
    except FileNotFoundError:
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

    for ip, port, proto in sorted(open_ports, key=lambda x: (x[0], x[1])):
        if proto == protocol:
            if port in common_ports:
                filename = os.path.join(folder_name, common_ports[port])
                if filename not in port_files:
                    port_files[filename] = set()
                port_files[filename].add(ip)
            else:
                if other_ports_file not in port_files:
                    port_files[other_ports_file] = set()
                port_files[other_ports_file].add(f"{ip}:{port}")
            
            if port in web_ports:
                protocol_prefix = "https" if port in {443, 8443, 10443} else "http"
                web_urls.add(f"{protocol_prefix}://{ip}:{port}")

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

## Scapy and Standard Port Scanning Section
async def check_tcp_port_scapy(ip, port, open_ports):
    source_port = random.randint(1024, 65535)
    ttl = random.randint(40, 255)
    flags = random.choice(['S', 'A', 'F', 'P', 'R'])

    command = f"""
from scapy.all import sr1, IP, TCP, fragment
ip = '{ip}'
port = {port}
source_port = {source_port}
ttl = {ttl}
flags = '{flags}'
packet = IP(dst=ip, version=4, ttl=ttl) / TCP(sport=source_port, dport=port, flags=flags)
fragmented_packets = fragment(packet)
for frag in fragmented_packets:
    response = sr1(frag, timeout=1, verbose=0)
    if response and response.haslayer(TCP) and response[TCP].flags == "SA":
        print('OPEN')
        break
"""
    result = await run_scapy_scan(command)
    if "OPEN" in result:
        open_ports.append((ip, port, 'tcp'))
        tqdm.write(f"{Fore.GREEN}TCP {ip}:{port} is open")

async def check_udp_port_scapy(ip, port, open_ports):
    source_port = random.randint(1024, 65535)
    ttl = random.randint(40, 255)

    command = f"""
from scapy.all import sr1, IP, UDP, fragment
ip = '{ip}'
port = {port}
source_port = {source_port}
ttl = {ttl}
packet = IP(dst=ip, version=4, ttl=ttl) / UDP(sport=source_port, dport=port)
fragmented_packets = fragment(packet)
for frag in fragmented_packets:
    response = sr1(frag, timeout=1, verbose=0)
    if response is None or response.haslayer(UDP):
        print('OPEN')
        break
"""
    result = await run_scapy_scan(command)
    if "OPEN" in result:
        open_ports.append((ip, port, 'udp'))
        tqdm.write(f"{Fore.GREEN}UDP {ip}:{port} is open")

async def check_tcp_port(ip, port, open_ports):
    try:
        conn = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(conn, timeout=1.0)
        open_ports.append((ip, port, 'tcp'))
        tqdm.write(f"{Fore.GREEN}TCP {ip}:{port} is open")
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
        except asyncio.TimeoutError:
            pass  # Port is likely closed or filtered
        finally:
            protocol.transport.close()
    except Exception as e:
        tqdm.write(f"{Fore.RED}Error checking UDP {ip}:{port} - {e}")

async def scan_ports(ip, ports, protocol, progress, open_ports, max_workers, use_scapy=False, use_adaptive=False, rate_limit=None):
    if use_adaptive:
        await adaptive_scan(ip, ports, protocol, progress, open_ports, max_workers, use_scapy, rate_limit)
    else:
        sem = asyncio.Semaphore(max_workers)

        async def scan_with_semaphore(port):
            async with sem:
                if protocol == 'tcp':
                    if use_scapy:
                        await check_tcp_port_scapy(ip, port, open_ports)
                    else:
                        await check_tcp_port(ip, port, open_ports)
                elif protocol == 'udp':
                    if use_scapy:
                        await check_udp_port_scapy(ip, port, open_ports)
                    else:
                        await check_udp_port(ip, port, open_ports)
                progress.update(1)
                if rate_limit:
                    await asyncio.sleep(1 / rate_limit)

        await asyncio.gather(*[scan_with_semaphore(port) for port in ports])

## End of Scapy and Standard Port Scanning Section

## Nmap Service Detection Section
async def nmap_service_detection(open_ports, protocol, folder_name):
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
        
        table_str = "HOST\tPORT\tSTATE\tSERVICE VERSION\n"
        table_str += "----\t----\t-----\t---------------\n"
        for result in summary_data:
            table_str += f"{result[0]}\t{result[1]}\t{result[2]}\t{result[3]}\n"
        
        await f.write(table_str)
    
    print(f"{Fore.YELLOW}Summary saved to: {summary_file}")

async def run_nmap_scan(ip, port):
    cmd = ["sudo", "nmap", "-sV", "-p", str(port), ip, "-Pn", "-T4"]
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
    script_path = os.path.abspath(__file__)
    command = f"python {script_path} {' '.join(sys.argv[1:])}"
    
    # Format the at command
    at_command = f"echo '{command}' | at {schedule_time}"
    
    try:
        subprocess.run(at_command, shell=True, check=True)
        print(f"{Fore.GREEN}Scan scheduled for {schedule_time}")
    except subprocess.CalledProcessError:
        print(f"{Fore.RED}Failed to schedule the scan. Make sure 'at' is installed and you have the necessary permissions.")
        sys.exit(1)

async def main():
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

    if args.schedule:
        try:
            schedule_datetime = datetime.strptime(args.schedule, "%m/%d %H:%M")
            current_year = datetime.now().year
            schedule_datetime = schedule_datetime.replace(year=current_year)
            
            if schedule_datetime <= datetime.now():
                schedule_datetime = schedule_datetime.replace(year=current_year + 1)
            
            schedule_time = schedule_datetime.strftime("%H:%M %m/%d/%Y")
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
                    await scan_ports(ip, ports, 'tcp', progress, open_ports, args.workers, use_scapy)
                if args.udp: 
                    await scan_ports(ip, ports, 'udp', progress, open_ports, args.workers, use_scapy)

        tcp_folder = None
        udp_folder = None

        if args.tcp:
            tcp_folder = await save_open_ports(open_ports, 'tcp')
        if args.udp:
            udp_folder = await save_open_ports(open_ports, 'udp')

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
        script_dir = os.path.dirname(os.path.abspath(__file__))

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
