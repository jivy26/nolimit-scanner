# NoLimit Scanner

NoLimit: An advanced, asynchronous port scanner and service enumerator built in Python. Inspired by Masscan, it offers high-speed scanning capabilities with customizable options for both TCP and UDP protocols. NoLimit provides a quick approach to port enumeration, designed for efficiency and speed.

## Features

- **High-Speed Scanning**
  - Asynchronous engine with customizable worker counts
  - Built-in service fingerprinting
  - Banner grabbing with protocol detection
  - TCP/UDP support with rate limiting

- **Advanced Capabilities**
  - Quick scan profiles for common services
  - Dual progress tracking system
  - Adaptive scanning with auto-adjustment
  - Token bucket algorithm for traffic control
  - Service version detection with nmap integration

## Installation

### Build from Source

1. Clone the repository:
   ```bash
   git clone https://github.com/jivy26/nolimit-scanner.git
   cd nolimit-scanner
   ```

2. Install required packages:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

Example usage:
```bash
python nolimit.py -p 1-4000 -i ips.txt -t -w 1000 -srv
```

This example scans TCP ports 1-4000 for IPs listed in ips.txt, using 1000 workers and enabling Nmap service detection.

### Options

### Options

- `-p, --ports`: Ports to scan (e.g., "80,443" or "1-1024"). Default: all ports
- `--top-ports`: Scan only the top N most common ports (e.g., --top-ports 100)
- `-i, --ip`: Target IP address or file containing list of IPs
- `-t, --tcp`: Enable TCP port scanning
- `-u, --udp`: Enable UDP port scanning
- `-srv, --service`: Enable service detection (requires sudo)
- `-w, --workers`: Number of concurrent workers (default: 500)
- `--quick`: Use predefined scan profiles (web, remote, database, mail, all)
- `--scapy`: Enable experimental evasion techniques
- `--adaptive`: Dynamic worker count adjustment
- `--rate-limit`: Control packets per second
- `--resume`: Resume from last saved progress
- `-l, --log`: Specify log file for scan results

## Output

NoLimit generates several output files:

1. Real-time console output with color-coded results.
2. Protocol-specific folders (e.g., `tcp_1234`, `udp_5678`) containing:
   - `summary.txt`: Comprehensive summary of all scanned ports and services.
   - Specific host files for common ports (e.g., `http-hosts.txt`, `ssh-hosts.txt`).
   - `web-urls.txt`: List of discovered web URLs.
   - `[protocol]_other_ports.txt`: List of open ports not covered by specific files.

When service detection is enabled, a detailed table of services and versions is displayed in the console.

## Scheduling Scans (Currently Not Functional)

To schedule a scan for future execution, use the `--schedule` option followed by the desired date and time in the format "MM/DD HH:MM". For example:

```bash
python nolimit.py --top-ports 4000 -i ips.txt -t -w 1000 -srv --schedule "05/15 12:00"
```

This will schedule the scan to run on May 15th at 12PM. The scheduling feature uses the 'at' command, so make sure it's installed and properly configured on your system.

## Warnings and Ethical Use

**IMPORTANT**: Improper use on networks without explicit permission may be illegal and unethical. Always ensure you have proper authorization before scanning any network or system you do not own.

## Acknowledgments

- Inspired by the Masscan project

