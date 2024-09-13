# NoLimit Port Scanner

NoLimit is an advanced, asynchronous port scanner and service enumerator built in Python. It offers high-speed scanning capabilities with customizable options for both TCP and UDP protocols, designed for network administrators and security professionals.

## Features

- **Asynchronous Scanning**: Utilizes Python's asyncio for high-performance, concurrent scanning.
- **TCP and UDP Support**: Scan both TCP and UDP ports with a single tool.
- **Service Detection**: Integrates with Nmap for accurate service and version detection.
- **Scapy Integration**: Optional use of Scapy for customized packet crafting to evade firewalls.
- **Adaptive Scanning**: Automatically adjusts worker count based on open ports found for optimal performance.
- **Resume Functionality**: Ability to resume interrupted scans from the last saved progress.
- **Rate Limiting**: Control scan intensity to avoid overwhelming target networks.
- **Customizable Workers**: Adjust the number of concurrent workers to balance speed and resource usage.
- **Progress Tracking**: Real-time progress bar and ETA using tqdm.
- **Colorized Output**: Easy-to-read, color-coded console output for better visibility.

## Installation

1. Clone the repository:
   ```
   https://github.com/jivy26/nolimit.git
   cd nolimit
   ```

2. Install required packages:
   ```
   pip install -r requirements.txt
   ```

3. Ensure you have Nmap installed on your system for service detection functionality.

## Example usage:
`python nolimit.py -p 1-4000 -i ips.txt -t -w 1000 -srv`
This example scans TCP ports 1-4000 for IPs listed in ips.txt, using 1000 workers and enabling Nmap service detection.

### Options

- `-p, --ports`: Ports to scan (e.g., "80,443" or "1-1024"). Default: all ports.
- `-i, --ip`: [Required] Single IP or file with list of IPs to scan.
- `-t, --tcp`: Enable TCP port scanning.
- `-u, --udp`: Enable UDP port scanning.
- `-srv, --service`: Enable service detection with Nmap.
- `-w, --workers`: Number of concurrent workers (default: 500).
- `--scapy`: Use Scapy for scanning (helps evade firewalls).
- `--resume`: Resume from the last saved progress.
- `--adaptive`: Use adaptive scanning to adjust worker count dynamically.
- `--rate-limit`: Set rate limit in packets per second.

## Output

NoLimit generates two main types of output:
1. Real-time console output with color-coded results.
2. Text files containing lists of open ports:
   - `tcp_openports.txt` for open TCP ports.
   - `udp_openports.txt` for open UDP ports.

When service detection is enabled, a detailed table of services and versions is displayed in the console.

## Warnings and Ethical Use

**IMPORTANT**: NoLimit is a powerful tool designed for authorized use only. Improper use on networks without explicit permission may be illegal and unethical. Always ensure you have proper authorization before scanning any network or system you do not own.
