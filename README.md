# NoLimit Scanner

NoLimit: An advanced, asynchronous port scanner and service enumerator built in Python. Inspired by Masscan, it offers high-speed scanning capabilities with customizable options for both TCP and UDP protocols. NoLimit provides a quick approach to port enumeration, designed for efficiency and speed.

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
- **Top Ports Scanning**: Option to scan only the most common ports as defined by Nmap.
- **Scan Scheduling**: Ability to schedule scans for future execution using the 'at' command.

## Installation

### Option 1: Install from PyPI (Currently not working, need to fix some PyPi specific Issues use Option 2 for now)

To install NoLimit directly from PyPI, run:
```pip install nolimit-scanner```


### Option 2: Build from Source

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

- `-p, --ports`: Ports to scan (e.g., "80,443" or "1-1024"). Default: all ports.
- `--top-ports`: Scan only the top N most common ports (e.g., --top-ports 100).
- `-i, --ip`: [Required] Single IP or file with list of IPs to scan.
- `-t, --tcp`: Enable TCP port scanning.
- `-u, --udp`: Enable UDP port scanning.
- `-srv, --service`: Enable service detection with Nmap.
- `-w, --workers`: Number of concurrent workers (default: 500).
- `--scapy`: Use Scapy for scanning (helps evade firewalls). **Recommend running against only tcpwrapped ports identified, as running on all ports will take a while**
- `--resume`: Resume from the last saved progress.
- `--adaptive`: Use adaptive scanning to adjust worker count dynamically.
- `--rate-limit`: Set rate limit in packets per second.
- `--schedule`: Schedule the scan for a future time (format: "MM/DD HH:MM").

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

