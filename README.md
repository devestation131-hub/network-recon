# 🌐 Network Recon Sweep
**Language:** Bash | **Author:** Zachari Higgins

Network reconnaissance tool that performs host discovery, port scanning, OS fingerprinting, and service enumeration. Generates HTML reports.

## Phases
1. Host Discovery (ping sweep / nmap -sn)
2. Port Scanning with service detection
3. ARP table enumeration
4. HTML report generation

## Usage
```bash
chmod +x net_recon.sh
./net_recon.sh -t 192.168.1.0/24
./net_recon.sh -t 10.0.0.0/24 -o report.html -p "22,80,443,3389"
./net_recon.sh -t 192.168.1.1 --quick
```

## Dependencies
- nmap (recommended, falls back to bash /dev/tcp)
- ping, arp

## Ethical Use
Only scan networks you own or have written authorization to test.