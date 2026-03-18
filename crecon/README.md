# crecon

Automated recon toolkit for Kali Linux. Chains port scanning, directory enumeration, subdomain discovery, web crawling, and SSH credential testing into a single tool.

## Features

- TCP port scanner with banner grabbing
- Directory and subdomain brute-forcing
- Web crawler — extracts emails, phones, and tech stack
- SSH credential testing via paramiko
- Full auto mode — chains everything based on open ports

## Install
```bash
git clone https://github.com/Abhracodec/Tools.git
cd Tools/crecon
pip3 install -r requirements.txt --break-system-packages
pip3 install -e . --break-system-packages
```

> Tested on Kali Linux with Python 3.13. The `--break-system-packages` flag is required on modern Kali due to PEP 668.

## Usage
```bash
# Full auto recon
crecon auto <target> --ports 1-1024 --wordlist /usr/share/wordlists/dirb/common.txt

# Port scan only
crecon scan <target> --start 1 --end 1000 --banners

# Web recon
crecon recon --url https://target.com --output results.csv

# Directory brute-force
crecon enum dirs --url http://target.com --wordlist /usr/share/wordlists/dirb/common.txt

# Subdomain enum
crecon enum subs --domain target.com --wordlist /usr/share/wordlists/dnsmap.txt
```

## Requirements

- Kali Linux (or any Debian-based distro)
- Python 3.10+
- Nmap installed (`sudo apt install nmap`)

## Legal

For authorized testing and educational use only.