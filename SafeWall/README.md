# SafeWall - Network Security Tool

A network monitoring and security tool that detects DDoS attacks and malware signatures.

## Features

- ✅ Real-time network traffic monitoring
- ✅ DDoS attack detection (>40 packets/sec)
- ✅ Malware signature detection (Nimda, SQL injection, XSS, etc.)
- ✅ IP whitelisting (trusted IPs)
- ✅ IP blacklisting (malicious IPs)
- ✅ Automatic IP blocking (Linux with iptables)
- ✅ Comprehensive logging

## Installation

### Windows
1. Download and install Npcap: https://npcap.com/dist/npcap-1.13.1.exe
   - Run installer
   - Check: "Install Npcap in WinPcap API-compatible mode"
   - Click Install → Finish

2. Install dependencies:
```bash
   pip install -r requirements.txt
```

3. Run as Administrator:
```bash
   python SafeWall.py
```

### Linux
1. Install dependencies:
```bash
   pip install -r requirements.txt
```

2. Run with sudo:
```bash
   sudo python3 SafeWall.py
```

## Configuration

Edit `whitelist.txt` - Add trusted IPs (one per line)
Edit `blacklist.txt` - Add malicious IPs (one per line)

## Usage
```bash
python SafeWall.py
```

Press `Ctrl+C` to stop monitoring.

## Logs

All events are logged to: `logs/security.log`

View logs:
```bash
type logs/security.log
```

## Troubleshooting

- **"no module named scapy"**: Run `pip install scapy`
- **"permission denied"**: Run Command Prompt as Administrator
- **"Npcap not found"**: Download from https://npcap.com/

## License

MIT License