#!/usr/bin/env python3
import os
import sys
import time
from collections import defaultdict
from scapy.all import sniff, IP, TCP, Raw

# Settings
THRESHOLD = 40
LOG_FILE = "logs/security.log"

# Create logs folder if it doesn't exist
os.makedirs("logs", exist_ok=True)

# Check if running as admin (Windows) or root (Linux)
def is_admin():
    if os.name == 'nt':  # Windows
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    else:  # Linux
        return os.geteuid() == 0

# Read IPs from file
def read_ips(filename):
    if not os.path.exists(filename):
        open(filename, 'w').close()
        return set()
    
    try:
        with open(filename, "r") as f:
            ips = [line.strip() for line in f if line.strip()]
        return set(ips)
    except Exception as e:
        print(f"Error reading {filename}: {e}")
        return set()

# Save log to file
def log_it(msg):
    with open(LOG_FILE, "a") as f:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{timestamp}] {msg}\n")
    print(msg)

# Check if packet has attack signature
def is_attack(packet):
    signatures = {
        "nimda": b"GET /scripts/root.exe",
        "sql_inject": b"' OR '1'='1",
        "cmd": b"cmd.exe",
        "xss": b"<script>alert",
        "traversal": b"../../../etc/passwd",
        "php": b"<?php system",
    }
    
    if not packet.haslayer(TCP) or packet[TCP].dport != 80:
        return None
    
    if packet.haslayer(Raw):
        payload = packet[Raw].load
        for name, pattern in signatures.items():
            if pattern in payload:
                return name
    
    return None

# Block IP with iptables
def block_ip(ip, reason):
    try:
        os.system(f"iptables -A INPUT -s {ip} -j DROP")
        log_it(f"BLOCKED: {ip} ({reason})")
    except Exception as e:
        print(f"Error blocking {ip}: {e}")

# Process each packet
def handle_packet(packet):
    try:
        if not packet.haslayer(IP):
            return
        
        src_ip = packet[IP].src
        
        # Skip whitelist
        if src_ip in whitelist:
            return
        
        # Block blacklist immediately
        if src_ip in blacklist:
            block_ip(src_ip, "blacklisted")
            return
        
        # Check for attack signatures
        attack_type = is_attack(packet)
        if attack_type:
            block_ip(src_ip, f"attack: {attack_type}")
            return
        
        # Count packets for DDoS detection
        packet_count[src_ip] += 1
        
        # Check every 1 second
        current_time = time.time()
        elapsed = current_time - start_time[0]
        
        if elapsed >= 1:
            for ip, count in packet_count.items():
                rate = count / elapsed
                
                if rate > THRESHOLD and ip not in blocked:
                    block_ip(ip, f"DDoS: {rate:.0f} pkt/sec")
                    blocked.add(ip)
            
            packet_count.clear()
            start_time[0] = current_time
    
    except Exception as e:
        print(f"Error: {e}")

# Main
if __name__ == "__main__":
    # Check for admin privileges
    if not is_admin():
        if os.name == 'nt':
            print("Need to run as Administrator!")
            print("Right-click Command Prompt → Run as Administrator")
        else:
            print("Need sudo: sudo python3 main.py")
        sys.exit(1)
    
    # Load lists
    whitelist = read_ips("whitelist.txt")
    blacklist = read_ips("blacklist.txt")
    
    print(f"\n=== DDoS Detector ===")
    print(f"Whitelist: {len(whitelist)} IPs")
    print(f"Blacklist: {len(blacklist)} IPs")
    print(f"DDoS threshold: {THRESHOLD} packets/sec")
    print(f"Logging to: {LOG_FILE}")
    print("Starting... press Ctrl+C to stop\n")
    
    log_it("=== Scanner started ===")
    
    # Initialize
    packet_count = defaultdict(int)
    start_time = [time.time()]
    blocked = set()
    
    # Start sniffing
    try:
        sniff(filter="ip", prn=handle_packet, store=False)
    except KeyboardInterrupt:
        print("\n\nStopped.")
        log_it("=== Scanner stopped ===")