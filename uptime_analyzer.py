
# Network Security Tool: System Uptime Analyzer
# Author: AS-Lazarus
# Purpose: Monitors critical infrastructure availability by performing active TCP handshakes to verify service reachability and port status.

import socket
import datetime

def check_port(ip, port=80):
    timestamp = datetime.datetime.now()
    # This uses a standard TCP connection (no special privileges needed!)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2) # 2-second timeout
    result = sock.connect_ex((ip, port))
    
    with open("system_logs.txt", "a") as log:
        if result == 0:
            log.write(f"[{timestamp}] SUCCESS: Port {port} on {ip} is OPEN.\n")
            print("System is UP.")
        else:
            log.write(f"[{timestamp}] ALERT: Port {port} on {ip} is CLOSED.\n")
            print("System is DOWN.")
    sock.close()

check_port("8.8.8.8", 53) # Port 53 is Google DNS

