#!/usr/bin/env python3
"""Send one SYN in the isolated SEED Mitnick Docker network.
Run: sudo docker exec -it seed-attacker python3 /volumes/syn_probe.py
"""
from scapy.all import IP, TCP, send

TRUSTED_IP = "10.9.0.6"       # Spoofed source, trusted-server container
TARGET_IP = "10.9.0.5"        # X-Terminal container
SOURCE_PORT = 1023            # Reserved source port used for this lab
TARGET_PORT = 514             # Legacy rsh service
CLIENT_ISN = 0x1000           # Decimal 4096

syn = (
    IP(src=TRUSTED_IP, dst=TARGET_IP)
    / TCP(sport=SOURCE_PORT, dport=TARGET_PORT,
          flags="S", seq=CLIENT_ISN)
)

print("[*] Sending one lab SYN", flush=True)
send(syn, count=1, verbose=False)
print("[+] SYN sent; inspect Wireshark for SYN-ACK", flush=True)
