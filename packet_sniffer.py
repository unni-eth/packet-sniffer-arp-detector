#!/usr/bin/env python3
"""
Basic Packet Sniffer + ARP Spoofing Detector
Skillfied Mentor Internship Project 2

Captures live network traffic and monitors ARP replies to detect
possible ARP spoofing / man-in-the-middle attacks by tracking
IP-to-MAC address mappings and flagging inconsistencies.
"""

import time
import logging
from datetime import datetime
from collections import defaultdict

try:
    from scapy.all import sniff, ARP, IP, TCP, UDP, Ether
except ImportError:
    raise SystemExit("scapy not installed. Run: pip install scapy --break-system-packages")

# ---------------------------------------------------------
# Configuration
# ---------------------------------------------------------
LOG_FILE = "sniffer_log.txt"
ALERT_FILE = "arp_spoof_alerts.txt"

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s | %(message)s"
)

# Table mapping IP -> MAC address seen so far
ip_mac_table = {}

# Track how many times each IP has changed MAC (helps reduce false positives)
change_counter = defaultdict(int)


# ---------------------------------------------------------
# Alerting
# ---------------------------------------------------------
def raise_alert(ip, old_mac, new_mac):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    message = (
        f"[!] POSSIBLE ARP SPOOFING DETECTED\n"
        f"    Time      : {timestamp}\n"
        f"    IP        : {ip}\n"
        f"    Old MAC   : {old_mac}\n"
        f"    New MAC   : {new_mac}\n"
        f"    Note      : Same IP resolved to a different MAC address.\n"
        "-" * 55
    )
    print(message)
    logging.warning(message.replace("\n", " | "))
    with open(ALERT_FILE, "a") as f:
        f.write(message + "\n")


# ---------------------------------------------------------
# ARP inspection
# ---------------------------------------------------------
def process_arp(pkt):
    if pkt.haslayer(ARP) and pkt[ARP].op == 2:  # op=2 -> ARP reply
        sender_ip = pkt[ARP].psrc
        sender_mac = pkt[ARP].hwsrc

        if sender_ip in ip_mac_table:
            known_mac = ip_mac_table[sender_ip]
            if known_mac != sender_mac:
                change_counter[sender_ip] += 1
                raise_alert(sender_ip, known_mac, sender_mac)
                ip_mac_table[sender_ip] = sender_mac
        else:
            ip_mac_table[sender_ip] = sender_mac
            logging.info(f"New IP-MAC mapping learned: {sender_ip} -> {sender_mac}")


# ---------------------------------------------------------
# General packet summary (sniffer part)
# ---------------------------------------------------------
def process_packet(pkt):
    try:
        if pkt.haslayer(ARP):
            process_arp(pkt)
            return

        if pkt.haslayer(IP):
            src = pkt[IP].src
            dst = pkt[IP].dst
            proto = "OTHER"
            sport = dport = None

            if pkt.haslayer(TCP):
                proto = "TCP"
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
            elif pkt.haslayer(UDP):
                proto = "UDP"
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport

            summary = f"{proto} {src}:{sport} -> {dst}:{dport}"
            print(summary)
            logging.info(summary)

    except Exception as e:
        logging.error(f"Error processing packet: {e}")


# ---------------------------------------------------------
# Entry point
# ---------------------------------------------------------
def main():
    print("=" * 55)
    print(" Basic Packet Sniffer + ARP Spoofing Detector")
    print(" Logging to:", LOG_FILE)
    print(" Alerts to :", ALERT_FILE)
    print(" Press Ctrl+C to stop")
    print("=" * 55)

    try:
        sniff(prn=process_packet, store=False)
    except PermissionError:
        print("[!] Run this script with sudo/administrator privileges.")
    except KeyboardInterrupt:
        print("\n[*] Sniffer stopped by user.")


if __name__ == "__main__":
    main()
