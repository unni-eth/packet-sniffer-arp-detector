# Basic Packet Sniffer + ARP Spoofing Detector

**Skillfied Mentor Cybersecurity Internship — Project 2**

## Objective
Build a lightweight network monitoring tool that:
1. Captures live packets on the network interface (sniffer functionality).
2. Continuously builds an IP-to-MAC address mapping table from ARP replies.
3. Flags a possible **ARP spoofing / Man-in-the-Middle (MITM) attack** whenever
   an IP address that was already mapped to one MAC address suddenly appears
   with a different MAC address.

## How It Works
- The tool uses `scapy` to sniff all traffic on the host machine.
- Every **TCP/UDP/IP** packet is logged with source IP, destination IP, and port
  information — this is the "packet sniffer" component.
- Every **ARP reply** packet is inspected separately:
  - If the sender IP has not been seen before, its MAC address is stored.
  - If the sender IP has been seen before **and** the MAC address does not
    match what was previously recorded, an alert is raised — this is the
    classic signature of ARP spoofing/cache poisoning, where an attacker
    sends forged ARP replies to associate their own MAC address with the
    IP of another host (commonly the gateway) to intercept traffic.

## Files
| File | Purpose |
|---|---|
| `packet_sniffer.py` | Main script — sniffing + ARP spoof detection logic |
| `requirements.txt` | Python dependencies |
| `sniffer_log.txt` | Auto-generated log of all captured packets |
| `arp_spoof_alerts.txt` | Auto-generated log of only ARP spoofing alerts |

## How to Run
```bash
pip install -r requirements.txt
sudo python3 packet_sniffer.py     # Linux/Mac — needs root for raw sockets
# On Windows, run terminal as Administrator instead of using sudo
```

## Sample Alert Output
```
[!] POSSIBLE ARP SPOOFING DETECTED
    Time      : 2026-08-12 14:32:10
    IP        : 192.168.1.1
    Old MAC   : aa:bb:cc:dd:ee:ff
    New MAC   : 11:22:33:44:55:66
    Note      : Same IP resolved to a different MAC address.
-------------------------------------------------------
```

## Vulnerability Report

**Vulnerability:** ARP Spoofing (ARP Cache Poisoning)

**Description:** ARP has no built-in authentication, so any device on a LAN
can send unsolicited ARP replies. An attacker exploits this by broadcasting
forged replies claiming their MAC address belongs to a trusted IP (often the
router), causing other hosts to send traffic through the attacker — enabling
traffic interception, session hijacking, or denial of service.

**Impact:**
- Confidentiality: Attacker can read intercepted traffic (MITM).
- Integrity: Traffic can be modified in transit.
- Availability: Attacker can silently drop packets (DoS).

**Detection Method Used:** Passive IP-to-MAC mapping table with mismatch
detection on every new ARP reply, as implemented in `packet_sniffer.py`.

## Mitigation Steps
1. **Static ARP entries** for critical infrastructure (gateway, servers) to
   prevent them from being overwritten.
2. **Dynamic ARP Inspection (DAI)** on managed switches to validate ARP
   packets against a trusted DHCP snooping binding table.
3. **Port security** on switches to limit MAC addresses per port.
4. **Network segmentation (VLANs)** to reduce the broadcast domain and
   limit the blast radius of a spoofing attack.
5. **Encrypted protocols (HTTPS, SSH, VPN)** so that even if traffic is
   intercepted, it cannot be read or tampered with in plaintext.
6. **Continuous monitoring** using tools like this sniffer, or production
   tools such as Arpwatch/XArp, to alert admins in real time.

## Key Learning
Clear vulnerability reports and mitigation steps are key skills in cyber
security roles — this project demonstrates the full loop of detecting a
network-layer attack technically and then translating that finding into an
actionable, prioritized mitigation plan.
