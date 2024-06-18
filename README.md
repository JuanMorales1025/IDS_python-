# Python IDS Project

## Description

This project implements an Intrusion Detection System (IDS) in Python using the Scapy library for capturing and analyzing network packets. The IDS is designed to detect patterns of suspicious traffic or anomalous behavior on a local network.

### Features

- **Packet Capture:** Uses Scapy to intercept and analyze IP and TCP/UDP packets.
- **Pattern Detection:** Implements simple rules to identify port scans and denial-of-service attacks.
- **Event Logging:** Utilizes the logging module to record detected events in a log file (`ids.log`).

## Prerequisites

- Python 3.x
- Scapy (`pip install scapy`)
- Npcap (on Windows for packet capture)

## Configuration

-Run python  `Prueba interfaces.py´ to list available network interfaces.
-Identify the correct interface and configure it in the main script (IDS.py).

## Usage
Run the IDS using the following command:
```bash
   python IDS.py
```
## Example Port Scan
Use nmap from another machine to scan ports on the machine running the IDS.
```bash
nmap -sS -p 1-65535 <IP_ADDRESS_OF_IDS>
```
