from scapy.all import sniff, IP, TCP, ICMP, conf,show_interfaces

import logging

# Configuración del logger
logging.basicConfig(filename='ids.log', level=logging.INFO, format='%(asctime)s - %(message)s')

connections = {}

def packet_callback(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        dst_port = packet[TCP].dport

        if ip_src not in connections:
            connections[ip_src] = set()
        connections[ip_src].add(dst_port)

        #print(f"IP {ip_src} se ha conectado a {len(connections[ip_src])} puertos")

        if len(connections[ip_src]) > 10:
            logging.info(f"Posible escaneo de puertos detectado desde {ip_src}")
            print(f"Posible escaneo de puertos detectado desde {ip_src}")

selected_iface = "Intel(R) Wi-Fi 6 AX200 160MHz"   # Initialize with None or a default interface name
      
if selected_iface is None:
    print("No matching interface found. Please check the IP address or specify the interface manually.")
else:
    # Use the selected interface for sniffing
    sniff(iface=selected_iface, prn=packet_callback, store=0)