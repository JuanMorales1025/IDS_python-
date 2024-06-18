from scapy.all import sniff, conf

def packet_callback(packet):
    print(packet.summary())

# List all interfaces and their details
for iface_name in conf.ifaces:
    iface_details = conf.ifaces[iface_name]
    try:
        print(f"Capturing on interface: {iface_details.name} ({iface_name})")
        # Use win_name for Windows compatibility
        sniff(iface=iface_details.name, prn=packet_callback, count=10, timeout=5)
    except Exception as e:
        print(f"Failed to capture on interface {iface_details.name} ({iface_name}): {e}")
