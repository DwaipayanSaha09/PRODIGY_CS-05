import scapy.all as scapy

def packet_sniffer(packet):
    if packet.haslayer(scapy.IP):
        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto
        payload = packet[scapy.Raw].load if packet.haslayer(scapy.Raw) else ""

        print(f"Source IP: {ip_src}, Destination IP: {ip_dst}, Protocol: {protocol}, Payload: {payload}")

scapy.sniff(iface="eth0", prn=packet_sniffer, store=False)
