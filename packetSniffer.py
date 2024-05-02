import scapy.all as scapy
import datetime


def sniff_packets(interface="en0"):
    try:
        scapy.sniff(iface=interface, prn=process_packet, store=False)
    except Exception as e:
        print("Error:", e)

def process_packet(packet):
    time = datetime.datetime.now()
    try:
        src = packet[scapy.IP].src
        dst = packet[scapy.IP].dst

        protocol = packet[scapy.IP].proto

        if packet.haslayer(scapy.TCP):
            payload = len(packet[scapy.TCP])
        elif packet.haslayer(scapy.UDP):
            payload = len(packet[scapy.UDP])
        elif packet.haslayer(scapy.ICMP):
            payload = len(packet[scapy.ICMP])
        else:
            payload = 0
        
        print(f"[{time}] Source IP: {src}, Destination IP: {dst}, Protocol: {protocol}, Payload Data: {payload} Bytes")
    except Exception as e:
        print("Error processing packet:", e)

def main():
    interface = input("Enter the interface you wish to analyze packets on: (eth0, lo0, en0, etc.): ")
    sniff_packets(interface)

if __name__ == "__main__":
    main()
