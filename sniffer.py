from scapy.all import sniff, IP, TCP
from datetime import datetime

def packet_callback(packet):
    if packet.haslayer(TCP) and packet.haslayer(IP):
        src, dst = packet[IP].src, packet[IP].dst
        sport, dport = packet[TCP].sport, packet[TCP].dport

        if dport == 80 or sport == 80:
            alert_msg = f"[{datetime.now()}] ⚠️ ALERT: HTTP detected from {src} to {dst}\n"
            print(alert_msg)
            
            # This appends every alert to a text file automatically
            with open("threat_log.txt", "a") as f:
                f.write(alert_msg)

print("🛡️  IDS LOGGING ACTIVE... Watching for threats.")
sniff(iface="en0", prn=packet_callback, store=0)
