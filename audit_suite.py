import os
from scapy.all import sniff, IP, TCP

def run_scanner():
    print("\n--- Starting Network Discovery ---")
    # This calls your existing ARP command
    os.system("arp -a")
    print("Discovery Complete.\n")

def packet_callback(packet):
    if packet.haslayer(TCP) and packet.haslayer(IP):
        src, dst = packet[IP].src, packet[IP].dst
        if packet[TCP].dport == 80 or packet[TCP].sport == 80:
            print(f"⚠️  ALERT: Unsecure HTTP from {src} to {dst}")

def run_ids():
    print("\n🛡️  IDS Active... Watching for unencrypted traffic.")
    sniff(iface="en0", prn=packet_callback, store=0)

def main():
    print("=== Frank's Security Audit Suite 2026 ===")
    print("1. Run Network Discovery (Scan)")
    print("2. Start Live IDS (Sniff)")
    choice = input("Select an option: ")

    if choice == '1':
        run_scanner()
    elif choice == '2':
        run_ids()
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()
