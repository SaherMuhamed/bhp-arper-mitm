from scapy.all import sniff, TCP, IP
import sys


def packet_callback(packet):
    if packet[TCP].payload:
        my_packet = str(packet[TCP].payload)
        if 'user' in my_packet.lower() or 'pass' in my_packet.lower():
            print(f"[*] Destination: {packet[IP].dst}")
            print(f"[*] {str(packet[TCP].payload)}")

    # print(packet.show())


def main():
    if len(sys.argv) != 2:
        print("[+] Usage: %s <iface>" % sys.argv[0])
        print("[+] Example: %s eth0" % sys.argv[0] + "\n")
        sys.exit(-1)
    try:
        print(f"[*] Start sniffing on interface -> {sys.argv[1]}")

        # 110 (POP3) / 143 (IMAP) / 25 (SMTP) focusing on mail-related ports
        sniff(filter='tcp port 110 or tcp port 25 or tcp port 143', iface=sys.argv[1], prn=packet_callback, count=1, store=0)
    except KeyboardInterrupt:
        print("\n[*] Detected 'ctrl + c' pressed, program terminated.")
        sys.exit(0)   


if __name__ == "__main__":
    main()
