from scapy.all import *
from colorama import Fore, init
from datetime import datetime
import argparse
import os



protocol_stats = {
    "TCP": 0,
    "UDP": 0,
    "ICMP": 0,
    "DNS": 0
}

# -----------------------------------
# Initialize Colorama
# -----------------------------------

init(autoreset=True)

# -----------------------------------
# Create Required Folders
# -----------------------------------

os.makedirs("logs", exist_ok=True)
os.makedirs("captures", exist_ok=True)

# -----------------------------------
# Suspicious Ports
# -----------------------------------

SUSPICIOUS_PORTS = [21, 22, 23, 4444, 5555, 1337]

# -----------------------------------
# Storage Variables
# -----------------------------------

captured_packets = []
scan_tracker = {}

# -----------------------------------
# Log Alerts
# -----------------------------------

def log_alert(message):

    with open("logs/alerts.txt", "a") as file:
        file.write(message + "\n")

# -----------------------------------
# Save Statistics
# -----------------------------------

def save_stats():

    with open("logs/stats.txt", "w") as file:

        for protocol, count in protocol_stats.items():

            file.write(f"{protocol}:{count}\n")
# -----------------------------------
# Detect Port Scan
# -----------------------------------

def detect_port_scan(ip, port):

    if ip not in scan_tracker:
        scan_tracker[ip] = set()

    scan_tracker[ip].add(port)

    # Alert if too many ports accessed
    if len(scan_tracker[ip]) > 10:

        alert = (
            f"[ALERT] Possible Port Scan "
            f"Detected from {ip}"
        )

        print(Fore.RED + alert)

        log_alert(alert)

# -----------------------------------
# Process Packets
# -----------------------------------

def process_packet(packet):

    # Store packets
    captured_packets.append(packet)

    # Save every 20 packets
    if len(captured_packets) % 20 == 0:

        wrpcap(
            "captures/network_traffic.pcap",
            captured_packets
        )

    # Check IP Layer
    if packet.haslayer(IP):

        timestamp = datetime.now().strftime("%H:%M:%S")

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # -----------------------------------
        # TCP
        # -----------------------------------

        if packet.haslayer(TCP):
            protocol_stats["TCP"] += 1
            save_stats()

            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

            print(
                Fore.GREEN +
                f"[{timestamp}] [TCP] "
                f"{src_ip}:{src_port} -> "
                f"{dst_ip}:{dst_port}"
            )

            # -----------------------------------
            # HTTP Payload Inspection
            # -----------------------------------

            if packet.haslayer(Raw):

                try:

                    payload = packet[Raw].load

                    decoded_payload = payload.decode(
                        errors="ignore"
                    )

                    # Common HTTP Methods
                    http_methods = [
                        "GET",
                        "POST",
                        "PUT",
                        "DELETE",
                        "HTTP"
                    ]

                    if any(
                        method in decoded_payload
                        for method in http_methods
                    ):

                        print(
                            Fore.BLUE +
                            "\n========== HTTP PAYLOAD =========="
                        )

                        print(
                            decoded_payload[:500]
                        )

                        print(
                            Fore.BLUE +
                            "==================================\n"
                        )

                except Exception:

                    pass

            # -----------------------------------
            # Suspicious Port Detection
            # -----------------------------------

            if dst_port in SUSPICIOUS_PORTS:

                alert = (
                    f"[ALERT] Suspicious Port "
                    f"Detected -> {dst_port}"
                )

                print(Fore.RED + alert)

                log_alert(alert)

            # -----------------------------------
            # Port Scan Detection
            # -----------------------------------

            detect_port_scan(src_ip, dst_port)

        # -----------------------------------
        # DNS
        # -----------------------------------

        elif packet.haslayer(DNS):
            protocol_stats["DNS"] += 1
            save_stats()

            try:

                if packet.haslayer(DNSQR):

                    domain = packet[DNSQR].qname.decode()

                    print(
                        Fore.MAGENTA +
                        f"[{timestamp}] [DNS] "
                        f"{src_ip} requested: {domain}"
                    )

            except Exception as e:

                print(Fore.RED + f"DNS Error: {e}")

        # -----------------------------------
        # UDP
        # -----------------------------------

        elif packet.haslayer(UDP):
            protocol_stats["UDP"] += 1
            save_stats()

            print(
                Fore.YELLOW +
                f"[{timestamp}] [UDP] "
                f"{src_ip} -> {dst_ip}"
            )

        # -----------------------------------
        # ICMP
        # -----------------------------------

        elif packet.haslayer(ICMP):
            protocol_stats["ICMP"] += 1
            save_stats()

            print(
                Fore.CYAN +
                f"[{timestamp}] [ICMP] "
                f"{src_ip} -> {dst_ip}"
            )

# -----------------------------------
# CLI Arguments
# -----------------------------------

parser = argparse.ArgumentParser()

parser.add_argument(
    "--filter",
    help="BPF Filter (tcp, udp, icmp, port 80)"
)

args = parser.parse_args()

# -----------------------------------
# Start Sniffer
# -----------------------------------

print(
    Fore.MAGENTA +
    "\n[+] Network Guardian Started...\n"
)

sniff(
    filter=args.filter if args.filter else None,
    prn=process_packet,
    store=False
)