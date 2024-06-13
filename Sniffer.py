import argparse
import json
import csv
import threading
import time
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation
from scapy.all import sniff, IP, TCP, UDP, wrpcap

packet_count = 0
times = []
counts = []
syn_packets = {}
packets_log = []

def packet_callback(packet):
    global packet_count
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst

        if packet.haslayer(TCP):
            proto = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport

            if packet[TCP].flags == "S":
                if ip_src in syn_packets:
                    syn_packets[ip_src] += 1
                else:
                    syn_packets[ip_src] = 1

                if syn_packets[ip_src] > 100:
                    print(f"SYN flood attack detected from {ip_src}")

        elif packet.haslayer(UDP):
            proto = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport
        else:
            proto = "OTHER"
            sport = None
            dport = None

        packet_info = {
            "timestamp": time.time(),
            "protocol": proto,
            "source_ip": ip_src,
            "source_port": sport,
            "destination_ip": ip_dst,
            "destination_port": dport
        }

        packets_log.append(packet_info)
        output = f"{proto} Packet: {ip_src}:{sport} -> {ip_dst}:{dport}"
        print(output)
        packet_count += 1
        wrpcap('captured_packets.pcap', packet, append=True)

def update(frame):
    times.append(frame)
    counts.append(packet_count)
    plt.cla()
    plt.plot(times, counts, label='Packets over time')
    plt.xlabel('Time')
    plt.ylabel('Packet Count')
    plt.legend(loc='upper left')

def save_logs_as_json(filename):
    with open(filename, 'w') as f:
        json.dump(packets_log, f, indent=4)

def save_logs_as_csv(filename):
    keys = packets_log[0].keys()
    with open(filename, 'w', newline='') as f:
        dict_writer = csv.DictWriter(f, fieldnames=keys)
        dict_writer.writeheader()
        dict_writer.writerows(packets_log)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Enhanced Packet Sniffer")
    parser.add_argument('--duration', type=int, default=60, help='Capture duration in seconds')
    parser.add_argument('--log-format', choices=['json', 'csv'], default='json', help='Format to save the logs')
    args = parser.parse_args()

    fig = plt.figure()
    ani = FuncAnimation(fig, update, interval=1000)

    end_time = time.time() + args.duration
    sniffer_thread = threading.Thread(target=lambda: sniff(prn=packet_callback, filter="tcp or udp", store=0, timeout=args.duration))
    sniffer_thread.start()

    plt.show()

    sniffer_thread.join()

    print("Packet capture completed.")

    if args.log_format == 'json':
        save_logs_as_json('packets_log.json')
    elif args.log_format == 'csv':
        save_logs_as_csv('packets_log.csv')

    print(f"Logs saved as {args.log_format}")
