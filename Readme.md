# Packet Sniffer

## Description
The Packet Sniffer Tool is a network monitoring utility designed for capturing, analyzing, and logging network traffic. It provides real-time visualization of captured packets, detects potential SYN flood attacks, and logs detailed packet information for further analysis. This tool is useful for network administrators, security analysts, and anyone interested in monitoring network traffic and identifying suspicious activities.


## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/G-r0ute/Packet-Sniffer.git


## Features
Packet Capture and Filtering:

## Captures TCP and UDP packets.
Extracts and logs detailed packet information including source and destination IP addresses, ports, and protocol type.

## Real-Time Visualization:
Displays a real-time plot of packet counts over time using matplotlib.

## SYN Flood Detection:
Monitors for potential SYN flood attacks by counting SYN packets from each IP address and alerting if the count exceeds a threshold.
Improved Logging:

## Logs captured packets with timestamps and detailed information.
Supports saving logs in JSON or CSV format.


## Command-Line Interface:
Allows setting the capture duration and log format through command-line arguments.


## Usage
Prerequisites:
Python 3.x
Required Python libraries: scapy, matplotlib

Install the required libraries using pip:
   ```bash
   pip install scapy matplotlib
```



## Running the Tool
To run the packet sniffer tool, use the following command:
```bash
   python packet_sniffer.py [--duration DURATION] [--log-format LOG_FORMAT]'
```
## Command-Line Arguments
## --duration DURATION: Specifies the capture duration in seconds. Default is 60 seconds.
   Example: --duration 120 (captures packets for 120 seconds)
## --log-format LOG_FORMAT: Specifies the format for saving logs. Choices are json or csv. Default is json.
   Example: --log-format csv (saves logs in CSV format)

## Examples
Capture packets for 60 seconds and save logs in JSON format:
```bash
   python packet_sniffer.py
```
Capture packets for 120 seconds and save logs in JSON format:
```bash
   python packet_sniffer.py --duration 120
```
Capture packets for 60 seconds and save logs in CSV format:
```bash
   python packet_sniffer.py --log-format csv
```
Capture packets for 120 seconds and save logs in CSV format:
```bash
   python packet_sniffer.py --duration 120 --log-format csv
```

## Example Output
When running the tool, you will see output in the console similar to:

### TCP Packet: 192.168.1.10:12345 -> 192.168.1.20:80
### UDP Packet: 192.168.1.15:54321 -> 192.168.1.25:53
### SYN flood attack detected from 192.168.1.10

A matplotlib window will also display a real-time plot of the number of packets captured over time.

## Log Files
Logs are saved in the specified format (packets_log.json or packets_log.csv).
Captured packets are saved in a PCAP file (captured_packets.pcap) for further analysis with tools like Wireshark and also customisable
