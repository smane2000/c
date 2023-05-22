import pyshark
import csv

def capture_packets(interface, filter_expression):
    capture = pyshark.LiveCapture(interface=interface, display_filter=filter_expression, only_summaries=True)
    capture.sniff(timeout=10)  # Capture packets for 10 seconds or adjust as needed
    return capture

def extract_info(packets):
    log_data = []
    for packet in packets:
        # Extract required fields from the packet
        timestamp = packet.time
        src_ip = packet.source
        dst_ip = packet.destination

        # Append the extracted data to the log_data list
        log_data.append([timestamp, src_ip, dst_ip])

    return log_data

interface = "eth0"  # Replace with the appropriate network interface name
filter_expression = "tcp port 80"  # Replace with your desired filter expression

packets = capture_packets(interface, filter_expression)
log_data = extract_info(packets)

output_file = "network_logs.csv"  # Replace with the desired output file name

with open(output_file, "w", newline="") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["Timestamp", "Source IP", "Destination IP"])  # Write the header row
    writer.writerows(log_data)  # Write the log data rows
