#!/usr/bin/env python3
# kafka_packet_producer.py
import os
import re
import time
import json
import argparse
import paramiko
from datetime import datetime
from kafka import KafkaProducer
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def parse_tcpdump_line(line, current_ts=None):
    """
    Parse a line of tcpdump output to extract packet information.
    Returns a tuple (packet_info, timestamp) where packet_info is a dictionary with packet details
    or None if the line doesn't contain a complete packet, and timestamp is the packet timestamp or None.
    """
    try:
        header_re = re.compile(r'^(?P<timestamp>\d{10}\.\d{6}).*\sIP\s')
        tcp_re = re.compile(
            r'(?P<src_ip>\d+\.\d+\.\d+\.\d+)\.(?P<src_port>\d+)\s+>\s+'
            r'(?P<dst_ip>\d+\.\d+\.\d+\.\d+)\.(?P<dst_port>\d+):\s+'
            r'Flags\s+\[(?P<flags>[^\]]+)\].*?length\s+(?P<length>\d+)'
        )
        udp_re = re.compile(
            r'(?P<src_ip>\d+\.\d+\.\d+\.\d+)\.(?P<src_port>\d+)\s+>\s+'
            r'(?P<dst_ip>\d+\.\d+\.\d+\.\d+)\.(?P<dst_port>\d+):\s+'
            r'UDP,\s+length\s+(?P<length>\d+)'
        )

        m_hdr = header_re.match(line)
        if m_hdr:
            return None, m_hdr.group('timestamp')

        if current_ts:
            m_tcp = tcp_re.search(line)
            if m_tcp:
                gd = m_tcp.groupdict()
                return {
                    "timestamp": float(current_ts),
                    "src_ip": gd["src_ip"],
                    "dst_ip": gd["dst_ip"],
                    "protocol": "TCP",
                    "sport": int(gd["src_port"]),
                    "dport": int(gd["dst_port"]),
                    "flags_str": gd["flags"],
                    "length": int(gd["length"]),
                    "interface": "eth0"
                }, None

            m_udp = udp_re.search(line)
            if m_udp:
                gd = m_udp.groupdict()
                return {
                    "timestamp": float(current_ts),
                    "src_ip": gd["src_ip"],
                    "dst_ip": gd["dst_ip"],
                    "protocol": "UDP",
                    "sport": int(gd["src_port"]),
                    "dport": int(gd["dst_port"]),
                    "flags_str": "",
                    "length": int(gd["length"]),
                    "interface": "eth0"
                }, None

        return None, None
    except Exception as e:
        print(f"Error parsing tcpdump line: {e}")
        return None, None

def create_kafka_producer(bootstrap_servers):
    """Create and return a Kafka producer instance."""
    max_retries = 30
    retry_interval = 5  # seconds

    for attempt in range(1, max_retries + 1):
        try:
            print(f"Attempt {attempt}/{max_retries} to connect to Kafka at {bootstrap_servers}")
            producer = KafkaProducer(
                bootstrap_servers=bootstrap_servers,
                value_serializer=lambda v: json.dumps(v).encode('utf-8'),
                key_serializer=lambda k: k.encode('utf-8') if k else None
            )
            print(f"Successfully connected to Kafka and created producer")
            return producer
        except Exception as e:
            print(f"Attempt {attempt}/{max_retries} failed: {e}")
            if attempt < max_retries:
                print(f"Waiting {retry_interval} seconds before next attempt...")
                time.sleep(retry_interval)
            else:
                print(f"Failed to create Kafka producer after {max_retries} attempts: {e}")
                return None

def ssh_capture_and_produce(hostname, username, key_file, interface_str, filters, producer, topic):
    """
    Establish SSH connection to remote server, run tcpdump, and send packets to Kafka.
    """
    ssh_client = None
    try:
        print(f"Connecting to {hostname} as {username} using key {key_file}")
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(hostname=hostname, username=username, key_filename=key_file)

        if "," in interface_str or interface_str == "any":
            tcpdump_cmd = f"sudo tcpdump -i any -nn -l -tt -v {filters}"
        else:
            tcpdump_cmd = f"sudo tcpdump -i {interface_str} -nn -l -tt -v {filters}"

        print(f"Running command: {tcpdump_cmd}")
        stdin, stdout, stderr = ssh_client.exec_command(tcpdump_cmd, get_pty=True)

        current_ts = None
        packet_count = 0

        for raw_line in stdout:
            line = raw_line.strip()
            packet_info, new_ts = parse_tcpdump_line(line, current_ts)

            if new_ts:
                current_ts = new_ts

            if packet_info:
                # Use src_ip + dst_ip as the key for partitioning
                key = f"{packet_info['src_ip']}_{packet_info['dst_ip']}"
                producer.send(topic, key=key, value=packet_info)
                packet_count += 1

                if packet_count % 100 == 0:
                    print(f"Sent {packet_count} packets to Kafka")

                current_ts = None

    except Exception as e:
        print(f"Error in SSH capture: {e}")
    finally:
        if ssh_client:
            ssh_client.close()
            print("SSH connection closed")

def main():
    parser = argparse.ArgumentParser(description='Capture network packets and send to Kafka')
    parser.add_argument('--bootstrap-servers', default=os.environ.get('KAFKA_BOOTSTRAP_SERVERS', 'localhost:9092'),
                        help='Kafka bootstrap servers')
    parser.add_argument('--topic', default=os.environ.get('KAFKA_TOPIC', 'raw-packets'),
                        help='Kafka topic to send packets to')
    parser.add_argument('--hostname', required=True, help='SSH hostname')
    parser.add_argument('--username', default='ubuntu', help='SSH username')
    parser.add_argument('--key-file', required=True, help='SSH private key file')
    parser.add_argument('--interfaces', default='any', help='Network interfaces to capture (comma-separated)')
    parser.add_argument('--filters', default='', help='Additional tcpdump filters')

    args = parser.parse_args()

    producer = create_kafka_producer(args.bootstrap_servers)
    if not producer:
        print("Failed to create Kafka producer. Exiting.")
        return

    try:
        print(f"Starting packet capture on {args.hostname} interfaces {args.interfaces}")
        print(f"Sending packets to Kafka topic {args.topic} on {args.bootstrap_servers}")
        ssh_capture_and_produce(
            args.hostname, 
            args.username, 
            args.key_file, 
            args.interfaces, 
            args.filters, 
            producer, 
            args.topic
        )
    except KeyboardInterrupt:
        print("Capture interrupted by user")
    finally:
        if producer:
            producer.flush()
            producer.close()
            print("Kafka producer closed")

if __name__ == "__main__":
    main()
