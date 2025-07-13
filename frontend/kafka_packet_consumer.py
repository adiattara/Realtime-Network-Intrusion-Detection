#!/usr/bin/env python3
# kafka_packet_consumer.py
import os
import json
import time
import argparse
import threading
import statistics
from datetime import datetime
from kafka import KafkaConsumer
from kafka import KafkaProducer
from dotenv import load_dotenv
import requests
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('kafka_packet_consumer')

# Load environment variables
load_dotenv()

# API URL for ML predictions
API_URL = os.environ.get('API_URL', "https://realtime-network-intrusion-detection-8itu.onrender.com/predict")

class FlowAggregator:
    def __init__(self, flow_timeout=60, cleanup_interval=30, alert_callback=None):
        self._bidirectional_sessions = {}
        self.flows = {}
        self.completed_flows = []
        self.flow_timeout = flow_timeout
        self.cleanup_interval = cleanup_interval
        self.lock = threading.Lock()
        self.last_cleanup = time.time()

        self.stats = {
            'total_packets_processed': 0,
            'active_flows': 0,
            'completed_flows': 0,
            'flows_per_minute': 0
        }

        self.alert_callback = alert_callback

    def create_flow_key(self, packet):
        src_ip = packet.get('src_ip', 'unknown')
        dst_ip = packet.get('dst_ip', 'unknown')
        sport = packet.get('sport', 0)
        dport = packet.get('dport', 0)
        protocol = packet.get('protocol', 'unknown')

        if src_ip < dst_ip or (src_ip == dst_ip and sport < dport):
            return f"{src_ip}:{sport}-{dst_ip}:{dport}-{protocol}"
        else:
            return f"{dst_ip}:{dport}-{src_ip}:{sport}-{protocol}"

    def determine_direction(self, packet, flow_key):
        dport = packet.get('dport', 0)
        sport = packet.get('sport', 0)
        server_ports = {21, 22, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 5432, 3306}

        if dport in server_ports:
            return 'forward'
        elif sport in server_ports:
            return 'backward'
        else:
            return 'forward' if sport > dport else 'backward'

    def extract_flags(self, packet):
        flags_str = packet.get('flags_str', '')
        return {
            'psh_count': 1 if 'P' in flags_str else 0,
            'urg_count': 1 if 'U' in flags_str else 0,
            'syn_count': 1 if 'S' in flags_str else 0,
            'fin_count': 1 if 'F' in flags_str else 0,
            'rst_count': 1 if 'R' in flags_str else 0,
            'ack_count': 1 if '.' in flags_str else 0
        }

    def process_packet(self, packet):
        try:
            with self.lock:
                self.stats['total_packets_processed'] += 1
                flow_key = self.create_flow_key(packet)

                if flow_key not in self.flows:
                    self.flows[flow_key] = self._create_new_flow(packet, flow_key)
                    self.stats['active_flows'] += 1
                else:
                    self._update_flow(self.flows[flow_key], packet)

                flow_copy = self.flows[flow_key].copy()
                features = extract_cic_features(flow_copy)
                flow_copy['cic_features'] = features
                flow_copy['feature_vector'] = features

                return flow_copy
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
            return None

    def _create_new_flow(self, packet, flow_key):
        current_time = time.time()
        packet_length = packet.get('length', 0)
        direction = self.determine_direction(packet, flow_key)

        # Convert timestamp to datetime if it's a float
        if isinstance(packet.get('timestamp'), float):
            timestamp = datetime.fromtimestamp(packet.get('timestamp'))
        else:
            timestamp = packet.get('timestamp', datetime.now())

        return {
            'flow_key': flow_key,
            'start_ts': timestamp.isoformat() if isinstance(timestamp, datetime) else timestamp,
            'end_ts': timestamp.isoformat() if isinstance(timestamp, datetime) else timestamp,
            'first_packet_ts': current_time,
            'last_packet_ts': current_time,

            'src_ip': packet.get('src_ip', 'unknown'),
            'dst_ip': packet.get('dst_ip', 'unknown'),
            'sport': packet.get('sport', 0),
            'dport': packet.get('dport', 0),
            'protocol': packet.get('protocol', 'unknown'),

            'total_bytes': packet_length,
            'pkt_count': 1,
            'fwd_bytes': packet_length if direction == 'forward' else 0,
            'bwd_bytes': packet_length if direction == 'backward' else 0,
            'fwd_pkts': 1 if direction == 'forward' else 0,
            'bwd_pkts': 1 if direction == 'backward' else 0,

            'fwd_packet_lengths': [packet_length] if direction == 'forward' else [],
            'bwd_packet_lengths': [packet_length] if direction == 'backward' else [],

            'duration_ms': 0,
            'status': 'active',
            'interface': packet.get('interface', 'unknown'),
            'last_activity': current_time,

            **self.extract_flags(packet)
        }

    def _update_flow(self, flow, packet):
        current_time = time.time()
        packet_length = packet.get('length', 0)
        direction = self.determine_direction(packet, flow['flow_key'])

        # Update packet counts and bytes
        flow['pkt_count'] += 1
        flow['total_bytes'] += packet_length

        if direction == 'forward':
            flow['fwd_pkts'] += 1
            flow['fwd_bytes'] += packet_length
            flow['fwd_packet_lengths'].append(packet_length)
        else:
            flow['bwd_pkts'] += 1
            flow['bwd_bytes'] += packet_length
            flow['bwd_packet_lengths'].append(packet_length)

        # Update flags
        flags = self.extract_flags(packet)
        for flag, count in flags.items():
            flow[flag] = flow.get(flag, 0) + count

        # Update timestamps and duration
        flow['last_activity'] = current_time
        flow['last_packet_ts'] = current_time
        flow['duration_ms'] = (flow['last_packet_ts'] - flow['first_packet_ts']) * 1000

        # Convert timestamp to datetime if it's a float
        if isinstance(packet.get('timestamp'), float):
            timestamp = datetime.fromtimestamp(packet.get('timestamp'))
        else:
            timestamp = packet.get('timestamp', datetime.now())

        # Update end timestamp
        flow['end_ts'] = timestamp.isoformat() if isinstance(timestamp, datetime) else timestamp

    def get_active_flows(self, limit=100):
        with self.lock:
            self.check_timeouts()
            active_flows = [flow for flow in self.flows.values() if flow.get('status') == 'active']
            return sorted(active_flows, key=lambda x: x.get('last_activity', 0), reverse=True)[:limit]

    def get_terminated_flows(self, limit=100):
        with self.lock:
            self.check_timeouts()
            terminated_flows = [flow for flow in self.flows.values() if flow.get('status') == 'terminated']
            return sorted(terminated_flows, key=lambda x: x.get('last_activity', 0), reverse=True)[:limit]

    def get_statistics(self):
        with self.lock:
            self.check_timeouts()
            now = time.time()
            active_count = len([flow for flow in self.flows.values() if flow.get('status') == 'active'])
            terminated_count = len([flow for flow in self.flows.values() if flow.get('status') == 'terminated'])

            self.stats['active_flows'] = active_count
            self.stats['completed_flows'] = terminated_count

            return self.stats

    def clear_all_flows(self):
        with self.lock:
            self.flows = {}
            self.completed_flows = []
            self.stats = {
                'total_packets_processed': 0,
                'active_flows': 0,
                'completed_flows': 0,
                'flows_per_minute': 0
            }
            logger.info("All flows cleared")

    def check_timeouts(self):
        now = time.time()
        with self.lock:
            for flow in self.flows.values():
                if flow.get('status') == 'active' and (now - flow.get('last_activity', now)) > self.flow_timeout:
                    flow['status'] = 'terminated'
                    logger.debug(f"Flow terminated by inactivity timeout: {flow['flow_key']}")


def extract_cic_features(flow):
    try:
        fwd_lengths = flow.get('fwd_packet_lengths', [])
        bwd_lengths = flow.get('bwd_packet_lengths', [])
        all_lengths = fwd_lengths + bwd_lengths
        duration_sec = max(flow.get('duration_ms', 0) / 1000.0, 0.001)

        dest_port = flow.get('dport', 0)
        bwd_packet_length_min = min(bwd_lengths) if bwd_lengths else 0
        bwd_packet_length_mean = statistics.mean(bwd_lengths) if bwd_lengths else 0
        bwd_packets_per_sec = flow.get('bwd_pkts', 0) / duration_sec
        min_packet_length = min(all_lengths) if all_lengths else 0
        psh_flag_count = flow.get('psh_count', 0)
        urg_flag_count = flow.get('urg_count', 0)
        avg_fwd_segment_size = statistics.mean(fwd_lengths) if fwd_lengths else 0
        avg_bwd_segment_size = statistics.mean(bwd_lengths) if bwd_lengths else 0
        min_seg_size_forward = min(fwd_lengths) if fwd_lengths else 0

        return [
            dest_port, bwd_packet_length_min, bwd_packet_length_mean,
            bwd_packets_per_sec, min_packet_length, psh_flag_count,
            urg_flag_count, avg_fwd_segment_size, avg_bwd_segment_size,
            min_seg_size_forward
        ]
    except Exception as e:
        logger.error(f"Error extracting features: {e}")
        return [0] * 10


def predict_flow(flow_features):
    try:
        response = requests.post(API_URL, json=flow_features, timeout=1)
        if response.status_code == 200:
            return response.json().get("label", "N/A")
        else:
            return "Erreur API"
    except Exception as e:
        return f"Erreur: {e}"


def create_kafka_consumer(bootstrap_servers, topic):
    """Create and return a Kafka consumer instance."""
    max_retries = 30
    retry_interval = 5  # seconds

    for attempt in range(1, max_retries + 1):
        try:
            logger.info(f"Attempt {attempt}/{max_retries} to connect to Kafka at {bootstrap_servers}")
            consumer = KafkaConsumer(
                topic,
                bootstrap_servers=bootstrap_servers,
                value_deserializer=lambda v: json.loads(v.decode('utf-8')),
                auto_offset_reset='latest',
                group_id='flow-aggregator-group'
            )
            logger.info(f"Successfully connected to Kafka and created consumer for topic {topic}")
            return consumer
        except Exception as e:
            logger.warning(f"Attempt {attempt}/{max_retries} failed: {e}")
            if attempt < max_retries:
                logger.info(f"Waiting {retry_interval} seconds before next attempt...")
                time.sleep(retry_interval)
            else:
                logger.error(f"Failed to create Kafka consumer after {max_retries} attempts: {e}")
                return None


def create_kafka_producer(bootstrap_servers):
    """Create and return a Kafka producer instance."""
    max_retries = 30
    retry_interval = 5  # seconds

    for attempt in range(1, max_retries + 1):
        try:
            logger.info(f"Attempt {attempt}/{max_retries} to connect to Kafka at {bootstrap_servers}")
            producer = KafkaProducer(
                bootstrap_servers=bootstrap_servers,
                value_serializer=lambda v: json.dumps(v).encode('utf-8'),
                key_serializer=lambda k: k.encode('utf-8') if k else None
            )
            logger.info(f"Successfully connected to Kafka and created producer")
            return producer
        except Exception as e:
            logger.warning(f"Attempt {attempt}/{max_retries} failed: {e}")
            if attempt < max_retries:
                logger.info(f"Waiting {retry_interval} seconds before next attempt...")
                time.sleep(retry_interval)
            else:
                logger.error(f"Failed to create Kafka producer after {max_retries} attempts: {e}")
                return None


def consume_and_process(consumer, producer, output_topic):
    """Consume packets from Kafka, process them with FlowAggregator, and send flows to output topic."""
    flow_aggregator = FlowAggregator(flow_timeout=30, cleanup_interval=10)
    packet_count = 0
    flow_count = 0
    is_ml_service = "predicted-flows" in output_topic

    logger.info(f"Starting to consume packets from Kafka to {output_topic}")

    for message in consumer:
        try:
            # For aggregator-service, message.value is a packet
            # For ml-service, message.value is a flow
            data = message.value

            if is_ml_service:
                # ML service: consume flows and add predictions
                flow = data.copy()  # Make a copy to avoid modifying the original

                # Extract features for ML prediction
                if 'total_bytes' in flow and 'pkt_count' in flow:
                    # Prepare ML input features
                    ml_features = {
                        "total_bytes": flow.get('total_bytes', 0),
                        "pkt_count": flow.get('pkt_count', 0),
                        "psh_count": flow.get('psh_count', 0),
                        "fwd_bytes": flow.get('fwd_bytes', 0),
                        "bwd_bytes": flow.get('bwd_bytes', 0),
                        "fwd_pkts": flow.get('fwd_pkts', 0),
                        "bwd_pkts": flow.get('bwd_pkts', 0),
                        "dport": flow.get('dport', 0),
                        "duration_ms": flow.get('duration_ms', 0),
                        "flow_pkts_per_s": flow.get('pkt_count', 0) / max(flow.get('duration_ms', 1) / 1000, 0.001),
                        "fwd_bwd_ratio": flow.get('fwd_bytes', 0) / max(flow.get('bwd_bytes', 1), 1)
                    }

                    # Add prediction
                    prediction = predict_flow(ml_features)
                    flow['prediction'] = prediction
                else:
                    logger.warning(f"Flow missing required fields for ML prediction: {flow}")
                    flow['prediction'] = "Normal"  # Default to Normal if we can't predict

                # Ensure only the specified fields are included in the predicted flow
                # Keep only the fields that should be in the predicted-flows topic
                predicted_flow = {
                    'flow_key': flow.get('flow_key', ''),
                    'start_ts': flow.get('start_ts', ''),
                    'end_ts': flow.get('end_ts', ''),
                    'first_packet_ts': flow.get('first_packet_ts', 0),
                    'last_packet_ts': flow.get('last_packet_ts', 0),
                    'src_ip': flow.get('src_ip', ''),
                    'dst_ip': flow.get('dst_ip', ''),
                    'sport': flow.get('sport', 0),
                    'dport': flow.get('dport', 0),
                    'protocol': flow.get('protocol', ''),
                    'total_bytes': flow.get('total_bytes', 0),
                    'pkt_count': flow.get('pkt_count', 0),
                    'fwd_bytes': flow.get('fwd_bytes', 0),
                    'bwd_bytes': flow.get('bwd_bytes', 0),
                    'fwd_pkts': flow.get('fwd_pkts', 0),
                    'bwd_pkts': flow.get('bwd_pkts', 0),
                    'duration_ms': flow.get('duration_ms', 0),
                    'status': flow.get('status', 'active'),
                    'interface': flow.get('interface', ''),
                    'psh_count': flow.get('psh_count', 0),
                    'prediction': flow.get('prediction', 'Normal')
                }

                # Send the flow with prediction to the output topic
                key = predicted_flow.get('flow_key', str(time.time()))
                producer.send(output_topic, key=key, value=predicted_flow)
                flow_count += 1
            else:
                # Aggregator service: process packets into flows
                packet_count += 1

                # Process the packet with FlowAggregator
                flow = flow_aggregator.process_packet(data)

                if flow:
                    # Ensure only the specified fields are included in the aggregated flow
                    # Keep only the fields that should be in the aggregated-flows topic
                    aggregated_flow = {
                        'flow_key': flow.get('flow_key', ''),
                        'start_ts': flow.get('start_ts', ''),
                        'end_ts': flow.get('end_ts', ''),
                        'first_packet_ts': flow.get('first_packet_ts', 0),
                        'last_packet_ts': flow.get('last_packet_ts', 0),
                        'src_ip': flow.get('src_ip', ''),
                        'dst_ip': flow.get('dst_ip', ''),
                        'sport': flow.get('sport', 0),
                        'dport': flow.get('dport', 0),
                        'protocol': flow.get('protocol', ''),
                        'total_bytes': flow.get('total_bytes', 0),
                        'pkt_count': flow.get('pkt_count', 0),
                        'fwd_bytes': flow.get('fwd_bytes', 0),
                        'bwd_bytes': flow.get('bwd_bytes', 0),
                        'fwd_pkts': flow.get('fwd_pkts', 0),
                        'bwd_pkts': flow.get('bwd_pkts', 0),
                        'duration_ms': flow.get('duration_ms', 0),
                        'status': flow.get('status', 'active'),
                        'interface': flow.get('interface', ''),
                        'last_activity': flow.get('last_activity', 0),
                        'psh_count': flow.get('psh_count', 0)
                    }

                    # Send the flow to the output topic
                    key = aggregated_flow['flow_key']
                    producer.send(output_topic, key=key, value=aggregated_flow)
                    flow_count += 1

                    # Check for timeouts and cleanup
                    flow_aggregator.check_timeouts()

            if flow_count % 10 == 0:
                logger.info(f"Processed {packet_count} packets, produced {flow_count} flows")

        except Exception as e:
            logger.error(f"Error processing message: {e}")

    logger.info("Consumer stopped")


def main():
    parser = argparse.ArgumentParser(description='Consume network packets from Kafka and aggregate into flows')
    parser.add_argument('--bootstrap-servers', default=os.environ.get('KAFKA_BOOTSTRAP_SERVERS', 'localhost:9092'),
                        help='Kafka bootstrap servers')
    parser.add_argument('--input-topic', default=os.environ.get('KAFKA_TOPIC', 'raw-packets'),
                        help='Kafka topic to consume packets from')
    parser.add_argument('--output-topic', default=os.environ.get('KAFKA_OUTPUT_TOPIC', 'aggregated-flows'),
                        help='Kafka topic to send flows to')

    args = parser.parse_args()

    consumer = create_kafka_consumer(args.bootstrap_servers, args.input_topic)
    if not consumer:
        logger.error("Failed to create Kafka consumer. Exiting.")
        return

    producer = create_kafka_producer(args.bootstrap_servers)
    if not producer:
        logger.error("Failed to create Kafka producer. Exiting.")
        consumer.close()
        return

    try:
        logger.info(f"Starting flow aggregation from {args.input_topic} to {args.output_topic}")
        consume_and_process(consumer, producer, args.output_topic)
    except KeyboardInterrupt:
        logger.info("Processing interrupted by user")
    finally:
        if consumer:
            consumer.close()
            logger.info("Kafka consumer closed")
        if producer:
            producer.flush()
            producer.close()
            logger.info("Kafka producer closed")


if __name__ == "__main__":
    main()
