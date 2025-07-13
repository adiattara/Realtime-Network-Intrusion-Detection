#!/usr/bin/env python3
# kafka_user_capture_manager.py
import os
import json
import time
import queue
import threading
import subprocess
from kafka import KafkaProducer, KafkaConsumer
from dotenv import load_dotenv
import logging
from alerting import process_new_flow_for_alerting

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('kafka_user_capture_manager')

# Load environment variables
load_dotenv()

class KafkaUserCaptureManager:
    """
    A Kafka-based version of UserCaptureManager that uses Kafka for communication
    between the UI, capture service, and flow aggregator.
    """
    def __init__(self, user_id, user_email):
        self.user_id = user_id
        self.user_email = user_email
        self.flow_queue = queue.Queue()
        self.aggregated_flows_queue = queue.Queue()
        self.raw_packets_queue = queue.Queue()

        # Kafka configuration
        self.bootstrap_servers = os.environ.get('KAFKA_BOOTSTRAP_SERVERS', 'kafka:9092')
        self.raw_packets_topic = os.environ.get('KAFKA_TOPIC', 'raw-packets')
        self.aggregated_flows_topic = os.environ.get('KAFKA_OUTPUT_TOPIC', 'aggregated-flows')
        self.capture_commands_topic = os.environ.get('KAFKA_COMMANDS_TOPIC', 'capture-commands')
        self.predicted_flows_topic = os.environ.get('KAFKA_PREDICTED_TOPIC', 'predicted-flows')

        # Kafka producers and consumers
        self.command_producer = self._create_kafka_producer()
        self.flow_consumer = None
        self.flow_consumer_thread = None
        self.aggregated_flows_consumer = None
        self.aggregated_flows_consumer_thread = None
        self.raw_packets_consumer = None
        self.raw_packets_consumer_thread = None

        # Data storage for UI
        self.top_dest_ports = []
        self.top_source_ports = []
        self.malicious_normal_counts = {"Mal": 0, "Benign": 0}
        self.current_throughput = 0
        self.last_throughput_update = time.time()
        self.packet_bytes_received = 0

        # Counters for total packets and flows
        self.total_raw_packets = 0
        self.total_aggregated_flows = 0

        # Historical data for graphs
        self.throughput_history = []  # List of (timestamp, throughput) tuples
        self.response_times = []  # List of (timestamp, response_time) tuples
        self.max_history_points = 60  # Keep 60 data points for history (1 hour if 1 point per minute)

        # Capture state
        self.connection_active = False
        self.ssh_config = {
            'hostname': '',
            'username': 'ubuntu',
            'key_file': None,
            'interfaces': [],
            'filters': ''
        }

        # Start consumer threads
        self._start_flow_consumer()
        self._start_aggregated_flows_consumer()
        self._start_raw_packets_consumer()

    def _create_kafka_producer(self):
        """Create and return a Kafka producer instance."""
        max_retries = 30
        retry_interval = 5  # seconds

        for attempt in range(1, max_retries + 1):
            try:
                logger.info(f"Attempt {attempt}/{max_retries} to connect to Kafka at {self.bootstrap_servers}")
                producer = KafkaProducer(
                    bootstrap_servers=self.bootstrap_servers,
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

    def _create_kafka_consumer(self, topic, group_id):
        """Create and return a Kafka consumer instance."""
        max_retries = 30
        retry_interval = 5  # seconds

        for attempt in range(1, max_retries + 1):
            try:
                logger.info(f"Attempt {attempt}/{max_retries} to connect to Kafka at {self.bootstrap_servers}")
                consumer = KafkaConsumer(
                    topic,
                    bootstrap_servers=self.bootstrap_servers,
                    value_deserializer=lambda v: json.loads(v.decode('utf-8')),
                    auto_offset_reset='latest',
                    group_id=group_id
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

    def _start_flow_consumer(self):
        """Start a thread to consume flows from Kafka and put them in the flow queue."""
        if self.flow_consumer_thread and self.flow_consumer_thread.is_alive():
            return

        self.flow_consumer = self._create_kafka_consumer(
            self.predicted_flows_topic, 
            f'ui-flow-consumer-{self.user_id}'
        )

        if not self.flow_consumer:
            logger.error("Failed to create Kafka flow consumer")
            return

        self.flow_consumer_thread = threading.Thread(
            target=self._consume_flows,
            daemon=True
        )
        self.flow_consumer_thread.start()
        logger.info(f"Started flow consumer thread for user {self.user_id}")

    def _start_aggregated_flows_consumer(self):
        """Start a thread to consume aggregated flows from Kafka."""
        if self.aggregated_flows_consumer_thread and self.aggregated_flows_consumer_thread.is_alive():
            return

        self.aggregated_flows_consumer = self._create_kafka_consumer(
            self.aggregated_flows_topic, 
            f'ui-aggregated-flows-consumer-{self.user_id}'
        )

        if not self.aggregated_flows_consumer:
            logger.error("Failed to create Kafka aggregated flows consumer")
            return

        self.aggregated_flows_consumer_thread = threading.Thread(
            target=self._consume_aggregated_flows,
            daemon=True
        )
        self.aggregated_flows_consumer_thread.start()
        logger.info(f"Started aggregated flows consumer thread for user {self.user_id}")

    def _start_raw_packets_consumer(self):
        """Start a thread to consume raw packets from Kafka."""
        if self.raw_packets_consumer_thread and self.raw_packets_consumer_thread.is_alive():
            return

        self.raw_packets_consumer = self._create_kafka_consumer(
            self.raw_packets_topic, 
            f'ui-raw-packets-consumer-{self.user_id}'
        )

        if not self.raw_packets_consumer:
            logger.error("Failed to create Kafka raw packets consumer")
            return

        self.raw_packets_consumer_thread = threading.Thread(
            target=self._consume_raw_packets,
            daemon=True
        )
        self.raw_packets_consumer_thread.start()
        logger.info(f"Started raw packets consumer thread for user {self.user_id}")

    def _consume_flows(self):
        """Consume flows from Kafka and put them in the flow queue."""
        logger.info(f"Starting to consume flows from {self.predicted_flows_topic}")

        try:
            for message in self.flow_consumer:
                try:
                    flow = message.value

                    # Process flow for alerting if it's predicted as malicious
                    if flow.get('prediction') == 'Mal':
                        self._alert_user(flow)
                        self.malicious_normal_counts["Mal"] += 1
                    elif flow.get('prediction') == 'Normal':
                        self.malicious_normal_counts["Benign"] += 1

                    # Put the flow in the queue for UI consumption
                    self.flow_queue.put(flow)

                except Exception as e:
                    logger.error(f"Error processing flow message: {e}")

                # Check if the connection is still active
                if not self.connection_active:
                    break

        except Exception as e:
            logger.error(f"Error in flow consumer: {e}")
            self.flow_queue.put({'error': str(e)})
        finally:
            if self.flow_consumer:
                self.flow_consumer.close()
                logger.info("Flow consumer closed")

    def _consume_aggregated_flows(self):
        """Consume aggregated flows from Kafka and update top ports."""
        logger.info(f"Starting to consume aggregated flows from {self.aggregated_flows_topic}")

        try:
            from collections import Counter
            dest_ports_bytes = Counter()
            source_ports_bytes = Counter()
            last_response_time = None

            for message in self.aggregated_flows_consumer:
                try:
                    flow = message.value

                    # Increment total aggregated flows counter
                    self.total_aggregated_flows += 1

                    # Update top destination ports by bytes
                    if 'dport' in flow and 'total_bytes' in flow:
                        dest_ports_bytes[flow['dport']] += flow['total_bytes']
                        # Keep only top 10
                        self.top_dest_ports = dest_ports_bytes.most_common(10)

                    # Update top source ports by bytes
                    if 'sport' in flow and 'total_bytes' in flow:
                        source_ports_bytes[flow['sport']] += flow['total_bytes']
                        # Keep only top 10
                        self.top_source_ports = source_ports_bytes.most_common(10)

                    # Calculate response time if available
                    if 'duration_ms' in flow and flow['duration_ms'] > 0:
                        current_time = time.time()
                        response_time = flow['duration_ms']  # in milliseconds

                        # Add to response times history
                        self.response_times.append((current_time, response_time))

                        # Keep all response times for complete history
                        # if len(self.response_times) > self.max_history_points:
                        #     self.response_times.pop(0)

                    # Put the flow in the queue for UI consumption
                    self.aggregated_flows_queue.put(flow)

                except Exception as e:
                    logger.error(f"Error processing aggregated flow message: {e}")

                # Check if the connection is still active
                if not self.connection_active:
                    break

        except Exception as e:
            logger.error(f"Error in aggregated flows consumer: {e}")
            self.aggregated_flows_queue.put({'error': str(e)})
        finally:
            if self.aggregated_flows_consumer:
                self.aggregated_flows_consumer.close()
                logger.info("Aggregated flows consumer closed")

    def _consume_raw_packets(self):
        """Consume raw packets from Kafka and calculate throughput."""
        logger.info(f"Starting to consume raw packets from {self.raw_packets_topic}")

        try:
            for message in self.raw_packets_consumer:
                try:
                    packet = message.value

                    # Increment total raw packets counter
                    self.total_raw_packets += 1

                    # Update throughput calculation
                    if 'length' in packet:
                        self.packet_bytes_received += packet['length']

                        # Calculate throughput every second
                        current_time = time.time()
                        time_diff = current_time - self.last_throughput_update

                        if time_diff >= 5.0:  # Update throughput every 5 seconds
                            # Calculate throughput in Mbps
                            throughput = (self.packet_bytes_received * 8) / (time_diff * 1_000_000)
                            self.current_throughput = throughput

                            # Add to throughput history
                            self.throughput_history.append((current_time, throughput))

                            # Keep all throughput history for complete view
                            # if len(self.throughput_history) > self.max_history_points:
                            #     self.throughput_history.pop(0)

                            self.last_throughput_update = current_time
                            self.packet_bytes_received = 0

                    # Put the packet in the queue for UI consumption
                    self.raw_packets_queue.put(packet)

                except Exception as e:
                    logger.error(f"Error processing raw packet message: {e}")

                # Check if the connection is still active
                if not self.connection_active:
                    break

        except Exception as e:
            logger.error(f"Error in raw packets consumer: {e}")
            self.raw_packets_queue.put({'error': str(e)})
        finally:
            if self.raw_packets_consumer:
                self.raw_packets_consumer.close()
                logger.info("Raw packets consumer closed")

    def _alert_user(self, flow):
        """
        Called in background when a malicious flow is terminated.
        process_new_flow_for_alerting handles thresholds, cooldowns, SMTP sending.
        """
        process_new_flow_for_alerting(flow, self.user_email)

    def start_capture(self, hostname, username, key_file, interfaces, filters=''):
        """
        Start packet capture by sending a command to the capture-commands Kafka topic.
        """
        if self.connection_active:
            logger.warning("Capture already active, ignoring start request")
            return False

        # Store SSH configuration
        self.ssh_config = {
            'hostname': hostname,
            'username': username,
            'key_file': key_file,
            'interfaces': interfaces,
            'filters': filters
        }

        # Create command message
        command = {
            'action': 'START',
            'user_id': self.user_id,
            'timestamp': time.time(),
            'config': self.ssh_config
        }

        # Send command to Kafka
        try:
            self.command_producer.send(
                self.capture_commands_topic,
                key=str(self.user_id),
                value=command
            )
            self.command_producer.flush()
            logger.info(f"Sent START command to {self.capture_commands_topic} for user {self.user_id}")

            # Update state
            self.connection_active = True
            return True

        except Exception as e:
            logger.error(f"Error sending START command to Kafka: {e}")
            self.flow_queue.put({'error': str(e)})
            return False

    def stop_capture(self):
        """
        Stop packet capture by sending a command to the capture-commands Kafka topic.
        """
        if not self.connection_active:
            logger.warning("No active capture to stop")
            return False

        # Create command message
        command = {
            'action': 'STOP',
            'user_id': self.user_id,
            'timestamp': time.time()
        }

        # Send command to Kafka
        try:
            self.command_producer.send(
                self.capture_commands_topic,
                key=str(self.user_id),
                value=command
            )
            self.command_producer.flush()
            logger.info(f"Sent STOP command to {self.capture_commands_topic} for user {self.user_id}")

            # Update state
            self.connection_active = False
            return True

        except Exception as e:
            logger.error(f"Error sending STOP command to Kafka: {e}")
            return False

    def get_active_flows(self, limit=100):
        """
        Get active flows from the flow queue.
        This method is called by the UI to get flows for display.
        """
        flows = []
        try:
            # Get all available flows from the queue
            while len(flows) < limit:
                try:
                    flow = self.flow_queue.get_nowait()
                    if 'error' in flow:
                        logger.error(f"Error in flow: {flow['error']}")
                        continue
                    flows.append(flow)
                except queue.Empty:
                    break
        except Exception as e:
            logger.error(f"Error getting flows from queue: {e}")

        return flows

    def get_terminated_flows(self, limit=100):
        """
        Get terminated flows.
        In the Kafka version, we don't have a concept of "terminated flows" because
        we're just consuming flows from Kafka. We'll return an empty list.
        """
        return []

    def process_packet(self, packet_info):
        """
        Process a packet.
        In the Kafka version, we don't process packets directly because that's
        handled by the Kafka-based architecture. This method is a no-op.
        """
        return None

    def get_statistics(self):
        """
        Return statistics about the capture.
        In the Kafka version, we don't have direct access to the FlowAggregator stats,
        so we return basic information based on the flows we've received.
        """
        # Get flows from the queue without removing them
        flows = []
        try:
            # Get all available flows from the queue
            while not self.flow_queue.empty():
                try:
                    flow = self.flow_queue.get_nowait()
                    if 'error' not in flow:
                        flows.append(flow)
                    self.flow_queue.task_done()
                except queue.Empty:
                    break
        except Exception as e:
            logger.error(f"Error getting flows from queue: {e}")

        # Count active flows
        active_flows = sum(1 for flow in flows if flow.get('status') == 'active')
        completed_flows = sum(1 for flow in flows if flow.get('status') == 'completed')

        return {
            'connection_active': self.connection_active,
            'hostname': self.ssh_config.get('hostname', ''),
            'interfaces': self.ssh_config.get('interfaces', []),
            'active_flows': active_flows,
            'completed_flows': completed_flows,
            'total_packets_processed': self.total_raw_packets,  # Use the raw packets counter
            'total_aggregated_flows': self.total_aggregated_flows,  # Add the aggregated flows counter
            'current_throughput': self.current_throughput,
            'malicious_normal_counts': self.malicious_normal_counts,
            'top_dest_ports': self.top_dest_ports,
            'top_source_ports': self.top_source_ports,
            'throughput_history': self.throughput_history,
            'response_times': self.response_times,
            'average_throughput': self.get_average_throughput(),
            'average_response_time': self.get_average_response_time()
        }

    def get_top_destination_ports(self):
        """
        Return the top 10 destination ports.
        """
        return self.top_dest_ports

    def get_top_source_ports(self):
        """
        Return the top 10 source ports.
        """
        return self.top_source_ports

    def get_malicious_normal_counts(self):
        """
        Return the counts of malicious and normal packets.
        """
        return self.malicious_normal_counts

    def get_current_throughput(self):
        """
        Return the current throughput in Mbps.
        """
        return self.current_throughput

    def get_throughput_history(self):
        """
        Return the throughput history as a list of (timestamp, throughput) tuples.
        """
        return self.throughput_history

    def get_response_times(self):
        """
        Return the response times history as a list of (timestamp, response_time) tuples.
        """
        return self.response_times

    def get_average_throughput(self):
        """
        Calculate and return the average throughput over the history period.
        """
        if not self.throughput_history:
            return 0.0

        total_throughput = sum(t[1] for t in self.throughput_history)
        return total_throughput / len(self.throughput_history)

    def get_average_response_time(self):
        """
        Calculate and return the average response time over the history period.
        """
        if not self.response_times:
            return 0.0

        total_response_time = sum(t[1] for t in self.response_times)
        return total_response_time / len(self.response_times)

    def clear_all_flows(self):
        """
        Clear all flows from the queue.
        """
        try:
            while not self.flow_queue.empty():
                self.flow_queue.get_nowait()
            logger.info("Cleared all flows from queue")
            return True
        except Exception as e:
            logger.error(f"Error clearing flows: {e}")
            return False

    def close(self):
        """
        Clean up resources when the manager is no longer needed.
        """
        try:
            # Stop capture if active
            if self.connection_active:
                self.stop_capture()

            # Close Kafka producers and consumers
            if self.command_producer:
                self.command_producer.close()

            if self.flow_consumer:
                self.flow_consumer.close()

            if self.aggregated_flows_consumer:
                self.aggregated_flows_consumer.close()

            if self.raw_packets_consumer:
                self.raw_packets_consumer.close()

            logger.info(f"Closed KafkaUserCaptureManager for user {self.user_id}")
            return True
        except Exception as e:
            logger.error(f"Error closing KafkaUserCaptureManager: {e}")
            return False


# Command-line interface for testing
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Test the KafkaUserCaptureManager')
    parser.add_argument('--user-id', default='test-user', help='User ID')
    parser.add_argument('--email', default='test@example.com', help='User email')
    parser.add_argument('--action', choices=['start', 'stop', 'stats'], required=True, help='Action to perform')
    parser.add_argument('--hostname', help='SSH hostname (for start action)')
    parser.add_argument('--username', default='ubuntu', help='SSH username (for start action)')
    parser.add_argument('--key-file', help='SSH key file (for start action)')
    parser.add_argument('--interfaces', default='any', help='Network interfaces (for start action)')
    parser.add_argument('--filters', default='', help='tcpdump filters (for start action)')

    args = parser.parse_args()

    manager = KafkaUserCaptureManager(args.user_id, args.email)

    if args.action == 'start':
        if not args.hostname or not args.key_file:
            parser.error("--hostname and --key-file are required for start action")

        success = manager.start_capture(
            args.hostname,
            args.username,
            args.key_file,
            args.interfaces,
            args.filters
        )
        print(f"Start capture: {'Success' if success else 'Failed'}")

    elif args.action == 'stop':
        success = manager.stop_capture()
        print(f"Stop capture: {'Success' if success else 'Failed'}")

    elif args.action == 'stats':
        stats = manager.get_statistics()
        print(f"Statistics: {json.dumps(stats, indent=2)}")

    # Clean up
    manager.close()
