#!/usr/bin/env python3
# kafka_command_listener.py
import os
import json
import time
import subprocess
import signal
import sys
import logging
from kafka import KafkaConsumer
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('kafka_command_listener')

# Load environment variables
load_dotenv()

class CaptureCommandListener:
    """
    Listens for capture commands on a Kafka topic and starts/stops the packet producer accordingly.
    """
    def __init__(self):
        self.bootstrap_servers = os.environ.get('KAFKA_BOOTSTRAP_SERVERS', 'kafka:9092')
        self.commands_topic = os.environ.get('KAFKA_COMMANDS_TOPIC', 'capture-commands')
        self.consumer = self._create_kafka_consumer()
        self.current_process = None
        self.running = True

        # Set up signal handlers
        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)

    def _create_kafka_consumer(self):
        """Create and return a Kafka consumer for the commands topic."""
        max_retries = 30
        retry_interval = 5  # seconds

        for attempt in range(1, max_retries + 1):
            try:
                logger.info(f"Attempt {attempt}/{max_retries} to connect to Kafka at {self.bootstrap_servers}")
                consumer = KafkaConsumer(
                    self.commands_topic,
                    bootstrap_servers=self.bootstrap_servers,
                    value_deserializer=lambda v: json.loads(v.decode('utf-8')),
                    auto_offset_reset='latest',
                    group_id='capture-service-group'
                )
                logger.info(f"Successfully connected to Kafka and created consumer for topic {self.commands_topic}")
                return consumer
            except Exception as e:
                logger.warning(f"Attempt {attempt}/{max_retries} failed: {e}")
                if attempt < max_retries:
                    logger.info(f"Waiting {retry_interval} seconds before next attempt...")
                    time.sleep(retry_interval)
                else:
                    logger.error(f"Failed to create Kafka consumer after {max_retries} attempts: {e}")
                    return None

    def _handle_signal(self, signum, frame):
        """Handle termination signals to clean up resources."""
        logger.info(f"Received signal {signum}, shutting down")
        self.running = False
        self._stop_current_capture()
        if self.consumer:
            self.consumer.close()
        sys.exit(0)

    def _start_capture(self, command):
        """Start a new capture process based on the command."""
        if self.current_process:
            logger.warning("Capture already running, stopping it first")
            self._stop_current_capture()

        config = command.get('config', {})
        hostname = config.get('hostname')
        username = config.get('username', 'ubuntu')
        key_file = config.get('key_file')
        interfaces = config.get('interfaces', 'any')
        filters = config.get('filters', '')

        if not hostname or not key_file:
            logger.error("Missing required parameters: hostname and key_file")
            return False

        # Ensure key_file is an absolute path
        if not key_file.startswith('/'):
            key_file = f"/app/ssh_keys/{key_file}"

        # Build command for kafka_packet_producer.py
        cmd = [
            "python", "/app/kafka_packet_producer.py",
            "--bootstrap-servers", self.bootstrap_servers,
            "--topic", os.environ.get('KAFKA_TOPIC', 'raw-packets'),
            "--hostname", hostname,
            "--username", username,
            "--key-file", key_file,
            "--interfaces", interfaces
        ]

        if filters:
            cmd.extend(["--filters", filters])

        try:
            logger.info(f"Starting capture with command: {' '.join(cmd)}")
            self.current_process = subprocess.Popen(cmd)
            logger.info(f"Started capture process with PID {self.current_process.pid}")
            return True
        except Exception as e:
            logger.error(f"Error starting capture: {e}")
            return False

    def _stop_current_capture(self):
        """Stop the current capture process if it's running."""
        if self.current_process:
            try:
                logger.info(f"Stopping capture process with PID {self.current_process.pid}")
                self.current_process.terminate()
                # Give it some time to terminate gracefully
                time.sleep(2)
                # Force kill if still running
                if self.current_process.poll() is None:
                    self.current_process.kill()
                    logger.info("Force killed capture process")
                self.current_process = None
                return True
            except Exception as e:
                logger.error(f"Error stopping capture: {e}")
                return False
        return True

    def run(self):
        """Main loop to listen for commands and process them."""
        if not self.consumer:
            logger.error("No Kafka consumer available, exiting")
            return

        logger.info(f"Starting to listen for commands on {self.commands_topic}")

        try:
            for message in self.consumer:
                if not self.running:
                    break

                try:
                    command = message.value
                    user_id = command.get('user_id', 'unknown')
                    action = command.get('action', '').upper()

                    logger.info(f"Received {action} command from user {user_id}")

                    if action == 'START':
                        success = self._start_capture(command)
                        logger.info(f"START command {'succeeded' if success else 'failed'}")
                    elif action == 'STOP':
                        success = self._stop_current_capture()
                        logger.info(f"STOP command {'succeeded' if success else 'failed'}")
                    else:
                        logger.warning(f"Unknown command action: {action}")

                except Exception as e:
                    logger.error(f"Error processing command: {e}")

        except Exception as e:
            logger.error(f"Error in command listener: {e}")
        finally:
            if self.consumer:
                self.consumer.close()
                logger.info("Kafka consumer closed")
            self._stop_current_capture()

def main():
    """Main entry point."""
    listener = CaptureCommandListener()
    listener.run()

if __name__ == "__main__":
    main()
