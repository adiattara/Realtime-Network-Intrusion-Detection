import dash
from dash import dcc, html, Input, Output, dash_table, callback_context, State, callback, no_update
import dash_bootstrap_components as dbc
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
import secrets
import threading
import time
from datetime import datetime, timedelta
import queue
import re
import base64
from collections import defaultdict
import paramiko
import hashlib
import uuid
import tempfile
import os
from dataclasses import dataclass
from typing import Dict, List, Optional
import json
import statistics
import requests
import sqlite3
import psycopg2
from psycopg2 import extras
from collections import Counter
import plotly.graph_objs as go
from alerting import process_new_flow_for_alerting
# from openai import OpenAI  # Commented out to improve performance
from dotenv import load_dotenv
import httpx
import logging

# Import the models and managers
from models_and_managers import User, UserSession

# Import the PostgreSQLUserManager (required)
from db_user_manager import PostgreSQLUserManager
HAS_POSTGRES_USER_MANAGER = True



load_dotenv()


API_URL = os.environ.get('API_URL', "http://model-server:8000/predict")
# Create a custom httpx client without proxy settings
http_client = httpx.Client()
# openai_client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'), http_client=http_client)  # Commented out to improve performance

def predict_flow(flow_features):
    try:
        response = requests.post(API_URL, json=flow_features, timeout=1)
        if response.status_code == 200:
            return response.json().get("label", "N/A")
        else:
            return "Erreur API"
    except Exception as e:
        return f"Erreur: {e}"


def resumer_texte(texte, modele="gpt-3.5-turbo"):
    """
    Résume un flow réseau malicieux à l’aide d’un LLM.
    Le texte d’entrée doit être un JSON avec les features réseau + prédiction.
    """
    try:
        # Code OpenAI commenté pour améliorer les performances
        # response = openai_client.chat.completions.create(
        #     model=modele,
        #     messages=[
        #         {
        #             "role": "system",
        #             "content": (
        #                 "Tu es un expert en cybersécurité chargé de résumer un flux réseau malicieux. "
        #                 "Chaque flux est au format JSON et contient des caractéristiques techniques (paquets, octets, durée, ratio, etc.) "
        #                 "et une prédiction ('Mal' ou 'Normal'). Ton objectif est de générer UNE SEULE formulation courte et claire, "
        #                 "compréhensible par un analyste SOC. Mets en avant les anomalies importantes (asymétrie, volume, durée, ratio). "
        #                 "Ta réponse ne doit PAS dépasser 3 phrases courtes."
        #             )
        #         },
        #         {
        #             "role": "user",
        #             "content": f"Voici un flow à résumer : {texte}"
        #         }
        #     ],
        #     temperature=0.5,
        #     max_tokens=200  # Ajuste selon ton usage
        # )
        # return response.choices[0].message.content.strip()

        # Remplacement par une fonction simplifiée
        import json
        try:
            data = json.loads(texte)
            prediction = data.get("prediction", "inconnu")
            src_ip = data.get("src_ip", "inconnu")
            dst_ip = data.get("dst_ip", "inconnu")

            # Si les IPs sont inconnues, on affiche uniquement la prédiction
            if src_ip == "inconnu" or dst_ip == "inconnu":
                return f"Classé comme {prediction}"
            else:
                return f"Flow {src_ip} → {dst_ip} classé comme {prediction}"
        except:
            return "Résumé simplifié du flow (OpenAI désactivé)"
    except Exception as e:
        return f"Erreur de résumé : {e}"

# =====================================
# FLOW AGGREGATOR INTÉGRÉ
# =====================================
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
            print(f"Erreur process_packet: {e}")
            return None

    def _create_new_flow(self, packet, flow_key):
        current_time = time.time()
        packet_length = packet.get('length', 0)
        direction = self.determine_direction(packet, flow_key)

        return {
            'flow_key': flow_key,
            'start_ts': packet.get('timestamp', datetime.now()).isoformat(),
            'end_ts': packet.get('timestamp', datetime.now()).isoformat(),
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
        flags = self.extract_flags(packet)

        flow['total_bytes'] += packet_length
        flow['pkt_count'] += 1
        flow['last_packet_ts'] = current_time
        flow['last_activity'] = current_time
        flow['duration_ms'] = (current_time - flow['first_packet_ts']) * 1000
        flow['end_ts'] = packet.get('timestamp', datetime.now()).isoformat()

        if direction == 'forward':
            flow['fwd_bytes'] += packet_length
            flow['fwd_pkts'] += 1
            flow['fwd_packet_lengths'].append(packet_length)
        else:
            flow['bwd_bytes'] += packet_length
            flow['bwd_pkts'] += 1
            flow['bwd_packet_lengths'].append(packet_length)

        for flag in ['psh_count', 'urg_count', 'syn_count', 'fin_count', 'rst_count', 'ack_count']:
            flow[flag] += flags[flag]

        if flags['fin_count'] > 0 or flags['rst_count'] > 0:
            flow['status'] = 'terminated'
            # C'est à ce moment-là qu'on fait la prédiction !
            if 'prediction' not in flow:  # Sécurité : on ne prédit qu'une fois
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
                prediction = predict_flow(ml_features)
                flow['prediction'] = str(prediction)

            # Sinon, pas de prédiction sur les flows actifs

                # 🚨 alerte en background, si défini
                if self.alert_callback:
                    # on lance dans un thread pour ne pas bloquer le traitement de paquets
                    threading.Thread(
                        target=self.alert_callback,
                        args=(flow,),
                        daemon=True
                    ).start()



    def get_active_flows(self, limit=100):
        with self.lock:
            flows = list(self.flows.values())
            flows.sort(key=lambda x: x['last_activity'], reverse=True)
            return flows[:limit]

    def get_terminated_flows(self, limit=100):
        #méthode pour passez les flows qui ne se sont pas fini depuis longtemps en terminated
        #self.check_timeouts()

        with self.lock:
            terminated_flows = [flow for flow in self.flows.values() if flow.get('status') == 'terminated']
            terminated_flows.sort(key=lambda x: x['last_activity'], reverse=True)
            return terminated_flows[:limit]

    def get_statistics(self):
        with self.lock:
            active_flows = 0
            completed_flows = 0

            # Count active and terminated flows
            for flow in self.flows.values():
                if flow.get('status') == 'terminated':
                    completed_flows += 1
                else:
                    active_flows += 1

            self.stats['active_flows'] = active_flows
            self.stats['completed_flows'] = completed_flows
            return self.stats.copy()

    def clear_all_flows(self):
        with self.lock:
            self.flows.clear()
            self.completed_flows.clear()
            self.stats = {
                'total_packets_processed': 0,
                'active_flows': 0,
                'completed_flows': 0,
                'flows_per_minute': 0
            }

    def check_timeouts(self):
        """
        Parcourt tous les flows actifs et les termine s'ils sont inactifs depuis plus de self.flow_timeout secondes.
        À appeler régulièrement ou avant de récupérer les flows terminés.
        """
        now = time.time()
        with self.lock:
            for flow in self.flows.values():
                if flow.get('status') == 'active' and (now - flow.get('last_activity', now)) > self.flow_timeout:
                    flow['status'] = 'terminated'
                    print(f"[DEBUG] Flow terminé par timeout d'inactivité : {flow['flow_key']}")


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
        print(f"Erreur extraction features: {e}")
        return [0] * 10


# =====================================
# CAPTURE RÉSEAU SSH INTÉGRÉE
# =====================================

class UserCaptureManager:
    def __init__(self, user_id, user_email):
        self.user_id = user_id
        self.user_email = user_email
        self.flow_aggregator = FlowAggregator(flow_timeout=5, cleanup_interval=10)
        self.flow_aggregator = FlowAggregator(
            flow_timeout=5,
            cleanup_interval=10,
            alert_callback=self._alert_user
        )
        self.packet_queue = queue.Queue()
        self.flow_queue = queue.Queue()

        self.connection_active = False
        self.ssh_client = None
        self.ssh_thread = None

        self.ssh_config = {
            'hostname': '',
            'username': 'ubuntu',
            'key_file': None,
            'interfaces': [],
            'filters': ''
        }

    def _alert_user(self, flow):
        """
        Appelé en background dès qu'un flow malveillant est terminé.
        process_new_flow_for_alerting gère seuils, cooldowns, envoi SMTP.
        """
        process_new_flow_for_alerting(flow, self.user_email)

def parse_tcpdump_line(line, current_ts=None):
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
                    "timestamp": datetime.fromtimestamp(float(current_ts)),
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
                    "timestamp": datetime.fromtimestamp(float(current_ts)),
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
        return None, None


def ssh_capture_thread(capture_manager, hostname, username, key_file, interface_str, filters):
    try:
        capture_manager.ssh_client = paramiko.SSHClient()
        capture_manager.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        capture_manager.ssh_client.connect(hostname=hostname, username=username, key_filename=key_file)

        if "," in interface_str or interface_str == "any":
            tcpdump_cmd = f"sudo tcpdump -i any -nn -l -tt -v {filters}"
        else:
            tcpdump_cmd = f"sudo tcpdump -i {interface_str} -nn -l -tt -v {filters}"

        stdin, stdout, stderr = capture_manager.ssh_client.exec_command(tcpdump_cmd, get_pty=True)
        capture_manager.connection_active = True

        current_ts = None
        for raw_line in stdout:
            if not capture_manager.connection_active:
                break

            line = raw_line.strip()
            packet_info, new_ts = parse_tcpdump_line(line, current_ts)

            if new_ts:
                current_ts = new_ts

            if packet_info:
                flow = capture_manager.flow_aggregator.process_packet(packet_info)
                if flow:
                    capture_manager.flow_queue.put(flow)
                current_ts = None

    except Exception as e:
        capture_manager.flow_queue.put({'error': str(e)})
        capture_manager.connection_active = False
    finally:
        if capture_manager.ssh_client:
            capture_manager.ssh_client.close()


# =====================================
# APPLICATION DASH ULTIME
# =====================================

class UltimateNetworkApp:
    def __init__(self):
        # Use only PostgreSQLUserManager without fallback to in-memory
        if not HAS_POSTGRES_USER_MANAGER:
            raise ImportError("PostgreSQLUserManager is required but not available")

        self.user_manager = PostgreSQLUserManager(fallback_to_memory=False)
        logging.info("Using PostgreSQL for user management (no fallback to memory)")

        self.user_captures: Dict[str, UserCaptureManager] = {}

        self.app = dash.Dash(__name__, external_stylesheets=[dbc.themes.BOOTSTRAP],suppress_callback_exceptions=True)
        self.app.server.secret_key = secrets.token_hex(32)
        self.app.config.suppress_callback_exceptions = True
        self.displayed_flows = {}  # user_id -> {flow_key: timestamp_affichage}
        self.accumulated_flow_cards = {}  # user_id -> {flow_key: flow_card}

        # Store throughput history for each user
        self.throughput_history = {}  # user_id -> [(timestamp, throughput_value), ...]


        self.init_database()
        self.setup_layout()
        self.setup_callbacks()

        self.last_terminated_flows = []

        # Set up periodic cleanup of expired sessions
        self.session_cleanup_thread = threading.Thread(
            target=self._session_cleanup_worker,
            daemon=True
        )
        self.session_cleanup_thread.start()

    def _session_cleanup_worker(self):
        """Worker thread to periodically clean up expired sessions"""
        while True:
            try:
                # Clean up expired sessions every hour
                time.sleep(3600)
                self.user_manager.cleanup_expired_sessions()
                logging.info("Cleaned up expired sessions")
            except Exception as e:
                logging.error(f"Error in session cleanup: {e}")
                time.sleep(60)  # Wait a bit before retrying

    def get_db_connection(self):
        """Get a connection to the PostgreSQL database"""
        database_url = os.environ.get('DATABASE_URL', 'postgresql://user:password@localhost:5432/networkdb')
        conn = psycopg2.connect(database_url)
        return conn

    def init_database(self):
        """Initialize the PostgreSQL database for storing reported erroneous flows"""
        try:
            conn = self.get_db_connection()
            cursor = conn.cursor()
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS reported_flows (
                id SERIAL PRIMARY KEY,
                flow_key TEXT NOT NULL,
                src_ip TEXT,
                dst_ip TEXT,
                sport INTEGER,
                dport INTEGER,
                protocol TEXT,
                total_bytes BIGINT,
                pkt_count INTEGER,
                prediction TEXT,
                label_humain TEXT,
                user_id TEXT,
                reported_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                flow_data TEXT
            )
            ''')

            # Create indexes for performance
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_reported_flows_user_id ON reported_flows(user_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_reported_flows_prediction ON reported_flows(prediction)')

            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Error initializing database: {e}")

    def store_reported_flow(self, flow, user_id):
        """Store a reported erroneous flow in the database"""
        try:
            conn = self.get_db_connection()
            cursor = conn.cursor()

            # Inverser la prédiction
            if flow.get('prediction') == 'Mal':
                label_humain = 'Normal'
            elif flow.get('prediction') == 'Normal':
                label_humain = 'Mal'

            # Convert the entire flow dict to JSON for storage
            flow_data = json.dumps(flow)

            cursor.execute('''
            INSERT INTO reported_flows 
            (flow_key, src_ip, dst_ip, sport, dport, protocol, total_bytes, pkt_count, prediction, label_humain, user_id, flow_data)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ''', (
                flow.get('flow_key', ''),
                flow.get('src_ip', ''),
                flow.get('dst_ip', ''),
                flow.get('sport', 0),
                flow.get('dport', 0),
                flow.get('protocol', ''),
                flow.get('total_bytes', 0),
                flow.get('pkt_count', 0),
                flow.get('prediction', ''),
                label_humain,
                user_id,
                flow_data
            ))

            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"Error storing reported flow: {e}")
            return False

    def get_reported_flows(self, user_id=None, prediction_filter=None, limit=100):
        """Retrieve reported flows from the database with optional filtering"""
        try:
            conn = self.get_db_connection()
            cursor = conn.cursor(cursor_factory=extras.DictCursor)  # This enables column access by name

            query = "SELECT * FROM reported_flows"
            params = []

            # Add filters if provided
            where_clauses = []
            # if user_id:
            #     where_clauses.append("user_id = %s")
            #     params.append(user_id)

            if prediction_filter and prediction_filter != "all":
                if prediction_filter == "Mal":
                    where_clauses.append("prediction = 'Mal'")
                else:
                    where_clauses.append("prediction = %s")
                    params.append(prediction_filter)

            if where_clauses:
                query += " WHERE " + " AND ".join(where_clauses)

            query += " ORDER BY reported_at DESC LIMIT %s"
            params.append(limit)
            print("Executing query:", query, "with params:", params)
            cursor.execute(query, params)
            rows = cursor.fetchall()
            print("rows retrieved:", len(rows))

            # Debug: Check if there are any rows in the table at all
            cursor.execute("SELECT COUNT(*) FROM reported_flows")
            total_rows = cursor.fetchone()[0]
            print("Total rows in reported_flows table:", total_rows)

            # Debug: If there are rows but none match our query, let's see what's in the table
            if total_rows > 0 and len(rows) == 0:
                cursor.execute("SELECT id, flow_key, prediction, user_id FROM reported_flows LIMIT 10")
                sample_rows = cursor.fetchall()
                print("Sample rows from reported_flows table:")
                for row in sample_rows:
                    print(dict(row))

            # Convert rows to dictionaries
            flows = []
            for row in rows:
                flow_dict = dict(row)
                # Parse the JSON stored in flow_data
                if 'flow_data' in flow_dict and flow_dict['flow_data']:
                    try:
                        flow_dict['parsed_flow_data'] = json.loads(flow_dict['flow_data'])
                    except:
                        flow_dict['parsed_flow_data'] = {}
                flows.append(flow_dict)

            conn.close()
            return flows
        except Exception as e:
            print(f"Error retrieving reported flows: {e}")
            return []

    def export_flows_for_retraining(self, flow_ids, export_format="json"):
        """Export selected flows for retraining in the specified format"""
        try:
            if not flow_ids:
                return False, "Aucun flow sélectionné pour l'export"

            # Get the flows from the database
            conn = self.get_db_connection()
            cursor = conn.cursor(cursor_factory=extras.DictCursor)

            # Create placeholders for the IN clause
            placeholders = ','.join(['%s'] * len(flow_ids))

            query = f"SELECT * FROM reported_flows WHERE id IN ({placeholders})"
            cursor.execute(query, flow_ids)
            rows = cursor.fetchall()

            if not rows:
                conn.close()
                return False, "Aucun flow trouvé avec les IDs spécifiés"

            # Convert rows to dictionaries
            flows = []
            for row in rows:
                flow_dict = dict(row)
                # Parse the JSON stored in flow_data
                if 'flow_data' in flow_dict and flow_dict['flow_data']:
                    try:
                        flow_dict['parsed_flow_data'] = json.loads(flow_dict['flow_data'])
                    except:
                        flow_dict['parsed_flow_data'] = {}
                flows.append(flow_dict)

            conn.close()

            # Create export filename with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"flows_for_retraining_{timestamp}.{export_format}"

            # Export the flows in the specified format
            if export_format == "json":
                with open(filename, 'w') as f:
                    json.dump(flows, f, indent=2)
            elif export_format == "csv":
                # Extract relevant fields for CSV
                csv_data = []
                for flow in flows:
                    if 'parsed_flow_data' in flow and flow['parsed_flow_data']:
                        # Extract features from the parsed flow data
                        features = flow['parsed_flow_data'].get('cic_features', [])
                        if features:
                            csv_data.append({
                                'flow_id': flow['id'],
                                'prediction': flow['prediction'],
                                'features': features
                            })

                # Write to CSV
                if csv_data:
                    with open(filename, 'w', newline='') as f:
                        import csv
                        writer = csv.writer(f)
                        # Write header
                        writer.writerow(['flow_id', 'prediction', 'features'])
                        # Write data
                        for row in csv_data:
                            writer.writerow([row['flow_id'], row['prediction'], row['features']])
                else:
                    return False, "Aucune donnée valide pour l'export CSV"
            else:
                return False, f"Format d'export non supporté: {export_format}"

            return True, f"Flows exportés avec succès dans {filename}"

        except Exception as e:
            print(f"Error exporting flows: {e}")
            return False, f"Erreur lors de l'export: {str(e)}"


    def get_user_capture_manager(self, session_id):
        user = self.user_manager.get_user_by_session(session_id)
        if not user:
            return None

        if user.user_id not in self.user_captures:
            # on passe aussi l'email pour l'alerte
            self.user_captures[user.user_id] = UserCaptureManager(
                user.user_id,
                user.email
            )
        return self.user_captures[user.user_id]

    def setup_layout(self):
        self.app.layout = html.Div([
            dcc.Location(id='url', refresh=False),
            html.Div(id='page-content'),
            dcc.Store(id='session-store', storage_type='session'),
            dcc.Store(id='ssh-key-content', data=None),
            dcc.Store(id='ssh-key-filename', data=None),
            dcc.Interval(id='main-interval', interval=1000, n_intervals=0, disabled=True),
            html.Div(
                dash_table.DataTable(id='flows-table', data=[]),
                style={'display': 'none'}
            ),
        ])

    def setup_callbacks(self):
        # Router principal
        @callback(
            Output('page-content', 'children'),
            Input('url', 'pathname'),
            State('session-store', 'data'),
            prevent_initial_call=False
        )
        def display_page(pathname, session_data):
            if pathname == '/register':
                return self.register_page()
            elif pathname in ['/login', '/', None]:
                return self.login_page()

            if not session_data or 'session_id' not in session_data:
                return self.login_page()

            user = self.user_manager.get_user_by_session(session_data['session_id'])
            if not user:
                return self.login_page()

            if pathname == '/dashboard':
                return self.dashboard_page(user)
            elif pathname == '/capture':
                return self.capture_page(user)
            elif pathname == '/analysis':
                return self.analysis_page(user)
            elif pathname == '/reported-flows':
                return self.reported_flows_page(user)
            else:
                return self.dashboard_page(user)

        # Login
        @callback(
            [Output('session-store', 'data', allow_duplicate=True),
             Output('url', 'pathname', allow_duplicate=True),
             Output('login-message', 'children')],
            Input('login-button', 'n_clicks'),
            [State('username-input', 'value'),
             State('password-input', 'value')],
            prevent_initial_call=True
        )
        def handle_login(n_clicks, username, password):
            if n_clicks and username and password:
                session_id = self.user_manager.authenticate(username, password)
                if session_id:
                    return {'session_id': session_id}, '/dashboard', ""
                else:
                    return no_update, no_update, dbc.Alert("❌ Identifiants incorrects", color="danger")
            return no_update, no_update, ""

        # Registration
        @callback(
            [Output('url', 'pathname', allow_duplicate=True),
             Output('register-message', 'children')],
            Input('register-button', 'n_clicks'),
            [State('reg-username-input', 'value'),
             State('reg-email-input', 'value'),
             State('reg-password-input', 'value'),
             State('reg-password-confirm-input', 'value')],
            prevent_initial_call=True
        )
        def handle_register(n_clicks, username, email, password, password_confirm):
            if not n_clicks:
                return no_update, ""

            if not all([username, email, password, password_confirm]):
                return no_update, dbc.Alert("❌ Tous les champs sont requis", color="danger")

            if password != password_confirm:
                return no_update, dbc.Alert("❌ Les mots de passe ne correspondent pas", color="danger")

            if len(password) < 6:
                return no_update, dbc.Alert("❌ Le mot de passe doit faire au moins 6 caractères", color="danger")

            success = self.user_manager.register_user(username, email, password)
            if success:
                return '/login', dbc.Alert("✅ Compte créé avec succès !", color="success")
            else:
                return no_update, dbc.Alert("❌ Ce username existe déjà", color="danger")

        # Logout
        @callback(
            [Output('session-store', 'data', allow_duplicate=True),
             Output('url', 'pathname', allow_duplicate=True)],
            Input('logout-button', 'n_clicks'),
            State('session-store', 'data'),
            prevent_initial_call=True
        )
        def handle_logout(n_clicks, session_data):
            if n_clicks and session_data:
                self.user_manager.logout(session_data.get('session_id'))
                return {}, '/login'
            return no_update, no_update

        # Upload SSH Key
        @callback(
            [Output('key-file-status', 'children'),
             Output('ssh-key-content', 'data'),
             Output('ssh-key-filename', 'data')],
            Input('upload-key', 'contents'),
            State('upload-key', 'filename')
        )
        def handle_key_upload(contents, filename):
            if contents is not None:
                try:
                    content_type, content_string = contents.split(',')
                    decoded = base64.b64decode(content_string)
                    decoded_str = decoded.decode('utf-8')

                    valid_key_patterns = [
                        '-----BEGIN RSA PRIVATE KEY-----',
                        '-----BEGIN PRIVATE KEY-----',
                        '-----BEGIN OPENSSH PRIVATE KEY-----'
                    ]

                    is_valid_key = any(pattern in decoded_str for pattern in valid_key_patterns)

                    if is_valid_key:
                        temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False)
                        temp_file.write(decoded_str)
                        temp_file.close()
                        os.chmod(temp_file.name, 0o600)

                        return (
                            dbc.Alert(f"✅ Clé SSH '{filename}' chargée avec succès", color="success"),
                            decoded_str,
                            temp_file.name
                        )
                    else:
                        return (
                            dbc.Alert("❌ Fichier de clé SSH invalide", color="danger"),
                            None, None
                        )
                except Exception as e:
                    return (
                        dbc.Alert(f"❌ Erreur: {str(e)}", color="danger"),
                        None, None
                    )
            return "", None, None

        # Test SSH Connection
        @callback(
            [Output('connection-status', 'children'),
             Output('interfaces-checklist', 'options'),
             Output('start-capture-btn', 'disabled')],
            Input('test-ssh-btn', 'n_clicks'),
            [State('hostname-input', 'value'),
             State('username-input-ssh', 'value'),
             State('ssh-key-filename', 'data'),
             State('session-store', 'data')]
        )
        def test_ssh_connection(n_clicks, hostname, username, keyfile_path, session_data):
            if not n_clicks or not all([hostname, username, keyfile_path]):
                return (
                    dbc.Alert("⚪ Remplissez tous les champs", color="secondary"),
                    [], True
                )

            if not session_data:
                return (
                    dbc.Alert("❌ Session expirée", color="danger"),
                    [], True
                )

            capture_manager = self.get_user_capture_manager(session_data['session_id'])
            if not capture_manager:
                return (
                    dbc.Alert("❌ Erreur utilisateur", color="danger"),
                    [], True
                )

            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(hostname=hostname, username=username, key_filename=keyfile_path, timeout=10)

                stdin, stdout, stderr = client.exec_command(
                    "ip link show | grep '^[0-9]' | awk '{print $2}' | sed 's/://'")
                interfaces = [line.strip() for line in stdout.readlines() if line.strip()]

                # Store SSH configuration in capture_manager
                capture_manager.ssh_config = {
                    'hostname': hostname,
                    'username': username,
                    'key_file': keyfile_path,
                    'interfaces': interfaces,
                    'filters': ''
                }

                # Store SSH client for later use
                capture_manager.ssh_client = client

                interface_options = [{'label': f"🔗 {iface}", 'value': iface} for iface in interfaces]

                return (
                    dbc.Alert(f"✅ Connexion réussie - {len(interfaces)} interfaces trouvées", color="success"),
                    interface_options, False
                )
            except Exception as e:
                # Clear SSH client if connection failed
                capture_manager.ssh_client = None
                return (
                    dbc.Alert(f"❌ Erreur de connexion: {str(e)}", color="danger"),
                    [], True
                )

        # Start/Stop Capture
        @callback(
            [Output('capture-status-display', 'children'),
             Output('stop-capture-btn', 'disabled'),
             Output('main-interval', 'disabled'),
             Output('url', 'pathname', allow_duplicate=True),
             Output('start-capture-btn', 'disabled', allow_duplicate=True)],
            [Input('start-capture-btn', 'n_clicks'),
             Input('stop-capture-btn', 'n_clicks')],
            [State('session-store', 'data'),
             State('hostname-input', 'value'),
             State('username-input-ssh', 'value'),
             State('ssh-key-filename', 'data'),
             State('interfaces-checklist', 'value'),
             State('filters-input', 'value')],
            prevent_initial_call=True
        )
        def manage_capture(start_clicks, stop_clicks, session_data, hostname, username, keyfile_path, interfaces,
                           filters):
            if not session_data:
                return dbc.Alert("❌ Session expirée", color="danger"), True, True, no_update, True

            capture_manager = self.get_user_capture_manager(session_data['session_id'])
            if not capture_manager:
                return dbc.Alert("❌ Erreur utilisateur", color="danger"), True, True, no_update, True

            ctx = callback_context
            if not ctx.triggered:
                return dbc.Alert("⚪ Prêt à démarrer", color="secondary"), True, True, no_update, False

            button_id = ctx.triggered[0]['prop_id'].split('.')[0]

            if button_id == 'start-capture-btn' and start_clicks:
                if not capture_manager.connection_active:
                    interface_str = ",".join(interfaces) if interfaces else "any"

                    # Close existing SSH client if it exists
                    if hasattr(capture_manager, 'ssh_client') and capture_manager.ssh_client:
                        try:
                            capture_manager.ssh_client.close()
                        except:
                            pass  # Ignore errors when closing

                    capture_manager.connection_active = True
                    capture_manager.ssh_thread = threading.Thread(
                        target=ssh_capture_thread,
                        args=(capture_manager, hostname, username, keyfile_path, interface_str, filters or ""),
                        daemon=True
                    )
                    capture_manager.ssh_thread.start()

                    return (
                        dbc.Alert(f"🟢 Capture en cours sur {interface_str}", color="success"),
                        False, False, '/dashboard', True
                    )

            elif button_id == 'stop-capture-btn' and stop_clicks:
                capture_manager.connection_active = False

                # Close existing SSH client if it exists
                if hasattr(capture_manager, 'ssh_client') and capture_manager.ssh_client:
                    try:
                        capture_manager.ssh_client.close()
                        capture_manager.ssh_client = None
                    except:
                        pass  # Ignore errors when closing

                return (
                    dbc.Alert("🔴 Capture arrêtée", color="warning"),
                    True, True, no_update, False  # Re-enable the start button
                )

            return dbc.Alert("⚪ Prêt", color="secondary"), True, True, no_update, False

        # Stop Capture from Dashboard
        @callback(
            [Output('capture-status-dashboard', 'children'),
             Output('dashboard-stop-btn', 'disabled'),
             Output('dashboard-stop-btn', 'style'),
             Output('main-interval', 'disabled', allow_duplicate=True)],
            Input('dashboard-stop-btn', 'n_clicks'),
            State('session-store', 'data'),
            prevent_initial_call=True
        )
        def stop_capture_from_dashboard(n_clicks, session_data):
            if not n_clicks or not session_data:
                return no_update, no_update, no_update, no_update

            capture_manager = self.get_user_capture_manager(session_data['session_id'])
            if not capture_manager:
                return dbc.Alert("❌ Erreur utilisateur", color="danger"), True, {'display': 'none'}, True

            # Arrêter la capture
            capture_manager.connection_active = False

            # Close existing SSH client if it exists
            if hasattr(capture_manager, 'ssh_client') and capture_manager.ssh_client:
                try:
                    capture_manager.ssh_client.close()
                    capture_manager.ssh_client = None
                except:
                    pass  # Ignore errors when closing

            return (
                dbc.Alert("🔴 Capture arrêtée depuis le dashboard", color="warning"),
                True,
                {'display': 'none'},
                True
            )

        # Stop Capture from Analysis Page
        @callback(
            [Output('capture-status-analysis', 'children'),
             Output('analysis-stop-btn', 'disabled'),
             Output('analysis-stop-btn', 'style'),
             Output('main-interval', 'disabled', allow_duplicate=True)],
            Input('analysis-stop-btn', 'n_clicks'),
            State('session-store', 'data'),
            prevent_initial_call=True
        )
        def stop_capture_from_analysis(n_clicks, session_data):
            if not n_clicks or not session_data:
                return no_update, no_update, no_update, no_update

            capture_manager = self.get_user_capture_manager(session_data['session_id'])
            if not capture_manager:
                return dbc.Alert("❌ Erreur utilisateur", color="danger"), True, {'display': 'none'}, True

            # Arrêter la capture
            capture_manager.connection_active = False

            # Close existing SSH client if it exists
            if hasattr(capture_manager, 'ssh_client') and capture_manager.ssh_client:
                try:
                    capture_manager.ssh_client.close()
                    capture_manager.ssh_client = None
                except:
                    pass  # Ignore errors when closing

            return (
                dbc.Alert("🔴 Capture arrêtée depuis la page d'analyse", color="warning"),
                True,
                {'display': 'none'},
                True
            )

        # Update Analysis Page Capture Status
        @callback(
            [Output('capture-status-analysis', 'children', allow_duplicate=True),
             Output('analysis-stop-btn', 'disabled', allow_duplicate=True),
             Output('analysis-stop-btn', 'style', allow_duplicate=True),
             Output('terminated-flows-content', 'children')],
            Input('main-interval', 'n_intervals'),
            [State('session-store', 'data'),
             State('url', 'pathname')],
            prevent_initial_call=True
        )
        def update_analysis_page(n_intervals, session_data, pathname):
            print("=== update_analysis_page CALLED ===")
            print("session_data:", session_data)
            print("pathname:", pathname)

            if not session_data or pathname != '/analysis':
                return no_update, no_update, no_update, []

            user = self.user_manager.get_user_by_session(session_data['session_id'])
            if not user:
                return no_update, no_update, no_update, no_update

            capture_manager = self.get_user_capture_manager(session_data['session_id'])
            print("capture_manager:", capture_manager)

            if not capture_manager:
                return no_update, no_update, no_update, no_update

            # Mise à jour du statut de capture dans la page d'analyse
            capture_active = capture_manager.connection_active

            if capture_active:
                capture_status = dbc.Alert("🟢 Capture en cours - Collecte de données active", color="success")
                stop_btn_disabled = False
                stop_btn_style = {'display': 'inline-block'}
            else:
                capture_status = dbc.Alert("⚪ Aucune capture active", color="secondary")
                stop_btn_disabled = True
                stop_btn_style = {'display': 'none'}

            # Récupérer les flows terminés - augmenter la limite pour afficher plus de flows
            terminated_flows = capture_manager.flow_aggregator.get_terminated_flows(limit=100)
            print("terminated_flows (raw):", terminated_flows)

            # Initialize displayed_flows and accumulated_flow_cards for this user if they don't exist
            if user.user_id not in self.displayed_flows:
                self.displayed_flows[user.user_id] = {}

            if user.user_id not in self.accumulated_flow_cards:
                self.accumulated_flow_cards[user.user_id] = {}

            current_time = time.time()

            if not terminated_flows and not self.accumulated_flow_cards[user.user_id]:
                terminated_flows_content = dbc.Alert("Aucun flow terminé disponible", color="info")
            else:
                # Process new flows
                for flow in terminated_flows:
                    #print("FLOW:", flow)
                    try:
                        # Get flow key
                        flow_key = flow.get('flow_key', '')

                        # Skip if we've already processed this flow
                        if flow_key in self.accumulated_flow_cards[user.user_id]:
                            continue

                        # Track when this flow was first displayed
                        if flow_key not in self.displayed_flows[user.user_id]:
                            self.displayed_flows[user.user_id][flow_key] = current_time

                        # Calculate how long this flow has been displayed
                        display_time = current_time - self.displayed_flows[user.user_id][flow_key]
                        can_report = display_time >= 10  # 10 seconds minimum

                        # Store the flow data for later use in the report callback
                        flow['prediction'] = ''  # Will be set below

                        # Extraire les features ML pour le format demandé
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

                        prediction = predict_flow(ml_features)
                        ml_features['prediction'] = str(prediction)
                        flow['prediction'] = str(prediction)  # Store prediction in flow data

                        # Injecter ces deux features dans le flow lui-même
                        flow["flow_pkts_per_s"] = ml_features["flow_pkts_per_s"]
                        flow["fwd_bwd_ratio"] = ml_features["fwd_bwd_ratio"]

                        print("flow type :", type(flow))
                        flow_summary = ""
                        if flow["prediction"] == "Mal":
                            try:
                                flow_summary = resumer_texte(json.dumps(ml_features))
                            except Exception as e:
                                flow_summary = f"Erreur de résumé : {e}"

                        # Couleur & badge en fonction du résultat
                        prediction_text = str(prediction)
                        if "Erreur" in prediction_text:
                            card_color = "warning"
                            prediction_badge = html.Span([
                                "⚠️ ", prediction_text
                            ], className="badge bg-warning text-dark")
                        elif prediction_text == "Normal":
                            card_color = "success"
                            prediction_badge = html.Span([
                                "✅ Trafic normal (benign)"
                            ], className="badge bg-success")
                        else:
                            card_color = "danger"
                            prediction_badge = html.Span([
                                "🚨 Attaque détectée: ", prediction_text
                            ], className="badge bg-danger")

                        # Create report button with appropriate state
                        if can_report:
                            report_button = dbc.Button(
                                "🚩 Signaler comme erroné",
                                id={"type": "report-flow-btn", "index": flow_key},
                                color="outline-danger",
                                size="sm",
                                className="mt-2",
                                n_clicks=0
                            )
                            report_status = ""
                        else:
                            # Calculate remaining time
                            remaining_seconds = int(10 - display_time)
                            report_button = dbc.Button(
                                f"🕒 Attendre {remaining_seconds}s",
                                id={"type": "report-flow-btn", "index": flow_key},
                                color="outline-secondary",
                                size="sm",
                                className="mt-2",
                                disabled=True
                            )
                            report_status = html.Small(
                                f"Ce flow pourra être signalé dans {remaining_seconds} secondes",
                                className="text-muted"
                            )

                        flow_card = dbc.Card([
                            dbc.CardHeader([
                                html.Div([
                                    dbc.Row([
                                        dbc.Col([
                                            dbc.Checkbox(
                                                id={"type": "flow-select-checkbox", "index": flow_key},
                                                className="me-2",
                                                persistence=True,               # ← active la persistence
                                                persistence_type='memory',
                                                value=False
                                            )
                                        ], width="auto"),
                                        dbc.Col([
                                            html.Span(
                                                f"Flow: {flow.get('src_ip', 'Unknown')}:{flow.get('sport', 0)} → {flow.get('dst_ip', 'Unknown')}:{flow.get('dport', 0)} ({flow.get('protocol', 'Unknown')})"),
                                            html.Div(prediction_badge, className="mt-2")
                                        ])
                                    ])
                                ])
                            ], className=f"bg-{card_color} bg-opacity-25"),
                            dbc.CardBody([
                                html.H6("ML Features:"),
                                html.Pre(json.dumps(ml_features, indent=2),
                                         style={'background-color': '#f8f9fa', 'padding': '10px',
                                                'border-radius': '5px'}),
                                html.H6("Résumé du Flow:", className="mt-3") if flow_summary else "",
                                html.Div(flow_summary, className="fst-italic text-dark") if flow_summary else "",
                                html.Div([
                                    report_button,
                                    report_status,
                                    html.Div(id={"type": "report-status", "index": flow_key})
                                ])
                            ])
                        ], className="mb-3", color=card_color, outline=True)

                        # Store the flow card in the accumulated flow cards dictionary
                        self.accumulated_flow_cards[user.user_id][flow_key] = flow_card
                    except Exception as e:
                        print(f"Erreur lors du rendu du flow : {flow.get('flow_key', '???')} : {e}")
                        # Ajoute une carte erreur pour visualiser dans l'UI
                        error_key = f"error_{time.time()}"
                        self.accumulated_flow_cards[user.user_id][error_key] = dbc.Alert(
                            f"Erreur rendering flow: {e}", color="danger", className="mb-2"
                        )

                # Récupérer toutes les cartes accumulées
                all_flow_cards = list(self.accumulated_flow_cards[user.user_id].values())

                # Filtrer tout None éventuel (sécurité)
                all_flow_cards = [card for card in all_flow_cards if card is not None]

                # Trier les cartes pour afficher les flows malveillants avant les normaux
                # On extrait la classe du CardHeader pour déterminer si c'est normal ou malveillant
                def get_card_type(card):
                    try:
                        # Les cartes malveillantes ont bg-danger, les normales ont bg-success
                        if hasattr(card, 'children') and card.children and len(card.children) > 0:
                            header = card.children[0]
                            if hasattr(header, 'className') and 'bg-danger' in header.className:
                                return 0  # Malicious flows first
                            elif hasattr(header, 'className') and 'bg-success' in header.className:
                                return 1  # Normal flows second
                    except:
                        pass
                    return 2  # Other cards last

                # Trier les cartes
                all_flow_cards.sort(key=get_card_type)

                # Toujours passer une liste de composants Dash, jamais de None ou d'objet natif
                terminated_flows_content = html.Div(
                    all_flow_cards,
                    style={
                        'maxHeight': '550px',  # ajuste la hauteur à ton besoin
                        'overflowY': 'auto',
                        'border': '1px solid #e5e5e5',
                        'backgroundColor': '#fcfcfc',
                        'padding': '8px'
                    }
                )

            return (
                capture_status,
                stop_btn_disabled,
                stop_btn_style,
                terminated_flows_content if terminated_flows_content else []
            )


        # Dashboard Updates
        @callback(
            [Output('user-stats-cards', 'children'),
             Output('flows-live-table', 'children'),
             Output('traffic-chart', 'figure'),
             Output('throughput-time-chart', 'figure'),  # New output for throughput time chart
             #Output('sessions-actives-value', 'children'),
             #Output('connexions-anormales-value', 'children'),
             Output('top-ips-chart', 'figure'),
             Output('capture-status-dashboard', 'children', allow_duplicate=True),
             Output('dashboard-stop-btn', 'disabled', allow_duplicate=True),
             Output('dashboard-stop-btn', 'style', allow_duplicate=True)],
            Input('main-interval', 'n_intervals'),
            [State('session-store', 'data'),
             State('url', 'pathname')],
            prevent_initial_call=True
        )
        def update_dashboard_live(n_intervals, session_data, pathname):
            if not session_data:
                return [], html.P("Session expirée"), go.Figure(), go.Figure(), no_update, no_update, no_update, no_update

            capture_manager = self.get_user_capture_manager(session_data['session_id'])
            if not capture_manager:
                return [], html.P("Erreur utilisateur"), go.Figure(), go.Figure(), no_update, no_update, no_update, no_update

            # Traitement des nouveaux flows - toujours exécuté même si l'utilisateur n'est pas sur le dashboard
            # pour continuer à collecter les données
            new_flows = []
            flow_count = 0
            while not capture_manager.flow_queue.empty() and flow_count < 20:
                try:
                    flow = capture_manager.flow_queue.get_nowait()
                    if 'error' not in flow:
                        new_flows.append(flow)
                        flow_count += 1
                except queue.Empty:
                    break

            # Si l'utilisateur n'est pas sur la page dashboard, continuer à traiter les données
            # mais ne pas mettre à jour l'interface
            if pathname != '/dashboard':
                # Continuer à traiter les données mais ne pas mettre à jour l'interface
                # Cela permet de maintenir l'état interne à jour
                return no_update, no_update, no_update, no_update, no_update, no_update, no_update, no_update

            # Statistiques utilisateur
            stats = capture_manager.flow_aggregator.get_statistics()
            user = self.user_manager.get_user_by_session(session_data['session_id'])
            user_id = session_data['session_id']

            # Table des flows en temps réel
            active_flows = capture_manager.flow_aggregator.get_active_flows(limit=30)
            flows_table = self.create_live_flows_table(active_flows)

            # Graphique du trafic
            traffic_fig = self.create_traffic_chart(active_flows)

            # Calcul du débit en Mbps
            debit_bytes = sum(flow['total_bytes'] for flow in active_flows)
            interval_s = 1  # Ajuste selon ton intervalle réel de rafraîchissement
            debit_mbps = (debit_bytes * 8) / 1_000_000 / interval_s  # en Mbps

            stats_cards = [
                self.create_stat_card("📊 Paquets", stats['total_packets_processed'], 'primary'),
                self.create_stat_card("📡 Débit Actuel", f"{debit_mbps:.2f} Mbps", 'success'),
                self.create_stat_card("👤 " + (user.username if user else "Unknown"),
                                      user.role if user else "unknown", 'secondary')
            ]

            # Store throughput data in history only if capture is active
            capture_active = capture_manager.connection_active

            if capture_active:
                if user_id not in self.throughput_history:
                    self.throughput_history[user_id] = []

                # Add current timestamp and throughput value to history
                current_time = datetime.now()
                self.throughput_history[user_id].append((current_time, debit_mbps))

                # Limit history to last 100 points to prevent memory issues
                if len(self.throughput_history[user_id]) > 100:
                    self.throughput_history[user_id] = self.throughput_history[user_id][-100:]

            # Create throughput time chart
            throughput_fig = self.create_throughput_time_chart(user_id)


            # Calcul du nombre de sessions actives (commenté car non utilisé)
            # nb_sessions = sum(1 for flow in active_flows if flow.get('status') == 'active')

            nb_connexions_anormales = sum(1 for flow in active_flows if flow.get('status') == 'anomalous')

            # Compte les IP sources
            counter_ips = Counter(flow.get('src_ip') for flow in active_flows if flow.get('src_ip'))
            top_ips = counter_ips.most_common(5)
            if top_ips:
                ips, counts = zip(*top_ips)
            else:
                ips, counts = [], []

            fig_top_ips = go.Figure()
            fig_top_ips.add_trace(go.Bar(
                x=list(counts),
                y=list(ips),
                orientation='h'
            ))
            fig_top_ips.update_layout(
                xaxis_title='Nombre de connexions',
                yaxis_title='Adresse IP',
                title='🌐 Top 10 IP Sources les plus actives',
                yaxis={'categoryorder': 'total ascending'}
            )


            # Mise à jour du statut de capture dans le dashboard
            if capture_active:
                capture_status = dbc.Alert("🟢 Capture en cours - Données en temps réel", color="success")
                stop_btn_disabled = False
                stop_btn_style = {'display': 'inline-block'}
            else:
                capture_status = dbc.Alert("⚪ Aucune capture active", color="secondary")
                stop_btn_disabled = True
                stop_btn_style = {'display': 'none'}

            return stats_cards, flows_table, traffic_fig, throughput_fig, fig_top_ips, capture_status, stop_btn_disabled, stop_btn_style

        # Update Capture Page Controls
        @callback(
            [Output('start-capture-btn', 'disabled', allow_duplicate=True),
             Output('stop-capture-btn', 'disabled', allow_duplicate=True),
             Output('capture-status-display', 'children', allow_duplicate=True)],
            [Input('url', 'pathname')],
            [State('session-store', 'data')],
            prevent_initial_call=True
        )
        def update_capture_page_controls(pathname, session_data):
            # Only update when navigating to the capture page
            if pathname != '/capture':
                return no_update, no_update, no_update

            if not session_data:
                return True, True, dbc.Alert("❌ Session expirée", color="danger")

            capture_manager = self.get_user_capture_manager(session_data['session_id'])
            if not capture_manager:
                return True, True, dbc.Alert("❌ Erreur utilisateur", color="danger")

            # Check if capture is active
            if capture_manager.connection_active:
                # If capture is active, disable start button and enable stop button
                return True, False, dbc.Alert("🟢 Capture en cours", color="success")
            else:
                # If capture is not active, enable start button (if SSH connection was tested)
                # and disable stop button
                if hasattr(capture_manager, 'ssh_client') and capture_manager.ssh_client:
                    return False, True, dbc.Alert("⚪ Prêt à démarrer", color="secondary")
                else:
                    return True, True, dbc.Alert("⚪ Testez d'abord la connexion SSH", color="secondary")

        # Flow Details
        @callback(
            Output('flow-details-modal', 'is_open'),
            Output('flow-details-content', 'children'),
            [Input('flows-table', 'active_cell'),
             Input('close-details-btn', 'n_clicks')],
            [State('flows-table', 'data'),
             State('session-store', 'data')]
        )

        def show_flow_details(active_cell, close_clicks, table_data, session_data):
            ctx = callback_context
            if not ctx.triggered:
                return False, ""

            trigger_id = ctx.triggered[0]['prop_id'].split('.')[0]

            if trigger_id == 'close-details-btn' and close_clicks:
                return False, ""

            if trigger_id == 'flows-table' and active_cell and table_data:
                row_idx = active_cell['row']
                flow_key = table_data[row_idx]['flow_key']

                capture_manager = self.get_user_capture_manager(session_data['session_id'])
                if capture_manager:
                    # Trouver le flow complet
                    active_flows = capture_manager.flow_aggregator.get_active_flows()
                    selected_flow = None
                    for flow in active_flows:
                        if flow.get('flow_key') == flow_key:
                            selected_flow = flow
                            break

                    if selected_flow:
                        details_content = self.create_flow_details(selected_flow)
                        return True, details_content

            return False, ""

        # Réactiver main-interval quand on revient sur le dashboard
        @callback(
            Output('main-interval', 'disabled', allow_duplicate=True),
            Input('url', 'pathname'),
            prevent_initial_call='initial_duplicate'
        )
        def enable_interval_on_dashboard(pathname):
            return pathname not in ['/dashboard', '/analysis']  # False = actif, True = désactivé

        # Refresh reported flows table
        @callback(
            Output('reported-flows-table', 'children'),
            [Input('refresh-reported-flows', 'n_clicks'),
             Input('url', 'pathname')],
            [State('prediction-filter', 'value'),
             State('limit-input', 'value'),
             State('session-store', 'data')],
            prevent_initial_call=False
        )
        def refresh_reported_flows(n_clicks, pathname, prediction_filter, limit, session_data):
            if pathname != '/reported-flows':
                return no_update

            if not session_data:
                return html.Div("Session expirée. Veuillez vous reconnecter.")

            user = self.user_manager.get_user_by_session(session_data['session_id'])
            if not user:
                return html.Div("Utilisateur non trouvé. Veuillez vous reconnecter.")

            # Get reported flows from database
            flows = self.get_reported_flows(
                user_id=user.user_id,
                prediction_filter=prediction_filter,
                limit=limit
            )

            if not flows:
                return html.Div("Aucun flow signalé trouvé.")

            # Create a table with checkboxes for selection
            table_header = [
                html.Thead(html.Tr([
                    html.Th("Sélection", style={'width': '10%'}),
                    html.Th("ID", style={'width': '5%'}),
                    html.Th("Source → Destination", style={'width': '25%'}),
                    html.Th("Prédiction", style={'width': '15%'}),
                    html.Td("Label humain", style={'width': '15%'}),
                    html.Th("Date signalé", style={'width': '15%'})
                    # ,
                    # html.Th("Détails", style={'width': '30%'})
                ]))
            ]

            rows = []
            for flow in flows:
                # Format the flow information
                flow_id = flow.get('id', 'N/A')
                src_ip = flow.get('src_ip', 'N/A')
                dst_ip = flow.get('dst_ip', 'N/A')
                sport = flow.get('sport', 'N/A')
                dport = flow.get('dport', 'N/A')
                protocol = flow.get('protocol', 'N/A')
                prediction = flow.get('prediction', 'N/A')
                label_humain = flow.get('label_humain', 'N/A')
                reported_at = flow.get('reported_at', 'N/A')

                # Format source to destination
                src_dst = f"{src_ip}:{sport} → {dst_ip}:{dport} ({protocol})"

                # Format prediction with color
                if prediction == 'Normal':
                    prediction_badge = html.Span("Normal", className="badge bg-success")
                elif "Erreur" in prediction:
                    prediction_badge = html.Span(prediction, className="badge bg-warning text-dark")
                else:
                    prediction_badge = html.Span(prediction, className="badge bg-danger")

                # Create a collapsible details section
                # details = dbc.Button(
                #     "Voir détails",
                #     id={"type": "flow-details-btn", "index": flow_id},
                #     color="info",
                #     size="sm",
                #     className="me-2"
                # )

                # Create the row
                row = html.Tr([
                    html.Td(dbc.Checkbox(
                        id={"type": "flow-checkbox", "index": flow_id},
                        persistence=True,
                        persistence_type='memory'
                    )),
                    html.Td(flow_id),
                    html.Td(src_dst),
                    html.Td(prediction_badge),
                    html.Td(label_humain),
                    html.Td(reported_at)
                    # ,
                    # html.Td(details)
                ])
                rows.append(row)

            table_body = [html.Tbody(rows)]

            table = dbc.Table(
                table_header + table_body,
                bordered=True,
                hover=True,
                responsive=True,
                striped=True,
                className="mt-3"
            )

            return table

        # Handle flow selection
        @callback(
            Output('selected-flows', 'data'),
            Input({"type": "flow-checkbox", "index": dash.ALL}, "checked"),
            State({"type": "flow-checkbox", "index": dash.ALL}, "id"),
            State('selected-flows', 'data'),
            prevent_initial_call=True
        )
        def update_selected_flows(checked_values, checkbox_ids, current_selection):
            selected_flows = current_selection.copy() if current_selection else []

            if checked_values and checkbox_ids:
                print(f"length of checked_values: {len(checked_values)}")
                for i, checked in enumerate(checked_values):
                    flow_id = checkbox_ids[i]["index"]
                    if checked and flow_id not in selected_flows:
                        selected_flows.append(flow_id)
                    elif not checked and flow_id in selected_flows:
                        selected_flows.remove(flow_id)
            print(f"Selected flows:{len(selected_flows)} : {selected_flows}")
            return selected_flows

        # Show export confirmation modal
        @callback(
            Output('export-confirmation-modal', 'is_open'),
            Input('export-selected-btn', 'n_clicks'),
            Input('cancel-export', 'n_clicks'),
            Input('confirm-export', 'n_clicks'),
            State('export-confirmation-modal', 'is_open'),
            prevent_initial_call=True
        )
        def toggle_export_modal(export_clicks, cancel_clicks, confirm_clicks, is_open):
            ctx = callback_context
            if not ctx.triggered:
                return is_open

            button_id = ctx.triggered[0]['prop_id'].split('.')[0]

            if button_id == 'export-selected-btn' and export_clicks:
                return True
            elif (button_id == 'cancel-export' and cancel_clicks) or (button_id == 'confirm-export' and confirm_clicks):
                return False

            return is_open

        # Handle export confirmation
        @callback(
            Output('export-status', 'children'),
            Input('confirm-export', 'n_clicks'),
            State('selected-flows', 'data'),
            State('session-store', 'data'),
            prevent_initial_call=True
        )
        def handle_export(n_clicks, selected_flows, session_data):
            if not n_clicks or not selected_flows:
                return no_update

            if not session_data:
                return dbc.Alert("Session expirée. Veuillez vous reconnecter.", color="danger")

            user = self.user_manager.get_user_by_session(session_data['session_id'])
            if not user:
                return dbc.Alert("Utilisateur non trouvé. Veuillez vous reconnecter.", color="danger")

            # Export the selected flows
            success, message = self.export_flows_for_retraining(selected_flows, export_format="json")

            if success:
                return dbc.Alert(message, color="success")
            else:
                return dbc.Alert(message, color="danger")

        # Handle flow selection on analysis page
        @callback(
            Output("analysis-selected-flows", "data"),
            Input({"type": "flow-select-checkbox", "index": dash.ALL}, "value"),
            State({"type": "flow-select-checkbox", "index": dash.ALL}, "id"),
            State("analysis-selected-flows", "data"),
            prevent_initial_call=True
        )
        def update_analysis_selected_flows(checked_values, checkbox_ids, current_selection):
            selected_flows = current_selection.copy() if current_selection else []

            if checked_values and checkbox_ids:
                for i, checked in enumerate(checked_values):
                    flow_key = checkbox_ids[i]["index"]
                    if checked and flow_key not in selected_flows:
                        selected_flows.append(flow_key)
                    elif not checked and flow_key in selected_flows:
                        selected_flows.remove(flow_key)

            print("Nouvelle sélection de flows sur analysis :", selected_flows)
            print("checkbox_ids =", checkbox_ids)
            print("checked_values =", checked_values)
            return selected_flows

        # Show export confirmation modal on analysis page
        @callback(
            Output("analysis-export-modal", "is_open"),
            Input("analysis-export-btn", "n_clicks"),
            Input("analysis-cancel-export", "n_clicks"),
            Input("analysis-confirm-export", "n_clicks"),
            State("analysis-export-modal", "is_open"),
            prevent_initial_call=True
        )
        def toggle_analysis_export_modal(export_clicks, cancel_clicks, confirm_clicks, is_open):
            ctx = callback_context
            if not ctx.triggered:
                return is_open

            button_id = ctx.triggered[0]['prop_id'].split('.')[0]

            if button_id == "analysis-export-btn" and export_clicks:
                return True
            elif (button_id == "analysis-cancel-export" and cancel_clicks) or (button_id == "analysis-confirm-export" and confirm_clicks):
                return False

            return is_open

        # Handle export confirmation on analysis page
        @callback(
            Output("capture-status-analysis", "children", allow_duplicate=True),
            Input("analysis-confirm-export", "n_clicks"),
            State("analysis-selected-flows", "data"),
            State("session-store", "data"),
            prevent_initial_call=True
        )
        def handle_analysis_export(n_clicks, selected_flows, session_data):
            print("selected_flows reçus pour export :", selected_flows)
            if not n_clicks or not selected_flows:
                return no_update

            if not session_data:
                return dbc.Alert("Session expirée. Veuillez vous reconnecter.", color="danger")

            user = self.user_manager.get_user_by_session(session_data['session_id'])
            if not user:
                return dbc.Alert("Utilisateur non trouvé. Veuillez vous reconnecter.", color="danger")

            capture_manager = self.get_user_capture_manager(session_data['session_id'])
            if not capture_manager:
                return dbc.Alert("Gestionnaire de capture non disponible.", color="danger")

            # Get the flows from the accumulated flow cards
            flows_to_export = []
            for flow_key in selected_flows:
                # Find the flow in terminated flows
                terminated_flows = capture_manager.flow_aggregator.get_terminated_flows(limit=100)
                for flow in terminated_flows:
                    if flow.get('flow_key', '') == flow_key:
                        # Store the flow in the database first
                        self.store_reported_flow(flow, user.user_id)
                        flows_to_export.append(flow_key)
                        break

            if not flows_to_export:
                return dbc.Alert("Aucun flow valide trouvé pour l'export.", color="warning")

            # Export the flows
            # We'll use the flow keys as IDs to retrieve from the database
            # First, get the IDs from the database
            conn = self.get_db_connection()
            cursor = conn.cursor()
            flow_ids = []

            for flow_key in flows_to_export:
                cursor.execute("SELECT id FROM reported_flows WHERE flow_key = %s AND user_id = %s ORDER BY reported_at DESC LIMIT 1",
                              (flow_key, user.user_id))
                result = cursor.fetchone()
                if result:
                    flow_ids.append(result[0])

            conn.close()

            if not flow_ids:
                return dbc.Alert("Aucun flow trouvé dans la base de données.", color="warning")

            # Now export the flows
            success, message = self.export_flows_for_retraining(flow_ids, export_format="json")

            if success:
                return dbc.Alert(message, color="success")
            else:
                return dbc.Alert(message, color="danger")

        # Handle report flow button click
        @callback(
            Output({"type": "report-status", "index": dash.dependencies.MATCH}, "children"),
            Input({"type": "report-flow-btn", "index": dash.dependencies.MATCH}, "n_clicks"),
            State({"type": "report-flow-btn", "index": dash.dependencies.MATCH}, "id"),
            State("session-store", "data"),
            prevent_initial_call=True
        )
        def handle_report_flow(n_clicks, btn_id, session_data):
            if not n_clicks or n_clicks <= 0 or not session_data:
                return no_update

            # Get the flow key from the button ID
            flow_key = btn_id["index"]

            # Get the user
            user = self.user_manager.get_user_by_session(session_data['session_id'])
            if not user:
                return dbc.Alert("❌ Erreur: Session utilisateur invalide", color="danger")

            # Get the capture manager
            capture_manager = self.get_user_capture_manager(session_data['session_id'])
            if not capture_manager:
                return dbc.Alert("❌ Erreur: Gestionnaire de capture non disponible", color="danger")

            # Find the flow in terminated flows
            terminated_flows = capture_manager.flow_aggregator.get_terminated_flows(limit=100)
            flow = None
            for f in terminated_flows:
                if f.get('flow_key', '') == flow_key:
                    flow = f
                    break

            if not flow:
                return dbc.Alert("❌ Erreur: Flow non trouvé", color="danger")

            # Store the flow in the database
            success = self.store_reported_flow(flow, user.user_id)

            if success:
                return dbc.Alert("✅ Flow signalé comme erroné avec succès", color="success")
            else:
                return dbc.Alert("❌ Erreur lors du signalement du flow", color="danger")

    def create_stat_card(self, title, value, color):
        return dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.H4(str(value), className=f"text-{color} mb-0"),
                    html.P(title, className="text-muted small")
                ])
            ], className="text-center")
        ], width=3)

    def create_live_flows_table(self, flows):
        # Ne garder que les flows terminés
        terminated_flows = [flow for flow in flows if flow.get('status') == 'terminated']

        # On ajoute à la mémoire persistante
        for flow in terminated_flows:
            # Pour éviter les doublons, on peut vérifier via le flow_key
            if flow.get('flow_key') not in [f.get('flow_key') for f in self.last_terminated_flows]:
                self.last_terminated_flows.append(flow)
        # On garde seulement les 20 derniers
        self.last_terminated_flows = self.last_terminated_flows[-20:]

        # Utilise la mémoire persistante pour l'affichage
        if not self.last_terminated_flows:
            return dbc.Alert("📭 Aucun flow terminé", color="info")

        table_data = []
        for flow in self.last_terminated_flows[::-1]:  # Plus récent en haut
            pred = flow.get('prediction', '').strip().lower()
            print("pred =", pred)
            if not pred:
                pred_affiche = "Analyse en cours…"
            elif pred not in ['mal', 'normal']:
                pred_affiche = "Inconnu"
            else:
                pred_affiche = pred.capitalize()
            table_data.append({
                'flow_key': flow.get('flow_key', 'Unknown')[:30] + '...' if len(
                    flow.get('flow_key', '')) > 30 else flow.get('flow_key', 'Unknown'),
                'src_ip': flow.get('src_ip', 'Unknown'),
                'dst_ip': flow.get('dst_ip', 'Unknown'),
                'dport': flow.get('dport', 0),
                'protocol': flow.get('protocol', 'Unknown'),
                'bytes': flow.get('total_bytes', 0),
                'packets': flow.get('pkt_count', 0),
                'duration': f"{flow.get('duration_ms', 0):.1f}ms",
                'prediction': pred_affiche
            })

        return dash_table.DataTable(
            id='flows-table',
            data=table_data,
            columns=[
                {'name': 'Flow Key', 'id': 'flow_key'},
                {'name': 'Source IP', 'id': 'src_ip'},
                {'name': 'Dest IP', 'id': 'dst_ip'},
                {'name': 'Port', 'id': 'dport'},
                {'name': 'Proto', 'id': 'protocol'},
                {'name': 'Bytes', 'id': 'bytes'},
                {'name': 'Pkts', 'id': 'packets'},
                {'name': 'Durée', 'id': 'duration'},
                {'name': 'Prédiction', 'id': 'prediction'},
            ],
            style_cell={'textAlign': 'left', 'fontSize': '11px', 'padding': '5px'},
            style_header={'backgroundColor': 'rgb(230, 230, 230)', 'fontWeight': 'bold'},
            style_data_conditional=[
                {
                    'if': {'filter_query': '{prediction} = Mal'},
                    'backgroundColor': '#ffdddd',
                    'color': 'black',
                    'fontWeight': 'bold'
                },
                {
                    'if': {'filter_query': '{prediction} = Normal'},
                    'backgroundColor': '#ddffdd',
                    'color': 'black',
                    'fontWeight': 'bold'
                },
                {
                    'if': {'filter_query': '{prediction} = inconnu'},
                    'backgroundColor': '#f5f5f5',
                    'color': '#888888',
                },
                {
                    'if': {'filter_query': '{protocol} = TCP'},
                    'color': '#0066cc',
                },
                {
                    'if': {'filter_query': '{protocol} = UDP'},
                    'color': '#cc6600',
                }
            ],
            sort_action="native",
            page_size=15,
            style_table={'overflowX': 'auto', 'height': '400px', 'overflowY': 'auto'}
        )

    def create_traffic_chart(self, flows):
        if not flows:
            fig = go.Figure()
            fig.add_annotation(
                text="Aucune donnée de trafic",
                xref="paper", yref="paper", x=0.5, y=0.5,
                showarrow=False, font=dict(size=16, color="gray")
            )
            fig.update_layout(title="📈 Trafic Réseau en Temps Réel")
            return fig

        # Graphique des ports les plus utilisés
        ports_data = [f.get('dport', 0) for f in flows if f.get('dport', 0) > 0]
        if ports_data:
            port_counts = pd.Series(ports_data).value_counts().head(10)

            service_map = {
                80: 'HTTP', 443: 'HTTPS', 22: 'SSH', 21: 'FTP', 25: 'SMTP',
                53: 'DNS', 110: 'POP3', 143: 'IMAP', 993: 'IMAPS', 995: 'POP3S'
            }

            port_labels = []
            for port in port_counts.index:
                service = service_map.get(port, '')
                label = f"{port}" + (f" ({service})" if service else "")
                port_labels.append(label)

            fig = px.bar(
                x=port_labels, y=port_counts.values,
                title="📈 Top 10 Ports de Destination",
                labels={'x': 'Port (Service)', 'y': 'Nombre de Flows'},
                color=port_counts.values,
                color_continuous_scale='Viridis'
            )
            fig.update_layout(showlegend=False, height=400)
        else:
            fig = go.Figure()
            fig.add_annotation(
                text="Aucun port détecté",
                xref="paper", yref="paper", x=0.5, y=0.5
            )

        return fig

    def create_throughput_time_chart(self, user_id):
        """
        Create a time-series chart showing the average network throughput over time.

        Args:
            user_id: The ID of the user to get throughput history for

        Returns:
            A Plotly figure object
        """
        # Get the throughput history for this user
        history = self.throughput_history.get(user_id, [])

        if not history:
            fig = go.Figure()
            fig.add_annotation(
                text="Aucune donnée de débit disponible",
                xref="paper", yref="paper", x=0.5, y=0.5,
                showarrow=False, font=dict(size=16, color="gray")
            )
            fig.update_layout(title="📊 Débit Moyen du Réseau au Cours du Temps")
            return fig

        # Convert history to dataframe for plotting
        df = pd.DataFrame(history, columns=['timestamp', 'throughput'])

        # Create the time-series chart
        fig = px.line(
            df, x='timestamp', y='throughput',
            title="📊 Débit Moyen du Réseau au Cours du Temps",
            labels={'timestamp': 'Temps', 'throughput': 'Débit (Mbps)'},
            line_shape='linear'
        )

        # Customize the layout
        fig.update_layout(
            xaxis_title="Temps",
            yaxis_title="Débit (Mbps)",
            height=400,
            margin=dict(l=40, r=40, t=40, b=40)
        )

        return fig


    def create_flow_details(self, flow):
        features = extract_cic_features(flow)

        return dbc.Container([
            html.H5("🔍 Détails du Flow", className="mb-3"),

            dbc.Row([
                dbc.Col([
                    html.Strong("Flow Key:"), html.Br(),
                    html.Code(flow.get('flow_key', 'Unknown')),
                    html.Hr(),

                    html.Strong("Connexion:"), html.Br(),
                    html.P([
                        f"🔗 {flow.get('src_ip', 'Unknown')}:{flow.get('sport', 0)} ",
                        "→ ",
                        f"{flow.get('dst_ip', 'Unknown')}:{flow.get('dport', 0)}"
                    ]),

                    html.Strong("Protocole:"), f" {flow.get('protocol', 'Unknown')}", html.Br(),
                    html.Strong("Interface:"), f" {flow.get('interface', 'Unknown')}", html.Br(),
                    html.Strong("Status:"), f" {flow.get('status', 'unknown')}"
                ], width=6),

                dbc.Col([
                    html.Strong("Métriques:"), html.Br(),
                    html.P([
                        f"📊 Durée: {flow.get('duration_ms', 0):.2f} ms", html.Br(),
                        f"📈 Total bytes: {flow.get('total_bytes', 0):,}", html.Br(),
                        f"📦 Total packets: {flow.get('pkt_count', 0)}", html.Br(),
                        f"⬆️ Forward: {flow.get('fwd_bytes', 0):,} bytes", html.Br(),
                        f"⬇️ Backward: {flow.get('bwd_bytes', 0):,} bytes"
                    ])
                ], width=6)
            ]),

            html.Hr(),
            html.H6("🤖 Features Machine Learning (CIC-IDS2017)"),

            dbc.Row([
                dbc.Col([
                    html.Ol([
                        html.Li(f"Destination Port: {features[0]}"),
                        html.Li(f"Bwd Packet Length Min: {features[1]:.2f}"),
                        html.Li(f"Bwd Packet Length Mean: {features[2]:.2f}"),
                        html.Li(f"Bwd Packets/s: {features[3]:.2f}"),
                        html.Li(f"Min Packet Length: {features[4]:.2f}")
                    ])
                ], width=6),
                dbc.Col([
                    html.Ol([
                        html.Li(f"PSH Flag Count: {features[5]}", start=6),
                        html.Li(f"URG Flag Count: {features[6]}"),
                        html.Li(f"Avg Fwd Segment Size: {features[7]:.2f}"),
                        html.Li(f"Avg Bwd Segment Size: {features[8]:.2f}"),
                        html.Li(f"Min Seg Size Forward: {features[9]:.2f}")
                    ])
                ], width=6)
            ]),

            html.Hr(),
            dbc.Alert([
                html.Strong("🔬 ML Ready: "),
                f"Vecteur de {len(features)} features prêt pour classification"
            ], color="success")
        ])

    # Pages de l'interface
    def login_page(self):
        return dbc.Container([
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardBody([
                            html.H2("🔐 Ultimate Network Analyzer", className="text-center mb-4"),
                            html.P("🌐 Capture • Analyse • ML Ready", className="text-center text-muted mb-4"),

                            dbc.Input(
                                id='username-input',
                                type='text',
                                placeholder='Username',
                                className="mb-3"
                            ),

                            dbc.Input(
                                id='password-input',
                                type='password',
                                placeholder='Password',
                                className="mb-3"
                            ),

                            dbc.Button(
                                "🚀 Se connecter",
                                id='login-button',
                                color="primary",
                                className="w-100 mb-3",
                                n_clicks=0
                            ),

                            html.Div(id='login-message'),

                            html.Hr(),

                            html.P([
                                "Nouveau ? ",
                                html.A("📝 Créer un compte", href="/register", className="text-decoration-none")
                            ], className="text-center"),

                            dbc.Alert([
                                html.Strong("🔑 Compte admin par défaut: "),
                                html.Code("admin / admin123")
                            ], color="info", className="mt-3")
                        ])
                    ])
                ], width=6)
            ], justify="center", className="mt-5")
        ])

    def register_page(self):
        return dbc.Container([
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardBody([
                            html.H2("📝 Créer un Compte", className="text-center mb-4"),

                            dbc.Input(
                                id='reg-username-input',
                                type='text',
                                placeholder='Username (min 3 caractères)',
                                className="mb-3"
                            ),

                            dbc.Input(
                                id='reg-email-input',
                                type='email',
                                placeholder='Email',
                                className="mb-3"
                            ),

                            dbc.Input(
                                id='reg-password-input',
                                type='password',
                                placeholder='Password (min 6 caractères)',
                                className="mb-3"
                            ),

                            dbc.Input(
                                id='reg-password-confirm-input',
                                type='password',
                                placeholder='Confirmer le password',
                                className="mb-3"
                            ),

                            dbc.Button(
                                "✅ Créer mon compte",
                                id='register-button',
                                color="success",
                                className="w-100 mb-3",
                                n_clicks=0
                            ),

                            html.Div(id='register-message'),

                            html.Hr(),

                            html.P([
                                html.A("← Retour à la connexion", href="/login", className="text-decoration-none")
                            ], className="text-center")
                        ])
                    ])
                ], width=6)
            ], justify="center", className="mt-5")
        ])

    def dashboard_page(self, user):
        # Vérifier si une capture est active pour cet utilisateur
        capture_manager = self.get_user_capture_manager(user.user_id)
        capture_active = capture_manager and capture_manager.connection_active

        return dbc.Container([
            # Header avec navigation
            dbc.Row([
                dbc.Col([
                    html.H1("📊 Ultimate Network Dashboard", className="text-primary mb-0"),
                    html.P(f"👋 Bienvenue {user.username} ({user.role})", className="text-muted")
                ], width=8),
                dbc.Col([
                    dbc.ButtonGroup([
                        dbc.Button("📡 Capture", href="/capture", color="success", outline=True, size="sm"),
                        dbc.Button("📈 Analyse", href="/analysis", color="info", outline=True, size="sm"),
                        dbc.Button("⏹️ Arrêter Capture", id="dashboard-stop-btn", color="warning", outline=True,
                                  size="sm", n_clicks=0, disabled=not capture_active,
                                  style={'display': 'inline-block' if capture_active else 'none'}),
                        dbc.Button("🚪 Logout", id="logout-button", color="danger", outline=True, size="sm", n_clicks=0)
                    ])
                ], width=4, className="text-end")
            ], className="mb-4"),

            # Statistiques temps réel
            dbc.Row([
                dbc.Col([
                    html.H4("📈 Statistiques Temps Réel"),
                    html.Div(id="capture-status-dashboard", className="mb-2"),
                    dbc.Row(id='user-stats-cards', className="mb-4")
                ])
            ]),

            # Graphique de débit moyen au cours du temps
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("📈 Débit Moyen du Réseau au Cours du Temps"),
                        dbc.CardBody([
                            dcc.Graph(id='throughput-time-chart', style={'height': '400px'})
                        ])
                    ])
                ], width=12)
            ], className="mb-4"),

            # Graphique de trafic
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("📊 Analyse du Trafic"),
                        dbc.CardBody([
                            dcc.Graph(id='traffic-chart', style={'height': '400px'})
                        ])
                    ])
                ], width=12)
            ], className="mb-4"),



                        dbc.Row([
                            dbc.Col([
                                dbc.Card([
                                    dbc.CardHeader("🌐 Top 5 IP Sources les plus actives"),
                                    dbc.CardBody([
                                        dcc.Graph(id='top-ips-chart', style={'height': '350px'})
                                    ])
                                ])
                            ], width=12)
                        ], className="mb-4"),

            # Flows en temps réel
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader([
                            html.H5("🌊 Flows Réseau en Temps Réel", className="mb-0")
                        ]),
                        dbc.CardBody([
                            html.Div(id='flows-live-table')
                        ])
                    ])
                ])
            ]),

            # Modal pour détails flow
            dbc.Modal([
                dbc.ModalHeader("🔍 Détails du Flow"),
                dbc.ModalBody(id='flow-details-content'),
                dbc.ModalFooter([
                    dbc.Button("Fermer", id="close-details-btn", color="secondary")
                ])
            ], id="flow-details-modal", size="lg"),

            # Actualisation automatique (handled by main layout)
            # Note: main-interval is defined in the main layout
        ], fluid=True)

    def capture_page(self, user):
        return dbc.Container([
            # Header
            dbc.Row([
                dbc.Col([
                    html.H1("📡 Configuration de Capture SSH", className="text-primary"),
                    html.A("← Retour dashboard", href="/dashboard", className="btn btn-outline-secondary btn-sm")
                ])
            ], className="mb-4"),

            # Configuration SSH
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("⚙️ Configuration SSH"),
                        dbc.CardBody([
                            dbc.Row([
                                dbc.Col([
                                    dbc.Label("🖥️ Hostname/IP"),
                                    dbc.Input(
                                        id="hostname-input",
                                        placeholder="ex: 15.188.161.38",
                                        value="15.188.161.38",
                                        type="text"
                                    )
                                ], width=4),
                                dbc.Col([
                                    dbc.Label("👤 Username"),
                                    dbc.Input(
                                        id="username-input-ssh",
                                        placeholder="ex: ubuntu",
                                        value="ubuntu",
                                        type="text"
                                    )
                                ], width=4),
                                dbc.Col([
                                    dbc.Label("🔑 Clé SSH"),
                                    dcc.Upload(
                                        id='upload-key',
                                        children=html.Div([
                                            '📁 Glissez votre clé .pem ou ',
                                            html.A('cliquez ici')
                                        ]),
                                        style={
                                            'width': '100%', 'height': '60px', 'lineHeight': '60px',
                                            'borderWidth': '2px', 'borderStyle': 'dashed',
                                            'borderRadius': '5px', 'textAlign': 'center',
                                            'backgroundColor': '#f8f9fa', 'cursor': 'pointer'
                                        },
                                        multiple=False
                                    ),
                                    html.Div(id='key-file-status', className="mt-2")
                                ], width=4)
                            ], className="mb-3"),

                            dbc.Row([
                                dbc.Col([
                                    dbc.Button("🔍 Tester Connexion", id="test-ssh-btn", color="info", n_clicks=0),
                                    html.Div(id="connection-status", className="mt-2")
                                ], width=12)
                            ])
                        ])
                    ])
                ])
            ], className="mb-4"),

            # Configuration capture
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("📡 Configuration de Capture"),
                        dbc.CardBody([
                            dbc.Row([
                                dbc.Col([
                                    dbc.Label("🌐 Interfaces Réseau"),
                                    dbc.Checklist(
                                        id="interfaces-checklist",
                                        options=[],
                                        value=[],
                                        inline=False
                                    ),
                                    html.Small("💡 Aucune sélection = toutes les interfaces", className="text-muted")
                                ], width=6),
                                dbc.Col([
                                    dbc.Label("🔍 Filtres tcpdump"),
                                    dbc.Input(
                                        id="filters-input",
                                        placeholder="ex: tcp and port 80",
                                        type="text"
                                    ),
                                    html.Small("💡 tcp, udp, port 80, host 192.168.1.1...", className="text-muted")
                                ], width=6)
                            ], className="mb-3"),

                            # Contrôles de capture
                            dbc.Row([
                                dbc.Col([
                                    dbc.ButtonGroup([
                                        dbc.Button("🚀 Démarrer", id="start-capture-btn", color="success", disabled=True,
                                                   n_clicks=0),
                                        dbc.Button("⏹️ Arrêter", id="stop-capture-btn", color="danger", disabled=True,
                                                   n_clicks=0),
                                        dbc.Button("🗑️ Clear", color="warning", disabled=False)
                                    ])
                                ], width=6),
                                dbc.Col([
                                    html.Div(id="capture-status-display")
                                ], width=6)
                            ])
                        ])
                    ])
                ])
            ])
        ], fluid=True)

    def analysis_page(self, user):
        # Vérifier si une capture est active pour cet utilisateur
        capture_manager = self.get_user_capture_manager(user.user_id)
        capture_active = capture_manager and capture_manager.connection_active

        return dbc.Container([
            # Store pour les flows sélectionnés
            dcc.Store(id="analysis-selected-flows", data=[]),

            # Modal de confirmation d'export
            dbc.Modal([
                dbc.ModalHeader("Confirmation d'export"),
                dbc.ModalBody("Êtes-vous sûr de vouloir exporter les flows sélectionnés pour le réentraînement?"),
                dbc.ModalFooter([
                    dbc.Button("Annuler", id="analysis-cancel-export", className="me-2"),
                    dbc.Button("Exporter", id="analysis-confirm-export", color="success")
                ])
            ], id="analysis-export-modal"),

            # Header avec navigation
            dbc.Row([
                dbc.Col([
                    html.H1("📈 Analyse ML Avancée", className="text-primary"),
                    html.A("← Retour dashboard", href="/dashboard", className="btn btn-outline-secondary btn-sm mb-4")
                ], width=8),
                dbc.Col([
                    dbc.Button("⏹️ Arrêter Capture", id="analysis-stop-btn", color="warning", outline=True,
                              size="sm", n_clicks=0, disabled=not capture_active,
                              style={'display': 'inline-block' if capture_active else 'none'}),
                    dbc.Button("📤 Exporter Sélection", id="analysis-export-btn", color="success", outline=True,
                              size="sm", className="ms-2"),
                    html.A("🔄 Flows Signalés", href="/reported-flows", className="btn btn-outline-info btn-sm ms-2")
                ], width=4, className="text-end")
            ], className="mb-4"),

            # Statut de la capture
            html.Div(id="capture-status-analysis", className="mb-2"),

            # Flows terminés avec features ML
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("🤖 Flows Terminés avec Features ML"),
                        dbc.CardBody([
                            html.Div(id="terminated-flows-content")
                        ])
                    ])
                ])
            ], className="mb-4"),

            # Explication des features
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("🔍 Explication des Features"),
                        dbc.CardBody([
                            html.P("📊 Prêt pour classification des flows réseau"),

                            dbc.Alert([
                                html.Strong("🎯 Features extraites:"), html.Br(),
                                "• total_bytes: Nombre total d'octets dans le flow", html.Br(),
                                "• pkt_count: Nombre total de paquets", html.Br(),
                                "• psh_count: Nombre de flags PSH", html.Br(),
                                "• fwd_bytes: Octets dans la direction forward", html.Br(),
                                "• bwd_bytes: Octets dans la direction backward", html.Br(),
                                "• fwd_pkts: Paquets dans la direction forward", html.Br(),
                                "• bwd_pkts: Paquets dans la direction backward", html.Br(),
                                "• dport: Port de destination", html.Br(),
                                "• duration_ms: Durée du flow en millisecondes", html.Br(),
                                "• flow_pkts_per_s: Paquets par seconde", html.Br(),
                                "• fwd_bwd_ratio: Ratio forward/backward"
                            ], color="info")
                        ])
                    ])
                ])
            ])
        ], fluid=True)

    def reported_flows_page(self, user):
        """Page for managing reported flows for retraining"""
        return dbc.Container([
            # Header avec navigation
            dbc.Row([
                dbc.Col([
                    html.H1("🔄 Flows Signalés pour Réentraînement", className="text-primary"),
                    html.A("← Retour analyse", href="/analysis", className="btn btn-outline-secondary btn-sm mb-4")
                ], width=8),
                dbc.Col([
                    html.Div(id="export-status")
                ], width=4, className="text-end")
            ], className="mb-4"),

            # Filtres
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("🔍 Filtres"),
                        dbc.CardBody([
                            dbc.Row([
                                dbc.Col([
                                    dbc.Label("Type de prédiction"),
                                    dbc.Select(
                                        id="prediction-filter",
                                        options=[
                                            {"label": "Tous", "value": "all"},
                                            {"label": "Normal", "value": "Normal"},
                                            {"label": "Mal", "value": "Mal"}
                                        ],
                                        value="all"
                                    )
                                ], width=6),
                                dbc.Col([
                                    dbc.Label("Limite"),
                                    dbc.Input(
                                        id="limit-input",
                                        type="number",
                                        min=1,
                                        max=1000,
                                        value=100
                                    )
                                ], width=6)
                            ]),
                            dbc.Button(
                                "🔄 Rafraîchir",
                                id="refresh-reported-flows",
                                color="primary",
                                className="mt-3"
                            )
                        ])
                    ])
                ])
            ], className="mb-4"),

            # Tableau des flows signalés
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader([
                            html.Div([
                                html.Span("📋 Flows Signalés", className="me-auto"),
                                dbc.Button(
                                    "📤 Exporter Sélection",
                                    id="export-selected-btn",
                                    color="success",
                                    className="ms-2"
                                )
                            ], className="d-flex justify-content-between align-items-center")
                        ]),
                        dbc.CardBody([
                            html.Div(id="reported-flows-table")
                        ])
                    ])
                ])
            ]),

            # Modal de confirmation d'export
            dbc.Modal([
                dbc.ModalHeader("Confirmation d'export"),
                dbc.ModalBody("Êtes-vous sûr de vouloir exporter les flows sélectionnés pour le réentraînement?"),
                dbc.ModalFooter([
                    dbc.Button("Annuler", id="cancel-export", className="me-2"),
                    dbc.Button("Exporter", id="confirm-export", color="success")
                ])
            ], id="export-confirmation-modal"),

            # Store pour les flows sélectionnés
            dcc.Store(id="selected-flows", data=[])
        ], fluid=True)

    def run(self, debug=True, port=8050):
        print("🚀" + "=" * 60)
        print("🌟 ULTIMATE NETWORK ANALYZER LAUNCHED!")
        print("=" * 62)
        print(f"📱 Interface Web    : http://localhost:{port}")
        print(f"🔐 Login Admin     : admin / admin123")
        print(f"👤 Multi-users     : ✅ Sessions sécurisées")
        print(f"📡 Capture SSH     : ✅ Temps réel distant")
        print(f"🌊 Flow Analysis   : ✅ Agrégation intelligente")
        print(f"🤖 ML Features     : ✅ CIC-IDS2017 auto-extract")
        print(f"📊 Dashboard Live  : ✅ Graphiques temps réel")
        print("=" * 62)
        print("🎯 Ready for professional network analysis!")

        self.app.run(debug=debug, port=port, host='0.0.0.0')


# Script de lancement
if __name__ == "__main__":
    app = UltimateNetworkApp()
    app.run(debug=True, port=8050)
