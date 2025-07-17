# models_and_managers.py
import hashlib
import uuid
import threading
import time
import statistics
import queue
from datetime import datetime, timedelta
from dataclasses import dataclass
from typing import Dict, Optional
from alerting import process_new_flow_for_alerting


@dataclass
class User:
    user_id: str
    username: str
    email: str
    password_hash: str
    created_at: datetime
    last_login: Optional[datetime] = None
    is_active: bool = True
    role: str = 'user'


@dataclass
class UserSession:
    session_id: str
    user_id: str
    username: str
    created_at: datetime
    last_activity: datetime
    ip_address: str
    expires_at: datetime


class UserManager:
    def __init__(self, session_timeout_hours=24):
        self.users: Dict[str, User] = {}
        self.usernames: Dict[str, str] = {}
        self.sessions: Dict[str, UserSession] = {}
        self.session_timeout = timedelta(hours=session_timeout_hours)
        self.lock = threading.Lock()
        self._create_default_admin()

    def _create_default_admin(self):
        admin_id = str(uuid.uuid4())
        password_hash = hashlib.sha256("admin123".encode()).hexdigest()

        admin = User(
            user_id=admin_id,
            username="admin",
            email="admin@localhost",
            password_hash=password_hash,
            created_at=datetime.now(),
            role="admin"
        )

        self.users[admin_id] = admin
        self.usernames["admin"] = admin_id
        print("👑 Admin créé - Username: admin, Password: admin123")

    def authenticate(self, username: str, password: str, ip_address: str = "unknown") -> Optional[str]:
        with self.lock:
            if username not in self.usernames:
                return None

            user_id = self.usernames[username]
            user = self.users[user_id]

            password_hash = hashlib.sha256(password.encode()).hexdigest()
            if user.password_hash != password_hash or not user.is_active:
                return None

            session_id = str(uuid.uuid4())
            now = datetime.now()

            session = UserSession(
                session_id=session_id,
                user_id=user_id,
                username=username,
                created_at=now,
                last_activity=now,
                ip_address=ip_address,
                expires_at=now + self.session_timeout
            )

            self.sessions[session_id] = session
            user.last_login = now
            return session_id

    def get_user_by_session(self, session_id: str) -> Optional[User]:
        with self.lock:
            if session_id not in self.sessions:
                return None

            session = self.sessions[session_id]
            now = datetime.now()

            if now > session.expires_at:
                del self.sessions[session_id]
                return None

            session.last_activity = now
            return self.users.get(session.user_id)

    def register_user(self, username: str, email: str, password: str, role: str = "user") -> bool:
        with self.lock:
            if username in self.usernames:
                return False

            user_id = str(uuid.uuid4())
            password_hash = hashlib.sha256(password.encode()).hexdigest()

            user = User(
                user_id=user_id,
                username=username,
                email=email,
                password_hash=password_hash,
                created_at=datetime.now(),
                role=role
            )

            self.users[user_id] = user
            self.usernames[username] = user_id
            return True

    def logout(self, session_id: str) -> bool:
        with self.lock:
            if session_id in self.sessions:
                del self.sessions[session_id]
                return True
            return False


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
        # Import local pour éviter import circulaire
        from network_utils import predict_flow

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
        # Import local pour éviter import circulaire
        from network_utils import predict_flow

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
        # méthode pour passez les flows qui ne se sont pas fini depuis longtemps en terminated
        # self.check_timeouts()

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
