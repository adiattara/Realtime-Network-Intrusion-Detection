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


# =====================================
# SYSTÈME MULTI-UTILISATEURS INTÉGRÉ
# =====================================

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


# =====================================
# FLOW AGGREGATOR INTÉGRÉ
# =====================================

class FlowAggregator:
    def __init__(self, flow_timeout=60, cleanup_interval=30):
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

    def get_active_flows(self, limit=100):
        with self.lock:
            flows = list(self.flows.values())
            flows.sort(key=lambda x: x['last_activity'], reverse=True)
            return flows[:limit]

    def get_terminated_flows(self, limit=100):
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
    def __init__(self, user_id):
        self.user_id = user_id
        self.flow_aggregator = FlowAggregator(flow_timeout=30, cleanup_interval=10)
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
        self.user_manager = UserManager()
        self.user_captures: Dict[str, UserCaptureManager] = {}

        self.app = dash.Dash(__name__, external_stylesheets=[dbc.themes.BOOTSTRAP],suppress_callback_exceptions=True)
        self.app.server.secret_key = secrets.token_hex(32)
        self.app.config.suppress_callback_exceptions = True

        self.setup_layout()
        self.setup_callbacks()

    def get_user_capture_manager(self, session_id):
        user = self.user_manager.get_user_by_session(session_id)
        if not user:
            return None

        if user.user_id not in self.user_captures:
            self.user_captures[user.user_id] = UserCaptureManager(user.user_id)

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
            if not session_data or pathname != '/analysis':
                return no_update, no_update, no_update, no_update

            capture_manager = self.get_user_capture_manager(session_data['session_id'])
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

            # Récupérer les flows terminés
            terminated_flows = capture_manager.flow_aggregator.get_terminated_flows(limit=50)

            if not terminated_flows:
                terminated_flows_content = dbc.Alert("Aucun flow terminé disponible", color="info")
            else:
                # Créer une liste de cartes pour chaque flow terminé
                flow_cards = []
                for flow in terminated_flows:
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

                    # Créer une carte pour ce flow
                    flow_card = dbc.Card([
                        dbc.CardHeader(f"Flow: {flow.get('src_ip', 'Unknown')}:{flow.get('sport', 0)} → {flow.get('dst_ip', 'Unknown')}:{flow.get('dport', 0)} ({flow.get('protocol', 'Unknown')})"),
                        dbc.CardBody([
                            html.H6("ML Features:"),
                            html.Pre(json.dumps(ml_features, indent=2),
                                    style={'background-color': '#f8f9fa', 'padding': '10px', 'border-radius': '5px'})
                        ])
                    ], className="mb-3")

                    flow_cards.append(flow_card)

                terminated_flows_content = html.Div(flow_cards)

            return capture_status, stop_btn_disabled, stop_btn_style, terminated_flows_content

        # Dashboard Updates
        @callback(
            [Output('user-stats-cards', 'children'),
             Output('flows-live-table', 'children'),
             Output('traffic-chart', 'figure'),
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
                return [], html.P("Session expirée"), go.Figure(), no_update, no_update, no_update

            capture_manager = self.get_user_capture_manager(session_data['session_id'])
            if not capture_manager:
                return [], html.P("Erreur utilisateur"), go.Figure(), no_update, no_update, no_update

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
                return no_update, no_update, no_update, no_update, no_update, no_update

            # Statistiques utilisateur
            stats = capture_manager.flow_aggregator.get_statistics()
            user = self.user_manager.get_user_by_session(session_data['session_id'])

            stats_cards = [
                self.create_stat_card("📊 Paquets", stats['total_packets_processed'], 'primary'),
                self.create_stat_card("🔄 Flows Actifs", stats['active_flows'], 'success'),
                self.create_stat_card("✅ Terminés", stats['completed_flows'], 'info'),
                self.create_stat_card("👤 " + (user.username if user else "Unknown"),
                                      user.role if user else "unknown", 'secondary')
            ]

            # Table des flows en temps réel
            active_flows = capture_manager.flow_aggregator.get_active_flows(limit=30)
            flows_table = self.create_live_flows_table(active_flows)

            # Graphique du trafic
            traffic_fig = self.create_traffic_chart(active_flows)

            # Mise à jour du statut de capture dans le dashboard
            capture_active = capture_manager.connection_active

            if capture_active:
                capture_status = dbc.Alert("🟢 Capture en cours - Données en temps réel", color="success")
                stop_btn_disabled = False
                stop_btn_style = {'display': 'inline-block'}
            else:
                capture_status = dbc.Alert("⚪ Aucune capture active", color="secondary")
                stop_btn_disabled = True
                stop_btn_style = {'display': 'none'}

            return stats_cards, flows_table, traffic_fig, capture_status, stop_btn_disabled, stop_btn_style

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
            prevent_initial_call=True
        )
        def enable_interval_on_dashboard(pathname):
            return pathname not in ['/dashboard', '/analysis']  # False = actif, True = désactivé

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
        if not flows:
            return dbc.Alert("📭 Aucun flow actif", color="info")

        # Préparer les données pour le tableau
        table_data = []
        for flow in flows[-20:]:  # 20 derniers flows
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
                'status': flow.get('status', 'unknown')
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
                {'name': 'État', 'id': 'status'}
            ],
            style_cell={'textAlign': 'left', 'fontSize': '11px', 'padding': '5px'},
            style_header={'backgroundColor': 'rgb(230, 230, 230)', 'fontWeight': 'bold'},
            style_data_conditional=[
                {
                    'if': {'filter_query': '{status} = active'},
                    'backgroundColor': '#e8f5e8',
                },
                {
                    'if': {'filter_query': '{status} = terminated'},
                    'backgroundColor': '#ffe8e8',
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
            # Header avec navigation
            dbc.Row([
                dbc.Col([
                    html.H1("📈 Analyse ML Avancée", className="text-primary"),
                    html.A("← Retour dashboard", href="/dashboard", className="btn btn-outline-secondary btn-sm mb-4")
                ], width=8),
                dbc.Col([
                    dbc.Button("⏹️ Arrêter Capture", id="analysis-stop-btn", color="warning", outline=True,
                              size="sm", n_clicks=0, disabled=not capture_active,
                              style={'display': 'inline-block' if capture_active else 'none'})
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
                            html.P("🔬 Features CIC-IDS2017 extraites automatiquement"),
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
