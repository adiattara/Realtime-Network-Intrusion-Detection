import dash
from dash import dcc, html, Input, Output, dash_table, callback_context, State
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
import paramiko
import threading
import time
from datetime import datetime
import queue
import re
import base64
from collections import defaultdict
import dash_bootstrap_components as dbc

# Configuration SSH par défaut
DEFAULT_SSH_CONFIG = {
    'hostname': "",
    'username': "ubuntu",
    'key_file': ""
}

# Variables globales
packet_queue = queue.Queue()
flow_queue = queue.Queue()  # Nouvelle queue pour les flows
connection_active = False
ssh_client = None
ssh_thread = None
packet_data = []
flow_data = []  # Nouvelle liste pour les flows
protocol_stats = defaultdict(int)
ip_stats = defaultdict(int)
available_interfaces = []
connection_tested = False

# Import de notre classe FlowAggregator après les variables globales
try:
    from flow_aggregator import FlowAggregator, extract_cic_features

    # Agrégateur de flows global
    flow_aggregator = FlowAggregator(flow_timeout=30, cleanup_interval=10)
except ImportError:
    print("ERREUR: Le fichier flow_aggregator.py est manquant !")
    print("Veuillez créer le fichier flow_aggregator.py dans le même dossier.")
    exit(1)


def test_ssh_connection(hostname, username, key_file):
    """Test la connexion SSH et récupère les interfaces disponibles"""
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname=hostname, username=username, key_filename=key_file, timeout=10)

        # Récupérer les interfaces réseau
        stdin, stdout, stderr = client.exec_command("ip link show | grep '^[0-9]' | awk '{print $2}' | sed 's/://'")
        interfaces = [line.strip() for line in stdout.readlines() if line.strip()]

        client.close()
        return True, interfaces, "Connexion réussie !"
    except Exception as e:
        return False, [], f"Erreur de connexion : {str(e)}"


def flags_to_int(flags_str: str) -> int:
    """
    Convertit la chaîne de drapeaux tcpdump (ex: 'P.')
    en son équivalent numérique (F=1, S=2, R=4, P=8, .=16, U=32, E=64, C=128).
    """
    mapping = {
        'F': 1,  # FIN
        'S': 2,  # SYN
        'R': 4,  # RST
        'P': 8,  # PSH
        '.': 16,  # ACK
        'U': 32,  # URG
        'E': 64,  # ECE
        'C': 128,  # CWR
    }
    val = 0
    for ch in flags_str:
        if ch in mapping:
            val |= mapping[ch]
    return val


def parse_tcpdump_line(line, current_ts=None):
    """
    Parse une ligne de tcpdump avec votre parser robuste et éprouvé
    Retourne (packet_info, new_current_ts) ou (None, new_current_ts)
    """
    try:
        # Regex pour détecter la ligne IP (10 chiffres + point + 6 décimales, puis " IP ")
        header_re = re.compile(r'^(?P<timestamp>\d{10}\.\d{6}).*\sIP\s')

        # Regex pour la ligne TCP
        tcp_re = re.compile(
            r'(?P<src_ip>\d+\.\d+\.\d+\.\d+)\.(?P<src_port>\d+)\s+>\s+'
            r'(?P<dst_ip>\d+\.\d+\.\d+\.\d+)\.(?P<dst_port>\d+):\s+'
            r'Flags\s+\[(?P<flags>[^\]]+)\].*?length\s+(?P<length>\d+)'
        )

        # Regex pour la ligne UDP
        udp_re = re.compile(
            r'(?P<src_ip>\d+\.\d+\.\d+\.\d+)\.(?P<src_port>\d+)\s+>\s+'
            r'(?P<dst_ip>\d+\.\d+\.\d+\.\d+)\.(?P<dst_port>\d+):\s+'
            r'UDP,\s+length\s+(?P<length>\d+)'
        )

        # 1) Détection de la ligne IP header
        m_hdr = header_re.match(line)
        if m_hdr:
            return None, m_hdr.group('timestamp')

        # 2) Si on a un timestamp en mémoire, tenter le parsing transport
        if current_ts:
            # TCP ?
            m_tcp = tcp_re.search(line)
            if m_tcp:
                gd = m_tcp.groupdict()
                packet_info = {
                    "timestamp": datetime.fromtimestamp(float(current_ts)),
                    "src_ip": gd["src_ip"],
                    "dst_ip": gd["dst_ip"],
                    "protocol": "TCP",
                    "sport": int(gd["src_port"]),
                    "dport": int(gd["dst_port"]),
                    "port": int(gd["dst_port"]),  # Pour compatibilité avec l'interface
                    "flags": flags_to_int(gd["flags"]),
                    "flags_str": gd["flags"],
                    "length": int(gd["length"]),
                    "payload_len": int(gd["length"]),
                    "proto_num": 6,
                    "raw": line.strip()
                }
                return packet_info, None

            # UDP ?
            m_udp = udp_re.search(line)
            if m_udp:
                gd = m_udp.groupdict()
                packet_info = {
                    "timestamp": datetime.fromtimestamp(float(current_ts)),
                    "src_ip": gd["src_ip"],
                    "dst_ip": gd["dst_ip"],
                    "protocol": "UDP",
                    "sport": int(gd["src_port"]),
                    "dport": int(gd["dst_port"]),
                    "port": int(gd["dst_port"]),  # Pour compatibilité avec l'interface
                    "flags": 0,
                    "flags_str": "",
                    "length": int(gd["length"]),
                    "payload_len": int(gd["length"]),
                    "proto_num": 17,
                    "raw": line.strip()
                }
                return packet_info, None

        # Pas de match ou pas de timestamp
        return None, None

    except Exception as e:
        # En cas d'erreur, retourner une entrée d'erreur
        error_packet = {
            'timestamp': datetime.now(),
            'protocol': 'PARSE_ERROR',
            'src_ip': 'Unknown',
            'dst_ip': 'Unknown',
            'port': 0,
            'sport': 0,
            'dport': 0,
            'flags': 0,
            'flags_str': '',
            'length': 0,
            'payload_len': 0,
            'proto_num': 0,
            'raw': line.strip(),
            'error': str(e)
        }
        return error_packet, None


def ssh_capture_thread(hostname, username, key_file, interface_str, filters):
    """Thread pour la capture SSH en arrière-plan avec agrégation de flows"""
    global connection_active, ssh_client, flow_aggregator

    try:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(hostname=hostname, username=username, key_filename=key_file)

        # Gérer les interfaces multiples
        if "," in interface_str:
            tcpdump_cmd = f"sudo tcpdump -i any -nn -l -tt -v {filters}"
        else:
            tcpdump_cmd = f"sudo tcpdump -i {interface_str} -nn -l -tt -v {filters}"

        stdin, stdout, stderr = ssh_client.exec_command(tcpdump_cmd, get_pty=True)
        connection_active = True

        current_ts = None  # Timestamp en cours de traitement

        for raw_line in stdout:
            if not connection_active:
                break

            line = raw_line.strip()
            packet_info, new_ts = parse_tcpdump_line(line, current_ts)

            # Mettre à jour le timestamp courant
            if new_ts:
                current_ts = new_ts

            # Si on a un paquet valide
            if packet_info:
                # Ajouter l'information sur l'interface
                if "," in interface_str:
                    interface_match = re.search(r'\[([^\]]+)\]', line)
                    packet_info['interface'] = interface_match.group(1) if interface_match else "unknown"
                else:
                    packet_info['interface'] = interface_str

                # NOUVEAU: Traiter le paquet avec l'agrégateur de flows
                flow = flow_aggregator.process_packet(packet_info)

                if flow:
                    # Envoyer le flow mis à jour dans la queue
                    flow_queue.put(flow)

                current_ts = None  # Reset après traitement

    except Exception as e:
        flow_queue.put({
            'error': str(e),
            'flow_key': 'ERROR',
            'status': 'error',
            'timestamp': datetime.now().isoformat()
        })
        connection_active = False
    finally:
        if ssh_client:
            ssh_client.close()


# Initialisation de l'application Dash
app = dash.Dash(__name__, external_stylesheets=[dbc.themes.BOOTSTRAP])

# Layout de l'application
app.layout = dbc.Container([
    dbc.Row([
        dbc.Col([
            html.H1("🌐 Analyseur de Trafic Réseau Avancé",
                    className="text-center mb-4 text-primary"),
            html.Hr()
        ])
    ]),

    # Configuration SSH
    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardHeader([
                    html.H5("⚙️ Configuration SSH", className="mb-0")
                ]),
                dbc.CardBody([
                    dbc.Row([
                        dbc.Col([
                            dbc.Label("🖥️ Adresse IP/Hostname"),
                            dbc.Input(
                                id="hostname-input",
                                placeholder="ex: 15.188.161.38",
                                value="",
                                type="text"
                            )
                        ], width=4),
                        dbc.Col([
                            dbc.Label("👤 Nom d'utilisateur"),
                            dbc.Input(
                                id="username-input",
                                placeholder="ex: ubuntu",
                                value="ubuntu",
                                type="text"
                            )
                        ], width=4),
                        dbc.Col([
                            dbc.Label("🔑 Fichier de clé SSH"),
                            dcc.Upload(
                                id='upload-key',
                                children=html.Div([
                                    '🔑 Glissez-déposez votre clé SSH (.pem) ou ',
                                    html.A('cliquez ici pour sélectionner',
                                           style={'color': '#007bff', 'cursor': 'pointer',
                                                  'text-decoration': 'underline'})
                                ]),
                                style={
                                    'width': '100%',
                                    'height': '70px',
                                    'lineHeight': '70px',
                                    'borderWidth': '2px',
                                    'borderStyle': 'dashed',
                                    'borderRadius': '8px',
                                    'borderColor': '#007bff',
                                    'textAlign': 'center',
                                    'margin': '5px 0',
                                    'background-color': '#f8f9fa',
                                    'cursor': 'pointer',
                                    'transition': 'all 0.3s ease'
                                },
                                # Permettre un seul fichier
                                multiple=False,
                                accept='.pem,.key,.txt'
                            ),
                            html.Div(id='key-file-status', style={'font-size': '12px', 'margin-top': '5px'})
                        ], width=4)
                    ], className="mb-3"),

                    dbc.Row([
                        dbc.Col([
                            dbc.Button("🔍 Tester Connexion", id="test-btn", color="info", className="me-2"),
                            dbc.Button("🔄 Rafraîchir Interfaces", id="refresh-interfaces-btn", color="secondary",
                                       disabled=True)
                        ], width=6),
                        dbc.Col([
                            html.Div(id="connection-status")
                        ], width=6)
                    ])
                ])
            ])
        ])
    ], className="mb-4"),

    # Configuration de capture
    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardHeader([
                    html.H5("📡 Configuration de Capture", className="mb-0")
                ]),
                dbc.CardBody([
                    dbc.Row([
                        dbc.Col([
                            dbc.Label("🌐 Interface(s) Réseau"),
                            html.Div([
                                dbc.Checklist(
                                    id="interface-checklist",
                                    options=[],
                                    value=[],
                                    inline=False,
                                    style={'max-height': '150px', 'overflow-y': 'auto'}
                                ),
                                html.Div([
                                    dbc.Button("✅ Tout sélectionner", id="select-all-btn", color="success", size="sm",
                                               className="me-2"),
                                    dbc.Button("❌ Tout désélectionner", id="deselect-all-btn", color="warning",
                                               size="sm")
                                ], className="mt-2")
                            ], id="interface-selection-div", style={'display': 'none'}),
                            html.Small("💡 Aucune sélection = écoute toutes les interfaces (any)",
                                       className="text-muted mt-1")
                        ], width=4),
                        dbc.Col([
                            dbc.Label("🔍 Filtres tcpdump"),
                            dbc.InputGroup([
                                dbc.Input(
                                    id="filters-input",
                                    placeholder="Exemples: port 80, host 192.168.1.1, tcp and port 443",
                                    value="",
                                    type="text"
                                ),
                                dbc.Button("💡", id="filter-help-btn", color="info", outline=True)
                            ]),
                            dbc.Collapse([
                                dbc.Card([
                                    dbc.CardBody([
                                        html.H6("💡 Exemples de filtres tcpdump :"),
                                        html.Ul([
                                            html.Li("tcp - Seulement TCP"),
                                            html.Li("udp - Seulement UDP"),
                                            html.Li("port 80 - Port 80 seulement"),
                                            html.Li("host 192.168.1.1 - Trafic avec cette IP"),
                                            html.Li("tcp and port 443 - HTTPS"),
                                            html.Li("icmp - Ping et autres ICMP"),
                                            html.Li("not port 22 - Exclure SSH"),
                                        ])
                                    ])
                                ])
                            ], id="filter-help-collapse", is_open=False)
                        ], width=4),
                        dbc.Col([
                            dbc.Label("📊 Limite de paquets"),
                            dbc.Input(
                                id="packet-limit-input",
                                placeholder="1000",
                                value="1000",
                                type="number",
                                min=100,
                                max=10000,
                                step=100
                            )
                        ], width=4)
                    ], className="mb-3"),

                    dbc.Row([
                        dbc.Col([
                            dbc.ButtonGroup([
                                dbc.Button("🚀 Démarrer Capture", id="start-btn", color="success", disabled=True),
                                dbc.Button("⏹️ Arrêter Capture", id="stop-btn", color="danger", disabled=True),
                                dbc.Button("🗑️ Vider Cache", id="clear-btn", color="warning", disabled=False)
                            ])
                        ], width=6),
                        dbc.Col([
                            html.Div(id="capture-status")
                        ], width=6)
                    ])
                ])
            ])
        ])
    ], className="mb-4"),

    # Statistiques en temps réel
    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.H5("📈 Statistiques en Temps Réel", className="card-title"),
                    html.Div(id="live-stats")
                ])
            ])
        ])
    ], className="mb-4"),

    # Top IPs et Ports
    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.H5("🏆 Top 10 IPs Sources", className="card-title"),
                    html.Div(id="top-ips-table")
                ])
            ])
        ], width=6),

        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.H5("🔌 Analyse des Ports", className="card-title"),
                    dcc.Graph(id="ports-chart")
                ])
            ])
        ], width=6)
    ], className="mb-4"),

    # Table des flows réseau
    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.H5("🌊 Flows Réseau (Conversations)", className="card-title"),
                    html.Div(id="flows-table")
                ])
            ])
        ])
    ], className="mb-4"),

    # Log des flows et statistiques
    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.H5("📊 Statistiques des Flows", className="card-title"),
                    html.Div(id="flow-stats")
                ])
            ])
        ], width=6),
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.H5("🔍 Détails Flow Sélectionné", className="card-title"),
                    html.Div(id="flow-details")
                ])
            ])
        ], width=6)
    ]),

    # Composant pour les mises à jour automatiques
    dcc.Interval(
        id='interval-component',
        interval=1000,
        n_intervals=0,
        disabled=True
    ),

    # Store pour sauvegarder les données
    dcc.Store(id='interfaces-store', data=[]),
    dcc.Store(id='ssh-config-store', data=DEFAULT_SSH_CONFIG),
    dcc.Store(id='ssh-key-content', data=None),
    dcc.Store(id='ssh-key-filename', data=None)
], fluid=True)


# Callback pour l'aide des filtres
@app.callback(
    Output("filter-help-collapse", "is_open"),
    [Input("filter-help-btn", "n_clicks")],
    [State("filter-help-collapse", "is_open")],
)
def toggle_filter_help(n, is_open):
    if n:
        return not is_open
    return is_open


# Callback pour gérer l'upload du fichier de clé
@app.callback(
    [Output('key-file-status', 'children'),
     Output('ssh-key-content', 'data'),
     Output('ssh-key-filename', 'data')],
    [Input('upload-key', 'contents')],
    [State('upload-key', 'filename')]
)
def handle_key_upload(contents, filename):
    if contents is not None:
        try:
            # Décoder le contenu du fichier
            content_type, content_string = contents.split(',')
            decoded = base64.b64decode(content_string)

            # Vérifier que c'est bien une clé SSH
            decoded_str = decoded.decode('utf-8')

            # Nettoyer la clé (supprimer les espaces en trop et normaliser les retours à la ligne)
            lines = decoded_str.strip().split('\n')
            cleaned_lines = []

            for line in lines:
                line = line.strip()
                if line:  # Ignorer les lignes vides
                    cleaned_lines.append(line)

            # Reconstruire la clé avec des retours à la ligne corrects
            cleaned_key = '\n'.join(cleaned_lines) + '\n'

            # Vérifier les différents formats de clés SSH supportés
            valid_key_patterns = [
                '-----BEGIN RSA PRIVATE KEY-----',
                '-----BEGIN PRIVATE KEY-----',
                '-----BEGIN OPENSSH PRIVATE KEY-----',
                '-----BEGIN DSA PRIVATE KEY-----',
                '-----BEGIN EC PRIVATE KEY-----'
            ]

            is_valid_key = any(pattern in cleaned_key for pattern in valid_key_patterns)

            if is_valid_key:
                # Créer un fichier temporaire pour la clé
                import tempfile
                import os

                temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False)
                temp_file.write(cleaned_key)
                temp_file.close()

                # Définir les bonnes permissions (lecture seule pour le propriétaire)
                os.chmod(temp_file.name, 0o600)

                # Déterminer le type de clé
                key_type = "RSA" if "RSA PRIVATE KEY" in cleaned_key else "Autre"

                return (
                    dbc.Alert(f"✅ Clé SSH {key_type} '{filename}' chargée avec succès", color="success",
                              style={'font-size': '12px'}),
                    cleaned_key,
                    temp_file.name
                )
            else:
                return (
                    dbc.Alert(
                        "❌ Le fichier ne contient pas une clé SSH valide. Vérifiez qu'il contient '-----BEGIN ... PRIVATE KEY-----'",
                        color="danger", style={'font-size': '12px'}),
                    None,
                    None
                )
        except UnicodeDecodeError:
            return (
                dbc.Alert("❌ Impossible de lire le fichier. Assurez-vous que c'est un fichier texte (clé SSH)",
                          color="danger", style={'font-size': '12px'}),
                None,
                None
            )
        except Exception as e:
            return (
                dbc.Alert(f"❌ Erreur lors du chargement: {str(e)}", color="danger", style={'font-size': '12px'}),
                None,
                None
            )

    return "", None, None


# Callback pour tester la connexion SSH
@app.callback(
    [Output('connection-status', 'children'),
     Output('interfaces-store', 'data'),
     Output('interface-checklist', 'options'),
     Output('interface-selection-div', 'style'),
     Output('refresh-interfaces-btn', 'disabled'),
     Output('start-btn', 'disabled')],
    [Input('test-btn', 'n_clicks'),
     Input('refresh-interfaces-btn', 'n_clicks')],
    [State('hostname-input', 'value'),
     State('username-input', 'value'),
     State('ssh-key-filename', 'data')]
)
def test_connection(test_clicks, refresh_clicks, hostname, username, keyfile_path):
    global available_interfaces, connection_tested

    ctx = callback_context
    if not ctx.triggered or not hostname or not username or not keyfile_path:
        return (
            dbc.Alert("⚪ Veuillez remplir tous les champs et charger une clé SSH", color="secondary"),
            [],
            [],
            {'display': 'none'},
            True,
            True
        )

    # Test de connexion avec le fichier temporaire
    success, interfaces, message = test_ssh_connection(hostname, username, keyfile_path)

    if success:
        available_interfaces = interfaces
        connection_tested = True
        interface_options = [{'label': f"🔗 {iface}", 'value': iface} for iface in interfaces]

        return (
            dbc.Alert(f"✅ {message} - {len(interfaces)} interfaces trouvées", color="success"),
            interfaces,
            interface_options,
            {'display': 'block'},
            False,
            False
        )
    else:
        connection_tested = False
        return (
            dbc.Alert(f"❌ {message}", color="danger"),
            [],
            [],
            {'display': 'none'},
            True,
            True
        )


# Callback pour les boutons de sélection d'interfaces
@app.callback(
    Output('interface-checklist', 'value'),
    [Input('select-all-btn', 'n_clicks'),
     Input('deselect-all-btn', 'n_clicks')],
    [State('interface-checklist', 'options'),
     State('interface-checklist', 'value')]
)
def manage_interface_selection(select_all_clicks, deselect_all_clicks, options, current_value):
    ctx = callback_context
    if not ctx.triggered or not options:
        return current_value or []

    button_id = ctx.triggered[0]['prop_id'].split('.')[0]

    if button_id == 'select-all-btn' and select_all_clicks:
        # Sélectionner toutes les interfaces
        return [option['value'] for option in options]
    elif button_id == 'deselect-all-btn' and deselect_all_clicks:
        # Désélectionner toutes les interfaces
        return []

    return current_value or []


# Callback pour gérer la capture
@app.callback(
    [Output('capture-status', 'children'),
     Output('stop-btn', 'disabled'),
     Output('interval-component', 'disabled')],
    [Input('start-btn', 'n_clicks'),
     Input('stop-btn', 'n_clicks'),
     Input('clear-btn', 'n_clicks')],
    [State('hostname-input', 'value'),
     State('username-input', 'value'),
     State('ssh-key-filename', 'data'),
     State('interface-checklist', 'value'),
     State('filters-input', 'value')]
)
def manage_capture(start_clicks, stop_clicks, clear_clicks, hostname, username, keyfile_path, interfaces_selected,
                   filters):
    global connection_active, ssh_thread, packet_data, flow_data, protocol_stats, ip_stats, flow_aggregator

    ctx = callback_context
    if not ctx.triggered:
        return dbc.Alert("⚪ Prêt à démarrer", color="secondary"), True, True

    button_id = ctx.triggered[0]['prop_id'].split('.')[0]

    if button_id == 'clear-btn' and clear_clicks:
        # Vider tous les caches
        packet_data = []
        flow_data = []
        protocol_stats = defaultdict(int)
        ip_stats = defaultdict(int)

        # Nettoyer l'agrégateur de flows
        flow_aggregator.clear_all_flows()

        # Vider les queues
        while not packet_queue.empty():
            try:
                packet_queue.get_nowait()
            except queue.Empty:
                break
        while not flow_queue.empty():
            try:
                flow_queue.get_nowait()
            except queue.Empty:
                break

        return dbc.Alert("🗑️ Cache vidé - Flows et paquets supprimés", color="info"), True, True

    elif button_id == 'start-btn' and start_clicks:
        if not connection_active:
            # Gérer la sélection d'interfaces avec checkboxes
            if not interfaces_selected or len(interfaces_selected) == 0:
                # Aucune interface sélectionnée = 'any'
                interface_str = "any"
                status_msg = "🟢 Capture en cours sur TOUTES les interfaces (any)..."
            elif len(interfaces_selected) == 1:
                # Une seule interface
                interface_str = interfaces_selected[0]
                status_msg = f"🟢 Capture en cours sur {interface_str}..."
            else:
                # Plusieurs interfaces spécifiques
                interface_str = ",".join(interfaces_selected)
                status_msg = f"🟢 Capture en cours sur {len(interfaces_selected)} interfaces: {', '.join(interfaces_selected)}"

            connection_active = True
            ssh_thread = threading.Thread(
                target=ssh_capture_thread,
                args=(hostname, username, keyfile_path, interface_str, filters),
                daemon=True
            )
            ssh_thread.start()
            return dbc.Alert(status_msg, color="success"), False, False

    elif button_id == 'stop-btn' and stop_clicks:
        connection_active = False
        return dbc.Alert("🔴 Capture arrêtée", color="warning"), True, True

    return dbc.Alert("⚪ Prêt à démarrer", color="secondary"), True, True


# Callback principal pour mettre à jour le dashboard avec les flows
@app.callback(
    [Output('ports-chart', 'figure'),
     Output('flows-table', 'children'),
     Output('top-ips-table', 'children'),
     Output('flow-stats', 'children'),
     Output('live-stats', 'children')],
    [Input('interval-component', 'n_intervals')],
    [State('packet-limit-input', 'value')]
)
def update_dashboard(n, packet_limit):
    global flow_data, flow_aggregator

    # Traitement des nouveaux flows
    new_flows = []
    flow_count = 0
    while not flow_queue.empty() and flow_count < 50:
        try:
            flow = flow_queue.get_nowait()
            if 'error' not in flow:
                flow_data.append(flow)
                new_flows.append(flow)
                flow_count += 1
        except queue.Empty:
            break

    # Limiter le nombre de flows stockés
    max_flows = int(packet_limit) if packet_limit else 1000
    if len(flow_data) > max_flows:
        flow_data = flow_data[-max_flows:]

    # Obtenir les flows actifs de l'agrégateur
    active_flows = flow_aggregator.get_active_flows(limit=50)
    all_flows = active_flows + flow_data[-50:]  # Combiner actifs + récents

    # Graphique des ports
    if all_flows:
        ports_data = [f.get('dport', 0) for f in all_flows if f.get('dport', 0) > 0]
        if ports_data:
            port_counts = pd.Series(ports_data).value_counts().head(10)

            # Ajouter des labels de services connus
            port_labels = []
            service_map = {
                80: 'HTTP', 443: 'HTTPS', 22: 'SSH', 21: 'FTP', 25: 'SMTP',
                53: 'DNS', 110: 'POP3', 143: 'IMAP', 993: 'IMAPS', 995: 'POP3S'
            }

            for port in port_counts.index:
                service = service_map.get(port, '')
                label = f"{port}" + (f" ({service})" if service else "")
                port_labels.append(label)

            ports_fig = px.bar(
                x=port_labels,
                y=port_counts.values,
                title="Top 10 des ports de destination (Flows)",
                labels={'x': 'Port (Service)', 'y': 'Nombre de flows'}
            )
        else:
            ports_fig = go.Figure().add_annotation(
                text="Aucun port détecté",
                xref="paper", yref="paper", x=0.5, y=0.5
            )
    else:
        ports_fig = go.Figure().add_annotation(
            text="Aucune donnée disponible",
            xref="paper", yref="paper", x=0.5, y=0.5
        )

    # Table des flows
    if all_flows:
        flows_df = pd.DataFrame(all_flows[-30:])  # 30 derniers flows

        # Préparer les données pour l'affichage
        display_flows = []
        for flow in all_flows[-30:]:
            display_flow = {
                'flow_key': flow.get('flow_key', 'Unknown')[:50] + '...' if len(
                    flow.get('flow_key', '')) > 50 else flow.get('flow_key', 'Unknown'),
                'src_ip': flow.get('src_ip', 'Unknown'),
                'dst_ip': flow.get('dst_ip', 'Unknown'),
                'dport': flow.get('dport', 0),
                'protocol': flow.get('protocol', 'Unknown'),
                'duration_ms': round(flow.get('duration_ms', 0), 2),
                'total_bytes': flow.get('total_bytes', 0),
                'pkt_count': flow.get('pkt_count', 0),
                'status': flow.get('status', 'unknown'),
                'psh_count': flow.get('psh_count', 0),
                'ml_features': len(extract_cic_features(flow))  # Nombre de features ML extraites
            }
            display_flows.append(display_flow)

        flows_table = dash_table.DataTable(
            data=display_flows,
            columns=[
                {'name': 'Flow Key', 'id': 'flow_key'},
                {'name': 'IP Source', 'id': 'src_ip'},
                {'name': 'IP Dest', 'id': 'dst_ip'},
                {'name': 'Port Dst', 'id': 'dport'},
                {'name': 'Protocole', 'id': 'protocol'},
                {'name': 'Durée (ms)', 'id': 'duration_ms'},
                {'name': 'Bytes Total', 'id': 'total_bytes'},
                {'name': 'Paquets', 'id': 'pkt_count'},
                {'name': 'Statut', 'id': 'status'},
                {'name': 'PSH', 'id': 'psh_count'},
                {'name': 'ML Ready', 'id': 'ml_features'}
            ],
            style_cell={'textAlign': 'left', 'fontSize': '11px'},
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
            row_selectable="single",
            page_size=15,
            style_table={'overflowX': 'auto'},
            id='flows-datatable'
        )
    else:
        flows_table = html.P("Aucun flow détecté...")

    # Top IPs (basé sur les flows maintenant)
    if all_flows:
        src_ips = [f.get('src_ip', 'Unknown') for f in all_flows]
        ip_counts = pd.Series(src_ips).value_counts().head(10)
        top_ips_df = pd.DataFrame({
            'IP Source': ip_counts.index,
            'Nombre de Flows': ip_counts.values
        })
        top_ips_table = dash_table.DataTable(
            data=top_ips_df.to_dict('records'),
            columns=[
                {'name': 'IP Source', 'id': 'IP Source'},
                {'name': 'Flows', 'id': 'Nombre de Flows'}
            ],
            style_cell={'textAlign': 'left', 'fontSize': '12px'},
            style_header={'backgroundColor': 'rgb(230, 230, 230)', 'fontWeight': 'bold'}
        )
    else:
        top_ips_table = html.P("Aucune donnée disponible")

    # Statistiques des flows
    flow_stats_data = flow_aggregator.get_statistics()
    flow_stats = [
        html.H6("📊 Statistiques Agrégateur"),
        html.P(f"Paquets traités: {flow_stats_data['total_packets_processed']}"),
        html.P(f"Flows actifs: {flow_stats_data['active_flows']}"),
        html.P(f"Flows terminés: {flow_stats_data['completed_flows']}"),
        html.P(f"Flows/minute: {flow_stats_data['flows_per_minute']:.1f}"),
        html.Hr(),
        html.H6("🔬 Prêt pour ML"),
        html.P(f"Features extraites: {len(all_flows)} flows → {len(all_flows)} samples ML")
    ]

    # Statistiques en temps réel (simplifiées pour flows)
    total_flows = len(flow_data) + flow_stats_data['active_flows']

    stats = dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.H4(str(total_flows), className="text-primary"),
                    html.P("Flows Totaux", className="text-muted")
                ])
            ])
        ], width=6),
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.H4(f"{len(new_flows)}/s", className="text-warning"),
                    html.P("Nouveaux Flows", className="text-muted")
                ])
            ])
        ], width=6)
    ])

    return (ports_fig, flows_table, top_ips_table,
            flow_stats, stats)


# Callback pour afficher les détails d'un flow sélectionné
@app.callback(
    Output('flow-details', 'children'),
    [Input('flows-datatable', 'selected_rows')],
    [State('flows-datatable', 'data')]
)
def display_flow_details(selected_rows, table_data):
    if not selected_rows or not table_data:
        return html.P("Sélectionnez un flow dans le tableau pour voir les détails et features ML",
                      className="text-muted")

    try:
        selected_flow_key = table_data[selected_rows[0]]['flow_key']

        # Trouver le flow complet dans l'agrégateur
        flow = flow_aggregator.get_flow_by_key(selected_flow_key)
        if not flow:
            # Chercher dans les flows stockés
            for f in flow_data:
                if f.get('flow_key') == selected_flow_key:
                    flow = f
                    break

        if not flow:
            return html.P("Flow non trouvé", className="text-muted")

        # Extraire les features ML
        ml_features = extract_cic_features(flow)

        details = [
            html.H6("🔍 Détails Complets"),
            html.P(f"Flow Key: {flow.get('flow_key', 'Unknown')}"),
            html.P(f"Statut: {flow.get('status', 'unknown')}"),
            html.P(f"Durée: {flow.get('duration_ms', 0):.2f} ms"),
            html.P(f"Bytes Forward: {flow.get('fwd_bytes', 0)}"),
            html.P(f"Bytes Backward: {flow.get('bwd_bytes', 0)}"),
            html.P(f"Ratio Fwd/Bwd: {flow.get('fwd_bwd_ratio', 0):.3f}"),
            html.Hr(),
            html.H6("🤖 Features ML (CIC-IDS2017)"),
            html.Ol([
                html.Li(f"Destination Port: {ml_features[0]}"),
                html.Li(f"Bwd Packet Length Min: {ml_features[1]:.2f}"),
                html.Li(f"Bwd Packet Length Mean: {ml_features[2]:.2f}"),
                html.Li(f"Bwd Packets/s: {ml_features[3]:.2f}"),
                html.Li(f"Min Packet Length: {ml_features[4]:.2f}"),
                html.Li(f"PSH Flag Count: {ml_features[5]}"),
                html.Li(f"URG Flag Count: {ml_features[6]}"),
                html.Li(f"Avg Fwd Segment Size: {ml_features[7]:.2f}"),
                html.Li(f"Avg Bwd Segment Size: {ml_features[8]:.2f}"),
                html.Li(f"Min Seg Size Forward: {ml_features[9]:.2f}")
            ]),
            html.Hr(),
            dbc.Button("🔬 Tester avec Modèle ML", color="primary", size="sm", disabled=True,
                       title="Fonctionnalité à venir")
        ]

        return details

    except Exception as e:
        return html.P(f"Erreur: {str(e)}", className="text-danger")


if __name__ == '__main__':
    print("🚀 Démarrage de l'analyseur de trafic réseau avancé...")
    print("📱 Accédez à l'interface sur: http://localhost:8050")
    print("⚙️ Configurez d'abord votre connexion SSH puis testez-la")
    app.run(debug=True, host='0.0.0.0', port=8050)