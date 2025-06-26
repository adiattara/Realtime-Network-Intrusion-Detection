import time
from datetime import datetime, timedelta
from collections import defaultdict
import threading
import json
import statistics


class FlowAggregator:
    """
    Classe pour agréger les paquets réseau en flows (conversations)
    VERSION CORRIGÉE: Direction préservée, calculs précis des features CIC-IDS2017
    Compatible avec le code Dash existant (mêmes noms de fonctions/variables)
    """

    def __init__(self, flow_timeout=60, cleanup_interval=30):
        """
        Initialize the Flow Aggregator

        Args:
            flow_timeout (int): Secondes avant qu'un flow soit considéré comme terminé (défaut: 60s)
            cleanup_interval (int): Intervalle de nettoyage des flows expirés (défaut: 30s)
        """
        self.flows = {}  # Dictionnaire des flows actifs {flow_key: flow_data}
        self.completed_flows = []  # Liste des flows terminés
        self.flow_timeout = flow_timeout
        self.cleanup_interval = cleanup_interval
        self.lock = threading.Lock()  # Thread safety pour Dash
        self.last_cleanup = time.time()

        # Statistiques
        self.stats = {
            'total_packets_processed': 0,
            'active_flows': 0,
            'completed_flows': 0,
            'flows_per_minute': 0
        }

    def create_flow_key(self, packet):
        """
        Crée une clé unique pour identifier un flow (conversation)
        CORRIGÉ: Direction préservée (pas de normalisation biaisée)

        Args:
            packet (dict): Paquet réseau parsé

        Returns:
            str: Clé directionnelle du flow
        """
        src_ip = packet.get('src_ip', 'unknown')
        dst_ip = packet.get('dst_ip', 'unknown')
        sport = packet.get('sport', 0)
        dport = packet.get('dport', 0)
        protocol = packet.get('protocol', 'unknown')

        # CORRECTION: Garder la direction originale (pas de normalisation)
        return f"{src_ip}:{sport}-{dst_ip}:{dport}-{protocol}"

    def determine_direction(self, packet, flow_key):
        """
        Détermine si le paquet va dans la direction forward ou backward
        CORRIGÉ: Forward = même direction que le premier paquet du flow

        Args:
            packet (dict): Paquet réseau
            flow_key (str): Clé du flow

        Returns:
            str: 'forward' ou 'backward'
        """
        # Extraire la direction originale du flow_key
        flow_parts = flow_key.split('-')
        flow_src_part = flow_parts[0]  # "src_ip:sport"
        flow_dst_part = flow_parts[1]  # "dst_ip:dport"

        flow_src_ip = flow_src_part.split(':')[0]
        flow_dst_ip = flow_dst_part.split(':')[0]
        flow_src_port = int(flow_src_part.split(':')[1])
        flow_dst_port = int(flow_dst_part.split(':')[1])

        pkt_src_ip = packet.get('src_ip')
        pkt_dst_ip = packet.get('dst_ip')
        pkt_src_port = packet.get('sport')
        pkt_dst_port = packet.get('dport')

        # Forward = même direction que le flow original
        if (pkt_src_ip == flow_src_ip and pkt_dst_ip == flow_dst_ip and
                pkt_src_port == flow_src_port and pkt_dst_port == flow_dst_port):
            return 'forward'
        else:
            return 'backward'

    def extract_flags(self, packet):
        """
        Extrait et compte les flags TCP du paquet

        Args:
            packet (dict): Paquet réseau

        Returns:
            dict: Compteurs des flags
        """
        flags_str = packet.get('flags_str', '')
        return {
            'psh_count': 1 if 'P' in flags_str else 0,
            'urg_count': 1 if 'U' in flags_str else 0,
            'syn_count': 1 if 'S' in flags_str else 0,
            'fin_count': 1 if 'F' in flags_str else 0,
            'rst_count': 1 if 'R' in flags_str else 0,
            'ack_count': 1 if '.' in flags_str else 0
        }

    def create_new_flow(self, packet, flow_key):
        """
        Crée un nouveau flow à partir du premier paquet
        CORRIGÉ: Stockage des longueurs de paquets pour calculs précis

        Args:
            packet (dict): Premier paquet du flow
            flow_key (str): Clé unique du flow

        Returns:
            dict: Nouveau flow initialisé
        """
        direction = self.determine_direction(packet, flow_key)
        flags = self.extract_flags(packet)
        packet_length = packet.get('length', 0)

        flow = {
            'flow_key': flow_key,
            'start_ts': packet.get('timestamp', datetime.now()).isoformat(),
            'end_ts': packet.get('timestamp', datetime.now()).isoformat(),
            'first_packet_ts': time.time(),
            'last_packet_ts': time.time(),

            # Compteurs basiques
            'total_bytes': packet_length,
            'pkt_count': 1,

            # Direction forward/backward
            'fwd_bytes': packet_length if direction == 'forward' else 0,
            'bwd_bytes': packet_length if direction == 'backward' else 0,
            'fwd_pkts': 1 if direction == 'forward' else 0,
            'bwd_pkts': 1 if direction == 'backward' else 0,

            # NOUVEAU: Stockage des longueurs pour calculs précis CIC-IDS2017
            'fwd_packet_lengths': [packet_length] if direction == 'forward' else [],
            'bwd_packet_lengths': [packet_length] if direction == 'backward' else [],

            # Flags TCP
            'psh_count': flags['psh_count'],
            'urg_count': flags['urg_count'],
            'syn_count': flags['syn_count'],
            'fin_count': flags['fin_count'],
            'rst_count': flags['rst_count'],
            'ack_count': flags['ack_count'],

            # Informations de connexion
            'src_ip': packet.get('src_ip', 'unknown'),
            'dst_ip': packet.get('dst_ip', 'unknown'),
            'sport': packet.get('sport', 0),
            'dport': packet.get('dport', 0),
            'protocol': packet.get('protocol', 'unknown'),

            # Métriques calculées (seront mises à jour)
            'duration_ms': 0,
            'flow_pkts_per_s': 0,
            'fwd_bwd_ratio': 0,
            'bytes_per_packet': packet_length,

            # Métadonnées
            'interface': packet.get('interface', 'unknown'),
            'status': 'active',
            'last_activity': time.time()
        }

        return flow

    def update_flow(self, flow, packet):
        """
        Met à jour un flow existant avec un nouveau paquet
        CORRIGÉ: Mise à jour des listes de longueurs pour calculs précis

        Args:
            flow (dict): Flow existant
            packet (dict): Nouveau paquet à ajouter
        """
        direction = self.determine_direction(packet, flow['flow_key'])
        flags = self.extract_flags(packet)
        packet_length = packet.get('length', 0)
        current_time = time.time()

        # Mise à jour des compteurs
        flow['total_bytes'] += packet_length
        flow['pkt_count'] += 1
        flow['end_ts'] = packet.get('timestamp', datetime.now()).isoformat()
        flow['last_packet_ts'] = current_time
        flow['last_activity'] = current_time

        # Direction forward/backward avec mise à jour des listes
        if direction == 'forward':
            flow['fwd_bytes'] += packet_length
            flow['fwd_pkts'] += 1
            flow['fwd_packet_lengths'].append(packet_length)
        else:
            flow['bwd_bytes'] += packet_length
            flow['bwd_pkts'] += 1
            flow['bwd_packet_lengths'].append(packet_length)

        # Flags TCP
        flow['psh_count'] += flags['psh_count']
        flow['urg_count'] += flags['urg_count']
        flow['syn_count'] += flags['syn_count']
        flow['fin_count'] += flags['fin_count']
        flow['rst_count'] += flags['rst_count']
        flow['ack_count'] += flags['ack_count']

        # Calcul des métriques
        duration_seconds = current_time - flow['first_packet_ts']
        flow['duration_ms'] = duration_seconds * 1000

        if duration_seconds > 0:
            flow['flow_pkts_per_s'] = flow['pkt_count'] / duration_seconds

        if flow['bwd_bytes'] > 0:
            flow['fwd_bwd_ratio'] = flow['fwd_bytes'] / flow['bwd_bytes']

        flow['bytes_per_packet'] = flow['total_bytes'] / flow['pkt_count']

        # Vérifier si le flow est terminé (FIN ou RST)
        if flags['fin_count'] > 0 or flags['rst_count'] > 0:
            flow['status'] = 'terminated'

    def process_packet(self, packet):
        """
        Traite un paquet et l'ajoute au flow approprié

        Args:
            packet (dict): Paquet réseau parsé

        Returns:
            dict: Flow mis à jour ou None si erreur
        """
        try:
            with self.lock:
                self.stats['total_packets_processed'] += 1

                flow_key = self.create_flow_key(packet)
                current_time = time.time()

                # Nettoyage périodique des flows expirés
                if current_time - self.last_cleanup > self.cleanup_interval:
                    self._cleanup_expired_flows()

                # Nouveau flow ou flow existant ?
                if flow_key not in self.flows:
                    # Créer un nouveau flow
                    self.flows[flow_key] = self.create_new_flow(packet, flow_key)
                    self.stats['active_flows'] += 1
                else:
                    # Mettre à jour le flow existant
                    self.update_flow(self.flows[flow_key], packet)

                return self.flows[flow_key].copy()  # Retourner une copie pour thread safety

        except Exception as e:
            print(f"Erreur lors du traitement du paquet: {e}")
            return None

    def _cleanup_expired_flows(self):
        """
        Nettoie les flows expirés (inactifs depuis trop longtemps)
        """
        current_time = time.time()
        expired_flows = []

        for flow_key, flow in self.flows.items():
            # Flow expiré si inactif depuis flow_timeout secondes
            if current_time - flow['last_activity'] > self.flow_timeout:
                expired_flows.append(flow_key)

        # Déplacer les flows expirés vers completed_flows
        for flow_key in expired_flows:
            expired_flow = self.flows.pop(flow_key)
            expired_flow['status'] = 'expired'
            self.completed_flows.append(expired_flow)
            self.stats['active_flows'] -= 1
            self.stats['completed_flows'] += 1

        # Limiter la taille de completed_flows (garder les 1000 derniers)
        if len(self.completed_flows) > 1000:
            self.completed_flows = self.completed_flows[-1000:]

        self.last_cleanup = current_time

        # Calculer flows par minute
        if len(expired_flows) > 0:
            time_elapsed_minutes = (current_time - self.last_cleanup) / 60
            if time_elapsed_minutes > 0:
                self.stats['flows_per_minute'] = len(expired_flows) / time_elapsed_minutes

    def get_active_flows(self, limit=100):
        """
        Retourne la liste des flows actifs

        Args:
            limit (int): Nombre maximum de flows à retourner

        Returns:
            list: Liste des flows actifs
        """
        with self.lock:
            flows = list(self.flows.values())
            # Trier par dernière activité (plus récents en premier)
            flows.sort(key=lambda x: x['last_activity'], reverse=True)
            return flows[:limit]

    def get_completed_flows(self, limit=100):
        """
        Retourne la liste des flows terminés

        Args:
            limit (int): Nombre maximum de flows à retourner

        Returns:
            list: Liste des flows terminés
        """
        with self.lock:
            return self.completed_flows[-limit:]

    def get_flow_by_key(self, flow_key):
        """
        Retourne un flow spécifique par sa clé

        Args:
            flow_key (str): Clé du flow

        Returns:
            dict: Flow ou None si non trouvé
        """
        with self.lock:
            return self.flows.get(flow_key, None)

    def get_statistics(self):
        """
        Retourne les statistiques de l'agrégateur

        Returns:
            dict: Statistiques actuelles
        """
        with self.lock:
            self.stats['active_flows'] = len(self.flows)
            return self.stats.copy()

    def force_complete_flow(self, flow_key):
        """
        Force la complétion d'un flow actif

        Args:
            flow_key (str): Clé du flow à terminer

        Returns:
            bool: True si le flow a été terminé, False sinon
        """
        with self.lock:
            if flow_key in self.flows:
                completed_flow = self.flows.pop(flow_key)
                completed_flow['status'] = 'forced_complete'
                self.completed_flows.append(completed_flow)
                self.stats['active_flows'] -= 1
                self.stats['completed_flows'] += 1
                return True
            return False

    def clear_all_flows(self):
        """
        Vide tous les flows (actifs et terminés)
        Utile pour reset ou tests
        """
        with self.lock:
            self.flows.clear()
            self.completed_flows.clear()
            self.stats = {
                'total_packets_processed': 0,
                'active_flows': 0,
                'completed_flows': 0,
                'flows_per_minute': 0
            }

    def export_flows_to_json(self, include_active=True, include_completed=True):
        """
        Exporte les flows en format JSON

        Args:
            include_active (bool): Inclure les flows actifs
            include_completed (bool): Inclure les flows terminés

        Returns:
            str: JSON des flows
        """
        with self.lock:
            export_data = {
                'timestamp': datetime.now().isoformat(),
                'statistics': self.get_statistics(),
                'flows': []
            }

            if include_active:
                export_data['flows'].extend(list(self.flows.values()))

            if include_completed:
                export_data['flows'].extend(self.completed_flows)

            return json.dumps(export_data, indent=2, default=str)


# Fonction utilitaire pour extraire les features ML - VERSION CORRIGÉE
def extract_cic_features(flow):
    """
    Extrait les features compatibles CIC-IDS2017 depuis un flow
    VERSION CORRIGÉE: Calculs précis avec les vraies longueurs de paquets

    Args:
        flow (dict): Flow agrégé

    Returns:
        list: Liste des 10 features pour le modèle ML
    """
    try:
        # Récupérer les listes de longueurs de paquets
        fwd_lengths = flow.get('fwd_packet_lengths', [])
        bwd_lengths = flow.get('bwd_packet_lengths', [])
        all_lengths = fwd_lengths + bwd_lengths

        # Calculs sécurisés (éviter division par zéro)
        duration_sec = max(flow.get('duration_ms', 0) / 1000.0, 0.001)

        # Feature 1: Destination Port
        dest_port = flow.get('dport', 0)

        # Features 2-3: Backward packet lengths
        if bwd_lengths:
            bwd_packet_length_min = min(bwd_lengths)
            bwd_packet_length_mean = statistics.mean(bwd_lengths)
        else:
            bwd_packet_length_min = 0
            bwd_packet_length_mean = 0

        # Feature 4: Backward Packets/s
        bwd_packets_per_sec = flow.get('bwd_pkts', 0) / duration_sec

        # Feature 5: Min Packet Length (overall)
        min_packet_length = min(all_lengths) if all_lengths else 0

        # Features 6-7: Flag counts
        psh_flag_count = flow.get('psh_count', 0)
        urg_flag_count = flow.get('urg_count', 0)

        # Features 8-9: Average segment sizes
        if fwd_lengths:
            avg_fwd_segment_size = statistics.mean(fwd_lengths)
        else:
            avg_fwd_segment_size = 0

        if bwd_lengths:
            avg_bwd_segment_size = statistics.mean(bwd_lengths)
        else:
            avg_bwd_segment_size = 0

        # Feature 10: Min segment size forward
        if fwd_lengths:
            min_seg_size_forward = min(fwd_lengths)
        else:
            min_seg_size_forward = 0

        # Les 10 features du modèle CIC-IDS2017 (calculs corrects)
        features = [
            dest_port,  # Destination Port
            bwd_packet_length_min,  # Bwd Packet Length Min
            bwd_packet_length_mean,  # Bwd Packet Length Mean
            bwd_packets_per_sec,  # Bwd Packets/s
            min_packet_length,  # Min Packet Length
            psh_flag_count,  # PSH Flag Count
            urg_flag_count,  # URG Flag Count
            avg_fwd_segment_size,  # Avg Fwd Segment Size
            avg_bwd_segment_size,  # Avg Bwd Segment Size
            min_seg_size_forward  # min_seg_size_forward
        ]

        return features

    except Exception as e:
        print(f"Erreur extraction features: {e}")
        return [0] * 10  # Retourner des zéros en cas d'erreur