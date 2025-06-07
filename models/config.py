dossiers_donnees = ['../output/normal', '../output/anormal']

colonnes_utiles = [
    'flow_key', 'start_ts', 'end_ts', 'total_bytes', 'pkt_count',
    'fwd_bytes', 'bwd_bytes', 'fwd_pkts', 'bwd_pkts',
    'duration_ms', 'flow_pkts_per_s', 'fwd_bwd_ratio',
    'window_start', 'window_end', 'Label'
]

colonnes_numeriques = [
    'total_bytes', 'pkt_count', 'fwd_bytes', 'bwd_bytes',
    'fwd_pkts', 'bwd_pkts', 'duration_ms', 'flow_pkts_per_s',
    'fwd_bwd_ratio'
]