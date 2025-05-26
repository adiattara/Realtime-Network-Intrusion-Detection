#!/usr/bin/env python3
"""
skpa_stats_v2.py
----------------
- Capture les paquets avec Scapy.
- Agrège 10 features par flux.
- Ajoute la colonne Target = {Normal, Mal}.
- Compatible HTTP / FTP / SSH / SFTP / SMTP…
"""

from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
import ipaddress, csv, signal, argparse, sys

# ─────────── paramètres CLI ─────────────────────────────────────────
cli = argparse.ArgumentParser()
cli.add_argument("-i", "--iface", default="br-benign",
                 help="interface à sniffer (bridge Docker)")
cli.add_argument("-t", "--time", type=int, default=1200,
                 help="durée de capture en secondes")
cli.add_argument("-o", "--out", default="flows.csv",
                 help="fichier CSV de sortie")
args = cli.parse_args()

# ─────────── plages « Normal » vs « Mal » ───────────────────────────
NORMAL_NET = ipaddress.ip_network("172.30.0.0/16")
MAL_NET    = ipaddress.ip_network("172.31.0.0/16")

def target(ip_str: str) -> str:
    ip = ipaddress.ip_address(ip_str)
    if ip in NORMAL_NET: return "Normal"
    if ip in MAL_NET:    return "Mal"
    return "Unknown"

# ─────────── stats par flux ─────────────────────────────────────────
flows = defaultdict(lambda: {
    "dst_port":0, "bwd_min":1e9, "bwd_bytes":0, "bwd_pkts":0,
    "min_len":1e9, "psh":0, "urg":0,
    "fwd_bytes":0, "fwd_pkts":0, "fwd_min":1e9,
    "start":0, "end":0, "label":"Unknown"
})

def update(pkt):
    if not (IP in pkt and (TCP in pkt or UDP in pkt)):
        return
    ip, length = pkt[IP], len(pkt)
    layer      = TCP if TCP in pkt else UDP
    sport, dport = pkt[layer].sport, pkt[layer].dport
    key = (ip.src, ip.dst, sport, dport, layer.name)
    rev = (ip.dst, ip.src, dport, sport, layer.name)
    fwd = key in flows or rev not in flows
    stat = flows[key] if fwd else flows[rev]

    if stat["start"] == 0:
        stat["start"] = pkt.time
    stat["end"]   = pkt.time
    stat["dst_port"] = dport
    stat["label"] = target(ip.src) if stat["label"] == "Unknown" else stat["label"]
    stat["min_len"] = min(stat["min_len"], length)

    if fwd:
        stat["fwd_bytes"] += length
        stat["fwd_pkts"]  += 1
        stat["fwd_min"]   = min(stat["fwd_min"], length)
        if TCP in pkt and pkt[TCP].flags & 0x08: stat["psh"] += 1
        if TCP in pkt and pkt[TCP].flags & 0x20: stat["urg"] += 1
    else:
        stat["bwd_bytes"] += length
        stat["bwd_pkts"]  += 1
        stat["bwd_min"]   = min(stat["bwd_min"], length)

# ─────────── sortie CSV & arrêt propre ──────────────────────────────
HEADER = ["Destination Port","Bwd Packet Length Min","Bwd Packet Length Mean",
          "Bwd Packets/s","Min Packet Length","PSH Flag Count","URG Flag Count",
          "Avg Fwd Segment Size","Avg Bwd Segment Size","min_seg_size_forward",
          "Target"]

def flush(*_):
    with open(args.out, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(HEADER)
        for s in flows.values():
            dur = max(s["end"] - s["start"], 1e-6)
            w.writerow([
                s["dst_port"],
                s["bwd_min"] if s["bwd_pkts"] else 0,
                s["bwd_bytes"]/s["bwd_pkts"] if s["bwd_pkts"] else 0,
                s["bwd_pkts"]/dur,
                s["min_len"] if s["min_len"] < 1e9 else 0,
                s["psh"], s["urg"],
                s["fwd_bytes"]/s["fwd_pkts"] if s["fwd_pkts"] else 0,
                s["bwd_bytes"]/s["bwd_pkts"] if s["bwd_pkts"] else 0,
                s["fwd_min"] if s["fwd_pkts"] else 0,
                s["label"]
            ])
    print(f"[✓] {len(flows)} flux écrits dans {args.out}")
    sys.exit(0)

signal.signal(signal.SIGINT, flush)

# ─────────── capture ────────────────────────────────────────────────
print(f"[+] Capture {args.time}s sur {args.iface}…  Ctrl-C pour stop")
sniff(iface=args.iface, store=False, prn=update, timeout=args.time)
flush()
