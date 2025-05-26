"""
skpa_stats_v2.py
----------------
- Sniff Docker‑bridge traffic with Scapy.
- Aggregate per‑flow statistics (13+ features).
- Add Target label based on source subnet (Normal / Mal / Unknown).
- Columns ready for quick ML (csv output).
"""

from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
import ipaddress, csv, signal, argparse, sys

# ─────────── CLI arguments ──────────────────────────────────────────
cli = argparse.ArgumentParser(description="Passive flow feature extractor")
cli.add_argument("-i", "--iface", default="br-benign",
                 help="interface à sniffer (bridge Docker)")
cli.add_argument("-t", "--time", type=int, default=1200,
                 help="durée de capture en secondes")
cli.add_argument("-o", "--out", default="flows.csv",
                 help="fichier CSV de sortie")
args = cli.parse_args()

# ─────────── ‘Normal’ vs ‘Mal’ subnets ──────────────────────────────
NORMAL_NET = ipaddress.ip_network("172.30.0.0/16")
MAL_NET    = ipaddress.ip_network("172.31.0.0/16")

def target(ip_str: str) -> str:
    ip = ipaddress.ip_address(ip_str)
    if ip in NORMAL_NET: return "Normal"
    if ip in MAL_NET:    return "Mal"
    return "Unknown"

# ─────────── flow state dict ────────────────────────────────────────
flows = defaultdict(lambda: {
    # basic directions
    "dst_port" : 0,
    "fwd_bytes": 0, "fwd_pkts": 0, "fwd_min": 1e9,
    "bwd_bytes": 0, "bwd_pkts": 0, "bwd_min": 1e9,
    # flags + misc
    "psh": 0, "urg": 0, "min_len": 1e9,
    # timing / label
    "start": 0, "end": 0, "label": "Unknown"
})

# ─────────── packet‑by‑packet update ────────────────────────────────

def update(pkt):
    if not (IP in pkt and (TCP in pkt or UDP in pkt)):
        return

    ip  = pkt[IP]
    l4  = TCP if TCP in pkt else UDP
    length = len(pkt)

    # (src, dst, sport, dport, proto) = flow key
    sport, dport = pkt[l4].sport, pkt[l4].dport
    key = (ip.src, ip.dst, sport, dport, l4.name)
    rev = (ip.dst, ip.src, dport, sport, l4.name)

    fwd  = key in flows or rev not in flows     # direction heuristic
    stat = flows[key] if fwd else flows[rev]

    # timing
    if stat["start"] == 0:
        stat["start"] = pkt.time
    stat["end"] = pkt.time

    # static fields
    stat["dst_port"] = dport
    if stat["label"] == "Unknown":
        stat["label"] = target(ip.src)

    # generic minima
    stat["min_len"] = min(stat["min_len"], length)

    # directional accounting
    if fwd:
        stat["fwd_bytes"] += length
        stat["fwd_pkts"]  += 1
        stat["fwd_min"]   = min(stat["fwd_min"], length)
        if TCP in pkt:
            flags = pkt[TCP].flags
            if flags & 0x08: stat["psh"] += 1   # PSH
            if flags & 0x20: stat["urg"] += 1   # URG
    else:
        stat["bwd_bytes"] += length
        stat["bwd_pkts"]  += 1
        stat["bwd_min"]   = min(stat["bwd_min"], length)

# ─────────── CSV output ─────────────────────────────────────────────
HEADER = [
    "Destination Port",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packets/s",
    "Min Packet Length",
    "PSH Flag Count",
    "URG Flag Count",
    "Avg Fwd Segment Size",
    "Avg Bwd Segment Size",
    "min_seg_size_forward",
    # new features
    "Flow Duration ms",
    "Flow_Pkts/s",
    "Fwd_Bwd_Ratio",
    "Target"
]


def flush(*_):
    with open(args.out, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(HEADER)
        for s in flows.values():
            dur = max(s["end"] - s["start"], 1e-6)
            fwd_mean = s["fwd_bytes"] / s["fwd_pkts"] if s["fwd_pkts"] else 0
            bwd_mean = s["bwd_bytes"] / s["bwd_pkts"] if s["bwd_pkts"] else 0
            total_pkts = s["fwd_pkts"] + s["bwd_pkts"]
            w.writerow([
                s["dst_port"],                       # Destination Port
                s["bwd_min"]   if s["bwd_pkts"] else 0,      # Bwd Packet Length Min
                bwd_mean,                             # Bwd Packet Length Mean
                s["bwd_pkts"] / dur,                 # Bwd Packets/s
                s["min_len"]  if s["min_len"] < 1e9 else 0,  # Min Packet Length (any dir)
                s["psh"],                              # PSH Flag Count
                s["urg"],                              # URG Flag Count
                fwd_mean,                             # Avg Fwd Segment Size
                bwd_mean,                             # Avg Bwd Segment Size
                s["fwd_min"] if s["fwd_pkts"] else 0,         # min_seg_size_forward
                (dur * 1000),                         # Flow Duration ms
                total_pkts / dur,                     # Flow_Pkts/s (pps overall)
                s["fwd_bytes"] / (s["bwd_bytes"] + 1),        # Fwd_Bwd_Ratio (bytes)
                s["label"]                             # Target
            ])
    print(f"[✓] {len(flows)} flows exported → {args.out}")
    sys.exit(0)

signal.signal(signal.SIGINT, flush)

# ─────────── start sniffing ─────────────────────────────────────────
print(f"[+] Sniffing {args.time}s on {args.iface}  (Ctrl‑C to stop)")
sniff(iface=args.iface, store=False, prn=update, timeout=args.time)
flush()

