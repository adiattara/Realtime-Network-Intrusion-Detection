#!/usr/bin/env python3
"""
skpa_stats_v5.py
────────────────
Sniff Scapy → agrège 13 features / flux
gère les floods UDP (clé sans port source) et ignore les flux < 5 paquets
"""

from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
import ipaddress, csv, signal, argparse, sys, math

# ─── CLI ────────────────────────────────────────────────────────────
ap = argparse.ArgumentParser()
ap.add_argument("-i", "--iface", default="br-benign",
                help="interface Docker à sniffer")
ap.add_argument("-t", "--time",  type=int, default=1200,
                help="durée max (s) – Ctrl-C pour sortir avant")
ap.add_argument("-o", "--out",   default="flows_v5.csv",
                help="fichier CSV de sortie")
args = ap.parse_args()

# ─── plages IP « Normal » / « Mal » ────────────────────────────────
NORMAL_NET = ipaddress.ip_network("172.30.0.0/16")
MAL_NET    = ipaddress.ip_network("172.31.0.0/16")

def label(ipstr:str)->str:
    ip = ipaddress.ip_address(ipstr)
    if ip in NORMAL_NET: return "Normal"
    if ip in MAL_NET:    return "Mal"
    return "Unknown"

# ─── conteneur de stats ────────────────────────────────────────────
flows = defaultdict(lambda: {
    # compteurs bruts
    "fwd_bytes":0, "fwd_pkts":0, "fwd_min":math.inf,
    "bwd_bytes":0, "bwd_pkts":0, "bwd_min":math.inf,
    "psh":0, "urg":0, "start":0, "end":0,
    # méta
    "dport":0, "label":"Unknown"
})

# ─── update à chaque paquet ────────────────────────────────────────
def update(pkt):
    if not (IP in pkt and (TCP in pkt or UDP in pkt)): return
    ip = pkt[IP]; plen = len(pkt)
    l4  = TCP if TCP in pkt else UDP
    sport, dport = pkt[l4].sport, pkt[l4].dport

    # ► clé : pour UDP on ignore sport (sinon flood = 1 paquet / flux)
    same_sport = sport if l4 is TCP else 0
    key = (ip.src, ip.dst, same_sport, dport, l4.name)
    rev = (ip.dst, ip.src, dport, same_sport, l4.name)   # sens retour
    fwd = key in flows or rev not in flows               # direction

    st = flows[key] if fwd else flows[rev]
    if st["start"] == 0: st["start"] = pkt.time
    st["end"]   = pkt.time
    st["dport"] = dport
    if st["label"] == "Unknown": st["label"] = label(ip.src)

    # métriques communes
    st["fwd_min"] = min(st["fwd_min"], plen) if fwd else st["fwd_min"]
    st["bwd_min"] = min(st["bwd_min"], plen) if not fwd else st["bwd_min"]

    if fwd:
        st["fwd_bytes"] += plen
        st["fwd_pkts"]  += 1
        if TCP in pkt and pkt[TCP].flags & 0x08: st["psh"] += 1
        if TCP in pkt and pkt[TCP].flags & 0x20: st["urg"] += 1
    else:
        st["bwd_bytes"] += plen
        st["bwd_pkts"]  += 1

# ─── CSV ────────────────────────────────────────────────────────────
HEAD = ["Destination Port","Bwd Packet Length Min","Bwd Packet Length Mean",
        "Bwd Packets/s","Min Packet Length","PSH Flag Count","URG Flag Count",
        "Avg Fwd Segment Size","Avg Bwd Segment Size","min_seg_size_forward",
        "Flow Duration ms","Flow_Pkts/s","Fwd_Bwd_Ratio","Target"]

def flush(*_):
    with open(args.out,"w",newline="") as f:
        w = csv.writer(f); w.writerow(HEAD)
        for s in flows.values():
            pkts_tot = s["fwd_pkts"]+s["bwd_pkts"]
            if pkts_tot < 5:          # on ignore les flux trop petits
                continue
            dur = max((s["end"]-s["start"])*1000, 1)   # ms
            w.writerow([
                s["dport"],
                0 if math.isinf(s["bwd_min"]) else s["bwd_min"],
                s["bwd_bytes"]/s["bwd_pkts"] if s["bwd_pkts"] else 0,
                s["bwd_pkts"]/(dur/1000),
                min(s["fwd_min"],s["bwd_min"]),
                s["psh"], s["urg"],
                s["fwd_bytes"]/s["fwd_pkts"] if s["fwd_pkts"] else 0,
                s["bwd_bytes"]/s["bwd_pkts"] if s["bwd_pkts"] else 0,
                0 if math.isinf(s["fwd_min"]) else s["fwd_min"],
                round(dur,3),
                pkts_tot/(dur/1000),
                round( (s["fwd_bytes"]+1)/(s["bwd_bytes"]+1) ,3),
                s["label"]
            ])
    print(f"[✓] {args.out} écrit ({sum(1 for _ in open(args.out))-1} flux)")
    sys.exit(0)

signal.signal(signal.SIGINT, flush)

print(f"[+] Sniff {args.time}s sur {args.iface} — Ctrl-C pour arrêter…")
sniff(iface=args.iface, store=False, prn=update, timeout=args.time)
flush()
