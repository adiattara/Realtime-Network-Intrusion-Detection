from scapy.all import sniff, IP, TCP, UDP
from confluent_kafka import Producer
import json, argparse, ipaddress

# Plages IP « Normal » et « Mal »
NORMAL_NET = ipaddress.ip_network("172.30.0.0/16")
MAL_NET = ipaddress.ip_network("172.31.0.0/16")


# Fonction pour déterminer si l'IP source est dans la plage Malveillante
def label_ip(ipstr: str) -> bool:
    ip = ipaddress.ip_address(ipstr)
    return ip in MAL_NET  # True pour attaque, False pour normal


# Arguments CLI
parser = argparse.ArgumentParser()
parser.add_argument("-i", "--iface", default="br-benign", help="interface à écouter")
parser.add_argument("-b", "--broker", default="localhost:29092", help="broker Kafka")
args = parser.parse_args()

# Initialisation du producteur Kafka
producer = Producer({"bootstrap.servers": args.broker})


def pkt_to_json(pkt):
    if IP not in pkt:
        return None

    data = {
        "timestamp": pkt.time,
        "src_ip": pkt[IP].src,
        "dst_ip": pkt[IP].dst,
        "proto": pkt[IP].proto,
    }

    # Ajouter sport, dport, payload_len pour TCP et UDP
    if TCP in pkt:
        data.update({
            "sport": pkt[TCP].sport,
            "dport": pkt[TCP].dport,
            "flags": int(pkt[TCP].flags),
            "payload_len": len(pkt[TCP].payload)
        })
    elif UDP in pkt:
        data.update({
            "sport": pkt[UDP].sport,
            "dport": pkt[UDP].dport,
            "payload_len": len(pkt[UDP].payload)
        })
    else:
        data.update({
            "sport": None,
            "dport": None,
            "payload_len": 0
        })

    # Ajouter le label d'attaque (True si IP dans MAL_NET, sinon False)
    data["attack"] = label_ip(pkt[IP].src)

    return data


def send_pkt(pkt):
    data = pkt_to_json(pkt)
    if data is not None:
        producer.produce("raw-packets", json.dumps(data).encode("utf-8"))
        producer.poll(0)  # flush async


# Sniffing de l'interface
print(f"[+] Sniffing interface {args.iface} et envoi des paquets bruts dans Kafka (topic 'raw-packets')")
sniff(iface=args.iface, prn=send_pkt, store=False)
