from scapy.all import sniff, IP, TCP, UDP
from confluent_kafka import Producer
import json, argparse

parser = argparse.ArgumentParser()
parser.add_argument("-i", "--iface", default="br-benign", help="interface à écouter")
parser.add_argument("-b", "--broker", default="localhost:29092", help="broker Kafka")
args = parser.parse_args()

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
    return data

def send_pkt(pkt):
    data = pkt_to_json(pkt)
    if data is not None:
        producer.produce("raw-packets", json.dumps(data).encode("utf-8"))
        producer.poll(0)

print(f"Sniffing interface {args.iface} and sending packets to Kafka topic 'raw-packets' on {args.broker}")
sniff(iface=args.iface, prn=send_pkt, store=False)

