# network_utils.py
import os
import re
import threading
import paramiko
import requests
from datetime import datetime
# from openai import OpenAI  # Commented out to improve performance
from dotenv import load_dotenv
import httpx

load_dotenv()

API_URL = os.environ.get('API_URL', "https://realtime-network-intrusion-detection-8itu.onrender.com/predict")
# Create a custom httpx client without proxy settings
http_client = httpx.Client()
# openai_client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'), http_client=http_client)  # Commented out to improve performance


def predict_flow(flow_features):
    try:
        response = requests.post(API_URL, json=flow_features, timeout=1)
        if response.status_code == 200:
            return response.json().get("label", "N/A")
        else:
            return "Erreur API"
    except Exception as e:
        return f"Erreur: {e}"


def resumer_texte(texte, modele="gpt-3.5-turbo"):
    """
    Résume un flow réseau malicieux à l'aide d'un LLM.
    Le texte d'entrée doit être un JSON avec les features réseau + prédiction.
    """
    try:
        # Code OpenAI commenté pour améliorer les performances
        # response = openai_client.chat.completions.create(
        #     model=modele,
        #     messages=[
        #         {
        #             "role": "system",
        #             "content": (
        #                 "Tu es un expert en cybersécurité chargé de résumer un flux réseau malicieux. "
        #                 "Chaque flux est au format JSON et contient des caractéristiques techniques (paquets, octets, durée, ratio, etc.) "
        #                 "et une prédiction ('Mal' ou 'Normal'). Ton objectif est de générer UNE SEULE formulation courte et claire, "
        #                 "compréhensible par un analyste SOC. Mets en avant les anomalies importantes (asymétrie, volume, durée, ratio). "
        #                 "Ta réponse ne doit PAS dépasser 3 phrases courtes."
        #             )
        #         },
        #         {
        #             "role": "user",
        #             "content": f"Voici un flow à résumer : {texte}"
        #         }
        #     ],
        #     temperature=0.5,
        #     max_tokens=200  # Ajuste selon ton usage
        # )
        # return response.choices[0].message.content.strip()

        # Remplacement par une fonction simplifiée
        import json
        try:
            data = json.loads(texte)
            prediction = data.get("prediction", "inconnu")
            src_ip = data.get("src_ip", "inconnu")
            dst_ip = data.get("dst_ip", "inconnu")

            # Si les IPs sont inconnues, on affiche uniquement la prédiction
            if src_ip == "inconnu" or dst_ip == "inconnu":
                return f"Classé comme {prediction}"
            else:
                return f"Flow {src_ip} → {dst_ip} classé comme {prediction}"
        except:
            return "Résumé simplifié du flow (OpenAI désactivé)"
    except Exception as e:
        return f"Erreur de résumé : {e}"


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
