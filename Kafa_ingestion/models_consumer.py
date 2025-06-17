import json
import logging

import requests
import psycopg2
from kafka import KafkaConsumer
import time
import traceback

# Configuration
KAFKA_TOPIC = "aggregated-flows"
KAFKA_BOOTSTRAP_SERVERS = ["localhost:9092"]
MODEL_ENDPOINT = "http://localhost:8004/predict"
POSTGRES_CONFIG = {
    "dbname": "postgres",
    "user": "nfuser",
    "password": "nfpass",
    "host": "localhost",
    "port": "5432",
}

def log(msg):
    print(f"[DEBUG] {msg}", flush=True)

# Connexion à PostgreSQL
try:
    conn = psycopg2.connect(**POSTGRES_CONFIG)
    cursor = conn.cursor()
    log("Connexion PostgreSQL réussie.")
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS predictions (
        id SERIAL PRIMARY KEY,
        total_bytes INTEGER,
        pkt_count INTEGER,
        psh_count INTEGER,
        fwd_bytes INTEGER,
        bwd_bytes INTEGER,
        fwd_pkts INTEGER,
        bwd_pkts INTEGER,
        dport INTEGER,
        duration_ms FLOAT,
        flow_pkts_per_s FLOAT,
        fwd_bwd_ratio FLOAT,
        prediction TEXT
    )
    """)
    conn.commit()
    log("Table predictions prête.")
except Exception:
    log("Erreur lors de la connexion PostgreSQL :")
    traceback.print_exc()
    exit(1)

# Connexion à Kafka
try:
    consumer = KafkaConsumer(
        KAFKA_TOPIC,
        bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
        value_deserializer=lambda m: json.loads(m.decode("utf-8")),
        enable_auto_commit=True,
        auto_commit_interval_ms=1000,
        group_id="model_consumer"
    )
    log("Kafka Consumer initialisé.")
except Exception:
    log("Erreur lors de la connexion à Kafka :")
    traceback.print_exc()
    exit(1)
logging.info(f"[DEBUG] Abonné aux topics: {consumer.subscription()}")
log("Consumer lancé, attente de messages...")

# Boucle principale bloquante
for message in consumer:
    try:
        log("Message reçu de Kafka.")
        flow = message.value
        log(f"Données reçues : {flow}")

        # Construction de l'entrée modèle
        model_input = {
            "total_bytes": flow["total_bytes"],
            "pkt_count": flow["pkt_count"],
            "psh_count": flow["psh_count"],
            "fwd_bytes": flow["fwd_bytes"],
            "bwd_bytes": flow["bwd_bytes"],
            "fwd_pkts": flow["fwd_pkts"],
            "bwd_pkts": flow["bwd_pkts"],
            "dport": flow["dport"],
            "duration_ms": flow["duration_ms"],
            "flow_pkts_per_s": flow["flow_pkts_per_s"],
            "fwd_bwd_ratio": flow["fwd_bwd_ratio"]
        }

        log(f"Requête envoyée à {MODEL_ENDPOINT} avec payload : {model_input}")
        response = requests.post(MODEL_ENDPOINT, json=model_input)
        response.raise_for_status()
        prediction = response.json()["label"]
        score = response.json()["score"]
        log(f"Prédiction reçue : {prediction}")

        # Insertion en BDD
        insert_query = """
        INSERT INTO predictions (
            total_bytes, pkt_count, psh_count, fwd_bytes, bwd_bytes,
            fwd_pkts, bwd_pkts, dport, duration_ms, flow_pkts_per_s,
            fwd_bwd_ratio, prediction
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        values = tuple(model_input.values()) + (prediction,)
        cursor.execute(insert_query, values)
        conn.commit()
        log(f"[✓] Prediction insérée avec succès : {prediction}")

    except Exception as e:
        log("[✗] Une erreur est survenue :")
        traceback.print_exc()
        time.sleep(1)
