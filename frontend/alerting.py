import smtplib
import time
import os
from collections import defaultdict
from email.mime.text import MIMEText

# --- Configuration ---
ALERT_THRESHOLD = 5       # Nombre de flows malveillants pour alerte globale
ALERT_WINDOW = 60         # Fenêtre de temps en secondes
ATTACKER_THRESHOLD = 3    # Nombre de flows malveillants par IP
COOLDOWN = 180            # Délai d'attente entre deux alertes identiques (en secondes)

# On stocke l'historique pour éviter le spam d'alertes
last_ip_alert_time = defaultdict(lambda: 0)   # {ip: timestamp}
last_global_alert_time = 0                    # timestamp global

# Tracking des flows malveillants
MAL_FLOWS_TIMESTAMPS = []
MAL_IP_FLOWS = defaultdict(list)

# ==== Paramètres de l'expéditeur BOT (à configurer dans les variables d'environnement pour la sécurité !) ====
BOT_EMAIL = os.getenv('BOT_EMAIL', 'votrebot@gmail.com')         # Change en variable d'environnement ou dans .env
BOT_APP_PASSWORD = os.getenv('BOT_APP_PASSWORD', 'votre_mdp_app')  # Jamais en clair en prod !

def send_email_alert(subject, body, to_addr):
    """
    Envoie une alerte email à l'utilisateur connecté (adresse passée en paramètre)
    """
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = BOT_EMAIL
    msg["To"] = to_addr

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(BOT_EMAIL, BOT_APP_PASSWORD)
            server.send_message(msg)
        print(f"[ALERTING] Email envoyé à {to_addr} : {subject}")
    except Exception as e:
        print(f"[ALERTING][ERROR] Impossible d'envoyer l'alerte à {to_addr} : {e}")

def process_new_flow_for_alerting(flow, user_email):
    """
    Appelée à chaque flow terminé avec prédiction. user_email = email utilisateur connecté
    """
    global last_ip_alert_time, last_global_alert_time, MAL_FLOWS_TIMESTAMPS, MAL_IP_FLOWS
    now = time.time()
    src_ip = flow.get("src_ip", None)
    prediction = str(flow.get("prediction", "")).lower()

    if prediction == "mal" and src_ip:
        MAL_FLOWS_TIMESTAMPS.append(now)
        MAL_IP_FLOWS[src_ip].append(now)

    # Garder les flows récents seulement
    MAL_FLOWS_TIMESTAMPS[:] = [t for t in MAL_FLOWS_TIMESTAMPS if now - t < ALERT_WINDOW]
    for ip in list(MAL_IP_FLOWS):
        MAL_IP_FLOWS[ip] = [t for t in MAL_IP_FLOWS[ip] if now - t < ALERT_WINDOW]
        if not MAL_IP_FLOWS[ip]:
            del MAL_IP_FLOWS[ip]

    # Alerte globale
    if len(MAL_FLOWS_TIMESTAMPS) >= ALERT_THRESHOLD:
        if now - last_global_alert_time > COOLDOWN:
            subject = "ALERTE : Trop de flows malveillants détectés"
            body = f"{len(MAL_FLOWS_TIMESTAMPS)} flows malveillants détectés en moins de {ALERT_WINDOW} secondes."
            send_email_alert(subject, body, user_email)
            last_global_alert_time = now

    # Alerte par IP
    for ip, ts_list in MAL_IP_FLOWS.items():
        if len(ts_list) >= ATTACKER_THRESHOLD:
            if now - last_ip_alert_time[ip] > COOLDOWN:
                subject = f"ALERTE : Activité suspecte de l'IP {ip}"
                body = f"L'adresse IP {ip} a généré {len(ts_list)} flows malveillants en moins de {ALERT_WINDOW} secondes."
                send_email_alert(subject, body, user_email)
                last_ip_alert_time[ip] = now