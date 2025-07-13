import os
import json
import pickle
import psycopg2
import numpy as np
import pandas as pd
from tensorflow.keras.models import load_model
from sklearn.metrics import classification_report, accuracy_score
from model import construire_ann  # ta fonction pour créer le modèle

# === CONFIGURATION ===
import os

DB_CONFIG = {
    "host": os.environ.get("DB_HOST", "network_db"),
    "port": int(os.environ.get("DB_PORT", 5432)),
    "database": os.environ.get("DB_NAME", "networkdb"),
    "user": os.environ.get("DB_USER", "user"),
    "password": os.environ.get("DB_PASSWORD", "password")
}
MODEL_PATH = "model.h5"
SCALER_PATH = "scaler.pkl"
X_BLIND_PATH = "X_blind_test.pkl"
Y_BLIND_PATH = "y_blind_test.pkl"

FEATURES = [
    "total_bytes", "pkt_count", "psh_count", "fwd_bytes", "bwd_bytes",
    "fwd_pkts", "bwd_pkts", "dport", "duration_ms", "flow_pkts_per_s", "fwd_bwd_ratio"
]

# === CHARGER LES DONNÉES DE FEEDBACK ===
def load_feedback_flows():
    conn = psycopg2.connect(**DB_CONFIG)
    df = pd.read_sql("SELECT flow_data, label_humain FROM reported_flows", conn)
    print("Colonnes présentes dans la table reported_flows:")
    print(df.columns.tolist())
    conn.close()

    # Parsing JSON
    def extract_features(flow_json):
        try:
            flow = json.loads(flow_json)
            return [flow.get(f, 0) for f in FEATURES]
        except Exception as e:
            print(f"Erreur parsing JSON: {e}")
            return [0] * len(FEATURES)

    features_df = df["flow_data"].apply(extract_features).apply(pd.Series)
    features_df.columns = FEATURES

    # Convertir le label texte en entier
    features_df["label"] = df["label_humain"].map({"Normal": 0, "Mal": 1})

    return features_df.dropna()

# === ÉVALUATION ===
def evaluate_model(model, X, y, label=""):
    y_pred = (model.predict(X) > 0.5).astype(int)
    print(f"\n📊 Rapport de classification : {label}")
    print(classification_report(y, y_pred))
    return accuracy_score(y, y_pred)

# === PIPELINE PRINCIPAL ===
def main():
    print("📥 Chargement des données signalées...")
    df = load_feedback_flows()

    X_new = df[FEATURES].values
    y_new = df["label"].astype(int).values

    print("🧪 Chargement des assets...")
    with open(SCALER_PATH, "rb") as f:
        scaler = pickle.load(f)
    with open(X_BLIND_PATH, "rb") as f:
        X_blind = pickle.load(f)
    with open(Y_BLIND_PATH, "rb") as f:
        y_blind = pickle.load(f)

    current_model = load_model(MODEL_PATH)

    # Appliquer le scaler
    # Vérifier si scaler est un objet StandardScaler ou un numpy array
    if hasattr(scaler, 'transform'):
        X_scaled = scaler.transform(X_new)
    else:
        # Si c'est un numpy array, on suppose que c'est déjà les données transformées
        # ou qu'il contient les paramètres de scaling (mean, std)
        from sklearn.preprocessing import StandardScaler
        temp_scaler = StandardScaler()
        # On fait un fit sur les données actuelles pour initialiser le scaler
        temp_scaler.fit(X_new)
        # On remplace les attributs mean_ et scale_ par ceux du scaler chargé
        if isinstance(scaler, tuple) and len(scaler) == 2:
            # Si c'est un tuple (mean, std)
            temp_scaler.mean_ = scaler[0]
            temp_scaler.scale_ = scaler[1]
        X_scaled = temp_scaler.transform(X_new)

    # Créer nouveau modèle avec mêmes poids
    print("🔁 Réentraînement du modèle avec feedback...")
    new_model = construire_ann(X_scaled.shape[1])
    new_model.set_weights(current_model.get_weights())
    new_model.fit(X_scaled, y_new, epochs=5, batch_size=32, validation_split=0.2)

    # Évaluer l'ancien et le nouveau
    acc_old = evaluate_model(current_model, X_blind, y_blind, label="Ancien modèle")
    acc_new = evaluate_model(new_model, X_blind, y_blind, label="Nouveau modèle")

    # Comparaison
    if acc_new >= acc_old:
        print("✅ Nouveau modèle adopté, sauvegarde en cours...")
        new_model.save(MODEL_PATH)
    else:
        print("❌ Nouveau modèle moins bon, conservation de l'ancien.")

if __name__ == "__main__":
    main()
