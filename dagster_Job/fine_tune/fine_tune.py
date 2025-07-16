import os
import json
import pickle
import psycopg2
import numpy as np
import pandas as pd
from tensorflow.keras.models import load_model
from sklearn.metrics import classification_report, accuracy_score
from model import construire_ann  # ta fonction pour créer le modèle
import mlflow
import mlflow.keras
import mlflow.sklearn
from datetime import datetime

# === CONFIGURATION ===
import os

# Configuration MLflow
os.environ["MLFLOW_TRACKING_URI"] = os.environ.get("MLFLOW_TRACKING_URI", "http://mlflow:5000")
EXPERIMENT_NAME = "network_anomaly_detection"

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
    report = classification_report(y, y_pred, output_dict=True)
    print(classification_report(y, y_pred))
    accuracy = accuracy_score(y, y_pred)

    # Retourner les métriques pour MLflow
    metrics = {
        "accuracy": accuracy,
        "precision_0": report["0"]["precision"],
        "recall_0": report["0"]["recall"],
        "f1_score_0": report["0"]["f1-score"],
        "precision_1": report["1"]["precision"],
        "recall_1": report["1"]["recall"],
        "f1_score_1": report["1"]["f1-score"],
    }

    return accuracy, metrics

# === PIPELINE PRINCIPAL ===
def main():
    # Configurer MLflow
    mlflow.set_experiment(EXPERIMENT_NAME)

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
    if hasattr(scaler, 'transform'):
        X_scaled = scaler.transform(X_new)
    else:
        from sklearn.preprocessing import StandardScaler
        temp_scaler = StandardScaler()
        temp_scaler.fit(X_new)
        if isinstance(scaler, tuple) and len(scaler) == 2:
            temp_scaler.mean_ = scaler[0]
            temp_scaler.scale_ = scaler[1]
        X_scaled = temp_scaler.transform(X_new)

    # Démarrer un run MLflow
    with mlflow.start_run(run_name=f"fine_tune_{datetime.now().strftime('%Y%m%d_%H%M%S')}"):
        # Loguer les paramètres
        mlflow.log_params({
            "epochs": 5,
            "batch_size": 32,
            "validation_split": 0.2,
            "input_features": len(FEATURES),
            "training_samples": len(X_new)
        })

        # Loguer le scaler
        mlflow.sklearn.log_model(scaler, "scaler")

        # Évaluer l'ancien modèle
        print("📊 Évaluation du modèle actuel...")
        acc_old, metrics_old = evaluate_model(current_model, X_blind, y_blind, label="Ancien modèle")

        # Loguer les métriques de l'ancien modèle
        for key, value in metrics_old.items():
            mlflow.log_metric(f"old_{key}", value)

        # Créer nouveau modèle avec mêmes poids
        print("🔁 Réentraînement du modèle avec feedback...")
        new_model = construire_ann(X_scaled.shape[1])
        new_model.set_weights(current_model.get_weights())

        # Entraîner le modèle et capturer l'historique
        history = new_model.fit(
            X_scaled, y_new, 
            epochs=5, 
            batch_size=32, 
            validation_split=0.2,
            verbose=1
        )

        # Loguer les métriques d'entraînement
        for epoch, (loss, acc, val_loss, val_acc) in enumerate(zip(
            history.history['loss'],
            history.history['accuracy'],
            history.history['val_loss'],
            history.history['val_accuracy']
        )):
            mlflow.log_metrics({
                "train_loss": loss,
                "train_accuracy": acc,
                "val_loss": val_loss,
                "val_accuracy": val_acc
            }, step=epoch)

        # Évaluer le nouveau modèle
        acc_new, metrics_new = evaluate_model(new_model, X_blind, y_blind, label="Nouveau modèle")

        # Loguer les métriques du nouveau modèle
        for key, value in metrics_new.items():
            mlflow.log_metric(f"new_{key}", value)

        # Loguer l'amélioration
        improvement = acc_new - acc_old
        mlflow.log_metric("accuracy_improvement", improvement)

        # Comparaison et sauvegarde
        if acc_new >= acc_old:
            print("✅ Nouveau modèle adopté, sauvegarde en cours...")
            new_model.save(MODEL_PATH)
            # Loguer le modèle dans MLflow
            mlflow.keras.log_model(new_model, "model")
            mlflow.log_artifact(MODEL_PATH, "saved_model")
            mlflow.set_tag("model_status", "adopted")
        else:
            print("❌ Nouveau modèle moins bon, conservation de l'ancien.")
            mlflow.keras.log_model(current_model, "model")
            mlflow.set_tag("model_status", "rejected")

if __name__ == "__main__":
    main()
