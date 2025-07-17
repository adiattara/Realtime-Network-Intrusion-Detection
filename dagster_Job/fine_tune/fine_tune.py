import os
import json
import pickle
import psycopg2
import numpy as np
import pandas as pd
import tensorflow as tf
from tensorflow.keras.models import load_model
from sklearn.metrics import classification_report, accuracy_score
from model import construire_ann
import wandb
from datetime import datetime

# === CONFIGURATION ===
# Weights & Biases configuration
WANDB_PROJECT = "network_anomaly_detection"
WANDB_ENTITY = os.environ.get("WANDB_ENTITY", None)  # Your wandb username or team name
WANDB_API_KEY = os.environ.get("WANDB_API_KEY", None)  # Your wandb API key
MODEL_NAME = "network_anomaly_detection_model"

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


def load_feedback_flows():
    """Charger les données de feedback"""
    conn = psycopg2.connect(**DB_CONFIG)
    df = pd.read_sql("SELECT flow_data, label_humain FROM reported_flows", conn)
    conn.close()

    def extract_features(flow_json):
        try:
            flow = json.loads(flow_json)
            return [flow.get(f, 0) for f in FEATURES]
        except Exception as e:
            print(f"Erreur parsing JSON: {e}")
            return [0] * len(FEATURES)

    features_df = df["flow_data"].apply(extract_features).apply(pd.Series)
    features_df.columns = FEATURES
    features_df["label"] = df["label_humain"].map({"Normal": 0, "Mal": 1})

    result = features_df.dropna()
    print(f"✅ Données chargées: {len(result)} échantillons")
    return result


def evaluate_model(model, X, y, label=""):
    """Évaluer un modèle"""
    y_pred = (model.predict(X) > 0.5).astype(int)
    accuracy = accuracy_score(y, y_pred)
    print(f"📊 {label} - Accuracy: {accuracy:.4f}")
    return accuracy


def main():
    print("🚀 FINE-TUNING AVEC WEIGHTS & BIASES")

    # Configuration Weights & Biases
    if WANDB_API_KEY:
        os.environ["WANDB_API_KEY"] = WANDB_API_KEY

    # Charger les données
    df = load_feedback_flows()
    X_new = df[FEATURES].values
    y_new = df["label"].astype(int).values

    # Charger les assets
    print("📁 Chargement des assets...")
    with open(SCALER_PATH, "rb") as f:
        scaler = pickle.load(f)
    with open(X_BLIND_PATH, "rb") as f:
        X_blind = pickle.load(f)
    with open(Y_BLIND_PATH, "rb") as f:
        y_blind = pickle.load(f)
    current_model = load_model(MODEL_PATH)
    print("✅ Assets chargés")

    # Préparer les données
    if hasattr(scaler, 'transform'):
        X_scaled = scaler.transform(X_new)
    else:
        X_scaled = X_new

    # Initialize wandb
    run_name = f"fine_tune_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    wandb.init(
        project=WANDB_PROJECT,
        entity=WANDB_ENTITY,
        name=run_name,
        config={
            "model_name": MODEL_NAME,
            "epochs": 5,
            "batch_size": 32,
            "input_features": len(FEATURES),
            "training_samples": len(X_new),
            "features": FEATURES
        }
    )
    print(f"✅ Weights & Biases configuré - Projet: {WANDB_PROJECT}, Run: {run_name}")

    # Get the run ID
    run_id = wandb.run.id

    # Entraîner le modèle
    print("🎯 Entraînement du modèle...")
    new_model = construire_ann(X_scaled.shape[1])
    new_model.set_weights(current_model.get_weights())

    # Add WandbCallback to log metrics during training
    from wandb.keras import WandbCallback
    history = new_model.fit(
        X_scaled, y_new,
        epochs=5,
        batch_size=32,
        validation_split=0.2,
        verbose=1,
        callbacks=[WandbCallback()]
    )

    # Évaluer le nouveau modèle
    acc_new = evaluate_model(new_model, X_blind, y_blind, "Nouveau modèle")
    wandb.log({"accuracy": acc_new})

    # STOCKAGE DU MODÈLE
    print("💾 STOCKAGE DU MODÈLE AVEC WANDB...")

    # 1. Sauvegarder localement d'abord
    model_filename = f"model_{run_id}.h5"
    new_model.save(model_filename)
    print(f"✅ Modèle sauvegardé localement: {model_filename}")

    # 2. Logger le modèle avec wandb
    try:
        print("🔄 Logging du modèle avec wandb...")
        # Log the model as an artifact
        model_artifact = wandb.Artifact(
            name=f"{MODEL_NAME}-{run_id}", 
            type="model",
            description=f"Trained model with accuracy {acc_new:.4f}"
        )
        model_artifact.add_file(model_filename)
        wandb.log_artifact(model_artifact)
        print("✅ Modèle loggé avec wandb")

        # 3. Logger aussi le scaler
        print("🔄 Logger le scaler...")
        with open(SCALER_PATH, "rb") as f:
            scaler_data = f.read()

        # Créer un fichier scaler temporaire
        temp_scaler = f"scaler_{run_id}.pkl"
        with open(temp_scaler, "wb") as f:
            f.write(scaler_data)

        # Log the scaler as an artifact
        scaler_artifact = wandb.Artifact(
            name=f"scaler-{run_id}", 
            type="preprocessor",
            description="Feature scaler for the model"
        )
        scaler_artifact.add_file(temp_scaler)
        wandb.log_artifact(scaler_artifact)
        print("✅ Scaler loggé avec wandb")

        # Nettoyer
        os.remove(temp_scaler)

    except Exception as e:
        print(f"❌ Erreur lors du logging des artefacts: {e}")

    # 4. Remplacer le modèle actuel
    new_model.save(MODEL_PATH)
    print(f"✅ Modèle actuel remplacé: {MODEL_PATH}")

    # 5. Nettoyer le fichier temporaire
    os.remove(model_filename)

    # 6. Enregistrer le modèle dans le Model Registry de W&B
    try:
        print("🔄 Enregistrement du modèle dans le Model Registry...")
        # Create a model registry entry
        registry_artifact = wandb.Artifact(
            name=MODEL_NAME, 
            type="model",
            description=f"Latest model with accuracy {acc_new:.4f}"
        )
        registry_artifact.add_file(MODEL_PATH)

        # Log and register the model
        wandb.log_artifact(registry_artifact)

        # Alias the model as "latest" or "production" depending on performance
        if acc_new > 0.8:  # Example threshold
            registry_artifact.aliases.append("production")
            print("✅ Modèle enregistré comme 'production' dans le Model Registry")
        else:
            registry_artifact.aliases.append("latest")
            print("✅ Modèle enregistré comme 'latest' dans le Model Registry")
    except Exception as e:
        print(f"❌ Erreur lors de l'enregistrement dans le Model Registry: {e}")

    # Finish the wandb run
    wandb.finish()

    print("🎉 FINE-TUNING TERMINÉ AVEC WANDB")
    print(f"📍 Accuracy: {acc_new:.4f}")
    print(f"🌐 Run ID: {run_id}")
    print(f"📁 Artefacts stockés dans Weights & Biases")


if __name__ == "__main__":
    main()
