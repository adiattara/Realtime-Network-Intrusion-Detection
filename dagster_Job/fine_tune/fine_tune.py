import os
import json
import pickle
import psycopg2
import boto3
from botocore.exceptions import BotoCoreError, NoCredentialsError
import pandas as pd
from tensorflow.keras.models import load_model
from sklearn.metrics import classification_report, accuracy_score
from datetime import datetime
import mlflow
from model import construire_ann

DB_CONFIG = {
    "host": os.environ.get("DB_HOST", "network_db"),
    "port": int(os.environ.get("DB_PORT", 5432)),
    "database": os.environ.get("DB_NAME", "networkdb"),
    "user": os.environ.get("DB_USER", "user"),
    "password": os.environ.get("DB_PASSWORD", "password"),
}

MODEL_PATH = "model.h5"
SCALER_PATH = "scaler.pkl"
X_BLIND_PATH = "X_blind_test.pkl"
Y_BLIND_PATH = "y_blind_test.pkl"

S3_BUCKET = os.environ.get("S3_BUCKET_NAME", "models")
S3_ENDPOINT = os.environ.get("S3_ENDPOINT_URL")
AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")

FEATURES = [
    "total_bytes", "pkt_count", "psh_count", "fwd_bytes", "bwd_bytes",
    "fwd_pkts", "bwd_pkts", "dport", "duration_ms", "flow_pkts_per_s", "fwd_bwd_ratio",
]

def upload_to_s3(file_path, object_name):
    session = boto3.session.Session(
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    )
    client = session.client("s3", endpoint_url=S3_ENDPOINT)
    try:
        client.upload_file(file_path, S3_BUCKET, object_name)
        print(f"✅ Fichier {file_path} envoyé sur S3 -> {S3_BUCKET}/{object_name}")
    except (BotoCoreError, NoCredentialsError) as e:
        print(f"❌ Erreur lors de l'envoi sur S3: {e}")

def load_feedback_flows():
    conn = psycopg2.connect(**DB_CONFIG)
    df = pd.read_sql("SELECT flow_data, label_humain FROM reported_flows", conn)
    conn.close()
    def extract_features(flow_json):
        try:
            flow = json.loads(flow_json)
            return [flow.get(f, 0) for f in FEATURES]
        except Exception:
            return [0] * len(FEATURES)
    features_df = df["flow_data"].apply(extract_features).apply(pd.Series)
    features_df.columns = FEATURES
    features_df["label"] = df["label_humain"].map({"Normal": 0, "Mal": 1})
    return features_df.dropna()

def evaluate_model(model, X, y, label=""):
    y_pred = (model.predict(X) > 0.5).astype(int)
    print(f"\n📊 Rapport de classification : {label}")
    print(classification_report(y, y_pred))
    report = classification_report(y, y_pred, output_dict=True)
    accuracy = accuracy_score(y, y_pred)
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

def main():
    print("📥 Chargement des données signalées...")
    df = load_feedback_flows()
    X_new = df[FEATURES].values
    y_new = df["label"].astype(int).values

    with open(SCALER_PATH, "rb") as f:
        scaler = pickle.load(f)
    with open(X_BLIND_PATH, "rb") as f:
        X_blind = pickle.load(f)
    with open(Y_BLIND_PATH, "rb") as f:
        y_blind = pickle.load(f)

    current_model = load_model(MODEL_PATH)

    if hasattr(scaler, "transform"):
        X_scaled = scaler.transform(X_new)
    else:
        from sklearn.preprocessing import StandardScaler
        temp_scaler = StandardScaler()
        temp_scaler.fit(X_new)
        if isinstance(scaler, tuple) and len(scaler) == 2:
            temp_scaler.mean_, temp_scaler.scale_ = scaler
        X_scaled = temp_scaler.transform(X_new)

    # Start MLflow run
    with mlflow.start_run(run_name="model_retraining") as run:
        print("📊 Évaluation du modèle actuel...")
        acc_old, metrics_old = evaluate_model(current_model, X_blind, y_blind, label="Ancien modèle")

        # Log old model metrics
        mlflow.log_metrics({f"old_{k}": v for k, v in metrics_old.items()})

        print("🔁 Réentraînement du modèle avec feedback...")
        new_model = construire_ann(X_scaled.shape[1])
        new_model.set_weights(current_model.get_weights())

        # Log training parameters
        mlflow.log_params({
            "epochs": 5,
            "batch_size": 32,
            "validation_split": 0.2,
            "num_features": X_scaled.shape[1],
            "num_training_samples": len(X_new)
        })

        # Train the model and capture history
        history = new_model.fit(
            X_scaled, y_new, 
            epochs=5, 
            batch_size=32, 
            validation_split=0.2, 
            verbose=1
        )

        # Log training metrics from history
        for epoch, metrics in enumerate(zip(
            history.history.get('loss', []),
            history.history.get('accuracy', []),
            history.history.get('val_loss', []),
            history.history.get('val_accuracy', [])
        )):
            mlflow.log_metrics({
                f"epoch_{epoch+1}_loss": metrics[0],
                f"epoch_{epoch+1}_accuracy": metrics[1],
                f"epoch_{epoch+1}_val_loss": metrics[2],
                f"epoch_{epoch+1}_val_accuracy": metrics[3]
            })

        acc_new, metrics_new = evaluate_model(new_model, X_blind, y_blind, label="Nouveau modèle")

        # Log new model metrics
        mlflow.log_metrics({f"new_{k}": v for k, v in metrics_new.items()})

        # Log improvement
        mlflow.log_metric("accuracy_improvement", acc_new - acc_old)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        tmp_model_path = f"retrained_model_{timestamp}.h5"
        new_model.save(tmp_model_path)
        upload_to_s3(tmp_model_path, os.path.basename(tmp_model_path))

        if acc_new >= acc_old:
            print("✅ Nouveau modèle adopté, mise à jour...")
            os.replace(tmp_model_path, MODEL_PATH)
            mlflow.log_metric("model_adopted", 1)
        else:
            print("❌ Nouveau modèle moins bon, conservation de l'ancien")
            os.remove(tmp_model_path)
            mlflow.log_metric("model_adopted", 0)

if __name__ == "__main__":
    main()
