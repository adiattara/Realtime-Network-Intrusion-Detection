import os
import json
import pickle
import psycopg2
import numpy as np
import pandas as pd
import tensorflow as tf
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
REGISTERED_MODEL_NAME = "network_anomaly_detection_model"

# Explication du Model Registry:
# Le Model Registry de MLflow permet de gérer le cycle de vie des modèles avec:
# - Versionnement automatique: chaque modèle enregistré reçoit un numéro de version
# - Gestion des étapes (stages): Development, Staging, Production, Archived
# - Transitions entre étapes: un modèle peut passer de Staging à Production
# - Traçabilité: chaque modèle est lié à l'expérience qui l'a produit
#
# Dans ce script:
# - Les nouveaux modèles performants sont enregistrés et mis en "Production"
# - Les anciens modèles de production sont archivés
# - Les modèles moins performants sont enregistrés en "Staging" pour évaluation

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
    print("\n=== Configuration MLflow ===")
    print(f"MLFLOW_TRACKING_URI: {os.environ.get('MLFLOW_TRACKING_URI', 'Non défini')}")
    print(f"EXPERIMENT_NAME: {EXPERIMENT_NAME}")
    print(f"REGISTERED_MODEL_NAME: {REGISTERED_MODEL_NAME}")

    # Vérifier que MLflow est accessible
    try:
        # Tester la connexion au serveur MLflow
        import requests
        mlflow_uri = os.environ.get('MLFLOW_TRACKING_URI', 'http://mlflow:5000')
        print(f"🔍 Test de connexion au serveur MLflow à {mlflow_uri}...")

        try:
            response = requests.get(mlflow_uri)
            if response.status_code == 200:
                print(f"✅ Connexion au serveur MLflow réussie (status code: {response.status_code})")
            else:
                print(f"⚠️ Connexion au serveur MLflow établie mais avec un status code inattendu: {response.status_code}")
        except Exception as conn_err:
            print(f"❌ Erreur de connexion au serveur MLflow: {conn_err}")
            print("⚠️ Cela peut indiquer un problème de réseau ou que le serveur MLflow n'est pas accessible")

        # Configurer l'expérience MLflow
        mlflow.set_experiment(EXPERIMENT_NAME)
        print(f"✅ MLflow accessible, expérience '{EXPERIMENT_NAME}' configurée")

        # Afficher les informations sur l'expérience
        from mlflow.tracking import MlflowClient
        client = MlflowClient()
        experiment = client.get_experiment_by_name(EXPERIMENT_NAME)
        if experiment:
            print(f"ℹ️ Expérience ID: {experiment.experiment_id}")
            print(f"ℹ️ Artefact Location: {experiment.artifact_location}")
        else:
            print(f"⚠️ L'expérience '{EXPERIMENT_NAME}' n'a pas été trouvée")
    except Exception as e:
        print(f"❌ Erreur lors de la configuration de MLflow: {e}")
        print("⚠️ Tentative de continuer malgré l'erreur...")

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
    run_name = f"fine_tune_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    print(f"\n=== Démarrage du run MLflow: {run_name} ===")

    with mlflow.start_run(run_name=run_name) as active_run:
        print(f"✅ Run MLflow démarré avec succès: {active_run.info.run_id}")
        # Afficher le chemin où les artefacts seront stockés
        artifact_uri = mlflow.get_artifact_uri()
        print(f"📁 Chemin des artefacts: {artifact_uri}")

        # Vérifier si le chemin des artefacts est accessible
        try:
            # Créer un fichier test pour vérifier l'accès en écriture
            test_file_path = os.path.join(os.getcwd(), "mlflow_test_file.txt")
            with open(test_file_path, "w") as f:
                f.write("Test MLflow artifact access")

            # Loguer le fichier test comme artefact
            mlflow.log_artifact(test_file_path, "test")
            print(f"✅ Test d'accès aux artefacts réussi: fichier test loggé à {artifact_uri}/test/mlflow_test_file.txt")

            # Supprimer le fichier test local
            os.remove(test_file_path)
        except Exception as e:
            print(f"❌ Erreur lors du test d'accès aux artefacts: {e}")
            print("⚠️ Cela peut indiquer un problème d'accès au stockage des artefacts")
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
            print("📝 Logging du modèle dans MLflow...")
            try:
                # Sauvegarder le modèle localement d'abord
                model_abs_path = os.path.abspath(MODEL_PATH)
                print(f"📝 Sauvegarde du modèle localement à {model_abs_path}...")
                new_model.save(MODEL_PATH)

                # Vérifier que le fichier a bien été créé
                if os.path.exists(MODEL_PATH):
                    print(f"✅ Modèle sauvegardé localement à {model_abs_path}")
                    print(f"   Taille du fichier: {os.path.getsize(MODEL_PATH)} octets")

                    # Vérifier que le modèle peut être rechargé
                    try:
                        # Use the already imported load_model function
                        test_model = load_model(MODEL_PATH)
                        print(f"✅ Modèle rechargé avec succès pour vérification")
                    except Exception as e:
                        print(f"❌ Erreur lors du rechargement du modèle pour vérification: {e}")
                else:
                    print(f"❌ Échec de la sauvegarde du modèle: le fichier {model_abs_path} n'existe pas")

                # Loguer le modèle directement dans MLflow
                mlflow.keras.log_model(new_model, "model")
                print("✅ Modèle loggé dans MLflow avec mlflow.keras.log_model")

                # Loguer le fichier du modèle comme artefact
                print(f"📝 Logging du fichier modèle {MODEL_PATH} comme artefact...")
                mlflow.log_artifact(MODEL_PATH, "saved_model")

                # Vérifier que l'artefact a bien été loggé
                artifact_path = os.path.join("saved_model", os.path.basename(MODEL_PATH))
                try:
                    # Obtenir l'URI de l'artefact
                    artifact_uri = mlflow.get_artifact_uri(artifact_path)
                    print(f"✅ Fichier modèle loggé comme artefact à {artifact_uri}")

                    # Vérifier si l'URI est un chemin local ou distant
                    if artifact_uri.startswith("file:"):
                        local_path = artifact_uri.replace("file:", "")
                        if os.path.exists(local_path):
                            print(f"✅ Vérification: L'artefact existe à {local_path}")
                            print(f"   Taille de l'artefact: {os.path.getsize(local_path)} octets")
                        else:
                            print(f"❌ Vérification: L'artefact n'existe pas à {local_path}")
                    else:
                        print(f"ℹ️ L'artefact est stocké à distance, impossible de vérifier directement")
                except Exception as e:
                    print(f"❌ Erreur lors de la vérification de l'artefact: {e}")

                # Vérifier que le fichier existe localement
                if os.path.exists(MODEL_PATH):
                    print(f"✅ Vérification: Le fichier {MODEL_PATH} existe localement")
                else:
                    print(f"❌ Vérification: Le fichier {MODEL_PATH} n'existe pas localement")

                mlflow.set_tag("model_status", "adopted")
            except Exception as e:
                print(f"❌ Erreur lors du logging du modèle: {e}")
                # Continuer malgré l'erreur pour ne pas bloquer le processus

            # Enregistrer le modèle dans le Model Registry
            try:
                model_uri = f"runs:/{mlflow.active_run().info.run_id}/model"
                registered_model = mlflow.register_model(
                    model_uri=model_uri,
                    name=REGISTERED_MODEL_NAME
                )
                print(f"✅ Modèle enregistré dans le registry: {registered_model.name} version {registered_model.version}")
            except Exception as e:
                print(f"⚠️ Erreur lors de l'enregistrement du modèle dans le registry: {e}")
                print("⚠️ Le modèle a été sauvegardé localement mais n'a pas pu être enregistré dans le registry")
                return

            # Transition du modèle vers la production
            try:
                client = mlflow.tracking.MlflowClient()

                # Vérifier s'il existe déjà un modèle en production
                production_models = client.get_latest_versions(REGISTERED_MODEL_NAME, stages=["Production"])

                # Déplacer le nouveau modèle vers la production
                client.transition_model_version_stage(
                    name=REGISTERED_MODEL_NAME,
                    version=registered_model.version,
                    stage="Production"
                )
                print(f"✅ Modèle version {registered_model.version} transitionné vers la Production")

                # Archiver les anciens modèles de production
                for model in production_models:
                    client.transition_model_version_stage(
                        name=REGISTERED_MODEL_NAME,
                        version=model.version,
                        stage="Archived"
                    )
                    print(f"📦 Ancien modèle version {model.version} archivé")
            except Exception as e:
                print(f"⚠️ Erreur lors de la transition du modèle: {e}")
                print("⚠️ Le modèle a été enregistré mais n'a pas pu être transitionné vers la Production")
        else:
            print("❌ Nouveau modèle moins bon, conservation de l'ancien.")
            print("📝 Logging de l'ancien modèle dans MLflow...")
            try:
                # Loguer l'ancien modèle directement dans MLflow
                mlflow.keras.log_model(current_model, "model")
                print("✅ Ancien modèle loggé dans MLflow avec mlflow.keras.log_model")

                # Loguer le fichier du modèle comme artefact
                print(f"📝 Logging du fichier modèle {MODEL_PATH} comme artefact...")
                mlflow.log_artifact(MODEL_PATH, "saved_model")

                # Vérifier que l'artefact a bien été loggé
                artifact_path = os.path.join("saved_model", os.path.basename(MODEL_PATH))
                try:
                    # Obtenir l'URI de l'artefact
                    artifact_uri = mlflow.get_artifact_uri(artifact_path)
                    print(f"✅ Fichier modèle loggé comme artefact à {artifact_uri}")

                    # Vérifier si l'URI est un chemin local ou distant
                    if artifact_uri.startswith("file:"):
                        local_path = artifact_uri.replace("file:", "")
                        if os.path.exists(local_path):
                            print(f"✅ Vérification: L'artefact existe à {local_path}")
                            print(f"   Taille de l'artefact: {os.path.getsize(local_path)} octets")
                        else:
                            print(f"❌ Vérification: L'artefact n'existe pas à {local_path}")
                    else:
                        print(f"ℹ️ L'artefact est stocké à distance, impossible de vérifier directement")
                except Exception as e:
                    print(f"❌ Erreur lors de la vérification de l'artefact: {e}")

                # Vérifier que le fichier existe localement
                if os.path.exists(MODEL_PATH):
                    print(f"✅ Vérification: Le fichier {MODEL_PATH} existe localement")
                else:
                    print(f"❌ Vérification: Le fichier {MODEL_PATH} n'existe pas localement")

                mlflow.set_tag("model_status", "rejected")
            except Exception as e:
                print(f"❌ Erreur lors du logging de l'ancien modèle: {e}")
                # Continuer malgré l'erreur pour ne pas bloquer le processus

            # Enregistrer quand même l'ancien modèle dans le registry pour traçabilité
            try:
                model_uri = f"runs:/{mlflow.active_run().info.run_id}/model"
                registered_model = mlflow.register_model(
                    model_uri=model_uri,
                    name=REGISTERED_MODEL_NAME
                )
                print(f"✅ Ancien modèle enregistré dans le registry: {registered_model.name} version {registered_model.version}")
            except Exception as e:
                print(f"⚠️ Erreur lors de l'enregistrement du modèle dans le registry: {e}")
                print("⚠️ Le modèle a été sauvegardé localement mais n'a pas pu être enregistré dans le registry")
                return

            # Transition du modèle vers le stage Staging pour évaluation ultérieure
            try:
                client = mlflow.tracking.MlflowClient()
                client.transition_model_version_stage(
                    name=REGISTERED_MODEL_NAME,
                    version=registered_model.version,
                    stage="Staging"
                )
                print(f"🔍 Modèle version {registered_model.version} transitionné vers Staging pour évaluation ultérieure")
            except Exception as e:
                print(f"⚠️ Erreur lors de la transition du modèle vers Staging: {e}")
                print("⚠️ Le modèle a été enregistré mais n'a pas pu être transitionné vers Staging")

if __name__ == "__main__":
    main()
