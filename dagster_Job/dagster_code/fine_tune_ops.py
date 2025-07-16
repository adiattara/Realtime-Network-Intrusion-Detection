import subprocess
import os
from dagster import op, job

@op
def fine_tune_model_op(context):
    """Opération Dagster qui exécute le script de réentraînement."""
    try:
        context.log.info("Lancement du script de réentraînement...")

        # Préparer les variables d'environnement pour la connexion à la base de données
        env = os.environ.copy()
        env.update({
            "DB_HOST": "network_db",
            "DB_PORT": "5432",
            "DB_NAME": "networkdb",
            "DB_USER": "user",
            "DB_PASSWORD": "password",
            "MLFLOW_TRACKING_URI": "http://mlflow:5000"
        })

        # Change to the fine_tune directory to ensure the script can find all required files
        result = subprocess.run(
            ["python", "fine_tune.py"],
            check=True,
            capture_output=True,
            text=True,
            env=env,
            cwd="/opt/dagster/dagster_home/fine_tune"
        )
        context.log.info("✅ Réentraînement terminé avec succès.")
        context.log.debug(f"Sortie du script :\n{result.stdout}")
    except subprocess.CalledProcessError as e:
        context.log.error("❌ Échec du réentraînement.")
        context.log.error(f"Stderr: {e.stderr}")
        context.log.error(f"Exit code: {e.returncode}")
        raise

@job
def model_retraining_job():
    fine_tune_model_op()
