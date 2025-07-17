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
            "MLFLOW_TRACKING_URI": "http://mlflow:5000",
            "S3_BUCKET_NAME": os.environ.get("S3_BUCKET_NAME", "rnid-retrained-models-pa"),
            "S3_ENDPOINT_URL": os.environ.get("S3_ENDPOINT_URL", "https://s3.eu-west-3.amazonaws.com"),
            "AWS_ACCESS_KEY_ID": os.environ.get("AWS_ACCESS_KEY_ID", "AKIA3DZD3S725PDEIAUT"),
            "AWS_SECRET_ACCESS_KEY": os.environ.get("AWS_SECRET_ACCESS_KEY", "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")
        })
        context.log.info(f"Bucket: {env['S3_BUCKET_NAME']} Endpoint: {env['S3_ENDPOINT_URL']}")

        # Change to the fine_tune directory to ensure the script can find all required files
        result = subprocess.run(
            ["python", "fine_tune.py"],
            check=True,
            capture_output=True,
            text=True,
            env=env,
            cwd="/opt/dagster/dagster_home/fine_tune"
        )
        context.log.info("✅ Réentraînement terminé avec succès..")
        context.log.debug(f"Sortie du script :\n{result.stdout}")
    except subprocess.CalledProcessError as e:
        context.log.error("❌ Échec du réentraînement.")
        context.log.error(f"Stderr: {e.stderr}")
        context.log.error(f"Exit code: {e.returncode}")
        raise

@job
def model_retraining_job():
    fine_tune_model_op()
