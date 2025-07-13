FROM python:3.10-slim

# Crée le répertoire pour Dagster
RUN mkdir -p /opt/dagster/dagster_home

# Copie les dépendances
COPY requirements.txt /opt/dagster/dagster_home/
RUN cd /opt/dagster/dagster_home/ && pip install --no-cache-dir -r requirements.txt

# Copie les fichiers de configuration Dagster
COPY workspace.yaml /opt/dagster/dagster_home/
COPY dagster.yaml /opt/dagster/dagster_home/

# Copie le code Dagster (jobs, ops, etc.)
COPY dagster_code/* /opt/dagster/dagster_home/dagster_code/

ENV PYTHONPATH="${PYTHONPATH}:/opt/dagster/dagster_home"


# ✅ Copie du dossier fine_tune contenant la logique de réentraînement
COPY fine_tune/* /opt/dagster/dagster_home/fine_tune/

# Définit le DAGSTER_HOME
ENV DAGSTER_HOME=/opt/dagster/dagster_home/

# Positionne le dossier de travail
WORKDIR /opt/dagster/dagster_home/
