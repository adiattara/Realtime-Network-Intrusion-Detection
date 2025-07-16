FROM python:3.9-slim

WORKDIR /app

# 1. Installer les dépendances système
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
  && rm -rf /var/lib/apt/lists/*

# 2. Copier tout le contenu du dossier fine_tune
COPY . .

# 3. Installer les dépendances Python
RUN pip install --no-cache-dir -r requirements.txt

# 4. Point d’entrée
ENTRYPOINT ["python", "fine_tune.py"]
