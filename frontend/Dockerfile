FROM python:3.10-slim

WORKDIR /app

# Installer les dépendances système
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Installer numpy d'abord pour éviter les conflits
RUN pip install --no-cache-dir numpy==1.24.3

# Copier requirements et installer
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copier le code
COPY . .

# Créer répertoire SSH
RUN mkdir -p /app/ssh_keys

EXPOSE 8050

CMD ["python", "main.py"]