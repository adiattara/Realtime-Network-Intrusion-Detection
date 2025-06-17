FROM python:3.9-slim

LABEL authors="adiattara"

WORKDIR /app

# Copie du code + modèle + dépendances
COPY serving.py model.pkl requirements.txt ./

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8000

# Ici on pointe sur le module `serving` et l’application `app`
CMD ["uvicorn", "serving:app", "--host", "0.0.0.0", "--port", "8000"]

