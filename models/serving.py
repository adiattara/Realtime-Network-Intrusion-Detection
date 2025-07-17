from fastapi import FastAPI
from pydantic import BaseModel
import pickle
import numpy as np
from tensorflow.keras.models import load_model

feature_cols = [
  "total_bytes",
  "pkt_count",
  "psh_count",
  "fwd_bytes",
  "bwd_bytes",
  "fwd_pkts",
  "bwd_pkts",
  "dport",
  "duration_ms",
  "flow_pkts_per_s",
  "fwd_bwd_ratio"
]
# 1) Schéma de la requête HTTP
class FlowFeatures(BaseModel):
    total_bytes: int
    pkt_count: int
    psh_count: int
    fwd_bytes: int
    bwd_bytes: int
    fwd_pkts: int
    bwd_pkts: int
    dport: int
    duration_ms: float
    flow_pkts_per_s: float
    fwd_bwd_ratio: float


app = FastAPI(title="Network IDS Predictor", version="1.0")

# 2) Charger le modèle globalement (startup)
model = load_model("model.h5")
with open("scaler.pkl", "rb") as f:
    scaler = pickle.load(f)

@app.get("/")
def root():
    return {"message": "Network IDS FastAPI Model Server is up."}

@app.post("/predict")
def predict_flow(features: FlowFeatures):
    # 1) Construire ton vecteur à partir du body JSON
    X = np.array([[getattr(features, col) for col in feature_cols]], dtype=float)

    # 2) Appliquer le scaler
    X_scaled = scaler.transform(X)

    # 3) Prédire la probabilité
    prob = float(model.predict(X_scaled)[0, 0])
    print("Probabilité prédite :", prob)  # pour debug

    # 4) Choisir le label
    label = "Mal" if prob > 0.5 else "Normal"

    return {"label": label, "score": prob}


