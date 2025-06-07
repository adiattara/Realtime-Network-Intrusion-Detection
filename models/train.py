# train.py
import pickle

import pandas as pd
import seaborn as sns
from matplotlib import pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from data_loader import charger_donnees_csv
from feature_engineering import nettoyer
from model import construire_ann
from config import dossiers_donnees, colonnes_utiles, colonnes_numeriques
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, accuracy_score
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report



if __name__ == "__main__":
    # 1. Charger les données
    df = charger_donnees_csv(dossiers_donnees)

    minority = df[df['attack'] == False]
    majority = df[df['attack'] == True].sample(n=len(minority), random_state=42)

    df = pd.concat([minority, majority]).sample(frac=1, random_state=42)

    df.head()

    print(df.head())
    #print(df.dtypes)
    # Nettoyer et normaliser
    df = nettoyer(df)
    #print(df.dtypes)
    X = df.drop('attack', axis=1)
    y = df['attack'].astype(int)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    # Split train/test
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.2, random_state=42,stratify=y
    )

    model = construire_ann(X_train.shape[1])

    history = model.fit(X_train, y_train, validation_split=0.2, epochs=5, batch_size=32)

    # Sauvegarde
    with open("model.pkl", "wb") as f:
        pickle.dump(model, f)

    #
    # Évaluer
    y_pred = (model.predict(X_test) > 0.5).astype(int)

    print("\n✅ Rapport de classification :")
    print(classification_report(y_test, y_pred))

    print(classification_report(y_test, y_pred))

