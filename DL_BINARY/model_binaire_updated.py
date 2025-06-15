
"""
This script builds, trains, and evaluates a CNN model for binary classification
"""

from pathlib import Path
import random
import os
from dotenv import load_dotenv
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix, roc_curve, auc, precision_recall_curve, f1_score
import tensorflow as tf
from tensorflow.keras.layers import (Input, Conv1D, MaxPooling1D, Dropout,
                                     Flatten, Dense)
from tensorflow.keras.models import Sequential
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau
import matplotlib.pyplot as plt
import time
import mlflow
import mlflow.tensorflow


def add_mean_pkt_size(df: pd.DataFrame) -> pd.DataFrame:
    """Add forward/backward mean packet‑size columns (in‑place)."""
    df["fwd_mean_pkt_size"] = np.where(df["spkts"] == 0, 0,
                                       df["sbytes"] / df["spkts"])
    df["bwd_mean_pkt_size"] = np.where(df["dpkts"] == 0, 0,
                                       df["dbytes"] / df["dpkts"])
    return df

def build_cnn(input_steps: int, input_channels: int) -> Sequential:
    """Return compiled 1‑D CNN for binary classification."""
    model = Sequential([
        Input(shape=(input_steps, input_channels)),
        # Block 1
        Conv1D(32, 3, padding="same", activation="relu"),
        Conv1D(32, 3, padding="same", activation="relu"),
        MaxPooling1D(2),
        Dropout(0.20),
        # Block 2
        Conv1D(64, 3, padding="same", activation="relu"),
        Conv1D(64, 3, padding="same", activation="relu"),
        MaxPooling1D(2),
        Dropout(0.30),
        # Dense
        Flatten(),
        Dense(128, activation="relu"),
        Dropout(0.40),
        Dense(1, activation="sigmoid")  # Binary classification: 1 neuron with sigmoid
    ])
    model.compile(
        optimizer=Adam(learning_rate=LR),
        loss="binary_crossentropy",  # Binary classification loss
        metrics=["accuracy"]
    )
    return model

def main():
    # --------------------------------------------------------------------------- #
    # 1. Reproducibility
    # --------------------------------------------------------------------------- #
    SEED = 42
    tf.keras.utils.set_random_seed(SEED)
    np.random.seed(SEED)
    random.seed(SEED)

    # --------------------------------------------------------------------------- #
    # 2. Paths & Params
    # --------------------------------------------------------------------------- #
    global LR  # Make LR accessible to build_cnn function
    
    DATA_DIR_TRAIN = Path(os.getenv("DATA_DIR_TRAIN"))
    DATA_DIR_TEST = Path(os.getenv("DATA_DIR_TEST"))
    MODEL_DIR = Path(os.getenv("MODEL_DIR"))
    TRAIN_CSV = DATA_DIR_TRAIN / "imbalanced_dataset_smote.csv"  # Dataset intentionnellement déséquilibré avec SMOTE
    TEST_CSV = DATA_DIR_TEST / "UNSW_NB15_testing-set.csv"

    FEATURES = [
        "dur", "spkts", "dpkts", "sbytes", "dbytes", "rate",
        "fwd_mean_pkt_size", "bwd_mean_pkt_size"
    ]
    BATCH_SIZE = 256
    N_EPOCHS = 100
    LR = 5e-4

    # --------------------------------------------------------------------------- #
    # 4. Load & preprocess training data
    # --------------------------------------------------------------------------- #
    df = pd.read_csv(TRAIN_CSV)

    train_df, val_df = train_test_split(
        df,
        test_size=0.15,
        stratify=df["attack_cat"],
        random_state=SEED
    )

    # Fit label‑encoder on training labels ONLY
    le = LabelEncoder()
    y_train_int = le.fit_transform(train_df["attack_cat"])
    y_val_int = le.transform(val_df["attack_cat"])

    # Persist encoder for later inference
    joblib.dump(le, MODEL_DIR / "label_encoder_binary.joblib")

    # Standardise numerical features
    scaler = StandardScaler()
    X_train = scaler.fit_transform(train_df[FEATURES])
    X_val = scaler.transform(val_df[FEATURES])

    # Persist scaler
    joblib.dump(scaler, MODEL_DIR / "feature_scaler_binary.joblib")

    # Reshape for Conv1D: (batch, steps, channels)
    X_train = X_train.reshape(-1, len(FEATURES), 1)
    X_val = X_val.reshape(-1, len(FEATURES), 1)

    # --------------------------------------------------------------------------- #
    # 5. Build & train model
    # --------------------------------------------------------------------------- #
    model = build_cnn(len(FEATURES), 1)  # No need for n_classes parameter for binary classification
    model.summary()

    callbacks = [
        EarlyStopping(monitor="val_loss", patience=5, restore_best_weights=True),
        ReduceLROnPlateau(monitor="val_loss", factor=0.1, patience=3, min_lr=1e-7)
    ]

    # Calculer les poids des classes pour compenser le déséquilibre
    # Cela complète l'approche SMOTE modifiée (avec sampling_strategy < 1)
    # en donnant plus d'importance à la classe minoritaire pendant l'entraînement
    class_counts = np.bincount(y_train_int)
    total_samples = len(y_train_int)
    class_weights = {
        0: total_samples / (len(np.unique(y_train_int)) * class_counts[0]),
        1: total_samples / (len(np.unique(y_train_int)) * class_counts[1])
    }
    print(f"Distribution des classes dans l'ensemble d'entraînement: {class_counts}")
    print(f"Poids des classes appliqués: {class_weights}")

    history = model.fit(
        X_train, y_train_int,
        validation_data=(X_val, y_val_int),
        epochs=N_EPOCHS,
        batch_size=BATCH_SIZE,
        callbacks=callbacks,
        class_weight=class_weights,  # Ajouter les poids des classes
        verbose=2
    )

    model.save(MODEL_DIR / "cnn_binary_ids.h5")

    # --------------------------------------------------------------------------- #
    # 6. Evaluation on UNSW‑NB15 testing set
    # --------------------------------------------------------------------------- #
    df_test = pd.read_csv(TEST_CSV)
    df_test = add_mean_pkt_size(df_test)

    # Convert test set to binary classification (Normal vs Attack)
    # Toutes les catégories d'attaque sont regroupées en une seule classe 'Attack'
    # C'est une exigence pour la classification binaire
    df_test['attack_cat'] = np.where(df_test['attack_cat'] == 'Normal', 'Normal', 'Attack')

    # Keep same 8 numeric features + attack_cat
    df_test = df_test[FEATURES + ["attack_cat"]]

    # Transform labels with *saved* encoder – no refit!
    y_test_int = le.transform(df_test["attack_cat"])

    # Standardise with *saved* scaler – no refit!
    X_test = scaler.transform(df_test[FEATURES]).reshape(-1, len(FEATURES), 1)

    # Evaluate
    test_loss, test_acc = model.evaluate(X_test, y_test_int, verbose=0)
    print(f"Test accuracy : {test_acc:.4f}")

    # Detailed metrics
    y_pred_proba = model.predict(X_test, verbose=0)
    y_pred_int = (y_pred_proba > 0.5).astype(int).flatten()

    print("\nClassification report (test set)\n")
    print(classification_report(
        y_test_int, y_pred_int,
        target_names=le.classes_,
        digits=4
    ))

    print("Confusion matrix\n")
    print(confusion_matrix(y_test_int, y_pred_int))

    # Sauvegarder le modèle au format .h5
    model.save(MODEL_DIR / "cnn_binary_ids.h5")
    print("Modèle binaire sauvegardé: cnn_binary_ids.h5")

    # Sauvegarder les poids du modèle au format .pkl
    joblib.dump(model.get_weights(), MODEL_DIR / "cnn_binary_ids_weights.pkl")
    print("Poids du modèle binaire sauvegardés: cnn_binary_ids_weights.pkl")

    # ROC Curve
    fpr, tpr, _ = roc_curve(y_test_int, y_pred_proba)
    roc_auc = auc(fpr, tpr)

    plt.figure(figsize=(8, 6))
    plt.plot(fpr, tpr, color="blue", label=f"ROC curve (AUC = {roc_auc:.4f})")
    plt.plot([0, 1], [0, 1], color="gray", linestyle="--")
    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate")
    plt.title("ROC Curve")
    plt.legend(loc="lower right")
    plt.grid()
    plt.show()

    # Courbe Precision-Recall
    precision, recall, _ = precision_recall_curve(y_test_int, y_pred_proba)

    plt.figure(figsize=(8, 6))
    plt.plot(recall, precision, color="green", label="Precision-Recall curve")
    plt.xlabel("Recall")
    plt.ylabel("Precision")
    plt.title("Precision-Recall Curve")
    plt.legend(loc="lower left")
    plt.grid()
    plt.show()

    # tester le temps d'execution (latence) du modèle
    n_iter = 1000  # nombre de prédictions à chronométrer
    start = time.time()

    for _ in range(n_iter):
        _ = model.predict(X_test[:1], verbose=0)  # 1 ligne à la fois

    end = time.time()
    avg_time = (end - start) / n_iter
    print(f"Temps moyen par prédiction : {avg_time:.6f} secondes")

    # Tuning du seuil de prédiction
    best_thresh = 0.5
    best_f1 = 0

    for threshold in np.arange(0.1, 0.9, 0.01):
        y_pred = (y_pred_proba > threshold).astype(int)
        f1 = f1_score(y_test_int, y_pred)

        if f1 > best_f1:
            best_f1 = f1
            best_thresh = threshold

    print(f"Seuil optimal = {best_thresh:.2f} avec F1-score = {best_f1:.4f}")

if __name__ == "__main__":
    # Load environment variables
    load_dotenv()
    main()