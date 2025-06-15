
"""
This script handles data preprocessing and preparation for binary classification
"""

import numpy as np
import pandas as pd
import os
from imblearn.over_sampling import SMOTE
from sklearn.preprocessing import LabelEncoder
import joblib
from dotenv import load_dotenv
from pathlib import Path

# Load environment variables
load_dotenv()

# Chemins des répertoires
normal_repo = os.getenv('NORMAL_DIR')
anomalous_repo = os.getenv('ANOMALOUS_DIR')
data_dir_train = os.getenv('DATA_DIR_TRAIN')
data_dir_test = os.getenv('DATA_DIR_TEST')
model_dir = os.getenv('MODEL_DIR')

def verifier_fichiers(repo):
    rapport = []
    for fichier in os.listdir(repo):
        if fichier.endswith('.csv'):
            chemin_fichier = os.path.join(repo, fichier)
            try:
                # Charger le fichier
                data = pd.read_csv(chemin_fichier)

                # Vérifications
                valeurs_manquantes = data.isnull().sum().sum()
                types_incorrects = any(data.dtypes == object)  # Vérifie si des colonnes numériques ont des types incorrects
                colonnes = data.columns.tolist()

                rapport.append({
                    'fichier': fichier,
                    'valeurs_manquantes': valeurs_manquantes,
                    'types_incorrects': types_incorrects,
                    'colonnes': colonnes
                })
            except Exception as e:
                rapport.append({'fichier': fichier, 'erreur': str(e)})
    return rapport

def charger_fichiers(repo):
    dataframes = []
    for fichier in os.listdir(repo):
        if fichier.endswith('.csv'):
            chemin_fichier = os.path.join(repo, fichier)
            try:
                # Charger le fichier
                data = pd.read_csv(chemin_fichier)
                dataframes.append(data)
            except Exception as e:
                print(f"Erreur lors du chargement de {fichier}: {e}")
    return pd.concat(dataframes, ignore_index=True)

def verifier(data):
    # Vérification des valeurs manquantes
    valeurs_manquantes = data.isnull().sum()
    print("Valeurs manquantes par colonne :")
    print(valeurs_manquantes)

    # Vérification des types incorrects
    print("\nTypes des colonnes :")
    print(data.dtypes)

    # Identification des colonnes numériques
    colonnes_numeriques = data.select_dtypes(include=['float64', 'int64']).columns
    print("\nColonnes numériques :")
    print(colonnes_numeriques)

def main():
    # Vérification des deux répertoires
    rapport_normal = verifier_fichiers(normal_repo)
    rapport_anormal = verifier_fichiers(anomalous_repo)

    # Afficher les rapports
    print("Rapport pour le traffic normal:")
    for r in rapport_normal:
        print(r)

    print("\nRapport pour le traffic anormal:")
    for r in rapport_anormal:
        print(r)

    # Charger et concaténer les données
    normal_data = charger_fichiers(normal_repo)
    anomalous_data = charger_fichiers(anomalous_repo)

    print(len(normal_data))
    print(len(anomalous_data))

    print("Vérification des données normales :")
    verifier(normal_data)
    print("\nVérification des données anormales :")
    verifier(anomalous_data)

    normal_data.to_csv(os.path.join(normal_repo, "normal_data.csv"))
    anomalous_data.to_csv(os.path.join(anomalous_repo, "anomalous_data.csv"))

    # ✅ Étape 1 : Nettoyage + Préparation des données
    
    # --- Étape 1 : Chargement des données ---
    df_normal = pd.read_csv(os.path.join(normal_repo, "normal_data.csv"))
    df_attack = pd.read_csv(os.path.join(anomalous_repo, "anomalous_data.csv"))

    # --- Étape 2 : Conversion des colonnes numériques ---
    numeric_cols = ['total_bytes', 'pkt_count', 'psh_count', 'urg_count',
                    'fwd_bytes', 'bwd_bytes', 'fwd_pkts', 'bwd_pkts',
                    'dport', 'duration_ms', 'flow_pkts_per_s', 'fwd_bwd_ratio']

    for col in numeric_cols:
        df_normal[col] = pd.to_numeric(df_normal[col], errors='coerce')
        df_attack[col] = pd.to_numeric(df_attack[col], errors='coerce')

    # --- Étape 3 : Suppression des colonnes inutiles ---
    cols_to_drop = ['flow_key', 'start_ts', 'end_ts', 'window_start', 'window_end']
    df_normal.drop(columns=cols_to_drop, inplace=True)
    df_attack.drop(columns=cols_to_drop, inplace=True)

    # --- Étape 4 : Ajout de labels binaires (Normal vs Attack) ---
    np.random.seed(42)  # reproductibilité
    df_attack['attack_type'] = 'Attack'  # Tous les types d'attaque sont regroupés en une seule classe
    df_normal['attack_type'] = 'Normal'

    # Taille cible pour la classe "Attack"
    taille_attack = len(df_attack)
    print("Nombre d'échantillons d'attaque:", taille_attack)

    # Utiliser tous les échantillons d'attaque
    df_attack_equilibre = df_attack.copy()

    # Vérification de l'équilibre
    print(df_attack_equilibre['attack_type'].value_counts())

    # --- Étape 5 : Équilibrage Normal vs Attack + Label Encoding ---
    # Échantillonner un nombre égal d'échantillons normaux pour équilibrer avec les attaques
    taille_normale = min(len(df_normal), taille_attack)
    df_normal_equilibre = df_normal.sample(taille_normale, random_state=42)

    print("Nombre d'échantillons normaux après équilibrage:", len(df_normal_equilibre))
    print("Nombre d'échantillons d'attaque:", len(df_attack_equilibre))

    # Fusion des données équilibrées
    df_all = pd.concat([df_normal_equilibre, df_attack_equilibre], ignore_index=True)

    # Encodage binaire (0 pour Normal, 1 pour Attack)
    le = LabelEncoder()
    df_all['attack_label'] = le.fit_transform(df_all['attack_type'])

    # --- Résultat ---
    print("Classes encodées (binaire) :", list(zip(le.classes_, le.transform(le.classes_))))
    print("Shape finale du dataset binaire :", df_all.shape)
    print(df_all.head())

    df_all['fwd_mean_pkt_size'] = np.where(df_all['fwd_pkts']==0, 0,
                                        df_all['fwd_bytes']/df_all['fwd_pkts'])
    df_all['bwd_mean_pkt_size'] = np.where(df_all['bwd_pkts']==0, 0,
                                        df_all['bwd_bytes']/df_all['bwd_pkts'])

    df_all.to_csv(os.path.join(data_dir_train, "dataset_simule_multiclass.csv"), index=False)
    df_sim = pd.read_csv(os.path.join(data_dir_train, "dataset_simule_multiclass.csv"))

    UNSW_NB15_dataset = pd.read_csv(os.path.join(data_dir_test, "UNSW_NB15_training-set.csv"))
    print(len(UNSW_NB15_dataset))

    verifier(UNSW_NB15_dataset)

    # Afficher les catégories d'attaque originales
    print("Catégories d'attaque originales dans UNSW-NB15:")
    print(UNSW_NB15_dataset['attack_cat'].value_counts())

    # Convertir en classification binaire (Normal vs Attack)
    UNSW_NB15_dataset['attack_cat_original'] = UNSW_NB15_dataset['attack_cat'].copy()
    UNSW_NB15_dataset['attack_cat'] = np.where(UNSW_NB15_dataset['attack_cat'] == 'Normal', 'Normal', 'Attack')

    # Afficher la distribution binaire
    print("\nDistribution binaire (Normal vs Attack):")
    print(UNSW_NB15_dataset['attack_cat'].value_counts())

    rename_map = {
        'duration_ms'      : 'dur',
        'fwd_pkts'         : 'spkts',
        'bwd_pkts'         : 'dpkts',
        'fwd_bytes'        : 'sbytes',
        'bwd_bytes'        : 'dbytes',
        'flow_pkts_per_s'  : 'rate'
    }
    df_sim.rename(columns=rename_map, inplace=True)

    # Ajout du label multiclasse (déjà présent dans df_sim["attack_type"])
    df_sim['attack_cat'] = df_sim['attack_type']    # harmonisation de nom

    # Sélection finale des 8 features + label
    keep_cols = ['dur','spkts','dpkts','sbytes','dbytes','rate'
                ,'fwd_mean_pkt_size','bwd_mean_pkt_size','attack_cat']
    df_sim = df_sim[keep_cols]

    # ------------------------------------------------------------------
    # Chargement des données UNSW-NB15
    # ------------------------------------------------------------------
    usecols_unsw = ['dur','spkts','dpkts','sbytes','dbytes','rate'
                    ,'attack_cat']                # dport existe via ct_dst_sport_ltm mais -> uint16
    df_unsw_tr = UNSW_NB15_dataset
    # df_unsw_ts = pd.read_csv("UNSW_NB15_testing-set.csv" , usecols=usecols_unsw)
    # df_unsw    = pd.concat([df_unsw_tr, df_unsw_ts], ignore_index=True)

    # Assurer les mêmes types
    for col in ['dur','spkts','dpkts','sbytes','dbytes','rate']:
        df_unsw_tr[col] = pd.to_numeric(df_unsw_tr[col], errors='coerce')

    # Créer les features moyennes paquets pour UNSW
    df_unsw_tr['fwd_mean_pkt_size'] = np.where(df_unsw_tr['spkts']==0, 0,
                                            df_unsw_tr['sbytes']/df_unsw_tr['spkts'])
    df_unsw_tr['bwd_mean_pkt_size'] = np.where(df_unsw_tr['dpkts']==0, 0,
                                            df_unsw_tr['dbytes']/df_unsw_tr['dpkts'])
    df_unsw_tr = df_unsw_tr[keep_cols]

    print(len(df_unsw_tr))
    print(len(df_sim))

    final_data = pd.concat([df_sim, df_unsw_tr], ignore_index=True)
    print(final_data)

    # Vérification de la distribution des classes avant équilibrage final
    print("Distribution des classes avant équilibrage final :")
    print(final_data['attack_cat'].value_counts())

    # Équilibrage final des classes (Normal vs Attack)
    attack_samples = final_data[final_data['attack_cat'] == 'Attack']
    normal_samples = final_data[final_data['attack_cat'] == 'Normal']

    # Déterminer la taille cible pour l'équilibrage
    target_size = min(len(attack_samples), len(normal_samples))
    print(f"Taille cible pour chaque classe après équilibrage: {target_size}")

    # Utiliser SMOTE pour équilibrer les classes au lieu du sous-échantillonnage
    # SMOTE (Synthetic Minority Over-sampling Technique) génère des échantillons synthétiques
    # pour la classe minoritaire au lieu de sous-échantillonner la classe majoritaire,
    # ce qui permet de conserver toutes les informations disponibles.
    # Séparer les features et la cible
    X = final_data[keep_cols[:-1]]  # Toutes les colonnes sauf 'attack_cat'
    y = final_data['attack_cat']

    # Appliquer SMOTE pour générer des échantillons synthétiques pour la classe minoritaire
    # Utiliser sampling_strategy pour contrôler le ratio des classes (pas 50/50)
    # Un ratio de 0.7 signifie que la classe minoritaire sera 70% de la taille de la classe majoritaire
    # Cela permet d'éviter un équilibre parfait qui pourrait être "dangereux" (surapprentissage)
    sampling_ratio = 0.7  # 70% - ajuster selon les besoins
    smote = SMOTE(sampling_strategy=sampling_ratio, random_state=42)
    X_resampled, y_resampled = smote.fit_resample(X, y)

    # Créer le dataset final avec SMOTE (intentionnellement déséquilibré)
    final_balanced_data = pd.DataFrame(X_resampled, columns=keep_cols[:-1])
    final_balanced_data['attack_cat'] = y_resampled

    print(f"Taille du dataset après SMOTE: {len(final_balanced_data)} échantillons")
    print(f"Distribution des classes après SMOTE:")
    print(final_balanced_data['attack_cat'].value_counts())
    print("Pourcentage de chaque classe après SMOTE:")
    print(final_balanced_data['attack_cat'].value_counts(normalize=True) * 100)

    # Encodage binaire
    le = LabelEncoder()
    final_balanced_data['attack_label'] = le.fit_transform(final_balanced_data['attack_cat'])
    print("Mapping label binaire → code :", dict(zip(le.classes_, le.transform(le.classes_))))

    # Sauvegarder l'encodeur
    joblib.dump(le, os.path.join(model_dir, "label_encoder.joblib"))

    # Sauvegarder le dataset
    final_balanced_data.to_csv(os.path.join(data_dir_train, "imbalanced_dataset_smote.csv"), index=False)
    print("Dataset préparé pour classification binaire : ", final_balanced_data.shape, "lignes, prêt pour le DL.")

    # Vérification finale du dataset avec SMOTE
    print("Dataset avec SMOTE sauvegardé avec succès.")
    print("Note: Ce dataset est intentionnellement déséquilibré (ratio de classes ~70%) pour éviter le surapprentissage.")
    print("      Il sera utilisé avec class_weight dans le modèle pour une meilleure généralisation.")

if __name__ == "__main__":
    main()