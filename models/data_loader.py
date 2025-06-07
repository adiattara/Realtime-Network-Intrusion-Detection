# data_loader.py

import os
import pandas as pd


def lister_csv(dossier):
    return [os.path.join(dossier, f) for f in os.listdir(dossier) if f.endswith('.csv')]


def charger_donnees_csv(dossiers):
    fichiers_csv = []
    for dossier in dossiers:
        fichiers_csv += lister_csv(dossier)

    liste_df = []
    for chemin_fichier in fichiers_csv:
        df = pd.read_csv(chemin_fichier)
        liste_df.append(df)

    df_concatene = pd.concat(liste_df, ignore_index=True)
    print(f"{len(df_concatene)} lignes importées depuis {len(fichiers_csv)} fichiers.")
    return df_concatene
