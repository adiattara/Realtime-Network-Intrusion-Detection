# Classification Binaire & MLOps (MLflow + MinIO + Docker)
### Présentation
Cette partie du projet vise à :
- Préparer et nettoyer des données pour la détection binaire d’attaques réseau.
- Entraîner et évaluer un modèle CNN (Deep Learning) pour la classification « Attack / Normal ».
- Versionner, tracker et stocker les modèles et métriques grâce à MLflow et MinIO (S3).
- Faciliter le déploiement et la portabilité via Docker Compose.

### 📦 Structure de cette partie
**docker-compose.yml** : Orchestration des services MLflow + MinIO\
**model_binaire_MLFLOW.py** : Entraînement & tracking du modèle CNN avec MLflow\
**explore_binaire.py** : Préparation, nettoyage, équilibrage des datasets\
**models_binaire** : Modèles et objets locaux (.h5, .pkl, .joblib)\
**mlflow.db** : (local) Tracking store MLflow (SQLite)\
**.env** : Variables d'environnement du projet

### 🛠️Lancement
1. **Docker Compose** : Lancez les services MLflow et MinIO dans le dossier racine de cette partie :
   ```bash
   docker-compose up -d
   ```
- MLflow sera accessible sur `http://localhost:5050` et MinIO sur `http://localhost:9001`.\
_**N.B**_ : Si c’est la première exécution, créez un bucket mlflow-artifacts dans MinIO via l’UI !
2. **Configurer les variables d’environnement dans le fichier `.env`** :
   ```bash
   MLFLOW_TRACKING_URI=http://localhost:5050
   MINIO_ENDPOINT=http://localhost:9000
   MINIO_ACCESS_KEY=minioadmin
   MINIO_SECRET_KEY=minioadmin
   
   DATA_DIR_TRAIN=...
   DATA_DIR_TEST=...
   MODEL_DIR=./models_binaire
   ```
3. **Préparer les données** :
  ```bash
    python explore_binaire.py
   ```
- Nettoie, concatène, encode, équilibre et sauvegarde les datasets (SMOTE).
- Génère le fichier prêt pour l’entraînement.
4. **Entraîner le modèle** :
   ```bash
   python model_binaire_MLFLOW.py
   ```
- Entraîne un CNN (Keras) pour la classification binaire.
- Tracke automatiquement tous les runs dans MLflow.
- Stocke modèles, métriques et artefacts à la fois localement et dans MinIO/S3.

### Accès aux résultats
- MLflow UI : pour consulter, comparer et exporter les runs, hyperparamètres, métriques, courbes et artefacts (modèles).

MinIO UI : pour voir/manager les fichiers de modèles sauvegardés dans le bucket `mlflow-artifacts`.