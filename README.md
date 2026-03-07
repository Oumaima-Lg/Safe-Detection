# SAFEDETECT

## Guide

### 1. Module de surveillance (`surveillance.py`)
- Logique de détection d'intrusion extraite dans une fonction réutilisable.
- Une même boucle de détection peut tourner par caméra (plusieurs en parallèle).
- En mode headless (sans fenêtre OpenCV) pour l'app web.
- Les captures sont enregistrées par caméra dans `captures_intrusions/<camera_id>/`.
- Les logs CSV incluent une colonne **Camera** pour identifier la source.

### 2. Script standalone (`openCV_prg.py`)
- Il appelle `surveillance.run_detection()` avec une seule URL (ou `URL_CAM` / variable d'environnement).
- Comportement inchangé pour une utilisation en ligne de commande avec une caméra.

### 3. Application web (`app.py`)
- **Connexion admin** : identifiant et mot de passe (par défaut `admin` / `safedetect2026`, modifiables via variables d'environnement).
- **Tableau de bord** après connexion :
  - Démarrer / Arrêter la surveillance pour toutes les caméras configurées.
  - Ajouter des caméras : nom optionnel + adresse (URL IP, flux HTTP, RTSP, etc.).
  - Liste des caméras avec statut (active ou non) et Supprimer.
  - Page **Logs** : consultation des derniers événements (intrusions) avec date, durée, caméra.

### 4. Stockage
- Liste des caméras : `data/cameras.json`.
- Identifiants admin : variables d'environnement `SAVEDETECT_ADMIN_USER`, `SAVEDETECT_ADMIN_PASSWORD`, et `SECRET_KEY` pour la session.

---

## Lancer l'application web

```bash
cd "d:\Safe Detection"
pip install -r requirements.txt
python app.py
```

Puis ouvrir **http://localhost:5000** :
1. Se connecter avec `admin` / `safedetect2026` (ou les identifiants définis en variables d'environnement).
2. Ajouter autant d'adresses de caméras que nécessaire (ex. `http://10.247.21.164:8080/video`, une autre IP, un flux RTSP…).
3. Cliquer sur **Démarrer la surveillance** pour lancer la détection sur toutes les caméras en parallèle.

---

## Changer le mot de passe admin (recommandé en production)

Sous Windows (PowerShell) :

```powershell
$env:SAVEDETECT_ADMIN_USER = "votre_login"
$env:SAVEDETECT_ADMIN_PASSWORD = "votre_mot_de_passe"
$env:SECRET_KEY = "une-cle-secrete-aleatoire"
python app.py
```


Clic gauche : ajouter des points du polygone (contour de la zone).
r : effacer tous les points et recommencer.
s ou Entrée : valider la zone (au moins 3 points).
q ou Échap : annuler → le code reprend l’ancienne zone rectangulaire en bas.