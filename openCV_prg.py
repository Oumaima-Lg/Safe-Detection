# import cv2
# import numpy as np
# import datetime
# import csv
# import time
# import os

# # Tente d'importer winsound pour Windows, sinon définit une fonction vide pour Linux/Mac
# try:
#     import winsound
# except ImportError:
#     winsound = None

# # ==========================================================
# # CONFIGURATION DU SYSTÈME SAVEDETECT
# # ==========================================================
# URL_CAM = "http://10.247.21.164:8080/video"
# LOG_FILE = "savedetect_security_logs.csv"
# SCREENSHOT_DIR = "captures_intrusions"

# # Paramètres de détection
# SURFACE_MIN_HUMAIN = 2500  # Ajuster selon la distance de la caméra
# LOG_INTERVAL = 2           # Secondes entre deux enregistrements CSV identiques

# # Couleurs (format BGR pour OpenCV)
# BLEU_ZONE = (255, 120, 0)
# JAUNE_INTRUS = (0, 255, 255)
# ROUGE_ALERTE = (0, 0, 255)
# VERT_OK = (0, 255, 0)
# BLANC = (255, 255, 255)

# # Définition de la Zone Interdite (ROI) : [x, y]
# roi_points = np.array([[100, 80], [540, 80], [540, 420], [100, 420]])

# # Initialisation des dossiers et fichiers
# if not os.path.exists(SCREENSHOT_DIR):
#     os.makedirs(SCREENSHOT_DIR)

# if not os.path.isfile(LOG_FILE):
#     with open(LOG_FILE, "w", newline="") as f:
#         writer = csv.writer(f)
#         writer.writerow(["Date et Heure", "Evenement", "Duree Presence (s)"])

# # ==========================================================
# # FONCTIONS UTILES
# # ==========================================================
# def alerte_sonore():
#     if winsound:
#         winsound.Beep(1000, 400) # Fréquence 1000Hz, 400ms
#     else:
#         print("\a") # Bip système standard pour Linux/Mac

# def check_roi(x, y):
#     return cv2.pointPolygonTest(roi_points, (x, y), False) >= 0

# # ==========================================================
# # LANCEMENT DE LA SURVEILLANCE
# # ==========================================================
# cap = cv2.VideoCapture(1)
# # Algorithme de soustraction de fond (détecte les changements de pixels)
# fgbg = cv2.createBackgroundSubtractorMOG2(history=800, varThreshold=45, detectShadows=True)

# # Variables d'état
# compteur_total = 0
# est_en_alerte = False
# temps_debut_intrusion = 0
# trajectoire = []

# print("--------------------------------------------------")
# print("   SAVEDETECT : PROTECTION INDUSTRIELLE ACTIVE    ")
# print("--------------------------------------------------")
# print("Appuyez sur 'q' pour arrêter le système.")

# while True:
#     ret, frame = cap.read()
#     if not ret:
#         print("Erreur : Impossible de joindre la caméra.")
#         break

#     # 1. PRÉ-TRAITEMENT
#     # frame_orig = cv2.resize(frame, (640, 480))
#     frame_orig = cv2.resize(frame, (480, 360))
#     #frame_orig = cv2.flip(frame_orig, 0) # Remise à l'endroit
#     frame_orig = cv2.rotate(frame_orig, cv2.ROTATE_90_COUNTERCLOCKWISE)
#     frame_visuelle = frame_orig.copy()
#     overlay = frame_orig.copy()

#     # 2. ANALYSE DU MOUVEMENT
#     mask = fgbg.apply(frame_orig)
#     _, mask = cv2.threshold(mask, 200, 255, cv2.THRESH_BINARY)
    
#     # Nettoyage du bruit (petits objets)
#     kernel = np.ones((5,5), np.uint8)
#     mask = cv2.morphologyEx(mask, cv2.MORPH_OPEN, kernel)
    
#     contours, _ = cv2.findContours(mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    
#     quelquun_dans_zone = False

#     for cnt in contours:
#         if cv2.contourArea(cnt) > SURFACE_MIN_HUMAIN:
#             x, y, w, h = cv2.boundingRect(cnt)
#             cx, cy = x + w//2, y + h//2
            
#             if check_roi(cx, cy):
#                 quelquun_dans_zone = True
#                 trajectoire.append((cx, cy))
                
#                 # Rectangle jaune (Intrus)
#                 cv2.rectangle(frame_visuelle, (x, y), (x+w, y+h), JAUNE_INTRUS, 2)
#                 cv2.putText(frame_visuelle, "INTRUS", (x, y-10), 
#                             cv2.FONT_HERSHEY_SIMPLEX, 0.5, JAUNE_INTRUS, 2)

#     # 3. LOGIQUE SAVEDETECT (ALERTE & LOGS)
#     if quelquun_dans_zone:
#         if not est_en_alerte:
#             # Déclenchement de l'alerte
#             est_en_alerte = True
#             compteur_total += 1
#             temps_debut_intrusion = time.time()
#             alerte_sonore()
            
#             # Capture de preuve
#             nom_photo = f"{SCREENSHOT_DIR}/intrusion_{datetime.datetime.now().strftime('%H%M%S')}.jpg"
#             cv2.imwrite(nom_photo, frame_visuelle)

#         # Message d'alerte à l'écran
#         cv2.putText(frame_visuelle, "ALERTE : INTRUSION DETECTEE", (130, 50), 
#                     cv2.FONT_HERSHEY_DUPLEX, 0.8, ROUGE_ALERTE, 2)
#     else:
#         if est_en_alerte:
#             # Fin de l'intrusion : enregistrement de la durée
#             duree = round(time.time() - temps_debut_intrusion, 2)
#             timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
#             with open(LOG_FILE, "a", newline="") as f:
#                 writer = csv.writer(f)
#                 writer.writerow([timestamp, "Violation Zone Critique", duree])
            
#             est_en_alerte = False
#             trajectoire = [] # Reset trajectoire pour le prochain

#     # 4. INTERFACE GRAPHIQUE (UI)
#     # Dessiner la trajectoire de l'intrus
#     for i in range(1, len(trajectoire)):
#         cv2.line(frame_visuelle, trajectoire[i-1], trajectoire[i], JAUNE_INTRUS, 1)

#     # Dessiner la zone bleue transparente
#     cv2.fillPoly(overlay, [roi_points], BLEU_ZONE)
#     cv2.addWeighted(overlay, 0.3, frame_visuelle, 0.7, 0, frame_visuelle)
#     cv2.polylines(frame_visuelle, [roi_points], True, BLEU_ZONE, 2)
#     cv2.putText(frame_visuelle, "ZONE SECURISEE", (roi_points[0][0], roi_points[0][1]-10), 
#                 cv2.FONT_HERSHEY_SIMPLEX, 0.5, BLEU_ZONE, 1)

#     # Bandeau de contrôle (Dashboard bas)
#     cv2.rectangle(frame_visuelle, (0, 440), (640, 480), (30, 30, 30), -1)
#     color_status = ROUGE_ALERTE if est_en_alerte else VERT_OK
#     text_status = "DANGER : INTRUSION" if est_en_alerte else "SYSTEME OK - AUCUN RISQUE"
    
#     cv2.putText(frame_visuelle, text_status, (15, 468), 
#                 cv2.FONT_HERSHEY_SIMPLEX, 0.6, color_status, 2)
#     cv2.putText(frame_visuelle, f"ALERTS: {compteur_total}", (480, 468), 
#                 cv2.FONT_HERSHEY_SIMPLEX, 0.6, BLANC, 1)

#     # Affichage
#     cv2.imshow("SAVEDETECT PRO - Gestion Securite Logistique", frame_visuelle)

#     if cv2.waitKey(1) & 0xFF == ord('q'):
#         break

# cap.release()
# cv2.destroyAllWindows()
# print(f"Session terminée. {compteur_total} intrusions enregistrées dans {LOG_FILE}.")




import cv2
import numpy as np
import datetime
import csv
import time
import os

# ==============================
# CONFIGURATION
# ==============================
try:
    import winsound
except ImportError:
    winsound = None

URL_CAM = "http://10.247.21.164:8080/video"
LOG_FILE = "savedetect_security_logs.csv"
SCREENSHOT_DIR = "captures_intrusions"

SURFACE_MIN_HUMAIN = 2500  # Ajuster selon la distance
LOG_INTERVAL = 2           # secondes entre logs identiques

# Couleurs BGR
BLEU_ZONE = (255, 120, 0)
JAUNE_INTRUS = (0, 255, 255)
ROUGE_ALERTE = (0, 0, 255)
VERT_OK = (0, 255, 0)
BLANC = (255, 255, 255)

# Initialisation fichiers/dossiers
if not os.path.exists(SCREENSHOT_DIR):
    os.makedirs(SCREENSHOT_DIR)

if not os.path.isfile(LOG_FILE):
    with open(LOG_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Date et Heure", "Evenement", "Duree Presence (s)"])

# ==============================
# FONCTIONS UTILES
# ==============================
def alerte_sonore():
    if winsound:
        winsound.Beep(1000, 400)
    else:
        print("\a")

# ==============================
# LANCEMENT DE LA SURVEILLANCE
# ==============================
cap = cv2.VideoCapture(1)
fgbg = cv2.createBackgroundSubtractorMOG2(history=800, varThreshold=45, detectShadows=True)

compteur_total = 0
est_en_alerte = False
temps_debut_intrusion = 0
trajectoire = []

print("--------------------------------------------------")
print("   SAVEDETECT : PROTECTION INDUSTRIELLE ACTIVE    ")
print("--------------------------------------------------")
print("Appuyez sur 'q' pour arrêter le système.")

while True:
    ret, frame = cap.read()
    if not ret:
        print("Erreur : Impossible de joindre la caméra.")
        break

    # ======= PRE-TRAITEMENT =======
    # Resize dynamically bigger
    #frame_orig = cv2.resize(frame, (720, 1080))  
    frame_orig = frame
    #frame_orig = cv2.rotate(frame_orig, cv2.ROTATE_90_COUNTERCLOCKWISE)
    frame_visuelle = frame_orig.copy()
    overlay = frame_orig.copy()
    
    frame_h, frame_w = frame_visuelle.shape[:2]

    # ======= ANALYSE MOUVEMENT =======
    mask = fgbg.apply(frame_orig)
    _, mask = cv2.threshold(mask, 200, 255, cv2.THRESH_BINARY)
    kernel = np.ones((5,5), np.uint8)
    mask = cv2.morphologyEx(mask, cv2.MORPH_OPEN, kernel)

    contours, _ = cv2.findContours(mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    quelquun_dans_zone = False

    # ======= ROI DYNAMIQUE (ZONE BLEUE) =======
    roi_bottom_margin = 50
    roi_height = 300
    roi_points = np.array([
        [0, frame_h - roi_bottom_margin - roi_height],
        [frame_w, frame_h - roi_bottom_margin - roi_height],
        [frame_w, frame_h - roi_bottom_margin],
        [0, frame_h - roi_bottom_margin]
    ])

    def check_roi(x, y):
        return cv2.pointPolygonTest(roi_points, (x, y), False) >= 0

    for cnt in contours:
        if cv2.contourArea(cnt) > SURFACE_MIN_HUMAIN:
            x, y, w, h = cv2.boundingRect(cnt)
            cx, cy = x + w//2, y + h//2

            if check_roi(cx, cy):
                quelquun_dans_zone = True
                trajectoire.append((cx, cy))
                cv2.rectangle(frame_visuelle, (x, y), (x+w, y+h), JAUNE_INTRUS, 2)
                cv2.putText(frame_visuelle, "INTRUS", (x, y-10), 
                            cv2.FONT_HERSHEY_SIMPLEX, 0.6, JAUNE_INTRUS, 2)

    # ======= LOGIQUE ALERT =======
    if quelquun_dans_zone:
        if not est_en_alerte:
            est_en_alerte = True
            compteur_total += 1
            temps_debut_intrusion = time.time()
            alerte_sonore()

            nom_photo = f"{SCREENSHOT_DIR}/intrusion_{datetime.datetime.now().strftime('%H%M%S')}.jpg"
            cv2.imwrite(nom_photo, frame_visuelle)

        cv2.putText(frame_visuelle, "ALERTE : INTRUSION DETECTEE", 
                    (frame_w//4, 50), cv2.FONT_HERSHEY_DUPLEX, 0.8, ROUGE_ALERTE, 2)
    else:
        if est_en_alerte:
            duree = round(time.time() - temps_debut_intrusion, 2)
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with open(LOG_FILE, "a", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([timestamp, "Violation Zone Critique", duree])
            est_en_alerte = False
            trajectoire = []

    # ======= TRAJECTOIRE =======
    for i in range(1, len(trajectoire)):
        cv2.line(frame_visuelle, trajectoire[i-1], trajectoire[i], JAUNE_INTRUS, 2)

    # ======= UI DYNAMIQUE =======
    cv2.fillPoly(overlay, [roi_points], BLEU_ZONE)
    cv2.addWeighted(overlay, 0.3, frame_visuelle, 0.7, 0, frame_visuelle)
    cv2.polylines(frame_visuelle, [roi_points], True, BLEU_ZONE, 2)
    cv2.putText(frame_visuelle, "ZONE SECURISEE", 
                (10, frame_h - roi_bottom_margin - roi_height - 10), 
                cv2.FONT_HERSHEY_SIMPLEX, 0.7, BLEU_ZONE, 2)

    dashboard_height = 40
    cv2.rectangle(frame_visuelle, (0, frame_h - dashboard_height), (frame_w, frame_h), (30,30,30), -1)
    color_status = ROUGE_ALERTE if est_en_alerte else VERT_OK
    text_status = "DANGER : INTRUSION" if est_en_alerte else "SYSTEME OK - AUCUN RISQUE"
    cv2.putText(frame_visuelle, text_status, (10, frame_h - 10), 
                cv2.FONT_HERSHEY_SIMPLEX, 0.6, color_status, 2)
    cv2.putText(frame_visuelle, f"ALERTS: {compteur_total}", (frame_w - 200, frame_h - 10), 
                cv2.FONT_HERSHEY_SIMPLEX, 0.6, BLANC, 1)

    cv2.imshow("SAVEDETECT PRO - Gestion Securite Logistique", frame_visuelle)

    if cv2.waitKey(1) & 0xFF == ord('q'):
        break

cap.release()
cv2.destroyAllWindows()
print(f"Session terminée. {compteur_total} intrusions enregistrées dans {LOG_FILE}.")