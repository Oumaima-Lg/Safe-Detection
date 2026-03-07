"""
Module de surveillance SAVEDETECT - Détection d'intrusion par caméra.
Peut être utilisé en script standalone (une caméra) ou par l'app web (plusieurs caméras).
"""
import cv2
import numpy as np
import datetime
import csv
import time
import os
import threading

try:
    import winsound
except ImportError:
    winsound = None

# ==============================
# CONFIGURATION
# ==============================
LOG_FILE = "savedetect_security_logs.csv"
SCREENSHOT_DIR = "captures_intrusions"
SURFACE_MIN_HUMAIN = 2500
LOG_INTERVAL = 2

BLEU_ZONE = (255, 120, 0)
JAUNE_INTRUS = (0, 255, 255)
ROUGE_ALERTE = (0, 0, 255)
VERT_OK = (0, 255, 0)
BLANC = (255, 255, 255)

if not os.path.exists(SCREENSHOT_DIR):
    os.makedirs(SCREENSHOT_DIR)

def _ensure_log_file():
    if not os.path.isfile(LOG_FILE):
        with open(LOG_FILE, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Date et Heure", "Evenement", "Duree Presence (s)", "Camera"])

def alerte_sonore():
    if winsound:
        try:
            winsound.Beep(1000, 400)
        except Exception:
            pass
    else:
        print("\a")


def run_detection(camera_url_or_index, camera_id="cam0", headless=False, stop_event=None):
    """
    Boucle de détection d'intrusion pour une caméra.
    - camera_url_or_index: URL (str) ou index (int) pour cv2.VideoCapture
    - camera_id: identifiant pour les logs et captures
    - headless: si True, pas de cv2.imshow (pour l'app web)
    - stop_event: threading.Event pour arrêter proprement la boucle
    """
    _ensure_log_file()
    if stop_event is None:
        stop_event = threading.Event()

    # Iriun Webcam / caméra locale : accepter l'index numérique (0, 1, 2...)
    source = camera_url_or_index
    if isinstance(source, str) and source.strip().isdigit():
        source = int(source.strip())
    cap = cv2.VideoCapture(source)
    if not cap.isOpened():
        return {"error": f"Impossible d'ouvrir la source: {camera_url_or_index}"}

    fgbg = cv2.createBackgroundSubtractorMOG2(history=800, varThreshold=45, detectShadows=True)
    compteur_total = 0
    est_en_alerte = False
    temps_debut_intrusion = 0
    trajectoire = []

    while not stop_event.is_set():
        ret, frame = cap.read()
        if not ret:
            if not headless:
                print(f"[{camera_id}] Impossible de lire la caméra.")
            break

        frame_orig = frame
        frame_visuelle = frame_orig.copy()
        overlay = frame_orig.copy()
        frame_h, frame_w = frame_visuelle.shape[:2]

        mask = fgbg.apply(frame_orig)
        _, mask = cv2.threshold(mask, 200, 255, cv2.THRESH_BINARY)
        kernel = np.ones((5, 5), np.uint8)
        mask = cv2.morphologyEx(mask, cv2.MORPH_OPEN, kernel)

        contours, _ = cv2.findContours(mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        quelquun_dans_zone = False

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
                cx, cy = x + w // 2, y + h // 2
                if check_roi(cx, cy):
                    quelquun_dans_zone = True
                    trajectoire.append((cx, cy))
                    cv2.rectangle(frame_visuelle, (x, y), (x + w, y + h), JAUNE_INTRUS, 2)
                    cv2.putText(frame_visuelle, "INTRUS", (x, y - 10),
                                cv2.FONT_HERSHEY_SIMPLEX, 0.6, JAUNE_INTRUS, 2)

        if quelquun_dans_zone:
            if not est_en_alerte:
                est_en_alerte = True
                compteur_total += 1
                temps_debut_intrusion = time.time()
                alerte_sonore()
                subdir = os.path.join(SCREENSHOT_DIR, camera_id.replace("/", "_"))
                os.makedirs(subdir, exist_ok=True)
                nom_photo = os.path.join(subdir, f"intrusion_{datetime.datetime.now().strftime('%H%M%S')}.jpg")
                cv2.imwrite(nom_photo, frame_visuelle)

            cv2.putText(frame_visuelle, "ALERTE : INTRUSION DETECTEE",
                        (frame_w // 4, 50), cv2.FONT_HERSHEY_DUPLEX, 0.8, ROUGE_ALERTE, 2)
        else:
            if est_en_alerte:
                duree = round(time.time() - temps_debut_intrusion, 2)
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                with open(LOG_FILE, "a", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow([timestamp, "Violation Zone Critique", duree, camera_id])
                est_en_alerte = False
                trajectoire = []

        for i in range(1, len(trajectoire)):
            cv2.line(frame_visuelle, trajectoire[i - 1], trajectoire[i], JAUNE_INTRUS, 2)

        cv2.fillPoly(overlay, [roi_points], BLEU_ZONE)
        cv2.addWeighted(overlay, 0.3, frame_visuelle, 0.7, 0, frame_visuelle)
        cv2.polylines(frame_visuelle, [roi_points], True, BLEU_ZONE, 2)
        cv2.putText(frame_visuelle, "ZONE CRITIQUE",
                    (10, frame_h - roi_bottom_margin - roi_height - 10),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.7, BLEU_ZONE, 2)

        dashboard_height = 40
        cv2.rectangle(frame_visuelle, (0, frame_h - dashboard_height), (frame_w, frame_h), (30, 30, 30), -1)
        color_status = ROUGE_ALERTE if est_en_alerte else VERT_OK
        text_status = "DANGER : INTRUSION" if est_en_alerte else "SYSTEME OK - AUCUN RISQUE"
        cv2.putText(frame_visuelle, text_status, (10, frame_h - 10),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.6, color_status, 2)
        cv2.putText(frame_visuelle, f"ALERTS: {compteur_total}", (frame_w - 200, frame_h - 10),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.6, BLANC, 1)

        if headless:
            # Exposer la frame pour le flux web (zone + alertes visibles dans le navigateur)
            ret_j, jpeg = cv2.imencode(".jpg", frame_visuelle)
            if ret_j:
                with _last_frames_lock:
                    _last_frames[camera_id] = jpeg.tobytes()
        else:
            cv2.imshow(f"SAVEDETECT - {camera_id}", frame_visuelle)

        if not headless and (cv2.waitKey(1) & 0xFF == ord('q')):
            break

    cap.release()
    with _last_frames_lock:
        _last_frames.pop(camera_id, None)
    if not headless:
        cv2.destroyAllWindows()
    return {"camera_id": camera_id, "alerts": compteur_total}


def get_last_frame(camera_id):
    """Retourne la dernière frame JPEG de la caméra (pour flux MJPEG dans l'app web)."""
    with _last_frames_lock:
        return _last_frames.get(camera_id)


# Dernière frame par caméra (pour flux web : zone + alertes visibles)
_last_frames = {}  # camera_id -> bytes (JPEG)
_last_frames_lock = threading.Lock()

# Threads actifs (pour l'app web)
_active_threads = {}  # camera_id -> {"thread": Thread, "stop_event": Event}


def start_surveillance(camera_urls):
    """
    Démarre la surveillance pour une liste d'URLs de caméras.
    camera_urls: liste de dicts [{"id": "cam1", "url": "http://..."}, ...]
    """
    global _active_threads
    for cam in camera_urls:
        cid = cam.get("id", f"cam_{len(_active_threads)}")
        url = cam.get("url", cam) if isinstance(cam, dict) else cam
        if cid in _active_threads:
            continue
        stop_ev = threading.Event()
        t = threading.Thread(
            target=run_detection,
            args=(url, cid, True, stop_ev),
            daemon=True
        )
        _active_threads[cid] = {"thread": t, "stop_event": stop_ev}
        t.start()
    return list(_active_threads.keys())


def stop_surveillance(camera_id=None):
    """Arrête la surveillance pour une caméra ou toutes."""
    global _active_threads
    if camera_id:
        if camera_id in _active_threads:
            _active_threads[camera_id]["stop_event"].set()
            del _active_threads[camera_id]
            with _last_frames_lock:
                _last_frames.pop(camera_id, None)
    else:
        for cid, data in list(_active_threads.items()):
            data["stop_event"].set()
        _active_threads.clear()
        with _last_frames_lock:
            _last_frames.clear()


def get_active_cameras():
    """Retourne la liste des caméras en cours de surveillance."""
    return list(_active_threads.keys())


if __name__ == "__main__":
    # Mode standalone : une caméra (comme l'ancien script)
    import sys
    URL_CAM = os.environ.get("URL_CAM", "http://10.247.21.164:8080/video")
    if len(sys.argv) > 1:
        URL_CAM = sys.argv[1]
    print("--------------------------------------------------")
    print("   SAVEDETECT : PROTECTION INDUSTRIELLE ACTIVE    ")
    print("--------------------------------------------------")
    print("Appuyez sur 'q' pour arrêter.")
    run_detection(URL_CAM, "cam0", headless=False)
