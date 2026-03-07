"""
Module de surveillance SAFEDETECT - Détection d'intrusion par caméra.
Peut être utilisé en script standalone (une caméra) ou par l'app web (plusieurs caméras).
"""
import cv2
import numpy as np
import datetime
import csv
import time
import os
import threading
import json

try:
    import winsound
except ImportError:
    winsound = None

try:
    from ultralytics import YOLO
    _YOLO_AVAILABLE = True
except Exception:
    YOLO = None
    _YOLO_AVAILABLE = False

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
ROI_CONFIG_FILE = "zone_critique.json"
# Fichier des zones par caméra (app web)
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ZONES_JSON = os.path.join(_SCRIPT_DIR, "data", "zones.json")

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


def _load_saved_roi(frame_w: int, frame_h: int):
    """
    Charge un polygone de zone critique sauvegardé depuis ROI_CONFIG_FILE
    en vérifiant la taille de l'image (script standalone).
    """
    if not os.path.isfile(ROI_CONFIG_FILE):
        return None
    try:
        with open(ROI_CONFIG_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        pts = data.get("points")
        size = data.get("frame_size")
        if not pts or not size:
            return None
        if size[0] != frame_w or size[1] != frame_h:
            return None
        return np.array(pts, dtype=np.int32)
    except Exception:
        return None


def load_roi_for_camera(camera_id: str, frame_w: int, frame_h: int):
    """
    Charge le polygone de zone critique pour une caméra (app web).
    Lit depuis data/zones.json, clé = camera_id. Retourne None si absent ou taille différente.
    """
    if not os.path.isfile(ZONES_JSON):
        return None
    try:
        with open(ZONES_JSON, "r", encoding="utf-8") as f:
            data = json.load(f)
        cam_data = data.get(camera_id)
        if not cam_data:
            return None
        pts = cam_data.get("points")
        size = cam_data.get("frame_size")
        if not pts or not size:
            return None
        if size[0] != frame_w or size[1] != frame_h:
            return None
        return np.array(pts, dtype=np.int32)
    except Exception:
        return None


def _save_roi(points, frame_w: int, frame_h: int):
    """Sauvegarde le polygone de zone critique dans ROI_CONFIG_FILE."""
    data = {
        "points": [(int(x), int(y)) for x, y in points],
        "frame_size": [int(frame_w), int(frame_h)],
    }
    with open(ROI_CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def _define_roi_with_mouse(frame):
    """
    Laisse l'utilisateur dessiner un polygone de zone critique avec la souris.
    - Clic gauche : ajoute un point
    - r : reset les points
    - s ou Entrée : valider (au moins 3 points)
    - q ou Échap : annuler
    """
    window_name = "SAFEDETECT - Dessiner la zone critique"
    points = []

    def on_mouse(event, x, y, flags, param):
        nonlocal points
        if event == cv2.EVENT_LBUTTONDOWN:
            points.append((x, y))

    cv2.namedWindow(window_name)
    cv2.setMouseCallback(window_name, on_mouse)

    while True:
        vis = frame.copy()
        if points:
            # Dessiner les points et les segments
            for p in points:
                cv2.circle(vis, p, 4, (0, 255, 255), -1)
            cv2.polylines(vis, [np.array(points, dtype=np.int32)], False, (0, 255, 255), 2)
        cv2.putText(
            vis,
            "Clic=gauche: points, s/Enter=valider, r=reset, q=annuler",
            (10, 25),
            cv2.FONT_HERSHEY_SIMPLEX,
            0.5,
            (255, 255, 255),
            1,
        )
        cv2.imshow(window_name, vis)
        key = cv2.waitKey(20) & 0xFF
        if key in (13, 10, ord("s")) and len(points) >= 3:
            break
        if key == ord("r"):
            points = []
        if key in (27, ord("q")):
            points = []
            break

    cv2.destroyWindow(window_name)
    if len(points) >= 3:
        return np.array(points, dtype=np.int32)
    return None


_yolo_model = None


def _get_yolo_model():
    """
    Charge le modèle YOLO (version légère) une seule fois.
    Utilise par défaut 'yolov8n.pt' (petit modèle) ou la valeur de SAFEDETECT_YOLO_MODEL.
    """
    global _yolo_model
    if not _YOLO_AVAILABLE:
        return None
    if _yolo_model is None:
        model_name = os.environ.get("SAFEDETECT_YOLO_MODEL", "yolov8n.pt")
        try:
            _yolo_model = YOLO(model_name)
        except Exception as e:
            # Échec de chargement (poids corrompus, etc.)
            print(f"[SAFEDETECT] Erreur chargement YOLO ({model_name}) : {e}")
            _yolo_model = None
            return None
    return _yolo_model


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

    # Modèle YOLO pour détecter uniquement les personnes
    model = _get_yolo_model()
    if model is None:
        return {"error": "Modèle YOLO indisponible. Installez le paquet 'ultralytics' et les poids (yolov8n.pt)."}

    compteur_total = 0
    est_en_alerte = False
    temps_debut_intrusion = 0
    roi_points = None

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

        # ==========================
        # Zone critique : polygone utilisateur si disponible
        # ==========================
        if roi_points is None:
            # 1) App web : zone par caméra (data/zones.json)
            roi_loaded = load_roi_for_camera(camera_id, frame_w, frame_h)
            if roi_loaded is not None:
                roi_points = roi_loaded
            # 2) Script standalone : zone globale (zone_critique.json)
            if roi_points is None:
                roi_loaded_standalone = _load_saved_roi(frame_w, frame_h)
                if roi_loaded_standalone is not None:
                    roi_points = roi_loaded_standalone
            if roi_points is None and not headless:
                # 3) En mode non headless, laisser l'utilisateur dessiner une zone (souris)
                drawn = _define_roi_with_mouse(frame_visuelle)
                if drawn is not None:
                    roi_points = drawn
                    _save_roi(roi_points, frame_w, frame_h)
                else:
                    # Si l'utilisateur annule, on retombe sur l'ancienne zone rectangulaire en bas
                    roi_bottom_margin = 50
                    roi_height = 300
                    roi_points = np.array(
                        [
                            [0, frame_h - roi_bottom_margin - roi_height],
                            [frame_w, frame_h - roi_bottom_margin - roi_height],
                            [frame_w, frame_h - roi_bottom_margin],
                            [0, frame_h - roi_bottom_margin],
                        ]
                    )
            else:
                # 4) Sinon : zone rectangulaire par défaut (bas de l'image)
                roi_bottom_margin = 50
                roi_height = 300
                roi_points = np.array(
                    [
                        [0, frame_h - roi_bottom_margin - roi_height],
                        [frame_w, frame_h - roi_bottom_margin - roi_height],
                        [frame_w, frame_h - roi_bottom_margin],
                        [0, frame_h - roi_bottom_margin],
                    ]
                )

        # ==========================
        # Détection YOLO des personnes
        # ==========================
        # Pour limiter la charge CPU, vous pouvez réduire la taille de l'image :
        # frame_input = cv2.resize(frame_orig, (640, 360))
        # et adapter les coordonnées. Ici on garde la taille native pour plus de précision.
        results = model(frame_orig, verbose=False)[0]
        quelquun_dans_zone = False

        def check_roi(x, y):
            # pointPolygonTest attend un tuple de floats
            return cv2.pointPolygonTest(roi_points, (float(x), float(y)), False) >= 0

        # Classe COCO 0 = "person"
        for box in getattr(results, "boxes", []):
            cls_id = int(box.cls[0]) if hasattr(box, "cls") else -1
            if cls_id != 0:
                continue
            xyxy = box.xyxy[0].cpu().numpy().astype(int)
            x1, y1, x2, y2 = xyxy
            cx = (x1 + x2) // 2
            cy = (y1 + y2) // 2
            conf = float(box.conf[0]) if hasattr(box, "conf") else None

            if check_roi(cx, cy):
                quelquun_dans_zone = True
                cv2.rectangle(frame_visuelle, (x1, y1), (x2, y2), JAUNE_INTRUS, 2)
                label = "PERSONNE"
                if conf is not None:
                    label += f" {conf*100:.0f}%"
                cv2.putText(
                    frame_visuelle,
                    label,
                    (x1, max(0, y1 - 10)),
                    cv2.FONT_HERSHEY_SIMPLEX,
                    0.6,
                    JAUNE_INTRUS,
                    2,
                )

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

        cv2.fillPoly(overlay, [roi_points], BLEU_ZONE)
        cv2.addWeighted(overlay, 0.3, frame_visuelle, 0.7, 0, frame_visuelle)
        cv2.polylines(frame_visuelle, [roi_points], True, BLEU_ZONE, 2)
        roi_min_y = int(np.min(roi_points[:, 1]))
        label_y = max(20, roi_min_y - 10)
        cv2.putText(
            frame_visuelle,
            "ZONE CRITIQUE",
            (10, label_y),
            cv2.FONT_HERSHEY_SIMPLEX,
            0.7,
            BLEU_ZONE,
            2,
        )

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
            cv2.imshow(f"SAFEDETECT - {camera_id}", frame_visuelle)

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
    # URL_CAM = os.environ.get("URL_CAM", "http://10.247.21.164:8080/video")
    URL_CAM = os.environ.get("URL_CAM", "1")  # Iriun sur index 1
    if len(sys.argv) > 1:
        URL_CAM = sys.argv[1]
    print("--------------------------------------------------")
    print("   SAFEDETECT : PROTECTION INDUSTRIELLE ACTIVE    ")
    print("--------------------------------------------------")
    print("Appuyez sur 'q' pour arrêter.")
    run_detection(URL_CAM, "cam0", headless=False)
