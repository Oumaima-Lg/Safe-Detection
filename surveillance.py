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
LOG_INTERVAL = 2

BLEU_ZONE = (255, 120, 0)
JAUNE_INTRUS = (0, 255, 255)
ROUGE_ALERTE = (0, 0, 255)
VERT_OK = (0, 255, 0)
BLANC = (255, 255, 255)
GRIS_INFO = (180, 180, 180)

ROI_CONFIG_FILE = "zone_critique.json"
# Fichier des zones par caméra (app web)
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ZONES_JSON = os.path.join(_SCRIPT_DIR, "data", "zones.json")
CAMERAS_JSON = os.path.join(_SCRIPT_DIR, "data", "cameras.json")

# Classes du modèle best.pt
# {0: 'ear_protection', 1: 'glasses', 2: 'helmet', 3: 'person', 4: 'vest'}
CLASS_PERSON = 3
CLASS_HELMET = 2
CLASS_VEST = 4

# Modes de détection
MODE_HUMAN = "human" # Alerte si humain dans zone
MODE_PPE = "ppe"     # Alerte si humain dans zone SANS gilet OU SANS casque

if not os.path.exists(SCREENSHOT_DIR):
    os.makedirs(SCREENSHOT_DIR)

def _get_camera_config(camera_id):
    """Charge la config d'une caméra pour connaître son mode de détection."""
    if not os.path.exists(CAMERAS_JSON):
        return {}
    try:
        with open(CAMERAS_JSON, "r", encoding="utf-8") as f:
            cameras = json.load(f)
        for c in cameras:
            if c.get("id") == camera_id:
                return c
    except Exception:
        pass
    return {}

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
            for p in points:
                cv2.circle(vis, p, 4, (0, 255, 255), -1)
            cv2.polylines(vis, [np.array(points, dtype=np.int32)], False, (0, 255, 255), 2)
        cv2.putText(vis, "Clic=gauche: points, s/Enter=valider, r=reset, q=annuler", (10, 25),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.5, (255, 255, 255), 1)
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
    """Charge le modèle best.pt par défaut."""
    global _yolo_model
    if not _YOLO_AVAILABLE:
        return None
    if _yolo_model is None:
        model_name = os.environ.get("SAFEDETECT_YOLO_MODEL", "best.pt")
        try:
            _yolo_model = YOLO(model_name)
        except Exception as e:
            print(f"[SAFEDETECT] Erreur chargement YOLO ({model_name}) : {e}")
            _yolo_model = None
    return _yolo_model


def box_iou(box1, box2):
    """Calcule l'intersection sur union (IoU) simplifiée ou juste le taux d'inclusion."""
    # box = [x1, y1, x2, y2]
    inter_x1 = max(box1[0], box2[0])
    inter_y1 = max(box1[1], box2[1])
    inter_x2 = min(box1[2], box2[2])
    inter_y2 = min(box1[3], box2[3])
    
    inter_area = max(0, inter_x2 - inter_x1) * max(0, inter_y2 - inter_y1)
    if inter_area <= 0: return 0
    
    # Pour le gilet/casque, on regarde surtout si l'inter est grande par rapport à l'objet PPE lui-même
    box2_area = (box2[2] - box2[0]) * (box2[3] - box2[1])
    return inter_area / box2_area if box2_area > 0 else 0


def run_detection(camera_url_or_index, camera_id="cam0", headless=False, stop_event=None):
    _ensure_log_file()
    if stop_event is None:
        stop_event = threading.Event()

    source = camera_url_or_index
    if isinstance(source, str) and source.strip().isdigit():
        source = int(source.strip())
    cap = cv2.VideoCapture(source)
    if not cap.isOpened():
        return {"error": f"Impossible d'ouvrir la source: {camera_url_or_index}"}

    model = _get_yolo_model()
    if model is None:
        return {"error": "Modèle YOLO (best.pt) indisponible."}

    compteur_total = 0
    est_en_alerte = False
    temps_debut_intrusion = 0
    roi_points = None
    last_roi_check = 0
    
    # Récupérer le mode de détection
    cam_config = _get_camera_config(camera_id)
    detection_mode = cam_config.get("detection_mode", MODE_HUMAN)

    while not stop_event.is_set():
        ret, frame = cap.read()
        if not ret: break

        frame_visuelle = frame.copy()
        overlay = frame.copy()
        frame_h, frame_w = frame.shape[:2]

        # Gestion ROI
        if time.time() - last_roi_check > 2.0:
            last_roi_check = time.time()
            roi_loaded = load_roi_for_camera(camera_id, frame_w, frame_h)
            if roi_loaded is not None:
                roi_points = roi_loaded
            if roi_points is None and not headless:
                roi_loaded_standalone = _load_saved_roi(frame_w, frame_h)
                if roi_loaded_standalone is not None:
                    roi_points = roi_loaded_standalone

        if roi_points is None:
            if not headless:
                drawn = _define_roi_with_mouse(frame_visuelle)
                if drawn is not None:
                    roi_points = drawn
                    _save_roi(roi_points, frame_w, frame_h)
            if roi_points is None:
                roi_points = np.array([[0, frame_h-350], [frame_w, frame_h-350], [frame_w, frame_h-50], [0, frame_h-50]])

        # Inférence YOLO
        results = model(frame, verbose=False, conf=0.5)[0]
        
        persons = []
        helmets = []
        vests = []
        
        for box in getattr(results, "boxes", []):
            cls_id = int(box.cls[0])
            xyxy = box.xyxy[0].cpu().numpy().astype(int)
            conf = float(box.conf[0])
            
            if cls_id == CLASS_PERSON:
                persons.append({"box": xyxy, "conf": conf, "helmet": False, "vest": False})
            elif cls_id == CLASS_HELMET:
                helmets.append(xyxy)
            elif cls_id == CLASS_VEST:
                vests.append(xyxy)

        # Association PPE -> Personnes
        for p in persons:
            for h_box in helmets:
                if box_iou(p["box"], h_box) > 0.5:
                    p["helmet"] = True
            for v_box in vests:
                if box_iou(p["box"], v_box) > 0.5:
                    p["vest"] = True

        # Logique d'alerte
        quelquun_en_infraction = False
        infraction_type = ""

        def in_roi(box):
            cx, cy = (box[0] + box[2]) // 2, (box[1] + box[3]) // 2
            return cv2.pointPolygonTest(roi_points, (float(cx), float(cy)), False) >= 0

        for p in persons:
            if in_roi(p["box"]):
                is_ok = True
                label = "PERSONNE"
                color = VERT_OK
                
                if detection_mode == MODE_PPE:
                    missing = []
                    if not p["helmet"]: missing.append("CASQUE")
                    if not p["vest"]: missing.append("GILET")
                    
                    if missing:
                        is_ok = False
                        quelquun_en_infraction = True
                        infraction_type = "EPI MANQUANT: " + " & ".join(missing)
                        color = JAUNE_INTRUS
                        label = "ATTENTION: " + infraction_type
                    else:
                        label = "PERSONNE OK (EPI)"
                else:
                    # MODE_HUMAN
                    quelquun_en_infraction = True
                    infraction_type = "PRESENCE ZONE CRITIQUE"
                    color = JAUNE_INTRUS

                cv2.rectangle(frame_visuelle, (p["box"][0], p["box"][1]), (p["box"][2], p["box"][3]), color, 2)
                cv2.putText(frame_visuelle, label, (p["box"][0], max(0, p["box"][1] - 10)),
                            cv2.FONT_HERSHEY_SIMPLEX, 0.5, color, 2)

        if quelquun_en_infraction:
            if not est_en_alerte:
                est_en_alerte = True
                compteur_total += 1
                temps_debut_intrusion = time.time()
                alerte_sonore()
                subdir = os.path.join(SCREENSHOT_DIR, camera_id.replace("/", "_"))
                os.makedirs(subdir, exist_ok=True)
                nom_photo = os.path.join(subdir, f"alerte_{datetime.datetime.now().strftime('%H%M%S')}.jpg")
                cv2.imwrite(nom_photo, frame_visuelle)
            
            cv2.putText(frame_visuelle, f"ALERTE: {infraction_type}", (frame_w // 10, 50),
                        cv2.FONT_HERSHEY_DUPLEX, 0.7, ROUGE_ALERTE, 2)
        else:
            if est_en_alerte:
                duree = round(time.time() - temps_debut_intrusion, 2)
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                with open(LOG_FILE, "a", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow([timestamp, infraction_type or "Alerte", duree, camera_id])
                est_en_alerte = False

        # Overlay UI
        cv2.fillPoly(overlay, [roi_points], BLEU_ZONE)
        cv2.addWeighted(overlay, 0.3, frame_visuelle, 0.7, 0, frame_visuelle)
        cv2.polylines(frame_visuelle, [roi_points], True, BLEU_ZONE, 2)
        
        # Dashboard bas
        cv2.rectangle(frame_visuelle, (0, frame_h - 40), (frame_w, frame_h), (30, 30, 30), -1)
        mode_txt = "MODE: " + ("DETECTION HUMAINE" if detection_mode == MODE_HUMAN else "CONTROLE EPI")
        cv2.putText(frame_visuelle, mode_txt, (10, frame_h - 15), cv2.FONT_HERSHEY_SIMPLEX, 0.5, GRIS_INFO, 1)
        
        status_color = ROUGE_ALERTE if est_en_alerte else VERT_OK
        status_txt = "ALERTE ACTIVE" if est_en_alerte else "PROTECTION ACTIVE"
        cv2.putText(frame_visuelle, status_txt, (frame_w // 2 - 50, frame_h - 15), cv2.FONT_HERSHEY_SIMPLEX, 0.6, status_color, 2)
        cv2.putText(frame_visuelle, f"ALERTS: {compteur_total}", (frame_w - 120, frame_h - 15), cv2.FONT_HERSHEY_SIMPLEX, 0.5, BLANC, 1)

        if headless:
            ret_j, jpeg = cv2.imencode(".jpg", frame_visuelle)
            if ret_j:
                with _last_frames_lock:
                    _last_frames[camera_id] = jpeg.tobytes()
        else:
            cv2.imshow(f"SAFEDETECT - {camera_id}", frame_visuelle)
            if cv2.waitKey(1) & 0xFF == ord('q'): break

    cap.release()
    with _last_frames_lock: _last_frames.pop(camera_id, None)
    if not headless: cv2.destroyAllWindows()
    return {"camera_id": camera_id, "alerts": compteur_total}


def get_last_frame(camera_id):
    with _last_frames_lock: return _last_frames.get(camera_id)

def get_snapshot(camera_url_or_index):
    source = int(camera_url_or_index) if str(camera_url_or_index).isdigit() else camera_url_or_index
    cap = cv2.VideoCapture(source)
    if not cap.isOpened(): return None
    for _ in range(5): ret, frame = cap.read()
    cap.release()
    return frame if ret else None

_last_frames = {}
_last_frames_lock = threading.Lock()
_active_threads = {}

def start_surveillance(camera_urls):
    global _active_threads
    for cam in camera_urls:
        cid = cam.get("id")
        url = cam.get("url")
        if cid in _active_threads: continue
        stop_ev = threading.Event()
        t = threading.Thread(target=run_detection, args=(url, cid, True, stop_ev), daemon=True)
        _active_threads[cid] = {"thread": t, "stop_event": stop_ev}
        t.start()
    return list(_active_threads.keys())

def stop_surveillance(camera_id=None):
    global _active_threads
    if camera_id:
        if camera_id in _active_threads:
            _active_threads[camera_id]["stop_event"].set()
            del _active_threads[camera_id]
            with _last_frames_lock: _last_frames.pop(camera_id, None)
    else:
        for cid, data in list(_active_threads.items()): data["stop_event"].set()
        _active_threads.clear()
        with _last_frames_lock: _last_frames.clear()

def get_active_cameras():
    return list(_active_threads.keys())

if __name__ == "__main__":
    import sys
    URL_CAM = sys.argv[1] if len(sys.argv) > 1 else "0"
    run_detection(URL_CAM, "cam0", headless=False)
