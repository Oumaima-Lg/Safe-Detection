"""
SAFEDETECT - Application web d'administration.
Connexion admin + gestion de plusieurs adresses de caméras.
"""
import os
import json
import csv
import time
import base64
from pathlib import Path
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, Response, send_from_directory, jsonify

import cv2
import numpy as np
from surveillance import start_surveillance, stop_surveillance, get_active_cameras, get_last_frame, get_snapshot

# ... (rest of configuration)

# ==============================
# CONFIGURATION
# ==============================
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
CAMERAS_FILE = DATA_DIR / "cameras.json"
CAPTURES_DIR = BASE_DIR / "captures_intrusions"
ZONES_FILE = DATA_DIR / "zones.json"

# Comptes admin (en production : utiliser des mots de passe hashés et une vraie base)
# Vous pouvez définir ADMIN_USER et ADMIN_PASSWORD dans les variables d'environnement
ADMIN_USER = os.environ.get("SAVEDETECT_ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ.get("SAVEDETECT_ADMIN_PASSWORD", "safedetect2026")
SECRET_KEY = os.environ.get("SECRET_KEY", "changez-moi-en-production-savedetect")

app = Flask(__name__)
app.secret_key = SECRET_KEY

DATA_DIR.mkdir(exist_ok=True)
if not CAMERAS_FILE.exists():
    CAMERAS_FILE.write_text("[]", encoding="utf-8")
if not ZONES_FILE.exists():
    ZONES_FILE.write_text("{}", encoding="utf-8")


# ==============================
# STOCKAGE CAMÉRAS
# ==============================
def load_cameras():
    with open(CAMERAS_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def save_cameras(cameras):
    with open(CAMERAS_FILE, "w", encoding="utf-8") as f:
        json.dump(cameras, f, indent=2, ensure_ascii=False)


# ==============================
# AUTH
# ==============================
def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if not session.get("admin_logged_in"):
            flash("Veuillez vous connecter.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapped


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = request.form.get("username", "").strip()
        pwd = request.form.get("password", "")
        if user == ADMIN_USER and pwd == ADMIN_PASSWORD:
            session["admin_logged_in"] = True
            session["admin_user"] = user
            flash("Connexion réussie.", "success")
            return redirect(url_for("dashboard"))
        flash("Identifiant ou mot de passe incorrect.", "error")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Vous êtes déconnecté.", "info")
    return redirect(url_for("login"))


# ==============================
# DASHBOARD & CAMÉRAS
# ==============================
@app.route("/")
def index():
    if session.get("admin_logged_in"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    cameras = load_cameras()
    active = get_active_cameras()
    return render_template("dashboard.html", cameras=cameras, active_cameras=active)


@app.route("/stream/<camera_id>")
@login_required
def stream(camera_id):
    """Flux MJPEG en direct : affiche la vue caméra avec la zone sécurisée et les alertes."""
    def generate():
        while True:
            frame = get_last_frame(camera_id)
            if frame:
                yield (b"--frame\r\nContent-Type: image/jpeg\r\n\r\n" + frame + b"\r\n")
            time.sleep(0.08)
    return Response(generate(), mimetype="multipart/x-mixed-replace; boundary=frame")


# ==============================
# ZONE CRITIQUE (dessin par caméra)
# ==============================
def load_zones():
    with open(ZONES_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def save_zones(zones):
    with open(ZONES_FILE, "w", encoding="utf-8") as f:
        json.dump(zones, f, indent=2, ensure_ascii=False)


@app.route("/zone-setup/<camera_id>")
@login_required
def zone_setup_page(camera_id):
    """Page pour dessiner la zone critique de la caméra."""
    cameras = load_cameras()
    cam = next((c for c in cameras if c.get("id") == camera_id), None)
    if not cam:
        flash("Caméra introuvable.", "error")
        return redirect(url_for("dashboard"))
    return render_template("zone_setup.html", camera_id=camera_id, camera_label=cam.get("label") or camera_id)


@app.route("/api/zone-setup/<camera_id>", methods=["GET"])
@login_required
def api_zone_setup_get(camera_id):
    """Retourne la dernière frame de la caméra (base64) + dimensions pour le dessin."""
    frame_bytes = get_last_frame(camera_id)
    
    # Si la surveillance ne tourne pas, on essaie de prendre une capture unique
    if frame_bytes is None:
        cameras = load_cameras()
        cam = next((c for c in cameras if c.get("id") == camera_id), None)
        if cam:
            frame_np = get_snapshot(cam['url'])
            if frame_np is not None:
                _, jpeg = cv2.imencode(".jpg", frame_np)
                frame_bytes = jpeg.tobytes()
            else:
                return jsonify({"error": "camera_unreachable"}), 200
        else:
            return jsonify({"error": "camera_not_found"}), 200

    nparr = np.frombuffer(frame_bytes, np.uint8)
    img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
    if img is None:
        return jsonify({"error": "invalid_frame"}), 200
    h, w = img.shape[:2]
    _, jpeg = cv2.imencode(".jpg", img)
    b64 = base64.b64encode(jpeg.tobytes()).decode("utf-8")
    return jsonify({"image": f"data:image/jpeg;base64,{b64}", "width": w, "height": h})


@app.route("/api/zone-setup/<camera_id>", methods=["POST"])
@login_required
def api_zone_setup_post(camera_id):
    """Enregistre la zone critique dessinée pour la caméra."""
    data = request.get_json(force=True, silent=True) or {}
    points = data.get("points")
    frame_size = data.get("frame_size")
    if not points or len(points) < 3 or not frame_size or len(frame_size) != 2:
        return jsonify({"error": "points_required"}), 400
    zones = load_zones()
    zones[camera_id] = {
        "points": [[int(x), int(y)] for x, y in points],
        "frame_size": [int(frame_size[0]), int(frame_size[1])],
    }
    save_zones(zones)
    return jsonify({"ok": True})


@app.route("/cameras/add", methods=["POST"])
@login_required
def add_camera():
    label = request.form.get("label", "").strip() or None
    url = request.form.get("url", "").strip()
    mode = request.form.get("detection_mode", "human")
    if not url:
        flash("L'adresse de la caméra est obligatoire.", "error")
        return redirect(url_for("dashboard"))

    cameras = load_cameras()
    # Utiliser un timestamp pour l'ID pour éviter les collisions (cam_20260307213015)
    cam_id = f"cam_{int(time.time())}"
    cameras.append({
        "id": cam_id, 
        "label": label or cam_id, 
        "url": url,
        "detection_mode": mode
    })
    save_cameras(cameras)
    flash(f"Caméra ajoutée : {label or url}. Veuillez définir la zone critique.", "success")
    return redirect(url_for("zone_setup_page", camera_id=cam_id))


@app.route("/cameras/update-mode/<cam_id>", methods=["POST"])
@login_required
def update_camera_mode(cam_id):
    mode = request.form.get("detection_mode")
    cameras = load_cameras()
    for c in cameras:
        if c.get("id") == cam_id:
            c["detection_mode"] = mode
            break
    save_cameras(cameras)
    flash("Mode de détection mis à jour.", "success")
    # Si la surveillance est active, il faudra redémarrer pour prendre en compte (ou la boucle le fera via _get_camera_config)
    return redirect(url_for("dashboard"))


@app.route("/cameras/delete/<cam_id>", methods=["POST"])
@login_required
def delete_camera(cam_id):
    cameras = load_cameras()
    cameras = [c for c in cameras if c.get("id") != cam_id]
    save_cameras(cameras)
    stop_surveillance(cam_id)
    flash("Caméra supprimée.", "success")
    return redirect(url_for("dashboard"))


@app.route("/surveillance/start", methods=["POST"])
@login_required
def start_surveillance_route():
    cameras = load_cameras()
    if not cameras:
        flash("Aucune caméra configurée. Ajoutez des adresses de caméras.", "error")
        return redirect(url_for("dashboard"))
    started = start_surveillance(cameras)
    flash(f"Surveillance démarrée pour {len(started)} caméra(s).", "success")
    return redirect(url_for("dashboard"))


@app.route("/surveillance/stop", methods=["POST"])
@login_required
def stop_surveillance_route():
    stop_surveillance()
    flash("Surveillance arrêtée pour toutes les caméras.", "info")
    return redirect(url_for("dashboard"))


# ==============================
# LOGS (optionnel)
# ==============================
@app.route("/logs")
@login_required
def logs():
    log_path = BASE_DIR / "savedetect_security_logs.csv"
    rows = []
    if log_path.exists():
        with open(log_path, "r", encoding="utf-8", newline="") as f:
            reader = csv.reader(f)
            header = next(reader, None)
            rows = list(reader)
            rows.reverse()
            rows = rows[:200]
    return render_template("logs.html", header=header, rows=rows)


@app.route("/captures")
@login_required
def captures():
    """Page listant les captures d'intrusion (screenshots) par caméra."""
    cameras = load_cameras()
    cam_map = {c.get("id"): c.get("label") or c.get("id") for c in cameras}
    
    captures_list = []
    if CAPTURES_DIR.exists():
        # Lister tous les dossiers de caméras
        for cam_dir in sorted(CAPTURES_DIR.iterdir()):
            if cam_dir.is_dir():
                cid = cam_dir.name
                # On ne montre que s'il y a des images
                images = sorted(list(cam_dir.glob("*.jpg")), key=os.path.getmtime, reverse=True)[:50]
                if images:
                    captures_list.append(
                        {
                            "id": cid,
                            "label": cam_map.get(cid, cid),
                            "files": [f"{cid}/{img.name}" for img in images],
                        }
                    )
    return render_template("captures.html", captures=captures_list)


@app.route("/captures/file/<path:filename>")
@login_required
def capture_file(filename):
    """Serre les fichiers d'image de captures_intrusions."""
    return send_from_directory(CAPTURES_DIR, filename)


# ==============================
# LANCEMENT
# ==============================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
