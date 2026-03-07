"""
SAVEDETECT - Application web d'administration.
Connexion admin + gestion de plusieurs adresses de caméras.
"""
import os
import json
import csv
import time
from pathlib import Path
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, Response

from surveillance import start_surveillance, stop_surveillance, get_active_cameras, get_last_frame

# ==============================
# CONFIGURATION
# ==============================
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
CAMERAS_FILE = DATA_DIR / "cameras.json"

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


@app.route("/cameras/add", methods=["POST"])
@login_required
def add_camera():
    label = request.form.get("label", "").strip() or None
    url = request.form.get("url", "").strip()
    if not url:
        flash("L'adresse de la caméra est obligatoire.", "error")
        return redirect(url_for("dashboard"))

    cameras = load_cameras()
    cam_id = f"cam_{len(cameras) + 1}"
    cameras.append({"id": cam_id, "label": label or cam_id, "url": url})
    save_cameras(cameras)
    flash(f"Caméra ajoutée : {label or url}", "success")
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


# ==============================
# LANCEMENT
# ==============================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
