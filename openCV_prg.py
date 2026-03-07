"""
SAFEDETECT - Script standalone (une caméra).
Pour plusieurs caméras, utilisez l'application web.
"""
import os
from surveillance import run_detection

# Une seule caméra en mode script
# Par défaut on utilise l'index 1 (souvent Iriun). Modifier ci‑dessous si besoin.
URL_CAM = os.environ.get("URL_CAM", "1")

if __name__ == "__main__":
    import sys

    # Permet aussi de passer l'index ou l'URL en argument : python openCV_prg.py 0
    cam_source = URL_CAM
    if len(sys.argv) > 1:
        cam_source = sys.argv[1]

    print("--------------------------------------------------")
    print("   SAFEDETECT : PROTECTION INDUSTRIELLE ACTIVE    ")
    print("--------------------------------------------------")
    print(f"Source camera = {cam_source}  (0/1/2 pour Iriun, ou URL)")
    print("Appuyez sur 'q' pour arrêter le système.")
    run_detection(cam_source, "cam0", headless=False)
