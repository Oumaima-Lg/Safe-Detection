"""
SAFEDETECT - Script standalone (une caméra).
Pour plusieurs caméras, utilisez l'application web.
"""
import os
from surveillance import run_detection

# Une seule caméra en mode script
URL_CAM = os.environ.get("URL_CAM", "http://10.247.21.164:8080/video")

if __name__ == "__main__":
    print("--------------------------------------------------")
    print("   SAFEDETECT : PROTECTION INDUSTRIELLE ACTIVE    ")
    print("--------------------------------------------------")
    print("Appuyez sur 'q' pour arrêter le système.")
    run_detection(URL_CAM, "cam0", headless=False)
