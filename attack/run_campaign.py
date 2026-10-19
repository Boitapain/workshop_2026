"""Lance les trois scénarios Red Team à la suite, avec une pause entre chacun.

Usage : python attack/run_campaign.py [cible]
"""
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
TARGET = sys.argv[1] if len(sys.argv) > 1 else "https://localhost"
SCRIPTS = ["injection_probe.py", "brute_force.py", "http_flood.py"]

for i, script in enumerate(SCRIPTS):
    subprocess.run([sys.executable, str(HERE / script), TARGET], check=False)
    if i < len(SCRIPTS) - 1:
        print("\n  (pause 45 s : retour au régime nominal)\n")
        time.sleep(45)
