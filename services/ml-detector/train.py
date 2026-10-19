"""Entraînement hors ligne du classifieur supervisé (étage 2 : qualification du type d'incident).

Entrées (volume /data du ml-detector) :
- features.csv : un vecteur toutes les 5 s, archivé en continu par le détecteur ;
- labels.csv   : intervalles [start, end] + type, écrits par chaos/chaos.py (et les scripts Red Team).

Sortie : /models/classifier.joblib (chargé au prochain démarrage du détecteur) + rapport d'évaluation.

Usage (PC Hôte) :
    docker cp ml/data/labels.csv resilience-ml-detector-1:/data/labels.csv
    docker compose -f infra/docker-compose.yml exec ml-detector python /srv/train.py
    docker compose -f infra/docker-compose.yml restart ml-detector
"""
import csv
import json
import sys
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix

sys.path.insert(0, "/srv/app")
from features import FEATURES  # noqa: E402

DATA, MODELS = Path("/data"), Path("/models")
TAIL_S = 30  # la fenêtre glissante de 30 s « voit » encore l'incident après sa fin


def load():
    with (DATA / "features.csv").open() as fh:
        rows = list(csv.DictReader(fh))
    with (DATA / "labels.csv").open() as fh:
        labels = [(float(r["start"]), float(r["end"]), r["type"]) for r in csv.DictReader(fh)]
    X, y, ts = [], [], []
    for r in rows:
        if "ts" not in r or r["ts"] in (None, ""):
            continue
        t = float(r["ts"])
        lab = next((typ for s, e, typ in labels if s <= t <= e + TAIL_S), "normal")
        # Une feature absente du CSV (schéma plus ancien) est traitée comme 0.
        X.append([float(r.get(f) or 0.0) for f in FEATURES])
        y.append(lab)
        ts.append(t)
    order = np.argsort(ts)
    return np.array(X)[order], np.array(y)[order]


def main() -> int:
    X, y = load()
    classes, counts = np.unique(y, return_counts=True)
    print("Répartition :", dict(zip(classes.tolist(), counts.tolist())))
    if len(classes) < 2:
        print("Pas assez de classes : lancer d'abord des campagnes de chaos / Red Team étiquetées.")
        return 1
    # Découpage TEMPOREL (pas aléatoire) : 75 % les plus anciens pour l'entraînement.
    cut = int(len(X) * 0.75)
    clf = RandomForestClassifier(n_estimators=300, class_weight="balanced", random_state=42, n_jobs=-1)
    clf.fit(X[:cut], y[:cut])
    if len(set(y[cut:])) > 1:
        pred = clf.predict(X[cut:])
        print(classification_report(y[cut:], pred, zero_division=0))
        print("Matrice de confusion (lignes = vrai, colonnes = prédit) :", clf.classes_.tolist())
        print(confusion_matrix(y[cut:], pred, labels=clf.classes_))
    else:
        print("Jeu de test sans incident : évaluation impossible, entraînement sur tout le jeu.")
    clf.fit(X, y)  # modèle final sur toutes les données
    MODELS.mkdir(exist_ok=True)
    joblib.dump(clf, MODELS / "classifier.joblib")
    importances = sorted(zip(FEATURES, clf.feature_importances_.round(3).tolist()), key=lambda kv: -kv[1])
    (MODELS / "model_card.json").write_text(json.dumps({
        "classes": clf.classes_.tolist(), "samples": len(X), "feature_importances": importances}, indent=2))
    print("Importances :", importances[:8])
    print("→ /models/classifier.joblib écrit. Redémarrer le ml-detector pour le charger.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
