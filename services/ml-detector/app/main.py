"""ml-detector — détection d'anomalies multivariée (Isolation Forest) et qualification de l'incident.

Ensemble de deux modèles appris sur la référence :
- IsolationForest : anomalies multivariées (combinaisons inhabituelles de features) ;
- enveloppe robuste par feature (médiane / IQR / maximum observés) : couvre les features quasi
  constantes en régime normal (sonde, invariant comptable, cibles arrêtées) que l'IsolationForest
  ne peut pas découper. Les bornes sont apprises, pas fixées à la main.

Cycle de vie :
1. BASELINE : au premier démarrage sans modèle, collecte BASELINE_SAMPLES vecteurs de trafic normal,
   puis entraîne RobustScaler + IsolationForest et calibre le seuil d'alerte sur cette période.
2. ACTIVE : toutes les 5 s, score du vecteur courant. Deux fenêtres anormales consécutives
   déclenchent un événement vers le moteur de remédiation.

Qualification du type d'incident :
- si un classifieur supervisé entraîné hors ligne existe (ml/train.py → classifier.joblib), il est utilisé ;
- sinon, attribution : le groupe de features qui s'écarte le plus de la référence désigne le type.
"""
import asyncio
import csv
import os
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

import httpx
import joblib
import numpy as np
import hmac

from fastapi import FastAPI, Header, HTTPException
from prometheus_client import Counter, Gauge, Histogram, make_asgi_app
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler

from features import FEATURES, collect
from resilience_common import log_event, read_secret, setup_logging

logger = setup_logging()

MODEL_DIR = Path(os.getenv("MODEL_DIR", "/models"))
DATA_DIR = Path(os.getenv("DATA_DIR", "/data"))
INTERVAL = float(os.getenv("DETECT_INTERVAL", "5"))
BASELINE_SAMPLES = int(os.getenv("BASELINE_SAMPLES", "120"))  # 120 × 5 s = 10 min
CONSECUTIVE = int(os.getenv("CONSECUTIVE_WINDOWS", "2"))
RESEND_S = float(os.getenv("EVENT_RESEND_S", "60"))      # relance si l'épisode d'anomalie persiste
EPISODE_END = int(os.getenv("EPISODE_END_WINDOWS", "3"))  # fenêtres normales consécutives = fin d'épisode
ENGINE_URL = os.getenv("ENGINE_URL", "http://remediation-engine:8000/events")
# Seule la sonde (vérification synthétique toutes les 5 s) est exclue du calcul des features « clients
# externes » : le trafic simulé (traffic-gen) représente des utilisateurs légitimes et DOIT faire partie
# de la référence, sinon « un client externe apparaît » devient le signal dominant de toute attaque.
# La protection contre le blocage (sonde ET trafic) reste gérée côté moteur (policy.yaml).
PROTECTED_UAS = {"resilience-probe/1.0"}
STARTED_AT = time.time()

# Attribution : groupes de features → type d'incident (utilisé sans classifieur supervisé).
GROUPS = {
    "brute_force": ["login_failure_ratio", "login_attempt_rate"],
    "injection": ["waf_403_rate", "ratio_4xx", "path_entropy"],
    "http_flood": ["waf_rps", "top_client_share", "api_latency_p95"],
    "data_tampering": ["pg_mod_per_payment", "ledger_drift"],
    "service_crash": ["targets_down", "ratio_5xx", "probe_failure"],
    "db_outage": ["pg_down"],
    "resource_exhaustion": ["cpu_business", "mem_business_mb", "pg_connections"],
}

# Features couvertes par l'enveloppe (invariants et signaux de sécurité, quasi constants en régime normal),
# avec leur marge minimale : un événement isolé et bénin (une transaction témoin ratée sur six, quelques
# fautes de frappe) ne suffit pas à sortir de l'enveloppe. Les comportements de trafic (débit, clients,
# chemins…) restent du ressort de l'IsolationForest.
ENVELOPE_FLOOR = {"probe_failure": 0.3, "targets_down": 0.5, "pg_down": 0.5, "ledger_drift": 0.001,
                  "ratio_5xx": 0.05, "login_failure_ratio": 0.15, "waf_403_rate": 0.2, "waf_rps": 25.0}

SCORE = Gauge("ml_anomaly_score", "Score d'anomalie normalisé (seuil d'alerte = 0.6)")
RAW = Gauge("ml_anomaly_raw", "Score brut de l'Isolation Forest")
FEATURE = Gauge("ml_feature", "Valeur courante des features", ["name"])
STATE = Gauge("ml_state", "0 = apprentissage de la référence, 1 = détection active")
BASELINE_PROGRESS = Gauge("ml_baseline_progress", "Progression de l'apprentissage (0-1)")
EVENTS = Counter("ml_events_total", "Événements envoyés au moteur", ["type"])
INFER = Histogram("ml_inference_seconds", "Durée d'un cycle de détection")


class Model:
    def __init__(self):
        self.scaler: RobustScaler | None = None
        self.forest: IsolationForest | None = None
        self.classifier = None
        self.threshold = 1.0
        self.median = None
        self.iqr = None
        self.hi = None
        self.margin = None
        self.version = None

    @property
    def ready(self) -> bool:
        return self.forest is not None

    def load(self) -> bool:
        path = MODEL_DIR / "detector.joblib"
        if not path.exists():
            return False
        bundle = joblib.load(path)
        if bundle.get("features") != FEATURES:
            log_event(logger, "model.features_mismatch", expected=FEATURES)
            return False
        self.__dict__.update({k: bundle[k] for k in
                              ("scaler", "forest", "threshold", "median", "iqr", "hi", "margin", "version")})
        clf_path = MODEL_DIR / "classifier.joblib"
        if clf_path.exists():
            self.classifier = joblib.load(clf_path)
        log_event(logger, "model.loaded", version=self.version, classifier=self.classifier is not None)
        return True

    def fit(self, X: np.ndarray) -> None:
        self.scaler = RobustScaler().fit(X)
        Xs = self.scaler.transform(X)
        self.forest = IsolationForest(n_estimators=200, contamination="auto", random_state=42).fit(Xs)
        raw = -self.forest.score_samples(Xs)
        # Seuil : au-dessus du pire score observé en trafic normal, avec une marge (0 faux positif visé).
        self.threshold = float(max(np.quantile(raw, 0.995), raw.max()) * 1.03)
        self.median = np.median(X, axis=0)
        q75, q25 = np.percentile(X, [75, 25], axis=0)
        self.iqr = np.maximum(q75 - q25, 1e-3 + 0.05 * np.abs(self.median))
        # 98e centile plutôt que le maximum absolu : une poignée de fenêtres polluées (résidu d'attaque
        # drainant au tout début de l'apprentissage) ne doit pas gonfler durablement le seuil d'enveloppe.
        self.hi = np.percentile(X, 98, axis=0)
        floor = np.array([ENVELOPE_FLOOR.get(f, np.inf) for f in FEATURES])  # inf = hors enveloppe
        self.margin = np.maximum.reduce([3 * self.iqr, 0.5 * np.abs(self.hi), floor])
        self.version = datetime.now(timezone.utc).strftime("%Y-%m-%d-%H%M")
        MODEL_DIR.mkdir(parents=True, exist_ok=True)
        joblib.dump({"features": FEATURES, "scaler": self.scaler, "forest": self.forest,
                     "threshold": self.threshold, "median": self.median, "iqr": self.iqr,
                     "hi": self.hi, "margin": self.margin, "version": self.version}, MODEL_DIR / "detector.joblib")
        log_event(logger, "model.trained", samples=len(X), threshold=round(self.threshold, 4), version=self.version)

    def score(self, x: np.ndarray) -> tuple[float, float]:
        raw = float(-self.forest.score_samples(self.scaler.transform(x.reshape(1, -1)))[0])
        thr = self.threshold
        forest = 0.6 * raw / thr if raw < thr else 0.6 + 0.4 * min(1.0, (raw - thr) / max(1 - thr, 1e-6))
        # Enveloppe : dépassement de (maximum observé + marge), exprimé en marges.
        env = np.isfinite(self.margin)
        excess = float(np.max((x[env] - (self.hi[env] + self.margin[env])) / self.margin[env]))
        envelope = 0.6 + 0.4 * min(1.0, excess) if excess > 0 else 0.0
        return raw, float(np.clip(max(forest, envelope), 0, 1))

    def qualify(self, x: np.ndarray) -> tuple[str, float, list]:
        # Écart robuste à la référence, uniquement dans le sens « plus que la normale ». Les features
        # quasi constantes (IQR ≈ 0) sont normalisées par leur marge d'enveloppe : sinon le moindre écart
        # (une transaction témoin ratée) écraserait tous les autres signaux.
        scale = np.where(np.isfinite(self.margin), self.margin, self.iqr)
        z = np.maximum((x - self.median) / scale, 0)
        contrib = sorted(zip(FEATURES, z.round(2).tolist()), key=lambda kv: -kv[1])[:4]
        if self.classifier is not None:
            proba = self.classifier.predict_proba(x.reshape(1, -1))[0]
            best = int(np.argmax(proba))
            label = str(self.classifier.classes_[best])
            if label != "normal":
                return label, float(proba[best]), contrib
        idx = {f: i for i, f in enumerate(FEATURES)}

        # Signatures spécifiques, par ordre de priorité : chaque type a UN signal qui lui est propre
        # et qu'on teste avant l'attribution générique par volume. Sans cela, une attaque intense
        # (brute force, injection) est noyée dans le signal « débit élevé » et qualifiée à tort http_flood.
        # Le seuil est « au-delà du maximum observé en régime normal + marge » : il est appris, pas fixé.
        def exceeds(feat: str) -> bool:
            return x[idx[feat]] > self.hi[idx[feat]] + self.margin[idx[feat]]

        signatures = [
            ("pg_down", "db_outage", 0.95),            # base injoignable
            ("ledger_drift", "data_tampering", 0.95),  # invariant comptable violé
            ("targets_down", "service_crash", 0.9),    # service métier arrêté
            ("login_failure_ratio", "brute_force", 0.9),  # pic d'échecs de connexion
            ("waf_403_rate", "injection", 0.9),        # pic de blocages ModSecurity
            ("waf_rps", "http_flood", 0.85),           # débit extrême sans autre signature
        ]
        for feat, type_, confidence in signatures:
            if exceeds(feat):
                return type_, confidence, contrib

        # Pas de signature franche : attribution par groupe de features (http_flood, resource_exhaustion).
        group_scores = {t: float(sum(z[idx[f]] for f in feats)) for t, feats in GROUPS.items()}
        total = sum(group_scores.values()) or 1.0
        best = max(group_scores, key=group_scores.get)
        return best, round(group_scores[best] / total, 3), contrib


model = Model()
baseline: list[list[float]] = []


def append_dataset(ts: float, feats: dict, raw: float, scaled: float) -> None:
    """Chaque vecteur est archivé : c'est le jeu de données d'entraînement (ml/train.py)."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    path = DATA_DIR / "features.csv"
    new = not path.exists()
    with path.open("a", newline="") as fh:
        writer = csv.writer(fh)
        if new:
            writer.writerow(["ts", *FEATURES, "raw_score", "score"])
        writer.writerow([round(ts, 1), *(round(feats[f], 5) for f in FEATURES), round(raw, 5), round(scaled, 4)])


async def loop() -> None:
    token = read_secret("internal_token")
    STATE.set(1 if model.load() else 0)
    # Épisode d'anomalie : un seul événement à son début (type qualifié à ce moment), puis une relance
    # toutes les RESEND_S s tant qu'il persiste. Évite qu'un même incident, dont les symptômes évoluent
    # (CPU → erreurs → sonde), ne soit déclaré plusieurs fois sous des types différents.
    streak, calm, episode_sent_at, episode_type = 0, 0, None, None
    async with httpx.AsyncClient(timeout=5) as client:
        while True:
            started = time.time()
            try:
                with INFER.time():
                    feats, suspects = await collect(client, time.time_ns(), PROTECTED_UAS)
                    x = np.array([feats[f] for f in FEATURES])
                    for f in FEATURES:
                        FEATURE.labels(f).set(feats[f])

                    if not model.ready:
                        # On n'apprend que sur des périodes saines : pas de panne en cours, et pas
                        # pendant les 30 premières secondes (la fenêtre glissante couvre l'avant-démarrage).
                        healthy = feats["probe_failure"] == 0 and feats["targets_down"] == 0 and feats["pg_down"] == 0
                        if started - STARTED_AT < 35 or not healthy:
                            await asyncio.sleep(max(0.5, INTERVAL - (time.time() - started)))
                            continue
                        baseline.append(x.tolist())
                        BASELINE_PROGRESS.set(len(baseline) / BASELINE_SAMPLES)
                        append_dataset(started, feats, 0, 0)
                        if len(baseline) >= BASELINE_SAMPLES:
                            model.fit(np.array(baseline))
                            STATE.set(1)
                    else:
                        raw, scaled = model.score(x)
                        RAW.set(raw)
                        SCORE.set(scaled)
                        append_dataset(started, feats, raw, scaled)
                        if scaled >= 0.6:
                            streak, calm = streak + 1, 0
                        else:
                            streak, calm = 0, calm + 1
                            if calm >= EPISODE_END:
                                episode_sent_at, episode_type = None, None
                        due = episode_sent_at is None or started - episode_sent_at > RESEND_S
                        if streak >= CONSECUTIVE and due:
                            type_, confidence, contrib = model.qualify(x)
                            if episode_type is not None:
                                type_ = episode_type  # relance : même incident, même type
                            episode_sent_at, episode_type = started, type_
                            event = {
                                "source": "ml-detector", "type": type_,
                                "anomaly_score": round(scaled, 3), "confidence": confidence,
                                "window": {"start": started - 30 - INTERVAL * (CONSECUTIVE - 1), "end": started},
                                "top_features": contrib, "suspects": suspects,
                                "model_version": model.version,
                            }
                            resp = await client.post(ENGINE_URL, json=event,
                                                     headers={"Authorization": f"Bearer {token}"})
                            EVENTS.labels(type_).inc()
                            log_event(logger, "ml.event", type=type_, score=round(scaled, 3),
                                      confidence=confidence, top=contrib[:2], engine=resp.status_code)
            except Exception as exc:
                log_event(logger, "ml.cycle_error", error=f"{type(exc).__name__}: {exc}")
            await asyncio.sleep(max(0.5, INTERVAL - (time.time() - started)))


@asynccontextmanager
async def lifespan(app: FastAPI):
    task = asyncio.create_task(loop())
    yield
    task.cancel()


app = FastAPI(title="ml-detector", lifespan=lifespan, docs_url=None, redoc_url=None)
app.mount("/metrics", make_asgi_app())


@app.get("/status")
async def status():
    return {"state": "active" if model.ready else "baseline",
            "baseline_progress": min(1.0, len(baseline) / BASELINE_SAMPLES),
            "model_version": model.version, "threshold": model.threshold,
            "classifier": model.classifier is not None}


@app.post("/retrain")
async def retrain(authorization: str = Header(default="")):
    """Relance l'apprentissage de la référence (à utiliser hors démo, trafic normal en cours)."""
    if not hmac.compare_digest(authorization.encode(), f"Bearer {read_secret('internal_token')}".encode()):
        raise HTTPException(403, "jeton de service invalide")
    (MODEL_DIR / "detector.joblib").unlink(missing_ok=True)
    global STARTED_AT
    baseline.clear()
    model.forest = None
    STARTED_AT = time.time()
    STATE.set(0)
    return {"state": "baseline"}


@app.get("/health")
async def health():
    return {"status": "ok"}
