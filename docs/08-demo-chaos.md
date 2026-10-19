# 08 — Démo, chaos engineering, Clip Chrono

## 1. Scénario de démo live (3 min, finale nationale)

Le jury juge la démo **depuis le PC Hôte**. Mains **hors du clavier** du PC Hôte dès le lancement de l'attaque.

| t | Écran (PC Hôte, dashboard plein écran) | Action / narration |
|---|----------------------------------------|--------------------|
| 0:00 | Bandeau vert, transactions qui défilent | « Voici la plateforme en fonctionnement nominal. » |
| 0:20 | — | Lancement **d'un seul script** sur le PC Attaquant |
| 0:30 | Courbes qui s'emballent, score ML qui monte | « Aucun seuil fixe : c'est le modèle qui voit l'écart. » |
| 0:45 | Bandeau orange : `DÉTECTÉ`, type, score | Le ML qualifie l'incident |
| 0:50 | Timeline : actions du playbook | La remédiation s'exécute seule |
| 1:00 | `✔ VÉRIFIÉ` : transaction témoin + RTO | Preuve de reprise |
| 1:10 | Bandeau vert | « Personne n'a touché le PC Hôte. » |
| 1:20 | Vue Grafana remédiation / journal d'audit | Traçabilité |
| 2:00 | Une **transaction manuelle** depuis le front | Seconde preuve, visible par le jury (après la reprise, c'est autorisé) |
| 2:30 | — | Marge / question |

Prévoir un **plan B** : un second scénario déjà répété, si le premier ne se déclenche pas dans les temps.

## 2. Checklist « zéro intervention humaine »

- [ ] Plateforme démarrée et stable depuis au moins 10 min (le ML a des fenêtres « normales » en mémoire)
- [ ] Générateur de trafic normal lancé (sinon tout ressemble à une anomalie)
- [ ] Deny-list WAF purgée, aucun incident ouvert, budget d'actions remis à zéro
- [ ] Veille, économiseur d'écran et notifications Windows désactivés ; PC sur secteur
- [ ] Ollama chaud (une requête de préchauffage envoyée) si l'assistant est montré
- [ ] Test de bout en bout effectué dans l'heure
- [ ] Horloges des PC synchronisées

## 3. Chaos engineering (jeudi)

Objectif : prouver que la reprise marche pour des **pannes**, pas seulement pour des attaques, et mesurer les RTO du PRA.

| # | Injection | Outil | Playbook attendu | RTO cible | RTO mesuré |
|---|-----------|-------|------------------|-----------|------------|
| C1 | Arrêt brutal de `payment-service` | `docker kill` / Pumba | `service_crash` | 15 s | |
| C2 | Arrêt de `postgres` | `docker kill` | `db_outage` | 30 s | |
| C3 | Latence réseau de 2 s vers la BDD | Pumba `netem` / Toxiproxy | `resource_exhaustion` | 60 s | |
| C4 | CPU saturé dans `auth-service` | `stress-ng` dans le conteneur | `resource_exhaustion` | 60 s | |
| C5 | Healthcheck KO (process vivant) | flag de debug | `restart_unhealthy` | 20 s | |
| C6 | Suppression de lignes en base | script SQL de test | `data_tampering` | 120 s | |
| C7 | Arrêt de `ml-detector` pendant un incident | `docker kill` | filet SIEM | 60 s | |
| C8 | Arrêt du moteur de remédiation | `docker kill` | auto-restart + reprise de l'état | 30 s | |
| C9 | Faux positif : pic de trafic légitime (×5) | Locust | **aucune action** | — | |

Chaque injection est scriptée dans `chaos/` et horodatée (ces labels alimentent aussi le dataset ML). Les RTO mesurés vont dans le dossier et le PCA/PRA.

## 4. Recette

| Critère | Méthode | OK |
|---------|---------|----|
| Déploiement depuis zéro < 5 min | `teardown -e purge=true` puis `deploy.yml`, chronométré | |
| Parcours de paiement complet | test E2E | |
| Chaque scénario Red Team détecté par le ML | rejeu × 3 | |
| Chaque scénario remédié sans humain | rejeu × 3 | |
| 0 faux positif en 30 min de trafic normal | Locust | |
| Aucun secret en clair dans le ZIP | `gitleaks detect` + revue | |
| Dashboard lisible à 3 m | test réel | |

## 5. Clip Chrono (60 s, **un seul plan, sans coupe**)

Il doit être « lisible à distance ». Filmer l'écran du dashboard (enregistrement d'écran ou caméra fixe), avec un **chronomètre visible** à l'écran.

| t | À l'image | Texte incrusté / voix |
|---|-----------|-----------------------|
| 0-8 s | Dashboard vert, transactions en cours | « Plateforme nominale » |
| 8-12 s | Lancement de l'attaque (PC Attaquant dans le champ, ou incrustation) | « Attaque lancée » |
| 12-25 s | Score ML qui monte, courbes rouges | « Détection ML » |
| 25-35 s | Timeline : actions du playbook | « Remédiation automatique » |
| 35-45 s | Transaction témoin ✔, RTO affiché | « Vérification : nouvelle transaction OK » |
| 45-60 s | Bandeau vert, récapitulatif (détection X s, reprise Y s, 0 intervention) | « Rétabli seul » |

Conseils : agrandir le zoom du navigateur, mode sombre contrasté, pas de curseur qui bouge, faire 5 à 10 prises et garder la meilleure. Tournage le jeudi, **avant le gel du code à 17 h**.
