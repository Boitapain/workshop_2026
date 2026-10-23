# 10 — État d'implémentation & mode d'emploi

Ce document décrit **ce qui tourne réellement** dans le dépôt. Il prime sur les documents 01-09 quand ils divergent : ceux-ci décrivent la cible.

## 1. Démarrer

```bash
python scripts/init_secrets.py                                # secrets locaux (ignorés par git)
docker compose -f infra/docker-compose.yml up -d --build      # ~20 conteneurs
```

Ou, depuis WSL / Linux : `ansible-playbook infra/ansible/deploy.yml`.

| URL (PC Hôte) | Contenu | Exposition |
|---------------|---------|------------|
| `https://localhost/` (ou `https://192.168.137.1/`) | Front client RESILIENCE Pay, via le WAF | **Seul port ouvert au réseau du labo** |
| `http://127.0.0.1:8080` | Dashboard ops (à filmer pour le Clip Chrono) | 127.0.0.1 uniquement |
| `http://127.0.0.1:3000` | Grafana (admin / `secrets/grafana_admin_password`) | 127.0.0.1 uniquement |
| `http://127.0.0.1:9090` | Prometheus | 127.0.0.1 uniquement |

Le certificat TLS est auto-signé (`secrets/tls_cert`) : le navigateur affiche un avertissement.

**Au premier démarrage**, le ml-detector apprend la référence « normale » pendant ~10 min (120 fenêtres saines de 5 s). Le dashboard affiche la progression. **Ne pas injecter d'incident pendant cette phase.** Le modèle est ensuite conservé dans le volume `ml-models`. Pour réapprendre : `POST /retrain` sur le ml-detector, avec le jeton de service.

> ⚠ Pour reconstruire **un seul** service, utiliser `--no-deps`. Sinon Compose recrée aussi ses dépendances, et l'apprentissage ML repart de zéro :
> `docker compose -f infra/docker-compose.yml up -d --build --no-deps <service>`

## 2. Ce qui est implémenté

| Composant | Fichiers | État |
|-----------|----------|------|
| auth-service | `services/auth-service/` | ✅ register / login / refresh / logout, JWT RS256 + JWKS, argon2id, verrouillage progressif, révocation interne (globale par époque, par compte) |
| payment-service | `services/payment-service/` | ✅ comptes, virements idempotents (`Idempotency-Key`), verrous ordonnés, anti-IDOR, mode lecture seule interne |
| front | `services/front/` | ✅ React + Tailwind : connexion, solde, virement, historique ; rafraîchissement automatique toutes les 3 s (indicateur « En direct ») |
| PostgreSQL | `infra/postgres/` | ✅ schéma + rôles à moindre privilège ; journal des écritures sans valeurs de paramètres |
| pg-backup | `services/pg-backup/` | ✅ dump toutes les 2 min, vérifié, marqué « sain » seulement si la sonde est OK ; `POST /restore` (données métier, journal d'audit préservé) |
| WAF | `infra/waf/` | ✅ ModSecurity + OWASP CRS (PL1), TLS, liste blanche des routes `/api`, rate-limit, deny-list IP **et** empreinte IP+UA dynamiques, mode strict, journal JSON |
| synthetic-probe | `services/synthetic-probe/` | ✅ login + virement + relecture toutes les 5 s **à travers le WAF** |
| traffic-gen | `services/traffic-gen/` | ✅ 20 utilisateurs simulés, charge variable, fautes de frappe réalistes |
| Observabilité | `infra/observability/` | ✅ Prometheus, Loki, Alloy, Grafana (dashboard provisionné), postgres-exporter, Alertmanager. CPU/mémoire des conteneurs lus via l'API Docker (proxy en lecture seule) ; cAdvisor retiré |
| SIEM | `infra/observability/rules/`, `loki-rules/` | ✅ règles métriques + journaux → Alertmanager → moteur |
| ml-detector | `services/ml-detector/` | ✅ 19 features, IsolationForest auto-calibré, anti-rebond, qualification par attribution ; ✅ `train.py` pour le classifieur supervisé (RandomForest) |
| remediation-engine | `services/remediation-engine/` | ✅ politique YAML, corrélation, garde-fous, vérification par sonde, escalade, SSE, persistance SQLite, reprise après crash, chien de garde interne, fenêtre de maintenance planifiée (`/admin/pause`) ; tests `tests/test_policy.py` |
| Accès Docker | `docker-proxy-rw` / `-ro` | ✅ proxys à regex : le moteur ne peut que lister, `restart` et `kill` (SIGHUP) |
| dashboard | `services/dashboard/` | ✅ bandeau d'état, KPI, courbes, timeline temps réel, conteneurs, panneau assistant |
| rag-assistant | `services/rag-assistant/` | ⚠️ code et image OK ; **non testé de bout en bout** (Ollama non installé sur le poste de dev) |
| Chaos | `chaos/chaos.py` | ✅ 6 scénarios, mesure du RTO, étiquettes pour le ML |
| Ansible | `infra/ansible/` | ⚠️ `deploy.yml`, `reset_demo.yml`, `teardown.yml` écrits, **non exécutés** (à lancer depuis WSL) |
| Scripts Red Team | `attack/` | ⚠️ kit portable (stdlib Python, cible par défaut `https://192.168.137.1`, mode aveugle) : `brute_force.py`, `injection_probe.py`, `http_flood.py`, `run_campaign.py` ; **à valider depuis le vrai PC Attaquant** |
| Vault | — | 🚧 non implémenté : secrets Docker + SOPS (voir ADR-006) |

## 3. Résultats mesurés (poste de dev, 19/10/2026, campagne `chaos/chaos.py`)

| Scénario | Détecté par | Type qualifié | Actions automatiques | RTO |
|----------|-------------|---------------|----------------------|-----|
| C1 — `docker kill payment-service` | surveillance Docker | `service_crash` | redémarrage de payment-service | **1,8 s** |
| C2 — `docker kill postgres` | surveillance Docker | `db_outage` | redémarrage de PostgreSQL | **1,9 s** |
| C4 — saturation CPU dans auth-service (4 processus, 90 s) | **ML** (cause principale `cpu_business`, suspect `auth-service`) | `resource_exhaustion` | redémarrage d'auth-service + mode strict au WAF (clients externes seulement) | **38,5 s** |
| C6 — mise à zéro de tous les soldes avec les identifiants applicatifs | **ML** (score 1,0, cause principale `ledger_drift`) | `data_tampering` | lecture seule → restauration du dernier dump sain (0,14 s) → révocation globale des sessions → réouverture | **39,6 s** |
| C7 — crash du ml-detector | — | — | relancé par Docker, modèle rechargé sans réapprentissage | 2,8 s |
| C8 — crash du moteur de remédiation | — | — | relancé par Docker, état SQLite repris | 5,1 s |
| Redéploiement d'auth + payment **sans** fenêtre de maintenance | Docker + ML (corrélés) | `service_crash` | redémarrage (conflit avec Compose) | 8,3 s |
| Redéploiement de WAF + moteur + ML **avec** fenêtre de maintenance | — | — | aucun (événements ignorés) | 0 faux incident |

Autres vérifications :

| Test | Résultat |
|------|----------|
| Transaction témoin à travers le WAF | ✅ ~110-160 ms |
| Blocage par empreinte (événement injecté) | ✅ le client ciblé reçoit 403, les autres clients derrière la même IP NAT passent toujours |
| Mode strict | ✅ client externe limité (429 au-delà de la rafale), trafic interne (sonde, traffic-gen) jamais limité |
| IP source vue par le WAF depuis l'hôte | `172.30.0.1` (passerelle Docker) → confirme le risque de l'ADR-009 |
| Faux positifs ML en régime normal | aucun incident ML hors injections et redéploiements (score courant ≈ 0,37-0,50, seuil 0,6) |
| Un incident par injection | ✅ après correctif « épisode d'anomalie » : C4 et C6 rejoués → 1 incident chacun, 1 événement ML chacun |
| Restauration de la base | ✅ 0,11-0,14 s ; invariant comptable revenu à 0 |

Les RTO de 38-40 s des scénarios ML se décomposent en : fenêtre glissante de 30 s + 2 fenêtres consécutives (anti-rebond) + actions + transaction témoin. Pour les réduire : fenêtre de 15 s, ou 1 seule fenêtre pour les violations d'invariant.

**Non testé ici** : les scénarios d'attaque réels (brute force, injection, flood depuis le PC Attaquant). La chaîne de blocage est validée par événement injecté ; les scripts Red Team sont écrits (`attack/README.md`) mais restent à rejouer depuis le PC Attaquant.

## 4. Chaîne de détection → remédiation

```
traffic-gen / clients ──► WAF ──► services ──► Prometheus / Loki
                                                    │
                     ml-detector (toutes les 5 s) ◄─┘──► Alertmanager (règles SIEM)
                            │ POST /events                    │ webhook
                            ▼                                 ▼
                     remediation-engine ◄── surveillance Docker (état / healthcheck)
                            │ politique YAML → actions
                            ├─► WAF : deny-list / empreinte / mode strict + SIGHUP
                            ├─► Docker : restart (via proxy à regex)
                            ├─► auth : révocation des sessions
                            ├─► payment : lecture seule
                            └─► pg-backup : restauration
                            │
                            ▼ vérification : transaction témoin postérieure aux actions
                     RESOLVED (RTO mesuré) ou escalade → ESCALATED
```

Trois sources d'événements alimentent le moteur. Le **ML** est la source principale ; la **surveillance Docker** et le **SIEM** sont des filets de sécurité. Les événements de même type sont corrélés dans un seul incident (fenêtre de 120 s).

## 5. Entraîner le classifieur supervisé

Sans classifieur, le type d'incident est déduit par **attribution** : le groupe de features qui s'écarte le plus de la référence désigne le type. Pour passer à un classifieur supervisé :

```bash
python chaos/chaos.py run all                       # → ml/data/labels.csv
cat attack/data/labels.csv >> ml/data/labels.csv    # labels du kit Red Team (sans l'en-tête)
docker cp ml/data/labels.csv resilience-ml-detector-1:/data/labels.csv
docker compose -f infra/docker-compose.yml exec ml-detector python /srv/train.py
docker compose -f infra/docker-compose.yml restart ml-detector
```

`train.py` affiche le rapport de classification et la matrice de confusion (à mettre dans le dossier), puis écrit `model_card.json`.

## 6. Écarts par rapport à la cible (docs 01-09)

| Cible | Implémenté | Raison |
|-------|-----------|--------|
| Vault (secrets dynamiques) | Secrets Docker générés localement + SOPS pour le partage | Temps ; Vault exige un descellement automatisé. Prochaine étape. |
| `tecnativa/docker-socket-proxy` | `wollomatic/socket-proxy` (regex par méthode) | tecnativa autorise *tous* les POST d'une section, donc `containers/create` → contraire au moindre privilège |
| Remédiation via `ansible-runner` | API HTTP internes (`pg-backup /restore`, `/internal/*`) + proxy Docker | Moins de privilèges et plus rapide ; Ansible sert au déploiement et à la préparation de la démo |
| SQLAlchemy + Alembic | `asyncpg` + SQL d'initialisation | Plus simple pour une semaine ; requêtes toutes paramétrées |
| Chroma | `InMemoryVectorStore` (langchain-core) | Corpus petit, aucune dépendance lourde |
| `waf_paranoia` dynamique, `rotate_secrets` | Non implémentés (`revoke_sessions global` à la place de la rotation) | À ajouter si le temps le permet |
| Latence réseau (C3) | Non implémentée dans `chaos.py` | Nécessite Pumba/Toxiproxy |

## 7. Bugs trouvés par les tests (et corrigés)

| Symptôme | Cause | Correctif |
|----------|-------|-----------|
| Altération des soldes non détectée, qualifiée `service_crash` | L'IsolationForest ignore les features constantes à l'apprentissage | Enveloppe robuste + invariant comptable `ledger_drift` ([04-ia-data.md §7](04-ia-data.md)) |
| Le playbook `restore_db` aurait planté | YAML 1.1 : la clé `on:` est lue comme le booléen `True` | Paramètre renommé `enabled` ; test `tests/test_policy.py` |
| 502 intermittents sur la transaction témoin | uvicorn ferme le keep-alive après 5 s, Nginx réutilise la connexion | `--timeout-keep-alive 75` (> 60 s côté Nginx) |
| Deux incidents parallèles (ML + alerte SIEM « sonde en échec ») | Symptôme générique non corrélé | `service_outage` rattaché à l'incident déjà ouvert |
| Faux incident juste après une reprise | La fenêtre glissante de 30 s voit encore l'incident | Événements des 45 s suivant une résolution rattachés à l'incident résolu |
| Moteur « zombie » après SIGTERM : API morte, conteneur « Up », aucune alerte | uvicorn attendait la fermeture du flux SSE du dashboard | `--timeout-graceful-shutdown 3` partout + chien de garde interne (3 échecs de `/health` → sortie → relance par Docker) |
| Features CPU/mémoire toujours à 0 | cAdvisor ne lit pas les conteneurs avec le stockage containerd de Docker Desktop | Lecture via l'API Docker (`/containers/<id>/stats`, proxy en lecture seule) ; cAdvisor (privileged) retiré |
| Une injection produit 2 ou 3 incidents ML de types différents (ex. `resource_exhaustion` puis `service_crash` ; `injection` en cascade après la révocation globale) | Les symptômes évoluent pendant l'incident et le ML ré-émettait après chaque délai de 30 s ; les effets de notre propre remédiation (rafale de 401) étaient vus comme une attaque | **Épisode d'anomalie** côté ML (un événement au début, type figé, relance seulement après 60 s de persistance) ; côté moteur, un événement ML est rattaché à tout incident ouvert ou résolu depuis moins de 45 s ; délai de grâce de 45 s après une maintenance |
| Stress CPU qualifié `service_crash`, redémarrage sauté (« aucune cible ») | Attribution : les features quasi constantes (IQR ≈ 0) écrasaient les autres ; aucun conteneur suspect transmis | Normalisation par la marge d'enveloppe ; le ML désigne le conteneur métier le plus consommateur de CPU |
| Le mode strict limitait aussi la sonde et le trafic de référence | Clé de limitation appliquée à toutes les IP | `geo $internal_client` : réseaux internes exemptés |
| Le moteur « répare » un redéploiement volontaire, ce qui fait échouer `docker compose up` | Conflit entre déploiement et auto-guérison | Fenêtre de maintenance `POST /admin/pause`, ouverte et fermée par `deploy.yml` |

## 8. Pièges connus

- **Images locales** : les services construits sur place portent `pull_policy: build`, sinon Compose tente de télécharger les images `resilience/*` depuis un registre où elles n'existent pas. `postgres-exporter` attend que PostgreSQL soit sain, et Grafana attend Prometheus et Loki.
- **Fins de ligne** : `.gitattributes` force LF ; un `02-roles.sh` en CRLF casse l'initialisation de PostgreSQL.
- **Réseaux `internal`** : Docker ne publie pas de port depuis un réseau interne ; d'où le réseau `admin` (sans NAT sortant) pour Prometheus, Grafana et le dashboard.
- **`docker kill`** désactive la politique de redémarrage du conteneur : c'est alors le moteur qui le relance. Un crash réel (sortie du processus) est relancé par Docker lui-même.
- **Volume `pgdata`** : les scripts d'initialisation ne s'exécutent qu'à la création. Après une modification du schéma, il faut `docker compose down -v` (cela efface les données).
