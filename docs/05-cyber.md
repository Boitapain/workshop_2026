# 05 — CYBER : menaces, WAF, SIEM, durcissement, secrets

> Cadre : toutes les actions Red Team visent **uniquement notre propre plateforme**, sur le réseau isolé `RESILIENCE-G<n>`. Les scripts de `attack/` refusent toute autre cible (`guard()` dans `attack/_common.py`).

Ce document décrit **ce qui est réellement en place** dans le dépôt. Les écarts avec la cible sont listés au §8.

## 1. Modèle de menace

| Actif | Menace | Prévention | Détection | Remédiation (playbook) |
|-------|--------|-----------|-----------|------------------------|
| Comptes clients | Bourrage d'identifiants | Rate-limit `login` (5 req/s), argon2id, verrouillage progressif | ML (ratio d'échecs de login) + SIEM `AuthFailureSurge` | `brute_force` : blocage de la source, révocation des sessions |
| API de paiement | Injection, exploitation applicative | WAF ModSecurity + CRS, liste blanche des routes, requêtes SQL paramétrées | ML (pic de 403) + SIEM `WafBlockSurge` | `injection` : blocage de la source |
| Disponibilité | Saturation HTTP | Rate-limit `api` (30 req/s), `client_max_body_size 64k`, `mem_limit` / `cpus` / `pids_limit` | ML (débit, latence) | `http_flood` : blocage + mode strict |
| Soldes et transactions | Altération des données | Rôles PostgreSQL à moindre privilège, journal des écritures | ML (invariant comptable `ledger_drift`) + SIEM `MassDataModification` | `data_tampering` : lecture seule, restauration, révocation globale |
| Composants | Panne, crash | `restart: unless-stopped`, healthchecks | Surveillance Docker + SIEM `BusinessTargetDown` / `PostgresDown` | `service_crash`, `db_outage` |
| Moteur de remédiation | Détournement pour saboter la plateforme | Proxy Docker à regex, liste de protection, budget d'actions | Journal d'audit | Escalade (`ESCALATED`) |

Chaque ligne correspond à un scénario opérationnel EBIOS ([07-gouvernance.md](07-gouvernance.md) §1, atelier 4).

## 2. Scénarios Red Team

Scripts lancés depuis le PC Attaquant (`attack/`, mode d'emploi dans [attack/README.md](../attack/README.md)).

| Script | Scénario EBIOS | Classe ML visée | Effet attendu |
|--------|----------------|-----------------|---------------|
| `brute_force.py` | SO1 — prise de contrôle de comptes | `brute_force` | Empreinte bloquée au WAF, sessions ciblées révoquées |
| `injection_probe.py` | SO2 — exploitation applicative | `injection` | Requêtes arrêtées par le CRS (403), puis source bloquée |
| `http_flood.py` | SO3 — saturation du service | `http_flood` | Source bloquée + mode strict |
| `run_campaign.py` | les trois à la suite | — | Une campagne étiquetée complète |

Chaque script utilise un User-Agent constant et distinct, horodate l'épisode dans `ml/data/labels.csv` (données d'entraînement du classifieur) et affiche le RTO mesuré par le moteur.

Les scénarios SO4 (altération des données) et SO5 (panne) sont rejoués par `chaos/chaos.py` ([08-demo-chaos.md](08-demo-chaos.md)).

## 3. WAF

Image `owasp/modsecurity-crs` (Nginx + ModSecurity v3 + OWASP CRS 4), configuration dans `infra/waf/default.conf.template`. C'est le **seul port exposé** au réseau du labo (443).

| Mesure | Réglage |
|--------|---------|
| Règles CRS | Paranoïa 1, seuil d'anomalie entrant 5, journal d'audit JSON |
| TLS | TLS 1.2/1.3 uniquement, suites ECDHE/AEAD, tickets de session désactivés |
| En-têtes | HSTS, CSP stricte, `X-Frame-Options DENY`, `nosniff`, `Referrer-Policy no-referrer`, version masquée |
| Surface d'API | Liste blanche explicite : `/api/auth/(login\|register\|refresh\|logout)`, `/api/accounts/me`, `/api/payments[/<uuid>]`. Tout autre chemin `/api/*` (dont `/internal`, `/metrics`) renvoie 404 |
| Rate-limit | `login` 5 req/s, `api` 30 req/s, réponse 429 |
| Blocage dynamique | Le moteur écrit dans `/etc/nginx/dynamic` puis envoie SIGHUP : deny-list IP (`*.deny`), empreinte IP + User-Agent (`*.fpdeny`), mode strict 3 req/s (`*.strict`) |
| Exemption interne | La sonde et le trafic de référence (`172.30.1.0/24`) ne sont jamais soumis au mode strict |

Blocage par empreinte : derrière Docker Desktop, le WAF voit la passerelle `172.30.0.1` au lieu de l'IP du client. Bloquer cette IP couperait tous les clients externes. Le moteur bloque alors le couple IP + User-Agent ([ADR-009](adr.md)).

## 4. SIEM

SIEM léger sur la pile d'observabilité imposée ([ADR-007](adr.md)) : règles → Alertmanager → webhook du moteur de remédiation. Le ML reste la source principale ; ces règles sont un **filet de sécurité**, y compris si le ml-detector tombe.

| Règle | Source | Condition | Type d'incident |
|-------|--------|-----------|-----------------|
| `ProbeTransactionFailing` | Prometheus | Transaction témoin en échec > 20 s | `service_outage` |
| `BusinessTargetDown` | Prometheus | auth ou payment injoignable > 15 s | `service_crash` |
| `PostgresDown` | Prometheus | `pg_up == 0` > 15 s | `db_outage` |
| `BackupFailing` | Prometheus | Sauvegardes en échec > 5 min | (alerte, PRA dégradé) |
| `AuthFailureSurge` | Loki | > 40 échecs de login / min | `brute_force` |
| `WafBlockSurge` | Loki | > 30 réponses 403 du WAF / min | `injection` |
| `MassDataModification` | Loki | `DELETE` / `TRUNCATE` / `DROP` hors superutilisateur | `data_tampering` |

Fichiers : `infra/observability/rules/siem.yml`, `infra/observability/loki-rules/fake/siem-logs.yml`. Les journaux de tous les conteneurs sont collectés par Alloy vers Loki ; le dashboard Grafana provisionné les affiche.

## 5. Durcissement

| Niveau | Mesure |
|--------|--------|
| Conteneurs | Ancre `x-hardening` sur tous les services : `read_only`, `cap_drop: ALL`, `no-new-privileges`, `tmpfs /tmp`, rotation des journaux. Services applicatifs en utilisateur non-root `10001`. PostgreSQL ne récupère que les capacités nécessaires |
| Ressources | `mem_limit` partout ; `cpus` et `pids_limit` sur les services métier (limite l'impact d'une saturation) |
| Réseaux | 7 réseaux segmentés. `app`, `data`, `monitoring`, `control` sont `internal` (pas d'accès Internet). `admin` sans NAT sortant |
| Exposition | Seul le WAF est publié (443). Dashboard, Grafana et Prometheus sur `127.0.0.1` uniquement |
| Base de données | Un rôle par service, au moindre privilège (`infra/postgres/02-roles.sh`). Journalisation des écritures **sans** les valeurs des paramètres |
| Socket Docker | Aucun service applicatif ne le monte. Accès via deux proxys à liste blanche (lecture seule / remédiation), voir §7 |
| Images | Versions épinglées par tag (pas de `latest`) |

## 6. Gestion des secrets

| Mesure | Détail |
|--------|--------|
| Génération | `scripts/init_secrets.py` : mots de passe aléatoires (module `secrets`), clé JWT RS256, certificat TLS auto-signé. Idempotent |
| Injection | **Docker secrets** montés dans `/run/secrets/*`, jamais en variable d'environnement (lus via les variantes `*_FILE`) |
| Dépôt | `secrets/*` ignoré par git ; seuls des fichiers `*.enc.yaml` chiffrés **SOPS + age** peuvent être commités. La clé privée age reste hors du dépôt |
| Cloisonnement | Chaque service ne reçoit que ses propres secrets (ex. le moteur de remédiation n'a que le jeton interne : ni mot de passe de base, ni clé JWT) |

Le sujet demande « Vault **ou** SOPS » : SOPS est en place. Vault (secrets dynamiques, rotation) reste une évolution ([ADR-006](adr.md)).

## 7. Accès du moteur de remédiation

Critère explicite de la grille (axe 2). Détail dans [06-remediation.md §5](06-remediation.md#5-maîtrise-des-accès-du-moteur). En résumé : proxy `wollomatic/socket-proxy` qui n'autorise que `GET /containers/json` et `POST /containers/<id>/(restart|kill)`, uniquement depuis `remediation-engine` ; cibles limitées au label `resilience.remediable=true` ; liste `protected` ; budget global d'actions.

## 8. Écarts et évolutions

| Cible | État | Prochaine étape |
|-------|------|-----------------|
| Vault | Non implémenté (SOPS + Docker secrets) | Vault en mode serveur, identifiants BDD dynamiques |
| Scan d'images (Trivy) | Non automatisé | `trivy image` sur chaque image avant la démo, résultats en annexe du dossier |
| Images épinglées par digest | Épinglées par tag | Passer aux digests `@sha256:` |
| Détection de secrets (gitleaks) | Non configurée | Hook pre-commit `gitleaks` + vérification du ZIP final |
| Pare-feu Windows du PC Hôte | À configurer sur place | N'autoriser que le 443 entrant depuis le hotspot |
| Scénarios Red Team réels | Écrits, à valider depuis le vrai PC Attaquant | Mesurer les RTO et vérifier l'IP vue par le WAF (ADR-009) |
