# 00 — Cahier des charges

Reformulation structurée du sujet (présentation `2627_PRESENTATION-WORKSHOP_Bac+5.pptx`). En cas de doute, **le sujet distribué fait foi**.

## 1. Contexte

Automne 2026. Une plateforme de paiement subit des incidents à répétition ; à chaque fois, les équipes la relancent **à la main**, avec des interventions lentes et non reproductibles. La *Direction Nationale de la Sûreté Numérique* lance **PROJECT RESILIENCE-ALPHA**.

**Mission :** prouver qu'un système critique peut **encaisser une attaque et se rétablir sans intervention humaine**.

## 2. Exigences fonctionnelles

| ID | Exigence | Source |
|----|----------|--------|
| F1 | Un SI de paiement fictif conteneurisé : **front, API, authentification, base de données** | Slide 3 |
| F2 | Le système de paiement est **codé par l'équipe** — aucune solution de paiement existante | Slide 4 |
| F3 | Une **attaque réelle** lancée depuis un **PC Attaquant distinct** du PC Hôte | Slide 3 |
| F4 | Une **détection par machine learning** — pas de simples seuils fixes | Slide 3 |
| F5 | Une **remédiation automatique** | Slide 3 |
| F6 | **Preuve** de reprise : une **nouvelle transaction réussit** après l'incident | Slide 3 |
| F7 | Un **dashboard** montrant l'état du service **avant, pendant et après** l'incident | Slide 7 |
| F8 | Un **assistant RAG local** (Ollama + LangChain, modèle ≤ 8 milliards de paramètres) | Slide 4 |

**Règle éliminatoire :** toute intervention humaine pendant la démo donne **0/5 sur l'axe remédiation**.

## 3. Exigences techniques par pilier

Les **5 piliers doivent être présents et réellement interconnectés** (pas cinq briques posées côte à côte).

| Pilier | Attendus | Notre réponse |
|--------|----------|---------------|
| **DEV** | Microservices (Node.js, Python/FastAPI ou Go), API REST ou gRPC, moteur de remédiation, dashboard React + Tailwind | [02-dev-microservices.md](02-dev-microservices.md), [06-remediation.md](06-remediation.md) |
| **INFRA** | Docker Compose, playbooks Ansible, observabilité Prometheus / Grafana / Loki | [03-infra.md](03-infra.md) |
| **IA / DATA** | Détection d'anomalies par ML, assistant RAG local (Ollama + LangChain, ≤ 8B) | [04-ia-data.md](04-ia-data.md) |
| **CYBER** | Attaque Red Team, WAF, SIEM, durcissement, gestion des secrets (Vault ou SOPS) | [05-cyber.md](05-cyber.md) |
| **TRANSFORMATION** | EBIOS RM, PCA/PRA, conformité NIS2/DORA, recommandations à la direction | [07-gouvernance.md](07-gouvernance.md) |

## 4. Contraintes du labo

| Poste | Rôle | Contraintes |
|-------|------|-------------|
| **PC Hôte** | Fait tourner toute la plateforme | Docker Desktop + WSL2, **16 Go RAM minimum** |
| **PC Attaquant** | Lance les attaques | Poste **physiquement distinct** |
| **PC IA** *(facultatif)* | Héberge **uniquement** le modèle de langage | — |
| **Réseau** | Point d'accès mobile Windows | SSID `RESILIENCE-G<n>` |

## 5. Livrables

Dossier `Workshop2026-M2-G<n>`, **remise avant jeudi 23 h 59** :

1. Dossier d'ingénierie et de gouvernance — PDF, 8 à 12 pages hors annexes
2. Support de présentation — PPTX
3. Clip Chrono — MP4, **60 secondes, sans coupe**
4. Archive du code source et du déploiement — ZIP, README inclus, **aucun secret en clair**
5. RESILIENCE-ALPHA fonctionnel, en démonstration live

## 6. Grilles d'évaluation

### Soutenance locale — 20 points

| Axe | Pts | Ce qui est vérifié |
|-----|-----|--------------------|
| 1. Démo live & remédiation autonome | 5 | Attaque depuis le PC Attaquant, détection et reprise **sans intervention**, nouvelle transaction réussie après l'incident |
| 2. Expertise technique & cohérence des 5 piliers | 4 | 5 piliers présents et interconnectés, **ML branché sur la remédiation**, **accès du moteur de remédiation maîtrisés** |
| 3. Clip Chrono & dashboard | 4 | 60 s en continu sans coupe, état du service visible avant/pendant/après |
| 4. Gouvernance, NIS2/DORA & pitch | 4 | EBIOS et PCA/PRA **reliés à l'architecture réelle**, recommandations argumentées, **5 min respectées** |
| 5. Dossier technique & Q&A | 3 | Dossier précis, **contribution de chacun visible**, maîtrise du code présenté (y compris généré par IA) |

### Finale nationale — 70 points

| Axe | Pts | Ce qui est vérifié |
|-----|-----|--------------------|
| Démonstration en direct | 25 | Attaque et reprise automatique en live **en 3 min**, depuis le PC Hôte |
| Clip Chrono | 15 | Séquence continue attaque → détection → reprise → vérification, **lisible à distance** |
| Pitch stratégique | 10 | Démarche claire **en 1 min**, introduction individuelle |
| Expertise technique & architecture | 10 | Chaîne cohérente de bout en bout, choix techniques justifiés |
| Gouvernance & conformité | 10 | Risques, PCA/PRA et NIS2/DORA reliés au démonstrateur |

## 7. Critères de succès que nous nous fixons

| Indicateur | Cible |
|------------|-------|
| Délai de détection (début d'attaque → alerte ML) | < 20 s |
| Délai de remédiation (alerte → action exécutée) | < 10 s |
| **RTO bout en bout** (début d'attaque → transaction témoin OK) | **< 60 s** |
| RPO base de données | < 5 min (0 en cas de simple redémarrage) |
| Interventions humaines pendant la démo | **0** |
| Faux positifs ML sur 30 min de trafic normal | 0 action déclenchée |
| Démarrage complet depuis zéro (`ansible-playbook deploy.yml`) | < 5 min |
