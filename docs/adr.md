# Décisions d'architecture (ADR)

Format court : contexte → décision → alternatives écartées → conséquences. Statuts : *Proposé*, *Accepté*, *Remplacé*.

---

### ADR-001 — Python/FastAPI pour tous les services backend
- **Statut** : Proposé
- **Contexte** : le sujet autorise Node.js, Python/FastAPI ou Go. Le pilier IA est en Python.
- **Décision** : FastAPI pour auth, payment, remediation-engine, probe et ml-detector.
- **Alternatives** : Node.js (écosystème front partagé) ; Go (performances, binaires légers).
- **Conséquences** : un seul langage côté backend, des bibliothèques communes (logs, métriques, client Vault), OpenAPI gratuite. Performances suffisantes pour la charge de démo.

### ADR-002 — REST plutôt que gRPC
- **Statut** : Proposé
- **Décision** : REST/JSON partout.
- **Raison** : le WAF (CRS) inspecte nativement le HTTP/JSON ; les logs sont lisibles ; le débogage est plus simple en une semaine.
- **Conséquences** : un peu moins performant, sans impact à notre échelle.

### ADR-003 — Détection en deux étages (Isolation Forest + Random Forest)
- **Statut** : Proposé
- **Décision** : détection non supervisée de l'anomalie, puis classification supervisée du type pour choisir le playbook.
- **Alternatives** : seuils fixes (interdits par le sujet) ; auto-encodeur LSTM (plus long à mettre au point) ; classifieur seul (ne voit pas l'inconnu).
- **Conséquences** : il faut un dataset étiqueté, produit automatiquement par le rejeu des scénarios.

### ADR-004 — Politique de remédiation déclarative et déterministe
- **Statut** : Proposé
- **Décision** : mapping type d'incident → playbook en YAML ; le ML qualifie, mais ne choisit pas librement l'action.
- **Alternatives** : laisser un LLM décider (non déterministe, vulnérable à l'injection de prompt via les logs) ; apprentissage par renforcement (trop risqué et trop long).
- **Conséquences** : auditable, testable, explicable au jury et aux régulateurs (DORA).

### ADR-005 — Proxy Docker à liste blanche pour le moteur de remédiation
- **Statut** : Accepté (implémenté)
- **Décision** : le moteur parle à Docker via `wollomatic/socket-proxy`, sur le réseau interne `control`, joignable uniquement depuis `remediation-engine`. Routes autorisées : `GET /containers/json`, `POST /containers/<id>/restart` et `POST /containers/<id>/kill` (pour le SIGHUP de rechargement du WAF). Rien d'autre. Un second proxy en lecture seule sert Alloy.
- **Alternatives** : monter `/var/run/docker.sock` (équivaut à root sur l'hôte) ; `tecnativa/docker-socket-proxy`, écarté car `POST=1` autorise aussi `containers/create` ; tout faire via Ansible (plus lent pour un simple restart).
- **Conséquences** : répond directement au critère « accès du moteur de remédiation maîtrisés ».

### ADR-006 — Vault pour les secrets d'exécution, SOPS + age pour les secrets du dépôt
- **Statut** : Partiellement implémenté. Les secrets sont générés localement (`scripts/init_secrets.py`) et injectés en *Docker secrets* (fichiers `/run/secrets/*`, jamais en variable d'environnement) ; SOPS + age sert au partage dans l'équipe. **Vault reste à intégrer.**
- **Décision** : Vault (mode serveur, stockage fichier) pour les identifiants BDD dynamiques et la clé JWT ; les clés de descellement et les secrets d'amorçage sont stockés chiffrés avec SOPS + age dans le dépôt et déchiffrés par Ansible au déploiement.
- **Alternatives** : SOPS seul (pas de rotation dynamique) ; Vault en mode `dev` (non sécurisé, à proscrire).
- **Conséquences** : rotation des secrets possible comme action de remédiation ; « aucun secret en clair » dans le ZIP. La clé privée age reste hors du dépôt.

### ADR-007 — SIEM léger basé sur Loki + Alertmanager
- **Statut** : Accepté (implémenté)
- **Décision** : les règles de corrélation de sécurité s'exécutent dans le ruler Loki et dans Prometheus, sont routées par Alertmanager et visualisées dans une vue Grafana « SIEM ».
- **Alternatives** : Wazuh (SIEM complet, mais ~4 Go de RAM en plus sur un hôte de 16 Go) ; Elastic Security (encore plus lourd).
- **Conséquences** : tient dans le budget RAM et réutilise la pile d'observabilité imposée. Si la RAM le permet (PC IA disponible), Wazuh peut être ajouté en option.

### ADR-008 — LLM hors du chemin critique
- **Statut** : Proposé
- **Décision** : le RAG explique et rédige ; il n'a aucun droit d'action.
- **Conséquences** : la reprise ne dépend ni de la latence ni de la disponibilité du LLM, et une injection de prompt ne peut rien déclencher.

### ADR-009 — Préservation de l'IP source derrière Docker Desktop
- **Statut** : Accepté (option b implémentée), **à revérifier depuis le vrai PC Attaquant**
- **Contexte** : Docker Desktop (WSL2) peut masquer l'IP réelle du client derrière une IP de passerelle ; dans ce cas, `block_source` par IP est inopérant.
- **Options** : (a) Docker Engine dans WSL2 avec le réseau `mirrored` ; (b) remédiation par empreinte (compte, jeton, motif de requête) + rate-limit global ; (c) reverse proxy natif Windows en frontal.
- **Constat** (19/10, depuis le PC Hôte) : le WAF voit `172.30.0.1`, la passerelle du réseau `edge`, et non l'IP du client.
- **Décision** : le moteur ne bloque **jamais** une IP de passerelle NAT (`protected.nat_gateways` dans `policy.yaml`). Pour une telle source, il bloque l'**empreinte IP + User-Agent** (`map` Nginx `*.fpdeny`), ce qui épargne les autres clients. Il active aussi le mode de limitation stricte si besoin. Si le test depuis le PC Attaquant montre la vraie IP, le blocage par IP s'applique automatiquement.
- **Limite assumée** : un attaquant qui change de User-Agent à chaque requête contourne l'empreinte ; le mode strict (rate-limit) reste alors le filet. Option (a), le réseau WSL `mirrored`, à tester pour la finale.

### ADR-010 — Grafana Alloy plutôt que Promtail
- **Statut** : Proposé
- **Raison** : Promtail est en fin de vie ; Alloy est son successeur officiel et pousse vers Loki.

### ADR-011 — Référence ML apprise automatiquement sur périodes saines
- **Statut** : Accepté (implémenté)
- **Décision** : au premier démarrage, le ml-detector collecte 120 fenêtres (10 min) de trafic produit par `traffic-gen`, en ignorant les fenêtres où la sonde échoue ou un service est arrêté. Il entraîne ensuite IsolationForest + RobustScaler et calibre le seuil au-dessus du pire score observé (+3 %), pour viser 0 faux positif.
- **Conséquences** : déploiement autonome, sans jeu de données préalable. La qualité dépend du réalisme de `traffic-gen`. Le classifieur supervisé (`train.py`) s'ajoute quand des campagnes étiquetées existent.

### ADR-012 — Vérification de la reprise par transaction témoin réelle
- **Statut** : Accepté (implémenté)
- **Décision** : un incident n'est `RESOLVED` que si `synthetic-probe` réussit un login + virement + relecture **à travers le WAF**, démarré **après** la dernière action. Le RTO est mesuré du début de la fenêtre anormale jusqu'à cette transaction.
- **Conséquences** : la preuve demandée par le sujet est produite et horodatée automatiquement. La sonde et le générateur de trafic sont protégés contre le blocage (réseau interne + User-Agent).
