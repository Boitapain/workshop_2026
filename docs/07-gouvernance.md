# 07 — TRANSFORMATION : EBIOS RM, PCA/PRA, NIS2/DORA, recommandations

La grille insiste : risques, PCA/PRA et NIS2/DORA doivent être **reliés à l'architecture réelle** du démonstrateur. Chaque élément ci-dessous renvoie donc à un composant, une métrique ou un playbook existant.

## 1. Analyse de risques EBIOS RM

### Atelier 1 — Socle de sécurité

| Valeur métier | Description | Biens supports (conteneurs) | Besoins D / I / C / T |
|---------------|-------------|-----------------------------|-----------------------|
| VM1 — Exécuter un paiement | Virement entre comptes | waf, front, auth-service, payment-service, postgres | D ++, I +++, C ++, T +++ |
| VM2 — Authentifier les clients | Connexion, sessions | auth-service, postgres, vault | D ++, I ++, C +++, T ++ |
| VM3 — Conserver l'historique | Soldes et transactions | postgres, pg-backup | D +, I +++, C ++, T +++ |
| VM4 — Superviser et rétablir | Détection et remédiation | prometheus, loki, ml-detector, remediation-engine | D +++, I +++ |

*(D = disponibilité, I = intégrité, C = confidentialité, T = traçabilité)*

Événements redoutés :

| ER | Description | Gravité |
|----|-------------|---------|
| ER1 | Service de paiement indisponible plus de 5 min | 3 — Grave |
| ER2 | Transactions ou soldes altérés | 4 — Critique |
| ER3 | Usurpation de comptes clients | 3 — Grave |
| ER4 | Fuite des données clients | 3 — Grave |
| ER5 | Perte de la capacité de détection et de reprise | 3 — Grave |

Socle : référentiel ANSSI (guide d'hygiène), exigences DORA (chapitre II), mesures de l'article 21 de NIS2.

### Atelier 2 — Sources de risque

| SR / OV | Motivation | Pertinence |
|---------|-----------|-----------|
| Cybercriminel / gain financier (fraude, rançon) | Forte | Retenu |
| Hacktiviste / atteinte à l'image (indisponibilité) | Moyenne | Retenu |
| Initié malveillant / sabotage | Moyenne | Retenu (justifie le moindre privilège du moteur) |
| Défaillance non intentionnelle (panne, bug) | — | Retenu (chaos engineering) |

### Atelier 3 — Scénarios stratégiques
Par exemple : « Un cybercriminel prend le contrôle de comptes clients pour émettre des virements frauduleux » → ER3, ER2. Ou : « Un hacktiviste rend le service indisponible » → ER1.

### Atelier 4 — Scénarios opérationnels ↔ démonstrateur

| SO | Lien avec | Détection | Playbook | Vraisemblance avant → après |
|----|-----------|-----------|----------|-----------------------------|
| SO1 — Prise de contrôle de comptes | ER3 | ML `brute_force` | `brute_force` | V3 → V1 |
| SO2 — Exploitation applicative de l'API | ER2, ER4 | ML `injection` + WAF | `injection` | V2 → V1 |
| SO3 — Saturation du service | ER1 | ML `http_flood` | `http_flood` | V3 → V2 |
| SO4 — Altération des données | ER2 | ML `data_tampering` | `data_tampering` (restauration) | V2 → V1 |
| SO5 — Panne d'un composant | ER1, ER5 | ML `service_crash` / `db_outage` | `service_crash`, `db_outage` | V3 → V1 |

### Atelier 5 — Traitement du risque
Une matrice gravité × vraisemblance avant/après, un plan de traitement (mesures préventives, de détection, de remédiation) et les **risques résiduels** assumés. Par exemple : poste hôte unique = point unique de défaillance physique, accepté pour le démonstrateur et traité dans les recommandations.

## 2. PCA / PRA

### Objectifs

| Service | RTO | RPO | Mécanisme | Mesure dans le démonstrateur |
|---------|-----|-----|-----------|------------------------------|
| Paiement (VM1) | **60 s** | 0 (si pas d'altération) | remédiation auto + restart | `incident_rto_seconds` |
| Authentification (VM2) | 60 s | 0 | restart, rotation des secrets | `incident_rto_seconds` |
| Données (VM3) | 2 min | **≤ 2 min** | dumps toutes les 2 min + `restore_db` | horodatage du dump restauré |
| Supervision (VM4) | 30 s | — | `restart: unless-stopped` | `up{job=...}` |

### PCA — continuité (le service reste rendu, éventuellement dégradé)
- Mode **lecture seule** (`maintenance_mode`) : on consulte son solde pendant une restauration.
- Rate-limit strict : le service reste disponible pour les clients légitimes pendant un flood.
- Redémarrage automatique des conteneurs.

### PRA — reprise
1. Détection → incident → isolation de la source.
2. Restauration du dernier dump **sain** (`latest_good`).
3. Rotation des secrets si une compromission est suspectée.
4. Vérification par transaction témoin.
5. Retour en mode nominal et rapport d'incident.

Chaque étape correspond à une action automatisée ([06-remediation.md](06-remediation.md)). Les tests de chaos du jeudi ([08-demo-chaos.md](08-demo-chaos.md)) **sont** les exercices de PRA : leurs RTO mesurés vont dans le dossier.

## 3. Conformité NIS2 / DORA

### Applicabilité
- Une plateforme de paiement relève du secteur financier. **DORA** (règlement UE 2022/2554, applicable depuis le 17 janvier 2025) s'applique aux entités financières. Il fait office de *lex specialis* par rapport à **NIS2** (directive UE 2022/2555) pour la gestion des risques TIC et la notification d'incidents.
- NIS2 reste pertinente pour le cadre général, la supervision nationale (ANSSI en France) et les prestataires. *État de la transposition française à vérifier au moment de la rédaction.*

### Matrice exigences ↔ démonstrateur

| Exigence | Texte | Réponse du démonstrateur |
|----------|-------|--------------------------|
| Cadre de gestion du risque TIC | DORA art. 5-6 | Analyse EBIOS RM, politique de remédiation versionnée |
| Identification des actifs | DORA art. 8 | Inventaire des conteneurs ([01-architecture.md](01-architecture.md)) |
| Protection et prévention | DORA art. 9 · NIS2 art. 21 | WAF, segmentation, durcissement, Vault, moindre privilège |
| Détection des anomalies | DORA art. 10 | ML + SIEM, supervision continue |
| Réponse et rétablissement | DORA art. 11-12 | Remédiation auto, sauvegardes, restauration testée, RTO/RPO mesurés |
| Apprentissage | DORA art. 13 | Incidents archivés, RAG pour le retour d'expérience |
| Gestion et classification des incidents | DORA art. 17-18 | États d'incident, journal d'audit horodaté |
| Notification des incidents majeurs | DORA art. 19 · NIS2 art. 23 | Le RAG produit un **brouillon** de rapport (notification initiale, intermédiaire, finale) à partir du journal d'audit |
| Tests de résilience | DORA art. 24-25 | Chaos engineering, rejeu des scénarios EBIOS |
| Risque lié aux tiers TIC | DORA art. 28 | Images Docker épinglées par digest et scannées ; LLM local (aucune donnée envoyée à un tiers) |
| Gouvernance / responsabilité de la direction | DORA art. 5 · NIS2 art. 20 | Recommandations à la direction (§4) |

Délais de notification à rappeler dans le dossier (à vérifier dans les textes et les normes techniques) : NIS2 → alerte précoce sous 24 h, notification sous 72 h, rapport final sous 1 mois. DORA → notification initiale rapide après classification de l'incident comme majeur, puis rapports intermédiaire et final.

## 4. Recommandations à la direction

Format conseillé : 5 recommandations, chacune avec *constat → recommandation → coût indicatif → gain en risque*.

1. **Généraliser l'auto-remédiation** aux services critiques, avec une politique déclarative revue en comité des risques.
2. **Supprimer le point unique de défaillance** : au moins deux hôtes, une BDD répliquée, un PRA multi-site.
3. **Industrialiser les tests de résilience** : chaos engineering mensuel, conforme aux tests exigés par DORA.
4. **Gouvernance de l'IA** : modèles versionnés, carte de modèle, revue des faux positifs ; le LLM reste hors du chemin de décision.
5. **Processus de notification** : modèles de rapport DORA/NIS2 pré-remplis par l'outillage, astreinte définie pour les cas `ESCALATED`.
