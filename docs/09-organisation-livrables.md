# 09 — Organisation, planning, livrables

## 1. Rôles (à adapter à la taille du consortium)

| Rôle | Pilier | Responsabilités | Membre(s) |
|------|--------|-----------------|-----------|
| Lead technique / architecte | transverse | Architecture, intégration, revue de code, ADR | |
| DEV backend | DEV | auth-service, payment-service, remediation-engine, probe | |
| DEV front | DEV | Front client, dashboard ops | |
| INFRA / SRE | INFRA | Compose, Ansible, observabilité, sauvegardes, réseau du labo | |
| IA / DATA | IA/DATA | Dataset, modèles, ml-detector, RAG | |
| CYBER | CYBER | Red Team, WAF, SIEM, durcissement, Vault | |
| Gouvernance | TRANSFORMATION | EBIOS RM, PCA/PRA, NIS2/DORA, recommandations, dossier PDF | |
| Pitch & clip | transverse | Support PPTX, Clip Chrono, répétitions | |

La grille note la **contribution individuelle visible** : chacun commite sous son nom, et le dossier contient un tableau « qui a fait quoi ». Chacun doit pouvoir **expliquer le code qu'il présente**, y compris le code généré par IA.

## 2. Planning

| Jour | Jalons | Point de contrôle |
|------|--------|-------------------|
| **Lundi** | Constitution du consortium, installation des postes et du réseau. Architecture + EBIOS (ateliers 1-2) **validées par les coachs** | Test de l'IP source vue par le WAF (ADR-009) ; ce dépôt et les ADR créés |
| **Mardi** | Docker Compose + Ansible + premiers microservices. Modèle ML (dataset normal), scripts Red Team, dossier NIS2/DORA | Paiement de bout en bout via le WAF ; Prometheus/Loki collectent |
| **Mercredi** | Intégration WAF/SIEM, branchement de la détection. Remédiation + dashboard + premiers tests de reprise | 1re boucle complète attaque → ML → remédiation → sonde |
| **Jeudi** | Chaos engineering et recette. Tournage du Clip Chrono, **gel du code à 17 h**, rendus **avant 23 h 59** | Tous les scénarios passent 3 fois de suite |
| **Vendredi** | Soutenance locale | — |

Règles du campus : émargement, présence obligatoire aux soutenances et à la finale nationale, salle rangée et propre.

## 3. Organisation du travail

- Branches courtes + pull requests relues par une autre personne.
- Pas de secret dans git : hook pre-commit `gitleaks`.
- Point d'équipe de 10 min matin et soir ; tableau Kanban (GitHub Projects).
- Une **intégration de bout en bout chaque soir** sur le PC Hôte.

## 4. Checklist de rendu — `Workshop2026-M2-G<n>`

- [ ] **Dossier d'ingénierie et de gouvernance** (PDF, 8 à 12 pages hors annexes)
  - [ ] Architecture (schémas de [01-architecture.md](01-architecture.md))
  - [ ] Choix techniques justifiés ([adr.md](adr.md))
  - [ ] Détection ML : features, modèles, métriques, délai de détection
  - [ ] Remédiation : politique, garde-fous, maîtrise des accès
  - [ ] EBIOS RM relié aux composants ; PCA/PRA avec RTO/RPO **mesurés**
  - [ ] Matrice NIS2/DORA ; recommandations à la direction
  - [ ] Tableau des contributions individuelles
- [ ] **Support de présentation** (PPTX) — pitch de 5 min en local, 1 min en finale
- [ ] **Clip Chrono** (MP4, 60 s, sans coupe)
- [ ] **Archive ZIP** du code + déploiement, README inclus, **aucun secret en clair** (vérifié avec `gitleaks`)
- [ ] **Démo live** répétée au moins 3 fois

## 5. Grille → preuves

| Critère | Preuve à montrer | Où |
|---------|------------------|-----|
| Attaque depuis le PC Attaquant | Script lancé en direct | démo |
| Détection et reprise sans intervention | Timeline du dashboard + journal d'audit | démo, clip |
| Nouvelle transaction réussie | `transaction_id` témoin + transaction manuelle | démo, clip |
| 5 piliers interconnectés | Tableau §7 de [01-architecture.md](01-architecture.md) | dossier, pitch |
| ML branché sur la remédiation | `POST /events` → incident (log en direct) | démo, dossier |
| Accès du moteur maîtrisés | §5 de [06-remediation.md](06-remediation.md) | dossier, Q&A |
| État avant/pendant/après | Bandeau vert → orange → vert | clip |
| EBIOS et PCA/PRA reliés à l'architecture | Tableau SO ↔ playbook | dossier, pitch |
| Choix techniques justifiés | ADR | dossier, Q&A |
