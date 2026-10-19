# 05 — CYBER : menaces, WAF, SIEM, durcissement, secrets

> 🚧 **Document à rédiger par le binôme CYBER.** Plan attendu ci-dessous.

> Cadre : toutes les actions Red Team visent **uniquement notre propre plateforme**, sur le réseau isolé `RESILIENCE-G<n>`.

## 1. Modèle de menace
Actifs, menaces, contre-mesures préventives, signal de détection, playbook de remédiation associé (cf. [06-remediation.md](06-remediation.md)).

## 2. Scénarios Red Team
Liste des scénarios rejoués depuis le PC Attaquant, chacun relié à un scénario opérationnel EBIOS ([07-gouvernance.md](07-gouvernance.md)) et à une classe du modèle ML ([04-ia-data.md](04-ia-data.md)).

## 3. WAF
Nginx + ModSecurity v3 + OWASP CRS : niveau de paranoïa, rate-limit, deny-list dynamique pilotée par le moteur de remédiation, logs vers Loki.

## 4. SIEM
Règles de corrélation (Loki ruler / Prometheus → Alertmanager → moteur de remédiation), vue Grafana SIEM.

## 5. Durcissement
Conteneurs (non-root, `read_only`, `cap_drop`), réseaux internes, pare-feu Windows, scan d'images (Trivy).

## 6. Gestion des secrets
Vault (secrets dynamiques BDD, clé JWT) + SOPS/age pour les secrets du dépôt — **aucun secret en clair dans le ZIP**.

## 7. Accès du moteur de remédiation
Voir [06-remediation.md §5](06-remediation.md#5-maîtrise-des-accès-du-moteur).
