# attack/ — kit d'attaque Red Team (portable)

> Scripts pour **tester ta propre plateforme RESILIENCE-ALPHA**, sur le labo local/isolé.
> Kit **autonome** : aucune dépendance vers le reste du projet, **stdlib Python 3.10+ uniquement**.
> Il se copie tel quel sur le **PC Attaquant** et se lance contre le labo via le **port 443**.
> Chaque script a un garde-fou : il **refuse toute cible autre que le labo**.

## Lancer depuis un autre PC du réseau

1. Branche le PC Attaquant sur le même réseau que le labo (hotspot `192.168.137.0/24`,
   voir [../docs/03-infra.md](../docs/03-infra.md)). Le labo écoute en **443** ; c'est le seul port ouvert vers le LAN.
2. Copie **uniquement** le dossier `attack/` sur le PC Attaquant (clé USB, `scp`, clone partiel…).
   Rien à installer : Python 3.10+ suffit (`requirements.txt` ne liste aucune dépendance).
3. Lance un scénario (la cible par défaut est déjà `https://192.168.137.1`) :

```bash
python brute_force.py                      # cible https://192.168.137.1 par défaut
python http_flood.py --seconds 60
python injection_probe.py
python run_campaign.py                     # les trois à la suite, avec pauses
```

Pour viser une autre IP (ex. labo sur une autre machine) : passe-la en argument, ou fixe-la une fois :

```bash
python brute_force.py https://192.168.137.1
RESILIENCE_TARGET=https://10.0.0.5 RESILIENCE_LAB_HOST=10.0.0.5 python run_campaign.py
```

## Scripts

| Script | Scénario EBIOS | Type d'incident visé | Ce qui doit se passer |
|--------|----------------|----------------------|------------------------|
| `brute_force.py` | SO1 | `brute_force` | Le ML voit le pic d'échecs de login → le WAF bloque l'empreinte, les sessions ciblées sont révoquées |
| `http_flood.py` | SO3 | `http_flood` | Le ML voit le pic de débit/latence → blocage + rate-limit strict |
| `injection_probe.py` | SO2 | `injection` | Le WAF (ModSecurity/CRS) renvoie 403 → le ML voit le pic de 403 → blocage de la source |

Chaque script :
1. attaque pendant `--seconds` (40 par défaut) ;
2. horodate l'épisode dans `attack/data/labels.csv` (voir « Labels » plus bas) ;
3. affiche le retour d'incident **si le dashboard ops est joignable**, sinon bascule en mode aveugle.

## Mode « aveugle » (depuis le PC Attaquant)

Le dashboard ops (`8080`) n'est publié que sur `127.0.0.1` côté labo, et le pare-feu n'ouvre
que le **443** vers le LAN. Depuis l'attaquant il n'est donc **pas joignable** : les scripts
lancent l'attaque mais **n'attendent pas** le retour d'incident. Le **RTO et les actions de
remédiation se regardent sur l'écran défenseur** (dashboard ops + Grafana, côté labo).

- Depuis le **labo lui-même** (cible `localhost`), le retour live reste affiché comme avant.
- Si tu as exposé le 8080 au LAN, force la base : `RESILIENCE_DASHBOARD=http://192.168.137.1:8080`.

## Labels (pour (ré)entraîner le ml-detector)

Les épisodes sont horodatés dans `attack/data/labels.csv` (local au kit, jamais commité).
Pour alimenter l'entraînement du `ml-detector`, recopie-les dans `ml/data/labels.csv` **sur l'hôte** :

```bash
# sur le PC labo : fusionne les labels du kit dans ceux du projet
cat attack/data/labels.csv >> ml/data/labels.csv   # dé-doublonne l'en-tête si besoin
docker cp ml/data/labels.csv resilience-ml-detector-1:/data/labels.csv
```

Si tu lances le kit directement sur l'hôte et veux écrire dans le projet :
`RESILIENCE_LABELS=../ml/data/labels.csv python brute_force.py`.

## Variables d'environnement

| Variable | Rôle | Défaut |
|----------|------|--------|
| `RESILIENCE_TARGET` | cible par défaut | `https://192.168.137.1` |
| `RESILIENCE_LAB_HOST` | hôte labo autorisé par le garde-fou | `192.168.137.1` |
| `RESILIENCE_DASHBOARD` | base du dashboard ops (sort du mode aveugle) | auto (`http://127.0.0.1:8080` si cible locale) |
| `RESILIENCE_LABELS` | fichier de labels | `attack/data/labels.csv` |

## Préparer la démo

Avant un run « propre », remettre à zéro les blocages (**à exécuter sur le PC labo**) :

```bash
docker compose -f infra/docker-compose.yml exec remediation-engine python -c "import httpx;t=open('/run/secrets/internal_token').read().strip();print(httpx.post('http://localhost:8000/admin/reset',headers={'Authorization':'Bearer '+t}).text)"
```

## Note sur l'IP source

**Non vérifié depuis le vrai PC Attaquant.** Le seul test réalisé (depuis le PC Hôte, 19/10) montre
que le WAF voit la passerelle Docker `172.30.0.1`, pas l'IP du client. Il est probable que ce soit
aussi le cas depuis le hotspot avec Docker Desktop. Le moteur bloque alors par **empreinte IP + User-Agent**
(chaque script garde un User-Agent constant et distinct) et ne bloque jamais l'IP de la passerelle.
Si le test montre l'IP réelle du PC Attaquant, le blocage par IP s'applique automatiquement.

Test à faire avant la démo : lancer un script depuis le PC Attaquant, puis lire `remote_addr`
dans les journaux du WAF (Grafana → Loki, `{service="waf"}`). Consigner le résultat dans [ADR-009](../docs/adr.md).
