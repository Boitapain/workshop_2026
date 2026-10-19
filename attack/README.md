# attack/ — scripts de test de résilience (Red Team)

> Scripts pour **tester ta propre plateforme RESILIENCE-ALPHA**, sur le labo local/isolé.
> En conditions de workshop, ils se lancent depuis le **PC Attaquant** contre `https://192.168.137.1`.
> Chaque script a un garde-fou : il **refuse toute cible autre que le labo local**.

## Scripts

| Script | Scénario EBIOS | Type d'incident visé | Ce qui doit se passer |
|--------|----------------|----------------------|------------------------|
| `brute_force.py` | SO1 | `brute_force` | Le ML voit le pic d'échecs de login → le WAF bloque l'empreinte, les sessions ciblées sont révoquées |
| `http_flood.py` | SO3 | `http_flood` | Le ML voit le pic de débit/latence → blocage + rate-limit strict |
| `injection_probe.py` | SO2 | `injection` | Le WAF (ModSecurity/CRS) renvoie 403 → le ML voit le pic de 403 → blocage de la source |

## Lancer

```bash
python attack/brute_force.py                 # cible localhost par défaut
python attack/http_flood.py --seconds 60
python attack/injection_probe.py
python attack/run_campaign.py                # les trois à la suite, avec pauses
```

Chaque script :
1. attaque pendant `--seconds` (40 par défaut) ;
2. horodate l'épisode dans `ml/data/labels.csv` (pour entraîner le classifieur du ml-detector) ;
3. attend la clôture de l'incident par le moteur et affiche le RTO + les actions.

## Préparer la démo

Avant un run « propre », remettre à zéro les blocages :

```bash
docker compose -f infra/docker-compose.yml exec remediation-engine python -c "import httpx;t=open('/run/secrets/internal_token').read().strip();print(httpx.post('http://localhost:8000/admin/reset',headers={'Authorization':'Bearer '+t}).text)"
```

## Note sur l'IP source (labo mono-PC)

Sur un seul PC (tout en Docker), le WAF voit l'IP de la passerelle Docker, pas celle de l'attaquant.
Le moteur bloque alors par **empreinte IP + User-Agent** : chaque script utilise un User-Agent
constant et distinct, pour que le blocage soit ciblé et n'affecte pas le trafic légitime.
Depuis le vrai PC Attaquant (réseau du hotspot), l'IP réelle peut être visible — voir ADR-009.
