# Poste attaquant — mode d'emploi (collègue)

Tu es sur le **même réseau** que le PC défenseur : connecte-toi au partage de connexion Windows
**SSID `RESILIENCE-G<n>`**. Ton poste reçoit une IP `192.168.137.x`, le PC défenseur est `192.168.137.1`.

## 1. Vérifier l'accès à la plateforme

```bash
curl -k https://192.168.137.1/healthz
```
Doit répondre `OK`. Sinon : le pare-feu du défenseur n'est pas ouvert (voir côté défenseur).

## 2. Récupérer les scripts

Copie le dossier `attack/` (et rien d'autre) sur ton poste. Il te faut juste **Python 3**.

## 3. Lancer les attaques (cible = le PC défenseur)

```bash
python attack/brute_force.py     https://192.168.137.1
python attack/injection_probe.py https://192.168.137.1
python attack/http_flood.py      https://192.168.137.1
python attack/run_campaign.py    https://192.168.137.1     # les trois à la suite
```

Chaque script :
- n'attaque que la cible passée (un garde-fou refuse toute autre adresse) ;
- affiche les codes de réponse (403 = bloqué par le WAF, 429 = rate-limité, 401 = refusé) ;
- attend que le défenseur se répare et affiche le RTO.

## 4. Ce que tu dois observer sur le dashboard du défenseur

Sur le PC défenseur (http://127.0.0.1:8080) : le bandeau passe vert → orange (REMÉDIATION) → vert,
un incident apparaît dans la timeline avec ton IP/empreinte, et une transaction témoin repasse OK.

> Attaque **uniquement** la plateforme RESILIENCE-ALPHA de ton groupe. Rien d'autre sur le réseau.
