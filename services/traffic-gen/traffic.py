"""traffic-gen — trafic légitime réaliste pour la référence « normale » du ML et pour la démo.

N utilisateurs simulés : connexion (avec quelques fautes de frappe), consultation du solde
et de l'historique, virements entre eux. La charge varie (vagues lentes + pics aléatoires)
pour que le modèle n'apprenne pas un trafic artificiellement constant.
"""
import asyncio
import math
import os
import random
import time
import uuid

import httpx

BASE = os.getenv("TARGET", "https://waf:8443")
USERS = int(os.getenv("USERS", "20"))
BASE_RATE = float(os.getenv("BASE_RATE", "4"))     # actions/s en moyenne
TYPO_RATE = float(os.getenv("TYPO_RATE", "0.03"))  # part des connexions avec un mauvais mot de passe
CA = "/run/secrets/tls_cert"
PASSWORD = open("/run/secrets/traffic_password").read().strip()


def log(msg: str) -> None:
    print(f'{{"service": "traffic-gen", "event": "{msg}"}}', flush=True)


class User:
    def __init__(self, idx: int):
        self.email = f"user{idx:02d}@resilience.example.com"
        self.token = None
        self.iban = None
        self.token_at = 0.0

    async def login(self, c: httpx.AsyncClient) -> None:
        pw = PASSWORD if random.random() > TYPO_RATE else PASSWORD[:-1] + "x"
        r = await c.post("/api/auth/login", json={"email": self.email, "password": pw})
        if r.status_code == 200:
            self.token, self.token_at = r.json()["access_token"], time.time()
        elif pw != PASSWORD:
            await asyncio.sleep(random.uniform(1, 3))  # l'utilisateur corrige sa faute
            await self.login(c)

    def headers(self) -> dict:
        return {"Authorization": f"Bearer {self.token}"}


async def setup(c: httpx.AsyncClient) -> list[User]:
    users = [User(i) for i in range(1, USERS + 1)]
    for u in users:
        await c.post("/api/auth/register", json={"email": u.email, "password": PASSWORD})
        await u.login(c)
        if u.token:
            r = await c.get("/api/accounts/me", headers=u.headers())
            u.iban = r.json().get("iban") if r.status_code == 200 else None
    return [u for u in users if u.iban]


async def act(c: httpx.AsyncClient, users: list[User]) -> None:
    u = random.choice(users)
    if not u.token or time.time() - u.token_at > 480 or random.random() < 0.05:
        await u.login(c)
        return
    roll = random.random()
    if roll < 0.40:
        r = await c.get("/api/accounts/me", headers=u.headers())
    elif roll < 0.65:
        r = await c.get("/api/payments", params={"limit": 10}, headers=u.headers())
    else:
        dst = random.choice([x for x in users if x is not u])
        r = await c.post("/api/payments", headers={**u.headers(), "Idempotency-Key": uuid.uuid4().hex},
                         json={"to_account": dst.iban, "amount_cents": random.randint(100, 5000),
                               "label": random.choice(["Loyer", "Courses", "Remboursement", "Cadeau", "Restaurant"])})
    if r.status_code == 401:
        await u.login(c)


async def main() -> None:
    await asyncio.sleep(10)
    limits = httpx.Limits(max_connections=20)
    async with httpx.AsyncClient(base_url=BASE, verify=CA, timeout=10, limits=limits,
                                 headers={"User-Agent": "resilience-traffic/1.0"}) as c:
        users = []
        while len(users) < 2:
            try:
                users = await setup(c)
            except httpx.HTTPError as exc:
                log(f"setup en attente : {type(exc).__name__}")
                await asyncio.sleep(5)
        log(f"{len(users)} utilisateurs prêts")
        start = time.time()
        while True:
            t = time.time() - start
            # Vague lente (période 7 min) + petite vague (90 s) + pics occasionnels.
            rate = BASE_RATE * (1 + 0.4 * math.sin(2 * math.pi * t / 420) + 0.15 * math.sin(2 * math.pi * t / 90))
            if random.random() < 0.01:
                rate *= 2
            asyncio.create_task(_safe(act(c, users)))
            await asyncio.sleep(random.expovariate(max(rate, 0.5)))


async def _safe(coro) -> None:
    try:
        await coro
    except httpx.HTTPError:
        pass  # pendant un incident, le trafic légitime subit les erreurs comme un vrai client


if __name__ == "__main__":
    asyncio.run(main())
