"""Cohérence de policy.yaml : à lancer avant chaque modification de la politique.

    docker compose -f infra/docker-compose.yml exec remediation-engine python /srv/tests/test_policy.py
"""
import sys
from pathlib import Path

import yaml

sys.path.insert(0, "/srv/app")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "app"))

POLICY = yaml.safe_load((Path(__file__).resolve().parent.parent / "policy.yaml").read_text(encoding="utf-8"))
ACTIONS = {"block_source", "rate_limit_strict", "revoke_sessions", "maintenance_mode", "restart_container", "restore_db"}
ML_TYPES = {"brute_force", "injection", "http_flood", "data_tampering", "service_crash", "db_outage", "resource_exhaustion"}


def test_actions_exist():
    for name, pb in POLICY["playbooks"].items():
        for step in pb["steps"]:
            assert step["action"] in ACTIONS, f"{name} : action inconnue {step['action']}"


def test_escalations_exist_and_terminate():
    pbs = POLICY["playbooks"]
    for name in pbs:
        seen, cur = set(), name
        while cur:
            assert cur in pbs, f"escalade vers un playbook inexistant : {cur}"
            assert cur not in seen, f"boucle d'escalade depuis {name}"
            seen.add(cur)
            cur = pbs[cur].get("escalate_to")


def test_every_ml_type_has_a_playbook():
    missing = ML_TYPES - set(POLICY["playbooks"])
    assert not missing, f"types ML sans playbook : {missing}"


def test_maintenance_is_always_switched_off():
    for name, pb in POLICY["playbooks"].items():
        steps = [s for s in pb["steps"] if s["action"] == "maintenance_mode"]
        assert all(set(s) == {"action", "enabled"} for s in steps), f"{name} : paramètre attendu « enabled »"
        states = [s["enabled"] for s in steps]
        if states:
            assert states[-1] is False, f"{name} laisse le service en lecture seule"


def test_probe_and_internal_networks_are_protected():
    import ipaddress
    nets = [ipaddress.ip_network(n) for n in POLICY["protected"]["ips"]]
    for ip in ("172.30.1.50", "172.30.4.10"):  # sonde, moteur
        assert any(ipaddress.ip_address(ip) in n for n in nets), f"{ip} non protégée"
    assert "resilience-probe/1.0" in POLICY["protected"]["user_agents"]


if __name__ == "__main__":
    tests = [v for k, v in dict(globals()).items() if k.startswith("test_")]
    for t in tests:
        t()
        print(f"OK  {t.__name__}")
    print(f"{len(tests)} tests passés")
