import time

from fastapi.testclient import TestClient

from aw import auth
from aw.api import app

client = TestClient(app)


def test_password_hash_roundtrip():
    h = auth.hash_password("alertwise")
    assert auth.verify_password("alertwise", h)
    assert not auth.verify_password("wrong", h)
    assert "alertwise" not in h   # the real password is not stored


def test_token_roundtrip_and_tamper():
    t = auth.make_token("analyst", ttl_seconds=60)
    assert auth.read_token(t) == "analyst"
    assert auth.read_token(t[:-1] + ("x" if t[-1] != "x" else "y")) is None


def test_token_expiry():
    t = auth.make_token("analyst", ttl_seconds=-1)
    assert auth.read_token(t) is None


def test_alerts_requires_token():
    assert client.get("/alerts").status_code == 401


def test_login_and_fetch_alerts():
    r = client.post("/login", json={"username": "analyst", "password": "alertwise"})
    assert r.status_code == 200
    token = r.json()["token"]
    r2 = client.get("/alerts", headers={"Authorization": f"Bearer {token}"})
    assert r2.status_code == 200
    assert "alerts" in r2.json()


def test_login_rejects_bad_password():
    r = client.post("/login", json={"username": "analyst", "password": "nope"})
    assert r.status_code == 401
