"""Simple, correct authentication for the dashboard API.

This covers the "basic privacy and authentication techniques" the role asks
for, done properly rather than with a plain-text password:

- Passwords are stored only as a salted PBKDF2-HMAC-SHA256 hash. The real
  password is never written down.
- Login checks the password in constant time (hmac.compare_digest), which
  avoids leaking the answer through timing.
- A successful login returns a signed token (HMAC-SHA256) that carries the
  user name and an expiry time. The server checks the signature and the
  expiry on every request, so no session store is needed.

The signing key comes from the AW_SECRET environment variable. The demo
falls back to a fixed key so it runs out of the box; in real use you set
AW_SECRET and it must be kept secret.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time

SECRET = os.environ.get("AW_SECRET", "dev-only-secret-change-me").encode()
PBKDF2_ROUNDS = 200_000


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ROUNDS)
    return f"pbkdf2_sha256${PBKDF2_ROUNDS}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, rounds, salt_b64, dk_b64 = stored.split("$")
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(dk_b64)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, int(rounds))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(dk, expected)


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def make_token(user: str, ttl_seconds: int = 3600) -> str:
    body = {"user": user, "exp": int(time.time()) + ttl_seconds}
    payload = _b64(json.dumps(body, separators=(",", ":")).encode())
    sig = _b64(hmac.new(SECRET, payload.encode(), hashlib.sha256).digest())
    return f"{payload}.{sig}"


def read_token(token: str) -> str | None:
    """Return the user name if the token is valid and not expired, else None."""
    try:
        payload, sig = token.split(".")
    except ValueError:
        return None
    good = _b64(hmac.new(SECRET, payload.encode(), hashlib.sha256).digest())
    if not hmac.compare_digest(sig, good):
        return None
    try:
        body = json.loads(_unb64(payload))
    except (ValueError, json.JSONDecodeError):
        return None
    if body.get("exp", 0) < int(time.time()):
        return None
    return body.get("user")


# a tiny demo user store (username -> password hash). Real use: a database.
def demo_users() -> dict[str, str]:
    return {"analyst": hash_password("alertwise")}
