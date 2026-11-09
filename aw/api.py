"""The dashboard API.

Endpoints:
  POST /login            -> exchange username/password for a token
  GET  /alerts           -> the current alerts (needs a token)
  GET  /alerts/{i}       -> one alert with both explanations (needs a token)
  GET  /healthz          -> liveness, no auth
  GET  /                 -> the dashboard page

The alerts are produced once at start-up from a log file (the demo log by
default, or AW_LOG if set) using the trained model when models/net.pt exists,
otherwise the readable rule baseline. Everything after login requires a valid
bearer token.
"""
from __future__ import annotations

import os
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

from . import auth
from .detect import RuleScorer
from .parse import parse_file
from .pipeline import run

ROOT = Path(__file__).resolve().parents[1]
app = FastAPI(title="AlertWise", version="0.1.0")
bearer = HTTPBearer(auto_error=False)
USERS = auth.demo_users()


def _scorer():
    net_path = ROOT / "models" / "net.pt"
    if net_path.exists():
        try:
            from .model import NetScorer
            return NetScorer.load(net_path), "model"
        except Exception:
            pass
    return RuleScorer(), "rule"


def load_alerts() -> dict:
    log = Path(os.environ.get("AW_LOG", ROOT / "data" / "sim" / "demo" / "auth.log"))
    scorer, which = _scorer()
    if not log.exists():
        return {"scorer": which, "log": str(log), "alerts": []}
    events = parse_file(log)
    return {"scorer": which, "log": str(log), "alerts": run(events, scorer)}


STATE = load_alerts()


class Login(BaseModel):
    username: str
    password: str


def require_user(creds: HTTPAuthorizationCredentials | None = Depends(bearer)) -> str:
    if creds is None:
        raise HTTPException(status_code=401, detail="missing token")
    user = auth.read_token(creds.credentials)
    if not user:
        raise HTTPException(status_code=401, detail="invalid or expired token")
    return user


@app.get("/healthz")
def healthz():
    return {"ok": True, "scorer": STATE["scorer"], "alerts": len(STATE["alerts"])}


@app.post("/login")
def login(body: Login):
    stored = USERS.get(body.username)
    if not stored or not auth.verify_password(body.password, stored):
        raise HTTPException(status_code=401, detail="wrong username or password")
    return {"token": auth.make_token(body.username), "user": body.username}


@app.get("/alerts")
def alerts(user: str = Depends(require_user)):
    brief = [{k: a[k] for k in ("kind", "severity", "title", "source_ip", "country",
                                "failed_attempts", "successful_logins", "different_usernames",
                                "span_minutes", "written_by")}
             for a in STATE["alerts"]]
    return {"count": len(brief), "scorer": STATE["scorer"], "alerts": brief}


@app.get("/alerts/{i}")
def alert(i: int, user: str = Depends(require_user)):
    if i < 0 or i >= len(STATE["alerts"]):
        raise HTTPException(status_code=404, detail="no such alert")
    return STATE["alerts"][i]


@app.get("/")
def index():
    page = ROOT / "web" / "index.html"
    if page.exists():
        return FileResponse(page)
    return JSONResponse({"detail": "dashboard page not found"}, status_code=404)
