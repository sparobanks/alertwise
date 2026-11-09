"""Tie the parts together: raw log in, explained alerts out.

    events = parse_file(path)
    alerts = run(events, scorer, writer)

Each alert is a small dictionary ready for the API and dashboard: what it is,
how serious, where from, the key numbers, and the two written notes. Normal
bursts are not returned as alerts.
"""
from __future__ import annotations

from dataclasses import asdict

from .detect import Burst, bursts_from_events
from .explain import explain
from .parse import Event


def score_bursts(bursts: list[Burst], scorer):
    return [scorer.predict(b) for b in bursts]


def run(events: list[Event], scorer, writer=None, keep_normal: bool = False) -> list[dict]:
    bursts = bursts_from_events(events)
    alerts = []
    for b in bursts:
        kind = scorer.predict(b)
        if kind == "normal" and not keep_normal:
            continue
        ex = explain(b, kind, writer=writer)
        alerts.append({
            "kind": ex.kind,
            "severity": ex.severity,
            "title": ex.title,
            "source_ip": b.ip,
            "country": b.country,
            "external": bool(b.external),
            "failed_attempts": b.n_fail,
            "successful_logins": b.n_accept,
            "different_usernames": b.distinct_users,
            "span_minutes": max(1, round(b.span_seconds / 60)),
            "time_start": b.t_start,
            "time_end": b.t_end,
            "technical": ex.technical,
            "manager": ex.manager,
            "grounded": ex.grounded,
            "written_by": ex.source,
        })
    order = {"high": 0, "medium": 1, "none": 2}
    alerts.sort(key=lambda a: (order.get(a["severity"], 3), -a["failed_attempts"]))
    return alerts
