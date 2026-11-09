"""Turn parsed auth events into alerts.

Step 1: group each source address's events into "bursts". A burst is a run
of activity from one address with no gap longer than ten minutes. Each burst
is one thing a human might look at.

Step 2: describe each burst with a few plain features (how many failures,
how many different user names were tried, whether a login finally succeeded,
where the address is, and so on).

Step 3: score each burst. Two scorers are provided:
- RuleScorer: a transparent baseline anyone can read.
- NetScorer: a small PyTorch classifier trained on labelled bursts.

The classes are: normal, brute_force, password_spray, account_compromise.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, asdict

from . import geo
from .parse import Event

CLASSES = ["normal", "brute_force", "password_spray", "account_compromise"]
GAP_SECONDS = 600


@dataclass
class Burst:
    ip: str
    country: str
    start_idx: int
    end_idx: int
    t_start: str
    t_end: str
    n_events: int
    n_fail: int
    n_accept: int
    n_invalid: int
    distinct_users: int
    success_after_fail: int
    max_fail_1min: int
    span_seconds: int
    external: int
    users: list[str]
    line_idxs: list[int]

    def features(self) -> list[float]:
        return [
            math.log1p(self.n_fail),
            math.log1p(self.n_accept),
            math.log1p(self.distinct_users),
            float(self.success_after_fail),
            math.log1p(self.max_fail_1min),
            math.log1p(self.span_seconds),
            float(self.external),
            float(self.n_fail) / max(1, self.n_events),
            math.log1p(self.n_invalid),
            math.log1p(self.n_fail / max(1, self.distinct_users)),
        ]


FEATURE_NAMES = ["log failures", "log successes", "log distinct users", "success after failures",
                 "log worst minute", "log span", "external address", "failure share",
                 "log invalid users", "log failures per user"]


def bursts_from_events(events: list[Event]) -> list[Burst]:
    by_ip: dict[str, list[Event]] = {}
    for ev in events:
        if ev.ip:
            by_ip.setdefault(ev.ip, []).append(ev)
    out = []
    for ip, evs in by_ip.items():
        evs.sort(key=lambda e: (e.t or _fallback(e)))
        group: list[Event] = []
        for ev in evs:
            if group and ev.t and group[-1].t and (ev.t - group[-1].t).total_seconds() > GAP_SECONDS:
                out.append(_make_burst(ip, group))
                group = []
            group.append(ev)
        if group:
            out.append(_make_burst(ip, group))
    out.sort(key=lambda b: b.start_idx)
    return out


def _fallback(ev: Event):
    import datetime as dt
    return dt.datetime.min


def _make_burst(ip: str, evs: list[Event]) -> Burst:
    fails = [e for e in evs if e.kind in ("fail",)]
    accepts = [e for e in evs if e.kind == "accept"]
    invalids = [e for e in evs if e.kind == "invalid"]
    users = sorted({e.user for e in evs if e.user})
    # did a success come after at least one failure in this burst?
    saf = 0
    seen_fail = False
    for e in evs:
        if e.kind == "fail":
            seen_fail = True
        if e.kind == "accept" and seen_fail:
            saf = 1
    # worst single minute of failures
    max1 = 0
    times = [e.t for e in fails if e.t]
    for i, t0 in enumerate(times):
        c = sum(1 for t in times if 0 <= (t - t0).total_seconds() < 60)
        max1 = max(max1, c)
    span = 0
    ts = [e.t for e in evs if e.t]
    if len(ts) >= 2:
        span = int((max(ts) - min(ts)).total_seconds())
    return Burst(
        ip=ip, country=geo.country(ip), start_idx=evs[0].idx, end_idx=evs[-1].idx,
        t_start=str(min(ts)) if ts else "", t_end=str(max(ts)) if ts else "",
        n_events=len(evs), n_fail=len(fails), n_accept=len(accepts), n_invalid=len(invalids),
        distinct_users=len(users), success_after_fail=saf, max_fail_1min=max1,
        span_seconds=span, external=0 if geo.is_internal(ip) else 1,
        users=users[:20], line_idxs=[e.idx for e in evs],
    )


class RuleScorer:
    """A readable baseline. No training."""

    def predict(self, b: Burst) -> str:
        if b.external and b.n_fail >= 20 and b.success_after_fail:
            return "account_compromise"
        if b.external and b.distinct_users >= 15 and b.n_fail >= 15:
            return "password_spray"
        if b.external and b.n_fail >= 20 and b.distinct_users <= 3:
            return "brute_force"
        return "normal"


def label_bursts(bursts: list[Burst], truth: dict) -> list[str]:
    """Attach the true class to each burst using the ground-truth line map."""
    line_label = {row["line"]: row["label"] for row in truth["events"]}
    labels = []
    for b in bursts:
        hits = [line_label[i] for i in b.line_idxs if i in line_label]
        if not hits:
            labels.append("normal")
        else:
            labels.append(max(set(hits), key=hits.count))
    return labels
