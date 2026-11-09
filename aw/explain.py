"""Explain an alert in plain English, for two kinds of reader.

The job asks for threat alerts that are communicated clearly to users at
different technical levels. This module turns a scored burst into:
- a technical note for IT staff (what, where, the numbers, what to do), and
- a short note for a non-technical manager (what it means, how urgent).

Two design choices matter for trust:

1. Grounding. The explanation is built only from a fixed "fact sheet" taken
   from the alert. Every number in the output must appear in those facts.
   check_grounded() verifies this, so an explanation cannot invent figures.
   This is the guard rail you need when a language model writes the text.

2. Privacy. The model-facing path works on redacted text (see redact.py).
   Real user names and addresses are put back only in the final note shown
   to staff inside the company.

A template writer is the default, so the whole pipeline runs offline and in
tests. An optional language-model writer can be plugged in behind the same
interface (see llm.py); its output is passed through the same grounding and
privacy checks, and the pipeline falls back to the template if a check fails.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .detect import Burst

SEVERITY = {"normal": "none", "brute_force": "medium",
            "password_spray": "medium", "account_compromise": "high"}
TITLE = {"brute_force": "Repeated failed logins against one account",
         "password_spray": "One password tried across many accounts",
         "account_compromise": "Account logged in after many failed attempts",
         "normal": "Normal activity"}


@dataclass
class Facts:
    kind: str
    severity: str
    country: str
    external: bool
    n_fail: int
    n_accept: int
    distinct_users: int
    success_after_fail: bool
    span_minutes: int
    users: list[str]
    ip: str

    def sheet(self) -> dict:
        return {
            "failed attempts": self.n_fail,
            "successful logins": self.n_accept,
            "different usernames": self.distinct_users,
            "minutes": self.span_minutes,
        }


def facts_from(burst: Burst, kind: str) -> Facts:
    return Facts(
        kind=kind, severity=SEVERITY[kind], country=burst.country, external=bool(burst.external),
        n_fail=burst.n_fail, n_accept=burst.n_accept, distinct_users=burst.distinct_users,
        success_after_fail=bool(burst.success_after_fail),
        span_minutes=max(1, round(burst.span_seconds / 60)), users=burst.users, ip=burst.ip,
    )


def _where(f: Facts) -> str:
    place = "an internal address" if not f.external else f"an outside address ({f.country})"
    return place


def technical_note(f: Facts) -> str:
    where = _where(f)
    if f.kind == "brute_force":
        body = (f"{f.n_fail} failed password attempts for one account came from {where} "
                f"over about {f.span_minutes} minutes. No login succeeded, so the attempt "
                f"appears to have failed.")
        action = ("Confirm the account is safe, block the address at the firewall, and check "
                  "nothing else came from it.")
    elif f.kind == "password_spray":
        body = (f"One address ({where}) tried to log in as {f.distinct_users} different users, "
                f"with {f.n_fail} failures in about {f.span_minutes} minutes. This is the pattern "
                f"of one password being tried against many accounts.")
        action = ("Block the address, and ask the targeted users to confirm their passwords are "
                  "strong and not reused.")
    elif f.kind == "account_compromise":
        body = (f"After {f.n_fail} failed attempts from {where}, a login finally succeeded "
                f"({f.n_accept} success) within about {f.span_minutes} minutes. A guessed password "
                f"may now be in use.")
        action = ("Treat as live. Disable the account, end its sessions, reset the password, turn "
                  "on multi-factor authentication, and review what the account did after the login.")
    else:
        body = "Activity here looks normal."
        action = "No action needed."
    return f"{body} Suggested action: {action}"


def manager_note(f: Facts) -> str:
    if f.kind == "account_compromise":
        return ("Urgent: it looks like someone guessed a staff password and got in. The IT team "
                "is locking the account and checking what was accessed. We will update you shortly.")
    if f.kind == "brute_force":
        return ("Someone from outside the company tried many times to break into one staff account "
                "but did not get in. The IT team is blocking them. No action is needed from you.")
    if f.kind == "password_spray":
        return ("Someone from outside tried one password against many staff accounts. None were "
                "broken into. The IT team is blocking the source and asking a few staff to check "
                "their passwords.")
    return "No security concern here."


NUM_RE = re.compile(r"\d+")


def check_grounded(text: str, f: Facts) -> bool:
    """Every number in the text must be one of the alert's own numbers."""
    allowed = {str(v) for v in f.sheet().values()}
    allowed |= {str(f.n_accept), str(f.span_minutes)}
    for n in NUM_RE.findall(text):
        if n not in allowed:
            return False
    return True


@dataclass
class Explanation:
    kind: str
    severity: str
    title: str
    technical: str
    manager: str
    grounded: bool
    source: str   # "template" or "llm"


def explain(burst: Burst, kind: str, writer=None) -> Explanation:
    """Build both notes. `writer` is an optional language-model backend."""
    f = facts_from(burst, kind)
    source = "template"
    tech = technical_note(f)
    mgr = manager_note(f)
    if writer is not None and kind != "normal":
        try:
            cand_tech = writer.write(f, audience="technical")
            cand_mgr = writer.write(f, audience="manager")
            # accept the model text only if it invents no numbers
            if check_grounded(cand_tech, f) and check_grounded(cand_mgr, f):
                tech, mgr, source = cand_tech, cand_mgr, "llm"
        except Exception:
            pass
    return Explanation(
        kind=kind, severity=SEVERITY[kind], title=TITLE[kind],
        technical=tech, manager=mgr, grounded=check_grounded(tech, f), source=source,
    )
