"""Parse OpenSSH auth logs into structured events.

Works line by line, pulling out the time, the event type, the user and the
source address. The patterns match the standard OpenSSH syslog format, so
the same parser reads the simulated log and the real LogHub OpenSSH sample.

Each raw line becomes an Event with a `kind`:
- fail      : a failed password (valid or invalid user)
- accept    : a successful login
- invalid   : an "Invalid user" notice
- breakin   : the "POSSIBLE BREAK-IN ATTEMPT" notice
- other     : anything else (kept, but not used by the detector)
"""
from __future__ import annotations

import datetime as dt
import re
from dataclasses import dataclass

IP = r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
PATTERNS = [
    ("fail", re.compile(rf"Failed password for (?:invalid user )?(?P<user>\S+) from {IP}")),
    ("accept", re.compile(rf"Accepted password for (?P<user>\S+) from {IP}")),
    ("invalid", re.compile(rf"Invalid user (?P<user>\S+) from {IP}")),
    ("breakin", re.compile(rf"POSSIBLE BREAK-IN ATTEMPT")),
]
HEAD = re.compile(r"^(?P<mon>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
                  r"sshd\[(?P<pid>\d+)\]:\s*(?P<msg>.*)$")
MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}


@dataclass
class Event:
    idx: int
    t: dt.datetime | None
    host: str
    pid: int
    kind: str
    user: str | None
    ip: str | None
    raw: str


def parse_line(idx: int, line: str, year: int = 2026) -> Event | None:
    m = HEAD.match(line.strip())
    if not m:
        return None
    msg = m.group("msg")
    try:
        t = dt.datetime(year, MONTHS[m.group("mon")], int(m.group("day")),
                        *[int(x) for x in m.group("time").split(":")])
    except (ValueError, KeyError):
        t = None
    kind, user, ip = "other", None, None
    for name, pat in PATTERNS:
        g = pat.search(msg)
        if g:
            kind = name
            user = g.groupdict().get("user")
            ip = g.groupdict().get("ip")
            break
    return Event(idx, t, m.group("host"), int(m.group("pid")), kind, user, ip, line.rstrip("\n"))


def parse_file(path, year: int = 2026) -> list[Event]:
    events = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f):
            ev = parse_line(i, line, year)
            if ev:
                events.append(ev)
    return events
