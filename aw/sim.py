"""Simulated company SSH/auth log with hidden incidents and exact ground truth.

This writes an OpenSSH-style auth log (the same line format as the real
LogHub OpenSSH sample), so the parser and detector can be tested against
the real sample too.

Normal life on a weekday: staff and admins sign in from the UK, a few
mistype their password, the internet throws low-level SSH scans at the
server all day (as every public server sees), and account admin happens
occasionally.

Hard negatives are included on purpose, because they look a little like
attacks but are not: password typos, a legitimate new starter account, a
large but normal month-end file sync.

Incidents (each line they produce carries a label):
- brute_force: many failed passwords for one user from one outside address,
  then nothing (the attempt failed).
- password_spray: one common password tried against many user names from
  one outside address.
- account_compromise: a brute force from an outside address that ends in a
  successful login (the serious case).

None of this is attack tooling. The log only records failed and successful
logins, which is exactly what a defender sees in the auth log.
"""
from __future__ import annotations

import datetime as dt
import json
import random
from dataclasses import dataclass, field
from pathlib import Path

from . import geo

FIRST = ["aisha", "ben", "chloe", "daniel", "emeka", "fatima", "george", "hannah", "ifeoma", "jack",
         "kofi", "laura", "mohammed", "nina", "oliver", "priya", "rachel", "samuel", "tomi",
         "uche", "victoria", "william", "yusuf", "zara", "amelia", "chidi", "ellie", "harry", "isla"]
LAST = ["khan", "smith", "okafor", "jones", "patel", "brown", "adeyemi", "taylor", "wilson", "evans"]
HOST = "srv-app01"
STAFF_BLOCKS = ["81.2.", "86.140.", "92.40."]
SCAN_BLOCKS = ["45.155.", "185.220.", "103.75.", "177.54.", "61.177.", "5.188.", "212.70."]
# user names outside attackers guess but that do not exist here
GUESS_USERS = ["admin", "root", "test", "oracle", "postgres", "ubuntu", "git", "ftpuser",
               "webmaster", "mysql", "deploy", "backup", "user", "guest", "support"]
COMMON_PW_USERS = None  # filled from staff list at run time


@dataclass
class Line:
    t: dt.datetime
    pid: int
    text: str
    label: str = "normal"      # normal | brute_force | password_spray | account_compromise
    incident: int = 0          # 0 = none, else incident id


@dataclass
class Sim:
    seed: int = 1
    days: int = 3
    start: dt.datetime = field(default_factory=lambda: dt.datetime(2026, 1, 12, 0, 0, 0))
    lines: list[Line] = field(default_factory=list)
    rng: random.Random = field(init=False)
    staff: list[str] = field(init=False)
    incident_id: int = 0

    def __post_init__(self):
        self.rng = random.Random(self.seed)
        self.staff = []
        used = set()
        for _ in range(60):
            u = f"{self.rng.choice(FIRST)}.{self.rng.choice(LAST)}"
            if u not in used:
                used.add(u)
                self.staff.append(u)

    # ---- low-level line writers (OpenSSH syslog format) ----
    def _emit(self, t, pid, text, label="normal", incident=0):
        self.lines.append(Line(t, pid, text, label, incident))

    def ok_login(self, t, user, ip, label="normal", incident=0):
        pid = self.rng.randint(2000, 59999)
        port = self.rng.randint(30000, 61000)
        self._emit(t, pid, f"Accepted password for {user} from {ip} port {port} ssh2", label, incident)
        self._emit(t + dt.timedelta(seconds=0), pid,
                   f"pam_unix(sshd:session): session opened for user {user} by (uid=0)", label, incident)

    def fail_login(self, t, user, ip, invalid=False, label="normal", incident=0):
        pid = self.rng.randint(2000, 59999)
        port = self.rng.randint(30000, 61000)
        if invalid:
            self._emit(t, pid, f"Invalid user {user} from {ip}", label, incident)
            self._emit(t, pid, f"input_userauth_request: invalid user {user} [preauth]", label, incident)
            self._emit(t, pid, "pam_unix(sshd:auth): check pass; user unknown", label, incident)
            self._emit(t, pid, f"pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 "
                               f"tty=ssh ruser= rhost={ip}", label, incident)
            self._emit(t, pid, f"Failed password for invalid user {user} from {ip} port {port} ssh2",
                       label, incident)
        else:
            self._emit(t, pid, f"pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 "
                               f"tty=ssh ruser= rhost={ip} user={user}", label, incident)
            self._emit(t, pid, f"Failed password for {user} from {ip} port {port} ssh2", label, incident)

    def disconnect(self, t, ip, label="normal", incident=0):
        pid = self.rng.randint(2000, 59999)
        self._emit(t, pid, f"Received disconnect from {ip} port 11: Bye Bye [preauth]", label, incident)

    # ---- background traffic ----
    def staff_ip(self):
        return self.rng.choice(STAFF_BLOCKS) + f"{self.rng.randint(1,254)}.{self.rng.randint(1,254)}"

    def scan_ip(self):
        return self.rng.choice(SCAN_BLOCKS) + f"{self.rng.randint(1,254)}.{self.rng.randint(1,254)}"

    def day_of_normal(self, day0):
        """One day of ordinary SSH activity."""
        base = self.start + dt.timedelta(days=day0)
        # staff/admin logins across the working day
        for _ in range(self.rng.randint(45, 70)):
            hour = int(min(23, max(6, self.rng.gauss(11, 3))))
            t = base + dt.timedelta(hours=hour, minutes=self.rng.randint(0, 59), seconds=self.rng.randint(0, 59))
            user = self.rng.choice(self.staff)
            ip = self.staff_ip()
            # a password typo before success sometimes (hard negative)
            if self.rng.random() < 0.15:
                self.fail_login(t, user, ip)
                t = t + dt.timedelta(seconds=self.rng.randint(3, 20))
            self.ok_login(t, user, ip)
        # internet background scans all day (invalid users, small numbers each)
        for _ in range(self.rng.randint(30, 50)):
            t = base + dt.timedelta(hours=self.rng.randint(0, 23), minutes=self.rng.randint(0, 59),
                                    seconds=self.rng.randint(0, 59))
            ip = self.scan_ip()
            for _ in range(self.rng.randint(1, 3)):
                self.fail_login(t, self.rng.choice(GUESS_USERS), ip, invalid=True)
                t = t + dt.timedelta(seconds=self.rng.randint(1, 4))
            self.disconnect(t, ip)

    # ---- incidents ----
    def brute_force(self, day0, compromise=False):
        """Many failed passwords for one existing user from one address.

        Sizes range from clearly large down to borderline (close to the number
        of everyday typos), so a fixed threshold cannot catch every case."""
        self.incident_id += 1
        iid = self.incident_id
        label = "account_compromise" if compromise else "brute_force"
        base = self.start + dt.timedelta(days=day0, hours=self.rng.randint(1, 20),
                                         minutes=self.rng.randint(0, 59))
        # real brute force often tries a handful of likely usernames, not just one
        k = self.rng.randint(1, 12)
        targets = self.rng.sample(self.staff, min(k, len(self.staff)))
        ip = self.scan_ip()
        t = base
        n = self.rng.randint(12, 90)   # includes borderline sizes near the typo range
        for _ in range(n):
            self.fail_login(t, self.rng.choice(targets), ip, invalid=False, label=label, incident=iid)
            t = t + dt.timedelta(seconds=self.rng.randint(1, 9))
        if compromise:
            self.ok_login(t, self.rng.choice(targets), ip, label=label, incident=iid)
        return iid, label

    def password_spray(self, day0):
        """One password tried against many user names from one address."""
        self.incident_id += 1
        iid = self.incident_id
        base = self.start + dt.timedelta(days=day0, hours=self.rng.randint(1, 20),
                                         minutes=self.rng.randint(0, 59))
        ip = self.scan_ip()
        t = base
        victims = self.rng.sample(self.staff, self.rng.randint(10, 45))
        for u in victims:
            self.fail_login(t, u, ip, invalid=False, label="password_spray", incident=iid)
            t = t + dt.timedelta(seconds=self.rng.randint(2, 8))
        return iid, "password_spray"

    # ---- hard negatives: benign, but a bit like an attack ----
    def forgetful_user(self, day0):
        """A real member of staff on the internal network mistypes a lot, then gets in.

        Looks a little like a compromise (fails then success), but it is from
        an internal address, so it should stay 'normal'. Tests that the source
        location matters, not just the fail-then-success shape."""
        base = self.start + dt.timedelta(days=day0, hours=self.rng.randint(8, 17),
                                         minutes=self.rng.randint(0, 59))
        user = self.rng.choice(self.staff)
        ip = "10." + f"{self.rng.randint(0,40)}.{self.rng.randint(1,254)}.{self.rng.randint(1,254)}"
        t = base
        for _ in range(self.rng.randint(5, 12)):
            self.fail_login(t, user, ip, invalid=False)
            t = t + dt.timedelta(seconds=self.rng.randint(5, 30))
        self.ok_login(t, user, ip)

    def bulk_automation(self, day0):
        """An internal automation account logs in many times in a short span.

        High volume from one internal address, almost all successful. Benign."""
        base = self.start + dt.timedelta(days=day0, hours=self.rng.randint(0, 23),
                                         minutes=self.rng.randint(0, 59))
        ip = "10.9." + f"{self.rng.randint(1,254)}.{self.rng.randint(1,254)}"
        user = "svc.backup"
        t = base
        for _ in range(self.rng.randint(25, 50)):
            if self.rng.random() < 0.05:
                self.fail_login(t, user, ip)
            else:
                self.ok_login(t, user, ip)
            t = t + dt.timedelta(seconds=self.rng.randint(2, 10))

    def build(self, incidents=True):
        incs = []
        for d in range(self.days):
            self.day_of_normal(d)
            # hard negatives most days
            if self.rng.random() < 0.8:
                self.forgetful_user(d)
            if self.rng.random() < 0.6:
                self.bulk_automation(d)
            if incidents:
                # several incidents each day, at random, so classes have real support
                for _ in range(self.rng.randint(3, 7)):
                    roll = self.rng.random()
                    if roll < 0.45:
                        incs.append(self.brute_force(d, compromise=False))
                    elif roll < 0.75:
                        incs.append(self.password_spray(d))
                    else:
                        incs.append(self.brute_force(d, compromise=True))
        self.lines.sort(key=lambda x: x.t)
        return incs


def write(sim: Sim, out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    raw = out_dir / "auth.log"
    truth = out_dir / "truth.json"
    with raw.open("w") as f:
        for ln in sim.lines:
            stamp = ln.t.strftime("%b %e %H:%M:%S")
            f.write(f"{stamp} {HOST} sshd[{ln.pid}]: {ln.text}\n")
    # ground truth: per incident, which lines (by order) belong to it
    rows = []
    for i, ln in enumerate(sim.lines):
        if ln.incident:
            rows.append({"line": i, "incident": ln.incident, "label": ln.label})
    truth.write_text(json.dumps({"lines": len(sim.lines), "events": rows}, indent=2))
    return raw, truth
