"""Remove personal data before an alert is sent to a language model.

Under GDPR, user names and IP addresses are personal data. A hosted language
model should not receive them. This module replaces them with stable tokens
(USER_1, ADDR_1) and keeps a private map so the real values can be put back
in the final text shown to staff, which never leaves the company.

It returns both the masked text and the mapping. The mapping stays on our
side; only the masked text would go to a model.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")


@dataclass
class Redaction:
    masked: str
    mapping: dict[str, str] = field(default_factory=dict)  # token -> real value

    def restore(self, text: str) -> str:
        out = text
        for token, real in self.mapping.items():
            out = out.replace(token, real)
        return out


def redact(text: str, users: list[str] | None = None) -> Redaction:
    mapping: dict[str, str] = {}
    counter = {"ADDR": 0, "USER": 0, "EMAIL": 0}

    def token(kind: str, real: str) -> str:
        for tok, val in mapping.items():
            if val == real:
                return tok
        counter[kind] += 1
        tok = f"{kind}_{counter[kind]}"
        mapping[tok] = real
        return tok

    out = text
    for real in sorted(users or [], key=len, reverse=True):
        if real:
            out = re.sub(rf"\b{re.escape(real)}\b", lambda m, r=real: token("USER", r), out)
    out = EMAIL_RE.sub(lambda m: token("EMAIL", m.group(0)), out)
    out = IP_RE.sub(lambda m: token("ADDR", m.group(0)), out)
    return Redaction(out, mapping)


def contains_pii(text: str, users: list[str] | None = None) -> bool:
    """True if any raw IP, email or known user name is still present."""
    if IP_RE.search(text) or EMAIL_RE.search(text):
        return True
    for u in users or []:
        if u and re.search(rf"\b{re.escape(u)}\b", text):
            return True
    return False
