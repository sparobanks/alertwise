"""Optional language-model writer for alert explanations.

This shows how a language model would be used safely inside the pipeline. It
is optional: the pipeline works without it, using the template writer, so the
project runs offline and in tests.

What makes this safe:
- It is given only the redacted fact sheet (no real user names or addresses),
  built with redact.py. Personal data never reaches the model.
- Its output is checked by explain.check_grounded() before use, so invented
  numbers are rejected and the template is used instead.
- It talks to any OpenAI-compatible endpoint (for example a local Ollama
  server, or an internal model), set by environment variables, so no data
  goes to a third party unless the company chooses that endpoint.

Environment variables:
  AW_LLM_BASE_URL   e.g. http://localhost:11434/v1   (Ollama)
  AW_LLM_MODEL      e.g. qwen2.5:0.5b-instruct
  AW_LLM_API_KEY    optional
"""
from __future__ import annotations

import json
import os
import urllib.request

from .explain import Facts
from .redact import redact

SYSTEM = ("You are a security analyst. Explain the alert using only the numbers and facts given. "
          "Do not invent any numbers. Keep it short and clear. "
          "For a technical reader: say what happened, where, the key numbers, and the action. "
          "For a manager: say what it means and how urgent it is, in plain words, no jargon.")


class LLMWriter:
    def __init__(self, base_url: str | None = None, model: str | None = None,
                 api_key: str | None = None, timeout: int = 30):
        self.base_url = (base_url or os.environ.get("AW_LLM_BASE_URL", "")).rstrip("/")
        self.model = model or os.environ.get("AW_LLM_MODEL", "")
        self.api_key = api_key or os.environ.get("AW_LLM_API_KEY", "")
        self.timeout = timeout
        if not self.base_url or not self.model:
            raise RuntimeError("no language-model endpoint configured")

    def _prompt(self, f: Facts, audience: str) -> str:
        # redact the fact sheet: country stays (not personal), address and users are masked
        red = redact(f"address {f.ip}, users {', '.join(f.users)}", f.users)
        facts = {
            "type": f.kind,
            "severity": f.severity,
            "source": "inside the company" if not f.external else f"outside ({f.country})",
            "masked_address": list(red.mapping)[0] if red.mapping else "ADDR_1",
            "failed_attempts": f.n_fail,
            "successful_logins": f.n_accept,
            "different_usernames": f.distinct_users,
            "minutes": f.span_minutes,
            "a_login_succeeded_after_failures": f.success_after_fail,
        }
        return (f"Audience: {audience}.\nFacts (JSON):\n{json.dumps(facts, indent=2)}\n\n"
                f"Write 2 to 4 sentences for this audience. Use only these numbers.")

    def write(self, f: Facts, audience: str) -> str:
        payload = {
            "model": self.model,
            "messages": [{"role": "system", "content": SYSTEM},
                         {"role": "user", "content": self._prompt(f, audience)}],
            "temperature": 0.2,
        }
        req = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json",
                     **({"Authorization": f"Bearer {self.api_key}"} if self.api_key else {})},
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            out = json.loads(r.read())
        text = out["choices"][0]["message"]["content"].strip()
        # the model saw only masked tokens; put the real values back for internal display
        return redact(f"address {f.ip}, users {', '.join(f.users)}", f.users).restore(text)
