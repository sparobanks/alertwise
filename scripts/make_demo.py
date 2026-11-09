"""Produce the dashboard screenshot used in the README.

    python scripts/make_demo.py

Starts the API on a background port against the demo log, signs in, opens the
first alert, and saves a screenshot to docs/img/dashboard.png.
"""
from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import uvicorn

PORT = 8099


def serve():
    os.environ.setdefault("AW_LOG", str(ROOT / "data" / "sim" / "demo" / "auth.log"))
    from aw.api import app
    uvicorn.run(app, host="127.0.0.1", port=PORT, log_level="warning")


def main():
    t = threading.Thread(target=serve, daemon=True)
    t.start()
    # wait for the server to answer before driving the browser
    import urllib.request
    for _ in range(40):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{PORT}/healthz", timeout=1)
            break
        except Exception:
            time.sleep(0.5)
    from playwright.sync_api import sync_playwright

    out = ROOT / "docs" / "img"
    out.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as pw:
        b = pw.chromium.launch()
        pg = b.new_page(viewport={"width": 920, "height": 1000})
        pg.goto(f"http://127.0.0.1:{PORT}/", wait_until="networkidle")
        pg.click("button")  # sign in with the prefilled demo credentials
        pg.wait_for_selector(".alert", timeout=8000)
        alerts = pg.query_selector_all(".alert")
        # expand the first high-severity alert if there is one
        for a in alerts:
            if "high" in (a.get_attribute("class") or ""):
                a.click()
                break
        else:
            alerts[0].click()
        pg.wait_for_timeout(600)
        pg.screenshot(path=str(out / "dashboard.png"), full_page=True)
        b.close()
    print("wrote", out / "dashboard.png")


if __name__ == "__main__":
    main()
