"""Train the detector, evaluate it, and run it on a real log sample.

    python scripts/run_detect.py

1. Build bursts from the training log, label them, train the PyTorch model.
2. Evaluate on the test log (a different seed the model never saw):
   per-class precision and recall, a confusion table, and the same for the
   readable rule baseline.
3. Run the trained model on the real LogHub OpenSSH sample and report what it
   finds (that sample has no labels, so this is a sanity check, not a score).
Writes models/net.pt, reports/metrics.json and reports/confusion.png.
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import numpy as np

from aw.detect import CLASSES, RuleScorer, bursts_from_events, label_bursts
from aw.model import NetScorer, train
from aw.parse import parse_file
from aw.pipeline import run


def load(name):
    d = ROOT / "data" / "sim" / name
    events = parse_file(d / "auth.log")
    bursts = bursts_from_events(events)
    truth = json.loads((d / "truth.json").read_text())
    labels = label_bursts(bursts, truth)
    return events, bursts, labels


def scores(true, pred):
    out = {}
    for c in CLASSES:
        tp = sum(1 for t, p in zip(true, pred) if t == c and p == c)
        fp = sum(1 for t, p in zip(true, pred) if t != c and p == c)
        fn = sum(1 for t, p in zip(true, pred) if t == c and p != c)
        prec = tp / (tp + fp) if tp + fp else 1.0
        rec = tp / (tp + fn) if tp + fn else 1.0
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        out[c] = {"precision": round(prec, 3), "recall": round(rec, 3), "f1": round(f1, 3),
                  "support": sum(1 for t in true if t == c)}
    attacks = [c for c in CLASSES if c != "normal"]
    tp = sum(1 for t, p in zip(true, pred) if t != "normal" and p != "normal")
    fp = sum(1 for t, p in zip(true, pred) if t == "normal" and p != "normal")
    fn = sum(1 for t, p in zip(true, pred) if t != "normal" and p == "normal")
    out["attack_vs_normal"] = {
        "precision": round(tp / (tp + fp), 3) if tp + fp else 1.0,
        "recall": round(tp / (tp + fn), 3) if tp + fn else 1.0,
        "attacks_total": sum(1 for t in true if t != "normal"),
        "attacks_found": tp, "false_alarms": fp,
    }
    return out


def confusion(true, pred):
    idx = {c: i for i, c in enumerate(CLASSES)}
    m = np.zeros((len(CLASSES), len(CLASSES)), int)
    for t, p in zip(true, pred):
        m[idx[t], idx[p]] += 1
    return m


def chart(m, path):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots(figsize=(5.4, 4.6))
    ax.imshow(m, cmap="Blues")
    short = ["normal", "brute", "spray", "compromise"]
    ax.set_xticks(range(len(CLASSES)), short, rotation=30, ha="right")
    ax.set_yticks(range(len(CLASSES)), short)
    for i in range(len(CLASSES)):
        for j in range(len(CLASSES)):
            ax.text(j, i, m[i, j], ha="center", va="center",
                    color="white" if m[i, j] > m.max() / 2 else "#1d2321", fontsize=11)
    ax.set_xlabel("Predicted")
    ax.set_ylabel("True")
    ax.set_title("Confusion on the unseen test log", loc="left", fontsize=11)
    fig.tight_layout()
    fig.savefig(path, dpi=150)


def main():
    (ROOT / "models").mkdir(exist_ok=True)
    (ROOT / "reports").mkdir(exist_ok=True)

    _, tr_b, tr_y = load("train")
    _, te_b, te_y = load("test")
    print(f"train bursts {len(tr_b)}  test bursts {len(te_b)}")
    print("train label mix:", dict(Counter(tr_y)))

    net = train(tr_b, tr_y, seed=0)
    net.save(ROOT / "models" / "net.pt")

    net_pred = [net.predict(b) for b in te_b]
    rule = RuleScorer()
    rule_pred = [rule.predict(b) for b in te_b]

    report = {
        "train_bursts": len(tr_b), "test_bursts": len(te_b),
        "test_label_mix": dict(Counter(te_y)),
        "model": scores(te_y, net_pred),
        "rule_baseline": scores(te_y, rule_pred),
    }

    # real LogHub OpenSSH sample (no labels): what does the model flag?
    real = ROOT / "data" / "real" / "OpenSSH_2k.log"
    if real.exists():
        ev = parse_file(real)
        alerts = run(ev, net)
        report["real_openssh_sample"] = {
            "events_parsed": len(ev),
            "alerts": len(alerts),
            "by_kind": dict(Counter(a["kind"] for a in alerts)),
            "top_sources": [{"ip": a["source_ip"], "country": a["country"],
                             "failed": a["failed_attempts"], "kind": a["kind"]}
                            for a in alerts[:5]],
        }

    (ROOT / "reports" / "metrics.json").write_text(json.dumps(report, indent=2))
    chart(confusion(te_y, net_pred), ROOT / "reports" / "confusion.png")
    print(json.dumps({k: report[k] for k in ("model", "rule_baseline")}, indent=2))
    if "real_openssh_sample" in report:
        print("real sample:", json.dumps(report["real_openssh_sample"], indent=2))


if __name__ == "__main__":
    main()
