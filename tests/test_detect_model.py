from pathlib import Path

from aw.detect import RuleScorer, bursts_from_events, label_bursts
from aw.model import train
from aw.parse import parse_file
import json

ROOT = Path(__file__).resolve().parents[1]


def _load(name):
    d = ROOT / "data" / "sim" / name
    if not (d / "auth.log").exists():
        return None
    ev = parse_file(d / "auth.log")
    b = bursts_from_events(ev)
    truth = json.loads((d / "truth.json").read_text())
    return b, label_bursts(b, truth)


def test_rule_baseline_flags_a_clear_brute_force():
    from aw.detect import Burst
    b = Burst(ip="45.155.1.9", country="RU", start_idx=0, end_idx=9, t_start="", t_end="",
              n_events=60, n_fail=60, n_accept=0, n_invalid=0, distinct_users=1,
              success_after_fail=0, max_fail_1min=40, span_seconds=300, external=1,
              users=["x"], line_idxs=[])
    assert RuleScorer().predict(b) == "brute_force"


def test_model_learns_and_generalises():
    tr = _load("train")
    te = _load("test")
    if tr is None or te is None:
        return  # data not generated in this environment
    net = train(tr[0], tr[1], seed=0, epochs=200)
    pred = [net.predict(b) for b in te[0]]
    true = te[1]
    # attacks found vs missed on the unseen test set
    tp = sum(1 for t, p in zip(true, pred) if t != "normal" and p != "normal")
    fn = sum(1 for t, p in zip(true, pred) if t != "normal" and p == "normal")
    recall = tp / (tp + fn) if tp + fn else 1.0
    assert recall >= 0.9
