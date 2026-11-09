"""Create simulated auth logs with ground truth.

    python scripts/make_data.py

Writes three datasets under data/sim:
- train: used to train the model
- test:  a different random seed, used only for evaluation
- demo:  a small one used by the dashboard and the README walk-through
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from aw.sim import Sim, write


def main():
    for name, seed, days in [("train", 1, 10), ("test", 2, 8), ("demo", 7, 2)]:
        sim = Sim(seed=seed, days=days)
        incs = sim.build(incidents=True)
        raw, truth = write(sim, ROOT / "data" / "sim" / name)
        print(f"{name}: {len(sim.lines)} lines, incidents={[l for _, l in incs]} -> {raw}")


if __name__ == "__main__":
    main()
