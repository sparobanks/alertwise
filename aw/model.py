"""A small PyTorch classifier that labels each burst.

The input is the nine features from detect.Burst. The output is one of the
four classes. It is deliberately small: the point is a clean, well-evaluated
model, not a large one. Standardisation statistics are learned on the
training set and saved with the weights so scoring uses the same scaling.
"""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import torch
import torch.nn as nn

from .detect import CLASSES, Burst

N_FEAT = 10


class Net(nn.Module):
    def __init__(self, n_feat: int = N_FEAT, n_class: int = len(CLASSES)):
        super().__init__()
        self.body = nn.Sequential(
            nn.Linear(n_feat, 32), nn.ReLU(), nn.Dropout(0.1),
            nn.Linear(32, 32), nn.ReLU(),
            nn.Linear(32, n_class),
        )

    def forward(self, x):
        return self.body(x)


@dataclass
class NetScorer:
    net: Net
    mean: np.ndarray
    std: np.ndarray

    def _x(self, feats: np.ndarray) -> torch.Tensor:
        z = (feats - self.mean) / self.std
        return torch.tensor(z, dtype=torch.float32)

    def predict(self, b: Burst) -> str:
        return self.predict_proba(b)[0]

    def predict_proba(self, b: Burst):
        self.net.eval()
        with torch.no_grad():
            logits = self.net(self._x(np.array([b.features()])))
            p = torch.softmax(logits, dim=1)[0].numpy()
        i = int(p.argmax())
        return CLASSES[i], float(p[i]), {c: float(p[j]) for j, c in enumerate(CLASSES)}

    def save(self, path):
        torch.save({"state": self.net.state_dict(), "mean": self.mean, "std": self.std}, path)

    @classmethod
    def load(cls, path):
        blob = torch.load(path, weights_only=False)
        net = Net()
        net.load_state_dict(blob["state"])
        return cls(net, blob["mean"], blob["std"])


def train(bursts, labels, seed: int = 0, epochs: int = 300) -> NetScorer:
    torch.manual_seed(seed)
    np.random.seed(seed)
    X = np.array([b.features() for b in bursts], dtype=np.float64)
    y = np.array([CLASSES.index(l) for l in labels])
    mean, std = X.mean(0), X.std(0) + 1e-6
    Xz = torch.tensor((X - mean) / std, dtype=torch.float32)
    yt = torch.tensor(y, dtype=torch.long)
    # class weights (attacks are rarer than normal bursts)
    counts = np.bincount(y, minlength=len(CLASSES)).astype(np.float64)
    w = torch.tensor((counts.sum() / (counts + 1)) ** 0.5, dtype=torch.float32)
    net = Net()
    opt = torch.optim.Adam(net.parameters(), lr=0.01, weight_decay=1e-4)
    loss_fn = nn.CrossEntropyLoss(weight=w)
    net.train()
    for _ in range(epochs):
        opt.zero_grad()
        loss = loss_fn(net(Xz), yt)
        loss.backward()
        opt.step()
    return NetScorer(net, mean, std)
