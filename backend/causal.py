"""
SentinelSOC - causal risk scoring.

Ported from DataSentinel's engines/causal_rca.py and retargeted from data
quality to security triage.

The idea worth keeping: an anomaly's importance is not its own deviation alone,
it is its own deviation PLUS the deviation of everything it causally reaches.
A spike in failed logins that leads nowhere is noise; the same spike followed
downstream by a privilege change and an egress spike is a breach. Correlation
alone cannot tell those apart because both look identical at the point of the
spike.

NOTEARS (Zheng et al. 2018) learns the structure by gradient descent instead of
combinatorial search. A weighted adjacency matrix W is fit to reconstruct the
data linearly, with two penalties: L1 for sparsity, and the acyclicity
constraint

    h(W) = trace(exp(W . W)) - d

which is exactly zero if and only if W encodes a DAG. That identity is what lets
a discrete graph-search problem be optimised with an ordinary gradient step.

Honest limits, because they matter when reading the output:

  * the DAG is over FEATURES, not over incidents. It answers "does a rise in
    failure_ratio precede a rise in log_mbytes_out across this estate", not
    "did incident A cause incident B".
  * it is linear and observational. Confounders are not adjusted for, so
    "causal" here means Granger-ish structure recovered from co-movement, not
    proof of mechanism.
  * with few windows the graph is unstable. Below MIN_ROWS this declines to run
    rather than return a confident-looking arbitrary matrix.

Used only for the deterministic fallback path. When a model is reachable, the
Threat Investigation Agent scores risk itself and explains its own reasoning.
"""

from __future__ import annotations

from dataclasses import dataclass, field

MIN_ROWS = 40
MAX_ROWS = 10_000
INNER_EPOCHS = 200
OUTER_STEPS = 12
LEARNING_RATE = 0.02
L1_LAMBDA = 0.01
EDGE_THRESHOLD = 0.20

# Augmented Lagrangian controls.
#
# A fixed acyclicity penalty does not converge: measured on a planted a->b->c
# chain it left h(W)=0.073 and the graph kept BOTH a->b and b->a, which is a
# correlation matrix wearing a DAG's clothes. NOTEARS needs dual ascent - rho
# escalates whenever h stops falling fast enough, alpha accumulates the
# constraint violation - which is what actually drives h to zero.
RHO_INIT = 1.0
RHO_MAX = 1e16
RHO_GROWTH = 10.0
H_TOLERANCE = 1e-6
H_PROGRESS = 0.25          # rho grows unless h drops to this share of its last value

# Keep the best graph seen, not the last one.
#
# Dual ascent does not stop at "acyclic" - it keeps pressing. Traced on a
# planted chain, max|W| climbed to 0.96 while h fell to 1e-5, then rho reached
# 1e11 and flattened every weight to 0.05: a graph with no edges, perfectly
# acyclic and perfectly useless. So snapshot each outer step and return the one
# with the lowest h that still carries usable edges.
DEVIATION_FLOOR = 1.0          # z-scores below this are not deviations worth tracing


@dataclass
class CausalModel:
    """A learned feature DAG plus the statistics needed to score against it."""

    features: list[str]
    weights: list[list[float]] = field(default_factory=list)
    mean: list[float] = field(default_factory=list)
    std: list[float] = field(default_factory=list)
    fitted: bool = False
    h: float = float("nan")        # acyclicity residual; 0 means a strict DAG

    def edges(self, limit: int = 12) -> list[tuple[str, str, float]]:
        """Strongest surviving edges, for showing a human what was learned."""
        out = []
        for i, row in enumerate(self.weights):
            for j, w in enumerate(row):
                if w:
                    out.append((self.features[i], self.features[j], round(w, 3)))
        out.sort(key=lambda e: -abs(e[2]))
        return out[:limit]


def learn_dag(matrix, features: list[str]) -> CausalModel:
    """
    Fit W by gradient descent under the acyclicity constraint.

    Returns an unfitted model when torch is absent or there is too little data;
    callers fall back to a non-causal score rather than trusting a graph learned
    from nothing.
    """
    model = CausalModel(features=list(features))
    try:
        import numpy as np
        import torch
    except ImportError:
        return model

    data = np.asarray(matrix, dtype=float)
    if data.ndim != 2 or data.shape[0] < MIN_ROWS or data.shape[1] != len(features):
        return model

    if data.shape[0] > MAX_ROWS:
        rng = np.random.default_rng(42)
        data = data[rng.choice(data.shape[0], MAX_ROWS, replace=False)]

    mean = data.mean(axis=0)
    std = data.std(axis=0)
    std[std == 0] = 1.0
    normed = (data - mean) / std

    X = torch.tensor(normed, dtype=torch.float32)
    d = X.shape[1]

    torch.manual_seed(42)
    W = torch.zeros(d, d, requires_grad=True)
    eye = torch.eye(d, dtype=torch.bool)

    def acyclicity(mat):
        """h(W) == 0 exactly when W encodes a DAG."""
        return torch.trace(torch.matrix_exp(mat * mat)) - d

    rho, alpha, h_last = RHO_INIT, 0.0, float("inf")
    best: tuple[float, object] | None = None

    for _ in range(OUTER_STEPS):
        # Inner problem: minimise reconstruction + sparsity under the current
        # penalty and multiplier.
        while rho < RHO_MAX:
            optimiser = torch.optim.Adam([W], lr=LEARNING_RATE)
            for _ in range(INNER_EPOCHS):
                optimiser.zero_grad()
                masked = W.masked_fill(eye, 0.0)
                mse = 0.5 / X.shape[0] * torch.sum((X @ masked - X) ** 2)
                l1 = L1_LAMBDA * torch.sum(torch.abs(masked))
                h = acyclicity(masked)
                (mse + l1 + 0.5 * rho * h * h + alpha * h).backward()
                optimiser.step()

            with torch.no_grad():
                h_now = float(acyclicity(W.masked_fill(eye, 0.0)))
            if h_now > H_PROGRESS * h_last:
                rho *= RHO_GROWTH      # not converging fast enough; press harder
            else:
                break

        with torch.no_grad():
            candidate = W.masked_fill(eye, 0.0).clone()
        # Only a graph that still has edges is a candidate.
        if float(candidate.abs().max()) >= EDGE_THRESHOLD and (
            best is None or h_now < best[0]
        ):
            best = (h_now, candidate)

        alpha += rho * h_now           # dual ascent
        h_last = h_now
        if h_now <= H_TOLERANCE:
            break

    if best is None:
        return model                   # never found a usable graph

    final = best[1].numpy()
    final[abs(final) < EDGE_THRESHOLD] = 0.0      # keep only confident edges
    if not final.any():
        return model

    model.h = round(best[0], 12)

    model.weights = final.tolist()
    model.mean = mean.tolist()
    model.std = std.tolist()
    model.fitted = True
    return model


def blast_radius(model: CausalModel, observation: list[float]) -> dict:
    """
    Score one observation: own deviation plus what it causally reaches.

    For each feature deviating beyond DEVIATION_FLOOR, the score is its own
    z-score plus, for every downstream feature that is ALSO deviating, the edge
    weight times that downstream deviation. A deviation whose consequences are
    all quiet scores as itself and no more.
    """
    if not model.fitted:
        return {"total": 0.0, "contributors": [], "fitted": False}

    deviations = []
    for i, value in enumerate(observation):
        std = model.std[i] or 1.0
        deviations.append(abs((value - model.mean[i]) / std))

    contributors = []
    for i, own in enumerate(deviations):
        if own < DEVIATION_FLOOR:
            continue
        downstream = 0.0
        reached = []
        for j, weight in enumerate(model.weights[i]):
            if weight and deviations[j] >= DEVIATION_FLOOR:
                downstream += abs(weight) * deviations[j]
                reached.append(model.features[j])
        contributors.append({
            "feature": model.features[i],
            "own_deviation": round(own, 3),
            "downstream": round(downstream, 3),
            "impact": round(own + downstream, 3),
            "reaches": reached,
        })

    contributors.sort(key=lambda c: -c["impact"])
    return {
        "total": round(sum(c["impact"] for c in contributors), 3),
        "contributors": contributors[:5],
        "fitted": True,
    }


def to_risk_score(total_impact: float, floor: int = 5, ceiling: int = 100) -> int:
    """
    Map an unbounded impact total onto 0-100.

    Saturating rather than linear: the difference between impact 8 and 40 is not
    thirty-two points of operational urgency, and a linear map would let one
    extreme feature pin every incident at 100.
    """
    import math

    if total_impact <= 0:
        return floor
    scaled = 1.0 - math.exp(-total_impact / 12.0)
    return max(floor, min(int(round(scaled * ceiling)), ceiling))
