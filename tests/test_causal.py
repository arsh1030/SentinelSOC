"""
NOTEARS causal risk scoring.

The property that matters: the graph must actually be a DAG. Without the
acyclicity constraint converging, this is a correlation matrix wearing a DAG's
clothes, and "downstream blast radius" means nothing.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

import numpy as np  # noqa: E402
import pytest  # noqa: E402

import causal  # noqa: E402

FEATURES = ["a", "b", "c", "d"]


def _planted(n=400, seed=0):
    """Ground truth: a -> b -> c. d independent."""
    rng = np.random.default_rng(seed)
    a = rng.normal(0, 1, n)
    b = 0.9 * a + rng.normal(0, 0.2, n)
    c = 0.8 * b + rng.normal(0, 0.2, n)
    d = rng.normal(0, 1, n)
    return np.column_stack([a, b, c, d])


@pytest.fixture(scope="module")
def model():
    return causal.learn_dag(_planted(), FEATURES)


# -- the constraint --------------------------------------------------------


def test_result_is_actually_acyclic(model):
    """
    h(W) = trace(exp(W.W)) - d is zero iff W is a DAG.

    The regression this guards: a fixed acyclicity penalty left h at 0.073 and
    the graph kept both a->b AND b->a. Only dual ascent drove it to zero.
    """
    assert model.fitted
    assert model.h <= causal.H_TOLERANCE, f"h={model.h} is not acyclic"


def test_no_edge_and_its_reverse_both_survive(model):
    pairs = {(src, dst) for src, dst, _ in model.edges(50)}
    for src, dst in pairs:
        assert (dst, src) not in pairs, f"cycle: {src}<->{dst}"


def test_recovers_the_planted_direction(model):
    pairs = {(src, dst) for src, dst, _ in model.edges(50)}
    assert ("a", "b") in pairs
    assert ("b", "a") not in pairs, "direction reversed"


def test_independent_feature_stays_disconnected(model):
    touching_d = [e for e in model.edges(50) if "d" in (e[0], e[1])]
    assert not touching_d, f"spurious edges on an independent feature: {touching_d}"


def test_graph_keeps_usable_edges(model):
    """
    Dual ascent does not stop at 'acyclic', it keeps pressing. Traced on this
    fixture, rho reaching 1e11 flattened every weight to 0.05 - perfectly
    acyclic, perfectly useless. The best-snapshot retention exists for this.
    """
    assert model.edges(), "converged to an empty graph"
    assert max(abs(w) for _, _, w in model.edges()) >= causal.EDGE_THRESHOLD


# -- scoring ---------------------------------------------------------------


def test_causally_linked_deviations_outrank_an_isolated_one(model):
    """The whole point: a spike that leads somewhere beats a spike that does not."""
    chain = causal.blast_radius(model, [3.0, 2.7, 2.2, 0.1])
    lone = causal.blast_radius(model, [0.1, 0.1, 0.1, 3.0])
    assert chain["total"] > lone["total"] * 2


def test_quiet_observation_scores_nothing(model):
    quiet = causal.blast_radius(model, [0.1, 0.1, 0.1, 0.1])
    assert quiet["total"] == 0.0
    assert causal.to_risk_score(quiet["total"]) == 5


def test_upstream_feature_carries_more_impact_than_terminal(model):
    """`a` reaches b and c; `c` reaches nothing. Same sigma, different weight."""
    result = causal.blast_radius(model, [3.0, 2.7, 2.2, 0.1])
    by_feature = {c["feature"]: c for c in result["contributors"]}
    assert by_feature["a"]["impact"] > by_feature["c"]["impact"]
    assert by_feature["a"]["reaches"], "the upstream feature should reach something"
    assert not by_feature["c"]["reaches"], "the terminal feature should reach nothing"


def test_downstream_only_counts_features_that_are_also_deviating(model):
    """A quiet consequence is not a blast radius."""
    alone = causal.blast_radius(model, [3.0, 0.1, 0.1, 0.1])
    with_chain = causal.blast_radius(model, [3.0, 2.7, 2.2, 0.1])
    a_alone = next(c for c in alone["contributors"] if c["feature"] == "a")
    a_chain = next(c for c in with_chain["contributors"] if c["feature"] == "a")
    assert a_alone["downstream"] == 0.0
    assert a_chain["downstream"] > 0.0


def test_risk_score_saturates_rather_than_running_away():
    """Impact 8 versus 40 is not 32 points of operational urgency."""
    scores = [causal.to_risk_score(t) for t in (0, 5, 15, 40, 200, 10_000)]
    assert scores == sorted(scores)
    assert scores[0] == 5 and scores[-1] <= 100
    assert scores[-1] - scores[-3] < 20, "the top of the range should compress"


# -- declining to guess ----------------------------------------------------


def test_too_few_rows_returns_an_unfitted_model():
    tiny = _planted(n=causal.MIN_ROWS - 1)
    m = causal.learn_dag(tiny, FEATURES)
    assert not m.fitted, "should decline rather than learn a graph from nothing"


def test_unfitted_model_scores_nothing_rather_than_guessing():
    m = causal.CausalModel(features=FEATURES)
    out = causal.blast_radius(m, [9.0, 9.0, 9.0, 9.0])
    assert out["fitted"] is False and out["total"] == 0.0


def test_mismatched_feature_count_is_refused():
    assert not causal.learn_dag(_planted(), ["a", "b"]).fitted


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
