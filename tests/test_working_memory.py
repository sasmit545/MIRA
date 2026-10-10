"""Tests for the working-memory contract."""

import json

import pytest

from mira.core import hypothesis as core
from mira.reasoning.contracts.memory import MemoryHypothesis
from mira.reasoning.contracts.objective import Objective
from mira.reasoning.contracts.state import State


def test_hypothesis_keeps_supporting_and_contradicting_evidence_apart():
    h = MemoryHypothesis(id="H1", statement="packed", supporting_evidence=["E1"], contradicting_evidence=["E2"])
    assert h.supporting_evidence == ["E1"] and h.contradicting_evidence == ["E2"]


def test_confidence_is_clamped():
    assert MemoryHypothesis(id="H1", statement="x", confidence=1.7).confidence == 1.0
    assert MemoryHypothesis(id="H1", statement="x", confidence=-1).confidence == 0.0


def test_status_accepts_provisional_and_rejects_the_rest():
    for status in core.PROVISIONAL:
        assert MemoryHypothesis(id="H1", statement="x", status=status).status == status
    for bad in (core.CONFIRMED, core.REJECTED, "bogus"):
        with pytest.raises(ValueError):
            MemoryHypothesis(id="H1", statement="x", status=bad)


def test_snapshot_serializes_memory_and_drops_scratch():
    state = State(objective=Objective(description="o"), run_id="r")
    state.working_memory.hypotheses.append(MemoryHypothesis(id="H1", statement="packed"))
    snap = state.snapshot()
    assert "scratch" not in snap
    assert json.loads(json.dumps(snap))["working_memory"]["hypotheses"][0]["id"] == "H1"
    assert state.evidence == [] and state.observations == []
