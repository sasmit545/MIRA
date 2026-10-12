"""Tests for the working-memory contract."""

import json

import pytest

from mira.core import hypothesis as core
from mira.reasoning.contracts.memory import MemoryHypothesis, WorkingMemory
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


def test_a_misnamed_text_field_is_coerced_not_rejected():
    """A live model wrote candidates as {"id", "question"}; ambiguity still rejects."""
    from mira.reasoning.runtime.narrative import apply_narrative

    def update(candidates):
        return {"understanding": "", "hypotheses": [], "open_questions": [], "candidates": candidates}

    memory = WorkingMemory()
    assert apply_narrative(memory, update([{"id": "C1", "question": "Check the overlay."}]), set()) == ("", [])
    assert memory.candidates[0].investigation == "Check the overlay."

    two = [{"id": "C2", "question": "a", "description": "b"}]
    assert "candidates[0].investigation must be a non-empty string" in apply_narrative(memory, update(two), set())[0]
