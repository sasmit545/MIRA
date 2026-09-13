"""InvestigationState is the shared memory three specialists write into.

With one agent it is optional bookkeeping. With three it is the point, so it
has to survive a real serialization boundary rather than merely importing.
"""

import json
from pathlib import Path

from mira.core.artifact import Artifact
from mira.core.evidence import Evidence
from mira.core.hypothesis import Hypothesis
from mira.core.state import InvestigationState
from mira.core.task import InvestigationTask


def build_state() -> InvestigationState:
    state = InvestigationState()
    state.sample = "sample.exe"
    state.add_artifact(
        Artifact(
            artifact_id="artifact_001",
            path=Path("/samples/sample.exe"),
            file_type="pe",
            size=1024,
            sha256="ab" * 32,
        )
    )
    state.add_evidence(
        Evidence(
            id="E1",
            observation="Section .text has entropy 7.9",
            source_agent="static_agent",
            capability="analyze_pe",
            artifact_id="artifact_001",
            confidence=0.8,
        )
    )
    state.add_hypothesis(
        Hypothesis(
            id="H1",
            statement="Sample is packed",
            confidence=0.72,
            supporting_evidence=["E1"],
        )
    )
    state.add_task(
        InvestigationTask(
            id="T1",
            objective="Assess packing indicators",
            specialist="static",
            status="pending",
            evidence_required=["E1"],
        )
    )
    return state


def test_state_round_trips_through_a_dict():
    restored = InvestigationState.from_dict(build_state().to_dict())

    assert restored.sample == "sample.exe"
    assert [artifact.artifact_id for artifact in restored.artifacts] == ["artifact_001"]
    assert [evidence.id for evidence in restored.evidence] == ["E1"]
    assert [hypothesis.id for hypothesis in restored.hypotheses] == ["H1"]
    assert [task.id for task in restored.tasks] == ["T1"]


def test_state_survives_json():
    """A dict round-trip alone would hide Path and datetime fields."""
    restored = InvestigationState.from_dict(json.loads(json.dumps(build_state().to_dict())))

    assert restored.artifacts[0].path == Path("/samples/sample.exe")
    assert restored.artifacts[0].size == 1024
    assert restored.artifacts[0].file_type == "pe"


def test_round_trip_preserves_hypothesis_links():
    hypothesis = InvestigationState.from_dict(build_state().to_dict()).hypotheses[0]

    assert hypothesis.statement == "Sample is packed"
    assert hypothesis.confidence == 0.72
    assert hypothesis.supporting_evidence == ["E1"]
    assert hypothesis.contradicting_evidence == []
    assert hypothesis.status == "open"


def test_round_trip_preserves_task_dependencies():
    task = InvestigationState.from_dict(build_state().to_dict()).tasks[0]

    assert task.objective == "Assess packing indicators"
    assert task.specialist == "static"
    assert task.status == "pending"
    assert task.evidence_required == ["E1"]
    assert task.depends_on == []


def test_evidence_keeps_its_source_agent():
    """source_agent is how the Coordinator tells specialists apart."""
    restored = InvestigationState.from_dict(build_state().to_dict())

    assert restored.evidence[0].source_agent == "static_agent"
    assert restored.evidence[0].capability == "analyze_pe"


def test_history_records_every_addition():
    kinds = [entry["change_type"] for entry in build_state().history]

    assert kinds == [
        "artifact_added",
        "evidence_added",
        "hypothesis_added",
        "task_added",
    ]


def test_task_status_update_is_recorded():
    state = build_state()

    state.update_task_status("T1", "completed")

    assert state.get_task_by_id("T1").status == "completed"
    assert state.history[-1]["change_type"] == "task_status_updated"


def test_hypothesis_confidence_is_clamped():
    assert Hypothesis(id="H1", statement="x", confidence=1.5).confidence == 1.0
    assert Hypothesis(id="H2", statement="x", confidence=-0.5).confidence == 0.0


def test_evidence_moves_a_hypothesis_off_open():
    """Evidence is what changes a belief — the point of tracking hypotheses."""
    hypothesis = Hypothesis(id="H1", statement="Sample is packed")

    hypothesis.support("E1", confidence=0.8)

    assert hypothesis.supporting_evidence == ["E1"]
    assert hypothesis.confidence == 0.8
    assert hypothesis.status == "supported"


def test_contradicting_evidence_weakens_a_hypothesis():
    hypothesis = Hypothesis(id="H1", statement="Sample is packed", confidence=0.8)

    hypothesis.contradict("E2", confidence=0.3)

    assert hypothesis.contradicting_evidence == ["E2"]
    assert hypothesis.confidence == 0.3
    assert hypothesis.status == "weakened"
