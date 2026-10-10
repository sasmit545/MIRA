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
from mira.core.objective import InvestigationObjective
from mira.core.task import InvestigationTask
from mira.agents.static.agent import StaticAgent
from mira.reasoning.contracts.model import ModelResponse
from mira.reasoning.contracts.tool import ToolCall
from support import REPORT, ToolThenReportModel


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


# --- The specialist's first inbound edge into the shared state --------------

PACKED = {
    "status": "ok",
    "data": {"packed": True, "packer": "UPX", "confidence": 0.9, "indicators": ["UPX0"]},
    "metadata": {},
}


class ScriptedClient:
    async def invoke(self, capability, artifact_id, **payload):
        return PACKED


def objective(name: str) -> InvestigationObjective:
    return InvestigationObjective(
        name=name, description=f"{name}.", reason="test", capabilities=("detect_packer",)
    )


async def investigate(tmp_path, name, state=None):
    agent = StaticAgent(ScriptedClient(), model=ToolThenReportModel("detect_packer"), trace_dir=tmp_path)
    return await agent.investigate(objective(name), "sample-1", state=state)


async def test_a_run_deposits_its_evidence_into_the_shared_state(tmp_path):
    state = InvestigationState()

    finding = await investigate(tmp_path, "Assess packing", state)

    assert len(state.evidence) == len(finding.evidence_refs) == 1
    # The message carries identifiers; the records themselves live in the state.
    for reference in finding.evidence_refs:
        assert state.get_evidence_by_id(reference) is not None


async def test_two_objectives_accumulate_rather_than_replace(tmp_path):
    state = InvestigationState()

    await investigate(tmp_path, "Assess packing", state)
    await investigate(tmp_path, "Assess capability", state)

    assert len(state.evidence) == 2
    assert {evidence.capability for evidence in state.evidence} == {"detect_packer"}


async def test_identifiers_stay_unique_across_runs_sharing_one_state(tmp_path):
    """Two findings citing 'E1' from different runs would be unresolvable."""
    state = InvestigationState()

    await investigate(tmp_path, "Assess packing", state)
    await investigate(tmp_path, "Assess capability", state)

    identifiers = [evidence.id for evidence in state.evidence]
    assert identifiers == sorted(set(identifiers), key=identifiers.index)
    assert len(set(identifiers)) == 2


async def test_a_run_given_no_state_is_unaffected(tmp_path):
    """The CLI path supplies no shared state and must behave as before."""
    finding = await investigate(tmp_path, "Assess packing")

    assert finding.evidence_refs == ["E1"]


async def test_the_deposit_is_logged_once_in_the_state_history(tmp_path):
    """add_evidence already logs; the specialist must not log in parallel."""
    state = InvestigationState()

    await investigate(tmp_path, "Assess packing", state)

    added = [entry for entry in state.history if entry["change_type"] == "evidence_added"]
    assert len(added) == 1


# --- Hypotheses promote on a reported completion only (U7) ------------------


def notes(*hypotheses, **fields):
    return {"understanding": "", "hypotheses": list(hypotheses), "open_questions": [], "candidates": [], **fields}


PACKER_CALL = ToolCall(tool_call_id="p", name="detect_packer", arguments={})
FIRST = notes(
    {"id": "H1", "statement": "Packed with UPX.", "confidence": 0.5, "status": "open"},
    understanding="Triage.",
    open_questions=[{"id": "Q1", "question": "What does the unpacked code do?"}],
)


def second(evidence_id="E1"):
    """Revises H1 against the evidence and adds H2, on a later turn than the call."""
    return notes(
        {"id": "H1", "confidence": 0.2, "status": "weakened", "contradicting_evidence": [evidence_id],
         "unknowns": "whether the stub is custom"},
        {"id": "H2", "statement": "A custom packer.", "confidence": 0.7, "status": "supported",
         "supporting_evidence": [evidence_id]},
        understanding="Packed, but not plain UPX.",
    )


class NotesModel:
    """Replays its responses, repeating the last; records the shared state's
    hypotheses as each prompt arrives."""

    def __init__(self, state, *responses):
        self.state = state
        self.responses = list(responses)
        self.seen = []

    def generate(self, context, tools, force=None):
        if force == "record_memory":
            return ModelResponse()  # declines the forced notes call; the script is not consumed
        self.seen.append(len(self.state.hypotheses) if self.state is not None else None)
        return self.responses[min(len(self.seen) - 1, len(self.responses) - 1)]


def reported(evidence_id="E1"):
    return (
        ModelResponse(tool_calls=[PACKER_CALL], memory_update=FIRST),
        ModelResponse(memory_update=second(evidence_id)),
        ModelResponse(report=REPORT),
    )


REPORTED = reported()


async def run_notes(tmp_path, state, *responses, name="Assess packing", max_turns=10):
    model = NotesModel(state, *responses)
    agent = StaticAgent(ScriptedClient(), model=model, trace_dir=tmp_path, max_turns=max_turns)
    return model, await agent.investigate(objective(name), "sample-1", state=state)


async def test_a_reported_run_promotes_its_latest_notes(tmp_path):
    state = InvestigationState()

    model, _ = await run_notes(tmp_path, state, *REPORTED)

    assert model.seen == [0, 0, 0]  # nothing deposited mid-run
    h1, h2 = state.get_hypothesis_by_id("H1"), state.get_hypothesis_by_id("H2")
    assert (h1.statement, h1.confidence, h1.status) == ("Packed with UPX.", 0.2, "weakened")
    assert h1.contradicting_evidence == ["E1"]
    assert (h2.status, h2.supporting_evidence) == ("supported", ["E1"])
    for hypothesis in state.hypotheses:
        for ref in hypothesis.supporting_evidence + hypothesis.contradicting_evidence:
            assert state.get_evidence_by_id(ref) is not None
    added = [entry for entry in state.history if entry["change_type"] == "hypothesis_added"]
    assert len(added) == 2


async def test_the_assessment_names_hypotheses_unknowns_and_open_questions(tmp_path):
    _, finding = await run_notes(tmp_path, InvestigationState(), *REPORTED)

    assert finding.assessment.startswith("suspicious: done")
    assert "Understanding: Packed, but not plain UPX." in finding.assessment
    assert "- H1 (weakened, 0.20) Packed with UPX. — unknown: whether the stub is custom" in finding.assessment
    assert "- H2 (supported, 0.70) A custom packer." in finding.assessment
    assert "- What does the unpacked code do?" in finding.assessment


async def test_a_degraded_run_deposits_evidence_but_no_hypotheses(tmp_path):
    state = InvestigationState()
    bad = ModelResponse(memory_update=notes({"id": "H1", "supporting_evidence": ["E99"]}))

    _, finding = await run_notes(tmp_path, state, REPORTED[0], bad)

    assert finding.assessment.startswith("inconclusive:")
    assert len(state.evidence) == 1
    assert state.hypotheses == []


async def test_a_run_out_of_turns_promotes_nothing(tmp_path):
    state = InvestigationState()

    await run_notes(tmp_path, state, *REPORTED[:2], max_turns=2)

    assert state.hypotheses == []


async def test_a_run_without_state_still_reports_its_notes(tmp_path):
    _, finding = await run_notes(tmp_path, None, *REPORTED)

    assert "- H2 (supported, 0.70) A custom packer." in finding.assessment


async def test_promoted_ids_continue_past_what_the_state_holds(tmp_path):
    state = InvestigationState()
    state.add_hypothesis(Hypothesis(id="H1", statement="Earlier belief."))

    _, first = await run_notes(tmp_path, state, *REPORTED)
    # The second run mints E2, so its notes cite that.
    _, later = await run_notes(tmp_path, state, *reported("E2"), name="Assess capability")

    assert [h.id for h in state.hypotheses] == ["H1", "H2", "H3", "H4", "H5"]
    assert state.hypotheses[0].statement == "Earlier belief."
    # The assessment cites the ids a reader can look up in the state.
    assert "- H2 (weakened" in first.assessment and "- H3 (supported" in first.assessment
    assert "- H4 (weakened" in later.assessment
    assert state.get_hypothesis_by_id("H5").supporting_evidence == ["E2"]
