"""The Coordinator sets the objective; the model picks tools within it.

Tool choice is no longer a fixed sequence, so these tests script the *model*
rather than asserting a hardcoded capability order. What must stay true is
that evidence from one objective changes the next one.
"""

import json

from mira.agents.base import Specialist
from mira.reasoning.composition import build_run_id
from mira.agents.static.agent import StaticAgent
from mira.core.coordinator import StaticCoordinator
from mira.core.state import InvestigationState
from mira.reasoning.contracts.model import ModelResponse
from mira.reasoning.contracts.tool import ToolCall

RESPONSES = {
    "file_info": {"status": "ok", "data": {"entropy": 7.8}, "metadata": {}},
    "analyze_pe": {
        "status": "ok",
        "data": {"sections": [{"name": ".text", "entropy": 7.9}]},
        "metadata": {},
    },
    "detect_packer": {
        "status": "ok",
        "data": {"packed": True, "indicators": ["high entropy"]},
        "metadata": {},
    },
    "extract_strings": {"status": "ok", "data": {"strings": []}, "metadata": {}},
}

REPORT = '{"summary": "done", "verdict": "suspicious", "findings": []}'


class ScriptedClient:
    def __init__(self):
        self.calls = []

    async def invoke(self, capability, artifact_id, **payload):
        self.calls.append(capability)
        return RESPONSES[capability]


class ToolThenReportModel:
    """Calls each named tool once, then submits a report.

    Stands in for a real model choosing capabilities. It also records the
    tools it was offered each turn, which is how we check the objective
    actually bounds the choice.
    """

    def __init__(self, *tool_names):
        self.pending = list(tool_names)
        self.offered = []

    def generate(self, context, tools):
        self.offered.append([spec.name for spec in tools])
        if self.pending:
            name = self.pending.pop(0)
            return ModelResponse(
                tool_calls=[ToolCall(tool_call_id=name, name=name, arguments={})]
            )
        return ModelResponse(report=REPORT)


def build_agent(client, tmp_path, *tool_names):
    return StaticAgent(
        client,
        model=ToolThenReportModel(*tool_names),
        trace_dir=tmp_path,
    )


def test_static_agent_satisfies_the_specialist_interface():
    """Dynamic and Forensics will qualify the same way: structurally."""
    assert isinstance(StaticAgent(ScriptedClient()), Specialist)


async def test_evidence_changes_the_second_static_objective(tmp_path):
    """The milestone's success criterion, with tool choice left to the model."""
    client = ScriptedClient()
    coordinator = StaticCoordinator()
    # Evidence reaches the next objective through the shared state now: the
    # returned message carries identifiers, not the records.
    state = InvestigationState()

    first_objective = coordinator.select_next_objective(state.evidence)
    await build_agent(client, tmp_path, "analyze_pe").investigate(
        first_objective, "sample-1", state=state
    )

    second_objective = coordinator.select_next_objective(state.evidence)
    second_finding = await build_agent(client, tmp_path, "detect_packer").investigate(
        second_objective, "sample-1", state=state
    )

    assert first_objective.name == "Characterize sample"
    assert second_objective.name == "Assess packing indicators"
    packing = [item for item in state.evidence if item.capability == "detect_packer"]
    assert packing, "the packing objective produced no evidence"
    assert "packer" in packing[0].observation.lower()
    assert packing[0].id in second_finding.evidence_refs


async def test_the_model_chooses_a_subset_of_the_objective(tmp_path):
    """The old fixed pipeline ran every capability; the model need not."""
    client = ScriptedClient()
    objective = StaticCoordinator().select_next_objective([])

    await build_agent(client, tmp_path, "analyze_pe").investigate(objective, "sample-1")

    assert client.calls == ["analyze_pe"]
    assert "file_info" in objective.capabilities


async def test_the_objective_bounds_the_tools_on_offer(tmp_path):
    client = ScriptedClient()
    objective = StaticCoordinator().select_next_objective([])
    model = ToolThenReportModel("file_info")

    await StaticAgent(client, model=model, trace_dir=tmp_path).investigate(
        objective, "sample-1"
    )

    assert set(model.offered[0]) == set(objective.capabilities)


async def test_a_capability_outside_the_objective_is_refused(tmp_path):
    """The Coordinator's objective is a boundary, not a suggestion."""
    client = ScriptedClient()
    objective = StaticCoordinator().select_next_objective([])

    finding = await build_agent(client, tmp_path, "detect_packer").investigate(
        objective, "sample-1"
    )

    assert "detect_packer" not in client.calls
    # The refusal no longer rides the returned message, which carries no raw
    # results at all. It is recorded where every full observation lives.
    trace = json.loads(
        (tmp_path / f"trace_{build_run_id('sample-1', objective.name)}.json").read_text()
    )
    errors = [result.get("error") for turn in trace for result in turn["tool_results"]]
    assert any("Unknown tool" in (error or "") for error in errors)
    assert finding.assessment


class SilentModel:
    """Never calls a tool and never reports - the degraded exit."""

    def generate(self, context, tools):
        return ModelResponse()


async def test_a_run_with_no_report_still_returns_a_well_formed_message(tmp_path):
    """The orchestrator gets the same shape whether or not the model delivered."""
    objective = StaticCoordinator().select_next_objective([])

    finding = await StaticAgent(
        ScriptedClient(), model=SilentModel(), trace_dir=tmp_path
    ).investigate(objective, "sample-1")

    assert finding.artifact_id == "sample-1"
    assert finding.assessment.startswith("inconclusive:")
    assert finding.findings == []
    assert finding.evidence_refs == []
    assert finding.confidence == "low"
    assert finding.recommended_actions == []
