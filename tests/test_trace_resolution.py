"""An evidence reference resolves to the full observation behind it.

This is the retrieval half of the contract: the orchestrator receives a
sentence and an identifier, and pulls the raw capability output only when it
actually needs it. The trace file already holds every full result, so nothing
else has to persist them.
"""

import json

from mira.agents.static.agent import StaticAgent
from mira.core.objective import InvestigationObjective
from mira.reasoning.contracts.model import ModelResponse
from mira.reasoning.contracts.tool import ToolCall
from mira.reasoning.runtime.trace import resolve_observation, trace_path, trace_provenance

PACKED = {
    "status": "ok",
    "data": {"packed": True, "packer": "UPX", "confidence": 0.9, "indicators": ["UPX0 section"]},
    "metadata": {"capability": "detect_packer"},
}
ENTROPY = {
    "status": "ok",
    "data": {"entropy": 7.8, "offset": 0, "length": 4096},
    "metadata": {"capability": "calculate_entropy"},
}
REPORT = '{"summary": "done", "verdict": "suspicious", "findings": []}'

OBJECTIVE = InvestigationObjective(
    name="Assess packing",
    description="Assess whether the sample is packed.",
    reason="test",
    capabilities=("detect_packer", "calculate_entropy"),
)


class ScriptedClient:
    async def invoke(self, capability, artifact_id, **payload):
        return {"detect_packer": PACKED, "calculate_entropy": ENTROPY}[capability]


class ToolThenReportModel:
    def __init__(self, *tool_names):
        self.pending = list(tool_names)

    def generate(self, context, tools):
        if self.pending:
            name = self.pending.pop(0)
            return ModelResponse(tool_calls=[ToolCall(tool_call_id=name, name=name, arguments={})])
        return ModelResponse(report=REPORT)


async def run(tmp_path, *capabilities):
    agent = StaticAgent(
        ScriptedClient(), model=ToolThenReportModel(*capabilities), trace_dir=tmp_path
    )
    return await agent.investigate(OBJECTIVE, "sample-1")


async def test_evidence_resolves_to_the_observation_that_produced_it(tmp_path):
    finding = await run(tmp_path, "detect_packer")

    evidence = finding.evidence[0]
    observation = resolve_observation(tmp_path, evidence.provenance)

    assert observation is not None
    assert observation["call"]["name"] == evidence.capability
    # The raw output the orchestrator never receives, available on demand.
    assert observation["result"]["output"] == PACKED


async def test_every_evidence_reference_in_a_run_resolves(tmp_path):
    """Resolution happens after the loop returned and State went out of scope."""
    finding = await run(tmp_path, "detect_packer", "calculate_entropy")

    assert len(finding.evidence) == 2
    for evidence in finding.evidence:
        observation = resolve_observation(tmp_path, evidence.provenance)
        assert observation is not None
        assert observation["call"]["name"] == evidence.capability


async def test_each_capability_resolves_to_its_own_observation(tmp_path):
    """Two results in one run must not both resolve to the first one."""
    finding = await run(tmp_path, "detect_packer", "calculate_entropy")

    resolved = {
        evidence.capability: resolve_observation(tmp_path, evidence.provenance)["result"]["output"]
        for evidence in finding.evidence
    }

    assert resolved == {"detect_packer": PACKED, "calculate_entropy": ENTROPY}


def test_an_unknown_run_resolves_to_an_explicit_absence(tmp_path):
    """Asking about an old run is a negative answer, not an exception."""
    assert resolve_observation(tmp_path, trace_provenance("never_ran", 0)) is None


async def test_a_position_past_the_end_of_the_trace_resolves_to_an_absence(tmp_path):
    finding = await run(tmp_path, "detect_packer")
    run_id, _, _ = finding.evidence[0].provenance.rpartition("#")

    assert resolve_observation(tmp_path, trace_provenance(run_id, 99)) is None


async def test_a_malformed_trace_file_resolves_to_an_absence(tmp_path):
    finding = await run(tmp_path, "detect_packer")
    provenance = finding.evidence[0].provenance
    run_id, _, _ = provenance.rpartition("#")

    with open(trace_path(tmp_path, run_id), "w") as truncated:
        truncated.write('[{"tool_results": [{"tool_c')

    assert resolve_observation(tmp_path, provenance) is None


def test_an_unparseable_provenance_resolves_to_an_absence(tmp_path):
    for provenance in ("", "no-separator", "run#", "run#not-a-number", "#0"):
        assert resolve_observation(tmp_path, provenance) is None


async def test_a_trace_holding_no_results_resolves_to_an_absence(tmp_path):
    finding = await run(tmp_path, "detect_packer")
    run_id, _, _ = finding.evidence[0].provenance.rpartition("#")

    with open(trace_path(tmp_path, run_id), "w") as empty:
        json.dump([], empty)

    assert resolve_observation(tmp_path, trace_provenance(run_id, 0)) is None
