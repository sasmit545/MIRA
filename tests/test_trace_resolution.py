"""An evidence reference resolves to the full observation behind it.

This is the retrieval half of the contract: the orchestrator receives a
sentence and an identifier, and pulls the raw capability output only when it
actually needs it. The trace file already holds every full result, so nothing
else has to persist them.
"""

import json

from support import ToolThenReportModel

from mira.agents.static.agent import StaticAgent
from mira.core.objective import InvestigationObjective
from mira.core.state import InvestigationState
from mira.reasoning.composition import build_run_id
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
OBJECTIVE = InvestigationObjective(
    name="Assess packing",
    description="Assess whether the sample is packed.",
    reason="test",
    capabilities=("detect_packer", "calculate_entropy"),
)


class ScriptedClient:
    async def invoke(self, capability, artifact_id, **payload):
        return {"detect_packer": PACKED, "calculate_entropy": ENTROPY}[capability]


async def run(tmp_path, *capabilities):
    """Return the evidence a run produced. The returned message carries only
    identifiers, so the records themselves come from the shared state."""
    agent = StaticAgent(
        ScriptedClient(), model=ToolThenReportModel(*capabilities), trace_dir=tmp_path
    )
    state = InvestigationState()
    await agent.investigate(OBJECTIVE, "sample-1", state=state)
    return state.evidence


async def test_evidence_resolves_to_the_observation_that_produced_it(tmp_path):
    evidence = await run(tmp_path, "detect_packer")

    item = evidence[0]
    observation = resolve_observation(tmp_path, item.provenance)

    assert observation is not None
    assert observation["call"]["name"] == item.capability
    # The raw output the orchestrator never receives, available on demand.
    assert observation["result"]["output"] == PACKED


async def test_every_evidence_reference_in_a_run_resolves(tmp_path):
    """Resolution happens after the loop returned and State went out of scope."""
    evidence = await run(tmp_path, "detect_packer", "calculate_entropy")

    assert len(evidence) == 2
    for item in evidence:
        observation = resolve_observation(tmp_path, item.provenance)
        assert observation is not None
        assert observation["call"]["name"] == item.capability


async def test_each_capability_resolves_to_its_own_observation(tmp_path):
    """Two results in one run must not both resolve to the first one."""
    evidence = await run(tmp_path, "detect_packer", "calculate_entropy")

    resolved = {
        item.capability: resolve_observation(tmp_path, item.provenance)["result"]["output"]
        for item in evidence
    }

    assert resolved == {"detect_packer": PACKED, "calculate_entropy": ENTROPY}


def test_an_unknown_run_resolves_to_an_explicit_absence(tmp_path):
    """Asking about an old run is a negative answer, not an exception."""
    assert resolve_observation(
        tmp_path, trace_provenance("never_ran", "detect_packer", 0)
    ) is None


async def test_a_position_past_the_end_of_the_trace_resolves_to_an_absence(tmp_path):
    await run(tmp_path, "detect_packer")
    run_id = build_run_id("sample-1", OBJECTIVE.name)

    assert resolve_observation(
        tmp_path, trace_provenance(run_id, "detect_packer", 99)
    ) is None


async def test_a_capability_never_called_resolves_to_an_absence(tmp_path):
    """Provenance names the capability, so asking for one this run never
    invoked is an absence rather than someone else's observation."""
    await run(tmp_path, "detect_packer")
    run_id = build_run_id("sample-1", OBJECTIVE.name)

    assert resolve_observation(
        tmp_path, trace_provenance(run_id, "calculate_entropy", 0)
    ) is None


async def test_a_malformed_trace_file_resolves_to_an_absence(tmp_path):
    evidence = await run(tmp_path, "detect_packer")
    provenance = evidence[0].provenance
    run_id = build_run_id("sample-1", OBJECTIVE.name)

    with open(trace_path(tmp_path, run_id), "w") as truncated:
        truncated.write('[{"tool_results": [{"tool_c')

    assert resolve_observation(tmp_path, provenance) is None


def test_an_unparseable_provenance_resolves_to_an_absence(tmp_path):
    for provenance in (
        "",
        "no-separator",
        "run#0",  # the old two-part form
        "run#capability#",
        "run#capability#not-a-number",
        "#capability#0",
        "run##0",
    ):
        assert resolve_observation(tmp_path, provenance) is None


async def test_a_trace_holding_no_results_resolves_to_an_absence(tmp_path):
    await run(tmp_path, "detect_packer")
    run_id = build_run_id("sample-1", OBJECTIVE.name)

    with open(trace_path(tmp_path, run_id), "w") as empty:
        json.dump([], empty)

    assert resolve_observation(
        tmp_path, trace_provenance(run_id, "detect_packer", 0)
    ) is None


REFUSED_OBJECTIVE = InvestigationObjective(
    name="Assess packing",
    description="Assess whether the sample is packed.",
    reason="test",
    capabilities=("detect_packer",),  # scan_yara is deliberately not permitted
)


async def test_a_refused_call_does_not_shift_later_provenance(tmp_path):
    """A capability outside the objective is refused before the executor runs,
    but the trace still records the attempt. Evidence minted afterwards must
    still resolve to the observation that actually produced it."""
    agent = StaticAgent(
        ScriptedClient(),
        model=ToolThenReportModel("scan_yara", "detect_packer"),
        trace_dir=tmp_path,
    )
    state = InvestigationState()

    await agent.investigate(REFUSED_OBJECTIVE, "sample-1", state=state)

    assert state.evidence, "the permitted capability produced no evidence"
    for item in state.evidence:
        observation = resolve_observation(tmp_path, item.provenance)
        assert observation is not None
        assert observation["call"]["name"] == item.capability
        assert observation["result"]["output"] == PACKED
