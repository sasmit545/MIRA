"""The Coordinator sets the objective; the model picks tools within it.

Tool choice is no longer a fixed sequence, so these tests script the *model*
rather than asserting a hardcoded capability order. What must stay true is
that evidence from one objective changes the next one.
"""

import json

import pytest

from support import EMPTY_NOTES, NoNotesModel, ToolThenReportModel

from mira.agents.base import Specialist
from mira.reasoning.composition import build_run_id
from mira.agents.static.agent import StaticAgent
from mira.core.coordinator import StaticCoordinator
from mira.core.state import InvestigationState
from mira.reasoning.contracts.finding import Confidence
from mira.reasoning.contracts.model import ModelResponse
from mira.reasoning.contracts.tool import ToolCall
from mira.reasoning.runtime.completion import MAX_MEMORY_REJECTIONS


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

class ScriptedClient:
    def __init__(self):
        self.calls = []

    async def invoke(self, capability, artifact_id, **payload):
        self.calls.append(capability)
        return RESPONSES[capability]


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

    def generate(self, context, tools, force=None):
        if force == "record_memory":
            return ModelResponse()  # declines the forced notes call; the script is not consumed
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
    assert finding.confidence is Confidence.LOW
    assert finding.recommended_actions == []


@pytest.mark.parametrize(
    "notes, calls",
    # Omitted notes are not owed on the first capability turn; sent ones are
    # always checked, so malformed notes are rejected from turn 1.
    [(None, MAX_MEMORY_REJECTIONS + 1), ({"hypotheses": "not a list"}, MAX_MEMORY_REJECTIONS)],
    ids=["omitted", "malformed"],
)
async def test_a_model_that_never_writes_valid_notes_stops_on_the_rejection_bound(tmp_path, notes, calls):
    """Ends on the total bound, not by exhausting its turns."""
    client = ScriptedClient()
    objective = StaticCoordinator().select_next_objective([])
    state = InvestigationState()

    finding = await StaticAgent(
        client, model=NoNotesModel("file_info", notes), trace_dir=tmp_path, max_turns=10
    ).investigate(objective, "sample-1", state=state)

    assert len(client.calls) == calls
    assert finding.assessment.startswith("inconclusive:")
    assert state.hypotheses == []


class RepeatingModel:
    """Calls file_info with notes, then repeats that exact call every turn."""

    def __init__(self, repeat_notes=None):
        self.repeat_notes = repeat_notes
        self.turns = 0

    def generate(self, context, tools, force=None):
        if force == "record_memory":
            return ModelResponse()  # declines the forced notes call; the script is not consumed
        self.turns += 1
        call = ToolCall(tool_call_id=str(self.turns), name="file_info", arguments={})
        notes = dict(EMPTY_NOTES) if self.turns == 1 else self.repeat_notes
        if callable(notes):
            notes = notes(self.turns)
        return ModelResponse(tool_calls=[call], memory_update=notes)


async def test_a_model_that_only_repeats_a_call_ends_degraded_not_at_max_turns(tmp_path):
    """Each refused rerun is an empty turn; two in a row end the run."""
    client = ScriptedClient()
    model = RepeatingModel()
    objective = StaticCoordinator().select_next_objective([])

    finding = await StaticAgent(client, model=model, trace_dir=tmp_path, max_turns=10).investigate(
        objective, "sample-1"
    )

    assert client.calls == ["file_info"]  # the repeats were refused, never run
    assert model.turns == 3
    assert finding.assessment.startswith("inconclusive:")


async def test_a_repeat_with_unchanged_notes_is_not_progress(tmp_path):
    """Refused reruns and notes that change nothing did nothing (KTD8)."""
    model = RepeatingModel(repeat_notes=dict(EMPTY_NOTES))
    objective = StaticCoordinator().select_next_objective([])

    await StaticAgent(ScriptedClient(), model=model, trace_dir=tmp_path, max_turns=5).investigate(
        objective, "sample-1"
    )

    assert model.turns == 3


async def test_a_repeat_sent_with_new_notes_is_still_progress(tmp_path):
    """The model is still reasoning, so only the turn limit bounds it."""
    model = RepeatingModel(repeat_notes=lambda turn: {**EMPTY_NOTES, "understanding": f"Reconsidered on turn {turn}."})
    objective = StaticCoordinator().select_next_objective([])

    await StaticAgent(ScriptedClient(), model=model, trace_dir=tmp_path, max_turns=5).investigate(
        objective, "sample-1"
    )

    assert model.turns == 5 + 1  # every turn, then the report-only turn


# --- The list_imports slice, end to end (U9) ---------------------------------

import re
from pathlib import Path

from support import PagedImports

from mira.agents.static.wiring import STATIC_ROLE, STATIC_SCOPE, build_evidence_executor, build_executor, tool_manifest
from mira.reasoning.composition import build_loop, build_tracer
from mira.reasoning.contracts.objective import Objective
from mira.reasoning.contracts.output import FinalOutput
from mira.reasoning.definition.agent import AgentDefinition
from mira.reasoning.runtime.tool_runtime import ToolRuntime
from mira.reasoning.runtime.trace import resolve_observation

SLICE_RUN = "slice_run"
IMPORTS_HANDLE = f"{SLICE_RUN}#list_imports#0"
LATE_INJECTION = 1500


def import_rows(count=2000):
    rows = [
        {"dll": ("KERNEL32.dll", "USER32.dll")[index % 2], "name": f"Fn{index}", "ordinal": None, "address": 4096 + index}
        for index in range(count)
    ]
    if count > LATE_INJECTION:
        rows[LATE_INJECTION]["name"] = "VirtualAllocEx"
    return rows


def injection_id(context):
    found = re.search(r"^\s+(E\d+) \[list_imports\] Imports associated with process injection", context, re.MULTILINE)
    return found.group(1) if found else None


class ImportSliceModel:
    """Collects the imports, recalls exactly the slice it needs, writes notes,
    tries to cite a recalled item instead of evidence, then reports."""

    def __init__(self):
        self.contexts = []

    def generate(self, context, tools, force=None):
        if force == "record_memory":
            return ModelResponse()
        self.contexts.append(context)
        turn = len(self.contexts)
        if turn == 1:
            return ModelResponse(tool_calls=[ToolCall("1", "list_imports", {})])
        cited = injection_id(context)
        if turn == 2:
            return ModelResponse(
                tool_calls=[
                    ToolCall("r1", "recall_observation", {"handle": IMPORTS_HANDLE, "path": "data.imports", "where": {"name": "virtualallocex"}}),
                    ToolCall("r2", "recall_observation", {"handle": IMPORTS_HANDLE, "path": "data.imports", "group_by": "dll"}),
                ],
                memory_update={**EMPTY_NOTES, "hypotheses": [
                    {"id": "H1", "statement": "Injects into other processes.", "confidence": 0.6, "status": "open",
                     "supporting_evidence": [cited]},
                ]},
            )
        refs = ["data.imports.1500"] if turn == 3 else [cited]
        return ModelResponse(report=json.dumps({
            "summary": "Imports a process-injection API late in a large table.",
            "verdict": "suspicious",
            "findings": [{"title": "Process injection import", "description": "VirtualAllocEx is imported.",
                          "severity": "medium", "confidence": "medium", "evidence_refs": refs}],
        }))


async def run_slice(tmp_path, client, model):
    """Composed as the CLI composes it, over a fake client instead of the MCP server."""
    manifest = tool_manifest()
    permitted = [spec for spec in manifest if spec.name == "list_imports"]
    evidence = []
    execute = build_evidence_executor(build_executor(client, "sample"), run_id=SLICE_RUN, artifact_id="sample", evidence=evidence)
    definition = AgentDefinition(
        role=STATIC_ROLE, scope=STATIC_SCOPE, tool_manifest=manifest, allowed_tools=permitted,
        max_turns=10, max_tool_calls=20, output_contract=FinalOutput,
    )
    loop = build_loop(tool_runtime=ToolRuntime(permitted, execute), tracer=build_tracer(run_id=SLICE_RUN, trace_dir=tmp_path), model=model)
    output = await loop.run(Objective(description="Assess what the imports reveal"), definition, evidence=evidence)
    return output, evidence


@pytest.fixture
async def import_slice(tmp_path):
    client, model = PagedImports(0, imports=import_rows()), ImportSliceModel()
    output, evidence = await run_slice(tmp_path, client, model)
    return output, evidence, client, model, tmp_path


async def test_the_report_cites_evidence_for_an_import_deep_in_the_list(import_slice):
    output, evidence, client, _, trace_dir = import_slice

    assert output.completion_reason == "reported"
    (finding,) = output.findings
    (ref,) = [item for item in evidence if item.id == finding.evidence_refs[0].evidence_id]
    assert "VirtualAllocEx" in ref.observation and "among all 2000 imports" in ref.observation
    assert ref.provenance == IMPORTS_HANDLE
    observation = resolve_observation(trace_dir, ref.provenance)
    assert observation["result"]["output"]["data"]["imports"][LATE_INJECTION]["name"] == "VirtualAllocEx"
    assert len(client.calls) == 2  # two pages, one call


async def test_no_prompt_carries_an_import_record_a_recall_did_not_return(import_slice):
    _, _, _, model, _ = import_slice
    needles = {index: json.dumps(row, sort_keys=True) for index, row in enumerate(import_rows())}

    shown = [{index for index, needle in needles.items() if needle in context} for context in model.contexts]

    assert shown[2] == {LATE_INJECTION}  # the turn after the where recall, and only it
    assert all(not found for turn, found in enumerate(shown) if turn != 2)
    assert '"KERNEL32.dll" 1000' in model.contexts[2]  # the group_by answer is counts, not records


async def test_the_slice_prompt_does_not_grow_with_the_list(import_slice):
    _, _, _, model, _ = import_slice

    assert max(len(context) for context in model.contexts) - len(model.contexts[0]) < 10_000


async def test_the_slice_serves_no_repeat_and_runs_no_duplicate(import_slice):
    output, *_ = import_slice

    assert output.metadata["repeat_recalls"] == 0
    assert output.metadata["reruns_refused"] == 0
    assert output.metadata["recalls_requested"] == 2


async def test_a_finding_citing_a_recalled_item_instead_of_evidence_is_rejected(import_slice):
    _, _, _, model, _ = import_slice

    assert "Report rejected" in model.contexts[3]
    assert "never observed: data.imports.1500" in model.contexts[3]


class EmptyTableModel:
    def __init__(self):
        self.contexts = []

    def generate(self, context, tools, force=None):
        if force == "record_memory":
            return ModelResponse()
        self.contexts.append(context)
        if len(self.contexts) == 1:
            return ModelResponse(tool_calls=[ToolCall("1", "list_imports", {})])
        if len(self.contexts) == 2:
            return ModelResponse(tool_calls=[ToolCall("r", "recall_observation", {
                "handle": IMPORTS_HANDLE, "path": "data.imports", "where": {"name": "VirtualAllocEx"}})])
        return ModelResponse(report='{"summary": "no imports", "verdict": "inconclusive", "findings": []}')


async def test_an_empty_import_table_is_described_and_recalled_as_empty(tmp_path):
    model = EmptyTableModel()

    output, evidence = await run_slice(tmp_path, PagedImports(0), model)

    assert evidence == []
    assert "data.imports (0)" in model.contexts[1] and "fetched 0 of 0" in model.contexts[1]
    assert "0 of 0 items" in model.contexts[2]
    assert output.completion_reason == "reported"
