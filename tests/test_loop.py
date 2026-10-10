"""Tests for AgentLoop."""

import json

from mira.core.evidence import Evidence
from mira.reasoning.contracts.finding import Confidence, Finding, Severity
from mira.reasoning.contracts.model import ModelResponse
from mira.reasoning.contracts.objective import Objective
from mira.reasoning.contracts.output import FinalOutput
from mira.reasoning.contracts.tool import ToolCall, ToolSpec
from mira.reasoning.definition.agent import AgentDefinition
from mira.reasoning.runtime.completion import CompletionChecker
from mira.reasoning.runtime.context import ContextBuilder
from mira.reasoning.runtime.loop import AgentLoop
from mira.reasoning.runtime.tool_runtime import ToolRuntime
from mira.reasoning.runtime.trace import Tracer

REPORT = '{"summary": "test", "verdict": "test", "findings": []}'

# What a compliant model writes when it has nothing new to say (R9).
NOTES = {"understanding": "", "hypotheses": [], "open_questions": [], "candidates": []}

FINDING = {
    "title": "Packed executable",
    "description": "The sample's .text section is packed.",
    "severity": "high",
    "confidence": "medium",
    "evidence_refs": ["E1"],
}


def report(finding=None, **fields):
    """A submitted report carrying one finding, with fields overridden."""
    body = {"summary": "test", "verdict": "suspicious", **fields}
    if finding is not None:
        body["findings"] = [finding]
    return json.dumps(body)


def gathered(*ids):
    """Evidence the specialist minted before the model reported."""
    return [
        Evidence(
            id=identifier,
            observation=f"observation behind {identifier}",
            source_agent="static",
            capability="detect_packer",
            confidence=0.9,
        )
        for identifier in ids
    ]


class ScriptedModel:
    """Plays a sequence of canned responses, repeating the last one."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = 0

    def generate(self, context, tools, force=None):
        if force == "record_memory":
            return ModelResponse()  # declines the forced notes call; the script is not consumed
        response = self.responses[min(self.calls, len(self.responses) - 1)]
        self.calls += 1
        return response


def build_definition(tools=(), max_turns=10, max_tool_calls=10):
    return AgentDefinition(
        role="You are a test investigator.",
        scope="Test scope only.",
        tool_manifest=list(tools),
        allowed_tools=list(tools),
        max_turns=max_turns,
        max_tool_calls=max_tool_calls,
        output_contract=FinalOutput,
    )


def build_loop(model, tmp_path, tools=(), executor=None, on_turn=None):
    return AgentLoop(
        model,
        ToolRuntime(list(tools), executor),
        CompletionChecker(),
        ContextBuilder(),
        Tracer(run_id="test", output_dir=str(tmp_path)),
        on_turn=on_turn,
    )


async def test_loop_reports_immediately(tmp_path):
    loop = build_loop(ScriptedModel(ModelResponse(report=REPORT)), tmp_path)

    result = await loop.run(Objective(description="Test objective"), build_definition())

    assert result.summary == "test"
    assert result.completion_reason == "reported"
    assert result.metadata["turns"] == 0


async def test_loop_stops_after_two_empty_responses(tmp_path):
    loop = build_loop(ScriptedModel(ModelResponse()), tmp_path)

    result = await loop.run(Objective(description="Test objective"), build_definition())

    assert result.completion_reason == "degraded"
    assert result.metadata["turns"] == 2


async def test_loop_writes_a_trace_file(tmp_path):
    loop = build_loop(ScriptedModel(ModelResponse(report=REPORT)), tmp_path)

    await loop.run(Objective(description="Test objective"), build_definition())

    assert (tmp_path / "trace_test.json").is_file()


async def test_malformed_report_is_observed_then_recovered(tmp_path):
    model = ScriptedModel(ModelResponse(report="not json"), ModelResponse(report=REPORT))
    loop = build_loop(model, tmp_path)

    result = await loop.run(Objective(description="Test objective"), build_definition())

    assert result.completion_reason == "reported"
    assert any(not evidence.success for evidence in result.observations)


async def test_tool_failure_is_observed_not_raised(tmp_path):
    spec = ToolSpec(name="boom", description="fails", parameters={})

    def executor(name, arguments):
        raise RuntimeError("capability exploded")

    model = ScriptedModel(
        ModelResponse(tool_calls=[ToolCall(tool_call_id="1", name="boom", arguments={})]),
        ModelResponse(report=REPORT),
    )
    loop = build_loop(model, tmp_path, tools=[spec], executor=executor)

    result = await loop.run(
        Objective(description="Test objective"), build_definition(tools=[spec])
    )

    assert result.completion_reason == "reported"
    assert "capability exploded" in result.observations[0].error


async def test_unknown_tool_is_observed(tmp_path):
    model = ScriptedModel(
        ModelResponse(tool_calls=[ToolCall(tool_call_id="1", name="nope", arguments={})]),
        ModelResponse(report=REPORT),
    )
    loop = build_loop(model, tmp_path)

    result = await loop.run(Objective(description="Test objective"), build_definition())

    assert "Unknown tool" in result.observations[0].error


async def test_on_turn_sees_each_tool_call_its_notes_and_the_final_report(tmp_path):
    spec = ToolSpec(name="probe", description="probes", parameters={})
    model = ScriptedModel(
        ModelResponse(tool_calls=[ToolCall(tool_call_id="1", name="probe", arguments={})], memory_update=NOTES),
        ModelResponse(report=REPORT),
    )
    events = []
    loop = build_loop(
        model, tmp_path, tools=[spec], executor=lambda name, arguments: "ok", on_turn=events.append
    )

    await loop.run(Objective(description="Test objective"), build_definition(tools=[spec]))

    kinds = [event["kind"] for event in events]
    assert kinds == ["tool_calls", "notes", "report"]
    assert events[0]["calls"][0].name == "probe"


async def test_a_broken_on_turn_callback_does_not_break_the_loop(tmp_path):
    model = ScriptedModel(ModelResponse(report=REPORT))
    loop = build_loop(model, tmp_path, on_turn=lambda event: 1 / 0)

    result = await loop.run(Objective(description="Test objective"), build_definition())

    assert result.completion_reason == "reported"


# --- Findings are typed values, not passthrough model JSON ------------------


async def run_with_evidence(tmp_path, submitted, *evidence_ids):
    """Run one turn where the model submits `submitted` against known evidence."""
    loop = build_loop(ScriptedModel(ModelResponse(report=submitted)), tmp_path)
    return await loop.run(
        Objective(description="Test objective"),
        build_definition(),
        evidence=gathered(*evidence_ids),
    )


async def test_a_valid_finding_becomes_a_typed_finding(tmp_path):
    result = await run_with_evidence(tmp_path, report(FINDING), "E1")

    assert result.completion_reason == "reported"
    finding = result.findings[0]
    assert isinstance(finding, Finding)
    assert finding.severity is Severity.HIGH
    assert finding.confidence is Confidence.MEDIUM
    assert [ref.evidence_id for ref in finding.evidence_refs] == ["E1"]


async def test_no_raw_dictionary_survives_into_the_findings(tmp_path):
    result = await run_with_evidence(tmp_path, report(FINDING), "E1")

    assert all(isinstance(finding, Finding) for finding in result.findings)


async def test_an_unrecognized_severity_is_rejected_and_reaches_the_model(tmp_path):
    """Rejection is an observation the model can recover from, not an exception."""
    submitted = report({**FINDING, "severity": "catastrophic"})
    model = ScriptedModel(ModelResponse(report=submitted), ModelResponse(report=REPORT))
    loop = build_loop(model, tmp_path)

    result = await loop.run(
        Objective(description="Test objective"), build_definition(), evidence=gathered("E1")
    )

    assert result.completion_reason == "reported"
    rejection = next(item for item in result.observations if not item.success)
    assert "severity" in rejection.error
    assert "catastrophic" in rejection.error


async def test_a_finding_naming_unknown_evidence_is_rejected(tmp_path):
    result = await run_with_evidence(
        tmp_path, report({**FINDING, "evidence_refs": ["E9"]}), "E1"
    )

    assert result.completion_reason != "reported"
    assert any("E9" in (item.error or "") for item in result.observations)


async def test_a_finding_missing_its_title_is_rejected(tmp_path):
    submitted = report({key: value for key, value in FINDING.items() if key != "title"})

    result = await run_with_evidence(tmp_path, submitted, "E1")

    assert result.completion_reason != "reported"
    assert any("title" in (item.error or "") for item in result.observations)


async def test_a_finding_citing_no_evidence_is_rejected_when_evidence_exists(tmp_path):
    """A finding the orchestrator cannot check back to an observation is not
    a finding it can act on."""
    result = await run_with_evidence(tmp_path, report({**FINDING, "evidence_refs": []}), "E1")

    assert result.completion_reason != "reported"
    assert any("evidence_refs" in (item.error or "") for item in result.observations)


async def test_a_finding_citing_no_evidence_is_accepted_when_none_was_gathered(tmp_path):
    """Nothing to cite must not deadlock the model into endless rejection."""
    result = await run_with_evidence(tmp_path, report({**FINDING, "evidence_refs": []}))

    assert result.completion_reason == "reported"
    assert result.findings[0].evidence_refs == []


async def test_a_malformed_report_then_a_valid_one_completes_as_reported(tmp_path):
    model = ScriptedModel(
        ModelResponse(report=report({**FINDING, "confidence": "very sure"})),
        ModelResponse(report=report(FINDING)),
    )
    loop = build_loop(model, tmp_path)

    result = await loop.run(
        Objective(description="Test objective"), build_definition(), evidence=gathered("E1")
    )

    assert result.completion_reason == "reported"
    assert result.findings[0].confidence is Confidence.MEDIUM


async def test_recommended_actions_ride_the_report(tmp_path):
    submitted = report(FINDING, recommended_actions=["Run the sample in a sandbox"])

    result = await run_with_evidence(tmp_path, submitted, "E1")

    assert result.recommended_actions == ["Run the sample in a sandbox"]


async def test_a_report_with_no_recommended_actions_is_still_valid(tmp_path):
    result = await run_with_evidence(tmp_path, report(FINDING), "E1")

    assert result.recommended_actions == []


async def test_a_report_does_not_discard_a_capability_call_in_the_same_turn(tmp_path):
    spec = ToolSpec(name="probe", description="d", parameters={})
    executed = []

    async def executor(name, arguments):
        executed.append(name)
        return {"status": "ok"}

    model = ScriptedModel(
        ModelResponse(
            tool_calls=[ToolCall(tool_call_id="1", name="probe", arguments={})],
            report=REPORT,
            memory_update={"understanding": "u"},
        )
    )
    loop = build_loop(model, tmp_path, tools=[spec], executor=executor)

    result = await loop.run(Objective(description="Test objective"), build_definition(tools=[spec]))

    assert executed == ["probe"]
    assert result.completion_reason == "reported"
    assert result.metadata["tool_calls"] == 1


# --- U4: narrative validation, merge and the rejection bound.

PROBE = ToolSpec(name="probe", description="d", parameters={})
CALL = ToolCall(tool_call_id="1", name="probe", arguments={})
# Different arguments, so the harness runs it rather than refusing a rerun.
NEXT_CALL = ToolCall(tool_call_id="2", name="probe", arguments={"page": 2})


def hypothesis(id="H1", **fields):
    return {"id": id, "statement": "packed", "confidence": 0.6, "status": "open", **fields}


def notes(**fields):
    return {**NOTES, **fields}


def counting_executor():
    calls = []

    def executor(name, arguments):
        calls.append(name)
        return {"status": "ok"}

    return calls, executor


async def run_loop(tmp_path, *responses, evidence=None):
    calls, executor = counting_executor()
    loop = build_loop(ScriptedModel(*responses), tmp_path, tools=[PROBE], executor=executor)
    result = await loop.run(
        Objective(description="o"), build_definition(tools=[PROBE]), evidence=evidence
    )
    return loop, result, calls


async def memory_after(tmp_path, *updates):
    """Run one capability turn per update, then report; return the final memory."""
    responses = [ModelResponse(tool_calls=[CALL], memory_update=update) for update in updates]
    responses.append(ModelResponse(report=REPORT))
    calls, executor = counting_executor()
    loop = build_loop(ScriptedModel(*responses), tmp_path, tools=[PROBE], executor=executor)
    captured = {}
    original = loop._merge_narrative

    def spy(state, update):
        captured["state"] = state
        return original(state, update)

    loop._merge_narrative = spy
    await loop.run(Objective(description="o"), build_definition(tools=[PROBE]))
    return captured["state"].working_memory


async def test_a_well_formed_narrative_merges_into_the_memory(tmp_path):
    memory = await memory_after(
        tmp_path, notes(understanding="looks packed", hypotheses=[hypothesis()],
                        open_questions=[{"id": "Q1", "question": "is it packed?"}])
    )

    assert memory.understanding == "looks packed"
    assert [h.id for h in memory.hypotheses] == ["H1"]
    assert [q.id for q in memory.open_questions] == ["Q1"]


async def test_a_status_differing_in_case_or_whitespace_is_coerced(tmp_path):
    memory = await memory_after(tmp_path, notes(hypotheses=[hypothesis(status="  Supported ")]))

    assert memory.hypotheses[0].status == "supported"


async def test_a_missing_narrative_is_rejected_and_the_reason_reaches_the_model(tmp_path):
    loop, result, calls = await run_loop(
        tmp_path,
        ModelResponse(tool_calls=[CALL], memory_update=NOTES),
        ModelResponse(tool_calls=[NEXT_CALL]),
        ModelResponse(report=REPORT),
    )

    rejected = [o.error for o in result.observations if o.error]
    assert len(rejected) == 1
    assert rejected[0].startswith("Notes rejected: record_memory is required on every turn that calls a capability")
    assert calls == ["probe", "probe"]


async def test_the_first_capability_turn_owes_no_notes(tmp_path):
    """Notes reflect results through the previous turn; turn 1 has none."""
    loop, result, calls = await run_loop(
        tmp_path,
        ModelResponse(tool_calls=[CALL]),
        ModelResponse(report=REPORT),
    )

    assert loop.completion.memory_rejections == 0
    assert result.completion_reason == "reported"
    assert calls == ["probe"]


async def test_a_missing_field_means_no_change_and_a_malformed_one_is_named(tmp_path):
    """A live model's forced notes omitted fields it had nothing new for."""
    partial = {"understanding": "Packed.", "hypotheses": [hypothesis()]}
    loop, result, _ = await run_loop(
        tmp_path,
        ModelResponse(tool_calls=[CALL], memory_update=partial),
        ModelResponse(memory_update={"candidates": "not a list"}),
        ModelResponse(report=REPORT),
    )

    assert loop.completion.memory_rejections == 1
    assert [o.error for o in result.observations if o.error] == ["Notes rejected: candidates must be an array"]


async def test_a_rejected_narrative_keeps_the_capability_result_and_does_not_rerun_it(tmp_path):
    _, result, calls = await run_loop(
        tmp_path,
        ModelResponse(tool_calls=[CALL], memory_update={"hypotheses": "not a list"}),
        ModelResponse(report=REPORT),
    )

    assert calls == ["probe"]
    assert result.observations[0].success
    assert result.metadata["tool_calls"] == 1


async def test_a_valid_report_survives_a_malformed_narrative(tmp_path):
    _, result, _ = await run_loop(
        tmp_path, ModelResponse(report=REPORT, memory_update={"hypotheses": "not a list"})
    )

    assert result.completion_reason == "reported"


async def test_a_narrative_leaves_unmentioned_hypotheses_alone(tmp_path):
    memory = await memory_after(
        tmp_path,
        notes(hypotheses=[hypothesis("H1"), hypothesis("H2", statement="injects")]),
        notes(hypotheses=[{"id": "H2", "confidence": 0.9}]),
    )

    by_id = {h.id: h for h in memory.hypotheses}
    assert by_id["H1"].confidence == 0.6
    assert by_id["H2"].confidence == 0.9 and by_id["H2"].statement == "injects"


async def test_closing_by_identifier_removes_an_entry(tmp_path):
    memory = await memory_after(
        tmp_path, notes(hypotheses=[hypothesis()]), notes(close=["H1"])
    )

    assert memory.hypotheses == []


def test_closing_an_unknown_identifier_is_rejected():
    from mira.reasoning.contracts.memory import WorkingMemory
    from mira.reasoning.runtime.narrative import apply_narrative

    memory = WorkingMemory()
    assert apply_narrative(memory, notes(hypotheses=[hypothesis()]), []) == ("", [])

    failure, _ = apply_narrative(memory, notes(close=["H9"]), [])

    assert "H9" in failure
    assert [h.id for h in memory.hypotheses] == ["H1"]


class RecordingModel(ScriptedModel):
    def __init__(self, *responses):
        super().__init__(*responses)
        self.contexts = []

    def generate(self, context, tools, force=None):
        self.contexts.append(context)
        return super().generate(context, tools, force)


async def notes_citing(tmp_path, *refs):
    update = notes(understanding="u", hypotheses=[hypothesis(supporting_evidence=list(refs))])
    model = RecordingModel(ModelResponse(tool_calls=[CALL], memory_update=update), ModelResponse(report=REPORT))
    calls, executor = counting_executor()
    loop = build_loop(model, tmp_path, tools=[PROBE], executor=executor)
    result = await loop.run(Objective(description="o"), build_definition(tools=[PROBE]), evidence=gathered("E1"))
    return loop, result, model.contexts


async def test_an_unknown_evidence_id_is_dropped_and_the_rest_of_the_notes_kept(tmp_path):
    loop, result, contexts = await notes_citing(tmp_path, "E1", "E99")

    (kept,) = result.memory.hypotheses
    assert kept.supporting_evidence == ["E1"] and result.memory.understanding == "u"
    assert "E99" in contexts[1] and "dropped" in contexts[1]
    assert loop.completion.memory_rejections == 0


async def test_a_hypothesis_citing_only_unknown_evidence_is_kept_unsupported(tmp_path):
    loop, result, contexts = await notes_citing(tmp_path, "E98", "E99")

    (kept,) = result.memory.hypotheses
    assert kept.supporting_evidence == []
    assert "E98, E99" in contexts[1]
    assert loop.completion.memory_rejections == 0


async def test_empty_collections_are_accepted_and_change_nothing(tmp_path):
    memory = await memory_after(tmp_path, notes(hypotheses=[hypothesis()]), notes())

    assert [h.id for h in memory.hypotheses] == ["H1"]


async def test_alternating_rejected_and_accepted_narratives_still_terminate(tmp_path):
    good = ModelResponse(tool_calls=[CALL], memory_update=NOTES)
    bad = ModelResponse(tool_calls=[CALL], memory_update={"hypotheses": "not a list"})
    model = ScriptedModel(bad, good, bad, good, bad, good, bad, good)
    calls, executor = counting_executor()
    loop = build_loop(model, tmp_path, tools=[PROBE], executor=executor)

    result = await loop.run(Objective(description="o"), build_definition(tools=[PROBE]))

    assert result.completion_reason == "degraded"
    assert result.metadata["turns"] < 10


async def test_rejections_do_not_spend_the_capability_budget(tmp_path):
    _, result, _ = await run_loop(
        tmp_path,
        ModelResponse(tool_calls=[CALL], memory_update={"hypotheses": "not a list"}),
        ModelResponse(report=REPORT),
    )

    assert result.metadata["tool_calls"] == 1
    assert len([o for o in result.observations]) == 2


async def test_an_identical_call_is_not_rerun_but_new_arguments_are(tmp_path):
    other = ToolCall(tool_call_id="2", name="probe", arguments={"offset": 4})
    _, result, calls = await run_loop(
        tmp_path,
        ModelResponse(tool_calls=[CALL], memory_update=NOTES),
        ModelResponse(tool_calls=[CALL, other], memory_update=NOTES),
        ModelResponse(report=REPORT),
    )

    assert calls == ["probe", "probe"]
    assert result.metadata["tool_calls"] == 2
    assert "Not rerun" in result.observations[1].error


async def test_a_rejection_is_announced_to_the_observer(tmp_path):
    events = []
    calls, executor = counting_executor()
    loop = build_loop(
        ScriptedModel(
            ModelResponse(tool_calls=[CALL], memory_update=NOTES),
            ModelResponse(tool_calls=[NEXT_CALL]),
            ModelResponse(report=REPORT),
        ),
        tmp_path, tools=[PROBE], executor=executor, on_turn=events.append,
    )

    await loop.run(Objective(description="o"), build_definition(tools=[PROBE]))

    assert [e["kind"] for e in events] == ["tool_calls", "notes", "tool_calls", "memory_rejected", "report"]


# --- Run counters feed the benchmark (R19) -------------------------------


def recall_probe(**arguments):
    handle = "test#probe#0"
    return ToolCall(tool_call_id="r", name="recall_observation", arguments={"handle": handle, **arguments})


async def test_counters_report_model_calls_and_recalls(tmp_path):
    _, result, _ = await run_loop(
        tmp_path,
        ModelResponse(tool_calls=[CALL, NEXT_CALL], memory_update=NOTES),
        ModelResponse(tool_calls=[recall_probe()]),
        ModelResponse(report=REPORT),
    )

    assert result.metadata["model_calls"] == 3
    assert result.metadata["recalls_requested"] == 1
    assert result.metadata["repeat_recalls"] == 0


async def test_a_forced_notes_call_counts_as_a_model_call_without_usage(tmp_path):
    _, result, _ = await run_loop(
        tmp_path,
        ModelResponse(tool_calls=[CALL], memory_update=NOTES),
        ModelResponse(tool_calls=[NEXT_CALL]),  # owes notes: one forced call, declined
        ModelResponse(report=REPORT),
    )

    assert result.metadata["model_calls"] == 4
    assert result.metadata["total_tokens"] == 0


async def test_an_identical_recall_is_counted_as_a_repeat(tmp_path):
    _, result, _ = await run_loop(
        tmp_path,
        ModelResponse(tool_calls=[CALL], memory_update=NOTES),
        ModelResponse(tool_calls=[recall_probe()]),
        ModelResponse(tool_calls=[recall_probe()], memory_update=NOTES),
        ModelResponse(report=REPORT),
    )

    assert result.metadata["recalls_requested"] == 2
    assert result.metadata["repeat_recalls"] == 1


async def test_a_refused_rerun_is_counted(tmp_path):
    _, result, _ = await run_loop(
        tmp_path,
        ModelResponse(tool_calls=[CALL], memory_update=NOTES),
        ModelResponse(tool_calls=[CALL], memory_update=NOTES),
        ModelResponse(report=REPORT),
    )

    assert result.metadata["reruns_refused"] == 1


async def test_a_salvaged_report_counts_its_discarded_findings(tmp_path):
    unsupported = {**FINDING, "evidence_refs": ["E99"]}
    salvaged = json.dumps({"summary": "s", "verdict": "suspicious", "findings": [FINDING, unsupported]})
    calls, executor = counting_executor()
    loop = build_loop(
        ScriptedModel(ModelResponse(tool_calls=[CALL], memory_update=NOTES), ModelResponse(report=salvaged)),
        tmp_path, tools=[PROBE], executor=executor,
    )

    result = await loop.run(
        Objective(description="o"), build_definition(tools=[PROBE], max_turns=1), evidence=gathered("E1")
    )

    assert len(result.findings) == 1
    assert result.metadata["findings_discarded"] == 1


# --- Retrieval ledger, repeats, and progress (KTD7-KTD9) ------------------

from mira.reasoning.contracts.state import State
from mira.reasoning.contracts.tool import ToolResult
from mira.reasoning.runtime.loop import _recall
from mira.reasoning.runtime.payload import recall_fingerprint

IMPORTS_SPEC = ToolSpec(
    name="list_imports", description="d",
    parameters={"type": "object", "properties": {"offset": {"type": "integer", "default": 0}}},
)


def collected(fetched=412, total=412, offset=0):
    metadata = {"capability": "list_imports", "offset": offset, "total": total,
                "fetched": fetched, "unfetched": total - fetched, "has_more": offset + fetched < total}
    if metadata["has_more"]:
        metadata["next_offset"] = offset + fetched
    rows = [{"dll": "KERNEL32.dll", "name": f"Fn{index}"} for index in range(offset, offset + fetched)]
    return {"status": "ok", "data": {"imports": rows}, "metadata": metadata}


def imports_call(id, **arguments):
    return ToolCall(tool_call_id=id, name="list_imports", arguments=arguments)


def recall_imports(**arguments):
    return ToolCall(tool_call_id="r", name="recall_observation",
                    arguments={"handle": "test#list_imports#0", "path": "data.imports", **arguments})


async def run_imports(tmp_path, *responses, output=None, evidence=None):
    calls = []

    def executor(name, arguments):
        calls.append(arguments)
        return output or collected()

    model = ScriptedModel(*responses)
    loop = build_loop(model, tmp_path, tools=[IMPORTS_SPEC], executor=executor)
    result = await loop.run(Objective(description="o"), build_definition(tools=[IMPORTS_SPEC]), evidence=evidence)
    return loop, result, calls


def test_a_fingerprint_ignores_argument_order_and_search_case():
    one = recall_fingerprint({"handle": "h", "path": "data.imports", "contains": ["VirtualAlloc"]})
    two = recall_fingerprint({"contains": ["virtualalloc "], "path": "data.imports", "handle": "h"})

    assert one == two
    assert one != recall_fingerprint({"handle": "h", "path": "data.imports", "contains": ["other"]})


async def test_a_repeated_recall_gets_a_pointer_and_no_items(tmp_path):
    seen = []

    class Watching(ScriptedModel):
        def generate(self, context, tools, force=None):
            seen.append(context)
            return super().generate(context, tools, force)

    model = Watching(
        ModelResponse(tool_calls=[imports_call("1")], memory_update=NOTES),
        ModelResponse(tool_calls=[recall_imports(offset=0, limit=3)], memory_update=NOTES),
        ModelResponse(tool_calls=[recall_imports(limit=3, offset=0)], memory_update=NOTES),
        ModelResponse(report=REPORT),
    )
    loop = build_loop(model, tmp_path, tools=[IMPORTS_SPEC], executor=lambda name, arguments: collected())
    result = await loop.run(Objective(description="o"), build_definition(tools=[IMPORTS_SPEC]))

    assert "[0] " in seen[2]
    assert "already answered on turn 2" in seen[3] and "[0] " not in seen[3]
    assert result.metadata["repeat_recalls"] == 1


async def test_a_model_that_only_repeats_a_recall_ends_degraded_after_two_turns(tmp_path):
    _, result, _ = await run_imports(
        tmp_path,
        ModelResponse(tool_calls=[imports_call("1")], memory_update=NOTES),
        ModelResponse(tool_calls=[recall_imports(limit=5)], memory_update=NOTES),
        ModelResponse(tool_calls=[recall_imports(limit=5)], memory_update=NOTES),
    )

    assert result.completion_reason == "degraded"
    assert result.metadata["turns"] == 4


def test_a_recall_of_items_already_shown_is_served_but_is_not_progress():
    state = State(objective=Objective(description="o"), run_id="test")
    state.record_tool_call(imports_call("1"))
    state.record_tool_result(ToolResult("1", success=True, output=collected()))

    first, first_new = _recall(state, recall_imports(offset=0, limit=10).arguments)
    again, again_new = _recall(state, recall_imports(where={"name": "Fn5"}).arguments)
    later, later_new = _recall(state, recall_imports(offset=400).arguments)

    assert first_new and "[9] " in first
    assert not again_new and "[5] " in again
    assert later_new
    assert state.shown_items["test#list_imports#0"]["data.imports"] == set(range(10)) | set(range(400, 412))


async def test_a_refused_repeat_recall_owes_no_notes(tmp_path):
    loop, result, _ = await run_imports(
        tmp_path,
        ModelResponse(tool_calls=[imports_call("1")], memory_update=NOTES),
        ModelResponse(tool_calls=[recall_imports(limit=5)], memory_update=NOTES),
        ModelResponse(tool_calls=[recall_imports(limit=5)]),  # a repeat: nothing new to note
        ModelResponse(tool_calls=[imports_call("2", offset=500)], memory_update=NOTES),
        ModelResponse(report=REPORT),
    )

    assert loop.completion.memory_rejections == 0
    assert result.metadata["model_calls"] == 5  # no forced notes call


async def test_recalls_add_no_evidence(tmp_path):
    _, result, _ = await run_imports(
        tmp_path,
        ModelResponse(tool_calls=[imports_call("1")], memory_update=NOTES),
        ModelResponse(tool_calls=[recall_imports(limit=5), recall_imports(group_by="dll")], memory_update=NOTES),
        ModelResponse(report=report(FINDING)),
        evidence=gathered("E1"),
    )

    assert result.evidence == ["E1"]


async def test_a_call_equal_after_filling_defaults_is_not_rerun(tmp_path):
    _, result, calls = await run_imports(
        tmp_path,
        ModelResponse(tool_calls=[imports_call("1", offset=0)], memory_update=NOTES),
        ModelResponse(tool_calls=[imports_call("2")], memory_update=NOTES),
        ModelResponse(report=REPORT),
    )

    assert len(calls) == 1
    assert result.metadata["reruns_refused"] == 1


async def test_a_call_inside_a_collected_range_points_to_recall(tmp_path):
    _, result, calls = await run_imports(
        tmp_path,
        ModelResponse(tool_calls=[imports_call("1")], memory_update=NOTES),
        ModelResponse(tool_calls=[imports_call("2", offset=300)], memory_update=NOTES),
        ModelResponse(report=REPORT),
    )

    assert len(calls) == 1
    refusal = result.observations[1].error
    assert "recall_observation" in refusal and "offset=300" in refusal and "test#list_imports#0" in refusal


async def test_a_call_past_a_truncated_collection_runs(tmp_path):
    _, _, calls = await run_imports(
        tmp_path,
        ModelResponse(tool_calls=[imports_call("1")], memory_update=NOTES),
        ModelResponse(tool_calls=[imports_call("2", offset=10_000)], memory_update=NOTES),
        ModelResponse(report=REPORT),
        output=collected(fetched=10_000, total=12_000),
    )

    assert calls == [{}, {"offset": 10_000}]


async def test_a_failed_call_is_retried_with_the_same_arguments(tmp_path):
    outcomes = [RuntimeError("worker died"), collected()]

    def executor(name, arguments):
        outcome = outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    model = ScriptedModel(
        ModelResponse(tool_calls=[imports_call("1")], memory_update=NOTES),
        ModelResponse(tool_calls=[imports_call("2")], memory_update=NOTES),
        ModelResponse(report=REPORT),
    )
    loop = build_loop(model, tmp_path, tools=[IMPORTS_SPEC], executor=executor)
    result = await loop.run(Objective(description="o"), build_definition(tools=[IMPORTS_SPEC]))

    assert outcomes == [] and result.metadata["tool_calls"] == 2
