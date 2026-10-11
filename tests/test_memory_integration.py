"""The notebook across a real run: what the model wrote is what it reads back
next turn, and every evidence id it cites resolves to an observation."""

import json

from mira.agents.static.wiring import build_evidence_executor
from mira.reasoning.contracts.model import ModelResponse
from mira.reasoning.contracts.objective import Objective
from mira.reasoning.contracts.output import FinalOutput
from mira.reasoning.contracts.tool import ToolCall, ToolSpec
from mira.reasoning.definition.agent import AgentDefinition
from mira.reasoning.runtime.completion import CompletionChecker
from mira.reasoning.runtime.context import ContextBuilder
from mira.reasoning.runtime.loop import AgentLoop
from mira.reasoning.runtime.tool_runtime import ToolRuntime
from mira.reasoning.runtime.trace import Tracer, resolve_observation, trace_provenance

RUN = "memory_run"
URL = "http://evil.example/stage2.bin"
# inconclusive: the verdict gate refuses any verdict outside benign, malicious, inconclusive (R8).
REPORT = '{"summary": "done", "verdict": "inconclusive", "findings": []}'
STRINGS = ToolSpec(name="extract_strings", description="Extract strings.", parameters={})
PACKER = ToolSpec(name="detect_packer", description="Detect packing.", parameters={})

PAGE = {
    "status": "ok",
    "data": {
        "strings": [
            {"value": URL if index == 990 else f"benign_{index:04d}", "offset": index, "encoding": "ascii"}
            for index in range(1000)
        ],
        "offset": 0,
    },
    "metadata": {"capability": "extract_strings", "limit": 1000, "offset": 0, "has_more": False},
}
PACKED = {
    "status": "ok",
    "data": {"packed": True, "packer": "UPX", "confidence": 0.9, "indicators": ["UPX0 section"]},
    "metadata": {"capability": "detect_packer"},
}


def notes(hypotheses=(), **fields):
    return {"understanding": "", "hypotheses": list(hypotheses), "open_questions": [], "candidates": [], **fields}


def call(name):
    return ToolCall(tool_call_id=name, name=name, arguments={})


class Recorder:
    """Replays its responses. A forced notes call is answered apart from the
    script: declined by default, or with `forced_notes` when given."""

    def __init__(self, *responses, forced_notes=None):
        self.responses = list(responses)
        self.contexts = []
        self.offered = []
        self.forced_notes = forced_notes
        self.forced = []  # (context, tools offered) of each forced notes call

    def generate(self, context, tools, force=None):
        if force == "record_memory":
            self.forced.append((context, [spec.name for spec in tools]))
            return ModelResponse(memory_update=self.forced_notes)
        self.contexts.append(context)
        self.offered.append([spec.name for spec in tools])
        return self.responses[min(len(self.contexts) - 1, len(self.responses) - 1)]


async def run(tmp_path, *responses, forced_notes=None):
    """A loop wired the way both composition roots wire it: evidence is
    minted by the shared executor as each result arrives (KTD14)."""
    evidence = []

    async def invoke(capability, arguments):
        return {"extract_strings": PAGE, "detect_packer": PACKED}[capability]

    executor = build_evidence_executor(invoke, run_id=RUN, artifact_id="sample", evidence=evidence)
    model = Recorder(*responses, forced_notes=forced_notes)
    loop = AgentLoop(
        model,
        ToolRuntime([STRINGS, PACKER], executor),
        CompletionChecker(),
        ContextBuilder(),
        Tracer(run_id=RUN, output_dir=str(tmp_path)),
    )
    loop.events = []
    loop.on_turn = loop.events.append
    captured = {}
    original = loop._merge_narrative

    def spy(state, update):
        captured["state"] = state
        return original(state, update)

    loop._merge_narrative = spy
    definition = AgentDefinition(
        role="You are a test investigator.",
        scope="Test scope only.",
        tool_manifest=[STRINGS, PACKER],
        allowed_tools=[STRINGS, PACKER],
        max_turns=10,
        max_tool_calls=10,
        output_contract=FinalOutput,
    )
    result = await loop.run(Objective(description="test"), definition, evidence=evidence)
    return model, captured.get("state"), result, loop


# --- 1. Persistence: the next prompt shows exactly the merged notes


async def test_an_omitted_hypothesis_reads_back_unchanged_and_a_reused_id_revises(tmp_path):
    first = notes(
        [
            {"id": "H1", "statement": "The sample is packed.", "confidence": 0.6, "status": "open"},
            {"id": "H2", "statement": "It downloads a second stage.", "confidence": 0.3, "status": "open"},
        ],
        understanding="Early triage.",
    )
    second = notes([{"id": "H2", "confidence": 0.8, "status": "supported"}])
    model, state, _, loop = await run(
        tmp_path,
        ModelResponse(tool_calls=[call("detect_packer")], memory_update=first),
        ModelResponse(tool_calls=[call("extract_strings")], memory_update=second),
        ModelResponse(report=REPORT),
    )

    before, after_first, after_second = model.contexts
    assert "(none recorded yet)" in before
    assert "H1 [open, confidence 0.60] The sample is packed." in after_first
    # H1 was omitted from the second update: it reads back exactly as before.
    assert "H1 [open, confidence 0.60] The sample is packed." in after_second
    # H2's id was reused: revised fields change, its statement stands.
    assert "H2 [supported, confidence 0.80] It downloads a second stage." in after_second
    assert "confidence 0.30" not in after_second
    # Understanding was left empty in the second update, so it stands too.
    assert "Understanding: Early triage." in after_second
    assert loop.completion.memory_rejections == 0
    assert [h.id for h in state.working_memory.hypotheses] == ["H1", "H2"]


# --- 2. Evidence integrity: every cited id resolves to its observation


async def test_every_cited_evidence_id_resolves_including_after_a_recall(tmp_path):
    strings_handle = trace_provenance(RUN, "extract_strings", 0)
    model, state, _, loop = await run(
        tmp_path,
        ModelResponse(tool_calls=[call("detect_packer"), call("extract_strings")], memory_update=notes()),
        ModelResponse(
            tool_calls=[ToolCall("r", "recall_observation", {"handle": strings_handle, "contains": ["http"]})]
        ),
        # Cites what it read: the evidence minted from the recalled call, and the packer's.
        ModelResponse(memory_update=notes([{
            "id": "H1",
            "statement": "Packed dropper fetching a second stage.",
            "confidence": 0.7,
            "status": "supported",
            "supporting_evidence": ["E1", "E2"],
        }])),
        ModelResponse(report=REPORT),
    )

    assert URL in model.contexts[2]  # the recall reached the model
    assert loop.completion.memory_rejections == 0
    by_id = {item.id: item for item in state.evidence}
    cited = {ref for h in state.working_memory.hypotheses for ref in h.supporting_evidence + h.contradicting_evidence}
    assert cited == {"E1", "E2"}
    for ref in cited:
        item = by_id[ref]  # cited ids are minted evidence, never invented
        observation = resolve_observation(tmp_path, item.provenance)
        assert observation["call"]["name"] == item.capability
    url_evidence = [item for item in state.evidence if URL in item.observation]
    assert [item.provenance for item in url_evidence] == [strings_handle]


async def test_citing_only_an_id_the_run_never_minted_changes_nothing_and_is_not_a_rejection(tmp_path):
    model, state, _, loop = await run(
        tmp_path,
        ModelResponse(tool_calls=[call("detect_packer")], memory_update=notes([{
            "id": "H1", "statement": "s", "confidence": 0.5, "status": "open", "supporting_evidence": ["E1"],
        }])),
        ModelResponse(memory_update=notes([{"id": "H1", "supporting_evidence": ["E9"]}])),
        ModelResponse(report=REPORT),
    )

    assert loop.completion.memory_rejections == 0  # KTD11: dropped, not rejected
    assert state.working_memory.hypotheses[0].supporting_evidence == ["E1"]
    assert "dropped E9" in model.contexts[2]


# --- The rejection bound ends in one report-only turn, not in nothing

def malformed(n):
    """A capability call that ran (progress, KTD8) with notes that cannot merge."""
    return ModelResponse(tool_calls=[ToolCall(f"m{n}", "extract_strings", {"min_length": n})],
                         memory_update={"hypotheses": "not a list"})
SALVAGED = '{"summary": "salvaged", "verdict": "inconclusive", "findings": []}'


async def test_a_run_ended_by_rejected_notes_still_gets_its_report(tmp_path):
    model, state, result, _ = await run(
        tmp_path,
        ModelResponse(tool_calls=[call("detect_packer")], memory_update=notes()),
        ModelResponse(tool_calls=[call("extract_strings")]),  # no notes: rejection 1
        malformed(1),  # 2
        malformed(2),  # 3: the bound trips
        ModelResponse(report=SALVAGED),
    )

    assert (result.summary, result.verdict) == ("salvaged", "inconclusive")
    # Still degraded: the notes lag the results, so nothing will be promoted.
    assert result.completion_reason == "degraded"
    assert "E1" in result.evidence
    assert "Run ending: notes were rejected 3 times" in model.contexts[-1]
    assert model.offered[-1] == []  # no capability on offer
    assert result.metadata["turns"] == 5


async def test_no_report_on_the_final_turn_ends_inconclusive(tmp_path):
    model, _, result, _ = await run(
        tmp_path,
        ModelResponse(tool_calls=[call("detect_packer")], memory_update=notes()),
        ModelResponse(tool_calls=[call("extract_strings")]),
        malformed(1),  # replayed: its rerun is refused, and its notes are rejection 3
    )

    assert len(model.contexts) == 5  # one accepted, three rejected, one final
    assert (result.verdict, result.completion_reason) == ("inconclusive", "degraded")


async def test_the_rejection_says_what_to_send(tmp_path):
    model, *_ = await run(
        tmp_path,
        ModelResponse(tool_calls=[call("detect_packer")], memory_update=notes()),
        ModelResponse(tool_calls=[call("extract_strings")]),
        ModelResponse(report=REPORT),
    )

    assert "Send a record_memory call in this response" in model.contexts[2]


# --- A turn that recalls may write its notes one turn later


def recall_and(name, offset):
    handle = trace_provenance(RUN, "detect_packer", 0)
    return ModelResponse(tool_calls=[
        # A different part each time: a repeated recall shows nothing new (KTD8).
        ToolCall("r", "recall_observation", {"handle": handle, "path": ("data.packer", "data.confidence")[offset - 1]}),
        ToolCall(name, name, {"offset": offset}),  # fresh arguments: not a refused rerun
    ])


async def test_a_recall_turn_defers_its_notes_once(tmp_path):
    _, _, result, loop = await run(
        tmp_path,
        ModelResponse(tool_calls=[call("detect_packer")], memory_update=notes()),
        recall_and("extract_strings", 1),  # deferred, not rejected
        ModelResponse(tool_calls=[call("extract_strings")], memory_update=notes()),  # paid
        recall_and("extract_strings", 2),  # may defer again after paying
        ModelResponse(report=REPORT),
    )

    assert loop.completion.memory_rejections == 0
    assert result.completion_reason == "reported"


async def test_a_deferral_cannot_run_two_turns(tmp_path):
    _, _, _, loop = await run(
        tmp_path,
        ModelResponse(tool_calls=[call("detect_packer")], memory_update=notes()),
        recall_and("extract_strings", 1),  # deferred
        recall_and("extract_strings", 2),  # owed now: rejected
        ModelResponse(report=REPORT),
    )

    assert loop.completion.memory_rejections == 1


async def test_skipping_notes_without_a_recall_is_still_rejected(tmp_path):
    _, _, _, loop = await run(
        tmp_path,
        ModelResponse(tool_calls=[call("detect_packer")], memory_update=notes()),
        ModelResponse(tool_calls=[call("extract_strings")]),
        ModelResponse(report=REPORT),
    )

    assert loop.completion.memory_rejections == 1


# --- A recall must be followed by notes; a turn limit still yields a report


RECALL_ONLY = ModelResponse(tool_calls=[
    ToolCall("r", "recall_observation", {"handle": trace_provenance(RUN, "detect_packer", 0)})
])


async def test_a_model_that_only_rereads_is_stopped_after_two_repeats(tmp_path):
    """A live run re-read the same results for seven turns without a note. A
    repeat is now answered with a pointer and is not progress (R11)."""
    model, _, result, loop = await run(
        tmp_path,
        ModelResponse(tool_calls=[call("detect_packer")], memory_update=notes()),
        RECALL_ONLY,  # turn 2 shows it; turns 3 and 4 repeat it
    )

    assert loop.completion.memory_rejections == 0  # a repeat owes no notes
    assert len(model.contexts) == 4  # no report-only turn: the model went quiet
    assert result.completion_reason == "degraded"


async def test_notes_after_a_recall_pay_what_it_owed(tmp_path):
    _, _, result, loop = await run(
        tmp_path,
        ModelResponse(tool_calls=[call("detect_packer")], memory_update=notes()),
        RECALL_ONLY,
        ModelResponse(memory_update=notes(understanding="Read the packer result.")),
        RECALL_ONLY,  # pending again, but a report-only turn acts on nothing and owes none
        ModelResponse(report=REPORT),
    )

    assert loop.completion.memory_rejections == 0
    assert result.completion_reason == "reported"


async def test_a_run_out_of_turns_still_gets_a_report(tmp_path):
    model, _, result, _ = await run(
        tmp_path,
        # Notes that change every turn are progress (KTD8), so only max_turns=10 ends it.
        *[ModelResponse(memory_update=notes(understanding=f"step {n}")) for n in range(10)],
        ModelResponse(report=SALVAGED),
    )

    assert (result.summary, result.completion_reason) == ("salvaged", "limit_turns")
    assert "Run ending: the turn limit was reached" in model.contexts[-1]
    assert model.offered[-1] == []


# --- Fix 1: skipped notes get one forced record_memory call


async def test_skipped_notes_are_recorded_by_one_forced_call(tmp_path):
    model, state, result, loop = await run(
        tmp_path,
        ModelResponse(tool_calls=[call("detect_packer")], memory_update=notes()),
        ModelResponse(tool_calls=[call("extract_strings")]),  # skips its notes
        ModelResponse(report=REPORT),
        forced_notes=notes(understanding="Forced: packed, with a URL in its strings."),
    )

    assert len(model.forced) == 1
    forced_context, offered = model.forced[0]
    assert offered == []  # only record_memory, which the adapter declares and forces
    assert "Call record_memory now" in forced_context
    assert trace_provenance(RUN, "extract_strings", 0) in forced_context  # sees this turn's result
    assert state.working_memory.understanding == "Forced: packed, with a URL in its strings."
    assert loop.completion.memory_rejections == 0
    assert result.completion_reason == "reported"
    assert [e["turn"] for e in loop.events if e["kind"] == "notes"] == [1, 2]


async def test_no_forced_call_when_notes_were_recorded(tmp_path):
    model, *_ = await run(
        tmp_path,
        ModelResponse(tool_calls=[call("detect_packer")], memory_update=notes()),
        ModelResponse(tool_calls=[call("extract_strings")], memory_update=notes()),
        ModelResponse(report=REPORT),
        forced_notes=notes(),
    )

    assert model.forced == []


async def test_no_forced_call_where_notes_are_not_owed(tmp_path):
    """Neither the first capability turn nor a deferring recall turn owes notes."""
    model, _, _, loop = await run(
        tmp_path,
        ModelResponse(tool_calls=[call("detect_packer")]),
        recall_and("extract_strings", 1),
        ModelResponse(report=REPORT),
        forced_notes=notes(),
    )

    assert model.forced == []
    assert loop.completion.memory_rejections == 0


async def test_a_declined_forced_call_is_still_a_rejection(tmp_path):
    model, _, _, loop = await run(
        tmp_path,
        ModelResponse(tool_calls=[call("detect_packer")], memory_update=notes()),
        ModelResponse(tool_calls=[call("extract_strings")]),
        ModelResponse(report=REPORT),
    )

    assert len(model.forced) == 1
    assert loop.completion.memory_rejections == 1


# --- Fix 3: the final report keeps its supported findings and drops the rest


def finding(title, refs):
    return {"title": title, "description": "d", "severity": "medium", "confidence": "medium", "evidence_refs": refs}


def report_with(*findings, verdict="inconclusive"):
    return ModelResponse(report=json.dumps({"summary": "Final.", "verdict": verdict, "findings": list(findings)}))


def ending_with(final):
    """One evidence-minting turn, nine more until max_turns, then the final turn."""
    return (
        ModelResponse(tool_calls=[call("detect_packer")], memory_update=notes()),
        *[ModelResponse(memory_update=notes(understanding=f"step {n}")) for n in range(9)],
        final,
    )


async def test_the_final_report_keeps_only_supported_findings(tmp_path):
    _, state, result, _ = await run(tmp_path, *ending_with(report_with(
        finding("Packed with UPX", ["E1"]),
        finding("Uncited claim", []),
        finding("Invented evidence", ["E99"]),
    )))

    assert [f.title for f in result.findings] == ["Packed with UPX"]
    assert result.verdict == "inconclusive"
    assert "2 finding(s) without valid evidence references were discarded" in result.summary
    assert result.completion_reason == "limit_turns"
    minted = {item.id for item in state.evidence}
    for kept in result.findings:  # nothing unsupported slips through
        assert kept.evidence_refs and {ref.evidence_id for ref in kept.evidence_refs} <= minted


async def test_a_final_report_with_no_supported_finding_is_inconclusive(tmp_path):
    _, _, result, _ = await run(tmp_path, *ending_with(report_with(
        finding("Uncited claim", []), finding("Invented evidence", ["E99"]), verdict="malicious"
    )))

    assert result.findings == []
    assert result.verdict == "inconclusive"
    assert "2 finding(s) without valid evidence references were discarded" in result.summary


async def test_a_normal_turn_still_rejects_a_report_with_an_unsupported_finding(tmp_path):
    """Salvage is for the final turn only; earlier, the model can fix its report."""
    _, _, result, loop = await run(
        tmp_path,
        ModelResponse(tool_calls=[call("detect_packer")], memory_update=notes()),
        report_with(finding("Packed with UPX", ["E1"]), finding("Uncited claim", [])),
        report_with(finding("Packed with UPX", ["E1"])),
    )

    assert [e["kind"] for e in loop.events].count("report_rejected") == 1
    assert [f.title for f in result.findings] == ["Packed with UPX"]
    assert "discarded" not in result.summary


# --- Observers see the notes and the recalls as they happen


async def test_observers_get_each_accepted_note_and_each_recall(tmp_path):
    handle = trace_provenance(RUN, "detect_packer", 0)
    _, _, _, loop = await run(
        tmp_path,
        ModelResponse(tool_calls=[call("detect_packer")], memory_update=notes(
            [{"id": "H1", "statement": "Packed.", "confidence": 0.5, "status": "open"}]
        )),
        ModelResponse(tool_calls=[ToolCall("r", "recall_observation", {"handle": handle})]),
        ModelResponse(memory_update=notes([{"id": "H1", "status": "supported"}])),
        ModelResponse(report=REPORT),
    )

    by_kind = [(event["kind"], event["turn"]) for event in loop.events if event["kind"] in ("notes", "recall")]
    assert by_kind == [("notes", 1), ("recall", 2), ("notes", 3)]
    first, recall, last = [event for event in loop.events if event["kind"] in ("notes", "recall")]
    assert recall["handles"] == [handle]
    # Each event is a snapshot: turn 3's revision did not rewrite turn 1's.
    assert first["memory"].hypotheses[0].status == "open"
    assert last["memory"].hypotheses[0].status == "supported"
