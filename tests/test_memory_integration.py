"""The notebook across a real run: what the model wrote is what it reads back
next turn, and every evidence id it cites resolves to an observation."""

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
REPORT = '{"summary": "done", "verdict": "suspicious", "findings": []}'
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
    def __init__(self, *responses):
        self.responses = list(responses)
        self.contexts = []
        self.offered = []

    def generate(self, context, tools):
        self.contexts.append(context)
        self.offered.append([spec.name for spec in tools])
        return self.responses[min(len(self.contexts) - 1, len(self.responses) - 1)]


async def run(tmp_path, *responses):
    """A loop wired the way both composition roots wire it: evidence is
    minted by the shared executor as each result arrives (KTD14)."""
    evidence = []

    async def invoke(capability, arguments):
        return {"extract_strings": PAGE, "detect_packer": PACKED}[capability]

    executor = build_evidence_executor(invoke, run_id=RUN, artifact_id="sample", evidence=evidence)
    model = Recorder(*responses)
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
    return model, captured["state"], result, loop


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


async def test_citing_an_id_the_run_never_minted_leaves_the_notes_untouched(tmp_path):
    _, state, _, loop = await run(
        tmp_path,
        ModelResponse(tool_calls=[call("detect_packer")], memory_update=notes([{
            "id": "H1", "statement": "s", "confidence": 0.5, "status": "open", "supporting_evidence": ["E1"],
        }])),
        ModelResponse(memory_update=notes([{"id": "H1", "supporting_evidence": ["E9"]}])),
        ModelResponse(report=REPORT),
    )

    assert loop.completion.memory_rejections == 1
    assert state.working_memory.hypotheses[0].supporting_evidence == ["E1"]


# --- The rejection bound ends in one report-only turn, not in nothing

MALFORMED = ModelResponse(memory_update={"hypotheses": "not a list"})
SALVAGED = '{"summary": "salvaged", "verdict": "suspicious", "findings": []}'


async def test_a_run_ended_by_rejected_notes_still_gets_its_report(tmp_path):
    model, state, result, _ = await run(
        tmp_path,
        ModelResponse(tool_calls=[call("detect_packer")], memory_update=notes()),
        ModelResponse(tool_calls=[call("extract_strings")]),  # no notes: rejection 1
        MALFORMED,  # 2
        MALFORMED,  # 3: the bound trips
        ModelResponse(report=SALVAGED),
    )

    assert (result.summary, result.verdict) == ("salvaged", "suspicious")
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
        MALFORMED,
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

    assert "Send a record_memory call in the same response" in model.contexts[2]


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
