"""A digest stays small without hiding the rest: recall_observation reaches any
part of a full result by handle, range or search."""

import json

import pytest

from mira.reasoning.contracts.model import ModelResponse
from mira.reasoning.contracts.objective import Objective
from mira.reasoning.contracts.output import FinalOutput
from mira.reasoning.contracts.state import State
from mira.reasoning.contracts.tool import ToolCall, ToolResult, ToolSpec
from mira.reasoning.definition.agent import AgentDefinition
from mira.reasoning.runtime.completion import CompletionChecker
from mira.reasoning.runtime.context import ContextBuilder
from mira.reasoning.runtime.loop import MAX_RECALLS_PER_TURN, AgentLoop, _recall
from mira.reasoning.runtime.payload import (
    MAX_DIGEST_CHARS,
    MAX_RECALL_CHARS,
    PARTIAL_MARKER,
    digest,
    select,
)
from mira.reasoning.runtime.tool_runtime import ToolRuntime
from mira.reasoning.runtime.trace import (
    Tracer,
    capability_history,
    live_observation,
    resolve_observation,
    trace_provenance,
)

NOTES = {"understanding": "", "hypotheses": [], "open_questions": [], "candidates": []}
# inconclusive: the verdict gate refuses any verdict outside benign, malicious, inconclusive (R8).
REPORT = '{"summary": "done", "verdict": "inconclusive", "findings": []}'
URL = "http://evil.example/stage2.bin"
LATE = 990  # well past the first 4,000 serialized characters


def strings_page(size=1000, late=LATE):
    strings = [{"value": f"benign_string_{index:04d}", "offset": index * 16, "encoding": "ascii"} for index in range(size)]
    if late is not None:
        strings[late] = {"value": URL, "offset": late * 16, "encoding": "ascii"}
    return {
        "status": "ok",
        "data": {"strings": strings, "offset": 0},
        "metadata": {"capability": "extract_strings", "limit": size, "offset": 0, "has_more": False},
    }


PAGE = strings_page()

# 412 imports over 9 DLLs; the last three are ordinal-only.
DLLS = [("KERNEL32.dll", 180), ("USER32.dll", 95), ("ADVAPI32.dll", 40), ("GDI32.dll", 30), ("SHELL32.dll", 20),
        ("ole32.dll", 15), ("COMCTL32.dll", 15), ("msvcrt.dll", 12), ("ntdll.dll", 5)]


def imports_envelope(**metadata):
    imports = [
        {"dll": dll, "name": f"{dll.split('.')[0]}_api_{index}", "ordinal": None, "address": 4096 + position}
        for position, (dll, index) in enumerate((dll, index) for dll, count in DLLS for index in range(count))
    ]
    for ordinal, entry in enumerate(imports[-3:], 1):
        entry.update(name=None, ordinal=ordinal)
    return {
        "status": "ok",
        "data": {"imports": imports},
        "metadata": {"capability": "list_imports", "offset": 0, "total": 412, "fetched": 412, "unfetched": 0, **metadata},
    }


IMPORTS = imports_envelope()


def test_the_indicator_sits_beyond_the_old_prefix_boundary():
    """Guards the regression's premise: a 4,000-character prefix never saw it."""
    assert URL not in json.dumps(PAGE, sort_keys=True)[:4000]


# --- Digest


def test_a_large_digest_is_bounded_and_says_it_is_partial():
    text = digest(PAGE)

    assert len(text) <= MAX_DIGEST_CHARS + len(PARTIAL_MARKER) + 80
    assert text.endswith(PARTIAL_MARKER)
    assert "data.strings (1000)" in text
    assert "data.strings: 1000 items, fields {value, offset, encoding}" in text


def test_a_digest_shows_a_large_list_as_schema_and_distributions():
    text = digest(IMPORTS)

    assert "data.imports: 412 items, fields {dll, name, ordinal, address}" in text
    assert '"KERNEL32.dll" 180' in text and '"USER32.dll" 95' in text and '"ADVAPI32.dll" 40' in text
    assert "name: 409 distinct, 3 null" in text
    assert "_api_" not in text  # no item is sampled
    assert "coverage: fetched 412 of 412 (offset 0)" in text
    assert PARTIAL_MARKER in text


def test_a_huge_list_digest_stays_bounded_and_shows_no_high_cardinality_value():
    text = digest(strings_page(size=10_000, late=None))

    assert len(text) <= MAX_DIGEST_CHARS + len(PARTIAL_MARKER) + 80
    assert "benign_string" not in text
    assert "value: 10000 distinct" in text and "offset: 10000 distinct" in text
    assert '"ascii" 10000' in text


def test_a_truncated_collection_says_what_was_never_fetched():
    text = digest(imports_envelope(total=12_000, unfetched=11_588, has_more=True, next_offset=412))

    assert "coverage: fetched 412 of 12000 (offset 0)" in text
    assert "11588 not fetched" in text and "list_imports(offset=412)" in text


def test_a_failed_later_page_is_named_in_the_coverage():
    text = digest(imports_envelope(total=2000, unfetched=1588, next_offset=412, fetch_error="RESOURCE_LIMIT: timed out"))

    assert "RESOURCE_LIMIT: timed out" in text


def test_a_long_low_cardinality_value_is_truncated():
    rows = {"data": {"rows": [{"kind": letter * 200} for letter in "xy" * 10]}}

    text = digest(rows)

    assert "kind: 2 distinct" in text
    assert "x" * 200 not in text and "…(+" in text


def test_a_large_scalar_array_shows_its_count_and_distinct_count():
    text = digest({"data": {"names": [f"n{index % 30}" for index in range(500)]}})

    assert "data.names: 500 items, 30 distinct" in text
    assert "n7" not in text


def test_a_short_array_is_shown_in_full():
    sections = {"data": {"sections": [{"name": name, "entropy": 7.9, "raw_size": 512, "virtual_size": 512} for name in (".text", ".rdata", ".data", "UPX0", "UPX1")]}}

    text = digest(sections)

    assert all(name in text for name in (".text", ".rdata", ".data", "UPX0", "UPX1"))
    assert PARTIAL_MARKER not in text


def test_a_small_result_digest_is_whole_and_not_marked_partial():
    small = {"status": "ok", "data": {"packed": True, "packer": "UPX"}}

    text = digest(small)

    assert PARTIAL_MARKER not in text
    assert '"packer": "UPX"' in text


def test_a_digest_does_not_alter_the_result():
    page = strings_page()
    before = json.dumps(page, sort_keys=True)

    digest(page)

    assert json.dumps(page, sort_keys=True) == before


# --- Selection


def test_search_finds_an_indicator_late_in_a_large_array():
    text, failure, *_ = select(PAGE, {"contains": ["://"]})

    assert failure == ""
    assert f"[{LATE}]" in text and URL in text
    assert "1 of 1000 items" in text


def test_search_is_case_insensitive_and_respects_count():
    text, failure, *_ = select(PAGE, {"path": "data.strings", "contains": ["BENIGN_STRING_00"], "limit": 5})

    assert failure == ""
    assert "100 of 1000 items" in text
    assert text.count("\n[") == 5
    assert "continue with offset=5" in text


def test_a_range_returns_exactly_the_requested_items():
    text, _, *_ = select(PAGE, {"path": "data.strings", "offset": 10, "limit": 3})

    assert "items 10..12 of 1000" in text
    assert [line.split("]")[0] for line in text.splitlines()[1:]] == ["[10", "[11", "[12"]
    assert "continue with offset=13" in text


def test_a_range_at_the_end_returns_only_what_exists():
    text, failure, *_ = select(PAGE, {"path": "data.strings", "offset": 998, "limit": 50})

    assert failure == ""
    assert "items 998..999 of 1000" in text
    assert "continue" not in text


def test_the_character_limit_stops_a_range_with_a_continuation():
    wide = {"data": {"rows": ["x" * 1000 for _ in range(50)]}}

    text, failure, *_ = select(wide, {"path": "data.rows", "limit": 50})

    assert failure == ""
    assert len(text) < MAX_RECALL_CHARS + 500
    assert "stopped at item" in text and "continue with offset=" in text


def test_a_small_object_is_returned_whole():
    text, failure, *_ = select(PAGE, {"path": "metadata"})

    assert failure == ""
    assert '"has_more": false' in text


@pytest.mark.parametrize(
    "arguments, expected",
    [
        ({"path": "data.strings", "offset": 1000}, "past the end"),
        ({"path": "data.strings", "offset": -1}, "offset must be an integer"),
        ({"path": "data.strings", "offset": True}, "offset must be an integer"),
        ({"path": "data.strings", "limit": 0}, "limit must be an integer between 1 and 200"),
        ({"path": "data.strings", "limit": 201}, "limit must be an integer between 1 and 200"),
        ({"path": "data.strings", "contains": []}, "contains must be"),
        ({"path": "data.strings", "contains": [""]}, "contains must be"),
        ({"path": "data.nope"}, "'nope' is not in data; its keys are ['offset', 'strings']"),
        ({"path": "data.strings.5000"}, "array of 1000 items"),
        ({"path": "metadata", "offset": 0}, "metadata is not an array"),
        ({"path": ""}, "path must be a dotted path"),
    ],
)
def test_invalid_selectors_fail_with_a_clear_reason(arguments, expected):
    text, failure, *_ = select(PAGE, arguments)

    assert text == ""
    assert expected in failure


def test_a_whole_result_too_large_to_return_names_its_arrays():
    _, failure, *_ = select(PAGE, {})

    assert "over the 6000-character recall limit" in failure
    assert "data.strings (1000 items)" in failure


def test_an_ambiguous_array_needs_a_path():
    two = {"data": {"imports": [1, 2], "exports": [3]}}

    _, failure, *_ = select(two, {"offset": 0})

    assert "give a path" in failure


# --- Handles, live and traced

RUN = "recall_run"


def _state():
    state = State(objective=Objective(description="test"), run_id=RUN)

    def call(name, output=None, error=None):
        tool_call = ToolCall(tool_call_id=f"c{len(state.observations)}", name=name, arguments={})
        state.record_tool_call(tool_call)
        state.record_tool_result(ToolResult(tool_call.tool_call_id, success=error is None, output=output, error=error))

    call("extract_strings", error="TIMEOUT: too slow")
    call("extract_strings", output=PAGE)
    call("list_imports", output={"status": "ok", "data": {"imports": []}})
    call("extract_strings", output=strings_page(late=None))
    return state


def test_repeated_and_failed_calls_keep_distinct_handles_for_recall():
    state = _state()

    failed = _recall(state, {"handle": trace_provenance(RUN, "extract_strings", 0)})[0]
    found = _recall(state, {"handle": trace_provenance(RUN, "extract_strings", 1), "contains": ["evil"]})[0]
    clean = _recall(state, {"handle": trace_provenance(RUN, "extract_strings", 2), "contains": ["evil"]})[0]

    assert "that call failed" in failed and "TIMEOUT" in failed
    assert URL in found
    assert "0 of 1000 items" in clean


@pytest.mark.parametrize(
    "arguments, expected",
    [
        ({}, "handle is required"),
        ({"handle": 7}, "handle is required"),
        ({"handle": "recall_run#extract_strings#9"}, "no capability call in this run"),
        ({"handle": "other_run#extract_strings#1"}, "no capability call in this run"),
        ({"handle": "garbage"}, "no capability call in this run"),
        ({"handle": "recall_run#extract_strings#1", "limit": "ten"}, "limit must be an integer"),
    ],
)
def test_a_bad_recall_is_an_explicit_failure(arguments, expected):
    answer = _recall(_state(), arguments)[0]

    assert "failed" in answer and expected in answer


def test_recall_reads_the_same_observation_live_and_from_the_trace(tmp_path):
    state = _state()
    tracer = Tracer(RUN, str(tmp_path))
    for observation in state.observations:
        tracer.turn("", ModelResponse(), [observation["call"]], [observation["result"]], {})
    tracer.save()

    for record in capability_history(state):
        if not record.success:
            continue
        arguments = {"offset": 985, "limit": 10} if record.name == "extract_strings" else {}
        live = select(live_observation(state, record.handle)["result"].output, arguments)
        traced = select(resolve_observation(tmp_path, record.handle)["result"]["output"], arguments)
        assert live == traced


# --- Through the loop


class Recorder:
    """Plays canned responses and keeps every prompt it was sent."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.contexts = []

    def generate(self, context, tools, force=None):
        if force == "record_memory":
            return ModelResponse()  # declines the forced notes call; the script is not consumed
        self.contexts.append(context)
        return self.responses[min(len(self.contexts) - 1, len(self.responses) - 1)]


def _loop(model, tmp_path, output):
    spec = ToolSpec(name="extract_strings", description="Extract strings.", parameters={})
    definition = AgentDefinition(
        role="You are a test investigator.",
        scope="Test scope only.",
        tool_manifest=[spec],
        allowed_tools=[spec],
        max_turns=10,
        max_tool_calls=10,
        output_contract=FinalOutput,
    )
    loop = AgentLoop(
        model,
        ToolRuntime([spec], lambda name, arguments: output),
        CompletionChecker(),
        ContextBuilder(),
        Tracer(run_id="loop_run", output_dir=str(tmp_path)),
    )
    return loop, definition


def recall(**arguments):
    return ModelResponse(tool_calls=[ToolCall(tool_call_id="r", name="recall_observation", arguments=arguments)])


async def test_a_late_indicator_hidden_by_the_digest_is_recalled_for_one_turn(tmp_path):
    handle = trace_provenance("loop_run", "extract_strings", 0)
    model = Recorder(
        ModelResponse(tool_calls=[ToolCall("c1", "extract_strings", {})], memory_update=NOTES),
        recall(handle=handle, contains=["http"]),
        ModelResponse(memory_update=NOTES),
        ModelResponse(report=REPORT),
    )
    loop, definition = _loop(model, tmp_path, PAGE)

    result = await loop.run(Objective(description="test"), definition)

    first, recall_turn, after, last = model.contexts
    assert handle in recall_turn and "partial digest" in recall_turn
    assert URL not in recall_turn  # the digest alone does not show it
    assert URL in after  # the turn after the recall does
    assert URL not in last  # and only that one
    assert result.completion_reason == "reported"
    assert result.metadata["tool_calls"] == 1  # recall is off-budget
    assert loop.completion.memory_rejections == 0  # a recall-only turn owes no notes
    # The authoritative result is untouched in the trace.
    traced = resolve_observation(tmp_path, handle)["result"]["output"]
    assert traced == PAGE


async def test_recalls_past_the_per_turn_cap_are_refused(tmp_path):
    handle = trace_provenance("loop_run", "extract_strings", 0)
    many = ModelResponse(
        tool_calls=[
            ToolCall(f"r{index}", "recall_observation", {"handle": handle, "offset": index, "limit": 1})
            for index in range(MAX_RECALLS_PER_TURN + 1)
        ]
    )
    model = Recorder(
        ModelResponse(tool_calls=[ToolCall("c1", "extract_strings", {})], memory_update=NOTES),
        many,
        ModelResponse(report=REPORT),
    )
    loop, definition = _loop(model, tmp_path, PAGE)

    await loop.run(Objective(description="test"), definition)

    assert "Recall not served" in model.contexts[2]
    assert "items 2..2 of 1000" in model.contexts[2]


# --- fields: survey a whole large array in one recall

from mira.reasoning.runtime.payload import select as select_recall

CAPA = {"data": {"findings": [
    {"rule_id": f"rule-{n:02d}", "namespace": f"ns/{n}", "meta": {"scope": "function", "attack": ["T1"] * 20, "notes": "x" * 400}}
    for n in range(35)
]}}


def test_fields_fit_a_whole_large_array_in_one_recall():
    """The live run paged these 35 findings ten at a time; one recall now does it."""
    text, failure, *_ = select_recall(CAPA, {"path": "data.findings", "limit": 35, "fields": ["rule_id"]})

    assert failure == ""
    assert "items 0..34 of 35" in text and "stopped" not in text
    assert '[34] {"rule_id": "rule-34"}' in text
    assert "meta" not in text.split("\n", 1)[1]  # the bulky block is gone from every item


def test_a_cut_off_recall_suggests_fields_and_names_the_keys():
    text, _, *_ = select_recall(CAPA, {"path": "data.findings", "limit": 35})

    assert "stopped at item" in text
    assert "show fewer keys per item with fields (they have: meta, namespace, rule_id)" in text


def test_contains_searches_whole_items_while_fields_narrow_the_display():
    text, _, *_ = select_recall(CAPA, {"path": "data.findings", "contains": ["ns/7"], "fields": ["rule_id"]})

    assert '[7] {"rule_id": "rule-07"}' in text
    assert "ns/7" not in text.split("\n", 1)[1]


def test_unknown_fields_are_refused_with_the_real_keys():
    _, failure, *_ = select_recall(CAPA, {"path": "data.findings", "fields": ["name"]})

    assert "fields names name" in failure and "their keys are meta, namespace, rule_id" in failure


# --- Targeted retrieval over a whole stored list (KTD5) -----------------------


def recall_imports(output=IMPORTS, **arguments):
    return select(output, {"handle": "h", "path": "data.imports", **arguments})[:2]


def shown(text):
    return [int(line[1:line.index("]")]) for line in text.splitlines()[1:] if line.startswith("[")]


def test_where_matches_a_value_ignoring_case():
    text, failure = recall_imports(where={"dll": "advapi32.dll"}, fields=["dll", "name"], limit=200)

    assert failure == ""
    assert "40 of 412 items" in text
    assert shown(text) == list(range(275, 315))


def test_where_null_matches_items_without_that_value():
    text, _ = recall_imports(where={"name": None})

    assert shown(text) == [409, 410, 411]


def test_a_where_list_means_any_of():
    text, _ = recall_imports(where={"dll": ["USER32.dll", "GDI32.dll"]}, fields=["dll"], limit=200)

    assert "125 of 412 items" in text
    assert shown(text) == list(range(180, 275)) + list(range(315, 345))


def test_group_by_counts_every_value_in_descending_order():
    text, failure = recall_imports(group_by="dll")

    assert failure == ""
    assert "grouped by dll: 9 values" in text
    counts = [int(line.rsplit(" ", 1)[1]) for line in text.splitlines()[1:]]
    assert sum(counts) == 412 and counts == sorted(counts, reverse=True)
    assert text.splitlines()[1] == '"KERNEL32.dll" 180'


def test_group_by_counts_only_the_matched_items():
    text, _ = recall_imports(where={"dll": ["USER32.dll", "GDI32.dll"]}, group_by="dll")

    assert text.splitlines()[1:] == ['"USER32.dll" 95', '"GDI32.dll" 30']


def test_group_by_past_the_recall_limit_says_what_it_left_out():
    text, _ = recall_imports(group_by="name")

    assert len(text) <= MAX_RECALL_CHARS + 300
    assert "values left out" in text


def test_a_range_at_the_end_says_nothing_remains():
    text, _ = recall_imports(offset=400, limit=50)

    assert shown(text) == list(range(400, 412))
    assert "continue" not in text


def test_an_index_path_addresses_the_same_record_as_a_range():
    ranged, _ = recall_imports(offset=37, limit=1)
    single, *_ = select(IMPORTS, {"path": "data.imports.37"})

    assert ranged.splitlines()[1] == "[37] " + single.splitlines()[1]


@pytest.mark.parametrize("arguments, expected", [
    ({"start": 5}, "unknown argument start; accepted: handle, path, offset, limit, contains, where, fields, group_by"),
    ({"where": {"library": "x"}}, "their keys are address, dll, name, ordinal"),
    ({"group_by": "library"}, "their keys are address, dll, name, ordinal"),
    ({"where": "dll=x"}, "where must be an object"),
    ({"where": {"dll": {"nested": 1}}}, "where values must be"),
    ({"group_by": "dll", "fields": ["dll"]}, "fields does not apply to group_by"),
])
def test_unknown_or_malformed_retrieval_arguments_fail_and_name_what_exists(arguments, expected):
    text, failure = recall_imports(**arguments)

    assert text == ""
    assert expected in failure


def test_where_on_a_non_array_fails_and_names_the_arrays():
    _, failure, *_ = select(IMPORTS, {"path": "metadata", "where": {"dll": "x"}})

    assert "metadata is not an array" in failure and "data.imports (412 items)" in failure


def test_an_answer_over_a_truncated_list_names_what_was_never_fetched():
    truncated = imports_envelope(total=12_000, unfetched=11_588, has_more=True, next_offset=412)

    text, _ = recall_imports(truncated, limit=5)

    assert "11588 items of this list were never fetched" in text
    assert "list_imports(offset=412)" in text


def test_an_empty_list_answers_with_no_items():
    text, failure, *_ = select({"data": {"imports": []}}, {"path": "data.imports", "where": {"dll": "x"}})

    assert failure == "" and "0 of 0 items" in text
