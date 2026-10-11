"""Tests for ContextBuilder."""

from mira.core.evidence import Evidence
from mira.reasoning.contracts.objective import Objective
from mira.reasoning.contracts.output import FinalOutput
from mira.reasoning.contracts.state import State
from mira.reasoning.contracts.tool import ToolCall, ToolResult, ToolSpec
from mira.reasoning.definition.agent import AgentDefinition
from mira.reasoning.runtime.context import MAX_OBSERVATION_CHARS, ContextBuilder, truncate

SPEC = ToolSpec(name="file_info", description="Identify hashes.", parameters={})
ROLE = "You are a test investigator."
SCOPE = "Test scope only."


def build_definition(role=ROLE, scope=SCOPE):
    return AgentDefinition(
        role=role,
        scope=scope,
        tool_manifest=[SPEC],
        allowed_tools=[SPEC],
        max_turns=10,
        max_tool_calls=10,
        output_contract=FinalOutput,
    )


def build_state():
    return State(objective=Objective(description="Test objective"), run_id="test_run")


def test_context_includes_objective_and_tools():
    context = ContextBuilder.build(build_state(), build_definition())

    assert "Test objective" in context
    assert "file_info" in context
    assert "Identify hashes." in context


def test_context_carries_the_definitions_role_and_scope():
    """Role and scope come from the definition, so each specialist sets its own."""
    context = ContextBuilder.build(
        build_state(),
        build_definition(
            role="You are a dynamic malware investigator.",
            scope="Runtime behavior only.",
        ),
    )

    assert "You are a dynamic malware investigator." in context
    assert "Runtime behavior only." in context
    assert "static" not in context.lower()


def test_context_reports_an_empty_history():
    context = ContextBuilder.build(build_state(), build_definition())

    assert "no tools have been called yet" in context


def test_context_shows_each_call_by_handle_with_its_digest():
    state = build_state()
    state.record_tool_call(ToolCall(tool_call_id="1", name="file_info", arguments={}))
    state.record_tool_result(
        ToolResult(tool_call_id="1", success=True, output={"size": 4})
    )

    context = ContextBuilder.build(state, build_definition())

    assert "[test_run#file_info#0] file_info()" in context
    assert '{"size": 4}' in context  # a small result's digest is the whole result


def test_context_includes_tool_errors():
    state = build_state()
    state.record_tool_call(ToolCall(tool_call_id="1", name="file_info", arguments={}))
    state.record_tool_result(
        ToolResult(tool_call_id="1", success=False, error="it broke")
    )

    context = ContextBuilder.build(state, build_definition())

    assert "ERROR: it broke" in context


def test_a_large_result_is_digested_not_dumped():
    state = build_state()
    page = [{"value": f"string-{index}", "offset": index} for index in range(1000)]
    state.record_tool_call(ToolCall(tool_call_id="1", name="file_info", arguments={}))
    state.record_tool_result(
        ToolResult(tool_call_id="1", success=True, output={"status": "ok", "data": {"strings": page}})
    )

    context = ContextBuilder.build(state, build_definition())

    assert "partial digest" in context
    assert "data.strings (1000)" in context
    assert "data.strings: 1000 items, fields {value, offset}" in context
    assert "string-999" not in context and "string-500" not in context
    assert len(context) < 6_000


def test_a_harness_note_is_shown_without_a_handle():
    state = build_state()
    state.record_harness_observation(
        ToolCall(tool_call_id="dup", name="file_info", arguments={}),
        ToolResult(tool_call_id="dup", success=False, error="Not rerun"),
    )

    context = ContextBuilder.build(state, build_definition())

    assert "- file_info()" in context
    assert "ERROR: Not rerun" in context
    assert "#file_info#" not in context


def test_a_recall_is_rendered_in_its_own_section():
    state = build_state()
    state.recalled.append("recall_observation(handle='x'):\nanswer-text")

    context = ContextBuilder.build(state, build_definition())

    assert "Recalled this turn" in context
    assert "answer-text" in context


def test_the_instructions_say_how_to_read_past_a_digest():
    assert "recall_observation" in ContextBuilder.build(build_state(), build_definition())


def test_truncate_leaves_short_text_alone():
    assert truncate("short") == "short"
    assert truncate("A" * (MAX_OBSERVATION_CHARS + 1)).startswith("A")


def test_gathered_evidence_is_shown_with_the_identifiers_to_cite():
    """The model is required to cite evidence identifiers in its findings, so
    the context has to name them - otherwise every finding is rejected."""
    state = build_state()
    state.add_evidence(
        Evidence(
            id="E1",
            observation="Section '.text' has entropy 7.90.",
            source_agent="static",
            capability="analyze_pe",
            confidence=0.9,
        )
    )

    context = ContextBuilder.build(state, build_definition())

    assert "E1" in context
    assert "analyze_pe" in context
    assert "entropy 7.90" in context


def test_a_run_with_no_evidence_says_nothing_about_it():
    assert "cite these identifiers" not in ContextBuilder.build(
        build_state(), build_definition()
    )


# --- Working memory in the prompt (U6)

from mira.reasoning.contracts.memory import Candidate, MemoryHypothesis, OpenQuestion


def test_an_empty_notebook_claims_nothing():
    context = ContextBuilder.build(build_state(), build_definition())

    assert "Your working notes" in context
    assert "(none recorded yet)" in context
    assert "Hypotheses:" not in context


def test_the_notes_are_rendered_with_evidence_and_disposition():
    state = build_state()
    memory = state.working_memory
    memory.understanding = "Likely a packed dropper."
    memory.hypotheses.append(
        MemoryHypothesis(
            id="H1",
            statement="The sample is packed.",
            confidence=0.8,
            supporting_evidence=["E1"],
            contradicting_evidence=["E2"],
            unknowns="Whether it unpacks at runtime.",
        )
    )
    memory.open_questions.append(OpenQuestion(id="Q1", question="What does it download?"))
    memory.candidates.append(Candidate(id="C1", investigation="Search strings for URLs"))

    context = ContextBuilder.build(state, build_definition())

    assert "Understanding: Likely a packed dropper." in context
    assert "H1 [open, confidence 0.80] The sample is packed." in context
    assert "supported by: E1" in context and "weakened by: E2" in context
    assert "unknowns: Whether it unpacks at runtime." in context
    assert "Q1 What does it download?" in context
    assert "C1 Search strings for URLs" in context


def test_the_instructions_state_the_notes_obligations():
    context = ContextBuilder.build(build_state(), build_definition())

    assert "record_memory in the same response as every capability call" in context
    assert "Notes are additive" in context and "close" in context
    assert "questions you could not close" in context


import re

import pytest

# Whole words: "capa" must not match inside "capability".
STATIC_VOCABULARY = re.compile(r"\b(static|disassembl\w*|yara|capa|import table|pe)\b")


@pytest.mark.parametrize("role, scope", [
    ("You are a dynamic malware investigator.", "Runtime behavior only."),
    ("You are a forensic investigator.", "Memory and disk artifacts only."),
])
def test_the_generic_notes_carry_no_static_vocabulary(role, scope):
    """Dynamic and Forensics inherit this rendering; it must not speak static."""
    state = build_state()
    state.working_memory.understanding = "Behaves like a loader."
    state.working_memory.hypotheses.append(
        MemoryHypothesis(id="H1", statement="It persists across reboots.", unknowns="Which mechanism.")
    )
    state.working_memory.open_questions.append(OpenQuestion(id="Q1", question="Where does it write?"))
    state.working_memory.candidates.append(Candidate(id="C1", investigation="Check autoruns"))

    context = ContextBuilder.build(state, build_definition(role=role, scope=scope)).lower()

    assert STATIC_VOCABULARY.findall(context) == []


def test_a_digest_of_any_array_speaks_only_its_own_keys_and_values():
    """The schema digest is generic: nothing static leaks into it."""
    from mira.reasoning.runtime.payload import digest

    visits = {"data": {"visits": [{"city": city, "minutes": minutes % 7} for minutes, city in enumerate(["Lima", "Oslo"] * 40)]}}

    text = digest(visits)

    assert "fields {city, minutes}" in text and '"Lima" 40' in text
    assert STATIC_VOCABULARY.findall(text.lower()) == []


def test_a_huge_successful_result_barely_grows_the_prompt():
    """U6 verification: a 10,000-character result leaves the prompt within a
    few hundred characters of its prior size, with its handle and digest."""
    state = build_state()
    before = len(ContextBuilder.build(state, build_definition()))
    state.record_tool_call(ToolCall(tool_call_id="1", name="file_info", arguments={}))
    state.record_tool_result(ToolResult(tool_call_id="1", success=True, output="A" * 10_000))

    context = ContextBuilder.build(state, build_definition())

    assert len(context) - before < 400
    assert "[test_run#file_info#0]" in context
    assert "partial digest" in context
    assert "A" * 100 not in context


def test_the_notes_rule_closes_the_prompt_and_covers_the_empty_case():
    """A live model dropped the notes when it had nothing new or was recalling."""
    context = ContextBuilder.build(build_state(), build_definition())

    assert context.rstrip().splitlines()[-1].startswith("Reminder: any response that calls a capability must also call record_memory")
    assert "even when nothing changed: send empty lists" in context
    assert "never two such turns in a row" in context


def test_the_history_shows_which_items_recalls_have_shown():
    from mira.reasoning.runtime.loop import _recall

    state = build_state()
    rows = [{"dll": "KERNEL32.dll", "name": f"Fn{index}"} for index in range(412)]
    state.record_tool_call(ToolCall(tool_call_id="1", name="file_info", arguments={}))
    state.record_tool_result(ToolResult(tool_call_id="1", success=True, output={"data": {"imports": rows}}))
    handle = "test_run#file_info#0"
    _recall(state, {"handle": handle, "path": "data.imports", "limit": 50})
    _recall(state, {"handle": handle, "path": "data.imports", "offset": 400})

    context = ContextBuilder.build(state, build_definition())

    assert "shown data.imports: 0..49, 400..411 (62 of 412)" in context


def test_each_evidence_line_names_its_grade_and_never_the_number():
    state = build_state()
    for index, (capability, confidence) in enumerate([("extract_strings", 0.4), ("list_imports", 0.6), ("run_capa", 0.9)]):
        state.add_evidence(Evidence(
            id=f"E{index + 1}", observation=f"observation {index + 1}", source_agent="static",
            capability=capability, confidence=confidence,
        ))

    context = ContextBuilder.build(state, build_definition())

    assert "E1 [extract_strings, weak] observation 1" in context
    assert "E2 [list_imports, moderate] observation 2" in context
    assert "E3 [run_capa, strong] observation 3" in context
    assert "0.9" not in context and "0.4" not in context


def test_the_prompt_says_evidence_lines_are_graded_conclusions():
    context = ContextBuilder.build(build_state(), build_definition())

    assert "graded conclusions" in context and "source data" in context
    assert "Low entropy" in context and "not encryption" in context
    assert "capability is not intent" in context
