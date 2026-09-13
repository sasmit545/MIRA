"""Tests for ContextBuilder."""

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
    return State(objective=Objective(description="Test objective"))


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


def test_context_includes_tool_results():
    state = build_state()
    state.record_tool_call(ToolCall(tool_call_id="1", name="file_info", arguments={}))
    state.record_tool_result(
        ToolResult(tool_call_id="1", success=True, output={"size": 4})
    )

    context = ContextBuilder.build(state, build_definition())

    assert "file_info" in context
    assert "'size': 4" in context


def test_context_includes_tool_errors():
    state = build_state()
    state.record_tool_call(ToolCall(tool_call_id="1", name="file_info", arguments={}))
    state.record_tool_result(
        ToolResult(tool_call_id="1", success=False, error="it broke")
    )

    context = ContextBuilder.build(state, build_definition())

    assert "ERROR: it broke" in context


def test_long_results_are_truncated():
    state = build_state()
    state.record_tool_call(ToolCall(tool_call_id="1", name="file_info", arguments={}))
    state.record_tool_result(
        ToolResult(tool_call_id="1", success=True, output="A" * 10_000)
    )

    context = ContextBuilder.build(state, build_definition())

    assert "truncated" in context
    assert len(context) < 10_000


def test_truncate_leaves_short_text_alone():
    assert truncate("short") == "short"
    assert truncate("A" * (MAX_OBSERVATION_CHARS + 1)).startswith("A")
