"""Tests for ContextBuilder."""

from agent.contracts.objective import Objective
from agent.contracts.output import FinalOutput
from agent.contracts.state import State
from agent.contracts.tool import ToolCall, ToolResult, ToolSpec
from agent.definition.agent import StaticAgentDefinition
from agent.runtime.context import MAX_OBSERVATION_CHARS, ContextBuilder, truncate

SPEC = ToolSpec(name="file_info", description="Identify hashes.", parameters={})


def build_definition():
    return StaticAgentDefinition(
        instructions="Test instructions",
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
