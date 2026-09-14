"""Tests for CompletionChecker."""

from mira.reasoning.runtime.completion import CompletionChecker
from mira.reasoning.contracts.objective import Objective
from mira.reasoning.definition.agent import AgentDefinition
from mira.reasoning.contracts.state import State


def test_completion_checker_initialization():
    checker = CompletionChecker()
    assert checker.consecutive_empty_responses == 0


def test_is_active_max_turns():
    obj = Objective(description="Test objective")
    state = State(objective=obj, run_id="test_run")
    state.turn_count = 10
    agent_def = AgentDefinition(
        role="Test role.",
        scope="Test scope.",
        tool_manifest=[],
        allowed_tools=[],
        max_turns=5,
        max_tool_calls=100,
        output_contract=object  # dummy
    )
    checker = CompletionChecker()
    assert not checker.is_active(state, agent_def)


def test_is_active_max_tool_calls():
    obj = Objective(description="Test objective")
    state = State(objective=obj, run_id="test_run")
    state.tool_call_count = 10
    agent_def = AgentDefinition(
        role="Test role.",
        scope="Test scope.",
        tool_manifest=[],
        allowed_tools=[],
        max_turns=100,
        max_tool_calls=5,
        output_contract=object  # dummy
    )
    checker = CompletionChecker()
    assert not checker.is_active(state, agent_def)


def test_is_active_consecutive_empty_responses():
    obj = Objective(description="Test objective")
    state = State(objective=obj, run_id="test_run")
    agent_def = AgentDefinition(
        role="Test role.",
        scope="Test scope.",
        tool_manifest=[],
        allowed_tools=[],
        max_turns=100,
        max_tool_calls=100,
        output_contract=object  # dummy
    )
    checker = CompletionChecker()
    checker.consecutive_empty_responses = 2
    assert not checker.is_active(state, agent_def)


def test_record_empty_response():
    checker = CompletionChecker()
    checker.record_empty_response()
    assert checker.consecutive_empty_responses == 1
    checker.record_empty_response()
    assert checker.consecutive_empty_responses == 2


def test_record_non_empty_response():
    checker = CompletionChecker()
    checker.consecutive_empty_responses = 2
    checker.record_non_empty_response()
    assert checker.consecutive_empty_responses == 0
