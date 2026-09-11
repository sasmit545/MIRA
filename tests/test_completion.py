"""Tests for CompletionChecker."""

from agent.runtime.completion import CompletionChecker
from agent.contracts.objective import Objective
from agent.definition.agent import StaticAgentDefinition
from agent.contracts.state import State


def test_completion_checker_initialization():
    checker = CompletionChecker()
    assert checker.consecutive_empty_responses == 0


def test_is_active_max_turns():
    obj = Objective(description="Test objective")
    state = State(objective=obj)
    state.turn_count = 10
    agent_def = StaticAgentDefinition(
        instructions="Test",
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
    state = State(objective=obj)
    state.tool_call_count = 10
    agent_def = StaticAgentDefinition(
        instructions="Test",
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
    state = State(objective=obj)
    agent_def = StaticAgentDefinition(
        instructions="Test",
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
