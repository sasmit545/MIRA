"""Tests for ContextBuilder."""

from agent.runtime.context import ContextBuilder
from agent.contracts.state import State
from agent.contracts.objective import Objective


def test_context_builder_build():
    obj = Objective(description="Test objective")
    state = State(objective=obj)
    # We don't have a real agent_definition, so we'll pass None
    context = ContextBuilder.build(state, None)
    assert isinstance(context, str)
    assert "Objective: Test objective" in context
    assert "Turn: 0" in context
