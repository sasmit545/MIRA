"""Tests for AgentLoop."""

from agent.contracts.objective import Objective
from agent.contracts.tool import ToolSpec
from agent.contracts.output import FinalOutput
from agent.definition.agent import StaticAgentDefinition
from agent.model.adapter import ModelAdapter
from agent.runtime.context import ContextBuilder
from agent.runtime.tool_runtime import ToolRuntime
from agent.runtime.completion import CompletionChecker
from agent.runtime.trace import Tracer
from agent.runtime.loop import AgentLoop
from agent.contracts.model import ModelResponse


class MockModelAdapter:
    """Mock model adapter for testing that does not require Gemini API."""
    def __init__(self, response):
        self.response = response

    def generate(self, context, tools):
        return self.response


def test_loop_reports_immediately():
    obj = Objective(description="Test objective")
    # Define a minimal agent definition
    agent_def = StaticAgentDefinition(
        instructions="Test instructions",
        tool_manifest=[],
        allowed_tools=[],
        max_turns=10,
        max_tool_calls=10,
        output_contract=FinalOutput
    )
    # Mock model that returns a report immediately
    mock_response = ModelResponse(report='{"summary": "test", "verdict": "test", "findings": [], "evidence": [], "completion_reason": "reported", "metadata": {}}')
    model_adapter = MockModelAdapter(mock_response)
    tool_runtime = ToolRuntime([])
    completion_checker = CompletionChecker()
    context_builder = ContextBuilder()
    tracer = Tracer(run_id="test", output_dir=".")
    loop = AgentLoop(model_adapter, tool_runtime, completion_checker, context_builder, tracer)

    result = loop.run(obj, agent_def)

    assert result.summary == "test"
    assert result.verdict == "test"
    assert result.completion_reason == "reported"
    assert result.metadata["turns"] == 0


def test_loop_stops_after_two_empty_responses():
    obj = Objective(description="Test objective")
    agent_def = StaticAgentDefinition(
        instructions="Test instructions",
        tool_manifest=[],
        allowed_tools=[],
        max_turns=10,
        max_tool_calls=10,
        output_contract=FinalOutput,
    )
    model_adapter = MockModelAdapter(ModelResponse())
    loop = AgentLoop(
        model_adapter,
        ToolRuntime([]),
        CompletionChecker(),
        ContextBuilder(),
        Tracer(run_id="test", output_dir="."),
    )

    result = loop.run(obj, agent_def)

    assert result.completion_reason == "degraded"
    assert result.metadata["turns"] == 2
