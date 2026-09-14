"""Tests for AgentLoop."""

from mira.reasoning.contracts.model import ModelResponse
from mira.reasoning.contracts.objective import Objective
from mira.reasoning.contracts.output import FinalOutput
from mira.reasoning.contracts.tool import ToolCall, ToolSpec
from mira.reasoning.definition.agent import AgentDefinition
from mira.reasoning.runtime.completion import CompletionChecker
from mira.reasoning.runtime.context import ContextBuilder
from mira.reasoning.runtime.loop import AgentLoop
from mira.reasoning.runtime.tool_runtime import ToolRuntime
from mira.reasoning.runtime.trace import Tracer

REPORT = '{"summary": "test", "verdict": "test", "findings": []}'


class ScriptedModel:
    """Plays a sequence of canned responses, repeating the last one."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = 0

    def generate(self, context, tools):
        response = self.responses[min(self.calls, len(self.responses) - 1)]
        self.calls += 1
        return response


def build_definition(tools=(), max_turns=10, max_tool_calls=10):
    return AgentDefinition(
        role="You are a test investigator.",
        scope="Test scope only.",
        tool_manifest=list(tools),
        allowed_tools=list(tools),
        max_turns=max_turns,
        max_tool_calls=max_tool_calls,
        output_contract=FinalOutput,
    )


def build_loop(model, tmp_path, tools=(), executor=None, on_turn=None):
    return AgentLoop(
        model,
        ToolRuntime(list(tools), executor),
        CompletionChecker(),
        ContextBuilder(),
        Tracer(run_id="test", output_dir=str(tmp_path)),
        on_turn=on_turn,
    )


async def test_loop_reports_immediately(tmp_path):
    loop = build_loop(ScriptedModel(ModelResponse(report=REPORT)), tmp_path)

    result = await loop.run(Objective(description="Test objective"), build_definition())

    assert result.summary == "test"
    assert result.completion_reason == "reported"
    assert result.metadata["turns"] == 0


async def test_loop_stops_after_two_empty_responses(tmp_path):
    loop = build_loop(ScriptedModel(ModelResponse()), tmp_path)

    result = await loop.run(Objective(description="Test objective"), build_definition())

    assert result.completion_reason == "degraded"
    assert result.metadata["turns"] == 2


async def test_loop_writes_a_trace_file(tmp_path):
    loop = build_loop(ScriptedModel(ModelResponse(report=REPORT)), tmp_path)

    await loop.run(Objective(description="Test objective"), build_definition())

    assert (tmp_path / "trace_test.json").is_file()


async def test_malformed_report_is_observed_then_recovered(tmp_path):
    model = ScriptedModel(ModelResponse(report="not json"), ModelResponse(report=REPORT))
    loop = build_loop(model, tmp_path)

    result = await loop.run(Objective(description="Test objective"), build_definition())

    assert result.completion_reason == "reported"
    assert any(not evidence.success for evidence in result.evidence)


async def test_tool_failure_is_observed_not_raised(tmp_path):
    spec = ToolSpec(name="boom", description="fails", parameters={})

    def executor(name, arguments):
        raise RuntimeError("capability exploded")

    model = ScriptedModel(
        ModelResponse(tool_calls=[ToolCall(tool_call_id="1", name="boom", arguments={})]),
        ModelResponse(report=REPORT),
    )
    loop = build_loop(model, tmp_path, tools=[spec], executor=executor)

    result = await loop.run(
        Objective(description="Test objective"), build_definition(tools=[spec])
    )

    assert result.completion_reason == "reported"
    assert "capability exploded" in result.evidence[0].error


async def test_unknown_tool_is_observed(tmp_path):
    model = ScriptedModel(
        ModelResponse(tool_calls=[ToolCall(tool_call_id="1", name="nope", arguments={})]),
        ModelResponse(report=REPORT),
    )
    loop = build_loop(model, tmp_path)

    result = await loop.run(Objective(description="Test objective"), build_definition())

    assert "Unknown tool" in result.evidence[0].error


async def test_on_turn_sees_each_tool_call_and_the_final_report(tmp_path):
    spec = ToolSpec(name="probe", description="probes", parameters={})
    model = ScriptedModel(
        ModelResponse(tool_calls=[ToolCall(tool_call_id="1", name="probe", arguments={})]),
        ModelResponse(report=REPORT),
    )
    events = []
    loop = build_loop(
        model, tmp_path, tools=[spec], executor=lambda name, arguments: "ok", on_turn=events.append
    )

    await loop.run(Objective(description="Test objective"), build_definition(tools=[spec]))

    kinds = [event["kind"] for event in events]
    assert kinds == ["tool_calls", "report"]
    assert events[0]["calls"][0].name == "probe"


async def test_a_broken_on_turn_callback_does_not_break_the_loop(tmp_path):
    model = ScriptedModel(ModelResponse(report=REPORT))
    loop = build_loop(model, tmp_path, on_turn=lambda event: 1 / 0)

    result = await loop.run(Objective(description="Test objective"), build_definition())

    assert result.completion_reason == "reported"
