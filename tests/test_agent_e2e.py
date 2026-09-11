"""End-to-end: the composed agent drives real MCP capabilities.

Uses a scripted model so the run is deterministic, but everything below the
model is real — artifact store, MCP server, isolated worker, and the loop.
"""

from agent.contracts.model import ModelResponse
from agent.contracts.tool import ToolCall
from agent.main import investigate

REPORT = '{"summary": "a small file", "verdict": "benign", "findings": []}'
SAMPLE_BYTES = b"hello world" * 10


class ScriptedModel:
    """Plays canned responses and records every context it was given."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.contexts = []

    def generate(self, context, tools):
        self.contexts.append(context)
        index = min(len(self.contexts) - 1, len(self.responses) - 1)
        return self.responses[index]


def build_model():
    return ScriptedModel(
        ModelResponse(tool_calls=[ToolCall(tool_call_id="1", name="file_info", arguments={})]),
        ModelResponse(report=REPORT),
    )


async def test_agent_investigates_a_real_sample(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(SAMPLE_BYTES)
    model = build_model()

    output = await investigate(
        sample,
        "Characterize the sample",
        trace_dir=tmp_path / "runs",
        model=model,
    )

    assert output.completion_reason == "reported"
    assert output.verdict == "benign"
    assert output.metadata["tool_calls"] == 1

    result = output.evidence[0]
    assert result.success, result.error
    assert result.output["data"]["size"] == len(SAMPLE_BYTES)


async def test_the_model_sees_the_previous_tool_result(tmp_path):
    """The point of the context builder: turn two can see turn one's output."""
    sample = tmp_path / "sample.bin"
    sample.write_bytes(SAMPLE_BYTES)
    model = build_model()

    await investigate(
        sample,
        "Characterize the sample",
        trace_dir=tmp_path / "runs",
        model=model,
    )

    first_context, second_context = model.contexts
    assert "no tools have been called yet" in first_context
    assert "file_info" in second_context
    assert str(len(SAMPLE_BYTES)) in second_context


async def test_a_trace_is_written_for_the_run(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(SAMPLE_BYTES)

    await investigate(
        sample,
        "Characterize the sample",
        trace_dir=tmp_path / "runs",
        model=build_model(),
    )

    assert (tmp_path / "runs" / "trace_sample.json").is_file()


async def test_the_model_cannot_retarget_another_artifact(tmp_path):
    """artifact_id is bound by the runtime, so a model-supplied one is ignored."""
    sample = tmp_path / "sample.bin"
    sample.write_bytes(SAMPLE_BYTES)
    model = ScriptedModel(
        ModelResponse(
            tool_calls=[
                ToolCall(
                    tool_call_id="1",
                    name="file_info",
                    arguments={"artifact_id": "somewhere-else"},
                )
            ]
        ),
        ModelResponse(report=REPORT),
    )

    output = await investigate(
        sample,
        "Characterize the sample",
        trace_dir=tmp_path / "runs",
        model=model,
    )

    result = output.evidence[0]
    assert result.success, result.error
    assert result.output["data"]["size"] == len(SAMPLE_BYTES)
