"""End-to-end: the composed agent drives real MCP capabilities.

Uses a scripted model so the run is deterministic, but everything below the
model is real — artifact store, MCP server, isolated worker, and the loop.
"""

import asyncio
import json
import os
import re
import subprocess
import sys
from dataclasses import asdict
from pathlib import Path

import pytest

from support import build_minimal_pe

from mira.agents.static.agent import StaticAgent
from mira.agents.static.wiring import build_client
from mira.core.objective import InvestigationObjective
from mira.core.state import InvestigationState
from mira.reasoning.contracts.finding import Confidence, Severity
from mira.reasoning.runtime.trace import resolve_observation

from mira.reasoning.contracts.model import ModelResponse
from mira.reasoning.contracts.tool import ToolCall, ToolResult
from mira.reasoning.main import _print_turn, investigate

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

    result = output.observations[0]
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

    output = await investigate(
        sample,
        "Characterize the sample",
        trace_dir=tmp_path / "runs",
        model=build_model(),
    )

    assert (tmp_path / "runs" / "trace_sample_characterize_the_sample.json").is_file()
    # The whole point of one run id: metadata names the file on disk, so an
    # evidence reference can be resolved back to its full observation.
    assert output.metadata["run_id"] == "sample_characterize_the_sample"


async def test_two_objectives_do_not_overwrite_each_others_trace(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(SAMPLE_BYTES)

    first = await investigate(
        sample, "Assess packing", trace_dir=tmp_path / "runs", model=build_model()
    )
    second = await investigate(
        sample, "Assess capability", trace_dir=tmp_path / "runs", model=build_model()
    )

    assert first.metadata["run_id"] != second.metadata["run_id"]
    for output in (first, second):
        assert (tmp_path / "runs" / f"trace_{output.metadata['run_id']}.json").is_file()


def test_the_run_id_is_stable_across_processes():
    """hash() is seed-randomized per process, so a run id derived from it
    named a different trace file on every run."""
    source = (
        "from mira.reasoning.composition import build_run_id;"
        "print(build_run_id('sample', 'Assess packing'))"
    )
    seeds = [
        subprocess.run(
            [sys.executable, "-c", source],
            capture_output=True,
            text=True,
            check=True,
            env={**os.environ, "PYTHONHASHSEED": seed},
        ).stdout.strip()
        for seed in ("1", "2")
    ]
    assert seeds == ["sample_assess_packing", "sample_assess_packing"]


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

    result = output.observations[0]
    assert result.success, result.error
    assert result.output["data"]["size"] == len(SAMPLE_BYTES)


# --- The orchestrator-facing boundary --------------------------------------
# What the specialist returns lands in another model's context window. These
# assert the two properties that makes necessary: it stays small, and it
# carries no raw capability output.

# Measured against this sample: the message is ~474 bytes where the raw
# capability output it was derived from is ~162 KB. The budget is deliberately
# slack enough for a run that gathers far more evidence, and still fails loudly
# if a single page of raw output ever leaks back in.
MESSAGE_BUDGET_BYTES = 8 * 1024

# Enough distinct long strings that a single extract_strings page dwarfs any
# reasonable message budget.
BULK_STRINGS = b"".join(
    f"https://command-and-control-{n:04}.example.invalid/beacon/payload\x00".encode()
    for n in range(2000)
)

HIGH_VOLUME_OBJECTIVE = InvestigationObjective(
    name="Assess packing and capability",
    description="Assess whether the sample is packed and what it can do.",
    reason="test",
    capabilities=("extract_strings", "disassemble_function", "file_info"),
)


def build_high_volume_sample(directory):
    """A real PE with a large string blob, so the capabilities return real bulk."""
    sample = directory / "sample.exe"
    sample.write_bytes(build_minimal_pe() + BULK_STRINGS)
    return sample


class HighVolumeModel:
    """Calls the two highest-volume capabilities, then reports on what it saw."""

    def __init__(self):
        self.turn = 0

    def generate(self, context, tools):
        self.turn += 1
        if self.turn == 1:
            return ModelResponse(tool_calls=[
                ToolCall(tool_call_id="1", name="extract_strings",
                         arguments={"limit": 1000, "min_length": 4}),
                ToolCall(tool_call_id="2", name="disassemble_function",
                         arguments={"function_address": 0x1000, "limit": 1000}),
            ])
        cited = re.findall(r"^\s+(E\d+) \[", context, re.MULTILINE)
        return ModelResponse(report=json.dumps({
            "summary": "The sample embeds many command-and-control URLs.",
            "verdict": "malicious",
            "findings": [{
                "title": "Embedded command-and-control URLs",
                "description": "The sample carries a large table of beacon URLs.",
                "severity": "high",
                "confidence": "high",
                "evidence_refs": cited,
            }],
            "recommended_actions": ["Extract the full URL table for blocking."],
        }))


async def run_high_volume(tmp_path):
    sample = build_high_volume_sample(tmp_path)
    client, artifact_id = build_client(sample)
    agent = StaticAgent(client, model=HighVolumeModel(), trace_dir=tmp_path / "runs")
    state = InvestigationState()
    message = await agent.investigate(HIGH_VOLUME_OBJECTIVE, artifact_id, state=state)
    return message, state, tmp_path / "runs"


@pytest.fixture(scope="module")
def high_volume(tmp_path_factory):
    """One real high-volume run, shared: it drives isolated workers over a
    140 KB sample and is far too slow to repeat per assertion."""
    return asyncio.run(run_high_volume(tmp_path_factory.mktemp("high_volume")))


def serialize(message) -> str:
    return json.dumps(asdict(message), default=str)


def raw_outputs(trace_dir) -> list:
    """Every full capability result the run produced, straight from the trace."""
    trace = next(Path(trace_dir).glob("trace_*.json"))
    return [
        result.get("output")
        for turn in json.loads(trace.read_text())
        for result in turn.get("tool_results") or []
        if result.get("output")
    ]


def test_the_message_stays_within_its_budget(high_volume):
    """The return value sits in an orchestrator's context beside the findings
    of every prior specialist run, so its size cannot track its input's."""
    message, _, _ = high_volume

    serialized = serialize(message)
    assert len(serialized.encode()) < MESSAGE_BUDGET_BYTES, (
        f"the message is {len(serialized.encode())} bytes"
    )


def test_no_raw_capability_output_reaches_the_message(high_volume):
    message, _, trace_dir = high_volume

    serialized = serialize(message)
    needles = [
        json.dumps(value[0], default=str)
        for output in raw_outputs(trace_dir)
        for value in (output.get("data") or {}).values()
        if isinstance(value, list) and value
    ]
    assert needles, "the run produced no capability output to check against"

    # Collect first and assert on the small list: asserting against the
    # serialized message directly makes a failure render megabytes.
    leaked = [needle for needle in needles if needle in serialized]
    assert not leaked, f"raw capability output reached the message: {leaked}"


def test_every_evidence_reference_in_the_message_resolves(high_volume):
    message, state, trace_dir = high_volume

    assert message.evidence_refs
    for reference in message.evidence_refs:
        evidence = state.get_evidence_by_id(reference)
        assert evidence is not None, reference
        assert resolve_observation(trace_dir, evidence.provenance) is not None


def test_every_finding_carries_enum_severity_and_confidence(high_volume):
    message, _, _ = high_volume

    assert message.findings
    for finding in message.findings:
        assert isinstance(finding.severity, Severity)
        assert isinstance(finding.confidence, Confidence)
        assert all(ref.evidence_id in message.evidence_refs for ref in finding.evidence_refs)


def test_the_message_carries_every_field_the_finding_payload_names(high_volume):
    message, _, _ = high_volume

    assert set(asdict(message)) == {
        "artifact_id",
        "assessment",
        "findings",
        "evidence_refs",
        "confidence",
        "recommended_actions",
    }
    assert message.artifact_id
    assert message.assessment


def test_the_cli_still_reports_each_capability_as_it_runs(capsys):
    """The specialist's message narrowed; the CLI view, which is not context
    bound, still shows what ran and how it went."""
    _print_turn({
        "kind": "tool_calls",
        "turn": 1,
        "calls": [ToolCall(tool_call_id="1", name="file_info", arguments={})],
        "results": [ToolResult(tool_call_id="1", success=True, output={"status": "ok"})],
        "usage": None,
    })

    printed = capsys.readouterr().out
    assert "file_info" in printed
    assert "ok" in printed
