"""Tests for AgentLoop."""

import json

from mira.core.evidence import Evidence
from mira.reasoning.contracts.finding import Confidence, Finding, Severity
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

FINDING = {
    "title": "Packed executable",
    "description": "The sample's .text section is packed.",
    "severity": "high",
    "confidence": "medium",
    "evidence_refs": ["E1"],
}


def report(finding=None, **fields):
    """A submitted report carrying one finding, with fields overridden."""
    body = {"summary": "test", "verdict": "suspicious", **fields}
    if finding is not None:
        body["findings"] = [finding]
    return json.dumps(body)


def gathered(*ids):
    """Evidence the specialist minted before the model reported."""
    return [
        Evidence(
            id=identifier,
            observation=f"observation behind {identifier}",
            source_agent="static",
            capability="detect_packer",
            confidence=0.9,
        )
        for identifier in ids
    ]


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
    assert any(not evidence.success for evidence in result.observations)


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
    assert "capability exploded" in result.observations[0].error


async def test_unknown_tool_is_observed(tmp_path):
    model = ScriptedModel(
        ModelResponse(tool_calls=[ToolCall(tool_call_id="1", name="nope", arguments={})]),
        ModelResponse(report=REPORT),
    )
    loop = build_loop(model, tmp_path)

    result = await loop.run(Objective(description="Test objective"), build_definition())

    assert "Unknown tool" in result.observations[0].error


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


# --- Findings are typed values, not passthrough model JSON ------------------


async def run_with_evidence(tmp_path, submitted, *evidence_ids):
    """Run one turn where the model submits `submitted` against known evidence."""
    loop = build_loop(ScriptedModel(ModelResponse(report=submitted)), tmp_path)
    return await loop.run(
        Objective(description="Test objective"),
        build_definition(),
        evidence=gathered(*evidence_ids),
    )


async def test_a_valid_finding_becomes_a_typed_finding(tmp_path):
    result = await run_with_evidence(tmp_path, report(FINDING), "E1")

    assert result.completion_reason == "reported"
    finding = result.findings[0]
    assert isinstance(finding, Finding)
    assert finding.severity is Severity.HIGH
    assert finding.confidence is Confidence.MEDIUM
    assert [ref.evidence_id for ref in finding.evidence_refs] == ["E1"]


async def test_no_raw_dictionary_survives_into_the_findings(tmp_path):
    result = await run_with_evidence(tmp_path, report(FINDING), "E1")

    assert all(isinstance(finding, Finding) for finding in result.findings)


async def test_an_unrecognized_severity_is_rejected_and_reaches_the_model(tmp_path):
    """Rejection is an observation the model can recover from, not an exception."""
    submitted = report({**FINDING, "severity": "catastrophic"})
    model = ScriptedModel(ModelResponse(report=submitted), ModelResponse(report=REPORT))
    loop = build_loop(model, tmp_path)

    result = await loop.run(
        Objective(description="Test objective"), build_definition(), evidence=gathered("E1")
    )

    assert result.completion_reason == "reported"
    rejection = next(item for item in result.observations if not item.success)
    assert "severity" in rejection.error
    assert "catastrophic" in rejection.error


async def test_a_finding_naming_unknown_evidence_is_rejected(tmp_path):
    result = await run_with_evidence(
        tmp_path, report({**FINDING, "evidence_refs": ["E9"]}), "E1"
    )

    assert result.completion_reason != "reported"
    assert any("E9" in (item.error or "") for item in result.observations)


async def test_a_finding_missing_its_title_is_rejected(tmp_path):
    submitted = report({key: value for key, value in FINDING.items() if key != "title"})

    result = await run_with_evidence(tmp_path, submitted, "E1")

    assert result.completion_reason != "reported"
    assert any("title" in (item.error or "") for item in result.observations)


async def test_a_finding_citing_no_evidence_is_rejected_when_evidence_exists(tmp_path):
    """A finding the orchestrator cannot check back to an observation is not
    a finding it can act on."""
    result = await run_with_evidence(tmp_path, report({**FINDING, "evidence_refs": []}), "E1")

    assert result.completion_reason != "reported"
    assert any("evidence_refs" in (item.error or "") for item in result.observations)


async def test_a_finding_citing_no_evidence_is_accepted_when_none_was_gathered(tmp_path):
    """Nothing to cite must not deadlock the model into endless rejection."""
    result = await run_with_evidence(tmp_path, report({**FINDING, "evidence_refs": []}))

    assert result.completion_reason == "reported"
    assert result.findings[0].evidence_refs == []


async def test_a_malformed_report_then_a_valid_one_completes_as_reported(tmp_path):
    model = ScriptedModel(
        ModelResponse(report=report({**FINDING, "confidence": "very sure"})),
        ModelResponse(report=report(FINDING)),
    )
    loop = build_loop(model, tmp_path)

    result = await loop.run(
        Objective(description="Test objective"), build_definition(), evidence=gathered("E1")
    )

    assert result.completion_reason == "reported"
    assert result.findings[0].confidence is Confidence.MEDIUM


async def test_recommended_actions_ride_the_report(tmp_path):
    submitted = report(FINDING, recommended_actions=["Run the sample in a sandbox"])

    result = await run_with_evidence(tmp_path, submitted, "E1")

    assert result.recommended_actions == ["Run the sample in a sandbox"]


async def test_a_report_with_no_recommended_actions_is_still_valid(tmp_path):
    result = await run_with_evidence(tmp_path, report(FINDING), "E1")

    assert result.recommended_actions == []
