"""Agent loop."""

import json
from typing import Callable, List, Optional

from ..contracts.finding import Confidence, Evidence, Finding, Severity
from ..contracts.model import ModelResponse
from ..contracts.objective import Objective
from ..contracts.output import FinalOutput
from ..contracts.state import State
from ..contracts.tool import ToolCall, ToolResult, ToolSpec
from ..definition.agent import AgentDefinition
from ..model.adapter import ModelAdapter
from .completion import CompletionChecker
from .context import ContextBuilder
from .tool_runtime import ToolRuntime
from .trace import Tracer

REPORT_TOOL_CALL_ID = "submit_report"


class AgentLoop:
    """The agent loop that drives the investigation."""

    def __init__(
        self,
        model_adapter: ModelAdapter,
        tool_runtime: ToolRuntime,
        completion_checker: CompletionChecker,
        context_builder: ContextBuilder,
        tracer: Tracer,
        on_turn: Optional[Callable[[dict], None]] = None,
    ):
        self.model = model_adapter
        self.tools = tool_runtime
        self.completion = completion_checker
        self.context = context_builder
        self.tracer = tracer
        self.on_turn = on_turn

    def _notify(self, event: dict) -> None:
        """Best-effort live view of the loop for a CLI or other observer.
        Never lets a printer bug take down the investigation."""
        if self.on_turn is None:
            return
        try:
            self.on_turn(event)
        except Exception:
            pass

    async def run(
        self,
        objective: Objective,
        agent_def: AgentDefinition,
        evidence: Optional[List] = None,
    ) -> FinalOutput:
        """Run the investigation until completion. Always writes a trace.

        `evidence` is the specialist's own accumulator, shared rather than
        copied: the specialist mints evidence as results arrive, and the loop
        reads it both to show the model what it may cite and to reject a
        finding that cites something never observed.
        """
        # The tracer names the trace file; taking the run id from it is what
        # makes a recorded evidence reference resolvable back to that file.
        state = State(
            objective=objective,
            run_id=self.tracer.run_id,
            evidence=evidence if evidence is not None else [],
        )
        try:
            return await self._run(state, agent_def)
        finally:
            self.tracer.save()

    async def _run(self, state: State, agent_def: AgentDefinition) -> FinalOutput:
        while self.completion.is_active(state, agent_def):
            context_str = self.context.build(state, agent_def)
            available_tools: List[ToolSpec] = agent_def.allowed_tools

            response: ModelResponse = self.model.generate(
                context=context_str,
                tools=available_tools,
            )
            state.record_usage(response.usage)

            if response.report is not None:
                self.completion.record_non_empty_response()
                report, failure = self._parse_report(response.report, state, agent_def)
                if report is not None:
                    self._notify({"kind": "report", "turn": state.turn_count + 1, "report": report})
                    return report
                # Validation failure is an observation the model can recover from.
                self._record_report_failure(state, response.report, failure)
                self.tracer.turn(context_str, response, [], [], state.snapshot(), token_usage=response.usage)
                self._notify({"kind": "report_rejected", "turn": state.turn_count + 1, "failure": failure})
                state.turn_count += 1
                continue

            if not response.tool_calls:
                self.completion.record_empty_response()
                self.tracer.turn(context_str, response, [], [], state.snapshot(), token_usage=response.usage)
                self._notify({"kind": "empty", "turn": state.turn_count + 1})
                state.turn_count += 1
                continue

            self.completion.record_non_empty_response()

            calls: list[ToolCall] = []
            results: list[ToolResult] = []
            for tool_call in response.tool_calls:
                tool_result = await self.tools.execute(tool_call)
                state.record_tool_call(tool_call)
                state.record_tool_result(tool_result)
                calls.append(tool_call)
                results.append(tool_result)

            self.tracer.turn(context_str, response, calls, results, state.snapshot(), token_usage=response.usage)
            self._notify({"kind": "tool_calls", "turn": state.turn_count + 1, "calls": calls, "results": results, "usage": response.usage})
            state.turn_count += 1

        return FinalOutput(
            summary="The investigation stopped before the model submitted a report.",
            verdict="inconclusive",
            findings=state.findings,
            evidence=self._evidence(state),
            completion_reason=self._completion_reason(state, agent_def),
            metadata=self._metadata(state),
            observations=self._observations(state),
        )

    def _record_report_failure(self, state: State, report: str, failure: str) -> None:
        """Feed a malformed report back as an observation, not an exception."""
        call = ToolCall(
            tool_call_id=REPORT_TOOL_CALL_ID,
            name=REPORT_TOOL_CALL_ID,
            arguments={"report": report},
        )
        state.record_tool_call(call)
        state.record_tool_result(
            ToolResult(
                tool_call_id=REPORT_TOOL_CALL_ID,
                success=False,
                error=f"Report rejected: {failure}",
            )
        )

    def _parse_report(
        self,
        report: str,
        state: State,
        agent_def: AgentDefinition,
    ) -> tuple[FinalOutput | None, str]:
        """Validate a submitted report. Returns (output, failure_reason)."""
        try:
            payload = json.loads(report)
        except json.JSONDecodeError as error:
            return None, f"report must be valid JSON ({error})"
        if not isinstance(payload, dict):
            return None, "report must be a JSON object"

        missing_fields = {"summary", "verdict", "findings"} - payload.keys()
        if missing_fields:
            return None, f"report is missing required fields: {', '.join(sorted(missing_fields))}"

        metadata = payload.get("metadata", {})
        if not isinstance(metadata, dict):
            return None, "report metadata must be an object"

        findings, failure = _typed_findings(payload["findings"], state)
        if findings is None:
            return None, failure

        actions, failure = _recommended_actions(payload.get("recommended_actions"))
        if actions is None:
            return None, failure

        return (
            agent_def.output_contract(
                summary=payload["summary"],
                verdict=payload["verdict"],
                findings=findings,
                evidence=self._evidence(state),
                completion_reason="reported",
                metadata={**metadata, **self._metadata(state)},
                recommended_actions=actions,
                observations=self._observations(state),
            ),
            "",
        )

    @staticmethod
    def _evidence(state: State) -> list:
        """Identifiers only. The observation behind one is resolved on demand."""
        return [item.id for item in state.evidence]

    @staticmethod
    def _observations(state: State) -> list:
        return [
            observation["result"]
            for observation in state.observations
            if observation["result"] is not None
        ]

    @staticmethod
    def _metadata(state: State) -> dict:
        return {
            "run_id": state.run_id,
            "turns": state.turn_count,
            "tool_calls": state.tool_call_count,
            "prompt_tokens": state.total_prompt_tokens,
            "completion_tokens": state.total_completion_tokens,
            "total_tokens": state.total_tokens,
        }

    def _completion_reason(self, state: State, agent_def: AgentDefinition) -> str:
        if self.completion.consecutive_empty_responses >= 2:
            return "degraded"
        if state.tool_call_count >= agent_def.max_tool_calls:
            return "limit_calls"
        return "limit_turns"


# --- Report validation.
# A dataclass annotation is not a check: `findings: List[Finding]` held raw
# model dicts because nothing ever constructed a Finding. These turn the
# submitted JSON into typed values, or into a sentence the model can act on.


def _typed_findings(raw: object, state: State) -> tuple[Optional[List[Finding]], str]:
    if not isinstance(raw, list):
        return None, "findings must be an array"
    known = {getattr(item, "id", None) for item in state.evidence}
    known.discard(None)

    typed: List[Finding] = []
    for position, entry in enumerate(raw):
        finding, failure = _typed_finding(entry, known, f"findings[{position}]")
        if finding is None:
            return None, failure
        typed.append(finding)
    return typed, ""


def _typed_finding(
    entry: object, known: set, where: str
) -> tuple[Optional[Finding], str]:
    if not isinstance(entry, dict):
        return None, f"{where} must be an object"

    for name in ("title", "description"):
        value = entry.get(name)
        if not isinstance(value, str) or not value.strip():
            return None, f"{where}.{name} must be a non-empty string"

    severity, failure = _enum_member(Severity, entry.get("severity"), f"{where}.severity")
    if severity is None:
        return None, failure

    confidence, failure = _enum_member(Confidence, entry.get("confidence"), f"{where}.confidence")
    if confidence is None:
        return None, failure

    refs, failure = _evidence_refs(entry.get("evidence_refs"), known, where)
    if refs is None:
        return None, failure

    return (
        Finding(
            title=entry["title"],
            description=entry["description"],
            severity=severity,
            confidence=confidence,
            evidence_refs=refs,
            source_location=entry.get("source_location") or "",
        ),
        "",
    )


def _enum_member(enum_type, raw: object, where: str):
    options = ", ".join(member.value for member in enum_type)
    if not isinstance(raw, str):
        return None, f"{where} is required and must be one of: {options}"
    try:
        return enum_type(raw.strip().lower()), ""
    except ValueError:
        return None, f"{where} is {raw!r}, which is not one of: {options}"


def _evidence_refs(
    raw: object, known: set, where: str
) -> tuple[Optional[List[Evidence]], str]:
    field = f"{where}.evidence_refs"
    if raw is None:
        raw = []
    if not isinstance(raw, list) or not all(isinstance(ref, str) for ref in raw):
        return None, f"{field} must be an array of evidence identifiers"

    unknown = [ref for ref in raw if ref not in known]
    if unknown:
        return None, (
            f"{field} names evidence that was never observed: {', '.join(unknown)}. "
            f"Available: {', '.join(sorted(known)) or 'none'}"
        )
    if not raw and known:
        # A finding the orchestrator cannot trace back to an observation is
        # not one it can act on. Only excused when nothing was gathered, so a
        # clean run does not deadlock the model in endless rejection.
        return None, (
            f"{field} must name at least one of the evidence identifiers "
            f"gathered so far: {', '.join(sorted(known))}"
        )
    return [Evidence(evidence_id=ref) for ref in raw], ""


def _recommended_actions(raw: object) -> tuple[Optional[List[str]], str]:
    if raw is None:
        return [], ""
    if not isinstance(raw, list) or not all(isinstance(action, str) for action in raw):
        return None, "recommended_actions must be an array of strings"
    return raw, ""
