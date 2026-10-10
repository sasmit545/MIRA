"""Agent loop."""

import copy
import dataclasses
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
from .completion import MAX_MEMORY_REJECTIONS, CompletionChecker
from .context import ContextBuilder
from .narrative import apply_narrative
from .payload import select
from .tool_runtime import ToolRuntime
from .trace import Tracer, capability_history, live_observation

REPORT_TOOL_CALL_ID = "submit_report"
MEMORY_TOOL_CALL_ID = "record_memory"
RECALL_TOOL_NAME = "recall_observation"
MAX_RECALLS_PER_TURN = 3
FORCED_NOTES_PROMPT = (
    "Your last response called a capability or followed a recall without record_memory. "
    "Call record_memory now with what the results above show you (empty lists if nothing changed)."
)


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
        notes_pending = False
        while self.completion.is_active(state, agent_def):
            context_str = self.context.build(state, agent_def)
            # Shown in exactly this one prompt; this turn's recalls replace them.
            state.recalled = []
            available_tools: List[ToolSpec] = agent_def.allowed_tools

            response: ModelResponse = self.model.generate(
                context=context_str,
                tools=available_tools,
            )
            state.record_usage(response.usage)

            if response.report is None and not response.tool_calls and response.memory_update is None:
                self.completion.record_empty_response()
                self.tracer.turn(context_str, response, [], [], state.snapshot(), token_usage=response.usage)
                self._notify({"kind": "empty", "turn": state.turn_count + 1})
                state.turn_count += 1
                continue

            # Capabilities run before a sibling report is judged: the report may
            # cite evidence these calls just minted, and dropping them would
            # discard work already requested.
            # Notes reflect results through the previous turn (R7). Before any
            # capability has returned there is nothing to note, so the very
            # first capability turn owes none; notes it does send still merge.
            notes_owed = bool(capability_history(state))
            calls: list[ToolCall] = []
            results: list[ToolResult] = []
            recalls = 0
            recalled_handles: list = []
            for tool_call in response.tool_calls or []:
                if tool_call.name == RECALL_TOOL_NAME:
                    # Harness, not a capability (KTD7): off-budget, owes no notes.
                    recalls += 1
                    recalled_handles.append(tool_call.arguments.get("handle"))
                    state.recalled.append(
                        _recall(state, tool_call.arguments)
                        if recalls <= MAX_RECALLS_PER_TURN
                        else f"Recall not served: at most {MAX_RECALLS_PER_TURN} per turn."
                    )
                    continue
                prior = _prior_success(state, tool_call)
                if prior is not None:
                    # Capabilities are deterministic over one sample: rerunning an
                    # identical call buys the same result and a duplicate evidence id.
                    state.record_harness_observation(
                        tool_call,
                        ToolResult(
                            tool_call_id=tool_call.tool_call_id,
                            success=False,
                            error=f"Not rerun: identical to {prior}; use that result, or recall_observation for more of it.",
                        ),
                    )
                    continue
                tool_result = await self.tools.execute(tool_call)
                state.record_tool_call(tool_call)
                state.record_tool_result(tool_result)
                calls.append(tool_call)
                results.append(tool_result)

            # Judged after the calls: a turn whose every call was a refused rerun
            # did nothing, and counts as empty so a model that ignores the
            # refusal cannot loop to max_turns. Notes or a recall are progress.
            if calls or recalls or response.memory_update is not None or response.report is not None:
                self.completion.record_non_empty_response()
            else:
                self.completion.record_empty_response()

            # After the calls, so a rejected narrative cannot unwind a result or
            # the evidence minted from it. A report-only turn owes no narrative.
            memory_failure = ""
            update = response.memory_update
            owes = (calls and notes_owed) or (notes_pending and (calls or recalls))
            # Reading before writing: a turn that recalls may write its notes
            # next turn instead, but not two turns running.
            defer = update is None and owes and recalls and not notes_pending
            if update is None and owes and not defer:
                # Asking was not enough: a live model skipped record_memory on
                # nearly every turn. One extra call that must record the notes;
                # a model that still does not is rejected as before.
                update = self._forced_notes(state, agent_def)
            if update is not None:
                notes_pending = False
                memory_failure = self._merge_narrative(state, update)
            elif defer:
                notes_pending = True
            elif owes:
                memory_failure = self._merge_narrative(state, None)
            elif recalls:
                # A recall is shown once. What it showed must reach the notes on
                # the next turn that acts, or the model forgets it and re-reads
                # forever (a live run spent seven turns doing exactly that).
                notes_pending = True

            report, failure = None, ""
            if response.report is not None:
                report, failure = self._parse_report(response.report, state, agent_def)
                if report is None:
                    # Validation failure is an observation the model can recover from.
                    self._record_report_failure(state, response.report, failure)

            if calls or report is None:
                self.tracer.turn(context_str, response, calls, results, state.snapshot(), token_usage=response.usage)
            if calls:
                self._notify({"kind": "tool_calls", "turn": state.turn_count + 1, "calls": calls, "results": results, "usage": response.usage})
            if recalled_handles:
                self._notify({"kind": "recall", "turn": state.turn_count + 1, "handles": recalled_handles})
            if memory_failure:
                self._notify({"kind": "memory_rejected", "turn": state.turn_count + 1, "failure": memory_failure})
            elif update is not None:
                # A copy: an observer may keep it after later turns revise the notes.
                self._notify({"kind": "notes", "turn": state.turn_count + 1, "memory": copy.deepcopy(state.working_memory)})
            if report is not None:
                self._notify({"kind": "report", "turn": state.turn_count + 1, "report": report})
                return report
            if response.report is not None:
                self._notify({"kind": "report_rejected", "turn": state.turn_count + 1, "failure": failure})
            state.turn_count += 1

        # Any limit gets one report-only turn, except a model that has gone
        # silent: asking it once more would only spend another call.
        reason = self._completion_reason(state, agent_def)
        if self.completion.consecutive_empty_responses < 2:
            salvaged = await self._final_report_turn(state, agent_def, reason)
            if salvaged is not None:
                return salvaged

        return FinalOutput(
            summary="The investigation stopped before the model submitted a report.",
            verdict="inconclusive",
            findings=state.findings,
            evidence=self._evidence(state),
            completion_reason=reason,
            metadata=self._metadata(state),
            observations=self._observations(state),
            memory=state.working_memory,
        )

    async def _final_report_turn(self, state: State, agent_def: AgentDefinition, reason: str) -> Optional[FinalOutput]:
        """One last turn after a limit ends the run, accepting only a report.

        The result keeps the limit as its completion reason, so the specialist
        promotes nothing, but the investigation it paid for is not discarded.
        """
        why = {
            "degraded": f"notes were rejected {MAX_MEMORY_REJECTIONS} times",
            "limit_calls": "the capability-call limit was reached",
        }.get(reason, "the turn limit was reached")
        state.record_harness_observation(
            ToolCall(tool_call_id=REPORT_TOOL_CALL_ID, name=REPORT_TOOL_CALL_ID, arguments={}),
            ToolResult(
                tool_call_id=REPORT_TOOL_CALL_ID,
                success=False,
                error=f"Run ending: {why}. Call submit_report now with what you have; no capability will run.",
            ),
        )
        context_str = self.context.build(state, agent_def)
        state.recalled = []
        response: ModelResponse = self.model.generate(context=context_str, tools=[], force=REPORT_TOOL_CALL_ID)
        state.record_usage(response.usage)
        report, failure = None, "no report was submitted on the final turn"
        if response.report is not None:
            report, failure = self._parse_report(response.report, state, agent_def)
            if report is None:
                # No turn follows to fix it in, so keep what is supported rather
                # than lose the whole report to one uncited finding.
                report = self._supported_part(response.report, state, agent_def)
        self.tracer.turn(context_str, response, [], [], state.snapshot(), token_usage=response.usage)
        state.turn_count += 1
        if report is None:
            self._notify({"kind": "report_rejected", "turn": state.turn_count, "failure": failure})
            return None
        report = dataclasses.replace(
            report, completion_reason=reason, metadata={**report.metadata, **self._metadata(state)}
        )
        self._notify({"kind": "report", "turn": state.turn_count, "report": report})
        return report

    def _supported_part(self, raw: str, state: State, agent_def: AgentDefinition) -> Optional[FinalOutput]:
        """The report with every finding that fails validation removed.

        Each kept finding passes the same check a normal report does, so an
        unsupported finding never reaches the output. With none left, the
        verdict cannot stand on anything and becomes inconclusive. None when
        the report is broken for a reason other than its findings.
        """
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            return None
        if not isinstance(payload, dict) or not isinstance(payload.get("findings"), list):
            return None
        kept = [entry for entry in payload["findings"] if _typed_findings([entry], state)[0] is not None]
        dropped = len(payload["findings"]) - len(kept)
        if not dropped:
            return None
        salvaged = {
            **payload,
            "findings": kept,
            "summary": f"{payload.get('summary', '')} [{dropped} finding(s) without valid evidence references were discarded.]",
        }
        if not kept:
            salvaged["verdict"] = "inconclusive"
        report, _ = self._parse_report(json.dumps(salvaged), state, agent_def)
        return report

    def _forced_notes(self, state: State, agent_def: AgentDefinition) -> Optional[dict]:
        """Ask once more, offering only record_memory and requiring it. The
        prompt already shows this turn's results, so the notes can cover them."""
        context_str = self.context.build(state, agent_def) + "\n\n" + FORCED_NOTES_PROMPT
        response: ModelResponse = self.model.generate(context=context_str, tools=[], force=MEMORY_TOOL_CALL_ID)
        state.record_usage(response.usage)
        self.tracer.turn(context_str, response, [], [], state.snapshot(), token_usage=response.usage)
        return response.memory_update

    def _merge_narrative(self, state: State, update: Optional[dict]) -> str:
        """Merge the turn's narrative; on rejection tell the model why."""
        if update is None:
            # Says what to send, not only what was missing: a model that drops
            # the notes under a long prompt needs the fix spelled out.
            failure = (
                "record_memory is required on every turn that calls a capability, "
                "and on the turn after a recall. Send a record_memory call in this response; "
                "empty lists are accepted when nothing changed."
            )
        else:
            failure = apply_narrative(
                state.working_memory, update, {item.id for item in state.evidence}
            )
        if failure:
            self.completion.record_memory_rejection()
            state.record_harness_observation(
                ToolCall(
                    tool_call_id=MEMORY_TOOL_CALL_ID,
                    name=MEMORY_TOOL_CALL_ID,
                    arguments=update if isinstance(update, dict) else {},
                ),
                ToolResult(
                    tool_call_id=MEMORY_TOOL_CALL_ID,
                    success=False,
                    error=f"Notes rejected: {failure}",
                ),
            )
        return failure

    def _record_report_failure(self, state: State, report: str, failure: str) -> None:
        """Feed a malformed report back as an observation, not an exception."""
        call = ToolCall(
            tool_call_id=REPORT_TOOL_CALL_ID,
            name=REPORT_TOOL_CALL_ID,
            arguments={"report": report},
        )
        # A rejected report has always spent capability budget; it is still a
        # harness entry, so it takes no occurrence in the capability history.
        state.tool_call_count += 1
        state.record_harness_observation(
            call,
            ToolResult(
                tool_call_id=REPORT_TOOL_CALL_ID,
                success=False,
                error=f"Report rejected: {failure}",
            ),
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
                memory=state.working_memory,
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
        if self.completion.memory_rejections >= MAX_MEMORY_REJECTIONS:
            return "degraded"
        if state.tool_call_count >= agent_def.max_tool_calls:
            return "limit_calls"
        return "limit_turns"


def _prior_success(state: State, call: ToolCall) -> Optional[str]:
    """Handle of an earlier successful call with the same name and arguments.
    Failures are not matched: they may be transient and worth a retry."""
    for record in capability_history(state):
        if record.success and record.name == call.name and record.arguments == call.arguments:
            return record.handle
    return None


def _recall(state: State, arguments: dict) -> str:
    """Answer one recall_observation, success or failure, as prompt text."""
    asked = ", ".join(f"{name}={value!r}" for name, value in arguments.items())
    handle = arguments.get("handle")
    if not isinstance(handle, str) or not handle:
        return f"recall_observation({asked}) failed: handle is required, copied from the capability history."
    observation = live_observation(state, handle)
    if observation is None:
        return (
            f"recall_observation({asked}) failed: no capability call in this run has "
            f"handle {handle!r}; use one listed in the capability history."
        )
    result = observation["result"]
    if not result.success:
        return f"recall_observation({asked}): that call failed, and its error is all it produced: {result.error}"
    text, failure = select(result.output, arguments)
    if failure:
        return f"recall_observation({asked}) failed: {failure}"
    return f"recall_observation({asked}):\n{text}"


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
