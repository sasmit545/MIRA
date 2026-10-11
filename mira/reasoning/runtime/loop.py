"""Agent loop."""

import copy
import dataclasses
import json
from typing import Callable, FrozenSet, List, Optional, Tuple

from ..contracts.finding import Confidence, Evidence, Finding, Severity
from ..contracts.model import ModelResponse
from ..contracts.objective import Objective
from ..contracts.output import FinalOutput
from ..contracts.state import State
from ..contracts.tool import ToolCall, ToolResult, ToolSpec
from ..definition.agent import AgentDefinition
from ..model.adapter import ModelAdapter
from .completion import MAX_MEMORY_REJECTIONS, MAX_REPORT_REJECTIONS, CompletionChecker
from .context import ContextBuilder
from .narrative import apply_narrative
from .payload import recall_fingerprint, select
from .tool_runtime import ToolRuntime
from .trace import Tracer, capability_calls, covered_range, live_observation
from .verdict import check

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
                self.completion.record_empty_response(silent=True)
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
            notes_owed = next(capability_calls(state), None) is not None
            calls: list[ToolCall] = []
            results: list[ToolResult] = []
            recalls = 0
            # Recalls that showed something new (KTD8). Only these owe notes:
            # a repeat or an already-shown answer gave the model nothing to note.
            fresh_recalls = 0
            recalled_handles: list = []
            for tool_call in response.tool_calls or []:
                if tool_call.name == RECALL_TOOL_NAME:
                    # Harness, not a capability (KTD7): off-budget.
                    recalls += 1
                    state.recalls_requested += 1
                    recalled_handles.append(tool_call.arguments.get("handle"))
                    if recalls > MAX_RECALLS_PER_TURN:
                        state.recalled.append(f"Recall not served: at most {MAX_RECALLS_PER_TURN} per turn.")
                        continue
                    answer, new = _recall(state, tool_call.arguments)
                    state.recalled.append(answer)
                    fresh_recalls += new
                    continue
                refusal = _prior_success(state, tool_call, self.tools.available_tools.get(tool_call.name))
                if refusal is not None:
                    state.reruns_refused += 1
                    # Capabilities are deterministic over one sample: rerunning a
                    # covered call buys the same result and a duplicate evidence id.
                    state.record_harness_observation(
                        tool_call,
                        ToolResult(tool_call_id=tool_call.tool_call_id, success=False, error=refusal),
                    )
                    continue
                tool_result = await self.tools.execute(tool_call)
                state.record_tool_call(tool_call)
                state.record_tool_result(tool_result)
                calls.append(tool_call)
                results.append(tool_result)

            # After the calls, so a rejected narrative cannot unwind a result or
            # the evidence minted from it. A report-only turn owes no narrative.
            memory_failure = ""
            memory_before = copy.deepcopy(state.working_memory)
            update = response.memory_update
            owes = (calls and notes_owed) or (notes_pending and (calls or fresh_recalls))
            # Reading before writing: a turn that recalls may write its notes
            # next turn instead, but not two turns running.
            defer = update is None and owes and fresh_recalls and not notes_pending
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
            elif fresh_recalls:
                # A recall is shown once. What it showed must reach the notes on
                # the next turn that acts, or the model forgets it and re-reads
                # forever (a live run spent seven turns doing exactly that).
                notes_pending = True

            # Judged last (KTD8): progress is a call that ran, a recall that
            # showed something new, a report, or notes that changed the memory.
            # A turn of refused reruns, repeated recalls and unchanged notes did
            # nothing, and counts as empty so it cannot loop to max_turns.
            if calls or fresh_recalls or response.report is not None or state.working_memory != memory_before:
                self.completion.record_non_empty_response()
            else:
                self.completion.record_empty_response()

            report, failure, validation = None, "", None
            if response.report is not None:
                report, failure, validation = self._parse_report(response.report, state, agent_def)
                if report is None:
                    # Validation failure is an observation the model can recover from.
                    self._record_report_failure(state, response.report, failure)

            # Every submitted report reaches the trace with the validator's outcome (R13).
            self.tracer.turn(
                context_str, response, calls, results, state.snapshot(), token_usage=response.usage,
                validation=_validation(response.report, validation, failure),
            )
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
        # silent: asking it once more would only spend another call. A model
        # that loops on repeats is still talking, and the run it paid for
        # should end in a report, not in the stock message below.
        reason = self._completion_reason(state, agent_def)
        if self.completion.consecutive_silent_responses < 2:
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
            "limit_reports": f"{MAX_REPORT_REJECTIONS} reports were rejected",
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
        report, failure, validation = None, "no report was submitted on the final turn", None
        if response.report is not None:
            # No turn follows, so a verdict the gate refuses becomes inconclusive.
            report, failure, validation = self._parse_report(response.report, state, agent_def, final=True)
            if report is None:
                # No turn follows to fix it in, so keep what is supported rather
                # than lose the whole report to one uncited finding.
                report, salvaged = self._supported_part(response.report, state, agent_def)
                validation = salvaged or validation
        self.tracer.turn(
            context_str, response, [], [], state.snapshot(), token_usage=response.usage,
            validation=_validation(response.report, validation, failure),
        )
        state.turn_count += 1
        if report is None:
            self._notify({"kind": "report_rejected", "turn": state.turn_count, "failure": failure})
            return None
        report = dataclasses.replace(
            report, completion_reason=reason, metadata={**report.metadata, **self._metadata(state)}
        )
        self._notify({"kind": "report", "turn": state.turn_count, "report": report})
        return report

    def _supported_part(self, raw: str, state: State, agent_def: AgentDefinition) -> tuple[Optional[FinalOutput], Optional[dict]]:
        """The report with every finding that fails validation removed.

        Each kept finding passes the same check a normal report does, so an
        unsupported finding never reaches the output. With none left, the
        verdict cannot stand on anything and becomes inconclusive. None when
        the report is broken for a reason other than its findings. Returned
        with the gate's record of the salvaged report.
        """
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            return None, None
        if not isinstance(payload, dict) or not isinstance(payload.get("findings"), list):
            return None, None
        kept = [entry for entry in payload["findings"] if _typed_findings([entry], state)[0] is not None]
        dropped = len(payload["findings"]) - len(kept)
        if not dropped:
            return None, None
        state.findings_discarded += dropped
        salvaged = {
            **payload,
            "findings": kept,
            "summary": f"{payload.get('summary', '')} [{dropped} finding(s) without valid evidence references were discarded.]",
        }
        if not kept:
            salvaged["verdict"] = "inconclusive"
        report, _, validation = self._parse_report(json.dumps(salvaged), state, agent_def, final=True)
        return report, validation

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
            failure, warnings = apply_narrative(
                state.working_memory, update, {item.id for item in state.evidence}
            )
            if warnings and not failure:
                # Merged, so not a rejection; stated in the history so the
                # model does not believe a dropped citation stands.
                state.record_harness_observation(
                    ToolCall(tool_call_id=MEMORY_TOOL_CALL_ID, name=MEMORY_TOOL_CALL_ID, arguments={}),
                    ToolResult(
                        tool_call_id=MEMORY_TOOL_CALL_ID,
                        success=False,
                        error=f"Notes merged, except: {'; '.join(warnings)}. Cite only identifiers listed in the context.",
                    ),
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
        self.completion.record_report_rejection()
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
        final: bool = False,
    ) -> tuple[FinalOutput | None, str, Optional[dict]]:
        """Validate a submitted report: its schema, then the verdict gate.

        Returns (output, failure_reason, the gate's record). On the final
        report turn a gate failure downgrades the verdict instead (KTD6).
        """
        try:
            payload = json.loads(report)
        except json.JSONDecodeError as error:
            return None, f"report must be valid JSON ({error})", None
        if not isinstance(payload, dict):
            return None, "report must be a JSON object", None

        missing_fields = {"summary", "verdict", "findings"} - payload.keys()
        if missing_fields:
            return None, f"report is missing required fields: {', '.join(sorted(missing_fields))}", None

        metadata = payload.get("metadata", {})
        if not isinstance(metadata, dict):
            return None, "report metadata must be an object", None

        findings, failure = _typed_findings(payload["findings"], state)
        if findings is None:
            return None, failure, None

        actions, failure = _recommended_actions(payload.get("recommended_actions"))
        if actions is None:
            return None, failure, None

        gate = check(payload["verdict"], findings, state.evidence, state.working_memory, final=final)
        if gate.failure:
            return None, gate.failure, gate.record
        summary, audit = payload["summary"], {"severities_capped": len(gate.record["repairs"])}
        if gate.record["outcome"] == "downgraded":
            reasons = gate.record["reasons"]
            summary = f"{summary} [Verdict gate: {payload['verdict']!r} became inconclusive: {'; '.join(reasons)}.]"
            audit["verdict_gate"] = {"submitted_verdict": payload["verdict"], "reasons": reasons}

        return (
            agent_def.output_contract(
                summary=summary,
                verdict=gate.verdict,
                findings=gate.findings,
                evidence=self._evidence(state),
                completion_reason="reported",
                metadata={**metadata, **self._metadata(state), **audit},
                recommended_actions=actions,
                observations=self._observations(state),
                memory=state.working_memory,
            ),
            "",
            gate.record,
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

    def _metadata(self, state: State) -> dict:
        return {
            "report_rejections": self.completion.report_rejections,
            "run_id": state.run_id,
            "turns": state.turn_count,
            "tool_calls": state.tool_call_count,
            "prompt_tokens": state.total_prompt_tokens,
            "completion_tokens": state.total_completion_tokens,
            "total_tokens": state.total_tokens,
            "model_calls": state.model_calls,
            "recalls_requested": state.recalls_requested,
            "repeat_recalls": state.repeat_recalls,
            "reruns_refused": state.reruns_refused,
            "findings_discarded": state.findings_discarded,
        }

    def _completion_reason(self, state: State, agent_def: AgentDefinition) -> str:
        if self.completion.consecutive_empty_responses >= 2:
            return "degraded"
        if self.completion.memory_rejections >= MAX_MEMORY_REJECTIONS:
            return "degraded"
        if self.completion.report_rejections >= MAX_REPORT_REJECTIONS:
            return "limit_reports"
        if state.tool_call_count >= agent_def.max_tool_calls:
            return "limit_calls"
        return "limit_turns"


def _validation(raw: Optional[str], record: Optional[dict], failure: str) -> Optional[dict]:
    """The trace's record of a submitted report: the gate's, or a schema
    rejection's. None when the turn submitted no report."""
    if raw is None:
        return None
    return record or {"outcome": "rejected", "reasons": [failure]}


def _prior_success(state: State, call: ToolCall, spec: Optional[ToolSpec]) -> Optional[str]:
    """Why an earlier successful call makes this one pointless, or None (KTD9).

    Arguments are compared after filling the spec's defaults, so `f()` and
    `f(offset=0)` are one call. A call whose offset falls inside the range an
    earlier collected call fetched, all else equal, is answered by recall.
    Failures are not matched: they may be transient and worth a retry.
    """
    properties = (spec.parameters.get("properties") if spec else None) or {}
    defaults = {name: schema["default"] for name, schema in properties.items() if isinstance(schema, dict) and "default" in schema}
    asked = {**defaults, **call.arguments}
    for handle, earlier_call, result in capability_calls(state):
        if not result.success or earlier_call.name != call.name:
            continue
        earlier = {**defaults, **earlier_call.arguments}
        if earlier == asked:
            return f"Not rerun: identical to {handle}; use that result, or recall_observation for more of it."
        covered = covered_range(result)
        if covered is None or not isinstance(asked.get("offset"), int):
            continue
        start, end = covered
        same_otherwise = {k: v for k, v in earlier.items() if k != "offset"} == {k: v for k, v in asked.items() if k != "offset"}
        if same_otherwise and start <= asked["offset"] < end:
            return (
                f"Not rerun: {handle} already holds items {start}..{end - 1} of this list; read them with "
                f"recall_observation(handle={handle!r}, offset={asked['offset'] - start})."
            )
    return None


def _recall(state: State, arguments: dict) -> Tuple[str, bool]:
    """Answer one recall_observation as prompt text, and whether it showed
    anything new (KTD8). A repeat gets a pointer, not the answer again (R11)."""
    asked = ", ".join(f"{name}={value!r}" for name, value in arguments.items())
    fingerprint = recall_fingerprint(arguments)
    if fingerprint in state.recall_fingerprints:
        state.repeat_recalls += 1
        return (
            f"recall_observation({asked}): already answered on turn {state.recall_fingerprints[fingerprint]}; "
            "not repeated. What it showed belongs in your notes; ask for something else, "
            "or submit your report if you have enough."
        ), False
    handle = arguments.get("handle")
    if not isinstance(handle, str) or not handle:
        return f"recall_observation({asked}) failed: handle is required, copied from the capability history.", False
    observation = live_observation(state, handle)
    if observation is None:
        return (
            f"recall_observation({asked}) failed: no capability call in this run has "
            f"handle {handle!r}; use one listed in the capability history."
        ), False
    result = observation["result"]
    if not result.success:
        return f"recall_observation({asked}): that call failed, and its error is all it produced: {result.error}", False
    selection = select(result.output, arguments)
    if selection.failure:
        return f"recall_observation({asked}) failed: {selection.failure}", False
    # Only an answer is remembered: a failure may stop applying, so its retry runs.
    state.recall_fingerprints[fingerprint] = state.turn_count + 1
    # The ledger (KTD7) records what was shown, apart from evidence: showing
    # an item makes it citable no more than before.
    view = None if selection.fields is None else frozenset(selection.fields)
    seen = state.shown_items.get(handle, {}).get(selection.path, {})
    # An aggregate or a value is new by its new question; a listing by items,
    # or keys of items, not shown before.
    new = not selection.shown or not all(_covers(seen.get(index, frozenset()), view) for index in selection.shown)
    if selection.shown:
        ledger = state.shown_items.setdefault(handle, {}).setdefault(selection.path, {})
        for index in selection.shown:
            had = ledger.get(index, frozenset())
            ledger[index] = None if had is None or view is None else had | view
    return f"recall_observation({asked}):\n{selection.text}", new


def _covers(had: Optional[FrozenSet[str]], view: Optional[FrozenSet[str]]) -> bool:
    """Whether the keys already shown of an item (None: all) include those asked."""
    return had is None or (view is not None and view <= had)


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
