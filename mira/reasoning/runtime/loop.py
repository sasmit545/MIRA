"""Agent loop."""

import json
from typing import Callable, List, Optional

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
    ) -> FinalOutput:
        """Run the investigation until completion. Always writes a trace."""
        # The tracer names the trace file; taking the run id from it is what
        # makes a recorded evidence reference resolvable back to that file.
        state = State(objective=objective, run_id=self.tracer.run_id)
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

        return (
            agent_def.output_contract(
                summary=payload["summary"],
                verdict=payload["verdict"],
                findings=payload["findings"],
                evidence=self._evidence(state),
                completion_reason="reported",
                metadata={**metadata, **self._metadata(state)},
            ),
            "",
        )

    @staticmethod
    def _evidence(state: State) -> list:
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
