"""Agent loop."""

import json

from typing import List
from ..contracts.objective import Objective
from ..contracts.tool import ToolSpec, ToolCall, ToolResult
from ..contracts.model import ModelResponse
from ..contracts.output import FinalOutput
from ..contracts.state import State
from ..definition.agent import StaticAgentDefinition
from .context import ContextBuilder
from ..model.adapter import ModelAdapter
from .tool_runtime import ToolRuntime
from .completion import CompletionChecker
from .trace import Tracer


class AgentLoop:
    """The agent loop that drives the investigation."""

    def __init__(
        self,
        model_adapter: ModelAdapter,
        tool_runtime: ToolRuntime,
        completion_checker: CompletionChecker,
        context_builder: ContextBuilder,
        tracer: Tracer,
    ):
        self.model = model_adapter
        self.tools = tool_runtime
        self.completion = completion_checker
        self.context = context_builder
        self.tracer = tracer

    def run(
        self,
        objective: Objective,
        agent_def: StaticAgentDefinition,
    ) -> FinalOutput:
        """Run the investigation until completion."""
        state = State(objective=objective)

        while self.completion.is_active(state, agent_def):
            # Build context for the model
            context_str = self.context.build(state, agent_def)
            # Get available tools (as ToolSpecs)
            available_tools: List[ToolSpec] = agent_def.allowed_tools

            # Ask the model what to do
            response: ModelResponse = self.model.generate(
                context=context_str,
                tools=available_tools,
            )

            # Handle the response
            if response.report is not None:
                self.completion.record_non_empty_response()
                return self._parse_report(response.report, state, agent_def)

            if response.tool_calls is None or len(response.tool_calls) == 0:
                self.completion.record_empty_response()
                self.tracer.turn(context_str, response, [], [], state.snapshot())
                state.turn_count += 1
                continue

            self.completion.record_non_empty_response()

            # Process tool calls
            for tool_call in response.tool_calls:
                # Execute the tool
                tool_result: ToolResult = self.tools.execute(tool_call)
                # Record the tool call and result in the state
                state.record_tool_call(tool_call)
                state.record_tool_result(tool_result)
                # Trace the turn
                self.tracer.turn(context_str, response, [tool_call], [tool_result], state.snapshot())

            # Increment turn count
            state.turn_count += 1

        completion_reason = self._completion_reason(state, agent_def)
        return FinalOutput(
            summary="The investigation stopped before the model submitted a report.",
            verdict="inconclusive",
            findings=state.findings,
            evidence=[
                observation["result"]
                for observation in state.observations
                if observation["result"] is not None
            ],
            completion_reason=completion_reason,
            metadata={
                "run_id": state.run_id,
                "turns": state.turn_count,
                "tool_calls": state.tool_call_count,
            },
        )

    @staticmethod
    def _parse_report(report: str, state, agent_def: StaticAgentDefinition) -> FinalOutput:
        try:
            payload = json.loads(report)
        except json.JSONDecodeError as error:
            raise ValueError("Model report must be valid JSON") from error
        if not isinstance(payload, dict):
            raise ValueError("Model report must be a JSON object")

        required_fields = {"summary", "verdict", "findings"}
        missing_fields = required_fields - payload.keys()
        if missing_fields:
            raise ValueError(f"Model report is missing required fields: {', '.join(sorted(missing_fields))}")

        metadata = payload.get("metadata", {})
        if not isinstance(metadata, dict):
            raise ValueError("Model report metadata must be an object")
        return agent_def.output_contract(
            summary=payload["summary"],
            verdict=payload["verdict"],
            findings=payload["findings"],
            evidence=[
                observation["result"]
                for observation in state.observations
                if observation["result"] is not None
            ],
            completion_reason="reported",
            metadata={
                **metadata,
                "run_id": state.run_id,
                "turns": state.turn_count,
                "tool_calls": state.tool_call_count,
            },
        )

    def _completion_reason(self, state, agent_def: StaticAgentDefinition) -> str:
        if self.completion.consecutive_empty_responses >= 2:
            return "degraded"
        if state.tool_call_count >= agent_def.max_tool_calls:
            return "limit_calls"
        return "limit_turns"
