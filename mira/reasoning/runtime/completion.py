"""Completion semantics for the agent loop."""

from ..contracts.state import State
from ..definition.agent import AgentDefinition


# Counts every rejected narrative in the run, not only consecutive ones: a
# model that alternates rejected and accepted would never trip a consecutive
# bound. Three leaves room for a slip or two while capping the wasted turns.
MAX_MEMORY_REJECTIONS = 3


class CompletionChecker:
    """Determines when the investigation should terminate."""

    def __init__(self):
        self.consecutive_empty_responses = 0
        self.memory_rejections = 0

    def is_active(self, state: State, agent_def: AgentDefinition) -> bool:
        """Return True if the loop should continue, False if it should terminate."""
        # Condition 2: max_turns reached
        if state.turn_count >= agent_def.max_turns:
            return False

        # Condition 3: max_tool_calls reached
        if state.tool_call_count >= agent_def.max_tool_calls:
            return False

        # Condition 4: Model returns empty/degraded response twice
        # We track this in the CompletionChecker state (consecutive_empty_responses)
        if self.consecutive_empty_responses >= 2:
            return False

        if self.memory_rejections >= MAX_MEMORY_REJECTIONS:
            return False

        # Condition 1: Model submits a report via the report tool
        # This is not checked here; the loop checks for a report in the model's response.
        # If the model submits a report, the loop will return a FinalOutput and exit.
        # So we don't need to check for report submission in the completion checker.
        # The loop will break out when it sees a report.

        # If none of the termination conditions are met, continue.
        return True

    def record_empty_response(self) -> None:
        """Call this when the model returns an empty response."""
        self.consecutive_empty_responses += 1

    def record_memory_rejection(self) -> None:
        """Call this when a narrative is rejected."""
        self.memory_rejections += 1

    def record_non_empty_response(self) -> None:
        """Call this when the model returns a non-empty response (tool calls or report)."""
        self.consecutive_empty_responses = 0
