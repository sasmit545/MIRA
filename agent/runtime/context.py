"""Model-facing context assembly."""

from typing import Any

from ..contracts.state import State


class ContextBuilder:
    """Builds the model-facing context from state and agent definition."""

    @staticmethod
    def build(state: State, agent_definition: Any) -> str:
        """Generate the context string for the model.

        Placeholder. The full assembly (SYSTEM, OBJECTIVE, CURRENT STATE,
        INVESTIGATION HISTORY with truncated observations, FINDINGS/EVIDENCE,
        AVAILABLE TOOLS) is not implemented yet.
        """
        return f"Objective: {state.objective.description}\nTurn: {state.turn_count}"
