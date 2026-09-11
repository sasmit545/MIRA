"""Model-facing context assembly.

This is the only place model-facing text is assembled.
"""

from typing import Any

from ..contracts.state import State
from ..contracts.tool import ToolResult
from ..definition.instructions import assemble_instructions

MAX_OBSERVATION_CHARS = 2000

SCOPE = (
    "Static analysis only. The artifact under investigation is bound by the runtime, "
    "so tool arguments never need to name it."
)


class ContextBuilder:
    """Builds the model-facing context from state and agent definition."""

    @staticmethod
    def build(state: State, agent_definition: Any) -> str:
        return assemble_instructions(
            objective=state.objective.description,
            scope=SCOPE,
            available_tools=list(agent_definition.allowed_tools),
            current_state=render_state(state),
        )


def render_state(state: State) -> str:
    """Render counters, investigation history, and findings for the prompt."""
    lines = [
        f"Turn: {state.turn_count}",
        f"Tool calls so far: {state.tool_call_count}",
        "",
        "Investigation history:",
    ]
    if not state.observations:
        lines.append("  (no tools have been called yet)")
    for index, observation in enumerate(state.observations):
        call = observation["call"]
        arguments = ", ".join(f"{name}={value!r}" for name, value in call.arguments.items())
        lines.append(f"  [{index}] {call.name}({arguments})")
        lines.append(f"      -> {_render_result(observation['result'])}")

    if state.findings:
        lines.append("")
        lines.append("Findings so far:")
        for finding in state.findings:
            lines.append(f"  - {finding.title}: {finding.description}")
    return "\n".join(lines)


def _render_result(result: ToolResult | None) -> str:
    if result is None:
        return "(pending)"
    if not result.success:
        return f"ERROR: {result.error}"
    return truncate(repr(result.output))


def truncate(text: str, limit: int = MAX_OBSERVATION_CHARS) -> str:
    """Cap a rendered payload so one tool result cannot fill the context window."""
    if len(text) <= limit:
        return text
    return f"{text[:limit]}... [truncated, {len(text) - limit} more characters]"
