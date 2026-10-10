"""Model-facing context assembly.

This is the only place model-facing text is assembled.
"""

from typing import Any

from ..contracts.state import State
from ..definition.instructions import assemble_instructions
from .payload import MAX_OBSERVATION_CHARS, truncate  # noqa: F401 - re-exported
from .trace import capability_history


class ContextBuilder:
    """Builds the model-facing context from state and agent definition."""

    @staticmethod
    def build(state: State, agent_definition: Any) -> str:
        return assemble_instructions(
            role=agent_definition.role,
            objective=state.objective.description,
            scope=agent_definition.scope,
            available_tools=list(agent_definition.allowed_tools),
            current_state=render_state(state),
        )


def render_state(state: State) -> str:
    """Render counters, capability history, and findings for the prompt.

    A successful call is shown as its digest, never its raw payload: the full
    result stays in the observation log, reachable through its handle.
    """
    lines = [
        f"Turn: {state.turn_count}",
        f"Tool calls so far: {state.tool_call_count}",
        "",
        "Capability history (handle, call, outcome):",
    ]
    if not state.observations:
        lines.append("  (no tools have been called yet)")
    history = iter(capability_history(state))
    for observation in state.observations:
        call = observation["call"]
        arguments = ", ".join(f"{name}={value!r}" for name, value in call.arguments.items())
        if observation.get("harness"):
            # Harness notes (a rejected report or notes, a skipped repeat) carry
            # no handle: nothing ran, so there is nothing to recall.
            result = observation["result"]
            lines.append(f"  - {call.name}({arguments})")
            lines.append(f"      -> ERROR: {result.error}")
            continue
        record = next(history, None)
        if record is None:  # a call whose result has not arrived yet
            continue
        lines.append(f"  [{record.handle}] {record.name}({arguments})")
        if not record.success:
            lines.append(f"      -> ERROR: {record.error}")
            continue
        if record.evidence:
            lines.append(f"      -> evidence: {', '.join(record.evidence)}")
        for line in record.digest.splitlines():
            lines.append(f"      | {line}")

    if state.recalled:
        lines.append("")
        lines.append("Recalled this turn (shown once; keep what matters in record_memory):")
        for answer in state.recalled:
            lines.extend(f"  {line}" for line in answer.splitlines())

    if state.evidence:
        # The model is required to cite these identifiers in its findings, so
        # it has to be shown them.
        lines.append("")
        lines.append("Evidence gathered so far (cite these identifiers in your findings):")
        for evidence in state.evidence:
            lines.append(
                f"  {evidence.id} [{evidence.capability}] {evidence.observation}"
            )

    if state.findings:
        lines.append("")
        lines.append("Findings so far:")
        for finding in state.findings:
            lines.append(f"  - {finding.title}: {finding.description}")
    return "\n".join(lines)
