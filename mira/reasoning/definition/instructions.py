"""Instructions / prompt assembly."""

from typing import List
from ..contracts.tool import ToolSpec


def assemble_instructions(
    role: str,
    objective: str,
    scope: str,
    available_tools: List[ToolSpec],
    current_state: str,
) -> str:
    """Assemble the model-facing prompt from sections."""
    sections = [
        f"Role: {role}",
        "",
        f"Investigation objective: {objective}",
        "",
        f"Scope: {scope}",
        "",
        "Available capabilities:",
        *[
            f"- {tool.name}: {tool.description}"
            for tool in available_tools
        ],
        "",
        "How to evaluate evidence:",
        "Promote observations to evidence when they directly support or refute the objective.",
        "",
        "How to decide next action:",
        "Choose the tool that will most likely yield new, relevant evidence.",
        "",
        "Reading past a digest:",
        "The capability history shows each result as a partial digest: array lengths, the first and last items, and the evidence read from it.",
        "When a digest marked partial may hide what you need, call recall_observation with the call's handle, and a path plus a range (start, count) or a search (contains).",
        "Evidence such as 'and N more' also means the rest is only reachable by recall. Do not rerun a capability to see more of its result.",
        "",
        "Error handling:",
        "Tool failures are observations, not dead ends. Adapt and try another approach.",
        "",
        "When to stop:",
        "Call the submit_report tool when you have enough evidence to form a verdict.",
        "",
        "Required report schema:",
        "The report must be a JSON object with the following fields:",
        "- summary: string",
        "- verdict: string",
        "- findings: list of objects with title, description, severity, confidence, evidence_refs, source_location",
        "",
        "Current state:",
        current_state,
    ]
    return "\n".join(sections)
