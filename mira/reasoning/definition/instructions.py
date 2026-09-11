"""Instructions / prompt assembly."""

from typing import List
from ..contracts.tool import ToolSpec


def assemble_instructions(
    objective: str,
    scope: str,
    available_tools: List[ToolSpec],
    current_state: str,
) -> str:
    """Assemble the model-facing prompt from sections."""
    sections = [
        "Role: You are a static malware investigator.",
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
