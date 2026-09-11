"""Agent definition (immutable configuration)."""

from dataclasses import dataclass
from typing import List, Optional
from ..contracts.tool import ToolSpec
from ..contracts.model import ModelResponse
from ..contracts.output import FinalOutput


@dataclass(frozen=True)
class StaticAgentDefinition:
    """Immutable, read-only config for the agent."""
    instructions: str
    tool_manifest: List[ToolSpec]  # what exists
    allowed_tools: List[ToolSpec]  # what is permitted this run (subset of manifest)
    max_turns: int
    max_tool_calls: int
    output_contract: type[FinalOutput]  # e.g., FinalOutput class
