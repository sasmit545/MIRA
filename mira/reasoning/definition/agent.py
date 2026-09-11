"""Agent definition (immutable configuration)."""

from dataclasses import dataclass
from typing import List

from ..contracts.tool import ToolSpec
from ..contracts.output import FinalOutput


@dataclass(frozen=True)
class AgentDefinition:
    """Immutable, read-only config for one specialist's reasoning run.

    The loop itself is specialist-agnostic. `role` and `scope` are what
    specialize a run, so each specialist supplies its own rather than
    inheriting a default from the runtime.
    """
    role: str  # the investigator identity the model is asked to adopt
    scope: str  # what this specialist may investigate, and what it may not
    instructions: str
    tool_manifest: List[ToolSpec]  # what exists
    allowed_tools: List[ToolSpec]  # what is permitted this run (subset of manifest)
    max_turns: int
    max_tool_calls: int
    output_contract: type[FinalOutput]  # e.g., FinalOutput class
