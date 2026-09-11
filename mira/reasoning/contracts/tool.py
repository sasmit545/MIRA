"""Tool-related contracts."""

from dataclasses import dataclass
from typing import Any, Dict, Optional, Union


@dataclass(frozen=True)
class ToolSpec:
    """Specification of a tool available to the agent."""
    name: str
    description: str
    parameters: Dict[str, Any]  # JSON Schema for the tool's input


@dataclass(frozen=True)
class ToolCall:
    """A request to execute a tool."""
    tool_call_id: str  # Unique identifier for this call
    name: str          # Name of the tool to call
    arguments: Dict[str, Any]  # Arguments for the tool, as a dict


@dataclass(frozen=True)
class ToolResult:
    """Result of executing a tool."""
    tool_call_id: str  # Matches the ToolCall that produced this result
    success: bool
    # If success is True, then output is the result; otherwise, error is the error message.
    output: Optional[Any] = None
    error: Optional[str] = None

    def __post_init__(self):
        if self.success:
            if self.error is not None:
                raise ValueError("Successful ToolResult must not have an error")
        else:
            if self.output is not None:
                raise ValueError("Failed ToolResult must not have an output")
