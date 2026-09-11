"""Model response contracts."""

from dataclasses import dataclass
from typing import List, Optional
from .tool import ToolCall


@dataclass
class ModelResponse:
    """Response from the model, which can be tool calls, a report, or empty."""
    tool_calls: Optional[List[ToolCall]] = None
    report: Optional[str] = None

    def __post_init__(self):
        if self.tool_calls is not None and self.report is not None:
            raise ValueError("ModelResponse cannot have both tool_calls and report")
