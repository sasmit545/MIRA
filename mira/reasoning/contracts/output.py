"""Output contracts."""

from dataclasses import dataclass
from typing import List, Optional
from .finding import Finding
from .tool import ToolResult


@dataclass(frozen=True)
class FinalOutput:
    """The final output of the investigation."""
    summary: str
    verdict: str
    findings: List[Finding]
    evidence: List[ToolResult]  # References to full observations held in State
    completion_reason: str  # e.g., "reported", "limit_turns", "limit_calls", "degraded"
    metadata: dict  # turns, tool calls, token usage, run_id
