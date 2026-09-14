"""Output contracts."""

from dataclasses import dataclass, field
from typing import List
from .finding import Finding
from .tool import ToolResult


@dataclass(frozen=True)
class FinalOutput:
    """The final output of the investigation."""
    summary: str
    verdict: str
    findings: List[Finding]
    evidence: List[str]  # Identifiers of the evidence gathered during the run
    completion_reason: str  # e.g., "reported", "limit_turns", "limit_calls", "degraded"
    metadata: dict  # turns, tool calls, token usage, run_id
    recommended_actions: List[str] = field(default_factory=list)
    # Raw capability results, for the CLI and for anything else not bound by a
    # context window. This never crosses to an orchestrator: the specialist's
    # own message carries evidence references instead.
    observations: List[ToolResult] = field(default_factory=list)
