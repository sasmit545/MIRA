"""Output contracts."""

from dataclasses import dataclass, field
from typing import List
from .finding import Finding
from .memory import WorkingMemory
from .tool import ToolResult

# The only verdicts a report may carry (R8). inconclusive is an answer, not a failure.
VERDICTS = ("benign", "malicious", "inconclusive")


@dataclass(frozen=True)
class FinalOutput:
    """The final output of the investigation."""
    summary: str
    verdict: str
    findings: List[Finding]
    evidence: List[str]  # Identifiers of the evidence gathered during the run
    completion_reason: str  # e.g., "reported", "limit_turns", "limit_calls", "limit_reports", "degraded"
    metadata: dict  # turns, tool calls, token usage, run_id
    recommended_actions: List[str] = field(default_factory=list)
    # Raw capability results, for the CLI and for anything else not bound by a
    # context window. This never crosses to an orchestrator: the specialist's
    # own message carries evidence references instead.
    observations: List[ToolResult] = field(default_factory=list)
    # The notes as they stood when the run returned, so the specialist can
    # promote the hypotheses and compose its assessment from them.
    memory: WorkingMemory = field(default_factory=WorkingMemory)
