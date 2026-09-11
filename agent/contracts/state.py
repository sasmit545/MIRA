"""Investigation state."""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from ..contracts.objective import Objective
from ..contracts.tool import ToolCall, ToolResult
from ..contracts.finding import Finding


@dataclass
class State:
    """Mutable state owned by the run."""
    objective: Objective
    turn_count: int = 0
    tool_call_count: int = 0
    findings: List[Finding] = field(default_factory=list)
    evidence: List[Any] = field(default_factory=list)  # Curated subset of observations
    observations: List[Dict[str, Any]] = field(default_factory=list)  # Each observation: {'call': ToolCall, 'result': ToolResult}
    scratch: Dict[str, Any] = field(default_factory=dict)  # visible to model, excluded from output
    run_id: str = field(init=False)

    def __post_init__(self) -> None:
        self.run_id = "run_" + str(hash(self.objective.description))

    def record_tool_call(self, tool_call: ToolCall) -> None:
        self.tool_call_count += 1
        self.observations.append({'call': tool_call, 'result': None})

    def record_tool_result(self, tool_result: ToolResult) -> None:
        # Find the last observation with result None and set it
        for obs in reversed(self.observations):
            if obs['result'] is None:
                obs['result'] = tool_result
                return
        # This should not happen if we call record_tool_call before record_tool_result
        raise RuntimeError("No pending tool call to record result for")

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def add_evidence(self, evidence: Any) -> None:
        self.evidence.append(evidence)

    def snapshot(self) -> Dict[str, Any]:
        """Return a snapshot of the state for tracing."""
        return {
            'objective': self.objective.description,
            'turn_count': self.turn_count,
            'tool_call_count': self.tool_call_count,
            'findings_count': len(self.findings),
            'evidence_count': len(self.evidence),
            'observations_count': len(self.observations),
            'scratch': self.scratch.copy(),
            'run_id': self.run_id,
        }
