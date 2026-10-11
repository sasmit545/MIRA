"""Investigation state."""

from dataclasses import asdict, dataclass, field
from typing import List, Optional, Dict, Any, FrozenSet
from ..contracts.objective import Objective
from ..contracts.tool import ToolCall, ToolResult
from ..contracts.finding import Finding
from ..contracts.memory import WorkingMemory


@dataclass
class State:
    """Mutable state owned by the run."""
    objective: Objective
    # Names this run's trace file too, so an evidence reference recorded here
    # resolves back to the full observation on disk. Supplied by the caller:
    # deriving it here (from hash(), say) makes it unstable across processes.
    run_id: str
    turn_count: int = 0
    tool_call_count: int = 0
    total_prompt_tokens: int = 0
    total_completion_tokens: int = 0
    total_tokens: int = 0
    findings: List[Finding] = field(default_factory=list)
    evidence: List[Any] = field(default_factory=list)  # Curated subset of observations
    observations: List[Dict[str, Any]] = field(default_factory=list)  # Each observation: {'call': ToolCall, 'result': ToolResult}
    working_memory: WorkingMemory = field(default_factory=WorkingMemory)
    # Recall answers from this turn, shown in the next prompt only (KTD10). The
    # prompt is rebuilt from state each turn, so this is the only way one lands.
    recalled: List[str] = field(default_factory=list)
    # Run counters the benchmark reads from the metadata (R19).
    model_calls: int = 0
    recalls_requested: int = 0
    repeat_recalls: int = 0
    reruns_refused: int = 0
    findings_discarded: int = 0
    # The retrieval ledger (KTD7), kept apart from evidence: each answered
    # recall's normalized query mapped to the turn that asked it, and per handle
    # and array path, each item index shown with the keys shown (None: all).
    recall_fingerprints: Dict[str, int] = field(default_factory=dict)
    shown_items: Dict[str, Dict[str, Dict[int, Optional[FrozenSet[str]]]]] = field(default_factory=dict)

    def record_usage(self, usage: Optional[Dict[str, int]]) -> None:
        """Called once per model response, so it also counts the call: a
        provider that reports no usage still cost one."""
        self.model_calls += 1
        if usage is None:
            return
        self.total_prompt_tokens += usage.get("prompt_tokens", 0)
        self.total_completion_tokens += usage.get("completion_tokens", 0)
        self.total_tokens += usage.get("total_tokens", 0)

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

    def record_harness_observation(self, call: ToolCall, result: ToolResult) -> None:
        """Log a harness-tool outcome (a rejected narrative, say) for the model
        and the trace without spending capability budget: record_tool_call is
        the only other way in, and it counts toward max_tool_calls."""
        # Marked so the capability history skips it: a skipped duplicate carries
        # a capability's name, yet it never ran and must take no occurrence.
        self.observations.append({'call': call, 'result': result, 'harness': True})

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
            'working_memory': asdict(self.working_memory),
            'run_id': self.run_id,
            'total_tokens': self.total_tokens,
        }
