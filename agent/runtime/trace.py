"""Tracing for the agent loop."""

import json
import os
from datetime import datetime
from typing import List, Dict, Any, Optional
from ..contracts.tool import ToolCall, ToolResult
from ..contracts.model import ModelResponse


class Tracer:
    """Records each turn and writes a trace file."""

    def __init__(self, run_id: str, output_dir: str):
        self.run_id = run_id
        self.output_dir = output_dir
        self.trace: List[Dict[str, Any]] = []
        # Ensure the output directory exists
        os.makedirs(self.output_dir, exist_ok=True)

    def turn(
        self,
        context_sent: str,
        response_received: ModelResponse,
        tool_calls: List[ToolCall],
        tool_results: List[ToolResult],
        state_snapshot: Dict[str, Any],
        token_usage: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Record a single turn."""
        turn_record = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "context_sent": context_sent,
            "response_received": response_received.__dict__,  # Assuming ModelResponse is a dataclass
            "tool_calls": [tc.__dict__ for tc in tool_calls],
            "tool_results": [tr.__dict__ for tr in tool_results],
            "state_snapshot": state_snapshot,
            "token_usage": token_usage,
        }
        self.trace.append(turn_record)

    def save(self) -> str:
        """Save the trace to a JSON file and return the file path."""
        trace_file = os.path.join(self.output_dir, f"trace_{self.run_id}.json")
        with open(trace_file, "w") as f:
            json.dump(self.trace, f, indent=2)
        return trace_file
