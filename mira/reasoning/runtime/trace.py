"""Tracing for the agent loop."""

import json
import os
from datetime import datetime
from typing import List, Dict, Any, Optional
from ..contracts.tool import ToolCall, ToolResult
from ..contracts.model import ModelResponse


PROVENANCE_SEPARATOR = "#"


def trace_provenance(run_id: str, observation_index: int) -> str:
    """Name one observation: which run wrote it, and where in that run it sits.

    This is the whole retrieval story (KTD2). The trace file already holds every
    full tool result, so a reference of this shape resolves back to the raw
    observation without a second persistence layer.
    """
    return f"{run_id}{PROVENANCE_SEPARATOR}{observation_index}"


def trace_path(trace_dir: str | os.PathLike[str], run_id: str) -> str:
    """Where `Tracer.save()` puts this run's trace."""
    return os.path.join(str(trace_dir), f"trace_{run_id}.json")


def resolve_observation(
    trace_dir: str | os.PathLike[str], provenance: str
) -> Optional[Dict[str, Any]]:
    """Return the full observation a piece of evidence was derived from.

    Returns None rather than raising for every kind of miss - an unknown run,
    a position past the end, an unreadable or truncated trace. A caller asking
    about an old run deserves a negative answer, not an exception.
    """
    run_id, separator, position = provenance.rpartition(PROVENANCE_SEPARATOR)
    if not separator or not run_id or not position.isdigit():
        return None

    try:
        with open(trace_path(trace_dir, run_id)) as trace_file:
            turns = json.load(trace_file)
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(turns, list):
        return None

    # Observations are numbered across the whole run, in call order. Turns that
    # recorded no tool call - an empty response, a rejected report - contribute
    # nothing, which is what keeps this aligned with the specialist's counter.
    observations = [
        {"call": call, "result": result}
        for turn in turns
        if isinstance(turn, dict)
        for call, result in zip(turn.get("tool_calls") or [], turn.get("tool_results") or [])
    ]
    index = int(position)
    return observations[index] if index < len(observations) else None


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
        trace_file = trace_path(self.output_dir, self.run_id)
        with open(trace_file, "w") as f:
            json.dump(self.trace, f, indent=2, default=_serializable)
        return trace_file


def _serializable(value: Any):
    """Render contract objects and stray payloads so a trace always writes."""
    if hasattr(value, "__dict__"):
        return dict(value.__dict__)
    return repr(value)
