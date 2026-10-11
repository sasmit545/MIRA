"""Tracing for the agent loop."""

import json
import os
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, Iterator, List, Dict, Any, Optional, Tuple
from ..contracts.tool import ToolCall, ToolResult
from ..contracts.model import ModelResponse
from ..contracts.state import State
from .payload import MAX_DIGEST_CHARS, MAX_OBSERVATION_CHARS, digest, list_arrays, truncate  # noqa: F401 - re-exported


PROVENANCE_SEPARATOR = "#"


def trace_provenance(run_id: str, capability: str, occurrence: int) -> str:
    """Name one observation: which run wrote it, and which call within that run.

    This is the whole retrieval story (KTD2). The trace file already holds every
    full tool result, so a reference of this shape resolves back to the raw
    observation without a second persistence layer.

    Keyed by capability rather than by position in the whole run: a call the
    runtime refuses before the executor - a capability outside the objective -
    is still recorded in the trace, so a single run-wide counter kept by the
    executor drifts from the trace the moment one is refused. A capability is
    either permitted for the whole run or never executed, so counting each
    capability's own calls cannot drift.
    """
    return f"{run_id}{PROVENANCE_SEPARATOR}{capability}{PROVENANCE_SEPARATOR}{occurrence}"


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
    parsed = _parse_provenance(provenance)
    if parsed is None:
        return None
    run_id, capability, occurrence = parsed

    try:
        with open(trace_path(trace_dir, run_id)) as trace_file:
            turns = json.load(trace_file)
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(turns, list):
        return None

    # Turns that recorded no tool call - an empty response, a rejected report -
    # contribute nothing: the tracer only writes capability calls.
    pairs = (
        (call.get("name"), call, result)
        for turn in turns
        if isinstance(turn, dict)
        for call, result in zip(turn.get("tool_calls") or [], turn.get("tool_results") or [])
        if isinstance(call, dict)
    )
    return _find(pairs, capability, occurrence)


def live_observation(state: State, provenance: str) -> Optional[Dict[str, Any]]:
    """`resolve_observation()` against the run still in progress.

    The trace file is only written when the run ends (KTD6), so a mid-run
    lookup reads the observation log instead, through the same numbering.
    A handle naming another run is an absence, like any other miss.
    """
    parsed = _parse_provenance(provenance)
    if parsed is None or parsed[0] != state.run_id:
        return None
    return _find(_live_pairs(state), parsed[1], parsed[2])


@dataclass(frozen=True)
class CapabilityRecord:
    """One capability call as the model is shown it, without its raw payload."""
    handle: str  # trace_provenance(), so recall and evidence share one identifier
    name: str
    arguments: Dict[str, Any]
    success: bool
    error: Optional[str]
    digest: str  # empty for a failure: the error is what it produced
    evidence: Tuple[str, ...] = ()  # ids minted from this call: what the specialist read out of it
    shown: Tuple[str, ...] = ()  # per array, the items recalls have shown (R10)


def capability_calls(state: State) -> Iterator[Tuple[str, ToolCall, ToolResult]]:
    """Every capability call this run made, in order, with its handle and
    nothing rendered: for questions about the calls rather than the prompt."""
    for name, occurrence, call, result in _numbered(_live_pairs(state)):
        yield trace_provenance(state.run_id, name, occurrence), call, result


def capability_history(state: State) -> List[CapabilityRecord]:
    """Every capability call this run made, in order, as the prompt shows it."""
    minted: Dict[str, List[str]] = {}
    for item in state.evidence:
        provenance = getattr(item, "provenance", None)
        if provenance:
            minted.setdefault(provenance, []).append(item.id)
    return [
        CapabilityRecord(
            handle=handle,
            name=call.name,
            arguments=dict(call.arguments),
            success=result.success,
            error=result.error,
            digest=digest(result.output) if result.success else "",
            evidence=tuple(minted.get(handle, ())),
            shown=_shown(state.shown_items.get(handle) or {}, result.output),
        )
        for handle, call, result in capability_calls(state)
    ]


def _shown(paths: Dict[str, set], output: Any) -> Tuple[str, ...]:
    lengths = dict(list_arrays(output))
    return tuple(
        f"shown {path}: {_ranges(sorted(indices))} ({len(indices)}"
        + (f" of {lengths[path]})" if path in lengths else ")")
        for path, indices in paths.items()
    )


def _ranges(indices: List[int]) -> str:
    """0, 1, 2, 7 -> "0..2, 7"."""
    spans: List[List[int]] = []
    for index in indices:
        if spans and index == spans[-1][1] + 1:
            spans[-1][1] = index
        else:
            spans.append([index, index])
    return ", ".join(f"{start}..{end}" if end > start else str(start) for start, end in spans)


def covered_range(result: ToolResult) -> Optional[Tuple[int, int]]:
    """The item range [start, end) a collected call fetched (KTD2), if any."""
    metadata = result.output.get("metadata") if result.success and isinstance(result.output, dict) else None
    if not isinstance(metadata, dict) or not isinstance(metadata.get("fetched"), int):
        return None
    start = metadata.get("offset") or 0
    return start, start + metadata["fetched"]


def _parse_provenance(provenance: str) -> Optional[Tuple[str, str, int]]:
    parts = provenance.rsplit(PROVENANCE_SEPARATOR, 2)
    if len(parts) != 3:
        return None
    run_id, capability, position = parts
    if not run_id or not capability or not position.isdigit():
        return None
    return run_id, capability, int(position)


def _live_pairs(state: State) -> Iterator[Tuple[str, ToolCall, ToolResult]]:
    """The observation log as the trace would hold it: capability calls only.

    Harness entries - a rejected report or narrative, a skipped duplicate -
    never reach the tracer, so they take no occurrence here either.
    """
    for observation in state.observations:
        if not observation.get("harness") and observation["result"] is not None:
            yield observation["call"].name, observation["call"], observation["result"]


def _numbered(pairs: Iterable[Tuple[Any, Any, Any]]) -> Iterator[Tuple[Any, int, Any, Any]]:
    """Number each capability's own calls in log order - the one counting rule.

    A call the runtime refused belongs to a different capability, so it cannot
    shift this one's numbering. A failed call to this capability does occupy
    an occurrence: the trace records it like any other.
    """
    seen: Counter = Counter()
    for name, call, result in pairs:
        yield name, seen[name], call, result
        seen[name] += 1


def _find(pairs, capability: str, occurrence: int) -> Optional[Dict[str, Any]]:
    for name, number, call, result in _numbered(pairs):
        if name == capability and number == occurrence:
            return {"call": call, "result": result}
    return None


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
        validation: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Record a single turn. `validation` is the verdict gate's record of
        a report this turn submitted."""
        turn_record = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "context_sent": context_sent,
            "response_received": response_received.__dict__,  # Assuming ModelResponse is a dataclass
            "tool_calls": [tc.__dict__ for tc in tool_calls],
            "tool_results": [tr.__dict__ for tr in tool_results],
            "state_snapshot": state_snapshot,
            "token_usage": token_usage,
        }
        if validation is not None:
            turn_record["validation"] = validation
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
