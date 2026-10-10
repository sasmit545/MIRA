"""Model response contracts."""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from .tool import ToolCall


@dataclass
class ModelResponse:
    """Response from the model: tool calls, a working-memory update, a report, any mix, or nothing.

    The three are independent channels - a turn can carry a capability call
    and its notes, or the notes and the final report - so nothing here forbids
    a combination. Dropping a sibling call would discard real work.
    """
    tool_calls: Optional[List[ToolCall]] = None
    report: Optional[str] = None
    memory_update: Optional[Dict[str, Any]] = None  # raw arguments of record_memory, validated by the loop
    usage: Optional[dict] = None  # {"prompt_tokens", "completion_tokens", "total_tokens"}, when the provider reports it
