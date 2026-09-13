from __future__ import annotations

from typing import List, Optional

from pydantic import Field

from mira.contracts.common import Contract


class Function(Contract):
    address: int
    # Unknown without an analysis engine; the entry-point heuristic emits None.
    size: Optional[int] = None
    name: str
    discovery_source: str


class ListFunctionsInput(Contract):
    artifact_id: str = Field(..., description="Identifier of the artifact")
    limit: int = Field(100, ge=1, le=1000, description="Maximum number of items to return")
    offset: int = Field(0, ge=0, description="Offset for pagination")


class ListFunctionsOutput(Contract):
    # Paging counters ride in the envelope's metadata, not here.
    functions: List[Function] = Field(..., description="Discovered functions for this page")
    limitations: str = Field(..., description="What this discovery pass cannot see")
