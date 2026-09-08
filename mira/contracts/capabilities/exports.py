from __future__ import annotations

from typing import List, Optional

from pydantic import Field

from mira.contracts.common import Contract


class ExportEntry(Contract):
    name: str
    address: int
    ordinal: Optional[int] = None


class ListExportsInput(Contract):
    artifact_id: str = Field(..., description="Identifier of the artifact")
    limit: int = Field(100, ge=1, le=1000, description="Maximum number of items to return")
    offset: int = Field(0, ge=0, description="Offset for pagination")


class ListExportsOutput(Contract):
    entries: List[ExportEntry] = Field(..., description="Export entries")
    total: int = Field(..., description="Total number of exports available")
    limit: int = Field(..., description="Limit used for this query")
    offset: int = Field(..., description="Offset used for this query")
