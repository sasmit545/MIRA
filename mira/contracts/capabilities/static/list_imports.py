from __future__ import annotations

from typing import List, Optional

from pydantic import Field

from mira.contracts.common import Contract


class ImportEntry(Contract):
    dll: str
    name: Optional[str] = None
    ordinal: Optional[int] = None
    address: int


class ListImportsInput(Contract):
    artifact_id: str = Field(..., description="Identifier of the artifact")
    limit: int = Field(100, ge=1, le=1000, description="Maximum number of items to return")
    offset: int = Field(0, ge=0, description="Offset for pagination")


class ListImportsOutput(Contract):
    # Paging counters ride in the envelope's metadata, not here: result_ok
    # receives them as **page and they never enter `data`.
    imports: List[ImportEntry] = Field(..., description="Import entries for this page")
