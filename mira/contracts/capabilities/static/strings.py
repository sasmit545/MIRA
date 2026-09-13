from __future__ import annotations

from typing import List

from pydantic import Field

from mira.contracts.common import Contract


class StringEntry(Contract):
    value: str
    offset: int
    encoding: str


class ExtractStringsInput(Contract):
    artifact_id: str = Field(..., description="Identifier of the artifact")
    limit: int = Field(100, ge=1, le=1000, description="Maximum number of items to return")
    offset: int = Field(0, ge=0, description="Offset for pagination")
    # Bounds match the handler's own guard; a value it would reject must not
    # pass input validation here.
    min_length: int = Field(4, ge=3, le=256, description="Minimum string length to consider")


class ExtractStringsOutput(Contract):
    # Paging counters ride in the envelope's metadata, not here.
    strings: List[StringEntry] = Field(..., description="Extracted strings for this page")
