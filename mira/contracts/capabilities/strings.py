from __future__ import annotations

from typing import List, Optional

from pydantic import Field

from mira.contracts.common import Contract


class StringEntry(Contract):
    value: str
    offset: int
    length: int


class ExtractStringsInput(Contract):
    artifact_id: str = Field(..., description="Identifier of the artifact")
    limit: int = Field(100, ge=1, le=1000, description="Maximum number of items to return")
    offset: int = Field(0, ge=0, description="Offset for pagination")
    min_length: int = Field(5, ge=1, description="Minimum string length to consider")


class ExtractStringsOutput(Contract):
    strings: List[StringEntry] = Field(..., description="Extracted strings")
    total: int = Field(..., description="Total number of strings available")
    limit: int = Field(..., description="Limit used for this query")
    offset: int = Field(..., description="Offset used for this query")
