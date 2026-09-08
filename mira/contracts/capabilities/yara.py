from __future__ import annotations

from typing import List, Optional

from pydantic import Field

from mira.contracts.common import Contract


class YaraMatch(Contract):
    rule: str
    namespace: str
    tags: List[str]
    meta: dict


class ScanYaraInput(Contract):
    artifact_id: str = Field(..., description="Identifier of the artifact")
    limit: int = Field(100, ge=1, le=1000, description="Maximum number of matches to return")
    offset: int = Field(0, ge=0, description="Offset for pagination")


class ScanYaraOutput(Contract):
    matches: List[YaraMatch] = Field(..., description="YARA matches")
    total: int = Field(..., description="Total number of matches available")
    limit: int = Field(..., description="Limit used for this query")
    offset: int = Field(..., description="Offset used for this query")
