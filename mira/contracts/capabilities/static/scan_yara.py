from __future__ import annotations

from typing import List

from pydantic import Field

from mira.contracts.common import Contract


class YaraMatch(Contract):
    rule: str
    namespace: str
    tags: List[str]


class ScanYaraInput(Contract):
    artifact_id: str = Field(..., description="Identifier of the artifact")
    ruleset: str = Field(..., description="Name of a configured rule set to scan with")
    limit: int = Field(100, ge=1, le=1000, description="Maximum number of items to return")
    offset: int = Field(0, ge=0, description="Offset for pagination")


class ScanYaraOutput(Contract):
    matches: List[YaraMatch] = Field(..., description="YARA matches")
