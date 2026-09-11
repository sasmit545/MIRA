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
    # TODO(pagination): limit/offset deferred - scan_yara returns every match.
    # Add both with paginate(), the way extract_strings already does.
    artifact_id: str = Field(..., description="Identifier of the artifact")
    ruleset: str = Field(..., description="Name of a configured rule set to scan with")


class ScanYaraOutput(Contract):
    matches: List[YaraMatch] = Field(..., description="YARA matches")
    total: int = Field(..., description="Total number of matches available")
    limit: int = Field(..., description="Limit used for this query")
    offset: int = Field(..., description="Offset used for this query")
