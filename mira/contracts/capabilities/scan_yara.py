from __future__ import annotations

from typing import List

from pydantic import Field

from mira.contracts.common import Contract


class YaraMatch(Contract):
    rule: str
    namespace: str
    tags: List[str]


class ScanYaraInput(Contract):
    # TODO(pagination): limit/offset deferred - scan_yara returns every match.
    # Add both with paginate(), the way extract_strings already does.
    artifact_id: str = Field(..., description="Identifier of the artifact")
    ruleset: str = Field(..., description="Name of a configured rule set to scan with")


class ScanYaraOutput(Contract):
    matches: List[YaraMatch] = Field(..., description="YARA matches")
