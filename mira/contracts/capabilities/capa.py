from __future__ import annotations

from typing import List, Optional

from pydantic import Field

from mira.contracts.common import Contract


class CAPAFinding(Contract):
    rule_id: str = Field(..., description="CAPA rule identifier")
    namespace: str = Field(default="", description="Namespace of the rule")
    meta: dict = Field(default_factory=dict, description="Metadata from the rule")


class RunCapaInput(Contract):
    # TODO(pagination): limit/offset deferred - run_capa is still a stub that
    # reports TOOL_NOT_AVAILABLE. Add both when capa is actually integrated.
    artifact_id: str = Field(..., description="Identifier of the artifact")


class RunCapaOutput(Contract):
    findings: List[CAPAFinding] = Field(..., description="List of CAPA findings")
    total: int = Field(..., description="Total number of findings available")
    limit: int = Field(..., description="Limit used for this query")
    offset: int = Field(..., description="Offset used for this query")
