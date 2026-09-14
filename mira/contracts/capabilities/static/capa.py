from __future__ import annotations

from typing import List

from pydantic import Field

from mira.contracts.common import Contract


class CAPAFinding(Contract):
    rule_id: str = Field(..., description="CAPA rule identifier")
    namespace: str = Field(default="", description="Namespace of the rule")
    meta: dict = Field(default_factory=dict, description="Metadata from the rule")


class RunCapaInput(Contract):
    artifact_id: str = Field(..., description="Identifier of the artifact")
    limit: int = Field(100, ge=1, le=1000, description="Maximum number of findings to return")
    offset: int = Field(0, ge=0, description="Offset for pagination")


class RunCapaOutput(Contract):
    # Reports TOOL_NOT_AVAILABLE when no rules directory is configured; output
    # validation only runs on an ok envelope.
    findings: List[CAPAFinding] = Field(..., description="List of CAPA findings")
