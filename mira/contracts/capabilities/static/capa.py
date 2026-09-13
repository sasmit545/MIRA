from __future__ import annotations

from typing import List

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
    # Never produced yet: the handler always reports TOOL_NOT_AVAILABLE, and
    # output validation only runs on an ok envelope.
    findings: List[CAPAFinding] = Field(..., description="List of CAPA findings")
