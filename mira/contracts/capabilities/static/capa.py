from __future__ import annotations

from typing import List

from pydantic import Field

from mira.contracts.common import Contract


class CAPAFinding(Contract):
    """One matched rule, compact enough that a whole run's findings fit one recall."""
    rule_id: str = Field(..., description="CAPA rule identifier")
    namespace: str = Field(default="", description="Namespace of the rule")
    attack: List[str] = Field(default_factory=list, description="ATT&CK technique ids, e.g. T1562.001")
    mbc: List[str] = Field(default_factory=list, description="MBC behavior ids, e.g. B0001.035")
    matches: int = Field(default=0, description="Locations the rule matched")


class CAPADetail(Contract):
    """The full record of one finding, at the same index as its finding."""
    rule_id: str = Field(..., description="CAPA rule identifier")
    description: str = Field(default="", description="The rule's own description, when it has one")
    scopes: dict = Field(default_factory=dict, description="Static and dynamic scopes of the rule")
    attack: List[str] = Field(default_factory=list, description="Full ATT&CK entries")
    mbc: List[str] = Field(default_factory=list, description="Full MBC entries")
    references: List[str] = Field(default_factory=list, description="References the rule cites")
    addresses: List[str] = Field(default_factory=list, description="Virtual addresses of the first matches, in hex")
    matched: List[str] = Field(
        default_factory=list,
        description="Features that made the rule match, such as an API or a regex with the string it matched",
    )


class RunCapaInput(Contract):
    artifact_id: str = Field(..., description="Identifier of the artifact")
    limit: int = Field(100, ge=1, le=1000, description="Maximum number of findings to return")
    offset: int = Field(0, ge=0, description="Offset for pagination")


class RunCapaOutput(Contract):
    # Reports TOOL_NOT_AVAILABLE when no rules directory is configured; output
    # validation only runs on an ok envelope.
    findings: List[CAPAFinding] = Field(..., description="Compact CAPA findings, sorted by rule_id")
    details: List[CAPADetail] = Field(..., description="Full record of each finding, in the same order")
