from __future__ import annotations

from typing import Optional

from pydantic import Field
from datetime import datetime

from mira.contracts.common import Contract


class Evidence(Contract):
    """Evidence model for agent reasoning."""
    evidence_id: str = Field(..., description="Unique identifier for this evidence")
    observation: str = Field(..., description="Observation or finding")
    artifact_id: str = Field(..., description="Identifier of the artifact this evidence pertains to")
    capability: str = Field(..., description="Capability that produced this evidence")
    location: Optional[str] = Field(None, description="Location within the artifact (e.g., function name, offset)")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence in the evidence")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="When the evidence was generated")
    provenance: Optional[str] = Field(None, description="Source of the evidence (e.g., tool name)")
