from __future__ import annotations

from typing import Optional

from pydantic import Field

from mira.contracts.common import Contract


class DetectPackerInput(Contract):
    artifact_id: str = Field(..., description="Identifier of the artifact")


class DetectPackerOutput(Contract):
    packer: Optional[str] = Field(None, description="Detected packer name")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence in detection")
    details: Optional[dict] = Field(None, description="Additional details")
