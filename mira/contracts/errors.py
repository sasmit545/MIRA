from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class CapabilityError(BaseModel):
    """Structured error model for capability failures."""
    code: str = Field(..., description="Machine-readable error code")
    message: str = Field(..., description="Human-readable error message")
    details: Optional[dict] = Field(None, description="Additional error details")


# Standard error codes
ARTIFACT_NOT_FOUND = "ARTIFACT_NOT_FOUND"
INVALID_INPUT = "INVALID_INPUT"
UNSUPPORTED_FILE_TYPE = "UNSUPPORTED_FILE_TYPE"
ANALYSIS_FAILED = "ANALYSIS_FAILED"
TOOL_NOT_AVAILABLE = "TOOL_NOT_AVAILABLE"
TIMEOUT = "TIMEOUT"
RESOURCE_LIMIT = "RESOURCE_LIMIT"
PERMISSION_DENIED = "PERMISSION_DENIED"
