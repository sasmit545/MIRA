from __future__ import annotations

from typing import Generic, TypeVar, Optional, Dict, Any

from pydantic import BaseModel, Field, field_validator

from .common import Contract, ContractVersion, RequestId
from .errors import CapabilityError


T = TypeVar('T')


class CapabilityResult(Contract, Generic[T]):
    """Generic MCP result for a capability."""
    request_id: RequestId = Field(..., description="Identifier of the request this result corresponds to")
    status: str = Field(..., description="Status of the operation: ok, unsupported, error")
    data: Optional[T] = Field(None, description="Capability-specific output data")
    error: Optional[CapabilityError] = Field(None, description="Structured error information if status is error")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Additional metadata")
    
    @field_validator('status')
    @classmethod
    def status_must_be_valid(cls, v):
        allowed = {'ok', 'unsupported', 'error'}
        if v not in allowed:
            raise ValueError(f'status must be one of {allowed}')
        return v
