from __future__ import annotations

from typing import Generic, TypeVar, Dict, Any

from pydantic import BaseModel, Field, field_validator

from .common import Contract, ContractVersion, RequestId, CapabilityName


T = TypeVar('T')


class CapabilityRequest(Contract, Generic[T]):
    """Generic MCP request for a capability."""
    request_id: RequestId = Field(..., description="Unique identifier for this request")
    capability: CapabilityName = Field(..., description="Name of the capability to invoke")
    input: T = Field(..., description="Capability-specific input parameters")
    
    @field_validator('input')
    @classmethod
    def input_must_be_dict(cls, v):
        if not isinstance(v, dict):
            raise ValueError('input must be a dictionary')
        return v
