from __future__ import annotations

from typing import Generic, TypeVar

from pydantic import BaseModel, Field

from .common import Contract, ContractVersion, RequestId, CapabilityName


T = TypeVar("T", bound=BaseModel)


class CapabilityRequest(Contract, Generic[T]):
    """Generic MCP request for a capability."""
    request_id: RequestId = Field(..., description="Unique identifier for this request")
    capability: CapabilityName = Field(..., description="Name of the capability to invoke")
    input: T = Field(..., description="Capability-specific input parameters")
