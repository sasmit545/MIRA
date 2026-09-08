from __future__ import annotations

from datetime import datetime
from typing import NewType, Optional

from pydantic import BaseModel, Field, validator


# Basic NewTypes for identifiers and names
ContractVersion = NewType('ContractVersion', str)
RequestId = NewType('RequestId', str)
ArtifactId = NewType('ArtifactId', str)
CapabilityName = NewType('CapabilityName', str)
Timestamp = NewType('Timestamp', datetime)


class Contract(BaseModel):
    """Base contract model with version."""
    contract_version: ContractVersion = Field(default='1.0')
    
    class Config:
        extra = 'forbid'
        validate_assignment = True
