from __future__ import annotations

from typing import List, Optional

from pydantic import Field

from mira.contracts.common import Contract


class EntropyChunk(Contract):
    offset: int
    size: int
    entropy: float


class CalculateEntropyInput(Contract):
    artifact_id: str = Field(..., description="Identifier of the artifact")
    chunk_size: int = Field(1024, ge=1, description="Size of chunks for entropy calculation")
    limit: int = Field(100, ge=1, le=1000, description="Maximum number of chunks to return")
    offset: int = Field(0, ge=0, description="Offset for pagination")


class CalculateEntropyOutput(Contract):
    chunks: List[EntropyChunk] = Field(..., description="Entropy per chunk")
    overall_entropy: float = Field(..., description="Overall entropy of the artifact")
    total_chunks: int = Field(..., description="Total number of chunks")
    limit: int = Field(..., description="Limit used for this query")
    offset: int = Field(..., description="Offset used for this query")
