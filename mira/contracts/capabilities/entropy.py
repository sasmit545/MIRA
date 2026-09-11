from __future__ import annotations

from typing import List, Optional

from pydantic import Field

from mira.contracts.common import Contract


class EntropyChunk(Contract):
    offset: int
    size: int
    entropy: float


class CalculateEntropyInput(Contract):
    # Note: offset here is a byte-region start paired with length, not a
    # pagination cursor. Chunked entropy (chunk_size/chunks[]) is deferred;
    # the handler measures the whole file or one bounded region.
    artifact_id: str = Field(..., description="Identifier of the artifact")
    offset: int | None = Field(None, ge=0, description="Start of the region to measure; supply with length")
    length: int | None = Field(None, ge=1, description="Size of the region to measure; supply with offset")


class CalculateEntropyOutput(Contract):
    chunks: List[EntropyChunk] = Field(..., description="Entropy per chunk")
    overall_entropy: float = Field(..., description="Overall entropy of the artifact")
    total_chunks: int = Field(..., description="Total number of chunks")
    limit: int = Field(..., description="Limit used for this query")
    offset: int = Field(..., description="Offset used for this query")
