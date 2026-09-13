from __future__ import annotations

from pydantic import Field

from mira.contracts.common import Contract


class CalculateEntropyInput(Contract):
    # Note: offset here is a byte-region start paired with length, not a
    # pagination cursor. Chunked entropy (chunk_size/chunks[]) is deferred;
    # the handler measures the whole file or one bounded region.
    artifact_id: str = Field(..., description="Identifier of the artifact")
    offset: int | None = Field(None, ge=0, description="Start of the region to measure; supply with length")
    length: int | None = Field(None, ge=1, description="Size of the region to measure; supply with offset")


class CalculateEntropyOutput(Contract):
    entropy: float = Field(..., description="Shannon entropy of the measured bytes")
    offset: int = Field(..., description="Start of the measured region; 0 for the whole file")
    length: int = Field(..., description="Number of bytes measured")
