from __future__ import annotations

from typing import List, Optional

from pydantic import Field

from mira.contracts.common import Contract


class EntropyChunk(Contract):
    offset: int
    length: int
    entropy: float


class CalculateEntropyInput(Contract):
    # Note: offset here is a byte-region start paired with length, not a
    # pagination cursor.
    artifact_id: str = Field(..., description="Identifier of the artifact")
    offset: int | None = Field(None, ge=0, description="Start of the region to measure; supply with length")
    length: int | None = Field(None, ge=1, description="Size of the region to measure; supply with offset")
    chunk_size: int | None = Field(None, ge=1, description="Split the region into fixed-size windows and report entropy per window; requires offset and length")


class CalculateEntropyOutput(Contract):
    entropy: float = Field(..., description="Shannon entropy of the measured bytes")
    offset: int = Field(..., description="Start of the measured region; 0 for the whole file")
    length: int = Field(..., description="Number of bytes measured")
    chunks: Optional[List[EntropyChunk]] = Field(None, description="Per-window entropy; present only when chunk_size was requested")
