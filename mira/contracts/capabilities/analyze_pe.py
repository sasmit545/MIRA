from __future__ import annotations

from typing import List

from pydantic import Field

from mira.contracts.common import Contract


class Section(Contract):
    name: str
    virtual_address: int
    virtual_size: int
    raw_size: int
    characteristics: int
    entropy: float


class CoffHeader(Contract):
    machine: int
    characteristics: int


class OptionalHeader(Contract):
    magic: int
    image_base: int
    subsystem: int
    dll_characteristics: int


class AnalyzePEInput(Contract):
    artifact_id: str = Field(..., description="Identifier of the PE artifact")


class AnalyzePEOutput(Contract):
    architecture: str = Field(..., description="CPU architecture (e.g., x86, x64)")
    coff_header: CoffHeader = Field(..., description="COFF file header fields")
    optional_header: OptionalHeader = Field(..., description="Optional header fields")
    entry_point: int = Field(..., description="Entry point RVA")
    sections: List[Section] = Field(..., description="PE sections")
    overlay_size: int = Field(..., description="Bytes trailing the last section")
