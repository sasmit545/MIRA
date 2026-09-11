from __future__ import annotations

from typing import List

from pydantic import Field

from mira.contracts.common import Contract


class Section(Contract):
    name: str
    virtual_address: int
    virtual_size: int
    raw_data_pointer: int
    raw_data_size: int
    characteristics: int


class AnalyzePEInput(Contract):
    artifact_id: str = Field(..., description="Identifier of the PE artifact")


class AnalyzePEOutput(Contract):
    architecture: str = Field(..., description="CPU architecture (e.g., x86, x64)")
    entry_point: int = Field(..., description="Entry point RVA")
    image_base: int = Field(..., description="Image base address")
    sections: List[Section] = Field(..., description="PE sections")
