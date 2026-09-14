from __future__ import annotations

from typing import List

from pydantic import Field

from mira.contracts.common import Contract


class Instruction(Contract):
    address: int = Field(..., description="Instruction address")
    bytes: str = Field(..., description="Raw instruction bytes, hex encoded")
    mnemonic: str = Field(..., description="Assembly mnemonic")
    operands: str = Field(..., description="Operands string")


class DisassembleFunctionInput(Contract):
    artifact_id: str = Field(..., description="Identifier of the artifact")
    function_address: int = Field(..., description="Address of the function to disassemble")
    limit: int = Field(100, ge=1, le=1000, description="Maximum number of instructions to return")
    offset: int = Field(0, ge=0, description="Offset for pagination")


class DisassembleFunctionOutput(Contract):
    function_address: int = Field(..., description="Address that was disassembled")
    architecture: str = Field(..., description="Decoding mode used, x86 or x64")
    instructions: List[Instruction] = Field(..., description="Disassembled instructions")
