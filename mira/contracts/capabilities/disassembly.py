from __future__ import annotations

from typing import List, Optional

from pydantic import Field

from mira.contracts.common import Contract


class Instruction(Contract):
    address: int = Field(..., description="Instruction address")
    mnemonic: str = Field(..., description="Assembly mnemonic")
    op_str: str = Field(..., description="Operands string")


class DisassembleFunctionInput(Contract):
    artifact_id: str = Field(..., description="Identifier of the artifact")
    function_address: int = Field(..., description="Address of the function to disassemble")
    limit: int = Field(100, ge=1, le=1000, description="Maximum number of instructions to return")
    offset: int = Field(0, ge=0, description="Offset for pagination")


class DisassembleFunctionOutput(Contract):
    instructions: List[Instruction] = Field(..., description="Disassembled instructions")
    total: int = Field(..., description="Total number of instructions available")
    limit: int = Field(..., description="Limit used for this query")
    offset: int = Field(..., description="Offset used for this query")
