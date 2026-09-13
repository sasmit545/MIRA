"""Selected-function instruction decoding via optional Capstone."""

from mira.core.artifact import Artifact
from mira.capabilities.static.common import result_error, result_ok
from mira.capabilities.static.pe_support import load_pe


def disassemble_function(artifact: Artifact, *, function_address: int | str, limit: int = 100) -> dict:
    pe, failure = load_pe(artifact, "disassemble_function")
    if failure:
        return failure
    try:
        address = int(function_address, 0) if isinstance(function_address, str) else function_address
        if not isinstance(address, int) or limit < 1 or limit > 1_000:
            raise ValueError
    except ValueError:
        return result_error(artifact.artifact_id, "disassemble_function", "INVALID_INPUT", "function_address and limit are invalid")
    try:
        import capstone
    except ImportError:
        return result_error(artifact.artifact_id, "disassemble_function", "TOOL_NOT_AVAILABLE", "capstone is not installed")
    try:
        rva = address - pe.OPTIONAL_HEADER.ImageBase
        data = pe.get_data(rva, 4096)
    except ValueError:
        return result_error(artifact.artifact_id, "disassemble_function", "INVALID_INPUT", "function address is outside the image")
    mode = capstone.CS_MODE_64 if pe.FILE_HEADER.Machine == 0x8664 else capstone.CS_MODE_32
    instructions = [{"address": instruction.address, "bytes": instruction.bytes.hex(), "mnemonic": instruction.mnemonic, "operands": instruction.op_str} for instruction in list(capstone.Cs(capstone.CS_ARCH_X86, mode).disasm(data, address))[:limit]]
    return result_ok(artifact, "disassemble_function", {"function_address": address, "architecture": "x64" if mode == capstone.CS_MODE_64 else "x86", "instructions": instructions}, has_more=len(instructions) == limit)
