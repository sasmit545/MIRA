"""Selected-function instruction decoding via optional Capstone."""

from mira.core.artifact import Artifact
from mira.capabilities.static.common import paginate, result_error, result_ok
from mira.capabilities.static.pe_support import load_pe

#: Longest x86 instruction is 15 bytes; overfetch enough raw bytes to decode
#: past offset+limit instructions, capped so a huge offset can't force a
#: giant read.
MAX_DISASSEMBLY_WINDOW = 64 * 1024


def disassemble_function(artifact: Artifact, *, function_address: int | str, limit: int = 100, offset: int = 0) -> dict:
    pe, failure = load_pe(artifact, "disassemble_function")
    if failure:
        return failure
    try:
        address = int(function_address, 0) if isinstance(function_address, str) else function_address
        if not isinstance(address, int) or limit < 1 or limit > 1_000 or offset < 0:
            raise ValueError
    except ValueError:
        return result_error(artifact.artifact_id, "disassemble_function", "INVALID_INPUT", "function_address, limit, and offset are invalid")
    try:
        import capstone
    except ImportError:
        return result_error(artifact.artifact_id, "disassemble_function", "TOOL_NOT_AVAILABLE", "capstone is not installed")
    try:
        rva = address - pe.OPTIONAL_HEADER.ImageBase
        window = min(MAX_DISASSEMBLY_WINDOW, (offset + limit) * 15)
        data = pe.get_data(rva, window)
    except ValueError:
        return result_error(artifact.artifact_id, "disassemble_function", "INVALID_INPUT", "function address is outside the image")
    mode = capstone.CS_MODE_64 if pe.FILE_HEADER.Machine == 0x8664 else capstone.CS_MODE_32
    decoded = list(capstone.Cs(capstone.CS_ARCH_X86, mode).disasm(data, address))
    try:
        selected, page = paginate(decoded, limit, offset)
    except ValueError as error:
        return result_error(artifact.artifact_id, "disassemble_function", "INVALID_INPUT", str(error))
    instructions = [{"address": instruction.address, "bytes": instruction.bytes.hex(), "mnemonic": instruction.mnemonic, "operands": instruction.op_str} for instruction in selected]
    architecture = "x64" if mode == capstone.CS_MODE_64 else "x86"
    return result_ok(artifact, "disassemble_function", {"function_address": address, "architecture": architecture, "instructions": instructions}, **page)
