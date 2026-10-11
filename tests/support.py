"""Helpers shared across the test suite."""

import struct

from mira.capabilities.static.common import paginate
from mira.reasoning.contracts.model import ModelResponse
from mira.reasoning.contracts.tool import ToolCall


def build_minimal_pe() -> bytes:
    """A real enough PE32 that pefile parses it and PE capabilities run."""
    dos = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x40)
    coff = struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, 0xE0, 0x102)
    optional = struct.pack("<HBBIIIII", 0x10B, 1, 0, 0x200, 0, 0, 0x1000, 0x1000)
    optional += struct.pack("<II", 0x400000, 0x1000)
    optional += struct.pack("<I", 0x200) + b"\x00" * (0xE0 - len(optional) - 4)
    section = (
        b".text\x00\x00\x00"
        + struct.pack("<IIII", 0x200, 0x1000, 0x200, 0x400)
        + b"\x00" * 12
        + struct.pack("<I", 0x60000020)
    )
    head = dos + b"PE\x00\x00" + coff + optional + section
    return head + b"\x00" * (0x400 - len(head)) + b"\x90" * 0x200


REPORT = '{"summary": "done", "verdict": "suspicious", "findings": []}'
# Well-formed and empty: "nothing changed this turn" (R9).
EMPTY_NOTES = {"understanding": "", "hypotheses": [], "open_questions": [], "candidates": []}


class ToolThenReportModel:
    """Calls each named tool once, with the notes every call owes, then
    submits a report.

    Stands in for a real model choosing capabilities. It also records the
    tools it was offered each turn, which is how a test checks that the
    objective actually bounds the choice.
    """

    def __init__(self, *tool_names):
        self.pending = list(tool_names)
        self.offered = []

    def generate(self, context, tools, force=None):
        if force == "record_memory":
            return ModelResponse()  # declines the forced notes call; the script is not consumed
        self.offered.append([spec.name for spec in tools])
        if self.pending:
            name = self.pending.pop(0)
            return ModelResponse(
                tool_calls=[ToolCall(tool_call_id=name, name=name, arguments={})],
                memory_update=dict(EMPTY_NOTES),
            )
        return ModelResponse(report=REPORT)


class NoNotesModel:
    """Calls a capability every turn and never supplies acceptable notes:
    `notes=None` omits them, a dict sends it as-is (malformed)."""

    def __init__(self, name, notes=None):
        self.name = name
        self.notes = notes
        self.turns = 0

    def generate(self, context, tools, force=None):
        if force == "record_memory":
            return ModelResponse()  # declines the forced notes call; the script is not consumed
        self.turns += 1
        # Fresh arguments each turn, so the harness never refuses it as a rerun.
        call = ToolCall(tool_call_id=str(self.turns), name=self.name, arguments={"offset": self.turns})
        return ModelResponse(tool_calls=[call], memory_update=self.notes)


class PagedImports:
    """Serves list_imports pages the way the server does, recording each call."""

    def __init__(self, count, fail_from=None, raise_from=None, imports=None):
        self.imports = imports if imports is not None else [
            {"dll": "KERNEL32.dll", "name": f"Fn{index}", "ordinal": None, "address": 0x1000 + index}
            for index in range(count)
        ]
        self.calls = []
        self.fail_from = fail_from
        self.raise_from = raise_from

    async def invoke(self, capability, artifact_id, **parameters):
        self.calls.append({"artifact_id": artifact_id, **parameters})
        offset = int(parameters.get("offset", 0))  # the server's contract coerces "500" to 500
        if self.raise_from is not None and offset >= self.raise_from:
            raise RuntimeError("worker crashed")
        if self.fail_from is not None and offset >= self.fail_from:
            return {
                "status": "error", "data": None,
                "error": {"code": "RESOURCE_LIMIT", "message": "analysis timed out"},
                "metadata": {"artifact_id": artifact_id, "capability": capability},
            }
        selected, page = paginate(self.imports, int(parameters.get("limit", 100)), offset)
        return {
            "status": "ok", "data": {"imports": selected},
            "metadata": {"artifact_id": artifact_id, "capability": capability, "tool_version": "0.1.0", **page},
        }
