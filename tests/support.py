"""Helpers shared across the test suite."""

import struct

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


class ToolThenReportModel:
    """Calls each named tool once, then submits a report.

    Stands in for a real model choosing capabilities. It also records the
    tools it was offered each turn, which is how a test checks that the
    objective actually bounds the choice.
    """

    def __init__(self, *tool_names):
        self.pending = list(tool_names)
        self.offered = []

    def generate(self, context, tools):
        self.offered.append([spec.name for spec in tools])
        if self.pending:
            name = self.pending.pop(0)
            return ModelResponse(
                tool_calls=[ToolCall(tool_call_id=name, name=name, arguments={})]
            )
        return ModelResponse(report=REPORT)
