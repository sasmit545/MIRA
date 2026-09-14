"""Helpers shared across the test suite."""

import struct


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
