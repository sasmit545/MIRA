"""Declarative metadata for static MCP capabilities."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CapabilityDefinition:
    name: str
    description: str
    category: str
    supported_artifact_types: tuple[str, ...]
    input_schema: dict


STATIC_CAPABILITIES = {
    definition.name: definition
    for definition in (
        CapabilityDefinition("file_info", "Identify hashes, file type, and whole-file entropy.", "triage", ("pe", "unknown"), {"artifact_id": "string"}),
        CapabilityDefinition("analyze_pe", "Inspect PE headers and sections.", "structure", ("pe",), {"artifact_id": "string"}),
        CapabilityDefinition("list_imports", "List imported DLLs and functions.", "structure", ("pe",), {"artifact_id": "string", "limit": "integer", "offset": "integer"}),
        CapabilityDefinition("list_exports", "List exported symbols.", "structure", ("pe",), {"artifact_id": "string", "limit": "integer", "offset": "integer"}),
        CapabilityDefinition("extract_strings", "Extract ASCII and UTF-16LE strings.", "content", ("pe", "unknown"), {"artifact_id": "string", "minimum_length": "integer", "limit": "integer", "offset": "integer"}),
        CapabilityDefinition("calculate_entropy", "Calculate whole-file or bounded-region entropy.", "triage", ("pe", "unknown"), {"artifact_id": "string", "offset": "integer", "length": "integer"}),
        CapabilityDefinition("detect_packer", "Report packing/protection indicators.", "triage", ("pe",), {"artifact_id": "string"}),
        CapabilityDefinition("scan_yara", "Run a configured YARA rule set.", "detection", ("pe", "unknown"), {"artifact_id": "string", "ruleset": "string"}),
        CapabilityDefinition("run_capa", "Detect CAPA capabilities.", "detection", ("pe",), {"artifact_id": "string"}),
        CapabilityDefinition("list_functions", "List heuristically discovered functions.", "code", ("pe",), {"artifact_id": "string", "limit": "integer", "offset": "integer"}),
        CapabilityDefinition("disassemble_function", "Disassemble one selected function.", "code", ("pe",), {"artifact_id": "string", "function_address": "integer|string", "limit": "integer"}),
    )
}
