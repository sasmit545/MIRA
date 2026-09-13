"""What the static server exposes, and what runs each capability.

Both registries live here on purpose. They were previously split across
mira/mcp/capability_registry.py and a hardcoded handler map inside
mira/mcp/isolation.py, so adding a capability meant two edits in two generic
modules with nothing detecting drift between them.

A dynamic or forensics server adds a sibling module shaped like this one; it
does not edit anything here.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from mira.contracts.capabilities.static.analyze_pe import AnalyzePEInput, AnalyzePEOutput
from mira.contracts.capabilities.static.entropy import CalculateEntropyInput, CalculateEntropyOutput
from mira.contracts.capabilities.static.capa import RunCapaInput, RunCapaOutput
from mira.contracts.capabilities.static.disassembly import DisassembleFunctionInput, DisassembleFunctionOutput
from mira.contracts.capabilities.static.exports import ListExportsInput, ListExportsOutput
from mira.contracts.capabilities.static.file_info import FileInfoInput, FileInfoOutput
from mira.contracts.capabilities.static.functions import ListFunctionsInput, ListFunctionsOutput
from mira.contracts.capabilities.static.list_imports import ListImportsInput, ListImportsOutput
from mira.contracts.capabilities.static.packer import DetectPackerInput, DetectPackerOutput
from mira.contracts.capabilities.static.scan_yara import ScanYaraInput, ScanYaraOutput
from mira.contracts.capabilities.static.strings import ExtractStringsInput, ExtractStringsOutput
from mira.mcp.capability_registry import CapabilityDefinition

#: Dotted path the isolated worker imports to reach `invoke` below.
DISPATCH = __name__

STATIC_CAPABILITIES = {
    definition.name: definition
    for definition in (
        CapabilityDefinition(
            name="file_info",
            description="Identify hashes, file type, and whole-file entropy.",
            category="triage",
            supported_artifact_types=("pe", "unknown"),
            input_model=FileInfoInput,
            output_model=FileInfoOutput,
        ),
        CapabilityDefinition(
            name="analyze_pe",
            description="Inspect PE headers and sections.",
            category="structure",
            supported_artifact_types=("pe",),
            input_model=AnalyzePEInput,
            output_model=AnalyzePEOutput,
        ),
        CapabilityDefinition(
            name="list_imports",
            description="List imported DLLs and functions.",
            category="structure",
            supported_artifact_types=("pe",),
            input_model=ListImportsInput,
            output_model=ListImportsOutput,
        ),
        CapabilityDefinition(
            name="list_exports",
            description="List exported symbols.",
            category="structure",
            supported_artifact_types=("pe",),
            input_model=ListExportsInput,
            output_model=ListExportsOutput,
        ),
        CapabilityDefinition(
            name="extract_strings",
            description="Extract ASCII and UTF-16LE strings.",
            category="content",
            supported_artifact_types=("pe", "unknown"),
            input_model=ExtractStringsInput,
            output_model=ExtractStringsOutput,
        ),
        CapabilityDefinition(
            name="calculate_entropy",
            description="Calculate whole-file or bounded-region entropy.",
            category="triage",
            supported_artifact_types=("pe", "unknown"),
            input_model=CalculateEntropyInput,
            output_model=CalculateEntropyOutput,
        ),
        CapabilityDefinition(
            name="detect_packer",
            description="Report packing/protection indicators.",
            category="triage",
            supported_artifact_types=("pe",),
            input_model=DetectPackerInput,
            output_model=DetectPackerOutput,
        ),
        CapabilityDefinition(
            name="scan_yara",
            description="Run a configured YARA rule set.",
            category="detection",
            supported_artifact_types=("pe", "unknown"),
            input_model=ScanYaraInput,
            output_model=ScanYaraOutput,
        ),
        CapabilityDefinition(
            name="run_capa",
            description="Detect CAPA capabilities.",
            category="detection",
            supported_artifact_types=("pe",),
            input_model=RunCapaInput,
            output_model=RunCapaOutput,
        ),
        CapabilityDefinition(
            name="list_functions",
            description="List heuristically discovered functions.",
            category="code",
            supported_artifact_types=("pe",),
            input_model=ListFunctionsInput,
            output_model=ListFunctionsOutput,
        ),
        CapabilityDefinition(
            name="disassemble_function",
            description="Disassemble one selected function.",
            category="code",
            supported_artifact_types=("pe",),
            input_model=DisassembleFunctionInput,
            output_model=DisassembleFunctionOutput,
        ),
    )
}


def invoke(job: Any) -> dict:
    """Run one static capability. Called inside the isolated worker process.

    The handler imports stay inside this function so the parent process never
    loads pefile, capstone, or yara just to describe what it can do.
    """
    from mira.capabilities.static.capa_analyzer import run_capa
    from mira.capabilities.static.disassembler import disassemble_function
    from mira.capabilities.static.entropy_analyzer import calculate_entropy
    from mira.capabilities.static.export_lister import list_exports
    from mira.capabilities.static.file_info import analyze_file_info
    from mira.capabilities.static.function_analyzer import list_functions
    from mira.capabilities.static.import_lister import list_imports
    from mira.capabilities.static.packer_detector import detect_packer
    from mira.capabilities.static.pe_analyzer import analyze_pe
    from mira.capabilities.static.string_analyzer import extract_strings
    from mira.capabilities.static.yara_scanner import scan_yara

    handlers = {
        "file_info": analyze_file_info,
        "analyze_pe": analyze_pe,
        "list_imports": list_imports,
        "list_exports": list_exports,
        "extract_strings": extract_strings,
        "calculate_entropy": calculate_entropy,
        "detect_packer": detect_packer,
        "scan_yara": scan_yara,
        "run_capa": run_capa,
        "list_functions": list_functions,
        "disassemble_function": disassemble_function,
    }
    if job.capability == "scan_yara":
        return handlers[job.capability](job.artifact, rulesets=job.rulesets, **job.parameters)
    return handlers[job.capability](job.artifact, **job.parameters)
