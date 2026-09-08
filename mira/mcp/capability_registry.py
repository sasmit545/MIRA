"""Declarative metadata for static MCP capabilities."""

from __future__ import annotations

from dataclasses import dataclass

from mira.contracts.capabilities.analyze_pe import AnalyzePEInput, AnalyzePEOutput
from mira.contracts.capabilities.calculate_entropy import CalculateEntropyInput, CalculateEntropyOutput
from mira.contracts.capabilities.capa import RunCapaInput, RunCapaOutput
from mira.contracts.capabilities.disassembly import DisassembleFunctionInput, DisassembleFunctionOutput
from mira.contracts.capabilities.exports import ListExportsInput, ListExportsOutput
from mira.contracts.capabilities.file_info import FileInfoInput, FileInfoOutput
from mira.contracts.capabilities.functions import ListFunctionsInput, ListFunctionsOutput
from mira.contracts.capabilities.imports import ListImportsInput, ListImportsOutput
from mira.contracts.capabilities.packer import DetectPackerInput, DetectPackerOutput
from mira.contracts.capabilities.scan_yara import ScanYaraInput, ScanYaraOutput
from mira.contracts.capabilities.strings import ExtractStringsInput, ExtractStringsOutput
from pydantic import BaseModel


@dataclass(frozen=True)
class CapabilityDefinition:
    name: str
    description: str
    category: str
    supported_artifact_types: tuple[str, ...]
    input_model: type[BaseModel]
    output_model: type[BaseModel]

    @property
    def input_schema(self) -> dict:
        return self.input_model.model_json_schema()

    @property
    def output_schema(self) -> dict:
        return self.output_model.model_json_schema()


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
