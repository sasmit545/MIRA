"""
Test capability registry.
"""
from __future__ import annotations

from mira.mcp.capability_registry import STATIC_CAPABILITIES
from mira.contracts.capabilities.analyze_pe import AnalyzePEInput, AnalyzePEOutput


def test_capability_registry_has_expected_capabilities():
    """Test that the registry contains the expected capabilities."""
    expected = {
        "file_info",
        "analyze_pe",
        "list_imports",
        "list_exports",
        "extract_strings",
        "calculate_entropy",
        "detect_packer",
        "scan_yara",
        "run_capa",
        "list_functions",
        "disassemble_function",
    }
    assert set(STATIC_CAPABILITIES.keys()) == expected


def test_analyze_pe_capability_schema():
    """Test that the analyze_pe capability has the correct schemas."""
    cap = STATIC_CAPABILITIES["analyze_pe"]
    assert cap.name == "analyze_pe"
    assert cap.description == "Inspect PE headers and sections."
    assert cap.category == "structure"
    assert cap.supported_artifact_types == ("pe",)
    # Check that input and output models are correct
    assert cap.input_model == AnalyzePEInput
    assert cap.output_model == AnalyzePEOutput
    # Check that the JSON schemas are generated
    assert "properties" in cap.input_schema
    assert "artifact_id" in cap.input_schema["properties"]
    assert "properties" in cap.output_schema
    assert "architecture" in cap.output_schema["properties"]
