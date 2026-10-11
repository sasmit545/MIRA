"""The model can only pass an argument it was told about.

Capabilities with required parameters were unreachable while declarations()
advertised every tool as taking none.
"""

from mira.agents.static.wiring import tool_manifest
from mira.reasoning.contracts.finding import Confidence, Severity
from mira.reasoning.model.adapter import declarations, tool_parameters
from mira.mcp.servers.static.capabilities import STATIC_CAPABILITIES


def declared_by_name():
    return {tool["function"]["name"]: tool["function"] for tool in declarations(tool_manifest())}


def test_required_parameters_reach_the_model():
    """disassemble_function is unusable without function_address."""
    declared = declared_by_name()["disassemble_function"]["parameters"]

    assert "function_address" in declared["properties"]
    assert declared["required"] == ["function_address"]


def test_runtime_bound_fields_are_never_offered():
    """artifact_id is bound by the runtime; the model must not supply it."""
    for name, tool in declared_by_name().items():
        properties = tool["parameters"]["properties"]
        assert "artifact_id" not in properties, name
        assert "contract_version" not in properties, name
        assert "artifact_id" not in tool["parameters"].get("required", []), name


def test_optional_fields_are_flattened():
    """Optional[int] becomes anyOf, which the provider cannot express."""
    offset = declared_by_name()["calculate_entropy"]["parameters"]["properties"]["offset"]

    assert offset["type"] == "integer"
    assert "anyOf" not in offset


def test_every_declaration_is_a_json_schema_object():
    for name, tool in declared_by_name().items():
        parameters = tool["parameters"]
        assert set(parameters) <= {"type", "properties", "required"}, name
        assert parameters["type"] == "object", name


def test_every_capability_is_declared():
    assert set(declared_by_name()) == set(STATIC_CAPABILITIES) | {"submit_report", "record_memory", "recall_observation"}


def test_a_collected_capability_hides_limit_and_keeps_offset():
    from mira.agents.static.wiring import COLLECTED_CAPABILITIES

    declared = declared_by_name()

    for name in COLLECTED_CAPABILITIES:
        properties = declared[name]["parameters"]["properties"]
        assert "limit" not in properties and "offset" in properties, name
        assert "whole list" in declared[name]["description"], name
    assert "function_address" in declared["disassemble_function"]["parameters"]["required"]


def test_the_recall_declaration_instructions_and_select_agree_on_argument_names():
    from mira.reasoning.definition.instructions import assemble_instructions
    from mira.reasoning.runtime.payload import RECALL_ARGUMENTS

    declared = declared_by_name()["recall_observation"]["parameters"]["properties"]

    assert set(declared) == set(RECALL_ARGUMENTS)
    assert "start" not in declared and "count" not in declared
    instructions = assemble_instructions("role", "objective", "scope", [], "")
    assert all(name in instructions for name in ("offset", "limit", "where", "group_by", "fields", "contains"))


def test_a_capability_with_no_arguments_still_declares_an_object():
    assert tool_parameters({}) == {"type": "object", "properties": {}}


def report_schema():
    return declared_by_name()["submit_report"]["parameters"]


def test_severity_and_confidence_are_declared_as_constrained_values():
    """Free-form strings meant the model was never asked for a value the
    contract could type."""
    finding = report_schema()["properties"]["findings"]["items"]["properties"]

    assert finding["severity"]["enum"] == [member.value for member in Severity]
    assert finding["confidence"]["enum"] == [member.value for member in Confidence]


def test_the_model_is_asked_for_every_field_a_finding_needs():
    findings = report_schema()["properties"]["findings"]

    assert set(findings["items"]["required"]) == {
        "title",
        "description",
        "severity",
        "confidence",
        "evidence_refs",
    }
    assert "findings" in report_schema()["required"]


def test_the_model_is_asked_for_recommended_actions():
    assert "recommended_actions" in report_schema()["properties"]


def test_harness_tools_are_declared_even_when_the_objective_permits_one_capability():
    only = [spec for spec in tool_manifest() if spec.name == "file_info"]
    names = {tool["function"]["name"] for tool in declarations(only)}

    assert names == {"file_info", "record_memory", "recall_observation", "submit_report"}


def test_record_memory_bounds_confidence_and_constrains_status():
    hypothesis = declared_by_name()["record_memory"]["parameters"]["properties"]["hypotheses"]["items"]["properties"]

    assert hypothesis["confidence"] == {"type": "number", "minimum": 0, "maximum": 1}
    assert hypothesis["status"]["enum"] == ["open", "supported", "weakened"]


def test_the_report_offers_only_the_verdicts_the_gate_accepts():
    from mira.reasoning.contracts.output import VERDICTS

    verdict = declared_by_name()["submit_report"]["parameters"]["properties"]["verdict"]

    assert verdict["enum"] == list(VERDICTS)
    assert "suspicious" not in verdict["description"]
