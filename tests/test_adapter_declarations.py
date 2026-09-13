"""The model can only pass an argument it was told about.

Capabilities with required parameters were unreachable while declarations()
advertised every tool as taking none.
"""

from mira.agents.static.wiring import tool_manifest
from mira.reasoning.model.adapter import declarations, tool_parameters
from mira.mcp.capability_registry import STATIC_CAPABILITIES


def declared_by_name():
    return {tool["name"]: tool for tool in declarations(tool_manifest())[0]["function_declarations"]}


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


def test_only_provider_accepted_keys_survive():
    for name, tool in declared_by_name().items():
        parameters = tool["parameters"]
        assert set(parameters) <= {"type", "properties", "required"}, name
        for field, spec in parameters["properties"].items():
            unexpected = set(spec) - {
                "type", "description", "enum", "items", "minimum", "maximum"
            }
            assert not unexpected, f"{name}.{field}: {unexpected}"


def test_every_capability_is_declared():
    assert set(declared_by_name()) == set(STATIC_CAPABILITIES) | {"submit_report"}


def test_a_capability_with_no_arguments_still_declares_an_object():
    assert tool_parameters({}) == {"type": "object", "properties": {}}
