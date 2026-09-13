"""
Test contract models.
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from mira.contracts.common import Contract
from mira.contracts.errors import CapabilityError, ARTIFACT_NOT_FOUND
from mira.contracts.requests import CapabilityRequest
from mira.contracts.results import CapabilityResult
from mira.contracts.capabilities.static.analyze_pe import (
    AnalyzePEInput,
    AnalyzePEOutput,
    CoffHeader,
    OptionalHeader,
    Section,
)


def test_contract_base():
    """Test base contract model."""
    class TestContract(Contract):
        name: str

    # Valid
    ct = TestContract(name="test")
    assert ct.name == "test"
    assert ct.contract_version == "1.0"

    # Extra fields forbidden
    with pytest.raises(ValidationError):
        TestContract(name="test", extra=1)


def test_analyze_pe_models():
    """Test AnalyzePE input and output models."""
    # Input
    inp = AnalyzePEInput(artifact_id="artifact_001")
    assert inp.artifact_id == "artifact_001"

    # Output
    sec = Section(
        name=".text",
        virtual_address=0x1000,
        virtual_size=0x200,
        raw_size=0x200,
        characteristics=0x60000020,
        entropy=6.1,
    )
    out = AnalyzePEOutput(
        architecture="x64",
        coff_header=CoffHeader(machine=0x8664, characteristics=0x22),
        optional_header=OptionalHeader(
            magic=0x20B, image_base=0x140000000, subsystem=3, dll_characteristics=0x8160
        ),
        entry_point=0x2000,
        sections=[sec],
        overlay_size=0,
    )
    assert out.architecture == "x64"
    assert len(out.sections) == 1
    assert out.sections[0].name == ".text"


def test_capability_request():
    """Test generic request model."""
    req = CapabilityRequest[AnalyzePEInput](
        request_id="req_001",
        capability="analyze_pe",
        input=AnalyzePEInput(artifact_id="artifact_001"),
    )
    assert req.request_id == "req_001"
    assert req.capability == "analyze_pe"
    assert req.input.artifact_id == "artifact_001"

    # Input must be a dict (validator)
    with pytest.raises(ValidationError):
        CapabilityRequest[AnalyzePEInput](
            request_id="req_001",
            capability="analyze_pe",
            input="not a dict",  # type: ignore
        )


def test_capability_result():
    """Test generic result model."""
    # Success
    sec = Section(
        name=".text",
        virtual_address=0x1000,
        virtual_size=0x200,
        raw_size=0x200,
        characteristics=0x60000020,
        entropy=6.1,
    )
    out = AnalyzePEOutput(
        architecture="x64",
        coff_header=CoffHeader(machine=0x8664, characteristics=0x22),
        optional_header=OptionalHeader(
            magic=0x20B, image_base=0x140000000, subsystem=3, dll_characteristics=0x8160
        ),
        entry_point=0x2000,
        sections=[sec],
        overlay_size=0,
    )
    res = CapabilityResult[AnalyzePEOutput](
        request_id="req_001",
        status="ok",
        data=out,
    )
    assert res.request_id == "req_001"
    assert res.status == "ok"
    assert res.data is not None
    assert res.data.architecture == "x64"

    # Error
    err = CapabilityError(
        code=ARTIFACT_NOT_FOUND,
        message="Artifact not found",
        details={"artifact_id": "artifact_001"},
    )
    res_err = CapabilityResult[AnalyzePEOutput](
        request_id="req_001",
        status="error",
        error=err,
    )
    assert res_err.status == "error"
    assert res_err.error is not None
    assert res_err.error.code == ARTIFACT_NOT_FOUND

    # Invalid status
    with pytest.raises(ValidationError):
        CapabilityResult[AnalyzePEOutput](
            request_id="req_001",
            status="invalid_status",
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
