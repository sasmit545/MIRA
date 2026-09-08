"""Optional pefile integration shared by PE-oriented capabilities."""

from __future__ import annotations

from mira.artifacts import Artifact
from mira.capabilities.static.common import is_pe, result_error


def load_pe(artifact: Artifact, capability: str):
    if not is_pe(artifact):
        return None, result_error(
            artifact.artifact_id,
            capability,
            "UNSUPPORTED_FILE_TYPE",
            "Artifact is not a valid PE file.",
            unsupported=True,
        )
    try:
        import pefile
    except ImportError:
        return None, result_error(artifact.artifact_id, capability, "TOOL_NOT_AVAILABLE", "pefile is not installed")
    try:
        return pefile.PE(str(artifact.path), fast_load=False), None
    except (OSError, pefile.PEFormatError):
        return None, result_error(
            artifact.artifact_id,
            capability,
            "UNSUPPORTED_FILE_TYPE",
            "Artifact is not a valid PE file.",
            unsupported=True,
        )
