"""Optional pefile integration shared by PE-oriented capabilities."""

from __future__ import annotations

from mira.core.artifact import Artifact
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
        # data= instead of name=: pefile.PE(name=...) mmaps the file and
        # never releases it unless something calls pe.close(), which no
        # caller here does - on Windows that leaves the sample locked for
        # the life of the process. Passing the bytes directly means there's
        # no file handle or mmap to leak in the first place.
        return pefile.PE(data=artifact.path.read_bytes(), fast_load=False), None
    except (OSError, pefile.PEFormatError):
        return None, result_error(
            artifact.artifact_id,
            capability,
            "UNSUPPORTED_FILE_TYPE",
            "Artifact is not a valid PE file.",
            unsupported=True,
        )
