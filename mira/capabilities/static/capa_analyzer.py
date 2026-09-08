"""Optional CAPA integration with explicit dependency failures."""

from mira.artifacts import Artifact
from mira.capabilities.static.common import result_error


def run_capa(artifact: Artifact) -> dict:
    return result_error(artifact.artifact_id, "run_capa", "TOOL_NOT_AVAILABLE", "CAPA integration requires a configured flare-capa runtime")
