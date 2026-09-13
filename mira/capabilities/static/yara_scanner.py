"""YARA scanning against configured rule sets only."""

from pathlib import Path

from mira.core.artifact import Artifact
from mira.capabilities.static.common import result_error, result_ok


def scan_yara(artifact: Artifact, *, ruleset: str, rulesets: dict[str, Path] | None = None) -> dict:
    configured_rulesets = rulesets or {}
    rules_path = configured_rulesets.get(ruleset)
    if rules_path is None:
        return result_error(artifact.artifact_id, "scan_yara", "INVALID_INPUT", "ruleset is not configured")
    try:
        import yara
    except ImportError:
        return result_error(artifact.artifact_id, "scan_yara", "TOOL_NOT_AVAILABLE", "yara-python is not installed")
    try:
        matches = yara.compile(filepath=str(rules_path)).match(str(artifact.path))
    except yara.Error as error:
        return result_error(artifact.artifact_id, "scan_yara", "ANALYSIS_FAILED", str(error))
    return result_ok(artifact, "scan_yara", {"matches": [{"rule": match.rule, "namespace": match.namespace, "tags": match.tags} for match in matches]}, ruleset=ruleset)
