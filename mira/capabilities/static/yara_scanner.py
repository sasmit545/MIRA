"""YARA scanning against configured rule sets only."""

from pathlib import Path

from mira.core.artifact import Artifact
from mira.capabilities.static.common import is_pe, paginate, result_error, result_ok


def scan_yara(artifact: Artifact, *, ruleset: str, limit: int = 100, offset: int = 0, rulesets: dict[str, Path] | None = None) -> dict:
    configured_rulesets = rulesets or {}
    rules_path = configured_rulesets.get(ruleset)
    if rules_path is None:
        return result_error(artifact.artifact_id, "scan_yara", "INVALID_INPUT", "ruleset is not configured")
    try:
        import yara
    except ImportError:
        return result_error(artifact.artifact_id, "scan_yara", "TOOL_NOT_AVAILABLE", "yara-python is not installed")
    try:
        compiled = yara.compile(filepath=str(rules_path), externals=_standard_externals(artifact))
        matches = compiled.match(str(artifact.path))
    except yara.Error as error:
        return result_error(artifact.artifact_id, "scan_yara", "ANALYSIS_FAILED", str(error))
    results = [{"rule": match.rule, "namespace": match.namespace, "tags": match.tags} for match in matches]
    try:
        selected, page = paginate(results, limit, offset)
    except ValueError as error:
        return result_error(artifact.artifact_id, "scan_yara", "INVALID_INPUT", str(error))
    return result_ok(artifact, "scan_yara", {"matches": selected}, ruleset=ruleset, **page)


def _standard_externals(artifact: Artifact) -> dict[str, str]:
    """External variables the LOKI/THOR convention expects (signature-base and
    similar public rule sets use them freely) - undeclared, they fail
    compilation outright rather than just not matching.

    filename/filepath/extension/imphash are real facts about the artifact.
    filetype/owner have no reliable equivalent in a sandboxed static analysis
    context (no live filesystem ACLs, no THOR-taxonomy file classifier), so
    they're best-effort placeholders: rules gated on them just won't match,
    same as an artifact that genuinely doesn't meet the condition.
    """
    path = artifact.path
    externals = {
        "filename": path.name,
        "filepath": str(path),
        "extension": path.suffix,
        "filetype": "",
        "owner": "",
        "imphash": "",
    }
    if not is_pe(artifact):
        return externals
    externals["filetype"] = "EXE"
    try:
        import pefile
    except ImportError:
        return externals
    try:
        externals["imphash"] = pefile.PE(data=path.read_bytes(), fast_load=False).get_imphash() or ""
    except (OSError, pefile.PEFormatError):
        pass
    return externals
