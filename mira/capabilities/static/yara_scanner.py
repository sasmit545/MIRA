"""YARA scanning against configured rule sets only."""

import difflib
from pathlib import Path

from mira.core.artifact import Artifact
from mira.capabilities.static.common import is_pe, paginate, result_error, result_ok


def _ruleset_hint(asked: str, names: list[str]) -> str:
    """Enough for a caller to pick a real name. Hundreds may be configured,
    so name the closest ones, or the prefix families and a few examples."""
    if not names:
        return "no rulesets are configured"
    close = difflib.get_close_matches(asked, names, n=5, cutoff=0.5)
    if close:
        return f"closest configured: {', '.join(close)}"
    families = sorted({name.split("_", 1)[0] for name in names})
    return (
        f"{len(names)} are configured, named after their rule files by family "
        f"({', '.join(families[:15])}), e.g. {', '.join(sorted(names)[:5])}"
    )


def scan_yara(artifact: Artifact, *, ruleset: str, limit: int = 100, offset: int = 0, rulesets: dict[str, Path] | None = None) -> dict:
    configured_rulesets = rulesets or {}
    rules_path = configured_rulesets.get(ruleset)
    if rules_path is None:
        return result_error(
            artifact.artifact_id, "scan_yara", "INVALID_INPUT",
            f"ruleset {ruleset!r} is not configured; {_ruleset_hint(ruleset, list(configured_rulesets))}",
        )
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
