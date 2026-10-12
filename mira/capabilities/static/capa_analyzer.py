"""CAPA integration: behavioral capability detection against a configured rule set.

Mirrors yara_scanner's shape - TOOL_NOT_AVAILABLE when nothing is configured,
a real scan once it is. Unlike yara's named rulesets, capa takes one rule
directory (capa-rules is a tree, not a single file).
"""

from __future__ import annotations

import gc
import re
from pathlib import Path

from mira.core.artifact import Artifact
from mira.capabilities.static.common import paginate, result_error, result_ok
from mira.capabilities.static.pe_support import load_pe

MAX_ADDRESSES = 20  # per detail; a finding's `matches` keeps the full count
MAX_MATCHED = 10  # matched features per detail, across all its locations
MAX_MATCHED_CHARS = 160
_ID = re.compile(r"\[([^\]]+)\]\s*$")


def run_capa(artifact: Artifact, *, limit: int = 100, offset: int = 0, rules_dir: Path | None = None) -> dict:
    _, failure = load_pe(artifact, "run_capa")
    if failure:
        return failure
    if rules_dir is None or not rules_dir.is_dir():
        return result_error(artifact.artifact_id, "run_capa", "TOOL_NOT_AVAILABLE", "CAPA integration requires a configured rules directory")
    try:
        import capa.exceptions
        import capa.loader
        import capa.rules
        from capa.capabilities.common import find_capabilities
    except ImportError:
        return result_error(artifact.artifact_id, "run_capa", "TOOL_NOT_AVAILABLE", "flare-capa is not installed")

    try:
        ruleset = capa.rules.get_rules([rules_dir], enable_cache=False)
    except (OSError, capa.rules.InvalidRule, capa.rules.InvalidRuleSet) as error:
        return result_error(artifact.artifact_id, "run_capa", "INVALID_INPUT", f"configured rules directory is invalid: {error}")

    try:
        # OS is hardcoded: run_capa only declares PE support (see
        # STATIC_CAPABILITIES), and every PE capa analyzes here is Windows.
        extractor = capa.loader.get_extractor(artifact.path, "pe", "windows", "vivisect", [], disable_progress=True)
        capabilities = find_capabilities(ruleset, extractor, disable_progress=True)
    except (
        capa.exceptions.UnsupportedFormatError,
        capa.exceptions.UnsupportedArchError,
        capa.exceptions.UnsupportedOSError,
        capa.loader.CorruptFile,
    ) as error:
        return result_error(artifact.artifact_id, "run_capa", "UNSUPPORTED_FILE_TYPE", str(error), unsupported=True)

    # Subscope rules are match-only building blocks for other rules, the way
    # capa's own CLI report excludes them too. Sorted, so a page is stable.
    names = sorted(name for name in capabilities.matches if not ruleset.rules[name].is_subscope_rule())
    findings, details = [], []
    for name in names:
        meta = ruleset.rules[name].meta
        attack, mbc = [str(entry) for entry in meta.get("att&ck", [])], [str(entry) for entry in meta.get("mbc", [])]
        # The raw meta block (authors, examples, rule path) was most of every
        # item: a live model paged 35 findings ten at a time to read it.
        findings.append({"rule_id": name, "namespace": meta.get("namespace", ""), "attack": _ids(attack), "mbc": _ids(mbc),
                         "matches": len(capabilities.matches[name])})
        addresses = sorted(int(address) for address, _ in capabilities.matches[name] if isinstance(address, int))
        details.append({"rule_id": name, "description": str(meta.get("description", "")), "scopes": dict(meta.get("scopes") or {}),
                        "attack": attack, "mbc": mbc, "references": [str(ref) for ref in meta.get("references", [])],
                        "addresses": [hex(address) for address in addresses[:MAX_ADDRESSES]],
                        "matched": _matched(result for _, result in capabilities.matches[name])})

    # vivisect's PE parser (vivisect/parsers/pe.py) opens the sample with a
    # plain open() and never closes it - not our code or even capa's, so
    # there's nothing to pass data= into like pe_support.load_pe does.
    # Dropping the last references and forcing a collection reliably closes
    # it (verified: a rename that fails while `extractor` is alive succeeds
    # right after this). Without it the sample stays locked on Windows until
    # something else frees the objects.
    del extractor, capabilities
    gc.collect()

    try:
        selected, page = paginate(findings, limit, offset)
    except ValueError as error:
        return result_error(artifact.artifact_id, "run_capa", "INVALID_INPUT", str(error))
    return result_ok(artifact, "run_capa", {"findings": selected, "details": details[offset : offset + len(selected)]}, **page)


def _matched(results) -> list[str]:
    """The features that made a rule match, such as `api(CreateProcess)` or a
    regex with the string it matched. A live model asked three times which
    strings an anti-VM rule saw; the answer (`Xen7`, from compressed data)
    was in capa's match tree and nowhere in the result."""
    seen: list[str] = []

    def walk(result) -> None:
        if not result.success or len(seen) >= MAX_MATCHED:
            return
        children = [child for child in result.children if child.success]
        if children:
            for child in children:
                walk(child)
            return
        text = str(result.statement)[:MAX_MATCHED_CHARS]
        if text not in seen:
            seen.append(text)

    for result in results:
        walk(result)
    return seen[:MAX_MATCHED]


def _ids(entries: list[str]) -> list[str]:
    """'Defense Evasion::Impair Defenses [T1562.001]' -> 'T1562.001'."""
    return [match.group(1) if (match := _ID.search(entry)) else entry for entry in entries]
