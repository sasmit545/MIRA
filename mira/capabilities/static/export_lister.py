"""Bounded PE export-table listing."""

from mira.artifacts import Artifact
from mira.capabilities.static.common import paginate, result_error, result_ok
from mira.capabilities.static.pe_support import load_pe


def list_exports(artifact: Artifact, *, limit: int = 100, offset: int = 0) -> dict:
    pe, failure = load_pe(artifact, "list_exports")
    if failure:
        return failure
    exports = [
        {"name": symbol.name.decode("ascii", errors="replace") if symbol.name else None, "ordinal": symbol.ordinal, "address": symbol.address}
        for symbol in getattr(pe, "DIRECTORY_ENTRY_EXPORT", type("Empty", (), {"symbols": []})()).symbols
    ]
    try:
        selected, page = paginate(exports, limit, offset)
    except ValueError as error:
        return result_error(artifact.artifact_id, "list_exports", "INVALID_INPUT", str(error))
    return result_ok(artifact, "list_exports", {"exports": selected}, **page)
