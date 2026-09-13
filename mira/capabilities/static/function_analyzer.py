"""Heuristic static function discovery."""

from mira.core.artifact import Artifact
from mira.capabilities.static.common import paginate, result_error, result_ok
from mira.capabilities.static.pe_support import load_pe


def list_functions(artifact: Artifact, *, limit: int = 100, offset: int = 0) -> dict:
    pe, failure = load_pe(artifact, "list_functions")
    if failure:
        return failure
    entry_point = pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.AddressOfEntryPoint
    functions = [{"address": entry_point, "size": None, "name": "entry_point", "discovery_source": "pe_entry_point"}]
    try:
        selected, page = paginate(functions, limit, offset)
    except ValueError as error:
        return result_error(artifact.artifact_id, "list_functions", "INVALID_INPUT", str(error))
    return result_ok(artifact, "list_functions", {"functions": selected, "limitations": "Only the PE entry point is discovered without an analysis engine."}, **page)
