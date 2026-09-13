"""Bounded PE import-table listing."""

from mira.core.artifact import Artifact
from mira.capabilities.static.common import paginate, result_ok
from mira.capabilities.static.pe_support import load_pe


def list_imports(artifact: Artifact, *, limit: int = 100, offset: int = 0) -> dict:
    pe, failure = load_pe(artifact, "list_imports")
    if failure:
        return failure
    imports = []
    for descriptor in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        dll = descriptor.dll.decode("ascii", errors="replace")
        for entry in descriptor.imports:
            imports.append({"dll": dll, "name": entry.name.decode("ascii", errors="replace") if entry.name else None, "ordinal": entry.ordinal, "address": entry.address})
    try:
        selected, page = paginate(imports, limit, offset)
    except ValueError as error:
        from mira.capabilities.static.common import result_error

        return result_error(artifact.artifact_id, "list_imports", "INVALID_INPUT", str(error))
    return result_ok(artifact, "list_imports", {"imports": selected}, **page)
