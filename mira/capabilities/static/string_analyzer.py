"""ASCII and UTF-16LE string extraction with bounded pagination."""

from __future__ import annotations

import re

from mira.core.artifact import Artifact
from mira.capabilities.static.common import MAX_REGION_SIZE, paginate, read_region, result_error, result_ok


def extract_strings(
    artifact: Artifact,
    *,
    minimum_length: int = 4,
    limit: int = 100,
    offset: int = 0,
) -> dict:
    if not isinstance(minimum_length, int) or not 3 <= minimum_length <= 256:
        return result_error(artifact.artifact_id, "extract_strings", "INVALID_INPUT", "minimum_length must be between 3 and 256")
    if artifact.size > MAX_REGION_SIZE:
        return result_error(artifact.artifact_id, "extract_strings", "RESOURCE_LIMIT", "artifact exceeds the string-analysis size limit")
    try:
        data = read_region(artifact, 0, artifact.size)
        pattern = re.compile(rb"[\x20-\x7e]{" + str(minimum_length).encode() + rb",}")
        strings = [
            {"value": match.group().decode("ascii"), "offset": match.start(), "encoding": "ascii"}
            for match in pattern.finditer(data)
        ]
        unicode_pattern = re.compile(rb"(?:[\x20-\x7e]\x00){" + str(minimum_length).encode() + rb",}")
        strings.extend(
            {
                "value": match.group().decode("utf-16le"),
                "offset": match.start(),
                "encoding": "utf-16le",
            }
            for match in unicode_pattern.finditer(data)
        )
        strings.sort(key=lambda item: item["offset"])
        selected, page = paginate(strings, limit, offset)
    except ValueError as error:
        return result_error(artifact.artifact_id, "extract_strings", "INVALID_INPUT", str(error))
    return result_ok(artifact, "extract_strings", {"strings": selected}, **page)
