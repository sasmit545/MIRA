"""ASCII and UTF-16LE string extraction with bounded pagination."""

from __future__ import annotations

import re

from mira.core.artifact import Artifact
from mira.capabilities.static.common import paginate, read_region, result_error, result_ok

# The file is scanned in windows so a large packed sample (a 20 MB installer
# overlay) is still searched; only a file past MAX_SCAN_SIZE is refused.
MAX_SCAN_SIZE = 64 * 1024 * 1024
WINDOW = 2 * 1024 * 1024
OVERLAP = 64 * 1024


def extract_strings(
    artifact: Artifact,
    *,
    min_length: int = 4,
    limit: int = 100,
    offset: int = 0,
) -> dict:
    if not isinstance(min_length, int) or not 3 <= min_length <= 256:
        return result_error(artifact.artifact_id, "extract_strings", "INVALID_INPUT", "min_length must be between 3 and 256")
    if artifact.size > MAX_SCAN_SIZE:
        return result_error(artifact.artifact_id, "extract_strings", "RESOURCE_LIMIT", "artifact exceeds the string-analysis size limit")
    try:
        ascii_pattern = re.compile(rb"[\x20-\x7e]{" + str(min_length).encode() + rb",}")
        unicode_pattern = re.compile(rb"(?:[\x20-\x7e]\x00){" + str(min_length).encode() + rb",}")
        strings = []
        # Each read carries OVERLAP bytes either side of its [start, end) block
        # and keeps only matches that begin inside the block, so a string that
        # spans a boundary is found exactly once.
        # ponytail: a string longer than OVERLAP is cut at the window edge.
        for start in range(0, artifact.size, WINDOW):
            end = min(start + WINDOW, artifact.size)
            base = max(start - OVERLAP, 0)
            data = read_region(artifact, base, min(end + OVERLAP, artifact.size) - base)
            for pattern, encoding in ((ascii_pattern, "ascii"), (unicode_pattern, "utf-16le")):
                for match in pattern.finditer(data):
                    if start <= base + match.start() < end:
                        strings.append(
                            {
                                "value": match.group().decode("ascii" if encoding == "ascii" else "utf-16le"),
                                "offset": base + match.start(),
                                "encoding": encoding,
                            }
                        )
        strings.sort(key=lambda item: item["offset"])
        selected, page = paginate(strings, limit, offset)
    except ValueError as error:
        return result_error(artifact.artifact_id, "extract_strings", "INVALID_INPUT", str(error))
    return result_ok(artifact, "extract_strings", {"strings": selected}, **page)
