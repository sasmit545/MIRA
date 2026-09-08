"""Bounded entropy calculations for whole artifacts and byte regions."""

from mira.artifacts import Artifact
from math import log2

from mira.capabilities.static.common import read_region, result_error, result_ok, shannon_entropy


def calculate_entropy(artifact: Artifact, *, offset: int | None = None, length: int | None = None) -> dict:
    if (offset is None) != (length is None):
        return result_error(artifact.artifact_id, "calculate_entropy", "INVALID_INPUT", "offset and length must be supplied together")
    try:
        if offset is None:
            counts = [0] * 256
            with artifact.path.open("rb") as artifact_file:
                for chunk in iter(lambda: artifact_file.read(1024 * 1024), b""):
                    for value in chunk:
                        counts[value] += 1
            entropy = -sum(
                (count / artifact.size) * log2(count / artifact.size)
                for count in counts
                if count
            ) if artifact.size else 0.0
            result_length = artifact.size
        else:
            data = read_region(artifact, offset, length)
            entropy = shannon_entropy(data)
            result_length = len(data)
    except ValueError as error:
        return result_error(artifact.artifact_id, "calculate_entropy", "INVALID_INPUT", str(error))
    return result_ok(artifact, "calculate_entropy", {"entropy": entropy, "offset": offset or 0, "length": result_length})
