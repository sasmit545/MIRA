"""Bounded entropy calculations for whole artifacts and byte regions."""

from mira.core.artifact import Artifact
from math import log2

from mira.capabilities.static.common import read_region, result_error, result_ok, shannon_entropy


def calculate_entropy(artifact: Artifact, *, offset: int | None = None, length: int | None = None, chunk_size: int | None = None) -> dict:
    if (offset is None) != (length is None):
        return result_error(artifact.artifact_id, "calculate_entropy", "INVALID_INPUT", "offset and length must be supplied together")
    if chunk_size is not None and offset is None:
        return result_error(artifact.artifact_id, "calculate_entropy", "INVALID_INPUT", "chunk_size requires offset and length")
    if chunk_size is not None and chunk_size < 1:
        return result_error(artifact.artifact_id, "calculate_entropy", "INVALID_INPUT", "chunk_size must be positive")
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
            result = {"entropy": entropy, "offset": 0, "length": artifact.size}
        else:
            data = read_region(artifact, offset, length)
            result = {"entropy": shannon_entropy(data), "offset": offset, "length": len(data)}
            if chunk_size is not None:
                chunks = []
                for start in range(0, len(data), chunk_size):
                    piece = data[start : start + chunk_size]
                    chunks.append({"offset": offset + start, "length": len(piece), "entropy": shannon_entropy(piece)})
                result["chunks"] = chunks
    except ValueError as error:
        return result_error(artifact.artifact_id, "calculate_entropy", "INVALID_INPUT", str(error))
    return result_ok(artifact, "calculate_entropy", result)
