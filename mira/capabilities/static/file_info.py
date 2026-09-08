"""Basic deterministic artifact triage."""

from __future__ import annotations

import hashlib

from mira.artifacts import Artifact
from mira.capabilities.static.common import result_ok, shannon_entropy


def analyze_file_info(artifact: Artifact) -> dict:
    digests = {"md5": hashlib.md5(), "sha1": hashlib.sha1(), "sha256": hashlib.sha256()}
    byte_counts = [0] * 256
    with artifact.path.open("rb") as artifact_file:
        for chunk in iter(lambda: artifact_file.read(1024 * 1024), b""):
            for digest in digests.values():
                digest.update(chunk)
            for value in chunk:
                byte_counts[value] += 1

    entropy = 0.0
    if artifact.size:
        from math import log2

        entropy = -sum(
            (count / artifact.size) * log2(count / artifact.size)
            for count in byte_counts
            if count
        )
    return result_ok(
        artifact,
        "file_info",
        {
            "file_type": artifact.file_type,
            "size": artifact.size,
            "md5": digests["md5"].hexdigest(),
            "sha1": digests["sha1"].hexdigest(),
            "sha256": digests["sha256"].hexdigest(),
            "entropy": entropy,
        },
    )
