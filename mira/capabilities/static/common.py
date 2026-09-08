"""Shared result contracts and bounded file access for static capabilities."""

from __future__ import annotations

from collections.abc import Mapping
from math import log2
from pathlib import Path
from typing import Any

from mira.artifacts import Artifact

TOOL_VERSION = "0.1.0"
DEFAULT_LIMIT = 100
MAX_LIMIT = 1_000
MAX_REGION_SIZE = 4 * 1024 * 1024


def result_ok(artifact: Artifact, capability: str, data: Mapping[str, Any], **metadata: Any) -> dict[str, Any]:
    return {
        "status": "ok",
        "data": dict(data),
        "metadata": {
            "artifact_id": artifact.artifact_id,
            "capability": capability,
            "tool_version": TOOL_VERSION,
            **metadata,
        },
    }


def result_error(
    artifact_id: str | None,
    capability: str,
    code: str,
    message: str,
    *,
    unsupported: bool = False,
    **metadata: Any,
) -> dict[str, Any]:
    return {
        "status": "unsupported" if unsupported else "error",
        "data": None,
        "error": {"code": code, "message": message},
        "metadata": {
            "artifact_id": artifact_id,
            "capability": capability,
            "tool_version": TOOL_VERSION,
            **metadata,
        },
    }


def is_pe(artifact: Artifact) -> bool:
    return artifact.file_type == "pe"


def read_region(artifact: Artifact, offset: int = 0, length: int | None = None) -> bytes:
    if offset < 0 or offset > artifact.size:
        raise ValueError("offset is outside artifact bounds")
    if length is None:
        length = artifact.size - offset
    if length <= 0 or length > MAX_REGION_SIZE or offset + length > artifact.size:
        raise ValueError("length must be positive, bounded, and within artifact bounds")
    with Path(artifact.path).open("rb") as artifact_file:
        artifact_file.seek(offset)
        return artifact_file.read(length)


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    frequencies = [data.count(value) / len(data) for value in range(256)]
    return -sum(frequency * log2(frequency) for frequency in frequencies if frequency)


def paginate(items: list[Any], limit: int = DEFAULT_LIMIT, offset: int = 0) -> tuple[list[Any], dict[str, Any]]:
    if not isinstance(limit, int) or not isinstance(offset, int) or limit < 1 or limit > MAX_LIMIT or offset < 0:
        raise ValueError(f"limit must be 1..{MAX_LIMIT} and offset must be non-negative")
    selected = items[offset : offset + limit]
    return selected, {"limit": limit, "offset": offset, "has_more": offset + len(selected) < len(items)}
