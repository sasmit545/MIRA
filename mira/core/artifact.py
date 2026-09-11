"""Artifact storage with a file-system boundary for analysis capabilities."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from os import R_OK, access
from pathlib import Path


class ArtifactError(ValueError):
    """Raised when an artifact cannot be safely registered or resolved."""


@dataclass(frozen=True)
class Artifact:
    artifact_id: str
    path: Path
    file_type: str
    size: int
    sha256: str
    parent_artifact_id: str | None = None


class ArtifactStore:
    """Resolves artifact identifiers without exposing arbitrary file paths."""

    def __init__(self, root: str | Path, *, max_file_size: int = 64 * 1024 * 1024):
        self.root = Path(root).resolve()
        self.max_file_size = max_file_size
        self._artifacts: dict[str, Artifact] = {}

    def register(
        self,
        artifact_id: str,
        path: str | Path,
        *,
        file_type: str | None = None,
        parent_artifact_id: str | None = None,
    ) -> Artifact:
        if not artifact_id or artifact_id in self._artifacts:
            raise ArtifactError("artifact_id must be unique and non-empty")

        resolved_path = Path(path).resolve()
        try:
            resolved_path.relative_to(self.root)
        except ValueError as error:
            raise ArtifactError("artifact path is outside the managed store") from error

        if not resolved_path.is_file() or not access(resolved_path, R_OK):
            raise ArtifactError("artifact is not an accessible file")

        size = resolved_path.stat().st_size
        if size > self.max_file_size:
            raise ArtifactError("artifact exceeds the configured file-size limit")

        artifact = Artifact(
            artifact_id=artifact_id,
            path=resolved_path,
            file_type=file_type or detect_file_type(resolved_path),
            size=size,
            sha256=_hash_file(resolved_path),
            parent_artifact_id=parent_artifact_id,
        )
        self._artifacts[artifact_id] = artifact
        return artifact

    def get(self, artifact_id: str) -> Artifact:
        try:
            return self._artifacts[artifact_id]
        except KeyError as error:
            raise ArtifactError("artifact was not found") from error


def detect_file_type(path: Path) -> str:
    with path.open("rb") as artifact_file:
        header = artifact_file.read(0x40)
        if header[:2] != b"MZ" or len(header) < 0x40:
            return "unknown"
        offset = int.from_bytes(header[0x3C:0x40], "little")
        artifact_file.seek(offset)
        return "pe" if artifact_file.read(4) == b"PE\\0\\0" else "unknown"


def _hash_file(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as artifact_file:
        for chunk in iter(lambda: artifact_file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
