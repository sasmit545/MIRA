from __future__ import annotations

from pydantic import Field

from mira.contracts.common import Contract


class FileInfoInput(Contract):
    artifact_id: str = Field(..., description="Identifier of the artifact")


class FileInfoOutput(Contract):
    size: int = Field(..., description="Size in bytes")
    mime_type: str = Field(..., description="MIME type")
    md5: str = Field(..., description="MD5 hash")
    sha1: str = Field(..., description="SHA-1 hash")
    sha256: str = Field(..., description="SHA-256 hash")
