"""Finding and evidence contracts."""

from dataclasses import dataclass
from enum import Enum
from typing import List


class Severity(Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True)
class Evidence:
    """Reference to a piece of evidence by its identifier.

    An index into State.observations outlived the list it indexed: State is
    local to one run and is discarded when the loop returns, so the reference
    was dangling by the time anyone read it. An identifier survives the run.
    """
    evidence_id: str


@dataclass(frozen=True)
class Finding:
    """A finding discovered during the investigation."""
    title: str
    description: str
    severity: Severity
    confidence: Confidence
    evidence_refs: List[Evidence]
    source_location: str  # e.g., file path, function name, etc.
