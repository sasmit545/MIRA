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
    """Reference to an observation in the State."""
    observation_index: int  # Index into State.observations list


@dataclass(frozen=True)
class Finding:
    """A finding discovered during the investigation."""
    title: str
    description: str
    severity: Severity
    confidence: Confidence
    evidence_refs: List[Evidence]
    source_location: str  # e.g., file path, function name, etc.
