"""
Evidence class for MIRA.
Represents normalized observations from analysis tools.
"""

from typing import List, Optional
from datetime import datetime
from .artifact import Artifact

# What each grade of Evidence.confidence means, for every specialist and the
# reasoning loop: below MODERATE_FROM is weak, from STRONG_FROM is strong.
MODERATE_FROM = 0.6
STRONG_FROM = 0.8


def grade(confidence: float) -> str:
    """weak, moderate or strong."""
    if confidence >= STRONG_FROM:
        return "strong"
    if confidence >= MODERATE_FROM:
        return "moderate"
    return "weak"


class Evidence:
    def __init__(
        self,
        id: str,
        observation: str,
        source_agent: str,
        capability: str,
        artifact_id: Optional[str] = None,
        confidence: float = 0.0,
        provenance: Optional[str] = None,
        related_evidence: Optional[List[str]] = None,
        corroborates: bool = True,
    ):
        self.id = id
        self.observation = observation
        self.source_agent = source_agent
        self.capability = capability
        self.artifact_id = artifact_id
        self.confidence = max(0.0, min(1.0, confidence))  # Clamp between 0 and 1
        self.provenance = provenance
        self.related_evidence = related_evidence or []
        # False for evidence that can support a conclusion but never establish
        # one on its own, such as high entropy: it still grades and cites
        # normally, but does not count toward a verdict's corroboration.
        self.corroborates = corroborates
        self.timestamp = datetime.now()
        self.updated_at = datetime.now()

    def update_confidence(self, new_confidence: float):
        """Update confidence score."""
        self.confidence = max(0.0, min(1.0, new_confidence))
        self.updated_at = datetime.now()

    def add_related_evidence(self, evidence_id: str):
        """Add related evidence ID."""
        if evidence_id not in self.related_evidence:
            self.related_evidence.append(evidence_id)
            self.updated_at = datetime.now()

    def to_dict(self) -> dict:
        """Convert evidence to dictionary for serialization."""
        return {
            "id": self.id,
            "observation": self.observation,
            "source_agent": self.source_agent,
            "capability": self.capability,
            "artifact_id": self.artifact_id,
            "confidence": self.confidence,
            "provenance": self.provenance,
            "related_evidence": self.related_evidence,
            "corroborates": self.corroborates,
            "timestamp": self.timestamp.isoformat(),
            "updated_at": self.updated_at.isoformat()
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'Evidence':
        """Create evidence from dictionary."""
        evidence = cls(
            id=data["id"],
            observation=data["observation"],
            source_agent=data["source_agent"],
            capability=data["capability"],
            artifact_id=data.get("artifact_id"),
            confidence=data.get("confidence", 0.0),
            provenance=data.get("provenance"),
            related_evidence=data.get("related_evidence", []),
            corroborates=data.get("corroborates", True),
        )
        if "timestamp" in data:
            evidence.timestamp = datetime.fromisoformat(data["timestamp"])
        if "updated_at" in data:
            evidence.updated_at = datetime.fromisoformat(data["updated_at"])
        return evidence