"""
Hypothesis class for MIRA.
Represents what the investigation currently believes, and how strongly.
"""

from typing import List, Optional
from datetime import datetime

OPEN = "open"
SUPPORTED = "supported"
WEAKENED = "weakened"
CONFIRMED = "confirmed"
REJECTED = "rejected"

#: A hypothesis moves through these as evidence accumulates. `confirmed` and
#: `rejected` are verdicts the Coordinator assigns; `support`/`contradict`
#: below only move a belief between the three provisional states.
STATUSES = (OPEN, SUPPORTED, WEAKENED, CONFIRMED, REJECTED)

PROVISIONAL = (OPEN, SUPPORTED, WEAKENED)


class Hypothesis:
    def __init__(
        self,
        id: str,
        statement: str,
        confidence: float = 0.0,
        supporting_evidence: Optional[List[str]] = None,
        contradicting_evidence: Optional[List[str]] = None,
        status: str = OPEN
    ):
        self.id = id
        self.statement = statement
        self.confidence = max(0.0, min(1.0, confidence))  # Clamp between 0 and 1
        self.supporting_evidence = supporting_evidence or []
        self.contradicting_evidence = contradicting_evidence or []
        self.status = status
        self.timestamp = datetime.now()
        self.updated_at = datetime.now()

    def update_confidence(self, new_confidence: float):
        """Update confidence score."""
        self.confidence = max(0.0, min(1.0, new_confidence))
        self.updated_at = datetime.now()

    def support(self, evidence_id: str, confidence: Optional[float] = None):
        """Link evidence supporting this hypothesis, and strengthen it."""
        if evidence_id not in self.supporting_evidence:
            self.supporting_evidence.append(evidence_id)
        if confidence is not None:
            self.confidence = max(0.0, min(1.0, confidence))
        if self.status in PROVISIONAL:
            self.status = SUPPORTED
        self.updated_at = datetime.now()

    def contradict(self, evidence_id: str, confidence: Optional[float] = None):
        """Link evidence contradicting this hypothesis, and weaken it."""
        if evidence_id not in self.contradicting_evidence:
            self.contradicting_evidence.append(evidence_id)
        if confidence is not None:
            self.confidence = max(0.0, min(1.0, confidence))
        if self.status in PROVISIONAL:
            self.status = WEAKENED
        self.updated_at = datetime.now()

    def to_dict(self) -> dict:
        """Convert hypothesis to dictionary for serialization."""
        return {
            "id": self.id,
            "statement": self.statement,
            "confidence": self.confidence,
            "supporting_evidence": self.supporting_evidence,
            "contradicting_evidence": self.contradicting_evidence,
            "status": self.status,
            "timestamp": self.timestamp.isoformat(),
            "updated_at": self.updated_at.isoformat()
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'Hypothesis':
        """Create hypothesis from dictionary."""
        hypothesis = cls(
            id=data["id"],
            statement=data["statement"],
            confidence=data.get("confidence", 0.0),
            supporting_evidence=data.get("supporting_evidence", []),
            contradicting_evidence=data.get("contradicting_evidence", []),
            status=data.get("status", OPEN)
        )
        if "timestamp" in data:
            hypothesis.timestamp = datetime.fromisoformat(data["timestamp"])
        if "updated_at" in data:
            hypothesis.updated_at = datetime.fromisoformat(data["updated_at"])
        return hypothesis
