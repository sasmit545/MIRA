"""
InvestigationTask class for MIRA.
Tracks one unit of investigation work, its specialist, and what it waits on.
"""

from typing import List, Optional
from datetime import datetime

PENDING = "pending"
ACTIVE = "active"
COMPLETED = "completed"
FAILED = "failed"

STATUSES = (PENDING, ACTIVE, COMPLETED, FAILED)


class InvestigationTask:
    def __init__(
        self,
        id: str,
        objective: str,
        specialist: str,
        status: str = PENDING,
        depends_on: Optional[List[str]] = None,
        evidence_required: Optional[List[str]] = None
    ):
        self.id = id
        self.objective = objective
        self.specialist = specialist
        self.status = status
        self.depends_on = depends_on or []
        self.evidence_required = evidence_required or []
        self.timestamp = datetime.now()
        self.updated_at = datetime.now()

    def to_dict(self) -> dict:
        """Convert task to dictionary for serialization."""
        return {
            "id": self.id,
            "objective": self.objective,
            "specialist": self.specialist,
            "status": self.status,
            "depends_on": self.depends_on,
            "evidence_required": self.evidence_required,
            "timestamp": self.timestamp.isoformat(),
            "updated_at": self.updated_at.isoformat()
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'InvestigationTask':
        """Create task from dictionary."""
        task = cls(
            id=data["id"],
            objective=data["objective"],
            specialist=data["specialist"],
            status=data.get("status", PENDING),
            depends_on=data.get("depends_on", []),
            evidence_required=data.get("evidence_required", [])
        )
        if "timestamp" in data:
            task.timestamp = datetime.fromisoformat(data["timestamp"])
        if "updated_at" in data:
            task.updated_at = datetime.fromisoformat(data["updated_at"])
        return task
