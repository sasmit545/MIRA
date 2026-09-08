"""
InvestigationState class for MIRA.
Tracks the overall state of the malware investigation.
"""

from typing import List, Optional
from datetime import datetime
from .evidence import Evidence
from .artifact import Artifact
from .hypothesis import Hypothesis
from .task import InvestigationTask


class InvestigationState:
    def __init__(self):
        self.sample = None
        self.artifacts: List[Artifact] = []
        self.evidence: List[Evidence] = []
        self.hypotheses: List[Hypothesis] = []
        self.tasks: List[InvestigationTask] = []
        self.history: List[dict] = []
        self.status = "running"
        self.created_at = datetime.now()
        self.updated_at = datetime.now()

    def add_evidence(self, evidence: Evidence):
        """Add evidence to the state and update timestamp."""
        self.evidence.append(evidence)
        self.updated_at = datetime.now()
        self._log_state_change("evidence_added", {"evidence_id": evidence.id})

    def add_artifact(self, artifact: Artifact):
        """Add artifact to the state and update timestamp."""
        self.artifacts.append(artifact)
        self.updated_at = datetime.now()
        self._log_state_change("artifact_added", {"artifact_id": artifact.id})

    def add_hypothesis(self, hypothesis: Hypothesis):
        """Add hypothesis to the state and update timestamp."""
        self.hypotheses.append(hypothesis)
        self.updated_at = datetime.now()
        self._log_state_change("hypothesis_added", {"hypothesis_id": hypothesis.id})

    def add_task(self, task: InvestigationTask):
        """Add task to the state and update timestamp."""
        self.tasks.append(task)
        self.updated_at = datetime.now()
        self._log_state_change("task_added", {"task_id": task.id})

    def update_task_status(self, task_id: str, status: str):
        """Update the status of a task."""
        for task in self.tasks:
            if task.id == task_id:
                task.status = status
                self.updated_at = datetime.now()
                self._log_state_change("task_status_updated", {
                    "task_id": task_id,
                    "status": status
                })
                break

    def _log_state_change(self, change_type: str, details: dict):
        """Log a state change to the history."""
        self.history.append({
            "timestamp": datetime.now().isoformat(),
            "change_type": change_type,
            "details": details
        })

    def get_evidence_by_id(self, evidence_id: str) -> Optional[Evidence]:
        """Get evidence by its ID."""
        for evidence in self.evidence:
            if evidence.id == evidence_id:
                return evidence
        return None

    def get_artifact_by_id(self, artifact_id: str) -> Optional[Artifact]:
        """Get artifact by its ID."""
        for artifact in self.artifacts:
            if artifact.id == artifact_id:
                return artifact
        return None

    def get_hypothesis_by_id(self, hypothesis_id: str) -> Optional[Hypothesis]:
        """Get hypothesis by its ID."""
        for hypothesis in self.hypotheses:
            if hypothesis.id == hypothesis_id:
                return hypothesis
        return None

    def get_task_by_id(self, task_id: str) -> Optional[InvestigationTask]:
        """Get task by its ID."""
        for task in self.tasks:
            if task.id == task_id:
                return task
        return None

    def to_dict(self) -> dict:
        """Convert state to dictionary for serialization."""
        return {
            "sample": self.sample,
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
            "evidence": [evidence.to_dict() for evidence in self.evidence],
            "hypotheses": [hypothesis.to_dict() for hypothesis in self.hypotheses],
            "tasks": [task.to_dict() for task in self.tasks],
            "history": self.history,
            "status": self.status,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat()
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'InvestigationState':
        """Create state from dictionary."""
        state = cls()
        state.sample = data.get("sample")

        # Import here to avoid circular imports
        from .evidence import Evidence
        from .artifact import Artifact
        from .hypothesis import Hypothesis
        from .task import InvestigationTask

        state.artifacts = [Artifact.from_dict(a) for a in data.get("artifacts", [])]
        state.evidence = [Evidence.from_dict(e) for e in data.get("evidence", [])]
        state.hypotheses = [Hypothesis.from_dict(h) for h in data.get("hypotheses", [])]
        state.tasks = [InvestigationTask.from_dict(t) for t in data.get("tasks", [])]
        state.history = data.get("history", [])
        state.status = data.get("status", "running")

        if "created_at" in data:
            state.created_at = datetime.fromisoformat(data["created_at"])
        if "updated_at" in data:
            state.updated_at = datetime.fromisoformat(data["updated_at"])

        return state