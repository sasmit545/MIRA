"""Working memory: the specialist's own notebook for one assignment.

Distinct from the shared investigation state. The facts (evidence, the
observation log) stay on `State`; this holds only what the *model* concludes
from them - its understanding, beliefs, open questions and next candidates.
"""

from dataclasses import dataclass, field
from typing import List

from mira.core.hypothesis import OPEN, PROVISIONAL


@dataclass
class MemoryHypothesis:
    """Mirrors `mira.core.hypothesis.Hypothesis` so promotion at completion is
    a direct construction. Confidence is a float clamped to 0..1, and status is
    limited to the provisional states: confirmed/rejected are the
    Coordinator's verdicts, not a specialist's."""
    id: str
    statement: str
    confidence: float = 0.0
    supporting_evidence: List[str] = field(default_factory=list)
    contradicting_evidence: List[str] = field(default_factory=list)
    status: str = OPEN
    unknowns: str = ""

    def __post_init__(self) -> None:
        if self.status not in PROVISIONAL:
            raise ValueError(f"status must be one of {PROVISIONAL}, got {self.status!r}")
        self.confidence = max(0.0, min(1.0, self.confidence))


@dataclass
class OpenQuestion:
    id: str
    question: str


@dataclass
class Candidate:
    """A possible next investigation - a candidate, not a committed plan."""
    id: str
    investigation: str
    reason: str = ""


@dataclass
class WorkingMemory:
    understanding: str = ""
    hypotheses: List[MemoryHypothesis] = field(default_factory=list)
    open_questions: List[OpenQuestion] = field(default_factory=list)
    candidates: List[Candidate] = field(default_factory=list)
