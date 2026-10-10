"""Validate a model-authored narrative and merge it into the working memory.

Pure: no loop, no model. Either the whole update is applied or none of it is,
so a rejected narrative never leaves the memory half-merged.
"""

import difflib
import math
from dataclasses import replace
from typing import Any, Collection, List

from mira.core.hypothesis import PROVISIONAL

from ..contracts.memory import Candidate, MemoryHypothesis, OpenQuestion, WorkingMemory

REQUIRED = ("understanding", "hypotheses", "open_questions", "candidates")


def apply_narrative(memory: WorkingMemory, update: Any, known_evidence: Collection[str]) -> str:
    """Merge `update` into `memory`. Returns "" on success, else the reason it
    was rejected, written for the model to act on.

    Additive (KTD11): an entry the update does not mention stands, a mentioned
    entry is revised by id, and removing one means naming its id in `close`.
    """
    if not isinstance(update, dict):
        return "record_memory must be an object"
    missing = [name for name in REQUIRED if name not in update]
    if missing:
        return f"record_memory is missing required fields: {', '.join(missing)}"

    understanding = update["understanding"]
    if not isinstance(understanding, str):
        return "understanding must be a string"

    hypotheses, failure = _hypotheses(memory.hypotheses, update["hypotheses"], set(known_evidence))
    if hypotheses is None:
        return failure
    questions, failure = _entries(memory.open_questions, update["open_questions"], "open_questions", "question", OpenQuestion)
    if questions is None:
        return failure
    candidates, failure = _entries(memory.candidates, update["candidates"], "candidates", "investigation", Candidate)
    if candidates is None:
        return failure

    closing = update.get("close", [])
    if not isinstance(closing, list) or not all(isinstance(item, str) for item in closing):
        return "close must be an array of entry identifiers"
    present = {entry.id for entries in (hypotheses, questions, candidates) for entry in entries}
    unknown = [item for item in closing if item not in present]
    if unknown:
        return f"close names entries that do not exist: {', '.join(unknown)}"

    memory.understanding = understanding or memory.understanding
    memory.hypotheses = [item for item in hypotheses if item.id not in closing]
    memory.open_questions = [item for item in questions if item.id not in closing]
    memory.candidates = [item for item in candidates if item.id not in closing]
    return ""


def _hypotheses(existing: List[MemoryHypothesis], raw: Any, known: set):
    if not isinstance(raw, list):
        return None, "hypotheses must be an array"
    merged = {item.id: item for item in existing}
    for index, entry in enumerate(raw):
        where = f"hypotheses[{index}]"
        if not isinstance(entry, dict) or not isinstance(entry.get("id"), str) or not entry["id"]:
            return None, f"{where} must be an object with a string id"
        current = merged.get(entry["id"])
        changes = {}

        if "statement" in entry:
            if not isinstance(entry["statement"], str) or not entry["statement"].strip():
                return None, f"{where}.statement must be a non-empty string"
            changes["statement"] = entry["statement"]
        elif current is None:
            return None, f"{where} is new, so it needs a statement"

        if "confidence" in entry:
            confidence = _number(entry["confidence"])
            if confidence is None:
                return None, f"{where}.confidence must be a number between 0 and 1"
            changes["confidence"] = confidence
        elif current is None:
            return None, f"{where} is new, so it needs a confidence"

        if "status" in entry:
            status = _status(entry["status"])
            if status is None:
                return None, f"{where}.status must be one of: {', '.join(PROVISIONAL)}"
            changes["status"] = status

        for name in ("supporting_evidence", "contradicting_evidence"):
            if name in entry:
                refs = entry[name]
                if not isinstance(refs, list) or not all(isinstance(ref, str) for ref in refs):
                    return None, f"{where}.{name} must be an array of evidence identifiers"
                never_seen = [ref for ref in refs if ref not in known]
                if never_seen:
                    return None, (
                        f"{where}.{name} names evidence that was never observed: "
                        f"{', '.join(never_seen)}. Cite only identifiers listed in the context."
                    )
                changes[name] = refs

        if "unknowns" in entry:
            if not isinstance(entry["unknowns"], str):
                return None, f"{where}.unknowns must be a string"
            changes["unknowns"] = entry["unknowns"]

        if current is None:
            merged[entry["id"]] = MemoryHypothesis(id=entry["id"], **changes)
        else:
            # replace() re-runs __post_init__, so a revision is clamped and checked too.
            merged[entry["id"]] = replace(current, **changes)
    return list(merged.values()), ""


def _entries(existing: list, raw: Any, name: str, key: str, build):
    if not isinstance(raw, list):
        return None, f"{name} must be an array"
    merged = {item.id: item for item in existing}
    for index, entry in enumerate(raw):
        where = f"{name}[{index}]"
        if not isinstance(entry, dict) or not isinstance(entry.get("id"), str) or not entry["id"]:
            return None, f"{where} must be an object with a string id"
        text = entry.get(key)
        if key not in entry:
            # Coerce before rejecting (KTD8): a live model wrote candidates as
            # {"id", "question"}. One other text field is unambiguously the one.
            others = [value for field, value in entry.items() if field != "id" and isinstance(value, str) and value.strip()]
            if len(others) == 1:
                text = others[0]
        if not isinstance(text, str) or not text.strip():
            return None, f"{where}.{key} must be a non-empty string"
        merged[entry["id"]] = build(**{"id": entry["id"], key: text})
    return list(merged.values()), ""


def _number(value: Any):
    """A confidence the model wrote as "0.7" is still a confidence; a boolean is not."""
    if isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


def _status(value: Any):
    """Case, whitespace and near-misses are the model's habit, not its error
    (KTD8): coerce what can be coerced and reject only what cannot."""
    if not isinstance(value, str):
        return None
    matches = difflib.get_close_matches(value.strip().lower(), PROVISIONAL, n=1, cutoff=0.7)
    return matches[0] if matches else None
