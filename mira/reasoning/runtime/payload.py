"""Bounded views of a capability result: the digest the model always sees, and
the selection a recall returns.

Specialist-agnostic (KTD1): it walks JSON structure and never interprets
values. Pulling indicators out of a result is the specialist's normalizer's
job, and what it found already reaches the prompt as evidence.
"""

import json
from typing import Any, Dict, List, Optional, Tuple

MAX_OBSERVATION_CHARS = 2000
MAX_DIGEST_CHARS = 2000
MAX_RECALL_CHARS = 6000
DEFAULT_RECALL_ITEMS = 50
MAX_RECALL_ITEMS = 200

# Digest shape: how much of each value survives.
SCALAR_CHARS = 80
INLINE_CHARS = 160  # an array or object this small is shown whole
SKETCH_DEPTH = 3
SMALL_ARRAY_ITEMS = 8  # shown whole; a larger array is sampled at both ends
PARTIAL_MARKER = "[partial digest: the full observation is kept; recall_observation retrieves any part of it]"


def truncate(text: str, limit: int = MAX_OBSERVATION_CHARS) -> str:
    """Cap a rendered payload so one tool result cannot fill the context window."""
    if len(text) <= limit:
        return text
    return f"{text[:limit]}... [truncated, {len(text) - limit} more characters]"


def digest(output: Any, limit: int = MAX_DIGEST_CHARS) -> str:
    """A bounded, code-derived summary of a successful result (R20).

    Every array is named with its length and sampled from both ends, so what
    sits late in a large result is not hidden behind its first few thousand
    characters. Says plainly when anything was left out.
    """
    elided: List[bool] = []
    text = _sketch(output, 0, elided)
    arrays = list_arrays(output)
    if arrays:
        text += "\narrays: " + ", ".join(f"{path} ({length})" for path, length in arrays)
    if elided or len(text) > limit:
        text = truncate(text, limit) + "\n" + PARTIAL_MARKER
    return text


def list_arrays(value: Any, prefix: str = "") -> List[Tuple[str, int]]:
    """Dotted paths of the arrays reachable through objects, with their lengths.

    Arrays inside arrays are not listed: a recall addresses them by index
    (`data.sections.2.flags`) once the model knows the outer one exists.
    """
    found: List[Tuple[str, int]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            if isinstance(child, list):
                found.append((path, len(child)))
            else:
                found.extend(list_arrays(child, path))
    return found


def select(output: Any, arguments: Dict[str, Any]) -> Tuple[str, str]:
    """Answer a recall against one full result. Returns (text, failure).

    Ranges and search apply to arrays only: an object has no order a position
    could mean anything in, so asking for one is an explicit failure that names
    the arrays that do exist.
    """
    path, start, count, terms, fields, failure = _recall_arguments(arguments)
    if failure:
        return "", failure

    positional = start is not None or count is not None or terms is not None or fields is not None
    if path is None and positional:
        arrays = list_arrays(output)
        if len(arrays) != 1:
            return "", f"give a path: this result holds {_array_names(arrays)}"
        path = arrays[0][0]

    target, failure = _resolve(output, path)
    if failure:
        return "", failure
    where = path or "(whole result)"

    if not isinstance(target, list):
        if positional:
            return "", (
                f"{where} is not an array; start, count, contains and fields apply to arrays: "
                f"{_array_names(list_arrays(output))}"
            )
        text = json.dumps(target, sort_keys=True, default=repr)
        if len(text) > MAX_RECALL_CHARS:
            return "", (
                f"{where} is {len(text)} characters, over the {MAX_RECALL_CHARS}-character "
                f"recall limit; narrow it with path and a range or search over "
                f"{_array_names(list_arrays(target, path or ''))}"
            )
        return f"{where}:\n{text}", ""

    if start is not None and start >= len(target) and target:
        return "", f"start {start} is past the end of {where}, which holds {len(target)} items (0..{len(target) - 1})"
    begin = start or 0
    limit = count or DEFAULT_RECALL_ITEMS

    if terms is not None:
        matches = [
            (index, item)
            for index, item in enumerate(target[begin:], begin)
            if any(term in _serialize(item).lower() for term in terms)
        ]
        picked = matches[:limit]
        header = (
            f"{where}: {len(matches)} of {len(target) - begin} items from {begin} "
            f"contain any of {terms}"
        )
    else:
        picked = list(enumerate(target[begin:begin + limit], begin))
        header = (
            f"{where}: items {begin}..{begin + len(picked) - 1} of {len(target)}"
            if picked else f"{where}: no items (it holds {len(target)})"
        )

    keys = sorted({key for _, item in picked if isinstance(item, dict) for key in item})
    if fields is not None:
        # Search above ran over whole items; only the display is narrowed.
        if keys and not set(fields) & set(keys):
            return "", f"none of fields {fields} exist on the items of {where}; their keys are {', '.join(keys)}"
        picked = [
            (index, {key: item[key] for key in fields if key in item} if isinstance(item, dict) else item)
            for index, item in picked
        ]
        header += f"; fields {fields}"

    lines, used = [], 0
    for index, item in picked:
        line = f"[{index}] {truncate(_serialize(item), MAX_RECALL_CHARS // 4)}"
        if used + len(line) > MAX_RECALL_CHARS and lines:
            header += f"; stopped at item {index} to stay within the recall limit, continue with start={index}"
            if fields is None and keys:
                # A live model paged a 35-item array 10 at a time: most of each
                # item was a block it did not need. Narrowing fits far more.
                header += f", or show fewer keys per item with fields (they have: {', '.join(keys)})"
            break
        lines.append(line)
        used += len(line) + 1
    else:
        shown_to = picked[-1][0] + 1 if picked else begin
        if terms is not None and len(matches) > len(picked):
            header += f"; showing the first {len(picked)}, continue with start={shown_to}"
        elif terms is None and shown_to < len(target):
            header += f"; more remain, continue with start={shown_to}"
    return "\n".join([header, *lines]), ""


def _recall_arguments(arguments: Dict[str, Any]):
    """Validate the optional selectors. Returns (path, start, count, terms, fields, failure)."""
    path = arguments.get("path")
    if path is not None and (not isinstance(path, str) or not path.strip()):
        return None, None, None, None, None, "path must be a dotted path such as data.strings"

    numbers = {}
    for name, low, high in (("start", 0, None), ("count", 1, MAX_RECALL_ITEMS)):
        value = arguments.get(name)
        if value is not None and (
            isinstance(value, bool) or not isinstance(value, int)
            or value < low or (high is not None and value > high)
        ):
            bound = f"between {low} and {high}" if high else f"at least {low}"
            return None, None, None, None, None, f"{name} must be an integer {bound}"
        numbers[name] = value

    terms = arguments.get("contains")
    if isinstance(terms, str):
        terms = [terms]
    if terms is not None:
        if not isinstance(terms, list) or not terms or not all(
            isinstance(term, str) and term.strip() for term in terms
        ):
            return None, None, None, None, None, "contains must be a non-empty list of non-empty strings"
        terms = [term.strip().lower() for term in terms]

    fields = arguments.get("fields")
    if isinstance(fields, str):
        fields = [fields]
    if fields is not None and (
        not isinstance(fields, list) or not fields or not all(isinstance(name, str) and name.strip() for name in fields)
    ):
        return None, None, None, None, None, "fields must be a non-empty list of item keys"

    return (path.strip() if path else None), numbers["start"], numbers["count"], terms, fields, ""


def _resolve(output: Any, path: Optional[str]) -> Tuple[Any, str]:
    if path is None:
        return output, ""
    value, walked = output, []
    for segment in path.split("."):
        if isinstance(value, dict) and segment in value:
            value = value[segment]
        elif isinstance(value, list) and segment.isdigit() and int(segment) < len(value):
            value = value[int(segment)]
        else:
            here = ".".join(walked) or "the result"
            if isinstance(value, dict):
                options = f"its keys are {sorted(value)}"
            elif isinstance(value, list):
                options = f"it is an array of {len(value)} items, so use an index 0..{len(value) - 1}"
            else:
                options = "it has no parts"
            return None, f"path {path!r} not found: {segment!r} is not in {here}; {options}"
        walked.append(segment)
    return value, ""


def _sketch(value: Any, depth: int, elided: List[bool]) -> str:
    if isinstance(value, str):
        if len(value) > SCALAR_CHARS:
            elided.append(True)
            return json.dumps(value[:SCALAR_CHARS]) + f"…(+{len(value) - SCALAR_CHARS} chars)"
        return json.dumps(value)
    if not isinstance(value, (dict, list)):
        return json.dumps(value, default=repr)

    whole = _serialize(value)
    if len(whole) <= INLINE_CHARS:
        return whole
    if depth >= SKETCH_DEPTH:
        elided.append(True)
        size = f"{len(value)} keys" if isinstance(value, dict) else f"{len(value)} items"
        return f"{{…{size}}}" if isinstance(value, dict) else f"[…{size}]"

    if isinstance(value, dict):
        parts = [f"{key}: {_sketch(child, depth + 1, elided)}" for key, child in value.items()]
        return "{" + ", ".join(parts) + "}"

    if len(value) <= SMALL_ARRAY_ITEMS:
        # A handful of items (PE sections, say) is shown in full: sampling
        # would hide the odd one out, which is usually the one that matters.
        items = [_sketch(item, depth + 1, elided) for item in value]
        return f"[{len(value)} items: " + ", ".join(items) + "]"

    # Both ends of a large array: what a capability returns late is as likely
    # to matter as what it returns first.
    elided.append(True)
    head = [_sketch(item, depth + 1, elided) for item in value[:2]]
    tail = [_sketch(value[-1], depth + 1, elided)]
    return f"[{len(value)} items: " + ", ".join(head + [f"…{len(value) - 3} more…"] + tail) + "]"


def _serialize(value: Any) -> str:
    return json.dumps(value, sort_keys=True, default=repr)


def _array_names(arrays: List[Tuple[str, int]]) -> str:
    if not arrays:
        return "no arrays"
    return ", ".join(f"{path} ({length} items)" for path, length in arrays)
