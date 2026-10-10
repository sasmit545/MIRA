"""Bounded views of a capability result: the digest the model always sees, and
the selection a recall returns.

Specialist-agnostic (KTD1): it walks JSON structure and never interprets
values. Pulling indicators out of a result is the specialist's normalizer's
job, and what it found already reaches the prompt as evidence.
"""

import json
from collections import Counter
from typing import Any, Dict, List, NamedTuple, Optional, Tuple

MAX_OBSERVATION_CHARS = 2000
MAX_DIGEST_CHARS = 2000
MAX_RECALL_CHARS = 6000
DEFAULT_RECALL_ITEMS = 50
MAX_RECALL_ITEMS = 200
RECALL_ARGUMENTS = ("handle", "path", "offset", "limit", "contains", "where", "fields", "group_by")
ARRAY_ARGUMENTS = RECALL_ARGUMENTS[2:]  # each one selects within an array

# Digest shape: how much of each value survives.
SCALAR_CHARS = 80
INLINE_CHARS = 160  # an array or object this small is shown whole
SKETCH_DEPTH = 3
SMALL_ARRAY_ITEMS = 8  # shown whole; a larger array is summarized
# A larger array's summary: its fields, and value counts for the fields whose
# values repeat. Values come from the sample, so only few of them are shown.
LOW_CARDINALITY = 50
TOP_VALUES = 5
MAX_SUMMARY_FIELDS = 12
PARTIAL_MARKER = "[partial digest: the full observation is kept; recall_observation retrieves any part of it]"


def truncate(text: str, limit: int = MAX_OBSERVATION_CHARS) -> str:
    """Cap a rendered payload so one tool result cannot fill the context window."""
    if len(text) <= limit:
        return text
    return f"{text[:limit]}... [truncated, {len(text) - limit} more characters]"


def digest(output: Any, limit: int = MAX_DIGEST_CHARS) -> str:
    """A bounded, code-derived summary of a successful result (R4, R6).

    A large array is shown as its schema and value distributions, never as
    sampled items: any sample is arbitrary, and the field names are what a
    recall needs. Coverage and the array list always survive the bound. Says
    plainly when anything was left out.
    """
    elided: List[bool] = []
    summaries: List[str] = []
    body = "\n".join([_sketch(output, 0, elided, "", summaries), *summaries])
    arrays = list_arrays(output)
    tail = [line for line in (
        _coverage(output),
        "arrays: " + ", ".join(f"{path} ({length})" for path, length in arrays) if arrays else "",
    ) if line]
    room = limit - sum(len(line) + 1 for line in tail)
    if elided or len(body) > room:
        body = truncate(body, max(room, limit // 4))
    text = "\n".join([body, *tail])
    if elided or len(text) > limit:
        text += "\n" + PARTIAL_MARKER
    return text


def _coverage(output: Any) -> str:
    """The paging counters of the shared result envelope (KTD2), as a line."""
    metadata = output.get("metadata") if isinstance(output, dict) else None
    if not isinstance(metadata, dict) or "total" not in metadata:
        return ""
    total, offset = metadata["total"], metadata.get("offset") or 0
    if "fetched" not in metadata:
        return f"coverage: one page from offset {offset} of {total} items" + (
            "; more remain past it" if metadata.get("has_more") else ""
        )
    line = f"coverage: fetched {metadata['fetched']} of {total} (offset {offset})"
    if metadata.get("unfetched"):
        line += f"; {metadata['unfetched']} not fetched"
        if "next_offset" in metadata:
            call = metadata.get("capability") or "the same capability"
            line += f", the rest with {call}(offset={metadata['next_offset']})"
    if metadata.get("fetch_error"):
        line += f"; fetching stopped: {metadata['fetch_error']}"
    return line


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


class Selection(NamedTuple):
    """A recall answer, and what it showed for the retrieval ledger."""
    text: str
    failure: str
    path: str = ""  # the array the shown indices belong to
    shown: Tuple[int, ...] = ()  # indices of the items the answer showed


def select(output: Any, arguments: Dict[str, Any]) -> Selection:
    """Answer a recall against one full result (KTD5).

    Over an array, filters apply in order: `offset` (where scanning starts),
    `where`, `contains`; then either `group_by` counts the matched values, or
    `limit` pages them, narrowed to `fields`. Every item is named by its index
    in the array, so handle, path and index address one record (R8). Any name
    the result does not have fails, listing the names that exist (R9).
    """
    query, failure = _recall_arguments(arguments)
    if failure:
        return Selection("", failure)

    path = query["path"]
    selective = any(query[name] is not None for name in ARRAY_ARGUMENTS)
    if path is None and selective:
        arrays = list_arrays(output)
        if len(arrays) != 1:
            return Selection("", f"give a path: this result holds {_array_names(arrays)}")
        path = arrays[0][0]

    target, failure = _resolve(output, path)
    if failure:
        return Selection("", failure)
    where = path or "(whole result)"

    if not isinstance(target, list):
        if selective:
            return Selection("", (
                f"{where} is not an array; {', '.join(ARRAY_ARGUMENTS)} apply to arrays: "
                f"{_array_names(list_arrays(output))}"
            ))
        text = json.dumps(target, sort_keys=True, default=repr)
        if len(text) > MAX_RECALL_CHARS:
            return Selection("", (
                f"{where} is {len(text)} characters, over the {MAX_RECALL_CHARS}-character "
                f"recall limit; narrow it with path and a range, filter or search over "
                f"{_array_names(list_arrays(target, path or ''))}"
            ))
        return Selection(f"{where}:\n{text}", "", *_item_address(output, path))

    begin = query["offset"] or 0
    if begin >= len(target) and target:
        return Selection("", f"offset {begin} is past the end of {where}, which holds {len(target)} items (0..{len(target) - 1})")

    keys = sorted({key for item in target if isinstance(item, dict) for key in item})
    for kind, names in (
        ("where", list(query["where"] or {})),
        ("group_by", [query["group_by"]] if query["group_by"] else []),
        ("fields", query["fields"] or []),
    ):
        unknown = [name for name in names if name not in keys]
        if unknown and target:
            if not keys:
                return Selection("", f"{kind} needs items that are objects, and the items of {where} are not")
            return Selection("", (
                f"{kind} names {', '.join(unknown)}, not a key of the items of {where}; "
                f"their keys are {', '.join(keys)}"
            ))

    matched = [
        (index, item)
        for index, item in enumerate(target[begin:], begin)
        if _matches(item, query["where"], query["contains"])
    ]
    criteria = " and ".join(
        part for part in (
            f"match where {json.dumps(query['where'], sort_keys=True)}" if query["where"] is not None else "",
            f"contain any of {query['contains']}" if query["contains"] is not None else "",
        ) if part
    )
    if criteria:
        header = f"{where}: {len(matched)} of {len(target) - begin} items from {begin} {criteria}"
    elif query["group_by"]:
        header = f"{where}: {len(matched)} items from {begin}"
    else:
        header = (
            f"{where}: items {begin}..{begin + min(len(matched), query['limit'] or DEFAULT_RECALL_ITEMS) - 1} of {len(target)}"
            if matched else f"{where}: no items (it holds {len(target)})"
        )
    header += _unfetched(output)

    if query["group_by"]:
        return Selection(_grouped(header, matched, query["group_by"], query["limit"]), "", path or "")

    limit = query["limit"] or DEFAULT_RECALL_ITEMS
    picked = matched[:limit]
    fields = query["fields"]
    if fields is not None:
        # Filters above ran over whole items; only the display is narrowed.
        picked = [
            (index, {key: item[key] for key in fields if key in item} if isinstance(item, dict) else item)
            for index, item in picked
        ]
        header += f"; fields {fields}"

    lines, used, shown = [], 0, []
    for index, item in picked:
        line = f"[{index}] {truncate(_serialize(item), MAX_RECALL_CHARS // 4)}"
        if used + len(line) > MAX_RECALL_CHARS and lines:
            header += f"; stopped at item {index} to stay within the recall limit, continue with offset={index}"
            if fields is None and keys:
                # A live model paged a 35-item array 10 at a time: most of each
                # item was a block it did not need. Narrowing fits far more.
                header += f", or show fewer keys per item with fields (they have: {', '.join(keys)})"
            break
        lines.append(line)
        shown.append(index)
        used += len(line) + 1
    else:
        shown_to = picked[-1][0] + 1 if picked else begin
        if criteria and len(matched) > len(picked):
            header += f"; showing the first {len(picked)}, continue with offset={shown_to}"
        elif not criteria and shown_to < len(target):
            header += f"; more remain, continue with offset={shown_to}"
    return Selection("\n".join([header, *lines]), "", path or "", tuple(shown))


def _grouped(header: str, matched: list, field: str, limit: Optional[int]) -> str:
    """Value counts of one field over the matched items, most common first."""
    counts = Counter(_serialize(item.get(field)) if isinstance(item, dict) else "null" for _, item in matched)
    groups = sorted(counts.items(), key=lambda pair: (-pair[1], pair[0]))
    header += f"; grouped by {field}: {len(groups)} values"
    lines, used = [], 0
    for value, count in groups[:limit or len(groups)]:
        line = f"{truncate(value, MAX_RECALL_CHARS // 4)} {count}"
        if used + len(line) > MAX_RECALL_CHARS and lines:
            break
        lines.append(line)
        used += len(line) + 1
    if len(lines) < len(groups):
        header += f"; {len(groups) - len(lines)} values left out, narrow with where or raise limit"
    return "\n".join([header, *lines])


def _matches(item: Any, where: Optional[Dict[str, Any]], terms: Optional[List[str]]) -> bool:
    if where:
        for field, wanted in where.items():
            value = item.get(field) if isinstance(item, dict) else None
            options = wanted if isinstance(wanted, list) else [wanted]
            if not any(_equal(value, option) for option in options):
                return False
    return terms is None or any(term in _serialize(item).lower() for term in terms)


def _equal(value: Any, wanted: Any) -> bool:
    """Strings ignore case; a missing key reads as null; True is not 1."""
    if isinstance(value, str) and isinstance(wanted, str):
        return value.casefold() == wanted.casefold()
    if isinstance(value, bool) or isinstance(wanted, bool):
        return type(value) is type(wanted) and value == wanted
    return value == wanted


def _unfetched(output: Any) -> str:
    """Items a collected list never fetched, and the call that fetches them."""
    metadata = output.get("metadata") if isinstance(output, dict) else None
    if not isinstance(metadata, dict) or not metadata.get("unfetched"):
        return ""
    text = f"; {metadata['unfetched']} items of this list were never fetched"
    if "next_offset" in metadata:
        call = metadata.get("capability") or "the same capability"
        text += f", fetch the rest with {call}(offset={metadata['next_offset']})"
    return text


def _item_address(output: Any, path: Optional[str]) -> Tuple[str, Tuple[int, ...]]:
    """A path ending in an array index shows that one item of its array."""
    parent, _, last = (path or "").rpartition(".")
    if parent and last.isdigit() and isinstance(_resolve(output, parent)[0], list):
        return parent, (int(last),)
    return path or "", ()


SCALARS = (str, int, float, bool, type(None))


def _recall_arguments(arguments: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], str]:
    """Validate the selectors. Returns (query, failure)."""
    unknown = [name for name in arguments if name not in RECALL_ARGUMENTS]
    if unknown:
        return None, f"unknown argument {', '.join(unknown)}; accepted: {', '.join(RECALL_ARGUMENTS)}"

    path = arguments.get("path")
    if path is not None and (not isinstance(path, str) or not path.strip()):
        return None, "path must be a dotted path such as data.strings"

    numbers = {}
    for name, low, high in (("offset", 0, None), ("limit", 1, MAX_RECALL_ITEMS)):
        value = arguments.get(name)
        if value is not None and (
            isinstance(value, bool) or not isinstance(value, int)
            or value < low or (high is not None and value > high)
        ):
            bound = f"between {low} and {high}" if high else f"at least {low}"
            return None, f"{name} must be an integer {bound}"
        numbers[name] = value

    terms = arguments.get("contains")
    if isinstance(terms, str):
        terms = [terms]
    if terms is not None:
        if not isinstance(terms, list) or not terms or not all(
            isinstance(term, str) and term.strip() for term in terms
        ):
            return None, "contains must be a non-empty list of non-empty strings"
        terms = [term.strip().lower() for term in terms]

    fields = arguments.get("fields")
    if isinstance(fields, str):
        fields = [fields]
    if fields is not None and (
        not isinstance(fields, list) or not fields or not all(isinstance(name, str) and name.strip() for name in fields)
    ):
        return None, "fields must be a non-empty list of item keys"

    where = arguments.get("where")
    if where is not None:
        if not isinstance(where, dict) or not where:
            return None, "where must be an object mapping item keys to a value, or to a list of values meaning any of them"
        for wanted in where.values():
            options = wanted if isinstance(wanted, list) else [wanted]
            if not options or not all(isinstance(option, SCALARS) for option in options):
                return None, "where values must be a string, number, boolean or null, or a non-empty list of those"

    group_by = arguments.get("group_by")
    if group_by is not None and (not isinstance(group_by, str) or not group_by.strip()):
        return None, "group_by must be one item key"
    if group_by is not None and fields is not None:
        return None, "fields does not apply to group_by, which shows value counts rather than items"

    return {
        "path": path.strip() if path else None,
        **numbers,
        "contains": terms,
        "fields": fields,
        "where": where,
        "group_by": group_by,
    }, ""


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


def _sketch(value: Any, depth: int, elided: List[bool], path: str, summaries: List[str]) -> str:
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
        parts = [
            f"{key}: {_sketch(child, depth + 1, elided, f'{path}.{key}' if path else str(key), summaries)}"
            for key, child in value.items()
        ]
        return "{" + ", ".join(parts) + "}"

    if len(value) <= SMALL_ARRAY_ITEMS:
        # A handful of items (PE sections, say) is shown in full: a summary
        # would hide the odd one out, which is usually the one that matters.
        items = [_sketch(item, depth + 1, elided, f"{path}.{index}", summaries) for index, item in enumerate(value)]
        return f"[{len(value)} items: " + ", ".join(items) + "]"

    elided.append(True)
    summaries.append(_summary(path or "(whole result)", value, elided))
    return f"[{len(value)} items, summarized below]"


def _summary(path: str, items: list, elided: List[bool]) -> str:
    """A large array as its size, its fields, and how their values spread."""
    if not all(isinstance(item, dict) for item in items):
        return f"{path}: {len(items)} items, {len({_serialize(item) for item in items})} distinct"
    fields = list(dict.fromkeys(key for item in items for key in item))
    lines = [f"{path}: {len(items)} items, fields {{{', '.join(fields)}}}"]
    for field in fields[:MAX_SUMMARY_FIELDS]:
        # A missing key counts as null, as a recall filter treats it.
        present = [_serialize(item[field]) for item in items if item.get(field) is not None]
        counts = Counter(present)
        line = f"  {field}: {len(counts)} distinct"
        if len(items) > len(present):
            line += f", {len(items) - len(present)} null"
        if len(counts) <= LOW_CARDINALITY and len(counts) * 2 <= len(present):
            top = counts.most_common(TOP_VALUES)
            line += " — " + ", ".join(f"{_clip(value, elided)} {count}" for value, count in top)
            if len(counts) > len(top):
                line += f", … (+{len(counts) - len(top)})"
        lines.append(line)
    if len(fields) > MAX_SUMMARY_FIELDS:
        lines.append(f"  (+{len(fields) - MAX_SUMMARY_FIELDS} more fields)")
    return "\n".join(lines)


def _clip(text: str, elided: List[bool]) -> str:
    if len(text) <= SCALAR_CHARS:
        return text
    elided.append(True)
    return f"{text[:SCALAR_CHARS]}…(+{len(text) - SCALAR_CHARS} chars)"


def _serialize(value: Any) -> str:
    return json.dumps(value, sort_keys=True, default=repr)


def _array_names(arrays: List[Tuple[str, int]]) -> str:
    if not arrays:
        return "no arrays"
    return ", ".join(f"{path} ({length} items)" for path, length in arrays)
