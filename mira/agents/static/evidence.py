"""Turn static capability results into evidence an orchestrator can read.

One pure function per capability. Each answers "what would an analyst say they
saw?" in a sentence, because the orchestrator is a model reading prose rather
than a routing table matching a closed taxonomy. If a later orchestrator needs
machine-matchable kinds, this is where that vocabulary would be added.

Confidence describes the strength of the *observation*, so it is computed here
from the signal rather than asked of the model (KTD3): a model scoring its own
inputs has no independent basis for the number.
"""

from __future__ import annotations

import re
from typing import Any, Callable, NamedTuple

# --- Tuning knobs. These are thresholds to calibrate against real samples,
# --- not incidental literals.
PACKED_SECTION_ENTROPY = 7.2
HIGH_REGION_ENTROPY = 7.2
MAX_BYTE_ENTROPY = 8.0  # log2(256): the ceiling a byte histogram can reach
BASE_CONFIDENCE = 0.5  # a signal that only just crosses its threshold
LOW_FUNCTION_DENSITY = 0.01  # functions per KiB; below this, discovery looks starved
MIN_SIZE_FOR_DENSITY = 64 * 1024  # density says nothing about a small file
MAX_EXAMPLES = 5  # keep an observation a sentence, not a dump of a page
# A rule engine reports one hit per rule, and a page holds up to a thousand of
# them. Minting an evidence record for each would put a thousand identifiers in
# a message that has to stay bounded, so past this many the rest are counted
# rather than named. The full list is always in the trace.
MAX_RULE_SIGNALS = 20

CONFIDENCE_RULE_MATCH = 0.9  # a curated rule fired on this sample
CONFIDENCE_STRONG = 0.8
CONFIDENCE_MODERATE = 0.6
CONFIDENCE_WEAK = 0.4  # a pattern that also occurs in benign software

# Capabilities whose results are a page of a longer list: the data key holding
# it, and what an item is called. Their observations state how much of the
# list they cover, so the orchestrator never reads silence as proof of absence.
PAGED_CAPABILITIES: dict[str, tuple[str, str]] = {
    "list_imports": ("imports", "imports"),
    "list_exports": ("exports", "exports"),
    "extract_strings": ("strings", "strings"),
    "scan_yara": ("matches", "YARA matches"),
    "run_capa": ("findings", "capa findings"),
    "list_functions": ("functions", "functions"),
    "disassemble_function": ("instructions", "instructions"),
}

# The claim when an envelope carries no list total to state coverage from.
PAGE_CAVEAT = "within the returned page"

STANDARD_SECTION_NAMES = frozenset({
    ".text", ".data", ".rdata", ".idata", ".edata", ".pdata", ".xdata",
    ".rsrc", ".reloc", ".bss", ".tls", ".debug", ".didat", ".sdata", ".crt",
})

ANTI_DEBUG_IMPORTS = frozenset({
    "isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess",
    "outputdebugstring", "ntsetinformationthread", "debugactiveprocess",
})
INJECTION_IMPORTS = frozenset({
    "virtualallocex", "writeprocessmemory", "createremotethread", "openprocess",
    "ntunmapviewofsection", "queueuserapc", "setwindowshookex", "resumethread",
    "ntwritevirtualmemory", "rtlcreateuserthread",
})
CRYPTO_IMPORTS = frozenset({
    "cryptacquirecontext", "cryptencrypt", "cryptdecrypt", "cryptgenkey",
    "cryptderivekey", "crypthashdata", "bcryptencrypt", "bcryptdecrypt",
})
NETWORK_IMPORTS = frozenset({
    "internetopen", "internetopenurl", "internetreadfile", "httpsendrequest",
    "urldownloadtofile", "wsastartup", "winhttpopen", "winhttpsendrequest",
    "gethostbyname", "socket", "connect", "send", "recv",
})
# Resolving APIs at run time hides them from the import table, so a table
# that looks clean is not proof of a clean program (R14). Benign loaders use
# these too, hence weak.
RUNTIME_RESOLUTION_IMPORTS = frozenset({
    "loadlibrary", "loadlibraryex", "getprocaddress", "ldrloaddll", "ldrgetprocedureaddress",
})
IMPORT_CATEGORIES: tuple[tuple[str, frozenset[str], float], ...] = (
    ("anti-debugging", ANTI_DEBUG_IMPORTS, CONFIDENCE_STRONG),
    ("process injection", INJECTION_IMPORTS, CONFIDENCE_STRONG),
    ("cryptography", CRYPTO_IMPORTS, CONFIDENCE_WEAK),
    ("network communication", NETWORK_IMPORTS, CONFIDENCE_MODERATE),
    ("run-time API resolution", RUNTIME_RESOLUTION_IMPORTS, CONFIDENCE_WEAK),
)

# Instructions used to detect a debugger, a VM, or a timing harness.
ANTI_ANALYSIS_MNEMONICS = frozenset({
    "rdtsc", "cpuid", "int3", "ud2", "sidt", "sgdt", "sldt", "smsw", "str", "in",
})

URL_PATTERN = re.compile(r"\b(?:https?|ftp)://\S+", re.IGNORECASE)
IP_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)
REGISTRY_PATTERN = re.compile(
    r"(?:HKEY_[A-Z_]+|HKLM|HKCU|SOFTWARE\\|SYSTEM\\CurrentControlSet)[\\\w]*",
    re.IGNORECASE,
)
STRING_CATEGORIES: tuple[tuple[str, re.Pattern[str], float], ...] = (
    ("URL", URL_PATTERN, CONFIDENCE_STRONG),
    ("registry path", REGISTRY_PATTERN, CONFIDENCE_MODERATE),
    # Dotted quads also appear in version numbers, so this one stays weak.
    ("IP literal", IP_PATTERN, CONFIDENCE_WEAK),
)

IMAGE_FILE_DLL = 0x2000


class Signal(NamedTuple):
    """One readable observation and how strongly the result supports it.

    The identifier, capability, and provenance are attached by the specialist,
    which is the one place that sees every result in order (KTD1).
    """

    observation: str
    confidence: float


def normalize(capability: str, result: dict, prior: dict[str, dict]) -> list[Signal]:
    """Normalize one capability result envelope into zero or more signals.

    A result that is not `status: ok` carries `data: None` and yields nothing
    (R4). `prior` is the results seen earlier this run; two signals are only
    meaningful against a fact another capability reported.
    """
    if result.get("status") != "ok":
        return []
    normalizer = NORMALIZERS.get(capability)
    if normalizer is None:
        return []
    data = result.get("data") or {}
    return normalizer(data, prior, _coverage(capability, data, result.get("metadata") or {}))


def _coverage(capability: str, data: dict, metadata: dict) -> str:
    """How much of a paged list this result holds, as a phrase (R16).

    Read from the envelope's paging counters (KTD2), so a collected list and a
    single page are described by the same rule.
    """
    if capability not in PAGED_CAPABILITIES:
        return ""
    key, noun = PAGED_CAPABILITIES[capability]
    total, offset = metadata.get("total"), metadata.get("offset") or 0
    if total is None:
        return PAGE_CAVEAT
    held = len(data.get(key) or [])
    if offset:
        return f"within {held} of {total} {noun} fetched from offset {offset}"
    if held >= total:
        return f"among all {total} {noun}"
    return f"within the first {held} of {total} {noun} fetched"


def _analyze_pe(data: dict, prior: dict[str, dict], coverage: str) -> list[Signal]:
    signals = []
    for section in data.get("sections") or []:
        name = section.get("name") or "(unnamed)"
        entropy = section.get("entropy") or 0.0
        if entropy >= PACKED_SECTION_ENTROPY:
            signals.append(Signal(
                f"Section {name!r} has entropy {entropy:.2f}, at or above the "
                f"{PACKED_SECTION_ENTROPY} threshold that suggests packed or encrypted content.",
                _entropy_confidence(entropy, PACKED_SECTION_ENTROPY),
            ))
        if name.lower() not in STANDARD_SECTION_NAMES:
            signals.append(Signal(
                f"Section {name!r} is not one of the section names a standard "
                f"toolchain emits, which packers and manual PE authors often produce.",
                CONFIDENCE_MODERATE,
            ))
    return signals


def _detect_packer(data: dict, prior: dict[str, dict], coverage: str) -> list[Signal]:
    indicators = data.get("indicators") or []
    if not data.get("packed") and not indicators:
        return []
    packer = data.get("packer") or "an unidentified packer"
    detail = f" ({'; '.join(indicators[:MAX_EXAMPLES])})" if indicators else ""
    return [Signal(
        f"Packing detection reports {packer}{detail}.",
        # The detector scored its own match; that is a measurement of the
        # signal, not a model's self-report, so it is usable as-is.
        float(data.get("confidence") or CONFIDENCE_MODERATE),
    )]


def _list_imports(data: dict, prior: dict[str, dict], coverage: str) -> list[Signal]:
    imports = data.get("imports") or []
    names = [entry.get("name") for entry in imports if entry.get("name")]
    signals = []
    for label, vocabulary, confidence in IMPORT_CATEGORIES:
        matched = [name for name in names if _is_known(name, vocabulary)]
        if matched:
            signals.append(Signal(
                f"Imports associated with {label} appear {coverage}: "
                f"{_examples(matched)}.",
                confidence,
            ))
    nameless = len(imports) - len(names)
    if nameless:
        # Benign code imports some DLLs by ordinal too, so this is weak.
        signals.append(Signal(
            f"{nameless} of {len(imports)} imports {coverage} have no name and are imported by "
            f"ordinal only, which hides which functions the program uses.",
            CONFIDENCE_WEAK,
        ))
    return signals


def _list_exports(data: dict, prior: dict[str, dict], coverage: str) -> list[Signal]:
    exports = data.get("exports") or []
    if not exports:
        return []
    signals = []
    unnamed = [entry for entry in exports if not entry.get("name")]
    if unnamed:
        signals.append(Signal(
            f"{len(unnamed)} of {len(exports)} exports {coverage} are reachable only "
            f"by ordinal, which hides their purpose from static inspection.",
            _fraction_confidence(len(unnamed), len(exports)),
        ))
    if _is_pe_without_dll_flag(prior):
        signals.append(Signal(
            f"The file exports {len(exports)} symbols {coverage} although its PE header "
            f"does not set the DLL characteristic.",
            CONFIDENCE_MODERATE,
        ))
    return signals


def _extract_strings(data: dict, prior: dict[str, dict], coverage: str) -> list[Signal]:
    values = [entry.get("value") or "" for entry in data.get("strings") or []]
    signals = []
    for label, pattern, confidence in STRING_CATEGORIES:
        matched = [match.group(0) for value in values for match in [pattern.search(value)] if match]
        if matched:
            signals.append(Signal(
                f"Strings containing a {label} appear {coverage}: {_examples(matched)}.",
                confidence,
            ))
    return signals


def _calculate_entropy(data: dict, prior: dict[str, dict], coverage: str) -> list[Signal]:
    signals = []
    entropy = data.get("entropy") or 0.0
    if entropy >= HIGH_REGION_ENTROPY:
        signals.append(Signal(
            f"The {data.get('length') or 0} bytes at offset {data.get('offset') or 0} have entropy {entropy:.2f}, "
            f"at or above the {HIGH_REGION_ENTROPY} threshold that suggests compressed or encrypted content.",
            _entropy_confidence(entropy, HIGH_REGION_ENTROPY),
        ))
    # A packed stub can hide inside a region whose average looks ordinary.
    chunks = data.get("chunks") or []
    high = [chunk for chunk in chunks if (chunk.get("entropy") or 0.0) >= HIGH_REGION_ENTROPY]
    if high:
        signals.append(Signal(
            f"{len(high)} of {len(chunks)} windows have entropy at or above the {HIGH_REGION_ENTROPY} "
            f"threshold, at offsets {_examples([chunk.get('offset') for chunk in high])}.",
            _entropy_confidence(max(chunk["entropy"] for chunk in high), HIGH_REGION_ENTROPY),
        ))
    return signals


def _scan_yara(data: dict, prior: dict[str, dict], coverage: str) -> list[Signal]:
    matches = data.get("matches") or []
    signals = []
    for match in matches[:MAX_RULE_SIGNALS]:
        tags = ", ".join(match.get("tags") or [])
        suffix = f" tagged {tags}" if tags else ""
        signals.append(Signal(
            f"YARA rule {match.get('rule')!r} from namespace "
            f"{match.get('namespace') or '(default)'!r} matched this artifact{suffix} "
            f"({coverage}).",
            CONFIDENCE_RULE_MATCH,
        ))
    return signals + _remainder(len(matches), "YARA rules matched", coverage)


def _run_capa(data: dict, prior: dict[str, dict], coverage: str) -> list[Signal]:
    findings = data.get("findings") or []
    signals = []
    for finding in findings[:MAX_RULE_SIGNALS]:
        namespace = finding.get("namespace") or "(uncategorized)"
        signals.append(Signal(
            f"capa identified the capability {finding.get('rule_id')!r} "
            f"({namespace}) in this artifact ({coverage}).",
            CONFIDENCE_RULE_MATCH,
        ))
    return signals + _remainder(len(findings), "capa capabilities were identified", coverage)


def _list_functions(data: dict, prior: dict[str, dict], coverage: str) -> list[Signal]:
    functions = data.get("functions") or []
    size = _reported_size(prior)
    if size < MIN_SIZE_FOR_DENSITY:
        return []
    density = len(functions) / (size / 1024)
    if density >= LOW_FUNCTION_DENSITY:
        return []
    return [Signal(
        f"Only {len(functions)} functions were discovered {coverage} in a {size}-byte file, "
        f"far below the density a normally compiled binary shows; code may be packed, "
        f"obfuscated, or generated at runtime.",
        CONFIDENCE_MODERATE,
    )]


def _disassemble_function(data: dict, prior: dict[str, dict], coverage: str) -> list[Signal]:
    mnemonics = [
        instruction.get("mnemonic") or ""
        for instruction in data.get("instructions") or []
    ]
    matched = sorted({m.lower() for m in mnemonics if m.lower() in ANTI_ANALYSIS_MNEMONICS})
    if not matched:
        return []
    return [Signal(
        f"The function at {data.get('function_address')} uses instructions associated with "
        f"anti-analysis checks {coverage}: {', '.join(matched)}.",
        CONFIDENCE_MODERATE,
    )]


def _file_info(data: dict, prior: dict[str, dict], coverage: str) -> list[Signal]:
    signals = []
    entropy = data.get("entropy") or 0.0
    if entropy >= HIGH_REGION_ENTROPY:
        signals.append(Signal(
            f"Whole-file entropy is {entropy:.2f}, at or above the {HIGH_REGION_ENTROPY} "
            f"threshold that suggests the bulk of the file is compressed or encrypted.",
            _entropy_confidence(entropy, HIGH_REGION_ENTROPY),
        ))
    if data.get("file_type") == "unknown":
        # ponytail: the plan's intended signal here is a declared type that
        # contradicts the filename extension, but the artifact record carries
        # no original filename - thread one through ArtifactStore.register to
        # get it. An unidentifiable type is the derivable cousin.
        signals.append(Signal(
            "The file's type could not be identified from its header, so the "
            "format-specific capabilities cannot be applied to it.",
            CONFIDENCE_WEAK,
        ))
    return signals


NORMALIZERS: dict[str, Callable[[dict, dict[str, dict], str], list[Signal]]] = {
    "analyze_pe": _analyze_pe,
    "detect_packer": _detect_packer,
    "list_imports": _list_imports,
    "list_exports": _list_exports,
    "extract_strings": _extract_strings,
    "calculate_entropy": _calculate_entropy,
    "scan_yara": _scan_yara,
    "run_capa": _run_capa,
    "list_functions": _list_functions,
    "disassemble_function": _disassemble_function,
    "file_info": _file_info,
}


def _entropy_confidence(value: float, threshold: float) -> float:
    """How far past the threshold the measurement sits, as 0.5..1.0."""
    span = MAX_BYTE_ENTROPY - threshold
    over = min(1.0, max(0.0, (value - threshold) / span)) if span else 1.0
    return round(BASE_CONFIDENCE + (1.0 - BASE_CONFIDENCE) * over, 2)


def _fraction_confidence(part: int, whole: int) -> float:
    """A signal covering most of a page is stronger than one covering a corner."""
    if not whole:
        return BASE_CONFIDENCE
    return round(BASE_CONFIDENCE + (1.0 - BASE_CONFIDENCE) * (part / whole), 2)


def _is_known(name: str, vocabulary: frozenset[str]) -> bool:
    """Match an import, tolerating the ANSI/wide suffix on the Win32 pairs."""
    lowered = name.lower()
    return lowered in vocabulary or (
        lowered.endswith(("a", "w")) and lowered[:-1] in vocabulary
    )


def _remainder(total: int, what: str, coverage: str) -> list[Signal]:
    """Account for rule hits past the cap, so the count is never lost."""
    if total <= MAX_RULE_SIGNALS:
        return []
    return [Signal(
        f"A further {total - MAX_RULE_SIGNALS} {what} {coverage}, beyond the "
        f"{MAX_RULE_SIGNALS} named individually; the full list is in the run trace.",
        CONFIDENCE_RULE_MATCH,
    )]


def _examples(values: list[str]) -> str:
    shown = ", ".join(repr(value) for value in values[:MAX_EXAMPLES])
    remainder = len(values) - MAX_EXAMPLES
    return f"{shown} and {remainder} more" if remainder > 0 else shown


def _reported_size(prior: dict[str, dict]) -> int:
    return int((_data(prior, "file_info").get("size")) or 0)


def _is_pe_without_dll_flag(prior: dict[str, dict]) -> bool:
    header = _data(prior, "analyze_pe").get("coff_header") or {}
    characteristics = header.get("characteristics")
    return characteristics is not None and not characteristics & IMAGE_FILE_DLL


def _data(prior: dict[str, dict], capability: str) -> dict[str, Any]:
    result = prior.get(capability) or {}
    if result.get("status") != "ok":
        return {}
    return result.get("data") or {}
