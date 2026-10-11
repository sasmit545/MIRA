"""Wiring that makes a reasoning run a *static* investigation.

Dynamic and Forensics will each need their own equivalent of this module —
their own capability manifest, their own client, their own role and scope.
None of it is shared, which is why it lives beside the specialist rather than
in the reasoning package.
"""

from __future__ import annotations

import os
from collections import Counter
from functools import lru_cache
from pathlib import Path

from mira.agents.static.evidence import normalize
from mira.core.artifact import ArtifactStore
from mira.core.evidence import Evidence
from mira.core.state import InvestigationState
from mira.mcp.isolation import AnalysisLimits
from mira.mcp.servers.static.capabilities import STATIC_CAPABILITIES
from mira.mcp.client import StaticMCPClient
from mira.mcp.servers.static.server import StaticMCPServer
from mira.reasoning.contracts.tool import ToolSpec
from mira.reasoning.runtime.trace import trace_provenance

ARTIFACT_ID = "sample"
SOURCE_AGENT = "static"

STATIC_ROLE = "You are a static malware investigator."
STATIC_SCOPE = (
    "Static analysis only. The artifact under investigation is bound by the runtime, "
    "so tool arguments never need to name it."
)

# Capabilities one call collects whole (KTD1): the data key holding the list,
# and the item cap that bounds the walk (KTD3). The cap is a tuning knob,
# calibrated from the benchmark like the thresholds in evidence.py.
COLLECTED_CAPABILITIES = {"list_imports": ("imports", 10_000)}
PAGE_SIZE = 1000  # the MCP input contracts' page bound (le=1000)


@lru_cache(maxsize=None)
def _capability_specs() -> tuple[ToolSpec, ...]:
    """Build the specs once.

    `input_schema` is a pydantic `model_json_schema()`, which is regenerated
    on every access, and a specialist rebuilds the manifest for each objective
    it is assigned. STATIC_CAPABILITIES is fixed at import, so the result is
    stable.
    """
    return tuple(_spec(definition) for definition in STATIC_CAPABILITIES.values())


def _spec(definition) -> ToolSpec:
    """A collected capability hides `limit` (KTD10): the walk picks page sizes,
    so prompt cost no longer depends on one the model chose."""
    parameters = definition.input_schema
    if definition.name not in COLLECTED_CAPABILITIES:
        return ToolSpec(name=definition.name, description=definition.description, parameters=parameters)
    cap = COLLECTED_CAPABILITIES[definition.name][1]
    parameters = {
        **parameters,
        "properties": {name: value for name, value in parameters["properties"].items() if name != "limit"},
        "required": [name for name in parameters.get("required", []) if name != "limit"],
    }
    return ToolSpec(
        name=definition.name,
        description=f"{definition.description} Returns the whole list in one call, up to {cap} items; "
        "offset starts it later.",
        parameters=parameters,
    )


def tool_manifest() -> list[ToolSpec]:
    """Expose the registered MCP capabilities as tool specs for the model."""
    return list(_capability_specs())


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _configured_yara_rulesets() -> dict[str, Path]:
    """Named YARA rulesets: every .yar/.yara file under MIRA_YARA_RULES_DIR,
    keyed by filename stem. Falls back to the vendored snapshot at
    rules/signature-base/yara (see scripts/fetch_rules.sh) when the env var
    isn't set, so a fresh clone works with no setup.
    """
    directory = os.getenv("MIRA_YARA_RULES_DIR") or str(_repo_root() / "rules" / "signature-base" / "yara")
    root = Path(directory)
    if not root.is_dir():
        return {}
    return {path.stem: path for pattern in ("*.yar", "*.yara") for path in root.glob(pattern)}


def _configured_capa_rules_dir() -> Path | None:
    """capa's rule tree, via MIRA_CAPA_RULES_DIR or the vendored rules/capa."""
    directory = os.getenv("MIRA_CAPA_RULES_DIR") or str(_repo_root() / "rules" / "capa")
    root = Path(directory)
    return root if root.is_dir() else None


def _submodule_uninitialized(directory: Path) -> bool:
    """True when git registered the submodule path (so the directory exists)
    but its contents were never checked out - i.e. nobody ran
    `git submodule update --init`."""
    return directory.is_dir() and not any(directory.iterdir())


def _check_vendored_rules_initialized() -> None:
    """Fail fast and clearly when a vendored rules submodule is present but
    empty, instead of letting run_capa/scan_yara degrade to a generic
    TOOL_NOT_AVAILABLE/INVALID_INPUT deep inside an investigation with
    nothing pointing back at the actual cause. This only ever fires for the
    "forgot to init" case: an explicit MIRA_*_RULES_DIR override skips it,
    and a deliberately-absent ruleset isn't representable here - after
    cloning this repo, the vendored path always exists (empty) until the
    submodule is initialized.
    """
    if os.getenv("MIRA_CAPA_RULES_DIR") is None and _submodule_uninitialized(_repo_root() / "rules" / "capa"):
        raise RuntimeError("rules/capa is empty - run: git submodule update --init")
    if os.getenv("MIRA_YARA_RULES_DIR") is None and _submodule_uninitialized(_repo_root() / "rules" / "signature-base"):
        raise RuntimeError("rules/signature-base is empty - run: git submodule update --init")


def _analysis_limits() -> AnalysisLimits:
    """capa's vivisect backend is far slower than every other capability -
    24-36s against the vendored rule set on a trivial synthetic PE, but 152s
    against a real one (notepad.exe: ~350KB, actual compiled code) - vivisect's
    cost scales with how much code there is to disassemble, and malware
    samples can easily be larger or denser than that.

    Override MIRA_ANALYSIS_TIMEOUT_SECONDS directly; otherwise this bumps the
    default once run_capa actually has rules to run (vendored or configured),
    leaving the rest of the static suite (fast) on the 15s default.
    """
    timeout = os.getenv("MIRA_ANALYSIS_TIMEOUT_SECONDS")
    if timeout:
        return AnalysisLimits(timeout_seconds=float(timeout))
    if _configured_capa_rules_dir() is not None:
        return AnalysisLimits(timeout_seconds=300.0)
    return AnalysisLimits()


def build_client(sample_path: Path) -> tuple[StaticMCPClient, str]:
    """Register the sample and return a client bound to its store."""
    _check_vendored_rules_initialized()
    store = ArtifactStore(sample_path.parent)
    store.register(ARTIFACT_ID, sample_path)
    server = StaticMCPServer(
        store,
        rulesets=_configured_yara_rulesets(),
        capa_rules_dir=_configured_capa_rules_dir(),
        limits=_analysis_limits(),
    )
    return StaticMCPClient(server), ARTIFACT_ID


def build_executor(client: StaticMCPClient, artifact_id: str):
    """Bind the artifact so the model never chooses which sample to analyze.

    Any model-supplied `artifact_id` is stripped and replaced with the real
    one, so a model cannot retarget another sample.
    """

    def execute(capability: str, arguments: dict):
        parameters = {**arguments}
        parameters.pop("artifact_id", None)
        if capability in COLLECTED_CAPABILITIES:
            return _collect(client, capability, artifact_id, parameters)
        return client.invoke(capability, artifact_id=artifact_id, **parameters)

    return execute


async def _collect(client: StaticMCPClient, capability: str, artifact_id: str, parameters: dict) -> dict:
    """Walk a paged capability from the model's offset until its list ends or
    the cap is reached, and return one envelope holding every item (KTD1).

    The merged metadata states coverage (KTD2): `total`, `fetched` and
    `unfetched` items, `pages` walked, and `next_offset` when items remain.
    A failure after the first page keeps what was fetched and names itself in
    `fetch_error` (R3); a first-page failure is the capability's own.
    """
    key, cap = COLLECTED_CAPABILITIES[capability]
    parameters.pop("limit", None)
    start = parameters.pop("offset", 0)
    first = await client.invoke(capability, artifact_id=artifact_id, **parameters, offset=start, limit=min(PAGE_SIZE, cap))
    if first.get("status") != "ok":
        return first
    # Walk on from the offset the server validated: the model may send "500".
    start = first["metadata"].get("offset", start)
    items = list(first["data"][key])
    has_more = first["metadata"]["has_more"]
    pages, fetch_error = 1, None
    while has_more and len(items) < cap:
        pages += 1
        try:
            page = await client.invoke(
                capability, artifact_id=artifact_id, **parameters,
                offset=start + len(items), limit=min(PAGE_SIZE, cap - len(items)),
            )
        except Exception as error:  # keep the pages already fetched
            fetch_error = f"{type(error).__name__}: {error}"
            break
        if page.get("status") != "ok":
            error = page.get("error") or {}
            fetch_error = f"{error.get('code') or page.get('status')}: {error.get('message') or page.get('status')}"
            break
        if not page["data"][key]:
            break  # a page that adds nothing would walk the same offset forever
        items.extend(page["data"][key])
        has_more = page["metadata"]["has_more"]

    total = first["metadata"]["total"]
    metadata = {key: value for key, value in first["metadata"].items() if key != "limit"}
    metadata.update(offset=start, has_more=start + len(items) < total, total=total,
                    fetched=len(items), unfetched=total - len(items), pages=pages)
    if metadata["has_more"]:
        metadata["next_offset"] = start + len(items)
    if fetch_error:
        metadata["fetch_error"] = fetch_error
    return {**first, "data": {**first["data"], key: items}, "metadata": metadata}


def build_evidence_executor(
    invoke,
    *,
    run_id: str,
    artifact_id: str,
    evidence: list[Evidence],
    state: InvestigationState | None = None,
):
    """Wrap `invoke` so each result is normalized into evidence as it arrives.

    The specialist is the one place that sees every result in order, so it is
    where evidence identifiers are minted (KTD1). `evidence` is the caller's
    accumulator, appended to in place; `state`, when given, also receives each
    item so it outlives the run. Without a state the run only mints and
    renders, which is what the CLI wants.

    Positions are counted per capability: the runtime refuses a capability
    outside the objective before it reaches this executor, yet the refusal
    still reaches the trace, so a single run-wide counter drifts from it.
    """
    results: dict[str, dict] = {}
    occurrences: Counter[str] = Counter()
    # Numbering continues past whatever the shared state already holds: two
    # runs both minting "E1" would leave their findings citing an identifier
    # the orchestrator cannot resolve to one observation.
    minted = len(state.evidence) if state is not None else 0

    async def execute(capability: str, arguments: dict):
        # Claimed before invoking: a call that raises still reaches the trace
        # as a failed result, so it occupies this capability's occurrence too.
        provenance = trace_provenance(run_id, capability, occurrences[capability])
        occurrences[capability] += 1
        result = await invoke(capability, arguments)
        # `results` is deliberately read before this result joins it: a
        # normalizer's `prior` is what earlier capabilities reported.
        for signal in normalize(capability, result, results):
            item = Evidence(
                id=f"E{minted + len(evidence) + 1}",
                observation=signal.observation,
                source_agent=SOURCE_AGENT,
                capability=capability,
                artifact_id=artifact_id,
                confidence=signal.confidence,
                provenance=provenance,
            )
            evidence.append(item)
            if state is not None:
                # add_evidence already logs the change into its history.
                state.add_evidence(item)
        results[capability] = result
        return result

    return execute
