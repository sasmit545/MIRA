"""Wiring that makes a reasoning run a *static* investigation.

Dynamic and Forensics will each need their own equivalent of this module —
their own capability manifest, their own client, their own role and scope.
None of it is shared, which is why it lives beside the specialist rather than
in the reasoning package.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from mira.core.artifact import ArtifactStore
from mira.mcp.isolation import AnalysisLimits
from mira.mcp.servers.static.capabilities import STATIC_CAPABILITIES
from mira.mcp.client import StaticMCPClient
from mira.mcp.servers.static.server import StaticMCPServer
from mira.reasoning.contracts.tool import ToolSpec

ARTIFACT_ID = "sample"

STATIC_ROLE = "You are a static malware investigator."
STATIC_SCOPE = (
    "Static analysis only. The artifact under investigation is bound by the runtime, "
    "so tool arguments never need to name it."
)


@lru_cache(maxsize=None)
def _capability_specs() -> tuple[ToolSpec, ...]:
    """Build the specs once.

    `input_schema` is a pydantic `model_json_schema()`, which is regenerated
    on every access, and a specialist rebuilds the manifest for each objective
    it is assigned. STATIC_CAPABILITIES is fixed at import, so the result is
    stable.
    """
    return tuple(
        ToolSpec(
            name=definition.name,
            description=definition.description,
            parameters=definition.input_schema,
        )
        for definition in STATIC_CAPABILITIES.values()
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


def _analysis_limits() -> AnalysisLimits:
    """capa's vivisect backend is far slower than every other capability -
    measured 24-36s against the vendored rule set on a trivial sample.

    Override MIRA_ANALYSIS_TIMEOUT_SECONDS directly; otherwise this bumps the
    default once run_capa actually has rules to run (vendored or configured),
    leaving the rest of the static suite (fast) on the 15s default.
    """
    timeout = os.getenv("MIRA_ANALYSIS_TIMEOUT_SECONDS")
    if timeout:
        return AnalysisLimits(timeout_seconds=float(timeout))
    if _configured_capa_rules_dir() is not None:
        return AnalysisLimits(timeout_seconds=90.0)
    return AnalysisLimits()


def build_client(sample_path: Path) -> tuple[StaticMCPClient, str]:
    """Register the sample and return a client bound to its store."""
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
        return client.invoke(capability, artifact_id=artifact_id, **parameters)

    return execute
