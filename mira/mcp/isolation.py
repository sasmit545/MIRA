"""Process isolation for analysis of untrusted artifacts.

Specialist-agnostic: a job names the module that knows how to run it, so this
module never imports an analysis library or names a capability.
"""

from __future__ import annotations

from contextlib import chdir
from dataclasses import dataclass
from math import ceil
from multiprocessing import get_context
from pathlib import Path
from queue import Empty
from tempfile import TemporaryDirectory
from typing import Any

from mira.core.artifact import Artifact


@dataclass(frozen=True)
class AnalysisLimits:
    timeout_seconds: float = 15.0
    max_concurrent: int = 2
    cpu_seconds: int = 10
    memory_bytes: int = 512 * 1024 * 1024

    def __post_init__(self) -> None:
        if self.timeout_seconds <= 0 or self.max_concurrent < 1 or self.cpu_seconds < 1 or self.memory_bytes < 1:
            raise ValueError("analysis limits must be positive and allow at least one worker")


@dataclass(frozen=True)
class AnalysisJob:
    capability: str
    artifact: Artifact
    parameters: dict[str, Any]
    rulesets: dict[str, Path]
    capa_rules_dir: Path | None
    #: Dotted path to the specialist module whose `invoke(job)` runs this.
    #: A string rather than a callable so it crosses the spawn boundary and
    #: is imported in the child, keeping analysis libraries out of the parent.
    dispatch: str


@dataclass(frozen=True)
class ExecutionResult:
    status: str
    response: dict | None = None
    message: str | None = None


def run_isolated(job: AnalysisJob, limits: AnalysisLimits) -> ExecutionResult:
    """Run one capability in a killable child process."""
    context = get_context("spawn")
    output = context.Queue(maxsize=1)
    process = context.Process(target=_worker, args=(output, job, limits))
    try:
        process.start()
    except OSError as error:
        output.close()
        output.join_thread()
        return ExecutionResult("resource_limit", message=str(error))
    try:
        # Read before joining. The queue is a pipe with a finite OS buffer: a
        # worker putting more than fits blocks in its feeder thread until this
        # process drains it, and cannot exit while it does. Joining first
        # therefore waits out the whole timeout and reports a healthy analysis
        # as a timeout - which silently capped every paginated capability at
        # whatever page the buffer happened to fit.
        try:
            response = output.get(timeout=limits.timeout_seconds)
        except Empty:
            if process.is_alive():
                process.terminate()
                process.join()
                return ExecutionResult("timeout", message="analysis exceeded the configured timeout")
            return ExecutionResult(
                "resource_limit" if process.exitcode else "failed",
                message="analysis worker exited without a result",
            )
        # Draining unblocked the worker, so this returns promptly.
        process.join(limits.timeout_seconds)
        if process.is_alive():
            process.terminate()
            process.join()
    finally:
        output.close()
        output.join_thread()
    if response.get("status") == "worker_error":
        return ExecutionResult("failed", message=response["message"])
    return ExecutionResult("ok", response=response)


def _worker(output, job: AnalysisJob, limits: AnalysisLimits) -> None:
    try:
        _apply_platform_limits(limits)
        with TemporaryDirectory(prefix="mira-analysis-") as temporary_directory:
            with chdir(temporary_directory):
                response = _invoke(job)
        output.put(response)
    except Exception as error:
        output.put({"status": "worker_error", "message": str(error)})


def _invoke(job: AnalysisJob) -> dict:
    """Hand the job to the specialist that owns it.

    Imported here rather than at module scope so the analysis libraries load
    in this child process only.
    """
    from importlib import import_module

    return import_module(job.dispatch).invoke(job)


def _apply_platform_limits(limits: AnalysisLimits) -> None:
    """Apply OS resource limits when the current platform supports them."""
    try:
        import resource
    except ImportError:
        return
    resource.setrlimit(resource.RLIMIT_CPU, (ceil(limits.cpu_seconds), ceil(limits.cpu_seconds)))
    resource.setrlimit(resource.RLIMIT_AS, (limits.memory_bytes, limits.memory_bytes))
