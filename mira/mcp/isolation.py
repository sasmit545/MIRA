"""Process isolation for static analysis of untrusted artifacts."""

from __future__ import annotations

from contextlib import chdir
from dataclasses import dataclass
from math import ceil
from multiprocessing import get_context
from pathlib import Path
from queue import Empty
from tempfile import TemporaryDirectory
from typing import Any

from mira.artifacts import Artifact


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
    process.join(limits.timeout_seconds)
    if process.is_alive():
        process.terminate()
        process.join()
        return ExecutionResult("timeout", message="analysis exceeded the configured timeout")
    try:
        response = output.get(timeout=0.2)
    except Empty:
        return ExecutionResult("resource_limit" if process.exitcode else "failed", message="analysis worker exited without a result")
    finally:
        output.close()
        output.join_thread()
    if response.get("status") == "worker_error":
        return ExecutionResult("failed", message=response["message"])
    return ExecutionResult("ok", response=response)


def _worker(output, job: AnalysisJob, limits: AnalysisLimits) -> None:
    try:
        _apply_platform_limits(limits)
        with TemporaryDirectory(prefix="mira-static-") as temporary_directory:
            with chdir(temporary_directory):
                response = _invoke(job)
        output.put(response)
    except Exception as error:
        output.put({"status": "worker_error", "message": str(error)})


def _invoke(job: AnalysisJob) -> dict:
    from mira.capabilities.static.capa_analyzer import run_capa
    from mira.capabilities.static.disassembler import disassemble_function
    from mira.capabilities.static.entropy_analyzer import calculate_entropy
    from mira.capabilities.static.export_lister import list_exports
    from mira.capabilities.static.file_info import analyze_file_info
    from mira.capabilities.static.function_analyzer import list_functions
    from mira.capabilities.static.import_lister import list_imports
    from mira.capabilities.static.packer_detector import detect_packer
    from mira.capabilities.static.pe_analyzer import analyze_pe
    from mira.capabilities.static.string_analyzer import extract_strings
    from mira.capabilities.static.yara_scanner import scan_yara

    handlers = {
        "file_info": analyze_file_info,
        "analyze_pe": analyze_pe,
        "list_imports": list_imports,
        "list_exports": list_exports,
        "extract_strings": extract_strings,
        "calculate_entropy": calculate_entropy,
        "detect_packer": detect_packer,
        "scan_yara": scan_yara,
        "run_capa": run_capa,
        "list_functions": list_functions,
        "disassemble_function": disassemble_function,
    }
    if job.capability == "scan_yara":
        return handlers[job.capability](job.artifact, rulesets=job.rulesets, **job.parameters)
    return handlers[job.capability](job.artifact, **job.parameters)


def _apply_platform_limits(limits: AnalysisLimits) -> None:
    """Apply OS resource limits when the current platform supports them."""
    try:
        import resource
    except ImportError:
        return
    resource.setrlimit(resource.RLIMIT_CPU, (ceil(limits.cpu_seconds), ceil(limits.cpu_seconds)))
    resource.setrlimit(resource.RLIMIT_AS, (limits.memory_bytes, limits.memory_bytes))
