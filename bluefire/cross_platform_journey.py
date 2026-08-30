"""Runtime evidence producer for the GATE-11 cross-platform contract.

The Windows proof uses the packaged runner through the managed mTLS host and
the ordinary :class:`BlueFireService` Execute surface.  Linux is intentionally
fail closed behind one literal WSL2 distribution identity; the journey never
installs a distribution and exposes no command or distribution input.  macOS
evidence is source-structural only.
"""

from __future__ import annotations

import base64
import json
import os
import queue
import re
import shutil
import stat
import subprocess  # nosec B404 - every command below has a fixed grammar
import sys
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence, cast

from .contracts import load_scenario
from .cross_platform_linux import (
    LinuxDependenciesUnavailableError,
    linux_dependencies_unavailable_report,
    linux_unavailable_report,
    run_linux_journey,
)
from .cross_platform_process_proof import process_tree_cancellation
from .cross_platform_readiness import (
    macos_report,
    platform_readiness_report,
    probe_wsl2,
)
from .cross_platform_recovery import transport_recovery
from .cross_platform_wheel import build_windows_wheel_resource
from .defense_frontier import _runtime_temp_parent
from .receiver_auth import derive_receiver_task_key
from .runner_bootstrap import current_platform
from .runner_client import SubprocessRustRunner
from .runner_lifecycle import (
    ManagedRunnerLifecycle,
    _windows_assign_process,
    _windows_close_handle,
    _windows_create_kill_job,
    _windows_open_process,
    _windows_process_in_job,
    _windows_process_running,
    _windows_terminate_job,
    _windows_terminate_process,
    _windows_wait_job_empty,
)
from .runner_trust import load_local_enrollment
from .service import BlueFireService

WINDOWS_REPORT = "windows-packaged-execute.json"
LINUX_REPORT = "linux-container-execute.json"
CANCELLATION_REPORT = "process-tree-cancellation.json"
RECEIVER_REPORT = "network-receiver.json"
RECOVERY_REPORT = "transport-recovery.json"
READINESS_REPORT = "platform-readiness.json"
MACOS_REPORT = "macos-contract.json"
CLASSIFICATION_REPORT = "proof-classification.json"

REPORT_PATHS = (
    WINDOWS_REPORT,
    LINUX_REPORT,
    CANCELLATION_REPORT,
    RECEIVER_REPORT,
    RECOVERY_REPORT,
    READINESS_REPORT,
    MACOS_REPORT,
    CLASSIFICATION_REPORT,
)

WINDOWS_SCHEMA = "bluefire.cross-platform-windows-execute.v1"
LINUX_SCHEMA = "bluefire.cross-platform-linux-execute.v1"
CANCELLATION_SCHEMA = "bluefire.cross-platform-process-cancellation.v2"
RECEIVER_SCHEMA = "bluefire.cross-platform-network-receiver.v1"
RECOVERY_SCHEMA = "bluefire.cross-platform-transport-recovery.v1"
READINESS_SCHEMA = "bluefire.cross-platform-readiness.v1"
MACOS_SCHEMA = "bluefire.cross-platform-macos-contract.v1"
CLASSIFICATION_SCHEMA = "bluefire.cross-platform-proof-classification.v1"
HELPER_SCHEMA = "bluefire.cross-platform-helper.v1"

WINDOWS_CHECK = "windows_packaged_execute"
LINUX_CHECK = "linux_container_execute"
CANCELLATION_CHECK = "process_tree_cancel"
RECEIVER_CHECK = "network_receiver"
RECOVERY_CHECK = "transport_recovery"
READINESS_CHECK = "platform_readiness"
MACOS_CHECK = "macos_contract"
CLASSIFICATION_CHECK = "proof_classification"

PROFILE_ID = "sandbox-endpoint-deep-lab.v1"
WINDOWS_ONLY_PROFILE_ID = "sandbox-windows-source-intake.v1"
SCENARIO_NAME = "endpoint_deep_behavior_lab.yaml"

ASSERTION_REPORTS: tuple[tuple[str, str, str], ...] = (
    ("GATE-11-WINDOWS-PACKAGED-EXECUTE", "dynamic", WINDOWS_REPORT),
    ("GATE-11-LINUX-CONTAINER-EXECUTE", "dynamic", LINUX_REPORT),
    ("GATE-11-PROCESS-TREE-CANCEL", "dynamic", CANCELLATION_REPORT),
    ("GATE-11-NETWORK-RECEIVER", "dynamic", RECEIVER_REPORT),
    ("GATE-11-TRANSPORT-RECOVERY", "dynamic", RECOVERY_REPORT),
    ("GATE-11-PLATFORM-READINESS", "dynamic", READINESS_REPORT),
    ("GATE-11-MACOS-CONTRACT", "structural", MACOS_REPORT),
    ("GATE-11-PROOF-CLASSIFICATION", "structural", CLASSIFICATION_REPORT),
)
CLASSIFICATION_LIMITATIONS = (
    "macOS evidence is structural because no macOS host is available.",
    (
        "The authenticated receiver is limited to a distinct same-host process on literal "
        "loopback; it is not LAN or remote transport."
    ),
    (
        "The disposable WSL2 execution distribution is stream-cloned from a dedicated "
        "persistent Gate 11 base; its registration and storage are removed after each run."
    ),
    (
        "The process-tree cancellation proof is Windows-specific and exercises one "
        "zero-parameter packaged Rust witness action; it is not a general process launcher."
    ),
)

_RUN_ID = re.compile(r"^run-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}$")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_MAX_REPORT_BYTES = 2 * 1024 * 1024
_MAX_SCAN_BYTES = 128 * 1024 * 1024


class CrossPlatformJourneyError(ValueError):
    """Raised when a dynamic claim cannot be demonstrated exactly."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise CrossPlatformJourneyError(message)


@dataclass(slots=True)
class _ReceiverProcess:
    launcher: subprocess.Popen[str]
    job_handle: int | None
    process_id: int | None = None
    process_handle: int | None = None


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    payload = (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    )
    _require(0 < len(payload) <= _MAX_REPORT_BYTES, "a Gate 11 report exceeded its byte bound")
    _require(path.parent.is_dir() and not path.exists(), "a Gate 11 report destination is stale")
    flags = os.O_CREAT | os.O_EXCL | os.O_RDWR
    flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    identity: tuple[int, int] | None = None
    try:
        descriptor = os.open(path, flags, 0o600)
        opened = os.fstat(descriptor)
        identity = (opened.st_dev, opened.st_ino)
        _require(
            stat.S_ISREG(opened.st_mode) and opened.st_nlink == 1,
            "a Gate 11 report destination is unsafe",
        )
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            _require(written > 0, "a Gate 11 report write made no progress")
            offset += written
        os.fsync(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        observed = bytearray()
        while len(observed) <= _MAX_REPORT_BYTES:
            block = os.read(descriptor, min(64 * 1024, _MAX_REPORT_BYTES + 1 - len(observed)))
            if not block:
                break
            observed.extend(block)
        final = os.fstat(descriptor)
        _require(
            bytes(observed) == payload
            and (final.st_dev, final.st_ino) == identity
            and stat.S_ISREG(final.st_mode)
            and final.st_nlink == 1
            and final.st_size == len(payload),
            "a Gate 11 report changed during publication",
        )
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
            descriptor = None
        try:
            details = path.lstat()
            if identity == (details.st_dev, details.st_ino) and not path.is_symlink():
                path.unlink()
        except OSError:
            pass
        raise
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _child_environment(repository: Path, state_parent: Path) -> dict[str, str]:
    allowed = (
        "COMSPEC",
        "PATH",
        "PATHEXT",
        "PROCESSOR_ARCHITECTURE",
        "SYSTEMROOT",
        "SystemRoot",
        "TEMP",
        "TMP",
        "WINDIR",
    )
    environment = {
        name: os.environ[name]
        for name in allowed
        if isinstance(os.environ.get(name), str) and os.environ[name]
    }
    environment.update(
        {
            "HOME": os.fspath(state_parent),
            "USERPROFILE": os.fspath(state_parent),
            "LOCALAPPDATA": os.fspath(state_parent),
            "APPDATA": os.fspath(state_parent / "Roaming"),
            "PYTHONPATH": os.fspath(repository),
            "PYTHONIOENCODING": "utf-8",
            "PYTHONUTF8": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
    )
    (state_parent / "Roaming").mkdir(exist_ok=True)
    return environment


def _read_process_line(stream: Any, timeout_seconds: float) -> str:
    lines: queue.Queue[str] = queue.Queue(maxsize=1)
    reader = threading.Thread(target=lambda: lines.put(stream.readline()), daemon=True)
    reader.start()
    try:
        return lines.get(timeout=timeout_seconds)
    except queue.Empty as exc:
        raise CrossPlatformJourneyError("the receiver did not publish bounded readiness") from exc


def _stop_receiver_process(receiver: _ReceiverProcess) -> None:
    """Stop the exact receiver job/handle and fail unless the tree is absent."""

    failures: list[BaseException] = []
    if receiver.job_handle is not None:
        try:
            terminated = _windows_terminate_job(receiver.job_handle)
            empty = _windows_wait_job_empty(receiver.job_handle, timeout_seconds=5.0)
            _require(terminated and empty, "the owned receiver job survived cleanup")
        except BaseException as exc:
            failures.append(exc)
        finally:
            _windows_close_handle(receiver.job_handle)
            receiver.job_handle = None
    if receiver.process_handle is not None:
        try:
            if _windows_process_running(receiver.process_handle):
                _require(
                    receiver.process_id is not None
                    and _windows_terminate_process(
                        receiver.process_handle,
                        process_id=receiver.process_id,
                        timeout_seconds=5.0,
                    ),
                    "the exact receiver process survived cleanup",
                )
            _require(
                not _windows_process_running(receiver.process_handle),
                "the exact receiver process survived cleanup",
            )
        except BaseException as exc:
            failures.append(exc)
        finally:
            _windows_close_handle(receiver.process_handle)
            receiver.process_handle = None
    if receiver.launcher.poll() is None:
        try:
            receiver.launcher.terminate()
            receiver.launcher.wait(timeout=5)
        except subprocess.TimeoutExpired:
            receiver.launcher.kill()
            receiver.launcher.wait(timeout=5)
        except BaseException as exc:
            failures.append(exc)
    if receiver.launcher.poll() is None:
        failures.append(CrossPlatformJourneyError("the receiver launcher survived cleanup"))
    if failures:
        raise CrossPlatformJourneyError("the owned receiver process tree survived cleanup") from (
            failures[0]
        )


def _close_completed_receiver(receiver: _ReceiverProcess) -> None:
    """Release retained handles only after natural terminal absence is proven."""

    _require(receiver.launcher.poll() is not None, "the receiver launcher is still running")
    _require(
        receiver.process_handle is not None
        and not _windows_process_running(receiver.process_handle),
        "the receiver process did not reach terminal absence",
    )
    _require(
        receiver.job_handle is not None
        and _windows_wait_job_empty(receiver.job_handle, timeout_seconds=5.0),
        "the receiver job retained a process after completion",
    )
    _windows_close_handle(cast(int, receiver.process_handle))
    _windows_close_handle(cast(int, receiver.job_handle))
    receiver.process_handle = None
    receiver.job_handle = None


def _start_receiver(
    repository: Path,
    state_parent: Path,
) -> tuple[_ReceiverProcess, Mapping[str, Any]]:
    command = [
        os.fspath(Path(sys.executable).resolve(strict=True)),
        "-m",
        "bluefire.cli",
        "receiver",
        "--host",
        "127.0.0.1",
        "--port",
        "0",
        "--max-requests",
        "1",
        "--disposable-peer",
    ]
    options: dict[str, Any] = {
        "cwd": repository,
        "env": _child_environment(repository, state_parent),
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "text": True,
        "encoding": "utf-8",
        "shell": False,
    }
    _require(os.name == "nt", "the packaged Windows receiver requires Windows")
    options["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(
        subprocess, "CREATE_SUSPENDED", 0x0000_0004
    )
    job_handle = _windows_create_kill_job()
    process: subprocess.Popen[str] | None = None
    receiver: _ReceiverProcess | None = None
    try:
        process = subprocess.Popen(command, **options)  # nosec B603 - fixed command
        receiver = _ReceiverProcess(launcher=process, job_handle=job_handle)
        try:
            _windows_assign_process(job_handle, process)  # type: ignore[arg-type]
        except OSError:
            receiver.job_handle = None
            raise
        SubprocessRustRunner._resume_windows_process(process)  # type: ignore[arg-type]
        _require(process.stderr is not None, "the receiver readiness stream is unavailable")
        ready_line = _read_process_line(process.stderr, 15.0)
        if not ready_line:
            process.communicate(timeout=5)
            raise CrossPlatformJourneyError("the receiver exited before readiness")
        ready = json.loads(ready_line)
        _require(
            isinstance(ready, Mapping)
            and set(ready)
            == {
                "schema_version",
                "mode",
                "process_id",
                "host",
                "port",
                "max_requests",
                "max_connections",
                "storage",
            }
            and ready.get("schema_version") == "bluefire.loopback-receiver-ready.v2"
            and ready.get("mode") == "disposable_peer"
            and type(ready.get("process_id")) is int
            and int(ready["process_id"]) > 0
            and ready.get("host") == "127.0.0.1"
            and type(ready.get("port")) is int
            and 1024 <= int(ready["port"]) <= 65535
            and ready.get("max_requests") == 1
            and ready.get("max_connections") == 8
            and ready.get("storage") == "memory_only",
            "the receiver readiness record is invalid",
        )
        receiver.process_id = int(ready["process_id"])
        receiver.process_handle = _windows_open_process(receiver.process_id)
        _require(
            receiver.job_handle is not None
            and _windows_process_in_job(receiver.process_handle, receiver.job_handle),
            "the authenticated receiver escaped its launch job",
        )
        return receiver, dict(ready)
    except BaseException:
        if receiver is not None:
            _stop_receiver_process(receiver)
        else:
            _windows_close_handle(job_handle)
        raise


def _remove_owned_runtime(runtime: Path) -> None:
    parent = _runtime_temp_parent().resolve(strict=True)
    details = runtime.lstat()
    is_reparse = bool(
        int(getattr(details, "st_file_attributes", 0))
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )
    _require(
        runtime.parent.resolve(strict=True) == parent
        and runtime.name.startswith(".gate11-runtime-")
        and stat.S_ISDIR(details.st_mode)
        and not stat.S_ISLNK(details.st_mode)
        and not is_reparse,
        "the Gate 11 runtime ownership boundary changed",
    )
    shutil.rmtree(runtime)
    try:
        runtime.lstat()
    except FileNotFoundError:
        return
    raise CrossPlatformJourneyError("the Gate 11 runtime survived cleanup")


def _close_runtime(
    runtime: Path,
    lifecycle: ManagedRunnerLifecycle,
    service: BlueFireService | None,
    *,
    lifecycle_bootstrapped: bool,
) -> None:
    failures: list[BaseException] = []
    if service is not None:
        try:
            service.close()
        except BaseException as exc:
            failures.append(exc)
    lifecycle_stopped = not lifecycle_bootstrapped
    if lifecycle_bootstrapped:
        try:
            before = lifecycle.status(profile_id=PROFILE_ID)
            process_state = before.get("process")
            if before.get("state") == "ready" or process_state not in {"absent", "stopped"}:
                lifecycle.stop(profile_id=PROFILE_ID)
            after = lifecycle.status(profile_id=PROFILE_ID)
            _require(
                after.get("state") != "ready" and after.get("process") == "absent",
                "the managed lifecycle host survived cleanup",
            )
            lifecycle_stopped = True
        except BaseException as exc:
            failures.append(exc)
    if lifecycle_stopped:
        try:
            _remove_owned_runtime(runtime)
        except BaseException as exc:
            failures.append(exc)
    if failures:
        raise CrossPlatformJourneyError("the Gate 11 runtime did not close cleanly") from failures[
            0
        ]


def _private_trust_material(
    enrollment: Any,
    receiver_task_ids: Sequence[str] = (),
) -> tuple[bytes, ...]:
    enrollment_key = enrollment.hmac_key()
    materials = [
        enrollment_key,
        enrollment.server_key_password(),
        enrollment.client_key_password(),
    ]
    materials.extend(
        derive_receiver_task_key(enrollment_key, task_id) for task_id in receiver_task_ids
    )
    paths = [enrollment.server_private_key, enrollment.client_private_key]
    paths.extend(sorted(enrollment.root.glob("*.secret")))
    for path in paths:
        details = path.lstat()
        _require(
            stat.S_ISREG(details.st_mode)
            and not stat.S_ISLNK(details.st_mode)
            and details.st_nlink == 1
            and 1 <= details.st_size <= 64 * 1024,
            "runner private trust material is unsafe",
        )
        materials.append(path.read_bytes())
    return tuple(dict.fromkeys(materials))


def _scenario_with_receiver(repository: Path, port: int) -> Mapping[str, Any]:
    scenario = load_scenario(repository / "scenarios" / SCENARIO_NAME).to_dict()
    steps = scenario.get("steps")
    _require(isinstance(steps, list), "the maintained endpoint scenario is invalid")
    matched = False
    for step in cast(list[Any], steps):
        if isinstance(step, dict) and step.get("id") == "authorized_peer_handoff":
            parameters = step.get("parameters")
            _require(isinstance(parameters, dict), "the peer step has no fixed parameters")
            cast(dict[str, Any], parameters)["port"] = port
            matched = True
    _require(matched, "the maintained endpoint scenario has no peer handoff")
    return scenario


def _execution_summary(result: Mapping[str, Any]) -> Mapping[str, Any]:
    cleanup = result.get("cleanup")
    run_id = result.get("run_id")
    steps = result.get("steps")
    _require(
        isinstance(run_id, str)
        and _RUN_ID.fullmatch(run_id) is not None
        and result.get("status") == "completed"
        and result.get("objective_reached") is True
        and isinstance(cleanup, Mapping)
        and cleanup.get("success") is True
        and cleanup.get("outstanding_receipt_count") == 0
        and isinstance(steps, list)
        and len(steps) > 0,
        "the packaged Windows Execute run did not reconcile",
    )
    return {
        "run_id": run_id,
        "status": "completed",
        "objective_reached": True,
        "cleanup_success": True,
        "outstanding_receipt_count": 0,
        "step_count": len(cast(list[Any], steps)),
    }


def _receiver_report(
    result: Mapping[str, Any],
    receiver: _ReceiverProcess,
    ready: Mapping[str, Any],
) -> Mapping[str, Any]:
    stdout, stderr = receiver.launcher.communicate(timeout=20)
    _require(
        receiver.launcher.returncode == 0 and stderr == "",
        "the receiver did not terminate cleanly",
    )
    _close_completed_receiver(receiver)
    try:
        summary = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise CrossPlatformJourneyError("the receiver summary is not JSON") from exc
    _require(
        summary
        == {
            "schema_version": "bluefire.loopback-receiver-summary.v1",
            "reason": "max_requests",
            "connections_handled": 2,
            "challenges_issued": 1,
            "requests_accepted": 1,
            "requests_refused": 0,
        },
        "the receiver did not accept exactly one authenticated transfer",
    )
    steps = result.get("steps")
    _require(isinstance(steps, list), "the Windows run has no step evidence")
    peer_step = next(
        (
            step
            for step in cast(list[Any], steps)
            if isinstance(step, Mapping)
            and step.get("behavior_id") == "sandbox.credential.peer-challenge.v1"
        ),
        None,
    )
    artifacts = peer_step.get("artifacts") if isinstance(peer_step, Mapping) else None
    receipt = artifacts.get("receipt") if isinstance(artifacts, Mapping) else None
    authorization = receipt.get("lab_authorization") if isinstance(receipt, Mapping) else None
    peers = receipt.get("lab_peers") if isinstance(receipt, Mapping) else None
    size = receipt.get("size") if isinstance(receipt, Mapping) else None
    digest = receipt.get("sha256") if isinstance(receipt, Mapping) else None
    run_id = result.get("run_id")
    step_id = peer_step.get("step_id") if isinstance(peer_step, Mapping) else None
    runner_task_id = peer_step.get("runner_task_id") if isinstance(peer_step, Mapping) else None
    source_process_id = peers.get("source_process_id") if isinstance(peers, Mapping) else None
    destination_process_id = (
        peers.get("destination_process_id") if isinstance(peers, Mapping) else None
    )
    _require(
        peer_step is not None
        and isinstance(run_id, str)
        and _RUN_ID.fullmatch(run_id) is not None
        and step_id == "authorized_peer_handoff"
        and isinstance(runner_task_id, str)
        and re.fullmatch(r"execute-[0-9a-f]{64}", runner_task_id) is not None
        and peer_step.get("status") == "success"
        and isinstance(authorization, Mapping)
        and authorization.get("scope") == "approved_task"
        and authorization.get("challenge_verified") is True
        and authorization.get("raw_credential_exposed") is False
        and isinstance(peers, Mapping)
        and peers.get("distinct_processes") is True
        and type(source_process_id) is int
        and type(destination_process_id) is int
        and source_process_id != destination_process_id
        and destination_process_id == ready.get("process_id")
        and peers.get("transfer_acknowledged") is True
        and type(size) is int
        and 1 <= int(size) <= 5 * 1024 * 1024
        and isinstance(digest, str)
        and re.fullmatch(r"[0-9a-f]{64}", digest) is not None,
        "the authenticated peer receipt is invalid",
    )
    return {
        "schema_version": RECEIVER_SCHEMA,
        "passed": True,
        "proof_kind": "dynamic",
        "platform": current_platform(),
        "boundary": "same-host-separate-process-loopback",
        "receiver": {
            "host": "127.0.0.1",
            "mode": "disposable_peer",
            "process_id": destination_process_id,
            "process_distinct": True,
            "process_exited": True,
            "requests_accepted": 1,
            "terminal_disposition": "exit_after_response",
        },
        "transfer": {
            "run_id": run_id,
            "step_id": step_id,
            "runner_task_id": runner_task_id,
            "source_process_id": source_process_id,
            "destination_process_id": destination_process_id,
            "authenticated": True,
            "bytes": size,
            "sha256": "sha256:" + cast(str, digest),
        },
    }


def _classification(reports: Mapping[str, Mapping[str, Any]]) -> Mapping[str, Any]:
    proofs: list[Mapping[str, Any]] = []
    prior_passed = True
    for assertion_id, kind, name in ASSERTION_REPORTS:
        if name == CLASSIFICATION_REPORT:
            state = "passed" if prior_passed else "blocked"
        elif name == LINUX_REPORT and reports[name].get("passed") is False:
            state = "unavailable"
        elif name == READINESS_REPORT and reports[name].get("passed") is False:
            state = "blocked"
        else:
            state = "passed" if reports[name].get("passed") is True else "failed"
        proofs.append({"assertion_id": assertion_id, "kind": kind, "state": state, "report": name})
        if name != CLASSIFICATION_REPORT:
            prior_passed = prior_passed and state == "passed"
    return {
        "schema_version": CLASSIFICATION_SCHEMA,
        "passed": prior_passed,
        "proof_kind": "structural",
        "proofs": proofs,
        "limitations": list(CLASSIFICATION_LIMITATIONS),
    }


def _secret_encodings(secret: bytes) -> tuple[bytes, ...]:
    return tuple(
        value
        for value in {
            secret,
            secret.hex().encode("ascii"),
            secret.hex().upper().encode("ascii"),
            base64.b64encode(secret),
            base64.b64encode(secret).rstrip(b"="),
            base64.b32encode(secret),
            base64.urlsafe_b64encode(secret),
            base64.urlsafe_b64encode(secret).rstrip(b"="),
        }
        if value
    )


def _assert_secrets_absent(root: Path, secrets: Sequence[bytes]) -> None:
    encodings = tuple(item for secret in secrets for item in _secret_encodings(secret))
    scanned = 0
    for path in root.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        size = path.stat().st_size
        scanned += size
        _require(scanned <= _MAX_SCAN_BYTES, "the Gate 11 evidence scan exceeded its bound")
        payload = path.read_bytes()
        _require(all(value not in payload for value in encodings), "runner trust material leaked")


def produce_cross_platform_evidence(
    repository: Path,
    evidence_dir: Path,
) -> Mapping[str, Any]:
    """Produce all eight reports and return the strict helper protocol summary."""

    root_details = repository.lstat()
    destination_details = evidence_dir.lstat()
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    _require(
        stat.S_ISDIR(root_details.st_mode)
        and not stat.S_ISLNK(root_details.st_mode)
        and not int(getattr(root_details, "st_file_attributes", 0)) & reparse
        and stat.S_ISDIR(destination_details.st_mode)
        and not stat.S_ISLNK(destination_details.st_mode)
        and not int(getattr(destination_details, "st_file_attributes", 0)) & reparse,
        "the Gate 11 roots are invalid",
    )
    root = repository.resolve(strict=True)
    destination = evidence_dir.resolve(strict=True)
    _require(
        not any((destination / name).exists() for name in (*REPORT_PATHS, "runs", "package")),
        "the Gate 11 evidence destination contains stale owned artifacts",
    )
    _require(current_platform() == "windows", "the Windows packaged journey requires Windows")
    wsl = probe_wsl2()
    probe_state = wsl.get("probe_state")
    if probe_state in {"absent", "incompatible"}:
        _write_json(destination / LINUX_REPORT, linux_unavailable_report(wsl))
        return {
            "schema_version": HELPER_SCHEMA,
            "status": "failed",
            "blocking_check": LINUX_CHECK,
            "reports": list(REPORT_PATHS),
            "run_count": 0,
        }
    _require(
        probe_state == "ready" and wsl.get("configured") is True and wsl.get("version") == "2",
        "the fixed WSL2 readiness probe was indeterminate",
    )

    runtime = Path(tempfile.mkdtemp(prefix=".gate11-runtime-", dir=_runtime_temp_parent()))
    state_parent = runtime / "state"
    state_parent.mkdir()
    lifecycle = ManagedRunnerLifecycle(state_parent / "BlueFire Nexus")
    receiver: _ReceiverProcess | None = None
    service: BlueFireService | None = None
    trust_material: tuple[bytes, ...] = ()
    lifecycle_bootstrapped = False
    cleanup_complete = False
    reports: dict[str, Mapping[str, Any]] = {}
    try:
        try:
            reports[LINUX_REPORT] = run_linux_journey(root, destination, runtime, wsl)
        except LinuxDependenciesUnavailableError:
            _close_runtime(
                runtime,
                lifecycle,
                service,
                lifecycle_bootstrapped=False,
            )
            cleanup_complete = True
            dependency_report = linux_dependencies_unavailable_report(wsl)
            _write_json(destination / LINUX_REPORT, dependency_report)
            return {
                "schema_version": HELPER_SCHEMA,
                "status": "failed",
                "blocking_check": LINUX_CHECK,
                "reports": list(REPORT_PATHS),
                "run_count": 0,
            }
        windows_resource, resource_root = build_windows_wheel_resource(root, destination, runtime)
        lifecycle.bootstrap(
            allowed_profile_ids=(PROFILE_ID,),
            environ={},
            resource_root=resource_root,
        )
        lifecycle_bootstrapped = True
        started = lifecycle.start(profile_id=PROFILE_ID)
        _require(started.get("state") == "ready", "the packaged managed runner did not start")
        enrollment = load_local_enrollment(lifecycle.enrollment_root)
        trust_material = _private_trust_material(enrollment)
        service = BlueFireService(
            project_root=root,
            runs_dir=destination / "runs",
            product_db_path=runtime / "product.sqlite3",
            runner_lifecycle=lifecycle,
        )
        receiver, ready = _start_receiver(root, state_parent)
        result = service.run(
            {
                "scenario": _scenario_with_receiver(root, int(ready["port"])),
                "mode": "execute",
                "runner_profile_id": PROFILE_ID,
                "target_scope": {"scope_refs": ["sandbox.workspace", "network.loopback"]},
                "autonomy": "off",
                "approval": {"confirmed": True, "approved_by": "gate-11-runtime-reviewer"},
            }
        )
        execution = _execution_summary(result)
        _require(
            service.store.validate_bundle(str(execution["run_id"])).get("valid") is True,
            "the Windows run bundle failed integrity validation",
        )
        status = lifecycle.status(profile_id=PROFILE_ID)
        runner = status.get("runner")
        _require(
            isinstance(runner, Mapping)
            and runner.get("source") == "packaged"
            and runner.get("id") == windows_resource["runner_id"]
            and runner.get("runner_version") == windows_resource["runner_version"]
            and runner.get("platform") == windows_resource["platform"]
            and runner.get("architecture") == windows_resource["architecture"]
            and runner.get("binary_digest") == windows_resource["binary_sha256"],
            "the packaged Windows runner identity is invalid",
        )
        reports[WINDOWS_REPORT] = {
            "schema_version": WINDOWS_SCHEMA,
            "passed": True,
            "proof_kind": "dynamic",
            "platform": "windows",
            "environment_type": "disposable",
            "runner": dict(windows_resource),
            "execution": execution,
            "run_bundle": {
                "run_id": execution["run_id"],
                "path": f"runs/{execution['run_id']}",
            },
        }
        reports[RECEIVER_REPORT] = _receiver_report(result, receiver, ready)
        receiver_task_id = reports[RECEIVER_REPORT]["transfer"]["runner_task_id"]
        trust_material = _private_trust_material(enrollment, (str(receiver_task_id),))
        receiver = None
        reports[RECOVERY_REPORT] = transport_recovery(
            service,
            lifecycle,
            require=_require,
        )
        reports[CANCELLATION_REPORT] = process_tree_cancellation(
            runtime,
            resource_root,
            service,
            expected_runner_digest=str(windows_resource["binary_sha256"]),
            require=_require,
        )
        reports[MACOS_REPORT] = macos_report(root, service, _require)
        reports[READINESS_REPORT] = platform_readiness_report(
            root,
            runtime,
            state_parent,
            service,
            reports[LINUX_REPORT],
            reports[MACOS_REPORT],
            wsl,
            child_environment=_child_environment,
            require=_require,
        )
        reports[CLASSIFICATION_REPORT] = _classification(reports)
        _require(
            all(reports[name].get("passed") is True for name in REPORT_PATHS),
            "the complete Gate 11 proof set did not pass",
        )
        _close_runtime(
            runtime,
            lifecycle,
            service,
            lifecycle_bootstrapped=lifecycle_bootstrapped,
        )
        cleanup_complete = True
        for name in REPORT_PATHS:
            _write_json(destination / name, reports[name])
        _assert_secrets_absent(destination, trust_material)
        return {
            "schema_version": HELPER_SCHEMA,
            "status": "passed",
            "blocking_check": None,
            "reports": list(REPORT_PATHS),
            "run_count": 2,
        }
    finally:
        if receiver is not None:
            _stop_receiver_process(receiver)
        if not cleanup_complete and runtime.exists():
            _close_runtime(
                runtime,
                lifecycle,
                service,
                lifecycle_bootstrapped=lifecycle_bootstrapped,
            )
        trust_material = ()
