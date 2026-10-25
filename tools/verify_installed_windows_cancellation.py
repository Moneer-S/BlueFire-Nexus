"""Verify the installed Windows wheel's approved native cancellation witness.

Copy this verifier and its adjacent Node driver outside the checkout. Run it
with isolated Python after installing the exact wheel under review. The check
uses the shipped Gate 11 profile and ordinary authenticated service endpoints;
it does not alter profile authority or contact external services.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import queue
import re
import shutil
import stat
import subprocess
import sys
import sysconfig
import threading
import time
import zipfile
from email.parser import BytesParser
from pathlib import Path
from typing import Any

PROFILE_ID = "gate11-windows-cancellation-witness.v1"
ACTION_ID = "sandbox.execution.process-tree-cancellation-witness.v1"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MAX_DRIVER_SECONDS = 360
_MAX_REPORT_BYTES = 256 * 1024
_MAX_READY_BYTES = 4096
_MAX_STATE_BYTES = 64 * 1024
_MAX_DRIVER_FRAME_BYTES = 1024
_MAX_WHEEL_BYTES = 128 * 1024 * 1024
_MAX_PACKAGE_BYTES = 256 * 1024 * 1024
_MAX_PACKAGE_FILES = 10000
# Win32 CREATE_SUSPENDED; subprocess stubs omit this supported creation flag.
_CREATE_SUSPENDED = 0x00000004
# Win32 CREATE_NO_WINDOW; subprocess stubs omit this supported creation flag.
_CREATE_NO_WINDOW = 0x08000000


def _digest(path: Path) -> str:
    details = path.lstat()
    if (
        path.is_symlink()
        or getattr(details, "st_file_attributes", 0) & 0x400
        or not path.is_file()
        or details.st_size > _MAX_WHEEL_BYTES
    ):
        raise ValueError("bounded verifier artifact is not a bounded regular file")
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def _installed_package_matches_wheel(wheel: Path, package: Path, version: str) -> bool:
    """Compare the installed import tree byte-for-byte with the supplied wheel."""
    try:
        with zipfile.ZipFile(wheel) as archive:
            infos = [item for item in archive.infolist() if not item.is_dir()]
            if len(infos) > _MAX_PACKAGE_FILES + 100:
                return False
            metadata_infos = [
                item for item in infos if re.fullmatch(r"[^/]+\.dist-info/METADATA", item.filename)
            ]
            if len(metadata_infos) != 1 or metadata_infos[0].file_size > 256 * 1024:
                return False
            metadata_info = metadata_infos[0]
            metadata = BytesParser().parsebytes(archive.read(metadata_info))

            def normalize(value: object) -> str:
                return re.sub(r"[-_.]+", "-", str(value)).lower()

            if (
                normalize(metadata.get("Name", "")) != "bluefire-nexus"
                or metadata.get("Version") != version
            ):
                return False
            data_root = metadata_info.filename.removesuffix(".dist-info/METADATA") + ".data"
            expected: dict[str, tuple[int, str]] = {}
            total = 0
            for item in infos:
                parts = item.filename.split("/")
                if not parts:
                    continue
                if parts[0] == "bluefire":
                    package_parts = parts[1:]
                elif item.filename.startswith(data_root + "/"):
                    if (
                        len(parts) < 3
                        or parts[1] not in {"purelib", "platlib"}
                        or parts[2] != "bluefire"
                    ):
                        continue
                    package_parts = parts[3:]
                else:
                    continue
                if (
                    item.filename.startswith("/")
                    or "\\" in item.filename
                    or any(part in {"", ".", ".."} for part in parts)
                    or item.external_attr >> 16 & 0o170000 == 0o120000
                    or item.file_size > _MAX_PACKAGE_BYTES
                ):
                    return False
                if not package_parts:
                    return False
                relative = "bluefire/" + "/".join(package_parts)
                total += item.file_size
                if total > _MAX_PACKAGE_BYTES or relative in expected:
                    return False
                expected[relative] = (
                    item.file_size,
                    hashlib.sha256(archive.read(item)).hexdigest(),
                )
            if "bluefire/__init__.py" not in expected or not expected:
                return False
            actual: dict[str, tuple[int, str]] = {}
            for path in package.rglob("*"):
                details = path.lstat()
                if path.is_symlink() or getattr(details, "st_file_attributes", 0) & 0x400:
                    return False
                if path.is_dir():
                    continue
                relative = path.relative_to(package.parent).as_posix()
                if "__pycache__" in path.parts or path.suffix == ".pyc":
                    continue
                if not path.is_file() or details.st_size > _MAX_PACKAGE_BYTES:
                    return False
                digest = _digest(path)
                actual[relative] = (details.st_size, digest)
                if len(actual) > _MAX_PACKAGE_FILES:
                    return False
            return actual == expected
    except (OSError, ValueError, zipfile.BadZipFile, RuntimeError):
        return False


def _write_receipt(path: Path, value: object, *, maximum: int = _MAX_STATE_BYTES) -> None:
    encoded = json.dumps(value, indent=2, sort_keys=True, allow_nan=False).encode("utf-8") + b"\n"
    if len(encoded) > maximum:
        raise RuntimeError("bounded verifier record exceeded its limit")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        offset = 0
        while offset < len(encoded):
            written = os.write(descriptor, encoded[offset:])
            if written <= 0:
                raise OSError("bounded verifier receipt write made no progress")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _read_object(path: Path, maximum: int) -> dict[str, Any]:
    with path.open("rb") as stream:
        raw = stream.read(maximum + 1)
    if len(raw) > maximum:
        raise ValueError("bounded verifier input exceeded its limit")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("verifier input must be an object")
    return value


_WITNESS_OBSERVATION_CODES = frozenset(
    {
        "ready_directory_unavailable",
        "ready_read_failed",
        "ready_json_invalid",
        "ready_contract_invalid",
        "parent_process_open_failed",
        "parent_process_not_live",
        "parent_process_wait_failed",
        "descendant_process_open_failed",
        "descendant_process_not_live",
        "descendant_process_wait_failed",
    }
)


class _WitnessObservationError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__("independent witness observation failed")
        self.code = code


def _witness_observation_error_code(error: BaseException) -> str:
    if (
        type(error) is _WitnessObservationError
        and type(error.code) is str
        and error.code in _WITNESS_OBSERVATION_CODES
    ):
        return error.code
    if type(error) is ValueError and error.args == (
        "fresh witness record failed its exact contract",
    ):
        return "ready_contract_invalid"
    return "witness_observation_failed"


def _read_witness_ready(directory: Path) -> dict[str, Any]:
    # The producer retains WRITE | DELETE access; the observer requests only READ
    # under the verified private parent. The native child inherits that parent's
    # ACL and must not be rewritten to the Python helper's protected-file ACL.
    from bluefire.runner_descriptor_io import (
        _descriptor_mount_identity,
        _read_descriptor_bounded,
    )
    from bluefire.runner_private_files import _PinnedPrivateDirectory

    stage = "ready_directory_unavailable"
    try:
        with _PinnedPrivateDirectory(
            directory, share_delete=True, verify_permissions_only=True
        ) as control:
            stage = "ready_read_failed"
            descriptor = control._open_existing("ready.json", write_dac=False)
            try:

                def snapshot() -> os.stat_result:
                    details = os.fstat(descriptor)
                    linked, mount_identity = control.entry_metadata_with_mount_identity(
                        "ready.json"
                    )
                    if (
                        not stat.S_ISREG(details.st_mode)
                        or not stat.S_ISREG(linked.st_mode)
                        or details.st_nlink != 1
                        or linked.st_nlink != 1
                        or getattr(details, "st_file_attributes", 0) & 0x400
                        or getattr(linked, "st_file_attributes", 0) & 0x400
                        or (details.st_dev, details.st_ino) != (linked.st_dev, linked.st_ino)
                        or not 0 <= details.st_size <= _MAX_READY_BYTES
                        or not 0 <= linked.st_size <= _MAX_READY_BYTES
                        or _descriptor_mount_identity(descriptor) != mount_identity
                    ):
                        raise OSError("native witness file identity is invalid")
                    return details

                before = snapshot()
                raw = _read_descriptor_bounded(descriptor, _MAX_READY_BYTES)
                after = snapshot()
                if (
                    before.st_dev,
                    before.st_ino,
                    before.st_size,
                    before.st_mtime_ns,
                    before.st_ctime_ns,
                ) != (
                    after.st_dev,
                    after.st_ino,
                    after.st_size,
                    after.st_mtime_ns,
                    after.st_ctime_ns,
                ):
                    raise OSError("native witness file changed while read")
            finally:
                os.close(descriptor)
    except (OSError, RuntimeError) as error:
        raise _WitnessObservationError(stage) from error

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate witness record field")
            value[key] = item
        return value

    def reject_constant(_constant: str) -> Any:
        raise ValueError("non-finite witness record value")

    try:
        value = json.loads(
            raw.decode("utf-8"), object_pairs_hook=unique_object, parse_constant=reject_constant
        )
        if not isinstance(value, dict):
            raise ValueError("witness record must be an object")
    except (ValueError, UnicodeError) as error:
        raise _WitnessObservationError("ready_json_invalid") from error
    return value


def _ready_record_valid(value: object, *, directory_name: str) -> bool:
    return (
        isinstance(directory_name, str)
        and re.fullmatch(r"[0-9a-f]{64}", directory_name) is not None
        and isinstance(value, dict)
        and set(value)
        == {
            "schema_version",
            "task_id",
            "request_hash",
            "parent_process_id",
            "descendant_process_id",
        }
        and value.get("schema_version") == "bluefire.process-tree-cancellation-ready.v1"
        and value.get("task_id") == "execute-" + directory_name
        and value.get("request_hash") == "sha256:" + directory_name
        and type(value.get("parent_process_id")) is int
        and 0 < value["parent_process_id"] <= 0xFFFFFFFF
        and type(value.get("descendant_process_id")) is int
        and 0 < value["descendant_process_id"] <= 0xFFFFFFFF
        and value["parent_process_id"] != value["descendant_process_id"]
    )


def _profile_authority_valid(profile: object) -> bool:
    return (
        isinstance(profile, dict)
        and profile.get("id") == PROFILE_ID
        and profile.get("mode") == "execute"
        and profile.get("platforms") == ["windows"]
        and profile.get("scope") == ["sandbox.workspace"]
        and profile.get("network_allowlist") == []
        and profile.get("approval_required") is True
        and profile.get("enabled_actions") == [ACTION_ID, "sandbox.cleanup.v1"]
        and profile.get("blocked_actions") == []
        and profile.get("budgets")
        == {"max_steps": 1, "max_seconds": 30, "max_artifacts": 4, "max_bytes": 65536}
    )


def _request_counts_valid(value: object) -> bool:
    required = {
        "session": 1,
        "catalog": 1,
        "runner_status": 2,
        "runner_bootstrap": 1,
        "runner_start": 1,
        "scenario_save": 1,
        "preflight": 1,
        "run_submit": 1,
        "approval": 1,
        "cancel": 1,
        "run_detail": 1,
        "runner_stop": 1,
    }
    if not isinstance(value, dict) or set(value) != {*required, "job_status"}:
        return False
    if any(
        type(value.get(key)) is not int or value[key] != count for key, count in required.items()
    ):
        return False
    return type(value.get("job_status")) is int and 2 <= value["job_status"] <= 100


def _driver_passed(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    return (
        set(value)
        == {
            "schema_version",
            "status",
            "profile_id",
            "scenario_id",
            "scenario_version",
            "scenario_digest",
            "job_id",
            "run_id",
            "preflight_status",
            "approval_status_before",
            "approval_status_after",
            "job_state_after_cancel",
            "witness_request_hash",
            "runner_stopped",
            "execution_interruption",
            "checks",
            "request_counts",
        }
        and value.get("schema_version") == "bluefire.installed-windows-cancellation.v1"
        and value.get("status") == "passed"
        and value.get("profile_id") == PROFILE_ID
        and isinstance(value.get("scenario_id"), str)
        and re.fullmatch(
            r"scenario\.installed-windows-cancel\.[0-9a-f-]{36}\.v1", value["scenario_id"]
        )
        is not None
        and type(value.get("scenario_version")) is int
        and value.get("scenario_version") == 1
        and isinstance(value.get("scenario_digest"), str)
        and _DIGEST.fullmatch(value["scenario_digest"]) is not None
        and isinstance(value.get("job_id"), str)
        and re.fullmatch(r"job-[0-9a-f]{32}", value["job_id"]) is not None
        and isinstance(value.get("run_id"), str)
        and re.fullmatch(r"run-[A-Za-z0-9T._-]{1,96}", value["run_id"]) is not None
        and value.get("preflight_status") == "approval_required"
        and value.get("approval_status_before") == "pending"
        and value.get("approval_status_after") in {"consumed", "claimed"}
        and value.get("job_state_after_cancel") == "cancelled"
        and isinstance(value.get("witness_request_hash"), str)
        and _DIGEST.fullmatch(value["witness_request_hash"]) is not None
        and value.get("runner_stopped") is True
        and value.get("execution_interruption")
        == {
            "cooperative_requested": True,
            "cooperative_acknowledged": True,
            "forced_tree_termination": True,
            "control_cleanup_verified": True,
            "process_tree_stopped": True,
        }
        and value.get("checks")
        == [
            "ephemeral_authenticated_session_created",
            "shipped_gate11_profile_and_action_verified",
            "fresh_installed_runner_bootstrapped_and_started_through_service",
            "exact_execute_preflight_and_fresh_approval_consumed",
            "cancel_requested_only_after_fresh_witness_processes_were_pinned",
            "retained_interruption_confirmed_cancellation_and_cleanup",
            "both_witness_process_handles_signaled_and_control_tree_removed",
            "managed_runner_stopped_through_service",
        ]
        and _request_counts_valid(value.get("request_counts"))
    )


def _all_owned_groups_stopped(report: dict[str, object]) -> bool:
    return report.get("driver_job_created") is False or (
        report.get("driver_job_created") is True
        and report.get("driver_job_empty") is True
        and report.get("driver_process_exited") is True
    )


def _runtime_removal_allowed(report: dict[str, object]) -> bool:
    witness_clean = report.get("witness_could_have_started") is not True or (
        report.get("witness_process_handles_stopped") is True
        and report.get("witness_control_tree_removed") is True
        and report.get("witness_observer_stopped") is True
    )
    return (
        _all_owned_groups_stopped(report)
        and report.get("managed_runner_stopped") is True
        and report.get("service_thread_stopped") is True
        and report.get("service_http_server_closed") is True
        and report.get("service_closed") is True
        and report.get("witness_observer_stopped") is True
        and report.get("driver_input_writer_stopped") is True
        and witness_clean
    )


def _cleanup_qualified(report: dict[str, object]) -> bool:
    return (
        _runtime_removal_allowed(report)
        and report.get("service_shutdown_succeeded") is True
    )


def _stop_http_server(server, thread, thread_started: bool) -> tuple[bool, bool, bool]:
    """Return thread-stopped, shutdown-succeeded, and socket-closed states."""
    if server is None:
        return thread is None or not thread.is_alive(), True, True
    shutdown_succeeded = not thread_started
    if thread_started:
        if thread.is_alive():
            try:
                server.shutdown()
                shutdown_succeeded = True
            except Exception:
                shutdown_succeeded = False
    if thread is None or not thread_started:
        thread_stopped = True
    else:
        try:
            thread.join(timeout=10)
            thread_stopped = not thread.is_alive()
        except Exception:
            thread_stopped = False
    server_closed = False
    if thread_stopped:
        try:
            server.server_close()
            server_closed = True
        except Exception:
            server_closed = False
    return thread_stopped, shutdown_succeeded, server_closed


def _witness_control_tree_removed(sandbox: Path) -> bool:
    """Remove only the exact private witness tree after its processes have stopped."""
    try:
        executions = sandbox / ".bluefire-executions"
        if not executions.exists():
            return True
        if not _safe_directory(executions):
            return False
        owners = list(executions.iterdir())
        if not owners:
            return True
        if len(owners) != 1 or not _safe_directory(owners[0]):
            return False
        control = owners[0] / ".bluefire-cancellation-witness-v1"
        if not control.exists():
            return True
        if not _safe_directory(control):
            return False
        children = list(control.iterdir())
        if not children:
            control.rmdir()
            return not control.exists()
        if len(children) != 1 or not re.fullmatch(r"[0-9a-f]{64}", children[0].name):
            return False
        if not _safe_directory(children[0]):
            return False
        shutil.rmtree(children[0])
        if control.exists():
            control.rmdir()
        return not control.exists()
    except OSError:
        return False


def _stop_managed_runner(lifecycle: Any) -> bool:
    try:
        status = lifecycle.status(profile_id=PROFILE_ID, profile_budget_seconds=30)
        if status.get("state") in {"stopped", "unbootstrapped"}:
            return True
        lifecycle.stop(profile_id=PROFILE_ID)
        status = lifecycle.status(profile_id=PROFILE_ID, profile_budget_seconds=30)
        return status.get("state") in {"stopped", "unbootstrapped"}
    except Exception:
        return False


def _require_windows() -> None:
    if os.name != "nt" or sys.platform != "win32" or not sys.flags.isolated:
        raise RuntimeError("Use isolated installed Python on Windows for this verifier")


def _windows_architecture_environment(machine: str) -> dict[str, str]:
    # platform.machine() reads this Windows system metadata after the environment is cleared.
    architecture = {
        "amd64": "AMD64",
        "x64": "AMD64",
        "x86_64": "AMD64",
        "arm64": "ARM64",
        "aarch64": "ARM64",
    }.get(machine.casefold())
    if architecture is None:
        raise RuntimeError("Windows verifier host architecture is unsupported")
    return {"PROCESSOR_ARCHITECTURE": architecture}


def _private_ready_record(sandbox: Path, stop: threading.Event) -> dict[str, Any]:
    deadline = time.monotonic() + _MAX_DRIVER_SECONDS - 15
    while not stop.is_set() and time.monotonic() < deadline:
        executions = sandbox / ".bluefire-executions"
        try:
            executions.lstat()
        except FileNotFoundError:
            time.sleep(0.05)
            continue
        if not _safe_directory(executions):
            raise ValueError("fresh Execute workspace root was redirected")
        owners = list(executions.iterdir())
        if not owners:
            time.sleep(0.05)
            continue
        if len(owners) != 1 or not _safe_directory(owners[0]):
            raise ValueError("fresh Execute workspace identity was ambiguous")
        controls = owners[0] / ".bluefire-cancellation-witness-v1"
        try:
            controls.lstat()
        except FileNotFoundError:
            time.sleep(0.05)
            continue
        if not _safe_directory(controls):
            raise ValueError("fresh witness control root was redirected")
        children = list(controls.iterdir())
        if not children:
            time.sleep(0.05)
            continue
        if len(children) != 1:
            raise ValueError("fresh witness control directory was ambiguous")
        child = children[0]
        if not _safe_directory(child):
            raise ValueError("fresh witness directory was redirected")
        ready_path = child / "ready.json"
        try:
            ready_path.lstat()
        except FileNotFoundError:
            time.sleep(0.05)
            continue
        if not _safe_regular_file(ready_path, _MAX_READY_BYTES):
            raise ValueError("fresh witness record was not a bounded regular file")
        ready = _read_witness_ready(child)
        if not _ready_record_valid(ready, directory_name=child.name):
            raise ValueError("fresh witness record failed its exact contract")
        _pin_windows_processes(ready)
        return {**ready, "control_path": child}
    if stop.is_set():
        raise RuntimeError("witness observation was stopped")
    raise TimeoutError("fresh cancellation witness did not arrive")


def _driver_input_writer(
    stream: Any, messages: queue.Queue[dict[str, Any] | None], errors: list[str]
) -> None:
    try:
        while True:
            value = messages.get()
            if value is None:
                return
            encoded = json.dumps(value, separators=(",", ":"), allow_nan=False).encode("ascii")
            if len(encoded) > _MAX_DRIVER_FRAME_BYTES:
                raise ValueError("bounded driver input frame exceeded its limit")
            if stream.write(encoded + b"\n") != len(encoded) + 1:
                raise OSError("bounded driver input write made no progress")
            stream.flush()
            if value.get("type") != "capability":
                return
    except (OSError, ValueError, TypeError, UnicodeError) as error:
        errors.append(type(error).__name__)
    finally:
        try:
            stream.close()
        except OSError:
            pass


def _pin_windows_processes(ready: dict[str, Any]) -> None:
    import ctypes
    from ctypes import wintypes

    kernel = _windows_kernel32(ctypes)
    open_process = kernel.OpenProcess
    open_process.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    open_process.restype = wintypes.HANDLE
    wait = kernel.WaitForSingleObject
    wait.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    wait.restype = wintypes.DWORD
    handles = []
    try:
        for name in ("parent_process_id", "descendant_process_id"):
            role = "parent" if name == "parent_process_id" else "descendant"
            handle = open_process(0x00100000 | 0x1000, False, ready[name])
            if not handle:
                raise _WitnessObservationError(role + "_process_open_failed")
            handles.append(int(handle))
            state = wait(handle, 0)
            if state != 0x00000102:
                raise _WitnessObservationError(
                    role + ("_process_not_live" if state == 0 else "_process_wait_failed")
                )
        _HELD_WITNESS_HANDLES.extend(handles)
    except BaseException:
        for handle in handles:
            kernel.CloseHandle(wintypes.HANDLE(handle))
        raise


_HELD_WITNESS_HANDLES: list[int] = []


def _windows_kernel32(ctypes: Any) -> Any:
    loader = getattr(ctypes, "WinDLL", None)
    if loader is None:
        raise RuntimeError("Windows process APIs are unavailable")
    return loader("kernel32", use_last_error=True)


def _safe_directory(path: Path) -> bool:
    try:
        details = path.lstat()
        return (
            path.is_dir()
            and not path.is_symlink()
            and not bool(getattr(details, "st_file_attributes", 0) & 0x400)
        )
    except OSError:
        return False


def _safe_regular_file(path: Path, maximum: int) -> bool:
    try:
        details = path.lstat()
        return (
            path.is_file()
            and not path.is_symlink()
            and not bool(getattr(details, "st_file_attributes", 0) & 0x400)
            and details.st_size <= maximum
        )
    except OSError:
        return False


def _held_witness_processes_stopped() -> bool:
    import ctypes
    from ctypes import wintypes

    if len(_HELD_WITNESS_HANDLES) != 2:
        return False
    kernel = _windows_kernel32(ctypes)
    wait = kernel.WaitForSingleObject
    wait.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    wait.restype = wintypes.DWORD
    results = []
    close_ok = True
    try:
        for handle in _HELD_WITNESS_HANDLES:
            try:
                results.append(wait(handle, 5000) == 0)
            except Exception:
                results.append(False)
            try:
                close_ok = bool(kernel.CloseHandle(wintypes.HANDLE(handle))) and close_ok
            except Exception:
                close_ok = False
    finally:
        _HELD_WITNESS_HANDLES.clear()
    return all(results) and close_ok


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--forbid-root", required=True, type=Path)
    parser.add_argument("--node", required=True, type=Path)
    parser.add_argument("--driver", required=True, type=Path)
    parser.add_argument("--wheel", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    _require_windows()
    forbidden = args.forbid_root.resolve(strict=True)
    verifier_path = Path(__file__).resolve(strict=True)
    driver = args.driver.resolve(strict=True)
    node = args.node.resolve(strict=True)
    wheel = args.wheel.resolve(strict=True)
    output = args.output.resolve()
    if (
        output.exists()
        or output.is_relative_to(forbidden)
        or verifier_path.is_relative_to(forbidden)
        or driver.is_relative_to(forbidden)
        or Path.cwd().is_relative_to(forbidden)
        or not driver.is_file()
        or not node.is_file()
    ):
        raise RuntimeError("Use a fresh output and copied verifier driver outside checkout")
    output.mkdir(mode=0o700)
    runtime = output / "runtime"
    report: dict[str, object] = {
        "schema_version": "bluefire.installed-windows-cancellation-receipt.v1",
        "status": "failed_or_incomplete",
        "scope": "installed Windows wheel; Gate 11 process-tree cancellation witness only",
        "installed_wheel": False,
        "native_witness": False,
        "live_model_inference": False,
        "external_network": False,
        "external_credentials": False,
        "driver_job_created": False,
        "driver_job_empty": False,
        "driver_process_exited": False,
        "driver_input_writer_stopped": True,
        "service_thread_stopped": False,
        "service_shutdown_succeeded": False,
        "service_http_server_closed": False,
        "service_closed": False,
        "managed_runner_stopped": False,
        "witness_could_have_started": False,
        "witness_observer_stopped": False,
        "witness_process_handles_stopped": False,
        "witness_control_tree_removed": False,
        "temporary_runtime_removed": False,
        "not_proven": [
            "other runner profiles or actions",
            "other operating systems",
            "effective access, defensive efficacy, or general process protection",
            "live network or credential behavior",
        ],
    }
    original_env = dict(os.environ)
    original_cwd = Path.cwd()
    service = None
    server = None
    service_thread = None
    service_thread_started = False
    driver_process: subprocess.Popen[bytes] | None = None
    driver_containment = None
    driver_job: int | None = None
    driver_assigned = False
    driver_input_messages: queue.Queue[dict[str, Any] | None] | None = None
    driver_input_thread: threading.Thread | None = None
    driver_input_errors: list[str] = []
    witness_thread: threading.Thread | None = None
    witness_thread_started = False
    witness_error: list[str] = []
    witness_result: list[dict[str, Any]] = []
    witness_messages: queue.Queue[tuple[str, dict[str, Any] | None]] = queue.Queue(maxsize=1)
    witness_stop = threading.Event()
    try:
        runtime.mkdir(mode=0o700)
        for name in ("home", "state", "temp", "work", "sandbox", "managed"):
            (runtime / name).mkdir(mode=0o700)
        package_runner = None
        architecture_env = _windows_architecture_environment(platform.machine())
        os.environ.clear()
        system_root = original_env.get("SYSTEMROOT") or original_env.get("WINDIR") or r"C:\Windows"
        env = {
            **architecture_env,
            "SYSTEMROOT": system_root,
            "WINDIR": system_root,
            "PATH": os.pathsep.join((str(node.parent), str(Path(system_root) / "System32"))),
            "HOME": str(runtime / "home"),
            "USERPROFILE": str(runtime / "home"),
            "TEMP": str(runtime / "temp"),
            "TMP": str(runtime / "temp"),
            "LOCALAPPDATA": str(runtime / "home" / "AppData" / "Local"),
            "APPDATA": str(runtime / "home" / "AppData" / "Roaming"),
            "PYTHONNOUSERSITE": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "BLUEFIRE_SANDBOX_ROOT": str(runtime / "sandbox"),
        }
        os.environ.update(env)
        os.chdir(runtime / "work")
        distribution = importlib.metadata.distribution("bluefire-nexus")
        library_roots = {
            Path(sysconfig.get_path(name)).resolve(strict=True) for name in ("purelib", "platlib")
        }
        package_candidates = [
            root / "bluefire" for root in library_roots if (root / "bluefire").exists()
        ]
        if len(package_candidates) != 1:
            raise RuntimeError("BlueFire installed package location is missing or ambiguous")
        package = package_candidates[0]
        package_runner = package / "native" / "bluefire-runner.exe"
        if (
            not _safe_directory(package)
            or package.is_relative_to(forbidden)
            or not package_runner.is_file()
            or not _installed_package_matches_wheel(wheel, package, distribution.version)
            or any(Path(entry or ".").resolve().is_relative_to(forbidden) for entry in sys.path)
            or '"editable": true' in (distribution.read_text("direct_url.json") or "").lower()
        ):
            raise RuntimeError("BlueFire must come from a non-editable wheel installation")
        import bluefire
        from bluefire.api import create_server, generate_browser_bootstrap_capability
        from bluefire.runner_lifecycle import ManagedRunnerLifecycle
        from bluefire.runner_windows_containment import WindowsJobContainment
        from bluefire.service import BlueFireService

        if Path(bluefire.__file__).resolve(strict=True) != (package / "__init__.py").resolve(
            strict=True
        ):
            raise RuntimeError("BlueFire import did not resolve to the verified installed package")
        env["BLUEFIRE_RUNNER_BINARY"] = str(package_runner)
        os.environ["BLUEFIRE_RUNNER_BINARY"] = str(package_runner)
        report.update(
            {
                "installed_wheel": True,
                "os": platform.platform(),
                "architecture": platform.machine(),
                "python_version": platform.python_version(),
                "product_version": distribution.version,
                "wheel_filename": wheel.name,
                "wheel_sha256": _digest(wheel),
                "installed_package_matches_wheel": True,
                "runner_binary_sha256": _digest(package_runner),
                "verifier_sha256": _digest(verifier_path),
                "driver_sha256": _digest(driver),
                "environment_names": sorted(env),
            }
        )
        service = BlueFireService(
            runs_dir=runtime / "runs",
            runner_lifecycle=ManagedRunnerLifecycle(runtime / "managed"),
        )
        capability = generate_browser_bootstrap_capability()
        server = create_server(
            service, host="127.0.0.1", port=0, browser_bootstrap_capability=capability
        )
        service_thread = threading.Thread(
            target=server.serve_forever,
            name="installed-cancel-service",
            daemon=False,
        )
        service_thread.start()
        service_thread_started = True
        sandbox = runtime / "sandbox"

        def observe_witness() -> None:
            try:
                ready = _private_ready_record(sandbox, witness_stop)
                witness_result.append(ready)
                witness_messages.put_nowait(
                    (
                        "permit",
                        {
                            key: ready[key]
                            for key in (
                                "schema_version",
                                "task_id",
                                "request_hash",
                                "parent_process_id",
                                "descendant_process_id",
                            )
                        },
                    )
                )
            except (OSError, ValueError, RuntimeError, TimeoutError) as error:
                witness_error.append(_witness_observation_error_code(error))
                try:
                    witness_messages.put_nowait(("denied", None))
                except queue.Full:
                    pass

        witness_thread = threading.Thread(target=observe_witness, name="installed-cancel-witness")
        witness_thread.start()
        witness_thread_started = True
        containment = WindowsJobContainment(kill_on_close=True)
        driver_containment = containment
        driver_job = containment.create_job()
        report["driver_job_created"] = True
        driver_process = subprocess.Popen(
            [str(node), str(driver), str(server.server_address[1]), str(sandbox), str(output)],
            env=env,
            cwd=runtime / "work",
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=_CREATE_NO_WINDOW | _CREATE_SUSPENDED,
        )
        containment.assign_retained(driver_job, driver_process)
        driver_assigned = True
        containment.resume_suspended(driver_process)
        report["witness_could_have_started"] = True
        driver_input_messages = queue.Queue()
        driver_input_thread = threading.Thread(
            target=_driver_input_writer,
            args=(driver_process.stdin, driver_input_messages, driver_input_errors),
            name="installed-cancel-input-writer",
            daemon=True,
        )
        driver_input_thread.start()
        report["driver_input_writer_stopped"] = False
        driver_input_messages.put({"type": "capability", "capability": capability})
        driver_deadline = time.monotonic() + _MAX_DRIVER_SECONDS
        frame_sent = False
        while driver_process.poll() is None and time.monotonic() < driver_deadline:
            if driver_input_errors:
                raise RuntimeError("installed driver input channel failed")
            if not frame_sent:
                try:
                    kind, payload = witness_messages.get(timeout=0.05)
                except queue.Empty:
                    continue
                if kind == "permit" and payload is not None:
                    driver_input_messages.put({"type": "witness_permit", "ready": payload})
                else:
                    driver_input_messages.put({"type": "witness_denied"})
                frame_sent = True
            else:
                time.sleep(0.05)
        if driver_process.poll() is None:
            report["status"] = "failed_or_incomplete"
        report["driver_process_exited"] = driver_process.poll() is not None
        if driver_process.poll() is not None and not witness_result:
            witness_stop.set()
        if driver_input_thread is not None:
            try:
                driver_input_messages.put_nowait(None)
            except queue.Full:
                pass
            driver_input_thread.join(timeout=1)
            report["driver_input_writer_stopped"] = not driver_input_thread.is_alive()
            if not report["driver_input_writer_stopped"]:
                report["status"] = "failed_or_incomplete"
        if not witness_result and witness_thread is not None:
            witness_stop.set()
        if witness_thread is not None:
            witness_thread.join(timeout=10)
        report["witness_process_handles_stopped"] = _held_witness_processes_stopped()
        if witness_result:
            record = witness_result[0]
            report["witness_request_hash"] = record["request_hash"]
            report["witness_control_tree_removed"] = not record["control_path"].exists()
        if witness_error:
            report["witness_observation_error"] = witness_error[0]
        report["driver_returncode"] = driver_process.returncode
        driver_report = _read_object(output / "driver-report.json", _MAX_REPORT_BYTES)
        driver_ok = _driver_passed(driver_report)
        report["installed_cancellation"] = driver_report
        report["native_witness"] = driver_ok
        report["managed_runner_stopped"] = driver_report.get("runner_stopped") is True
        report["status"] = (
            "passed"
            if driver_ok
            and driver_process.returncode == 0
            and report["witness_process_handles_stopped"] is True
            and report["witness_control_tree_removed"] is True
            and report["managed_runner_stopped"] is True
            else "failed_or_incomplete"
        )
    except (
        OSError,
        ImportError,
        RuntimeError,
        ValueError,
        KeyError,
        subprocess.SubprocessError,
    ) as error:
        report["error_type"] = type(error).__name__
    finally:
        try:
            if driver_process is not None:
                try:
                    if driver_process.poll() is None:
                        if driver_assigned and driver_containment is not None:
                            driver_containment.terminate(driver_process)
                        else:
                            # A not-yet-assigned child is still suspended.
                            driver_process.kill()
                            driver_process.wait(timeout=5)
                    else:
                        driver_process.wait(timeout=5)
                    report["driver_process_exited"] = driver_process.poll() is not None
                except Exception:
                    report["driver_process_exited"] = False
                try:
                    if driver_job is not None and driver_containment is not None:
                        if driver_assigned and driver_process.poll() is not None:
                            report["driver_job_empty"] = bool(
                                driver_containment.finish_retained(driver_process, driver_job)
                            )
                        elif not driver_assigned:
                            report["driver_job_empty"] = bool(
                                driver_containment.close_handle(driver_job)
                            )
                except Exception:
                    report["driver_job_empty"] = False
            elif driver_job is not None and driver_containment is not None:
                try:
                    report["driver_job_empty"] = bool(driver_containment.close_handle(driver_job))
                    report["driver_process_exited"] = True
                except Exception:
                    report["driver_job_empty"] = False
                    report["driver_process_exited"] = False
            else:
                report["driver_process_exited"] = True

            if driver_input_thread is not None:
                if driver_input_messages is not None:
                    driver_input_messages.put(None)
                try:
                    driver_input_thread.join(timeout=1)
                    report["driver_input_writer_stopped"] = not driver_input_thread.is_alive()
                except Exception:
                    report["driver_input_writer_stopped"] = False

            witness_stop.set()
            if witness_thread is None or not witness_thread_started:
                report["witness_observer_stopped"] = True
            else:
                try:
                    witness_thread.join(timeout=5)
                    report["witness_observer_stopped"] = not witness_thread.is_alive()
                except Exception:
                    report["witness_observer_stopped"] = False

            if service is None:
                report["managed_runner_stopped"] = True
                report["service_closed"] = True
            else:
                try:
                    report["managed_runner_stopped"] = _stop_managed_runner(
                        service.runner_lifecycle
                    )
                except Exception:
                    report["managed_runner_stopped"] = False

            (
                report["service_thread_stopped"],
                report["service_shutdown_succeeded"],
                report["service_http_server_closed"],
            ) = _stop_http_server(server, service_thread, service_thread_started)

            if service is not None:
                if (
                    report["managed_runner_stopped"] is True
                    and report["service_thread_stopped"] is True
                    and report["service_http_server_closed"] is True
                ):
                    try:
                        service.close()
                        report["service_closed"] = True
                    except Exception:
                        report["service_closed"] = False

            if report.get("witness_process_handles_stopped") is not True:
                try:
                    report["witness_process_handles_stopped"] = _held_witness_processes_stopped()
                except Exception:
                    report["witness_process_handles_stopped"] = False
            if report.get("witness_could_have_started") is True:
                if (
                    report.get("witness_process_handles_stopped") is True
                    and report.get("witness_observer_stopped") is True
                ):
                    report["witness_control_tree_removed"] = _witness_control_tree_removed(
                        runtime / "sandbox"
                    )
            else:
                report["witness_control_tree_removed"] = True

            try:
                os.chdir(original_cwd)
            except Exception:
                report["service_thread_stopped"] = False

            try:
                if _runtime_removal_allowed(report):
                    shutil.rmtree(runtime)
            except Exception:
                pass
            try:
                report["temporary_runtime_removed"] = not runtime.exists()
            except Exception:
                report["temporary_runtime_removed"] = False
            if (
                not report["temporary_runtime_removed"]
                or not _runtime_removal_allowed(report)
                or not _cleanup_qualified(report)
            ):
                report["status"] = "failed_or_incomplete"
            try:
                _write_receipt(output / "receipt.json", report)
            except Exception:
                pass
        finally:
            try:
                os.environ.clear()
                os.environ.update(original_env)
            except Exception:
                pass
    print(json.dumps(report, sort_keys=True, allow_nan=False))
    return 0 if report.get("status") == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
