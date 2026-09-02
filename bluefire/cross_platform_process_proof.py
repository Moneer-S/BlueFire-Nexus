"""Packaged-Rust process-tree cancellation proof used by the Gate 11 journey."""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import re
import select
import signal
import subprocess  # nosec B404 - one fixed /bin/sleep probe command
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Mapping, Protocol, cast

if TYPE_CHECKING:
    from .config import RunnerProfile

from .cross_platform_recovery_witness import (
    RecoveryWitnessError,
    capture_process_identity,
    process_identity_running,
)
from .runner_client import (
    RunnerTaskCancelled,
    SubprocessRustRunner,
    TaskAwareRunnerTransport,
    _pinned_launch_file,
    _PinnedPrivateDirectory,
    runner_pending_result_path,
    runner_watchdog_control_root,
)
from .runner_contracts import build_execution_manifest, build_runner_profile
from .util import canonical_json_bytes, content_hash, file_hash

CANCELLATION_SCHEMA = "bluefire.cross-platform-process-cancellation.v2"
ACTION_ID = "sandbox.execution.process-tree-cancellation-witness.v1"
PROFILE_ID = "gate11-windows-cancellation-witness.v1"
CONTROL_PARENT = ".bluefire-cancellation-witness-v1"
READY_SCHEMA = "bluefire.process-tree-cancellation-ready.v1"
POSIX_CONTAINMENT_SCHEMA = "bluefire.posix-watchdog-containment.v2"
POSIX_CONTAINMENT_IDENTITIES_SCHEMA = "bluefire.posix-watchdog-containment-identities.v2"
_POSIX_READY_SCHEMA = "bluefire.posix-watchdog-containment-ready.v1"
_POSIX_ABSENCE_DELAYS_MS = (0, 100, 250)
_FORK = getattr(os, "fork", None)
_SET_SESSION_ID = getattr(os, "setsid", None)
_GET_PROCESS_GROUP_ID = getattr(os, "getpgid", None)
_GET_SESSION_ID = getattr(os, "getsid", None)
_WAIT_PID = getattr(os, "waitpid", None)
_PIDFD_OPEN = getattr(os, "pidfd_open", None)
_PIDFD_SEND_SIGNAL = getattr(signal, "pidfd_send_signal", None)
_WAIT_NO_HANG = getattr(os, "WNOHANG", 1)
_PAUSE = getattr(signal, "pause", None)
_SIGKILL = getattr(signal, "SIGKILL", 9)
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_CANCELLATION_READY_TIMEOUT_SECONDS = 10.0


class ProcessProofError(ValueError):
    """Raised when the reviewed Rust tree is not proven absent after cancellation."""


class _Service(Protocol):
    config: Any
    registry: Any


def _approval_record() -> Mapping[str, str]:
    approved = datetime.now(timezone.utc)
    expires = approved + timedelta(minutes=5)

    def render(value: datetime) -> str:
        return value.isoformat(timespec="microseconds").replace("+00:00", "Z")

    return {
        "approved_by": "gate-11-cancellation-reviewer",
        "approved_at": render(approved),
        "expires_at": render(expires),
    }


def _ready_record(
    root: Path,
    *,
    task_id: str,
    request_hash: str,
) -> Mapping[str, Any]:
    with _PinnedPrivateDirectory(root.parent):
        with _PinnedPrivateDirectory(root, share_delete=True) as control:
            if set(control.names(maximum=3)) != {".lease", "ready.json"}:
                raise ProcessProofError("the cancellation witness control state is invalid")
            ready = SubprocessRustRunner._decode_json(
                control.read("ready.json", maximum=1024, apply_permissions=False),
                "cancellation witness readiness",
            )
    if (
        set(ready)
        != {
            "schema_version",
            "task_id",
            "request_hash",
            "parent_process_id",
            "descendant_process_id",
        }
        or ready.get("schema_version") != READY_SCHEMA
        or ready.get("task_id") != task_id
        or ready.get("request_hash") != request_hash
        or type(ready.get("parent_process_id")) is not int
        or int(ready["parent_process_id"]) <= 0
        or type(ready.get("descendant_process_id")) is not int
        or int(ready["descendant_process_id"]) <= 0
        or ready["parent_process_id"] == ready["descendant_process_id"]
    ):
        raise ProcessProofError("the cancellation witness readiness is not request-bound")
    return cast(Mapping[str, Any], ready)


def _remove_empty_control_parent(path: Path) -> bool:
    try:
        with _PinnedPrivateDirectory(path, delete=True) as parent:
            if parent.names(maximum=1):
                return False
            parent.remove()
        return not path.exists()
    except (OSError, RuntimeError):
        return False


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate key")
        value[key] = item
    return value


def _linux_process_identity(process_id: int) -> Mapping[str, int]:
    try:
        payload = (Path("/proc") / str(process_id) / "stat").read_bytes()
    except OSError as exc:
        raise ProcessProofError("the Linux probe process identity is unavailable") from exc
    close = payload.rfind(b")")
    fields = payload[close + 2 :].split() if 0 < close < len(payload) - 2 else []
    try:
        identity = {
            "process_id": process_id,
            "process_group_id": int(fields[2]),
            "session_id": int(fields[3]),
            "start_time_ticks": int(fields[19]),
        }
    except (IndexError, ValueError) as exc:
        raise ProcessProofError("the Linux probe process identity is invalid") from exc
    if not 0 < len(payload) <= 4096 or not all(value > 0 for value in identity.values()):
        raise ProcessProofError("the Linux probe process identity is invalid")
    return identity


def _linux_identity_present(identity: Mapping[str, int]) -> bool:
    try:
        observed = _linux_process_identity(int(identity["process_id"]))
    except ProcessProofError as exc:
        if isinstance(exc.__cause__, FileNotFoundError):
            return False
        raise
    return dict(observed) == dict(identity)


def _linux_process_instance(identity: Mapping[str, int]) -> tuple[int, int]:
    return int(identity["process_id"]), int(identity["start_time_ticks"])


def _open_identity_bound_pidfd(identity: Mapping[str, int]) -> int:
    """Open a pidfd only across stable pre/post immutable identity reads."""

    if not callable(_PIDFD_OPEN):
        raise ProcessProofError("the Linux watchdog pidfd boundary is unavailable")
    expected = _linux_process_instance(identity)
    before = _linux_process_identity(expected[0])
    if _linux_process_instance(before) != expected:
        raise ProcessProofError("the Linux watchdog pidfd is not identity-bound")
    descriptor = -1
    try:
        opened = _PIDFD_OPEN(expected[0], 0)
        if type(opened) is not int or opened < 0:
            raise ProcessProofError("the Linux watchdog pidfd is invalid")
        descriptor = opened
        after = _linux_process_identity(expected[0])
        if (
            _linux_process_instance(before) != _linux_process_instance(after)
            or _linux_process_instance(after) != expected
        ):
            raise ProcessProofError("the Linux watchdog pidfd is not identity-bound")
        return descriptor
    except BaseException:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise


def _linux_private_session_identities(
    leader_identity: Mapping[str, int],
) -> tuple[Mapping[str, int], ...]:
    leader = _linux_process_identity(int(leader_identity["process_id"]))
    leader_pid = int(leader["process_id"])
    if (
        _linux_process_instance(leader) != _linux_process_instance(leader_identity)
        or leader["process_group_id"] != leader_pid
        or leader["session_id"] != leader_pid
    ):
        raise ProcessProofError("the Linux cleanup session leader is not identity-bound")
    identities: list[Mapping[str, int]] = []
    try:
        entries = tuple(Path("/proc").iterdir())
    except OSError as exc:
        raise ProcessProofError("the Linux cleanup session cannot be enumerated") from exc
    for entry in entries:
        if not entry.name.isdecimal():
            continue
        try:
            identity = _linux_process_identity(int(entry.name))
        except ProcessProofError:
            continue
        if identity["session_id"] == leader_pid:
            identities.append(identity)
    if not any(dict(identity) == dict(leader) for identity in identities):
        raise ProcessProofError("the Linux cleanup session leader disappeared")
    return tuple(sorted(identities, key=lambda identity: int(identity["process_id"])))


def _cleanup_failed_posix_private_session(
    leader_identity: Mapping[str, int],
    pidfds: dict[int, int],
) -> set[int]:
    """Best-effort failure cleanup under verified private-SID/pidfd authority."""

    send_signal = _PIDFD_SEND_SIGNAL
    if not callable(send_signal):
        raise ProcessProofError("the Linux watchdog pidfd signal boundary is unavailable")
    identities = _linux_private_session_identities(leader_identity)
    leader_pid = int(leader_identity["process_id"])
    members: list[tuple[int, int]] = []
    for identity in identities:
        process_id = int(identity["process_id"])
        if process_id == leader_pid:
            continue
        descriptor = pidfds.get(process_id)
        if descriptor is None:
            try:
                descriptor = _open_identity_bound_pidfd(identity)
                if not _linux_identity_present(identity):
                    os.close(descriptor)
                    continue
                pidfds[process_id] = descriptor
            except (OSError, ProcessProofError, ValueError):
                continue
        members.append((process_id, descriptor))
    leader_descriptor = pidfds.get(leader_pid)
    if leader_descriptor is None:
        leader_descriptor = _open_identity_bound_pidfd(leader_identity)
        pidfds[leader_pid] = leader_descriptor

    # Descendants are stopped while the verified session leader remains
    # unreaped, so its private SID cannot be recycled during enumeration.
    for _process_id, descriptor in members:
        try:
            send_signal(descriptor, _SIGKILL, None, 0)
        except (OSError, ProcessLookupError):
            pass
    try:
        send_signal(leader_descriptor, _SIGKILL, None, 0)
    except (OSError, ProcessLookupError):
        pass

    reaped: set[int] = set()
    for process_id in (leader_pid, *(process_id for process_id, _descriptor in members)):
        try:
            _wait_for_reaped_process(process_id, time.monotonic() + 2.0)
            reaped.add(process_id)
        except ProcessProofError:
            continue
    return reaped


def _child_subreaper_enabled() -> bool:
    try:
        library = ctypes.CDLL(None, use_errno=True)
        prctl = library.prctl
        prctl.restype = ctypes.c_int
        current = ctypes.c_int()
        result = prctl(37, ctypes.byref(current), 0, 0, 0)
    except (AttributeError, OSError, TypeError, ValueError) as exc:
        raise ProcessProofError("the Linux child-subreaper boundary is unavailable") from exc
    if result != 0:
        raise ProcessProofError("the Linux child-subreaper boundary is unavailable")
    return bool(current.value)


def _set_child_subreaper(enabled: bool) -> None:
    try:
        library = ctypes.CDLL(None, use_errno=True)
        prctl = library.prctl
        prctl.restype = ctypes.c_int
        result = prctl(36, int(enabled), 0, 0, 0)
    except (AttributeError, OSError, TypeError, ValueError) as exc:
        raise ProcessProofError("the Linux child-subreaper boundary is unavailable") from exc
    if result != 0:
        raise ProcessProofError("the Linux child-subreaper boundary is unavailable")


def _write_pipe_payload(descriptor: int, value: Mapping[str, Any]) -> None:
    payload = canonical_json_bytes(value) + b"\n"
    if not 0 < len(payload) <= 8192:
        os._exit(72)
    offset = 0
    while offset < len(payload):
        try:
            written = os.write(descriptor, payload[offset:])
        except OSError:
            os._exit(73)
        if written <= 0:
            os._exit(73)
        offset += written


def _posix_probe_supervisor(
    descriptor: int,
    work_root: Path,
) -> None:
    try:
        if not callable(_SET_SESSION_ID) or not callable(_PAUSE):
            os._exit(70)
        _SET_SESSION_ID()
        executable = Path("/bin/sleep").resolve(strict=True)
        details = executable.stat()
        if not executable.is_file() or details.st_nlink != 1:
            os._exit(70)
        runner = SubprocessRustRunner(
            executable,
            work_root,
            timeout_seconds=65.0,
            output_limit_bytes=4096,
            _kill_child_on_job_close=True,
        )
        with _pinned_launch_file(executable, runner.runner_binary_digest) as launch:
            child = runner._spawn(
                [launch[0], "60"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                inherited_descriptors=launch[1],
            )
        executable_deadline = time.monotonic() + 5.0
        while True:
            try:
                observed_executable = (Path("/proc") / str(child.pid) / "exe").resolve(strict=True)
            except OSError:
                observed_executable = None
            if observed_executable == executable:
                break
            if child.poll() is not None or time.monotonic() >= executable_deadline:
                raise ProcessProofError("the Linux probe target never executed")
            time.sleep(0.005)
        identity_material = {
            "schema_version": POSIX_CONTAINMENT_IDENTITIES_SCHEMA,
            "child_program": "system-sleep",
            "child_executable_sha256": file_hash(executable),
            "parent_death_helper_sha256": runner.parent_death_script_digest,
            "supervisor": dict(_linux_process_identity(os.getpid())),
            "child": dict(_linux_process_identity(child.pid)),
        }
        _write_pipe_payload(
            descriptor,
            {
                "schema_version": _POSIX_READY_SCHEMA,
                "identity_material": identity_material,
            },
        )
        os.close(descriptor)
        descriptor = -1
        while True:
            _PAUSE()
    except BaseException:
        os._exit(71)
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _read_probe_ready(descriptor: int, deadline: float) -> Mapping[str, Any]:
    payload = bytearray()
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ProcessProofError("the Linux containment probe timed out")
        readable, _, _ = select.select([descriptor], [], [], remaining)
        if not readable:
            raise ProcessProofError("the Linux containment probe timed out")
        chunk = os.read(descriptor, 8193 - len(payload))
        if not chunk:
            break
        payload.extend(chunk)
        if len(payload) > 8192:
            raise ProcessProofError("the Linux containment probe exceeded its bound")
    try:
        value = json.loads(
            bytes(payload).decode("utf-8"),
            object_pairs_hook=_strict_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise ProcessProofError("the Linux containment probe output is invalid") from exc
    if (
        not isinstance(value, Mapping)
        or set(value) != {"schema_version", "identity_material"}
        or value.get("schema_version") != _POSIX_READY_SCHEMA
        or canonical_json_bytes(value) + b"\n" != bytes(payload)
    ):
        raise ProcessProofError("the Linux containment probe output is invalid")
    return value


def _wait_for_reaped_process(process_id: int, deadline: float) -> int:
    if not callable(_WAIT_PID):
        raise ProcessProofError("the Linux containment probe cannot reap processes")
    while time.monotonic() < deadline:
        try:
            waited, status = _WAIT_PID(process_id, _WAIT_NO_HANG)
        except ChildProcessError:
            time.sleep(0.01)
            continue
        if waited == process_id:
            return int(status)
        time.sleep(0.01)
    raise ProcessProofError("the Linux containment probe process survived")


def _pidfd_observed_exit(descriptor: int) -> bool:
    poll_factory = getattr(select, "poll", None)
    poll_in = getattr(select, "POLLIN", 1)
    poll_hup = getattr(select, "POLLHUP", 16)
    poll_error = getattr(select, "POLLERR", 8)
    if not callable(poll_factory):
        return False
    poller = poll_factory()
    poller.register(descriptor, poll_in | poll_hup | poll_error)
    return bool(poller.poll(1000))


def _positive_posix_identity(value: Any, label: str) -> Mapping[str, int]:
    fields = {"process_id", "process_group_id", "session_id", "start_time_ticks"}
    if (
        not isinstance(value, Mapping)
        or set(value) != fields
        or not all(type(value.get(key)) is int and 0 < int(value[key]) < 2**63 for key in fields)
    ):
        raise ProcessProofError(f"{label} is invalid")
    return {key: int(value[key]) for key in sorted(fields)}


def validate_posix_watchdog_containment_proof(value: Any) -> Mapping[str, Any]:
    """Validate exact dynamic evidence for the watchdog-owned Linux process group."""

    fields = {
        "schema_version",
        "passed",
        "proof_kind",
        "platform",
        "containment",
        "forced_signal",
        "termination_scope",
        "parent_death_contract",
        "identity_material",
        "identity_material_sha256",
        "supervisor_reaped",
        "child_reaped",
        "supervisor_exit_signal",
        "child_exit_signal",
        "pidfd_exit_observed",
        "absence_probes",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ProcessProofError("the POSIX watchdog containment proof fields are invalid")
    identity_material = value.get("identity_material")
    identity_fields = {
        "schema_version",
        "child_program",
        "child_executable_sha256",
        "parent_death_helper_sha256",
        "supervisor",
        "child",
    }
    if not isinstance(identity_material, Mapping) or set(identity_material) != identity_fields:
        raise ProcessProofError("the POSIX watchdog containment identity fields are invalid")
    supervisor = _positive_posix_identity(identity_material.get("supervisor"), "supervisor")
    child = _positive_posix_identity(identity_material.get("child"), "child")
    expected_probes = [
        {
            "delay_ms": delay,
            "supervisor_identity_present": False,
            "child_identity_present": False,
        }
        for delay in _POSIX_ABSENCE_DELAYS_MS
    ]
    valid = (
        value.get("schema_version") == POSIX_CONTAINMENT_SCHEMA
        and value.get("passed") is True
        and value.get("proof_kind") == "dynamic"
        and value.get("platform") == "linux"
        and value.get("containment") == "linux-parent-death-signal-private-session"
        and value.get("forced_signal") == "SIGKILL"
        and value.get("termination_scope") == "supervisor-pidfd-only"
        and value.get("parent_death_contract") == "PR_SET_PDEATHSIG"
        and identity_material.get("schema_version") == POSIX_CONTAINMENT_IDENTITIES_SCHEMA
        and identity_material.get("child_program") == "system-sleep"
        and isinstance(identity_material.get("child_executable_sha256"), str)
        and _SHA256.fullmatch(str(identity_material["child_executable_sha256"])) is not None
        and isinstance(identity_material.get("parent_death_helper_sha256"), str)
        and _SHA256.fullmatch(str(identity_material["parent_death_helper_sha256"])) is not None
        and supervisor["process_id"] == supervisor["process_group_id"] == supervisor["session_id"]
        and child["process_id"] != supervisor["process_id"]
        and child["process_group_id"] == supervisor["process_id"]
        and child["session_id"] == supervisor["process_id"]
        and value.get("identity_material_sha256") == content_hash(identity_material)
        and value.get("supervisor_reaped") is True
        and value.get("child_reaped") is True
        and value.get("supervisor_exit_signal") == "SIGKILL"
        and value.get("child_exit_signal") == "SIGKILL"
        and value.get("pidfd_exit_observed") is True
        and value.get("absence_probes") == expected_probes
    )
    if not valid:
        raise ProcessProofError("the POSIX watchdog containment proof is invalid")
    return value


def posix_watchdog_crash_containment(work_root: Path) -> Mapping[str, Any]:
    """Kill only a private supervisor PID and prove its armed child was reaped."""

    if (
        not sys.platform.startswith("linux")
        or not callable(_FORK)
        or not callable(_PIDFD_OPEN)
        or not callable(_PIDFD_SEND_SIGNAL)
        or not callable(_GET_PROCESS_GROUP_ID)
        or not callable(_GET_SESSION_ID)
    ):
        raise ProcessProofError("the Linux watchdog containment probe is unavailable")
    root = work_root.resolve()
    root.mkdir(mode=0o700, parents=False, exist_ok=False)
    read_descriptor, write_descriptor = os.pipe()
    supervisor_pid = -1
    child_pid = -1
    pidfds: dict[int, int] = {}
    supervisor_identity: Mapping[str, int] | None = None
    child_identity: Mapping[str, int] | None = None
    subreaper = False
    previous_subreaper = False
    supervisor_reaped = False
    child_reaped = False
    try:
        previous_subreaper = _child_subreaper_enabled()
        _set_child_subreaper(True)
        subreaper = True
        supervisor_pid = int(_FORK())
        if supervisor_pid == 0:
            os.close(read_descriptor)
            _posix_probe_supervisor(write_descriptor, root)
            os._exit(74)
        supervisor_identity = _linux_process_identity(supervisor_pid)
        pidfds[supervisor_pid] = _open_identity_bound_pidfd(supervisor_identity)
        os.close(write_descriptor)
        write_descriptor = -1
        ready = _read_probe_ready(read_descriptor, time.monotonic() + 10.0)
        identity_material = ready.get("identity_material")
        if not isinstance(identity_material, Mapping):
            raise ProcessProofError("the Linux containment identities are unavailable")
        supervisor = _positive_posix_identity(identity_material.get("supervisor"), "supervisor")
        child = _positive_posix_identity(identity_material.get("child"), "child")
        if _linux_process_instance(supervisor_identity) != _linux_process_instance(supervisor):
            raise ProcessProofError("the Linux watchdog identity changed before readiness")
        supervisor_identity = supervisor
        child_identity = child
        child_pid = child["process_id"]
        if (
            supervisor["process_id"] != supervisor_pid
            or supervisor["process_group_id"] != supervisor_pid
            or supervisor["session_id"] != supervisor_pid
            or child["process_group_id"] != supervisor_pid
            or child["session_id"] != supervisor_pid
            or not _linux_identity_present(supervisor)
            or not _linux_identity_present(child)
        ):
            raise ProcessProofError("the Linux watchdog and child containment topology is invalid")
        pidfds[child_pid] = _open_identity_bound_pidfd(child)
        if not _linux_identity_present(supervisor) or not _linux_identity_present(child):
            raise ProcessProofError("the Linux watchdog pidfds are not identity-bound")
        _PIDFD_SEND_SIGNAL(pidfds[supervisor_pid], _SIGKILL, None, 0)
        deadline = time.monotonic() + 10.0
        supervisor_status = _wait_for_reaped_process(supervisor_pid, deadline)
        supervisor_reaped = True
        child_status = _wait_for_reaped_process(child_pid, deadline)
        child_reaped = True
        if (
            not os.WIFSIGNALED(supervisor_status)
            or os.WTERMSIG(supervisor_status) != signal.SIGKILL
            or not os.WIFSIGNALED(child_status)
            or os.WTERMSIG(child_status) != signal.SIGKILL
        ):
            raise ProcessProofError("the Linux parent-death signal was not observed")
        pidfd_exit_observed = all(
            _pidfd_observed_exit(pidfds[process_id]) for process_id in (supervisor_pid, child_pid)
        )
        probes: list[Mapping[str, Any]] = []
        for delay_ms in _POSIX_ABSENCE_DELAYS_MS:
            if delay_ms:
                time.sleep(delay_ms / 1000)
            probes.append(
                {
                    "delay_ms": delay_ms,
                    "supervisor_identity_present": _linux_identity_present(supervisor),
                    "child_identity_present": _linux_identity_present(child),
                }
            )
        proof = {
            "schema_version": POSIX_CONTAINMENT_SCHEMA,
            "passed": True,
            "proof_kind": "dynamic",
            "platform": "linux",
            "containment": "linux-parent-death-signal-private-session",
            "forced_signal": "SIGKILL",
            "termination_scope": "supervisor-pidfd-only",
            "parent_death_contract": "PR_SET_PDEATHSIG",
            "identity_material": dict(identity_material),
            "identity_material_sha256": content_hash(identity_material),
            "supervisor_reaped": supervisor_reaped,
            "child_reaped": child_reaped,
            "supervisor_exit_signal": "SIGKILL",
            "child_exit_signal": "SIGKILL",
            "pidfd_exit_observed": pidfd_exit_observed,
            "absence_probes": probes,
        }
        return validate_posix_watchdog_containment_proof(proof)
    except (OSError, ValueError) as exc:
        if isinstance(exc, ProcessProofError):
            raise
        raise ProcessProofError("the Linux watchdog containment probe failed") from exc
    finally:
        for descriptor in (read_descriptor, write_descriptor):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        if supervisor_pid > 0 and not supervisor_reaped:
            if supervisor_identity is not None:
                try:
                    reaped = _cleanup_failed_posix_private_session(supervisor_identity, pidfds)
                    supervisor_reaped = supervisor_pid in reaped
                    child_reaped = child_reaped or child_pid in reaped
                except (OSError, ProcessProofError, ValueError):
                    pass
            supervisor_descriptor = pidfds.get(supervisor_pid)
            if supervisor_descriptor is None and supervisor_identity is not None:
                try:
                    supervisor_descriptor = _open_identity_bound_pidfd(supervisor_identity)
                    pidfds[supervisor_pid] = supervisor_descriptor
                except (OSError, ProcessProofError, ValueError):
                    supervisor_descriptor = None
            try:
                if not supervisor_reaped and supervisor_descriptor is not None:
                    _PIDFD_SEND_SIGNAL(supervisor_descriptor, _SIGKILL, None, 0)
            except (OSError, ProcessLookupError):
                pass
            if not supervisor_reaped:
                try:
                    _wait_for_reaped_process(supervisor_pid, time.monotonic() + 2.0)
                except ProcessProofError:
                    pass
        if child_pid > 0 and not child_reaped:
            child_descriptor = pidfds.get(child_pid)
            if child_descriptor is None and child_identity is not None:
                try:
                    child_descriptor = _open_identity_bound_pidfd(child_identity)
                    pidfds[child_pid] = child_descriptor
                except (OSError, ProcessProofError, ValueError):
                    child_descriptor = None
            try:
                if child_descriptor is not None:
                    _PIDFD_SEND_SIGNAL(child_descriptor, _SIGKILL, None, 0)
            except (OSError, ProcessLookupError):
                pass
            try:
                _wait_for_reaped_process(child_pid, time.monotonic() + 2.0)
            except ProcessProofError:
                pass
        for descriptor in pidfds.values():
            try:
                os.close(descriptor)
            except OSError:
                pass
        if subreaper:
            _set_child_subreaper(previous_subreaper)


class _CancellationReadinessEvent(threading.Event):
    """Turn the runner's existing caller-thread cancellation poll into readiness proof."""

    def __init__(self, control_root: Path, *, task_id: str, request_hash: str) -> None:
        super().__init__()
        self._control_root = control_root
        self._task_id = task_id
        self._request_hash = request_hash
        self._deadline = time.monotonic() + _CANCELLATION_READY_TIMEOUT_SECONDS
        self.observation: tuple[Mapping[str, Any], Mapping[str, Any], bool] | None = None
        self.failure: BaseException | None = None
        self.timed_out = False

    def is_set(self) -> bool:
        if super().is_set():
            return True
        if time.monotonic() >= self._deadline:
            self.timed_out = True
            self.set()
            return True
        if not self._control_root.is_dir() or not (self._control_root / "ready.json").is_file():
            return False
        try:
            ready = _ready_record(
                self._control_root,
                task_id=self._task_id,
                request_hash=self._request_hash,
            )
            try:
                parent = dict(capture_process_identity(int(ready["parent_process_id"])))
                descendant = dict(capture_process_identity(int(ready["descendant_process_id"])))
            except RecoveryWitnessError as exc:
                raise ProcessProofError("the cancellation process identity is unavailable") from exc
            simultaneously_live = (
                parent != descendant
                and process_identity_running(parent)
                and process_identity_running(descendant)
            )
            self.observation = (parent, descendant, simultaneously_live)
        except BaseException as exc:
            self.failure = exc
        self.set()
        return True


def _execute_cancellation_task(
    runner: TaskAwareRunnerTransport,
    manifest: Mapping[str, Any],
    profile: Mapping[str, Any],
    *,
    task_id: str,
    request_hash: str,
    control_root: Path,
    durable_result_path: Path,
    require: Callable[[bool, str], object],
) -> tuple[RunnerTaskCancelled, Mapping[str, Any], Mapping[str, Any]]:
    """Run and observe cancellation entirely on the launcher's caller thread."""

    cancel = _CancellationReadinessEvent(
        control_root,
        task_id=task_id,
        request_hash=request_hash,
    )
    cancellation_error: RunnerTaskCancelled | None = None
    execution_failure: BaseException | None = None
    try:
        runner.execute_task(
            manifest,
            profile,
            task_id=task_id,
            cancel_event=cancel,
            durable_result_path=durable_result_path,
        )
    except RunnerTaskCancelled as exc:
        cancellation_error = exc
    except BaseException as exc:
        execution_failure = exc
    finally:
        cancel.set()

    if execution_failure is not None:
        raise execution_failure
    if cancel.failure is not None:
        raise cancel.failure
    if cancel.timed_out:
        require(False, "the packaged Rust cancellation witness never started")
    require(
        cancel.observation is not None,
        "the packaged Rust cancellation witness never started",
    )
    if cancel.observation is None:
        raise ProcessProofError("the packaged Rust cancellation witness never started")
    parent_identity, descendant_identity, simultaneously_live = cancel.observation
    require(
        simultaneously_live,
        "the cancellation parent and descendant were not simultaneously live",
    )
    if not simultaneously_live:
        raise ProcessProofError(
            "the cancellation parent and descendant were not simultaneously live"
        )
    require(cancellation_error is not None, "the runner did not return typed cancellation")
    if cancellation_error is None:
        raise ProcessProofError("the runner did not return typed cancellation")
    return cancellation_error, parent_identity, descendant_identity


def process_tree_cancellation(
    runtime: Path,
    resource_root: Path,
    service: _Service,
    *,
    expected_runner_digest: str,
    require: Callable[[bool, str], None] | None = None,
) -> Mapping[str, Any]:
    """Cancel one real packaged Rust action and prove its exact tree absent."""

    check = require or (lambda condition, message: condition or (_raise(message)))
    check(os.name == "nt", "the Windows cancellation witness is unavailable")
    work = runtime / "cancellation"
    work.mkdir()
    runner_work = work / "runner-work"
    runner_work.mkdir()
    sandbox = work / "sandbox"
    profile = next(
        (item for item in service.config.runner_profiles if item.id == PROFILE_ID),
        None,
    )
    check(profile is not None, "the cancellation witness runner profile is unavailable")
    profile = cast("RunnerProfile", profile)
    profile_doc = build_runner_profile(
        profile,
        sandbox_root=sandbox,
        platform="windows",
        filesystem_scope=(CONTROL_PARENT,),
    )
    action = service.registry.get_action(ACTION_ID)
    manifest = build_execution_manifest(
        run_id="run-20260829T120000Z-abcdef0123456789",
        step_id="process_tree_cancellation_witness",
        behavior_id=ACTION_ID,
        action=action,
        runner_profile=profile_doc,
        params={},
        filesystem_scope=(CONTROL_PARENT,),
        network_destinations=(),
        evidence_refs=(),
        approval_record=_approval_record(),
        timeout_ms=15_000,
    )
    request_hash = str(manifest["request_hash"])
    task_id = "execute-" + request_hash.removeprefix("sha256:")
    control_parent = sandbox / CONTROL_PARENT
    control_root = control_parent / request_hash.removeprefix("sha256:")
    binary = (resource_root / "bluefire-runner.exe").resolve(strict=True)
    binary_digest = file_hash(binary)
    check(
        binary_digest == expected_runner_digest,
        "the cancellation witness did not use the wheel-bound runner",
    )
    durable = (work / "durable" / "result.json").resolve()
    runner = SubprocessRustRunner(
        binary,
        runner_work,
        timeout_seconds=20.0,
        output_limit_bytes=64 * 1024,
    )
    cancellation_error, parent_identity, descendant_identity = _execute_cancellation_task(
        runner,
        manifest,
        profile_doc,
        task_id=task_id,
        request_hash=request_hash,
        control_root=control_root,
        durable_result_path=durable,
        require=check,
    )
    survivor_probes: list[Mapping[str, Any]] = []
    for delay_ms in (0, 100, 250):
        if delay_ms:
            time.sleep(delay_ms / 1000)
        survivor_probes.append(
            {
                "delay_ms": delay_ms,
                "parent_running": process_identity_running(parent_identity),
                "descendant_running": process_identity_running(descendant_identity),
            }
        )
    no_survivors = not any(
        bool(row["parent_running"]) or bool(row["descendant_running"]) for row in survivor_probes
    )
    control_state_removed = not control_root.exists() and (
        not control_parent.exists() or _remove_empty_control_parent(control_parent)
    )
    clean_transport_state = (
        not durable.exists()
        and not runner_pending_result_path(durable, task_id).exists()
        and not runner_watchdog_control_root(durable, task_id).exists()
    )
    check(
        cancellation_error.cooperative_requested
        and cancellation_error.cooperative_acknowledged
        and cancellation_error.forced_tree_termination
        and cancellation_error.control_cleanup_verified
        and no_survivors
        and control_state_removed
        and clean_transport_state,
        "the cancellation tree retained a survivor, control object, or unresolved state",
    )
    return {
        "schema_version": CANCELLATION_SCHEMA,
        "passed": True,
        "proof_kind": "dynamic",
        "platform": "windows",
        "action_id": ACTION_ID,
        "behavior_id": ACTION_ID,
        "profile_id": PROFILE_ID,
        "containment": "windows-job-object-kill-on-close",
        "runner_binary_sha256": binary_digest,
        "cancellation": {
            "task_id": task_id,
            "request_hash": request_hash,
            "terminal_state": "cancelled",
            "parent_process_identity": parent_identity,
            "descendant_process_identity": descendant_identity,
            "cooperative_requested": True,
            "cooperative_acknowledged": True,
            "forced_tree_termination": True,
            "control_cleanup_verified": True,
            "control_state_removed": True,
            "parent_was_running": True,
            "descendant_was_running": True,
            "survivor_probe_count": len(survivor_probes),
            "survivor_probes": survivor_probes,
            "no_survivors": no_survivors,
            "identity_material_sha256": "sha256:"
            + hashlib.sha256(
                (
                    f"{parent_identity['process_id']}:{parent_identity['creation_time_100ns']}\n"
                    f"{descendant_identity['process_id']}:"
                    f"{descendant_identity['creation_time_100ns']}\n"
                ).encode("ascii")
            ).hexdigest(),
        },
    }


def _raise(message: str) -> bool:
    raise ProcessProofError(message)


__all__ = [
    "ACTION_ID",
    "CANCELLATION_SCHEMA",
    "CONTROL_PARENT",
    "POSIX_CONTAINMENT_IDENTITIES_SCHEMA",
    "POSIX_CONTAINMENT_SCHEMA",
    "PROFILE_ID",
    "ProcessProofError",
    "posix_watchdog_crash_containment",
    "process_tree_cancellation",
    "validate_posix_watchdog_containment_proof",
]
