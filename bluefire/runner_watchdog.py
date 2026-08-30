"""Crash-surviving supervisor for one exact fixed Rust runner task.

This module is launched with isolated Python module resolution by
``SubprocessRustRunner.execute_task``.  It has one intentionally tiny CLI: an
absolute path to a private, bounded configuration file.  It never accepts a
command, argument vector, environment variable, or executable choice from the
authenticated transport request.
"""

from __future__ import annotations

import math
import os
import re
import secrets
import stat
import sys
import threading
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Mapping, Sequence

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve(strict=True).parent.parent))
    from bluefire.runner_client import (
        RunnerDurableResultExists,
        RunnerPendingResultExists,
        RunnerTaskCancelled,
        RunnerTransportError,
        SubprocessRustRunner,
        _consume_receiver_task_environment,
        _PinnedPrivateDirectory,
        runner_watchdog_control_root,
    )
    from bluefire.runner_trust import _is_link_or_reparse
    from bluefire.util import canonical_json_bytes, file_hash
else:
    from .runner_client import (
        RunnerDurableResultExists,
        RunnerPendingResultExists,
        RunnerTaskCancelled,
        RunnerTransportError,
        SubprocessRustRunner,
        _consume_receiver_task_environment,
        _PinnedPrivateDirectory,
        runner_watchdog_control_root,
    )
    from .runner_trust import _is_link_or_reparse
    from .util import canonical_json_bytes, file_hash

_CONFIG_SCHEMA = "bluefire.runner-watchdog-config.v2"
_READY_SCHEMA = "bluefire.runner-watchdog-ready.v1"
_STATUS_SCHEMA = "bluefire.runner-watchdog-status.v2"
_CONFIG_LIMIT_BYTES = 8 * 1024 * 1024
_STATUS_LIMIT_BYTES = 4096
_START_TIMEOUT_SECONDS = 10.0
_POLL_SECONDS = 0.025
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_CANCELLATION_ACTION_ID = "sandbox.execution.process-tree-cancellation-witness.v1"
_CANCELLATION_CONTROL_PARENT = ".bluefire-cancellation-witness-v1"
_CANCELLATION_READY_SCHEMA = "bluefire.process-tree-cancellation-ready.v1"
_CANCELLATION_ACK_TIMEOUT_SECONDS = 2.0
_CONFIG_KEYS = frozenset(
    {
        "schema_version",
        "task_id",
        "runner_binary",
        "runner_binary_digest",
        "parent_death_script_digest",
        "watchdog_script_digest",
        "work_root",
        "timeout_seconds",
        "output_limit_bytes",
        "durable_result_path",
        "manifest",
        "profile",
        "cancellation_lease_token",
    }
)


@dataclass(frozen=True)
class _WatchdogConfig:
    task_id: str
    runner_binary: Path
    runner_binary_digest: str
    parent_death_script_digest: str
    watchdog_script_digest: str
    work_root: Path
    timeout_seconds: float
    output_limit_bytes: int
    durable_result_path: Path
    manifest: Mapping[str, Any]
    profile: Mapping[str, Any]
    cancellation_lease_token: str | None
    control_root: Path
    control: _PinnedPrivateDirectory

    @property
    def start_path(self) -> Path:
        return self.control_root / "start"

    @property
    def cancel_path(self) -> Path:
        return self.control_root / "cancel"

    @property
    def ready_path(self) -> Path:
        return self.control_root / "ready.json"

    @property
    def status_path(self) -> Path:
        return self.control_root / "status.json"

    @property
    def config_path(self) -> Path:
        return self.control_root / "config.json"


@dataclass(frozen=True)
class _CapturedControlFile:
    payload: bytes
    identity: tuple[int, int]


@dataclass(frozen=True)
class _CancellationHandshake:
    ready: _CapturedControlFile
    request: _CapturedControlFile | None = None
    acknowledgement: _CapturedControlFile | None = None


def _load_config(path_argument: str) -> _WatchdogConfig:
    path = Path(path_argument)
    try:
        if not path.is_absolute() or path.name != "config.json":
            raise OSError("invalid watchdog configuration path")
        control_root = path.parent.resolve(strict=True)
        if control_root != path.parent:
            raise OSError("watchdog control identity changed")
        with _PinnedPrivateDirectory(control_root) as pinned:
            raw = pinned.read("config.json", maximum=_CONFIG_LIMIT_BYTES)
            control_identity = pinned.directory_identity()
    except (OSError, RunnerTransportError):
        raise RunnerTransportError("runner watchdog state is unavailable") from None

    value = SubprocessRustRunner._decode_json(raw, "runner watchdog configuration")
    if set(value) != _CONFIG_KEYS or value.get("schema_version") != _CONFIG_SCHEMA:
        raise RunnerTransportError("runner watchdog configuration is invalid")

    task_id = value.get("task_id")
    binary_digest = value.get("runner_binary_digest")
    parent_death_digest = value.get("parent_death_script_digest")
    watchdog_digest = value.get("watchdog_script_digest")
    timeout_seconds = value.get("timeout_seconds")
    output_limit_bytes = value.get("output_limit_bytes")
    manifest = value.get("manifest")
    profile = value.get("profile")
    cancellation_lease_token = value.get("cancellation_lease_token")
    if (
        not isinstance(task_id, str)
        or not isinstance(binary_digest, str)
        or _DIGEST.fullmatch(binary_digest) is None
        or not isinstance(parent_death_digest, str)
        or _DIGEST.fullmatch(parent_death_digest) is None
        or not isinstance(watchdog_digest, str)
        or _DIGEST.fullmatch(watchdog_digest) is None
        or isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, int | float)
        or not math.isfinite(float(timeout_seconds))
        or not 0 < float(timeout_seconds) <= 86_400
        or isinstance(output_limit_bytes, bool)
        or not isinstance(output_limit_bytes, int)
        or not 4096 <= output_limit_bytes <= 64 * 1024 * 1024
        or not isinstance(manifest, dict)
        or not isinstance(profile, dict)
        or (
            manifest.get("action_id") == _CANCELLATION_ACTION_ID
            and (
                not isinstance(cancellation_lease_token, str)
                or re.fullmatch(r"[0-9a-f]{64}", cancellation_lease_token) is None
            )
        )
        or (
            manifest.get("action_id") != _CANCELLATION_ACTION_ID
            and cancellation_lease_token is not None
        )
    ):
        raise RunnerTransportError("runner watchdog configuration is invalid")

    try:
        watchdog_script = Path(__file__).resolve(strict=True)
        watchdog_details = watchdog_script.lstat()
        parent_death_script = watchdog_script.with_name("runner_parent_death.py")
        parent_death_details = parent_death_script.lstat()
        binary_raw = value.get("runner_binary")
        work_raw = value.get("work_root")
        destination_raw = value.get("durable_result_path")
        if not all(isinstance(item, str) for item in (binary_raw, work_raw, destination_raw)):
            raise OSError("invalid watchdog paths")
        runner_binary = Path(str(binary_raw))
        work_root = Path(str(work_raw))
        destination = Path(str(destination_raw))
        if (
            not stat.S_ISREG(watchdog_details.st_mode)
            or watchdog_details.st_nlink != 1
            or _is_link_or_reparse(watchdog_script)
            or file_hash(watchdog_script) != watchdog_digest
            or watchdog_script.name != "runner_watchdog.py"
            or not stat.S_ISREG(parent_death_details.st_mode)
            or parent_death_details.st_nlink != 1
            or _is_link_or_reparse(parent_death_script)
            or file_hash(parent_death_script) != parent_death_digest
            or parent_death_script.name != "runner_parent_death.py"
            or not runner_binary.is_absolute()
            or not work_root.is_absolute()
            or not destination.is_absolute()
        ):
            raise OSError("watchdog paths must be absolute")
        runner_binary = runner_binary.resolve(strict=True)
        work_root = work_root.resolve(strict=True)
        destination = destination.resolve(strict=False)
        if (
            not runner_binary.is_file()
            or not work_root.is_dir()
            or _is_link_or_reparse(runner_binary)
            or _is_link_or_reparse(work_root)
        ):
            raise OSError("unsafe watchdog paths")
        expected_root = runner_watchdog_control_root(destination, task_id)
        if expected_root != control_root:
            raise OSError("watchdog task identity changed")
    except (OSError, RunnerTransportError):
        raise RunnerTransportError("runner watchdog configuration is invalid") from None

    control = _PinnedPrivateDirectory(
        control_root,
        expected_identity=control_identity,
    )
    try:
        control.__enter__()
    except (OSError, RunnerTransportError):
        control.close()
        raise RunnerTransportError("runner watchdog state is unavailable") from None

    return _WatchdogConfig(
        task_id=task_id,
        runner_binary=runner_binary,
        runner_binary_digest=binary_digest,
        parent_death_script_digest=parent_death_digest,
        watchdog_script_digest=watchdog_digest,
        work_root=work_root,
        timeout_seconds=float(timeout_seconds),
        output_limit_bytes=output_limit_bytes,
        durable_result_path=destination,
        manifest=manifest,
        profile=profile,
        cancellation_lease_token=cancellation_lease_token,
        control_root=control_root,
        control=control,
    )


def _write_private_json(
    config: _WatchdogConfig,
    name: str,
    value: Mapping[str, Any],
) -> None:
    payload = canonical_json_bytes(dict(value)) + b"\n"
    if len(payload) > _STATUS_LIMIT_BYTES:
        raise RunnerTransportError("runner watchdog status exceeds its size limit")
    try:
        config.control.create(name, payload, maximum=_STATUS_LIMIT_BYTES)
    except (OSError, RunnerTransportError):
        raise RunnerTransportError("runner watchdog state is unavailable") from None


def _signal_exists(config: _WatchdogConfig, name: str, expected: bytes) -> bool:
    try:
        if not config.control.has_name(name):
            return False
        return config.control.read(name, maximum=32) == expected
    except (OSError, RunnerTransportError):
        # An invalid object at a control name is treated as fail-closed cancel.
        return name == "cancel"


def _wait_for_start(config: _WatchdogConfig) -> str:
    deadline = time.monotonic() + _START_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if _signal_exists(config, "cancel", b"cancel\n"):
            return "cancelled"
        if _signal_exists(config, "start", b"start\n"):
            return "started"
        time.sleep(_POLL_SECONDS)
    return "start_timeout"


def _cooperative_cancellation(
    config: _WatchdogConfig,
    requested: threading.Event,
    acknowledged: threading.Event,
    runner_process_ids: Sequence[int],
    handshakes: list[_CancellationHandshake] | None = None,
) -> None:
    """Request the one reviewed Rust witness handshake through fixed private names."""

    captured = handshakes if handshakes is not None else []
    if captured:
        return
    control_paths = _cancellation_control_paths(config)
    if control_paths is None:
        return
    control_parent, control_root = control_paths
    try:
        if (
            _is_link_or_reparse(control_parent)
            or control_parent.resolve(strict=True) != control_root.parent
            or _is_link_or_reparse(control_root)
            or control_root.resolve(strict=True).parent != control_parent
        ):
            return
        with _PinnedPrivateDirectory(control_parent):
            with _PinnedPrivateDirectory(control_root, share_delete=True) as control:
                if set(control.names(maximum=5)) != {".lease", "ready.json"}:
                    return
                expected_lease = f"lease:{config.cancellation_lease_token}\n".encode("ascii")
                if control.read(".lease", maximum=72, apply_permissions=False) != expected_lease:
                    return
                ready_payload, ready_identity = control.read_with_identity(
                    "ready.json", maximum=1024, apply_permissions=False
                )
                ready = _decode_cancellation_ready(config, ready_payload)
                if (
                    len(runner_process_ids) != 1
                    or ready.get("parent_process_id") != runner_process_ids[0]
                ):
                    return
                captured.append(
                    _CancellationHandshake(
                        ready=_CapturedControlFile(ready_payload, ready_identity)
                    )
                )
                nonce = secrets.token_hex(32)
                request = f"cancel:{nonce}\n".encode("ascii")
                expected_ack = f"ack:{nonce}\n".encode("ascii")
                control.create("cancel.request", request, maximum=72)
                request_payload, request_identity = control.read_with_identity(
                    "cancel.request", maximum=72, apply_permissions=False
                )
                if request_payload != request:
                    return
                captured[0] = replace(
                    captured[0],
                    request=_CapturedControlFile(request_payload, request_identity),
                )
                requested.set()
                deadline = time.monotonic() + _CANCELLATION_ACK_TIMEOUT_SECONDS
                while time.monotonic() < deadline:
                    if control.has_name("cancel.ack"):
                        ack_payload, ack_identity = control.read_with_identity(
                            "cancel.ack", maximum=69, apply_permissions=False
                        )
                        if ack_payload == expected_ack:
                            captured[0] = replace(
                                captured[0],
                                acknowledgement=_CapturedControlFile(
                                    ack_payload,
                                    ack_identity,
                                ),
                            )
                            acknowledged.set()
                        return
                    time.sleep(_POLL_SECONDS)
    except (FileExistsError, OSError, RunnerTransportError, ValueError):
        return


def _cancellation_control_paths(config: _WatchdogConfig) -> tuple[Path, Path] | None:
    manifest = config.manifest
    profile = config.profile
    request_hash = manifest.get("request_hash")
    expected_task_id = (
        "execute-" + request_hash.removeprefix("sha256:")
        if isinstance(request_hash, str) and _DIGEST.fullmatch(request_hash) is not None
        else None
    )
    if (
        manifest.get("action_id") != _CANCELLATION_ACTION_ID
        or manifest.get("behavior_id") != _CANCELLATION_ACTION_ID
        or manifest.get("params") != {}
        or manifest.get("platform") != "windows"
        or profile.get("platform") != "windows"
        or expected_task_id is None
        or config.task_id != expected_task_id
    ):
        return None
    sandbox_raw = profile.get("sandbox_root")
    if not isinstance(sandbox_raw, str):
        return None
    try:
        sandbox = Path(sandbox_raw)
        if not sandbox.is_absolute() or _is_link_or_reparse(sandbox):
            return None
        sandbox = sandbox.resolve(strict=True)
        if not sandbox.is_dir():
            return None
        parent = sandbox / _CANCELLATION_CONTROL_PARENT
        return parent, parent / str(request_hash).removeprefix("sha256:")
    except (OSError, RunnerTransportError):
        return None


def _decode_cancellation_ready(
    config: _WatchdogConfig,
    payload: bytes,
) -> Mapping[str, Any]:
    ready = SubprocessRustRunner._decode_json(
        payload,
        "runner cancellation readiness",
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
        or ready.get("schema_version") != _CANCELLATION_READY_SCHEMA
        or ready.get("task_id") != config.task_id
        or ready.get("request_hash") != config.manifest.get("request_hash")
        or type(ready.get("parent_process_id")) is not int
        or int(ready["parent_process_id"]) <= 0
        or type(ready.get("descendant_process_id")) is not int
        or int(ready["descendant_process_id"]) <= 0
        or ready["parent_process_id"] == ready["descendant_process_id"]
    ):
        raise RunnerTransportError("runner cancellation readiness is invalid")
    return ready


def _cancellation_ready(
    config: _WatchdogConfig,
    control: _PinnedPrivateDirectory,
) -> Mapping[str, Any]:
    return _decode_cancellation_ready(
        config,
        control.read("ready.json", maximum=1024, apply_permissions=False),
    )


def _cleanup_cooperative_cancellation(
    config: _WatchdogConfig,
    requested: threading.Event,
    acknowledged: threading.Event,
    handshakes: Sequence[_CancellationHandshake] = (),
) -> bool:
    """Delete only identities captured during the live fixed handshake."""

    control_paths = _cancellation_control_paths(config)
    if control_paths is None:
        return True
    control_parent, control_root = control_paths
    try:
        if not control_root.exists():
            return False
        if (
            _is_link_or_reparse(control_parent)
            or control_parent.resolve(strict=True) != control_root.parent
            or _is_link_or_reparse(control_root)
            or control_root.resolve(strict=True).parent != control_parent
        ):
            return False
        with _PinnedPrivateDirectory(control_parent):
            with _PinnedPrivateDirectory(control_root, share_delete=True) as control:
                names = set(control.names(maximum=5))
                expected_lease = f"lease:{config.cancellation_lease_token}\n".encode("ascii")
                if (
                    ".lease" not in names
                    or control.read(".lease", maximum=72, apply_permissions=False) != expected_lease
                ):
                    return False
                if not handshakes:
                    return (
                        names == {".lease"} and not requested.is_set() and not acknowledged.is_set()
                    )
                if len(handshakes) != 1:
                    return False
                handshake = handshakes[0]
                records: dict[str, _CapturedControlFile] = {
                    "ready.json": handshake.ready,
                }
                if handshake.request is not None:
                    records["cancel.request"] = handshake.request
                if handshake.acknowledgement is not None:
                    records["cancel.ack"] = handshake.acknowledgement
                if names != {".lease", *records}:
                    return False
                if requested.is_set() != (handshake.request is not None):
                    return False
                if acknowledged.is_set() != (handshake.acknowledgement is not None):
                    return False
                _decode_cancellation_ready(config, handshake.ready.payload)
                for name, record in sorted(records.items()):
                    maximum = 72 if name == "cancel.request" else 1024
                    observed, observed_identity = control.read_with_identity(
                        name,
                        maximum=maximum,
                        expected_identity=record.identity,
                    )
                    if observed != record.payload or observed_identity != record.identity:
                        return False
                    control.unlink(
                        name,
                        maximum=maximum,
                        expected=record.payload,
                        expected_identity=record.identity,
                    )
                return set(control.names(maximum=2)) == {".lease"}
    except (OSError, RunnerTransportError, ValueError):
        return False


def _classify_failure(error: RunnerTransportError) -> str:
    message = str(error).casefold()
    if "timed out" in message:
        return "timed_out"
    if "output limit" in message:
        return "output_limit"
    if "unsupported result schema" in message:
        return "unsupported_result_schema"
    if "not valid utf-8 json" in message:
        return "invalid_json"
    if "result" in message or "does not match" in message or "json" in message:
        return "invalid_result"
    return "runner_failure"


def _cleanup_private_inputs(config: _WatchdogConfig) -> None:
    for name in ("config.json", "start", "cancel", "ready.json"):
        try:
            identity = config.control.file_identity(
                name,
                maximum=_CONFIG_LIMIT_BYTES,
                apply_permissions=False,
            )
            config.control.unlink(
                name,
                maximum=_CONFIG_LIMIT_BYTES,
                expected_identity=identity,
            )
        except (OSError, RunnerTransportError):
            continue


def _run(
    config: _WatchdogConfig,
    *,
    receiver_environment: Mapping[str, str],
) -> tuple[str, str | None, Mapping[str, bool] | None]:
    gate = _wait_for_start(config)
    if gate == "cancelled":
        return (
            "cancelled",
            "cancelled",
            {
                "cooperative_requested": False,
                "cooperative_acknowledged": False,
                "forced_tree_termination": False,
                "control_cleanup_verified": True,
            },
        )
    if gate != "started":
        return "failed", "start_timeout", None

    cancel_event = threading.Event()
    cooperative_request_event = threading.Event()
    cooperative_ack_event = threading.Event()
    runner_process_ids: list[int] = []
    cancellation_handshakes: list[_CancellationHandshake] = []
    stop_polling = threading.Event()

    def observe_cancel() -> None:
        while not stop_polling.is_set():
            if _signal_exists(config, "cancel", b"cancel\n"):
                try:
                    _cooperative_cancellation(
                        config,
                        cooperative_request_event,
                        cooperative_ack_event,
                        runner_process_ids,
                        cancellation_handshakes,
                    )
                finally:
                    cancel_event.set()
                return
            stop_polling.wait(_POLL_SECONDS)

    observer = threading.Thread(
        target=observe_cancel,
        name="bluefire-watchdog-cancel",
        daemon=True,
    )
    observer.start()
    try:
        if file_hash(config.runner_binary) != config.runner_binary_digest:
            return "failed", "runner_identity_changed", None
        runner = SubprocessRustRunner(
            config.runner_binary,
            config.work_root,
            timeout_seconds=config.timeout_seconds,
            output_limit_bytes=config.output_limit_bytes,
            _kill_child_on_job_close=True,
        )
        if runner.parent_death_script_digest != config.parent_death_script_digest:
            return "failed", "runner_identity_changed", None
        runner._execute_task_locally(
            config.manifest,
            config.profile,
            task_id=config.task_id,
            cancel_event=cancel_event,
            durable_result_path=config.durable_result_path,
            receiver_environment=receiver_environment,
            cooperative_request_event=cooperative_request_event,
            cooperative_ack_event=cooperative_ack_event,
            runner_process_id_sink=runner_process_ids,
            cancellation_lease_token=config.cancellation_lease_token,
        )
        return "succeeded", None, None
    except RunnerTaskCancelled as exc:
        cleanup_verified = _cleanup_cooperative_cancellation(
            config,
            cooperative_request_event,
            cooperative_ack_event,
            cancellation_handshakes,
        )
        if config.manifest.get("action_id") == _CANCELLATION_ACTION_ID and not cleanup_verified:
            return "failed", "cancellation_cleanup_failed", None
        return (
            "cancelled",
            "cancelled",
            {
                "cooperative_requested": exc.cooperative_requested,
                "cooperative_acknowledged": exc.cooperative_acknowledged,
                "forced_tree_termination": exc.forced_tree_termination,
                "control_cleanup_verified": cleanup_verified,
            },
        )
    except RunnerDurableResultExists:
        return "failed", "durable_result_exists", None
    except RunnerPendingResultExists:
        return "failed", "pending_result_exists", None
    except RunnerTransportError as exc:
        return "failed", _classify_failure(exc), None
    except BaseException:
        return "failed", "watchdog_failure", None
    finally:
        stop_polling.set()
        observer.join(timeout=1)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) != 1:
        return 64
    try:
        config = _load_config(arguments[0])
    except RunnerTransportError:
        return 65
    try:
        receiver_environment = _consume_receiver_task_environment(expected_task_id=config.task_id)
    except RunnerTransportError:
        config.control.close()
        return 65

    try:
        _write_private_json(
            config,
            "ready.json",
            {
                "schema_version": _READY_SCHEMA,
                "task_id": config.task_id,
                "watchdog_pid": os.getpid(),
            },
        )
    except RunnerTransportError:
        _cleanup_private_inputs(config)
        config.control.close()
        return 66

    state = "failed"
    error_code: str | None = "watchdog_failure"
    cancellation_facts: Mapping[str, bool] | None = None
    try:
        state, error_code, cancellation_facts = _run(
            config,
            receiver_environment=receiver_environment,
        )
        status: dict[str, Any] = {
            "schema_version": _STATUS_SCHEMA,
            "task_id": config.task_id,
            "state": state,
            "error_code": error_code,
            "watchdog_pid": os.getpid(),
        }
        if state == "cancelled":
            if cancellation_facts is None:
                raise RunnerTransportError("runner cancellation proof is unavailable")
            status.update(cancellation_facts)
        if state == "succeeded":
            status["result_digest"] = file_hash(config.durable_result_path)
        # A published terminal status is valid only after every live-control
        # input is gone. The final cleanup in `finally` remains as a fail-safe.
        _cleanup_private_inputs(config)
        _write_private_json(config, "status.json", status)
    except (OSError, RunnerTransportError):
        return 67
    finally:
        _cleanup_private_inputs(config)
        config.control.close()

    if state == "succeeded":
        return 0
    if error_code == "cancelled":
        return 20
    if error_code == "timed_out":
        return 21
    return 22


if __name__ == "__main__":
    raise SystemExit(main())
