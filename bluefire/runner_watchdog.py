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
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

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

_CONFIG_SCHEMA = "bluefire.runner-watchdog-config.v1"
_READY_SCHEMA = "bluefire.runner-watchdog-ready.v1"
_STATUS_SCHEMA = "bluefire.runner-watchdog-status.v1"
_CONFIG_LIMIT_BYTES = 8 * 1024 * 1024
_STATUS_LIMIT_BYTES = 4096
_START_TIMEOUT_SECONDS = 10.0
_POLL_SECONDS = 0.025
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_CONFIG_KEYS = frozenset(
    {
        "schema_version",
        "task_id",
        "runner_binary",
        "runner_binary_digest",
        "work_root",
        "timeout_seconds",
        "output_limit_bytes",
        "durable_result_path",
        "manifest",
        "profile",
    }
)


@dataclass(frozen=True)
class _WatchdogConfig:
    task_id: str
    runner_binary: Path
    runner_binary_digest: str
    work_root: Path
    timeout_seconds: float
    output_limit_bytes: int
    durable_result_path: Path
    manifest: Mapping[str, Any]
    profile: Mapping[str, Any]
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
    timeout_seconds = value.get("timeout_seconds")
    output_limit_bytes = value.get("output_limit_bytes")
    manifest = value.get("manifest")
    profile = value.get("profile")
    if (
        not isinstance(task_id, str)
        or not isinstance(binary_digest, str)
        or _DIGEST.fullmatch(binary_digest) is None
        or isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, int | float)
        or not math.isfinite(float(timeout_seconds))
        or not 0 < float(timeout_seconds) <= 86_400
        or isinstance(output_limit_bytes, bool)
        or not isinstance(output_limit_bytes, int)
        or not 4096 <= output_limit_bytes <= 64 * 1024 * 1024
        or not isinstance(manifest, dict)
        or not isinstance(profile, dict)
    ):
        raise RunnerTransportError("runner watchdog configuration is invalid")

    try:
        binary_raw = value.get("runner_binary")
        work_raw = value.get("work_root")
        destination_raw = value.get("durable_result_path")
        if not all(isinstance(item, str) for item in (binary_raw, work_raw, destination_raw)):
            raise OSError("invalid watchdog paths")
        runner_binary = Path(str(binary_raw))
        work_root = Path(str(work_raw))
        destination = Path(str(destination_raw))
        if (
            not runner_binary.is_absolute()
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
        work_root=work_root,
        timeout_seconds=float(timeout_seconds),
        output_limit_bytes=output_limit_bytes,
        durable_result_path=destination,
        manifest=manifest,
        profile=profile,
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
) -> tuple[str, str | None]:
    gate = _wait_for_start(config)
    if gate == "cancelled":
        return "cancelled", "cancelled"
    if gate != "started":
        return "failed", "start_timeout"

    cancel_event = threading.Event()
    stop_polling = threading.Event()

    def observe_cancel() -> None:
        while not stop_polling.is_set():
            if _signal_exists(config, "cancel", b"cancel\n"):
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
            return "failed", "runner_identity_changed"
        runner = SubprocessRustRunner(
            config.runner_binary,
            config.work_root,
            timeout_seconds=config.timeout_seconds,
            output_limit_bytes=config.output_limit_bytes,
            _kill_child_on_job_close=True,
        )
        runner._execute_task_locally(
            config.manifest,
            config.profile,
            task_id=config.task_id,
            cancel_event=cancel_event,
            durable_result_path=config.durable_result_path,
            receiver_environment=receiver_environment,
        )
        return "succeeded", None
    except RunnerTaskCancelled:
        return "cancelled", "cancelled"
    except RunnerDurableResultExists:
        return "failed", "durable_result_exists"
    except RunnerPendingResultExists:
        return "failed", "pending_result_exists"
    except RunnerTransportError as exc:
        return "failed", _classify_failure(exc)
    except BaseException:
        return "failed", "watchdog_failure"
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
    try:
        state, error_code = _run(
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
