"""The only maintained Python transport allowed to launch the Rust runner."""

from __future__ import annotations

import json
import math
import os
import re
import signal

# Only the fixed, absolute Rust runner boundary uses subprocess.
import subprocess  # nosec B404
import sys
import tempfile
import threading
import time
from hashlib import sha256
from pathlib import Path
from typing import Any, BinaryIO, Mapping, Protocol, runtime_checkable

from .util import canonical_json_bytes, content_hash, file_hash

_INVENTORY_IDENTIFIER = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
_INVENTORY_MAX_ACTIONS = 512
_INVENTORY_MAX_BYTES = 2 * 1024 * 1024
_INVENTORY_PLATFORMS = frozenset({"linux", "macos", "windows"})
_ACTION_READINESS = frozenset({"ready", "structural", "unavailable"})
_TASK_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
_PROCESS_POLL_SECONDS = 0.025
_PROCESS_TERM_GRACE_SECONDS = 2.0
_PROCESS_KILL_GRACE_SECONDS = 5.0
_WATCHDOG_START_GRACE_SECONDS = 10.0
_WATCHDOG_EXIT_GRACE_SECONDS = 12.0
_WATCHDOG_CONFIG_LIMIT_BYTES = 8 * 1024 * 1024
_WATCHDOG_CONTROL_NAMES = frozenset({"config.json", "start", "cancel", "ready.json", "status.json"})
_KILL_PROCESS_GROUP = getattr(os, "killpg", None)
_FORCE_KILL_SIGNAL = getattr(signal, "SIGKILL", signal.SIGTERM)

FORBIDDEN_EXECUTION_KEYS = frozenset(
    {
        "command",
        "cmd",
        "shell",
        "script",
        "script_body",
        "payload",
        "binary",
        "shellcode",
        "interpreter",
        "executable",
    }
)


class RunnerTransportError(RuntimeError):
    pass


class RunnerReadinessError(RunnerTransportError):
    """A sanitized refusal raised before an Execute effect can be dispatched."""


class RunnerTaskCancelled(RunnerTransportError):
    """The complete runner process tree was confirmed stopped after cancellation."""


class RunnerPendingResultExists(RunnerTransportError):
    """A prior task attempt left crash-recovery output that must be reconciled."""


class RunnerDurableResultExists(RunnerTransportError):
    """A final task result already exists and was not overwritten."""


@runtime_checkable
class RunnerTransport(Protocol):
    def inventory(self) -> Mapping[str, Any]: ...

    def execute(
        self,
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
    ) -> Mapping[str, Any]: ...


@runtime_checkable
class TaskAwareRunnerTransport(RunnerTransport, Protocol):
    """Runner transport that durably identifies and cancels one exact task."""

    def execute_task(
        self,
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
        *,
        task_id: str,
        cancel_event: threading.Event,
        durable_result_path: str | Path,
    ) -> Mapping[str, Any]: ...


def canonical_runner_inventory(inventory: Mapping[str, Any]) -> Mapping[str, Any]:
    """Validate and normalize the stable identity-bearing runner inventory.

    The returned document deliberately contains only bounded, non-secret fields.
    Its digest is therefore safe to surface and stable across JSON key ordering.
    """

    if not isinstance(inventory, Mapping):
        raise RunnerReadinessError("Runner inventory is invalid or unsupported.")
    if inventory.get("schema_version") != "bluefire.runner-inventory.v1":
        raise RunnerReadinessError("Runner inventory is invalid or unsupported.")
    runner_id = _inventory_token(inventory.get("runner_id"), maximum=128)
    runner_version = _inventory_token(inventory.get("runner_version"), maximum=128)
    action_sdk_version = _inventory_token(inventory.get("action_sdk_version"), maximum=128)
    receipt_protocol = _inventory_token(inventory.get("receipt_protocol"), maximum=128)
    platform = inventory.get("platform")
    raw_actions = inventory.get("actions")
    if (
        runner_id is None
        or runner_version is None
        or action_sdk_version is None
        or receipt_protocol is None
        or not isinstance(platform, str)
        or platform not in _INVENTORY_PLATFORMS
        or not isinstance(raw_actions, list)
        or len(raw_actions) > _INVENTORY_MAX_ACTIONS
    ):
        raise RunnerReadinessError("Runner inventory is invalid or unsupported.")

    try:
        source_bytes = canonical_json_bytes(dict(inventory))
    except (TypeError, ValueError) as exc:
        raise RunnerReadinessError("Runner inventory is invalid or unsupported.") from exc
    if len(source_bytes) > _INVENTORY_MAX_BYTES:
        raise RunnerReadinessError("Runner inventory exceeds the readiness size limit.")

    actions: list[dict[str, str]] = []
    action_ids: set[str] = set()
    for raw_action in raw_actions:
        if not isinstance(raw_action, Mapping):
            raise RunnerReadinessError("Runner inventory is invalid or unsupported.")
        action_id = _inventory_token(raw_action.get("action_id"), maximum=200)
        action_version = _inventory_token(raw_action.get("action_version"), maximum=64)
        readiness = raw_action.get("readiness")
        if (
            action_id is None
            or not _INVENTORY_IDENTIFIER.fullmatch(action_id)
            or action_version is None
            or not isinstance(readiness, str)
            or readiness not in _ACTION_READINESS
            or action_id in action_ids
        ):
            raise RunnerReadinessError("Runner inventory is invalid or unsupported.")
        action_ids.add(action_id)
        actions.append(
            {
                "action_id": action_id,
                "action_version": action_version,
                "readiness": readiness,
                "contract_digest": content_hash(dict(raw_action)),
            }
        )
    actions.sort(key=lambda item: item["action_id"])
    canonical = {
        "schema_version": "bluefire.runner-inventory.v1",
        "runner_id": runner_id,
        "runner_version": runner_version,
        "action_sdk_version": action_sdk_version,
        "receipt_protocol": receipt_protocol,
        "platform": platform,
        "source_digest": content_hash(dict(inventory)),
        "actions": actions,
    }
    try:
        encoded = canonical_json_bytes(canonical)
    except (TypeError, ValueError) as exc:
        raise RunnerReadinessError("Runner inventory is invalid or unsupported.") from exc
    if len(encoded) > _INVENTORY_MAX_BYTES:
        raise RunnerReadinessError("Runner inventory exceeds the readiness size limit.")
    return canonical


def runner_inventory_digest(inventory: Mapping[str, Any]) -> str:
    """Return the canonical digest used by the approval and dispatch gates."""

    return content_hash(canonical_runner_inventory(inventory))


def runner_transport_identity(
    runner: RunnerTransport,
    inventory: Mapping[str, Any],
) -> Mapping[str, str]:
    """Build a secret-safe identity for the exact transport and runner binary."""

    canonical = canonical_runner_inventory(inventory)
    identity = {
        "transport": f"{type(runner).__module__}.{type(runner).__qualname__}",
        "runner_id": str(canonical["runner_id"]),
        "runner_version": str(canonical["runner_version"]),
        "platform": str(canonical["platform"]),
    }
    raw_binary = getattr(runner, "runner_binary", None)
    if isinstance(raw_binary, Path):
        try:
            binary = raw_binary.resolve(strict=True)
            if not binary.is_file():
                raise OSError("runner binary is not a file")
            identity["runner_binary_digest"] = file_hash(binary)
        except OSError as exc:
            raise RunnerReadinessError("Runner identity could not be verified.") from exc
    return identity


class InventoryBoundRunner:
    """Fail closed if the approved runner identity or inventory changes.

    Inventory is checked when orchestration claims the approval and again
    immediately before every action dispatch. The underlying transport error is
    never exposed because it may contain local paths or process diagnostics.
    """

    def __init__(
        self,
        runner: RunnerTransport,
        *,
        expected_inventory_digest: str,
        expected_identity_digest: str,
        recovery_identity: Mapping[str, Any],
    ) -> None:
        self.runner = runner
        self.expected_inventory_digest = expected_inventory_digest
        self.expected_identity_digest = expected_identity_digest
        self.recovery_identity = dict(recovery_identity)

    @property
    def runner_binary(self) -> Any:
        return getattr(self.runner, "runner_binary", None)

    def inventory(self) -> Mapping[str, Any]:
        try:
            inventory = self.runner.inventory()
            canonical = canonical_runner_inventory(inventory)
            identity = runner_transport_identity(self.runner, inventory)
        except (AttributeError, OSError, RunnerTransportError, TypeError, ValueError) as exc:
            raise RunnerReadinessError(
                "Runner became unavailable after approval; no action was dispatched."
            ) from exc
        if content_hash(canonical) != self.expected_inventory_digest:
            raise RunnerReadinessError(
                "Runner inventory changed after approval; submit a new Execute request."
            )
        if content_hash(identity) != self.expected_identity_digest:
            raise RunnerReadinessError(
                "Runner identity changed after approval; submit a new Execute request."
            )
        return inventory

    def execute(
        self,
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        self.inventory()
        return self.runner.execute(manifest, profile)

    def execute_task(
        self,
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
        *,
        task_id: str,
        cancel_event: threading.Event,
        durable_result_path: str | Path,
    ) -> Mapping[str, Any]:
        """Preserve the approval-time inventory gate for task-aware dispatch."""

        self.inventory()
        operation = getattr(self.runner, "execute_task", None)
        if not callable(operation):
            raise RunnerTransportError("Runner transport does not support task-aware execution.")
        result = operation(
            manifest,
            profile,
            task_id=task_id,
            cancel_event=cancel_event,
            durable_result_path=durable_result_path,
        )
        if not isinstance(result, Mapping):
            raise RunnerTransportError("runner result must be a JSON object")
        return result


def _inventory_token(value: Any, *, maximum: int) -> str | None:
    if not isinstance(value, str):
        return None
    token = value.strip()
    if not 1 <= len(token) <= maximum or any(ord(character) < 32 for character in token):
        return None
    return token


def reject_forbidden_execution_keys(value: Any, *, path: str = "$") -> None:
    """Recursively reject free-form executable content at the transport edge."""

    if isinstance(value, Mapping):
        for key, child in value.items():
            normalized = str(key).strip().casefold().replace("-", "_")
            if normalized in FORBIDDEN_EXECUTION_KEYS:
                raise RunnerTransportError(f"forbidden execution field at {path}.{key}")
            reject_forbidden_execution_keys(child, path=f"{path}.{key}")
    elif isinstance(value, list | tuple):
        for index, child in enumerate(value):
            reject_forbidden_execution_keys(child, path=f"{path}[{index}]")


def runner_pending_result_path(
    durable_result_path: str | Path,
    task_id: str,
) -> Path:
    """Return the deterministic crash-recovery path for a task's runner stdout.

    The task identifier is hashed into a fixed filename, so it can never select
    a path.  A server that restarts after its parent process was interrupted can
    use this helper to find and reconcile a complete, parseable runner result.
    """

    if not isinstance(task_id, str) or _TASK_IDENTIFIER.fullmatch(task_id) is None:
        raise RunnerTransportError("runner task identity is invalid")
    destination = Path(durable_result_path).expanduser()
    if not destination.is_absolute() or destination.name in {"", ".", ".."}:
        raise RunnerTransportError("runner durable result destination is invalid")
    try:
        destination = destination.resolve(strict=False)
    except OSError:
        raise RunnerTransportError("runner durable result destination is invalid") from None
    identity = sha256(f"{task_id}\0{destination.name}".encode("utf-8")).hexdigest()
    return destination.with_name(f".bluefire-result-{identity}.pending")


def runner_watchdog_control_root(
    durable_result_path: str | Path,
    task_id: str,
) -> Path:
    """Return the deterministic private control directory for one runner task."""

    if not isinstance(task_id, str) or _TASK_IDENTIFIER.fullmatch(task_id) is None:
        raise RunnerTransportError("runner task identity is invalid")
    destination = Path(durable_result_path).expanduser()
    if not destination.is_absolute() or destination.name in {"", ".", ".."}:
        raise RunnerTransportError("runner durable result destination is invalid")
    try:
        destination = destination.resolve(strict=False)
    except OSError:
        raise RunnerTransportError("runner durable result destination is invalid") from None
    identity = sha256(f"{task_id}\0{destination.name}".encode("utf-8")).hexdigest()
    return destination.parent / f".bluefire-watchdog-{identity}"


def runner_watchdog_cancel_path(
    durable_result_path: str | Path,
    task_id: str,
) -> Path:
    """Return the task's deterministic cancellation marker path."""

    return runner_watchdog_control_root(durable_result_path, task_id) / "cancel"


def runner_watchdog_ready_path(
    durable_result_path: str | Path,
    task_id: str,
) -> Path:
    """Return the task's private watchdog-readiness record path."""

    return runner_watchdog_control_root(durable_result_path, task_id) / "ready.json"


def runner_watchdog_status_path(
    durable_result_path: str | Path,
    task_id: str,
) -> Path:
    """Return the task's durable terminal watchdog-status path."""

    return runner_watchdog_control_root(durable_result_path, task_id) / "status.json"


def request_runner_task_cancel(
    durable_result_path: str | Path,
    task_id: str,
) -> None:
    """Durably request cancellation for an already-started watchdog task."""

    from .runner_trust import RunnerTrustError, _is_link_or_reparse, _owner_private

    root = runner_watchdog_control_root(durable_result_path, task_id)
    cancel_path = root / "cancel"
    try:
        if _is_link_or_reparse(root) or not root.is_dir():
            raise OSError("unsafe watchdog control directory")
        resolved = root.resolve(strict=True)
        if resolved != root or _is_link_or_reparse(resolved):
            raise OSError("watchdog control identity changed")
        _owner_private(resolved, directory=True)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(cancel_path, flags, 0o600)
        except FileExistsError:
            if _is_link_or_reparse(cancel_path) or not cancel_path.is_file():
                raise OSError("unsafe cancellation marker") from None
            details = cancel_path.stat(follow_symlinks=False)
            if details.st_nlink != 1 or cancel_path.read_bytes() != b"cancel\n":
                raise OSError("invalid cancellation marker") from None
            return
        try:
            os.write(descriptor, b"cancel\n")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        _owner_private(cancel_path, directory=False)
        if os.name != "nt":
            directory = os.open(resolved, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    except (OSError, RunnerTrustError):
        raise RunnerTransportError("runner cancellation signal is unavailable") from None


def cleanup_runner_watchdog_terminal_state(
    durable_result_path: str | Path,
    task_id: str,
) -> None:
    """Remove only a terminal watchdog record after durable task reconciliation."""

    from .runner_trust import RunnerTrustError, _is_link_or_reparse, _owner_private

    root = runner_watchdog_control_root(durable_result_path, task_id)
    status_path = root / "status.json"
    try:
        if _is_link_or_reparse(root) or not root.is_dir():
            raise OSError("unsafe watchdog control directory")
        resolved = root.resolve(strict=True)
        if resolved != root or _is_link_or_reparse(resolved):
            raise OSError("watchdog control identity changed")
        _owner_private(resolved, directory=True)
        entries = tuple(resolved.iterdir())
        if len(entries) != 1 or entries[0].name != "status.json":
            raise OSError("watchdog task is not terminal")
        if _is_link_or_reparse(status_path) or not status_path.is_file():
            raise OSError("unsafe watchdog status")
        details = status_path.stat(follow_symlinks=False)
        if details.st_nlink != 1 or details.st_size > 4096:
            raise OSError("unsafe watchdog status")
        _owner_private(status_path, directory=False)
        status = SubprocessRustRunner._decode_json(
            status_path.read_bytes(),
            "runner watchdog status",
        )
        if (
            status.get("schema_version") != "bluefire.runner-watchdog-status.v1"
            or status.get("task_id") != task_id
            or status.get("state") not in {"succeeded", "failed", "cancelled"}
        ):
            raise OSError("invalid watchdog status")
        status_path.unlink()
        resolved.rmdir()
        if os.name != "nt":
            descriptor = os.open(resolved.parent, os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    except (OSError, RunnerTrustError, RunnerTransportError):
        raise RunnerTransportError(
            "runner watchdog state is not ready for reconciliation"
        ) from None


class SubprocessRustRunner:
    """Invoke one preconfigured runner binary with a fixed argument grammar."""

    def __init__(
        self,
        runner_binary: str | Path,
        work_root: str | Path,
        *,
        timeout_seconds: float = 35.0,
        output_limit_bytes: int = 2 * 1024 * 1024,
        _kill_child_on_job_close: bool = False,
    ) -> None:
        binary = Path(runner_binary).expanduser()
        if not binary.is_absolute() or not binary.is_file():
            raise RunnerTransportError("runner binary must be an existing absolute file")
        root = Path(work_root).expanduser()
        root.mkdir(parents=True, exist_ok=True)
        self.runner_binary = binary.resolve(strict=True)
        self.work_root = root.resolve(strict=True)
        self.timeout_seconds = timeout_seconds
        self.output_limit_bytes = output_limit_bytes
        self._kill_child_on_job_close = bool(_kill_child_on_job_close)
        self._windows_jobs: dict[int, int] = {}
        self._windows_jobs_lock = threading.Lock()
        if timeout_seconds <= 0 or output_limit_bytes < 4096:
            raise RunnerTransportError("runner transport bounds are invalid")

    def inventory(self) -> Mapping[str, Any]:
        output = self._invoke([str(self.runner_binary), "inventory", "--json"])
        return self._decode_json(output, "runner inventory")

    def execute(
        self,
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        reject_forbidden_execution_keys(manifest)
        reject_forbidden_execution_keys(profile)
        with tempfile.TemporaryDirectory(prefix="request-", dir=self.work_root) as directory:
            request_root = Path(directory)
            manifest_path = request_root / "manifest.json"
            profile_path = request_root / "profile.json"
            manifest_path.write_bytes(canonical_json_bytes(manifest) + b"\n")
            profile_path.write_bytes(canonical_json_bytes(profile) + b"\n")
            output = self._invoke(
                [
                    str(self.runner_binary),
                    "execute",
                    "--manifest",
                    str(manifest_path),
                    "--profile",
                    str(profile_path),
                    "--json",
                ]
            )
        return self._validate_result(output, manifest, profile)

    def execute_task(
        self,
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
        *,
        task_id: str,
        cancel_event: threading.Event,
        durable_result_path: str | Path,
    ) -> Mapping[str, Any]:
        """Run one task through an independent crash-surviving watchdog process."""

        reject_forbidden_execution_keys(manifest)
        reject_forbidden_execution_keys(profile)
        if not callable(getattr(cancel_event, "is_set", None)):
            raise RunnerTransportError("runner cancellation signal is invalid")
        if cancel_event.is_set():
            raise RunnerTaskCancelled(
                "Runner task did not start because cancellation was requested."
            )

        destination, pending = self._durable_paths(durable_result_path, task_id)
        if pending.exists() or pending.is_symlink():
            raise RunnerPendingResultExists(
                "Runner pending result requires recovery before the task can start."
            )
        control_root = runner_watchdog_control_root(destination, task_id)
        config_path = control_root / "config.json"
        start_path = control_root / "start"
        watchdog: subprocess.Popen[bytes] | None = None
        try:
            self._prepare_watchdog_control(control_root)
            try:
                binary_digest = file_hash(self.runner_binary)
            except OSError:
                raise RunnerTransportError("Runner identity could not be verified.") from None
            config = {
                "schema_version": "bluefire.runner-watchdog-config.v1",
                "task_id": task_id,
                "runner_binary": str(self.runner_binary),
                "runner_binary_digest": binary_digest,
                "work_root": str(self.work_root),
                "timeout_seconds": self.timeout_seconds,
                "output_limit_bytes": self.output_limit_bytes,
                "durable_result_path": str(destination),
                "manifest": dict(manifest),
                "profile": dict(profile),
            }
            self._write_private_control_file(
                config_path,
                canonical_json_bytes(config) + b"\n",
                maximum=_WATCHDOG_CONFIG_LIMIT_BYTES,
            )
            watchdog = self._spawn_watchdog(config_path)
            # `_spawn_watchdog` returns only after Windows job assignment. The
            # watchdog refuses to launch Rust until this exclusive gate exists.
            self._write_private_control_file(start_path, b"start\n", maximum=32)
            return self._await_watchdog(
                watchdog,
                manifest=manifest,
                profile=profile,
                task_id=task_id,
                destination=destination,
                pending=pending,
                cancel_event=cancel_event,
            )
        except BaseException:
            if watchdog is not None and watchdog.poll() is None:
                try:
                    request_runner_task_cancel(destination, task_id)
                except RunnerTransportError:
                    pass
                stop_deadline = time.monotonic() + _WATCHDOG_EXIT_GRACE_SECONDS
                while watchdog.poll() is None and time.monotonic() < stop_deadline:
                    time.sleep(_PROCESS_POLL_SECONDS)
                if watchdog.poll() is None:
                    if os.name != "nt":
                        # Rust owns a separate POSIX process group. Killing only
                        # the watchdog here would orphan the exact effect whose
                        # status must remain recoverable. Leave the private state
                        # intact and let the watchdog enforce its own deadline.
                        raise RunnerPendingResultExists(
                            "Runner watchdog remains active and requires reconciliation."
                        ) from None
                    if not self._terminate_process_tree(watchdog):
                        raise RunnerTransportError(
                            "Runner watchdog process tree could not be stopped safely"
                        ) from None
                elif os.name == "nt" and not self._finish_windows_job(watchdog.pid):
                    raise RunnerTransportError(
                        "Runner watchdog containment could not be released"
                    ) from None
                elif os.name != "nt" and not self._finish_posix_process_group(watchdog):
                    raise RunnerTransportError(
                        "Runner watchdog containment could not be released"
                    ) from None
            raise
        finally:
            if watchdog is None or watchdog.poll() is not None:
                self._cleanup_watchdog_control(control_root)

    def _execute_task_locally(
        self,
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
        *,
        task_id: str,
        cancel_event: threading.Event,
        durable_result_path: str | Path,
    ) -> Mapping[str, Any]:
        """Watchdog-only fixed-runner execution and durable-result commit."""

        reject_forbidden_execution_keys(manifest)
        reject_forbidden_execution_keys(profile)
        if cancel_event.is_set():
            raise RunnerTaskCancelled(
                "Runner task did not start because cancellation was requested."
            )
        destination, pending = self._durable_paths(durable_result_path, task_id)
        try:
            with tempfile.TemporaryDirectory(prefix="request-", dir=self.work_root) as directory:
                request_root = Path(directory)
                manifest_path = request_root / "manifest.json"
                profile_path = request_root / "profile.json"
                manifest_path.write_bytes(canonical_json_bytes(manifest) + b"\n")
                profile_path.write_bytes(canonical_json_bytes(profile) + b"\n")
                output = self._invoke_task(
                    [
                        str(self.runner_binary),
                        "execute",
                        "--manifest",
                        str(manifest_path),
                        "--profile",
                        str(profile_path),
                        "--json",
                    ],
                    cancel_event=cancel_event,
                    pending_result_path=pending,
                )
            result = self._validate_result(output, manifest, profile)
            self._promote_pending_result(
                pending,
                destination,
                canonical_json_bytes(dict(result)) + b"\n",
            )
            return result
        except (RunnerDurableResultExists, RunnerPendingResultExists):
            raise
        except BaseException:
            self._remove_pending_result(pending)
            raise

    @staticmethod
    def _prepare_watchdog_control(root: Path) -> None:
        from .runner_trust import RunnerTrustError, _is_link_or_reparse, _owner_private

        try:
            root.mkdir(mode=0o700, parents=False, exist_ok=False)
            if _is_link_or_reparse(root) or not root.is_dir():
                raise OSError("unsafe watchdog control directory")
            resolved = root.resolve(strict=True)
            if resolved != root or _is_link_or_reparse(resolved):
                raise OSError("watchdog control identity changed")
            _owner_private(resolved, directory=True)
        except FileExistsError:
            raise RunnerPendingResultExists(
                "Runner watchdog state requires reconciliation before the task can start."
            ) from None
        except (OSError, RunnerTrustError):
            raise RunnerTransportError("runner watchdog state is unavailable") from None

    @staticmethod
    def _write_private_control_file(path: Path, payload: bytes, *, maximum: int) -> None:
        from .runner_trust import RunnerTrustError, _is_link_or_reparse, _owner_private

        if not 0 < len(payload) <= maximum:
            raise RunnerTransportError("runner watchdog state exceeds its size limit")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = -1
        created = False
        try:
            descriptor = os.open(path, flags, 0o600)
            created = True
            written = 0
            while written < len(payload):
                count = os.write(descriptor, payload[written:])
                if count <= 0:
                    raise OSError("short watchdog control write")
                written += count
            os.fsync(descriptor)
            _owner_private(path, directory=False)
            descriptor_state = os.fstat(descriptor)
            path_state = path.stat(follow_symlinks=False)
            if (
                descriptor_state.st_nlink != 1
                or path_state.st_nlink != 1
                or _is_link_or_reparse(path)
                or (descriptor_state.st_dev, descriptor_state.st_ino)
                != (path_state.st_dev, path_state.st_ino)
            ):
                raise OSError("watchdog control identity changed")
            if os.name != "nt":
                parent_descriptor = os.open(path.parent, os.O_RDONLY)
                try:
                    os.fsync(parent_descriptor)
                finally:
                    os.close(parent_descriptor)
        except FileExistsError:
            raise RunnerPendingResultExists(
                "Runner watchdog state requires reconciliation before the task can start."
            ) from None
        except (OSError, RunnerTrustError):
            if created:
                try:
                    path.unlink()
                except OSError:
                    pass
            raise RunnerTransportError("runner watchdog state is unavailable") from None
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def _spawn_watchdog(self, config_path: Path) -> subprocess.Popen[bytes]:
        try:
            interpreter = Path(sys.executable).resolve(strict=True)
            if not interpreter.is_file():
                raise OSError("Python runtime is unavailable")
        except OSError:
            raise RunnerTransportError("Runner watchdog runtime is unavailable") from None
        return self._spawn(
            [
                str(interpreter),
                "-I",
                "-m",
                "bluefire.runner_watchdog",
                str(config_path),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    def _await_watchdog(
        self,
        process: subprocess.Popen[bytes],
        *,
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
        task_id: str,
        destination: Path,
        pending: Path,
        cancel_event: threading.Event,
    ) -> Mapping[str, Any]:
        deadline = (
            time.monotonic()
            + self.timeout_seconds
            + _WATCHDOG_START_GRACE_SECONDS
            + _WATCHDOG_EXIT_GRACE_SECONDS
        )
        cancellation_requested = False
        while True:
            return_code = process.poll()
            if return_code is not None:
                if os.name == "nt" and not self._finish_windows_job(process.pid):
                    raise RunnerTransportError("Runner watchdog containment could not be released")
                if os.name != "nt" and not self._finish_posix_process_group(process):
                    raise RunnerTransportError("Runner watchdog containment could not be released")
                break
            if cancel_event.is_set() and not cancellation_requested:
                request_runner_task_cancel(destination, task_id)
                cancellation_requested = True
            if time.monotonic() >= deadline:
                if not cancellation_requested:
                    request_runner_task_cancel(destination, task_id)
                    cancellation_requested = True
                grace_deadline = time.monotonic() + _WATCHDOG_EXIT_GRACE_SECONDS
                while process.poll() is None and time.monotonic() < grace_deadline:
                    time.sleep(_PROCESS_POLL_SECONDS)
                if process.poll() is None:
                    if os.name != "nt":
                        raise RunnerPendingResultExists(
                            "Runner watchdog remains active and requires reconciliation."
                        )
                    if not self._terminate_process_tree(process):
                        raise RunnerTransportError(
                            "Runner watchdog process tree could not be stopped safely"
                        )
                if os.name == "nt" and not self._finish_windows_job(process.pid):
                    raise RunnerTransportError("Runner watchdog containment could not be released")
                if os.name != "nt" and not self._finish_posix_process_group(process):
                    raise RunnerTransportError("Runner watchdog containment could not be released")
                raise RunnerTransportError("Runner watchdog exceeded its terminal deadline")
            time.sleep(_PROCESS_POLL_SECONDS)

        status_path = runner_watchdog_status_path(destination, task_id)
        status: Mapping[str, Any] | None = None
        try:
            payload = status_path.read_bytes()
            if len(payload) > 4096:
                raise OSError("watchdog status is oversized")
            status = self._decode_json(payload, "runner watchdog status")
        except (OSError, RunnerTransportError):
            status = None
        if status is not None and (
            status.get("schema_version") != "bluefire.runner-watchdog-status.v1"
            or status.get("task_id") != task_id
        ):
            status = None
        code = status.get("error_code") if status is not None else None
        state = status.get("state") if status is not None else None
        if code == "cancelled":
            raise RunnerTaskCancelled("Runner task was cancelled after its process tree stopped.")
        if code == "timed_out":
            raise RunnerTransportError("Rust runner transport timed out")
        if code == "output_limit":
            raise RunnerTransportError("Rust runner exceeded the transport output limit")
        if code == "durable_result_exists":
            raise RunnerDurableResultExists(
                "Runner durable result already exists and requires reconciliation."
            )
        if code == "pending_result_exists" or pending.exists():
            raise RunnerPendingResultExists(
                "Runner pending result requires recovery before the task can start."
            )
        if code == "unsupported_result_schema":
            raise RunnerTransportError("runner returned an unsupported result schema")
        if code == "invalid_json":
            raise RunnerTransportError("runner result is not valid UTF-8 JSON")
        if code == "invalid_result":
            raise RunnerTransportError("runner returned a result that did not match its request")
        if state == "succeeded" or (status is None and destination.exists()):
            output = self._read_private_result(destination)
            return self._validate_result(output, manifest, profile)
        raise RunnerTransportError("Runner watchdog failed before publishing a valid result")

    def _read_private_result(self, path: Path) -> bytes:
        from .runner_trust import RunnerTrustError, _is_link_or_reparse, _owner_private

        try:
            if _is_link_or_reparse(path) or not path.is_file():
                raise OSError("unsafe durable result")
            details = path.stat(follow_symlinks=False)
            if details.st_nlink != 1 or details.st_size > self.output_limit_bytes:
                raise OSError("unsafe durable result")
            _owner_private(path, directory=False)
            payload = path.read_bytes()
            if len(payload) > self.output_limit_bytes:
                raise OSError("unsafe durable result")
            return payload
        except (OSError, RunnerTrustError):
            raise RunnerTransportError("runner durable result is unavailable") from None

    @staticmethod
    def _cleanup_watchdog_control(root: Path) -> None:
        from .runner_trust import _is_link_or_reparse

        try:
            if not root.exists() or _is_link_or_reparse(root) or not root.is_dir():
                return
            entries = tuple(root.iterdir())
            if any(
                entry.name not in _WATCHDOG_CONTROL_NAMES
                or _is_link_or_reparse(entry)
                or not entry.is_file()
                for entry in entries
            ):
                return
            for entry in entries:
                entry.unlink()
            root.rmdir()
        except OSError:
            return

    def _validate_result(
        self,
        output: bytes,
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        result = self._decode_json(output, "runner result")
        expected: dict[str, Any] = {"schema_version": "bluefire.runner-result.v1"}
        for field in (
            "request_id",
            "run_id",
            "step_id",
            "behavior_id",
            "action_id",
            "runner_id",
            "runner_profile_id",
            "platform",
            "request_hash",
            "policy_digest",
        ):
            if field in manifest:
                expected[field] = manifest[field]
        profile_bindings = {
            "runner_id": "runner_id",
            "runner_profile_id": "profile_id",
            "platform": "platform",
            "policy_digest": "policy_digest",
        }
        for result_field, profile_field in profile_bindings.items():
            if profile_field not in profile:
                continue
            profile_value = profile[profile_field]
            manifest_value = manifest.get(result_field)
            if result_field in manifest and manifest_value != profile_value:
                raise RunnerTransportError(
                    f"runner request {result_field} does not match its profile"
                )
            expected[result_field] = profile_value
        for field, value in expected.items():
            if result.get(field) != value:
                if field == "schema_version":
                    raise RunnerTransportError("runner returned an unsupported result schema")
                raise RunnerTransportError(f"runner result {field} does not match the request")
        return result

    def _invoke(self, argv: list[str]) -> bytes:
        process = self._spawn(argv, stdout=subprocess.PIPE)
        stdout = bytearray()
        stderr = bytearray()
        overflow = threading.Event()

        def drain(stream, destination: bytearray) -> None:
            if stream is None:
                return
            while True:
                chunk = stream.read(64 * 1024)
                if not chunk:
                    break
                remaining = self.output_limit_bytes - len(destination)
                if remaining > 0:
                    destination.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    overflow.set()

        readers = [
            threading.Thread(target=drain, args=(process.stdout, stdout), daemon=True),
            threading.Thread(target=drain, args=(process.stderr, stderr), daemon=True),
        ]
        for reader in readers:
            reader.start()
        try:
            return_code = self._monitor_process(process, overflow=overflow)
        finally:
            for reader in readers:
                reader.join(timeout=5)

        if overflow.is_set():
            raise RunnerTransportError("Rust runner exceeded the transport output limit")
        # The runner deliberately uses 3 for policy refusal/control blocking
        # and 4 for an action-level failed/partial result. Both still carry a
        # valid, signed-by-content JSON TaskResult on stdout and must reach the
        # evidence layer intact. Exit code 2 (or anything unexpected) is a
        # transport/CLI failure.
        if return_code not in {0, 3, 4}:
            raise RunnerTransportError(f"Rust runner exited with unexpected status {return_code}")
        return bytes(stdout)

    def _invoke_task(
        self,
        argv: list[str],
        *,
        cancel_event: threading.Event,
        pending_result_path: Path,
    ) -> bytes:
        output = self._open_pending_result(pending_result_path)
        stderr = bytearray()
        overflow = threading.Event()
        process: subprocess.Popen[bytes] | None = None
        try:
            process = self._spawn(argv, stdout=output)

            def drain_stderr(stream: BinaryIO | None) -> None:
                if stream is None:
                    return
                while True:
                    chunk = stream.read(64 * 1024)
                    if not chunk:
                        break
                    remaining = self.output_limit_bytes - len(stderr)
                    if remaining > 0:
                        stderr.extend(chunk[:remaining])
                    if len(chunk) > remaining:
                        overflow.set()

            reader = threading.Thread(
                target=drain_stderr,
                args=(process.stderr,),
                name="bluefire-runner-stderr",
                daemon=True,
            )
            reader.start()
            try:
                return_code = self._monitor_process(
                    process,
                    cancel_event=cancel_event,
                    overflow=overflow,
                    output_path=pending_result_path,
                )
            finally:
                reader.join(timeout=_PROCESS_KILL_GRACE_SECONDS)
            output.flush()
            os.fsync(output.fileno())
            descriptor_state = os.fstat(output.fileno())
            path_state = pending_result_path.stat(follow_symlinks=False)
            if (
                descriptor_state.st_nlink != 1
                or path_state.st_nlink != 1
                or pending_result_path.is_symlink()
                or (descriptor_state.st_dev, descriptor_state.st_ino)
                != (path_state.st_dev, path_state.st_ino)
            ):
                raise OSError("pending result identity changed")
            output.seek(0)
            result_output = output.read(self.output_limit_bytes + 1)
        except BaseException as exc:
            if process is not None and process.poll() is None:
                if not self._stop_process_tree(process):
                    raise RunnerTransportError(
                        "Runner process tree could not be stopped safely"
                    ) from None
            if isinstance(exc, RunnerTransportError):
                raise
            if isinstance(exc, OSError):
                raise RunnerTransportError("Rust runner transport failed") from None
            raise
        finally:
            output.close()

        if (
            overflow.is_set()
            or self._file_exceeds_limit(pending_result_path)
            or len(result_output) > self.output_limit_bytes
        ):
            raise RunnerTransportError("Rust runner exceeded the transport output limit")
        if return_code not in {0, 3, 4}:
            raise RunnerTransportError("Rust runner exited with an unexpected status")
        return result_output

    def _spawn(
        self,
        argv: list[str],
        *,
        stdout: int | BinaryIO | None,
        stderr: int | BinaryIO | None = subprocess.PIPE,
    ) -> subprocess.Popen[bytes]:
        environment: dict[str, str] = {"LC_ALL": "C", "LANG": "C"}
        options: dict[str, Any] = {}
        windows_job: int | None = None
        windows_suspended = False
        if os.name == "nt":
            system_directory = self._windows_system_directory()
            windows_root = system_directory.parent
            environment.update({"SYSTEMROOT": str(windows_root), "WINDIR": str(windows_root)})
            options["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(
                subprocess, "CREATE_NEW_PROCESS_GROUP", 0
            )
            if self._kill_child_on_job_close:
                # The inner Rust process must not execute even one instruction
                # until it is a member of the watchdog-owned kill-on-close Job.
                options["creationflags"] |= getattr(subprocess, "CREATE_SUSPENDED", 0x0000_0004)
                windows_suspended = True
            windows_job = self._create_windows_job()
        else:
            options["start_new_session"] = True
        try:
            # argv[0] is a validated absolute executable path and the grammar is fixed.
            process = subprocess.Popen(  # nosec B603
                argv,
                cwd=self.work_root,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                shell=False,
                **options,
            )
            if windows_job is not None:
                self._assign_windows_job(windows_job, process)
                windows_job = None  # ownership moved to `_windows_jobs`
            if windows_suspended:
                try:
                    self._resume_windows_process(process)
                except RunnerTransportError:
                    if not self._terminate_windows_process_tree(process):
                        raise RunnerTransportError(
                            "Windows process containment could not stop a suspended child"
                        ) from None
                    raise
            return process
        except (OSError, ValueError):
            if windows_job is not None:
                self._close_windows_handle(windows_job)
            raise RunnerTransportError("Rust runner could not be started") from None
        except RunnerTransportError:
            if windows_job is not None:
                self._close_windows_handle(windows_job)
            raise

    def _monitor_process(
        self,
        process: subprocess.Popen[bytes],
        *,
        cancel_event: threading.Event | None = None,
        overflow: threading.Event,
        output_path: Path | None = None,
    ) -> int:
        deadline = time.monotonic() + self.timeout_seconds
        while True:
            return_code = process.poll()
            if return_code is not None:
                released = (
                    self._finish_windows_job(process.pid)
                    if os.name == "nt"
                    else self._finish_posix_process_group(process)
                )
                if not released and self._kill_child_on_job_close:
                    self._retain_failed_process_tree(process)
                    released = True
                if not released:
                    raise RunnerTransportError("Runner process tree state could not be released")
                return return_code
            if overflow.is_set() or (
                output_path is not None and self._file_exceeds_limit(output_path)
            ):
                if not self._stop_process_tree(process):
                    raise RunnerTransportError("Runner process tree could not be stopped safely")
                raise RunnerTransportError("Rust runner exceeded the transport output limit")
            if cancel_event is not None and cancel_event.is_set():
                if not self._stop_process_tree(process):
                    raise RunnerTransportError("Runner process tree could not be stopped safely")
                raise RunnerTaskCancelled(
                    "Runner task was cancelled after its process tree stopped."
                )
            if time.monotonic() >= deadline:
                if not self._stop_process_tree(process):
                    raise RunnerTransportError("Runner process tree could not be stopped safely")
                raise RunnerTransportError("Rust runner transport timed out")
            time.sleep(_PROCESS_POLL_SECONDS)

    def _stop_process_tree(self, process: subprocess.Popen[bytes]) -> bool:
        """Stop a tree, retaining watchdog containment until emptiness is certain."""

        if self._terminate_process_tree(process):
            return True
        if not self._kill_child_on_job_close:
            return False
        self._retain_failed_process_tree(process)
        return True

    def _retain_failed_process_tree(self, process: subprocess.Popen[bytes]) -> None:
        """Fail closed while a watchdog-owned Job or process group is unresolved.

        This intentionally has no local deadline.  The request host can still
        cancel the outer watchdog containment on Windows; on POSIX it leaves the
        watchdog running as indeterminate recovery state.  Publishing a terminal
        task status while Rust descendants remain unconfirmed would be unsafe.
        """

        while not self._terminate_process_tree(process):
            time.sleep(_PROCESS_POLL_SECONDS)

    def _terminate_process_tree(self, process: subprocess.Popen[bytes]) -> bool:
        if os.name == "nt":
            return self._terminate_windows_process_tree(process)
        return self._terminate_posix_process_tree(process)

    @staticmethod
    def _posix_process_group_exists(process_group: int) -> bool:
        if not callable(_KILL_PROCESS_GROUP):
            return False
        try:
            _KILL_PROCESS_GROUP(process_group, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        return True

    def _terminate_posix_process_tree(self, process: subprocess.Popen[bytes]) -> bool:
        if not callable(_KILL_PROCESS_GROUP):
            return False
        process_group = process.pid
        try:
            _KILL_PROCESS_GROUP(process_group, signal.SIGTERM)
        except ProcessLookupError:
            pass
        except OSError:
            return False
        graceful_deadline = time.monotonic() + _PROCESS_TERM_GRACE_SECONDS
        while self._posix_process_group_exists(process_group):
            if time.monotonic() >= graceful_deadline:
                break
            process.poll()
            time.sleep(_PROCESS_POLL_SECONDS)
        if self._posix_process_group_exists(process_group):
            try:
                _KILL_PROCESS_GROUP(process_group, _FORCE_KILL_SIGNAL)
            except ProcessLookupError:
                pass
            except OSError:
                return False
        try:
            process.wait(timeout=_PROCESS_KILL_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            return False
        stopped_deadline = time.monotonic() + _PROCESS_KILL_GRACE_SECONDS
        while self._posix_process_group_exists(process_group):
            if time.monotonic() >= stopped_deadline:
                return False
            time.sleep(_PROCESS_POLL_SECONDS)
        return process.poll() is not None

    def _finish_posix_process_group(self, process: subprocess.Popen[bytes]) -> bool:
        if not self._posix_process_group_exists(process.pid):
            return process.poll() is not None
        return self._terminate_posix_process_tree(process)

    def _terminate_windows_process_tree(self, process: subprocess.Popen[bytes]) -> bool:
        with self._windows_jobs_lock:
            job = self._windows_jobs.get(process.pid)
        if job is None:
            return False
        try:
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            terminate_job = kernel32.TerminateJobObject
            terminate_job.argtypes = [wintypes.HANDLE, wintypes.UINT]
            terminate_job.restype = wintypes.BOOL
            terminated = bool(terminate_job(job, 1))
            if terminated:
                process.wait(timeout=_PROCESS_KILL_GRACE_SECONDS)
        except (AttributeError, OSError, subprocess.SubprocessError, ValueError):
            terminated = False
        if not terminated or not self._wait_for_empty_windows_job(job):
            return False
        return self._release_windows_job(process.pid) and process.poll() is not None

    def _create_windows_job(self) -> int:
        job = 0
        try:
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            create_job = kernel32.CreateJobObjectW
            create_job.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
            create_job.restype = wintypes.HANDLE

            raw_job = create_job(None, None)
            if not raw_job:
                raise OSError("job creation failed")
            job = int(raw_job)
            # The request-server's outer watchdog job intentionally survives
            # handle closure. Inside the watchdog, the Rust child job uses
            # KILL_ON_JOB_CLOSE so a watchdog crash cannot orphan execution.
            if self._kill_child_on_job_close:
                self._set_windows_job_kill_on_close(job)
            return job
        except (AttributeError, OSError, TypeError, ValueError):
            if job:
                self._close_windows_handle(job)
            raise RunnerTransportError("Windows process containment is unavailable") from None
        except RunnerTransportError:
            if job:
                self._close_windows_handle(job)
            raise

    @staticmethod
    def _set_windows_job_kill_on_close(job: int) -> None:
        try:
            import ctypes
            from ctypes import wintypes

            class BasicLimitInformation(ctypes.Structure):
                _fields_ = [
                    ("per_process_user_time_limit", ctypes.c_longlong),
                    ("per_job_user_time_limit", ctypes.c_longlong),
                    ("limit_flags", wintypes.DWORD),
                    ("minimum_working_set_size", ctypes.c_size_t),
                    ("maximum_working_set_size", ctypes.c_size_t),
                    ("active_process_limit", wintypes.DWORD),
                    ("affinity", ctypes.c_size_t),
                    ("priority_class", wintypes.DWORD),
                    ("scheduling_class", wintypes.DWORD),
                ]

            class IoCounters(ctypes.Structure):
                _fields_ = [
                    ("read_operation_count", ctypes.c_ulonglong),
                    ("write_operation_count", ctypes.c_ulonglong),
                    ("other_operation_count", ctypes.c_ulonglong),
                    ("read_transfer_count", ctypes.c_ulonglong),
                    ("write_transfer_count", ctypes.c_ulonglong),
                    ("other_transfer_count", ctypes.c_ulonglong),
                ]

            class ExtendedLimitInformation(ctypes.Structure):
                _fields_ = [
                    ("basic_limit_information", BasicLimitInformation),
                    ("io_info", IoCounters),
                    ("process_memory_limit", ctypes.c_size_t),
                    ("job_memory_limit", ctypes.c_size_t),
                    ("peak_process_memory_used", ctypes.c_size_t),
                    ("peak_job_memory_used", ctypes.c_size_t),
                ]

            details = ExtendedLimitInformation()
            details.basic_limit_information.limit_flags = 0x0000_2000
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            set_information = kernel32.SetInformationJobObject
            set_information.argtypes = [
                wintypes.HANDLE,
                ctypes.c_int,
                ctypes.c_void_p,
                wintypes.DWORD,
            ]
            set_information.restype = wintypes.BOOL
            if not set_information(
                job,
                9,
                ctypes.byref(details),
                ctypes.sizeof(details),
            ):
                raise OSError("job close containment is unavailable")
        except (AttributeError, OSError, TypeError, ValueError):
            raise RunnerTransportError("Windows process containment is unavailable") from None

    @staticmethod
    def _resume_windows_process(process: subprocess.Popen[bytes]) -> None:
        """Resume the one primary thread of a CREATE_SUSPENDED child."""

        snapshot = 0
        thread_handle = 0
        try:
            import ctypes
            from ctypes import wintypes

            class ThreadEntry32(ctypes.Structure):
                _fields_ = [
                    ("size", wintypes.DWORD),
                    ("usage", wintypes.DWORD),
                    ("thread_id", wintypes.DWORD),
                    ("owner_process_id", wintypes.DWORD),
                    ("base_priority", wintypes.LONG),
                    ("priority_delta", wintypes.LONG),
                    ("flags", wintypes.DWORD),
                ]

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            create_snapshot = kernel32.CreateToolhelp32Snapshot
            create_snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
            create_snapshot.restype = wintypes.HANDLE
            first_thread = kernel32.Thread32First
            first_thread.argtypes = [wintypes.HANDLE, ctypes.POINTER(ThreadEntry32)]
            first_thread.restype = wintypes.BOOL
            next_thread = kernel32.Thread32Next
            next_thread.argtypes = [wintypes.HANDLE, ctypes.POINTER(ThreadEntry32)]
            next_thread.restype = wintypes.BOOL
            open_thread = kernel32.OpenThread
            open_thread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
            open_thread.restype = wintypes.HANDLE
            resume_thread = kernel32.ResumeThread
            resume_thread.argtypes = [wintypes.HANDLE]
            resume_thread.restype = wintypes.DWORD

            raw_snapshot = create_snapshot(0x0000_0004, 0)
            invalid_handle = ctypes.c_void_p(-1).value
            if not raw_snapshot or int(raw_snapshot) == invalid_handle:
                raise OSError("thread snapshot unavailable")
            snapshot = int(raw_snapshot)
            entry = ThreadEntry32()
            entry.size = ctypes.sizeof(entry)
            available = bool(first_thread(snapshot, ctypes.byref(entry)))
            candidates: list[int] = []
            while available:
                if entry.owner_process_id == process.pid:
                    candidates.append(int(entry.thread_id))
                available = bool(next_thread(snapshot, ctypes.byref(entry)))
            if len(candidates) != 1:
                raise OSError("suspended child thread identity is ambiguous")
            raw_thread = open_thread(0x0002, False, candidates[0])
            if not raw_thread:
                raise OSError("suspended child thread is unavailable")
            thread_handle = int(raw_thread)
            previous_count = int(resume_thread(thread_handle))
            if previous_count != 1:
                raise OSError("suspended child was not resumed exactly once")
        except (AttributeError, OSError, TypeError, ValueError):
            raise RunnerTransportError("Windows suspended process start failed") from None
        finally:
            if thread_handle:
                SubprocessRustRunner._close_windows_handle(thread_handle)
            if snapshot:
                SubprocessRustRunner._close_windows_handle(snapshot)

    def _assign_windows_job(
        self,
        job: int,
        process: subprocess.Popen[bytes],
    ) -> None:
        process_handle = 0
        try:
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            open_process = kernel32.OpenProcess
            open_process.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
            open_process.restype = wintypes.HANDLE
            assign_process = kernel32.AssignProcessToJobObject
            assign_process.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
            assign_process.restype = wintypes.BOOL
            terminate_process = kernel32.TerminateProcess
            terminate_process.argtypes = [wintypes.HANDLE, wintypes.UINT]
            terminate_process.restype = wintypes.BOOL

            raw_process_handle = open_process(0x0001 | 0x0100 | 0x1000, False, process.pid)
            if not raw_process_handle:
                raise OSError("process handle unavailable")
            process_handle = int(raw_process_handle)
            if not assign_process(job, process_handle):
                terminate_process(process_handle, 1)
                raise OSError("job assignment failed")
            with self._windows_jobs_lock:
                self._windows_jobs[process.pid] = job
        except (AttributeError, OSError, TypeError, ValueError):
            if process.poll() is None:
                try:
                    process.kill()
                except OSError:
                    pass
            try:
                process.wait(timeout=_PROCESS_KILL_GRACE_SECONDS)
            except subprocess.TimeoutExpired:
                pass
            raise RunnerTransportError("Windows process containment is unavailable") from None
        finally:
            if process_handle:
                self._close_windows_handle(process_handle)

    def _release_windows_job(self, process_id: int) -> bool:
        with self._windows_jobs_lock:
            job = self._windows_jobs.pop(process_id, None)
        return job is None or self._close_windows_handle(job)

    def _finish_windows_job(self, process_id: int) -> bool:
        with self._windows_jobs_lock:
            job = self._windows_jobs.get(process_id)
        if job is None:
            return True
        try:
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            terminate_job = kernel32.TerminateJobObject
            terminate_job.argtypes = [wintypes.HANDLE, wintypes.UINT]
            terminate_job.restype = wintypes.BOOL
            descendants_stopped = bool(terminate_job(job, 1))
        except (AttributeError, TypeError, ValueError):
            descendants_stopped = False
        if not descendants_stopped or not self._wait_for_empty_windows_job(job):
            return False
        return self._release_windows_job(process_id)

    @staticmethod
    def _wait_for_empty_windows_job(job: int) -> bool:
        try:
            import ctypes
            from ctypes import wintypes

            class BasicAccountingInformation(ctypes.Structure):
                _fields_ = [
                    ("total_user_time", ctypes.c_longlong),
                    ("total_kernel_time", ctypes.c_longlong),
                    ("period_user_time", ctypes.c_longlong),
                    ("period_kernel_time", ctypes.c_longlong),
                    ("total_page_fault_count", wintypes.DWORD),
                    ("total_processes", wintypes.DWORD),
                    ("active_processes", wintypes.DWORD),
                    ("total_terminated_processes", wintypes.DWORD),
                ]

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            query = kernel32.QueryInformationJobObject
            query.argtypes = [
                wintypes.HANDLE,
                ctypes.c_int,
                ctypes.c_void_p,
                wintypes.DWORD,
                ctypes.POINTER(wintypes.DWORD),
            ]
            query.restype = wintypes.BOOL
            deadline = time.monotonic() + _PROCESS_KILL_GRACE_SECONDS
            while True:
                details = BasicAccountingInformation()
                returned = wintypes.DWORD()
                if not query(
                    job,
                    1,
                    ctypes.byref(details),
                    ctypes.sizeof(details),
                    ctypes.byref(returned),
                ):
                    return False
                if details.active_processes == 0:
                    return True
                if time.monotonic() >= deadline:
                    return False
                time.sleep(_PROCESS_POLL_SECONDS)
        except (AttributeError, OSError, TypeError, ValueError):
            return False

    @staticmethod
    def _close_windows_handle(handle: int) -> bool:
        try:
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            close_handle = kernel32.CloseHandle
            close_handle.argtypes = [wintypes.HANDLE]
            close_handle.restype = wintypes.BOOL
            return bool(close_handle(handle))
        except (AttributeError, TypeError, ValueError):
            return False

    @staticmethod
    def _windows_system_directory() -> Path:
        if os.name != "nt":
            raise RunnerTransportError("Windows process control is unavailable")
        try:
            import ctypes

            buffer = ctypes.create_unicode_buffer(32768)
            length = ctypes.windll.kernel32.GetSystemDirectoryW(  # type: ignore[attr-defined]
                buffer, len(buffer)
            )
            if length <= 0 or length >= len(buffer):
                raise OSError("system directory lookup failed")
            directory = Path(buffer.value).resolve(strict=True)
            if not directory.is_dir():
                raise OSError("system directory is unavailable")
            return directory
        except (AttributeError, OSError, ValueError):
            raise RunnerTransportError("Windows process control is unavailable") from None

    def _file_exceeds_limit(self, path: Path) -> bool:
        try:
            return path.stat().st_size > self.output_limit_bytes
        except OSError:
            return False

    def _durable_paths(
        self,
        durable_result_path: str | Path,
        task_id: str,
    ) -> tuple[Path, Path]:
        from .runner_trust import RunnerTrustError, _is_link_or_reparse, _owner_private

        destination = Path(durable_result_path).expanduser()
        if not destination.is_absolute() or destination.name in {"", ".", ".."}:
            raise RunnerTransportError("runner durable result destination is invalid")
        try:
            requested_parent = destination.parent
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            if _is_link_or_reparse(destination.parent):
                raise OSError("durable result parent is linked")
            parent = destination.parent.resolve(strict=True)
            if (
                os.path.normcase(os.path.normpath(str(requested_parent)))
                != os.path.normcase(os.path.normpath(str(parent)))
                or not parent.is_dir()
                or _is_link_or_reparse(parent)
            ):
                raise OSError("durable result parent is not a directory")
            _owner_private(parent, directory=True)
            if _is_link_or_reparse(parent) or parent.resolve(strict=True) != parent:
                raise OSError("durable result parent identity changed")
            destination = parent / destination.name
            if destination.exists() or _is_link_or_reparse(destination):
                raise RunnerDurableResultExists(
                    "Runner durable result already exists and requires reconciliation."
                )
        except RunnerDurableResultExists:
            raise
        except (OSError, RunnerTrustError):
            raise RunnerTransportError("runner durable result destination is unavailable") from None
        return destination, runner_pending_result_path(destination, task_id)

    @staticmethod
    def _open_pending_result(path: Path) -> BinaryIO:
        from .runner_trust import RunnerTrustError, _is_link_or_reparse, _owner_private

        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        handle: BinaryIO | None = None
        remove_created = False
        try:
            descriptor = os.open(path, flags, 0o600)
            handle = os.fdopen(descriptor, "w+b", buffering=0)
            remove_created = True
            _owner_private(path, directory=False)
            descriptor_state = os.fstat(descriptor)
            path_state = path.stat(follow_symlinks=False)
            if (
                descriptor_state.st_nlink != 1
                or path_state.st_nlink != 1
                or _is_link_or_reparse(path)
                or (descriptor_state.st_dev, descriptor_state.st_ino)
                != (path_state.st_dev, path_state.st_ino)
            ):
                raise OSError("unsafe pending result")
            return handle
        except FileExistsError:
            raise RunnerPendingResultExists(
                "Runner pending result requires recovery before the task can start."
            ) from None
        except (OSError, RunnerTrustError):
            if handle is not None:
                handle.close()
            if remove_created:
                try:
                    path.unlink()
                except OSError:
                    pass
            raise RunnerTransportError("runner pending result is unavailable") from None

    @staticmethod
    def _promote_pending_result(pending: Path, destination: Path, validated: bytes) -> None:
        from .runner_trust import RunnerTrustError, _is_link_or_reparse, _owner_private

        final_created = False
        handle: BinaryIO | None = None
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(destination, flags, 0o600)
            handle = os.fdopen(descriptor, "wb", buffering=0)
            final_created = True
            handle.write(validated)
            handle.flush()
            os.fsync(handle.fileno())
            _owner_private(destination, directory=False)
            descriptor_state = os.fstat(handle.fileno())
            path_state = destination.stat(follow_symlinks=False)
            if (
                descriptor_state.st_nlink != 1
                or path_state.st_nlink != 1
                or _is_link_or_reparse(destination)
                or (descriptor_state.st_dev, descriptor_state.st_ino)
                != (path_state.st_dev, path_state.st_ino)
            ):
                raise OSError("durable result identity changed")
            handle.close()
            handle = None
            if os.name != "nt":
                descriptor = os.open(destination.parent, os.O_RDONLY)
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            pending.unlink()
            if os.name != "nt":
                descriptor = os.open(destination.parent, os.O_RDONLY)
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
        except FileExistsError:
            raise RunnerDurableResultExists(
                "Runner durable result already exists and requires reconciliation."
            ) from None
        except (OSError, RunnerTrustError):
            if final_created:
                raise RunnerDurableResultExists(
                    "Runner durable result may be committed and requires reconciliation."
                ) from None
            raise RunnerTransportError("runner durable result could not be committed") from None
        finally:
            if handle is not None:
                handle.close()

    @staticmethod
    def _remove_pending_result(path: Path) -> None:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass

    @staticmethod
    def _decode_json(payload: bytes, label: str) -> Mapping[str, Any]:
        def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            value: dict[str, Any] = {}
            for key, child in pairs:
                if key in value:
                    raise ValueError("duplicate JSON object key")
                value[key] = child
            return value

        def finite_float(raw: str) -> float:
            value = float(raw)
            if not math.isfinite(value):
                raise ValueError("non-finite JSON number")
            return value

        def reject_constant(_raw: str) -> Any:
            raise ValueError("non-standard JSON constant")

        try:
            value = json.loads(
                payload.decode("utf-8"),
                object_pairs_hook=unique_object,
                parse_constant=reject_constant,
                parse_float=finite_float,
            )
        except (RecursionError, UnicodeDecodeError, ValueError) as exc:
            raise RunnerTransportError(f"{label} is not valid UTF-8 JSON") from exc
        if not isinstance(value, dict):
            raise RunnerTransportError(f"{label} must be a JSON object")
        return value


__all__ = [
    "InventoryBoundRunner",
    "RunnerTransport",
    "RunnerTransportError",
    "RunnerReadinessError",
    "RunnerDurableResultExists",
    "RunnerPendingResultExists",
    "RunnerTaskCancelled",
    "SubprocessRustRunner",
    "TaskAwareRunnerTransport",
    "canonical_runner_inventory",
    "reject_forbidden_execution_keys",
    "runner_inventory_digest",
    "runner_pending_result_path",
    "runner_transport_identity",
    "request_runner_task_cancel",
    "cleanup_runner_watchdog_terminal_state",
    "runner_watchdog_cancel_path",
    "runner_watchdog_control_root",
    "runner_watchdog_ready_path",
    "runner_watchdog_status_path",
]
