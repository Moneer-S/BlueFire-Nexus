"""Bounded lifecycle ownership for a reviewed external-engine worker.

This module owns one already-admitted process launch.  It does not select an
engine, mint authority, expand target scope, or interpret an engine report as
evidence.  The caller supplies a closed launch plan and, when the engine can
create resources outside its process group, an independent custody backend.

The durable launch reservation is deliberately created before ``Popen``.  A
reconnect can inspect that reservation, but cannot submit the same attempt a
second time.  Environment values are never written to lifecycle receipts.

This module is not a host-containment boundary.  A POSIX child can escape its
session with ``setsid`` and a process group cannot account for containers or
other daemon-owned resources.  Qualified engine execution therefore also
requires a dedicated worker VM, PID namespace, or cgroup; controller-enforced
network policy; and independent external-resource reconciliation.  The
controller record root must be protected by a different identity or ACL from
the engine workspace.  Merely placing it in a sibling directory is not an OS
security boundary.  Windows uses Job-backed hard stop, not a claimed console
cooperative-cancel channel.  POSIX reservation entries are directory-fsynced;
Windows power-loss durability still requires the product's transactional
attempt store in addition to this process-local reservation.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import signal
import subprocess  # nosec B404 - reviewed argv is launched without a shell
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import IO, Any, Mapping, Protocol

from .runner_transport_errors import RunnerTransportError
from .runner_windows_containment import WindowsJobContainment
from .util import canonical_json_bytes

_ATTEMPT_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_ENVIRONMENT_NAME = re.compile(r"[A-Z][A-Z0-9_]{0,127}")
_RESOURCE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@+-]{0,127}")
_LAUNCH_RECEIPT = "launch.json"
_OUTCOME_RECEIPT = "outcome.json"
_STDOUT_NAME = "worker.stdout.bin"
_STDERR_NAME = "worker.stderr.bin"
_POLL_SECONDS = 0.05
_READ_CHUNK = 64 * 1024
_MAX_ARGUMENTS = 128
_MAX_ARGUMENT_BYTES = 128 * 1024
_MAX_ENVIRONMENT_NAMES = 128
_MAX_ENVIRONMENT_BYTES = 128 * 1024


class EngineWorkerError(ValueError):
    """The trusted lifecycle caller supplied an invalid launch contract."""


class EngineExecutionState(str, Enum):
    RESERVED = "reserved"
    EXITED = "exited"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"
    INTERRUPTED = "interrupted"
    STARTUP_FAILED = "startup_failed"


class EngineCleanupState(str, Enum):
    VERIFIED = "verified"
    UNKNOWN = "unknown"


class ResourceCustodyState(str, Enum):
    VERIFIED_ABSENT = "verified_absent"
    PRESENT = "present"
    UNKNOWN = "unknown"


class CancellationSignal(Protocol):
    def is_set(self) -> bool: ...


class EngineResourceCustody(Protocol):
    """Observe and stop resources created outside the worker process group.

    An implementation is expected to use a controller-owned runtime endpoint
    and an exact attempt label.  Returning no rows is insufficient unless the
    backend can independently establish ``verified_absent``.
    """

    def inspect(
        self,
        attempt_id: str,
        *,
        custody_identity_digest: str,
        network_policy_digest: str,
        timeout_seconds: float,
    ) -> "ResourceCustodySnapshot": ...

    def stop_owned(
        self,
        attempt_id: str,
        *,
        custody_identity_digest: str,
        network_policy_digest: str,
        timeout_seconds: float,
    ) -> "ResourceCustodySnapshot": ...


@dataclass(frozen=True, slots=True)
class ResourceCustodySnapshot:
    state: ResourceCustodyState
    resource_ids: tuple[str, ...] = ()
    issue: str | None = None

    def __post_init__(self) -> None:
        if (
            len(self.resource_ids) > 256
            or tuple(sorted(set(self.resource_ids))) != self.resource_ids
        ):
            raise EngineWorkerError("resource custody identities must be sorted and unique")
        if any(_RESOURCE_ID.fullmatch(value) is None for value in self.resource_ids):
            raise EngineWorkerError("resource custody identity is invalid")
        if self.state is ResourceCustodyState.VERIFIED_ABSENT and self.resource_ids:
            raise EngineWorkerError("verified resource absence cannot retain resource identities")
        if self.state is ResourceCustodyState.PRESENT and not self.resource_ids:
            raise EngineWorkerError("present resources require bounded identities")
        if self.issue is not None and (
            not isinstance(self.issue, str)
            or not self.issue
            or len(self.issue) > 100
            or _RESOURCE_ID.fullmatch(self.issue) is None
        ):
            raise EngineWorkerError("resource custody issue is invalid")

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state.value,
            "resource_ids": list(self.resource_ids),
            "issue": self.issue,
        }


class UnavailableResourceCustody:
    """Fail-closed placeholder for deployments without independent custody."""

    def inspect(
        self,
        attempt_id: str,
        *,
        custody_identity_digest: str,
        network_policy_digest: str,
        timeout_seconds: float,
    ) -> ResourceCustodySnapshot:
        del attempt_id, custody_identity_digest, network_policy_digest, timeout_seconds
        return ResourceCustodySnapshot(ResourceCustodyState.UNKNOWN, issue="custody_unavailable")

    def stop_owned(
        self,
        attempt_id: str,
        *,
        custody_identity_digest: str,
        network_policy_digest: str,
        timeout_seconds: float,
    ) -> ResourceCustodySnapshot:
        del attempt_id, custody_identity_digest, network_policy_digest, timeout_seconds
        return ResourceCustodySnapshot(ResourceCustodyState.UNKNOWN, issue="custody_unavailable")


@dataclass(frozen=True, slots=True)
class EngineLaunchPlan:
    """One immutable, already-reviewed process launch.

    ``environment`` is an exact environment rather than additions to the
    ambient process.  It is represented as ordered pairs so a frozen plan has
    no mutable mapping hidden inside it.
    """

    attempt_id: str
    plan_digest: str
    argv: tuple[str, ...]
    environment: tuple[tuple[str, str], ...]
    working_directory: Path
    attempt_root: Path
    control_root: Path
    wall_time_seconds: float
    graceful_stop_seconds: float = 5.0
    hard_stop_seconds: float = 5.0
    output_limit_bytes: int = 4 * 1024 * 1024
    requires_resource_custody: bool = True
    custody_identity_digest: str | None = None
    network_policy_digest: str | None = None
    sensitive_environment_names: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if _ATTEMPT_ID.fullmatch(self.attempt_id) is None:
            raise EngineWorkerError("engine attempt identity is invalid")
        if _DIGEST.fullmatch(self.plan_digest) is None:
            raise EngineWorkerError("engine launch plan digest is invalid")
        if not self.argv or len(self.argv) > _MAX_ARGUMENTS:
            raise EngineWorkerError("engine launch argv is empty or oversized")
        if any(
            not isinstance(value, str)
            or not value
            or "\x00" in value
            or "\r" in value
            or "\n" in value
            for value in self.argv
        ):
            raise EngineWorkerError("engine launch argv contains an invalid argument")
        if sum(len(value.encode("utf-8")) for value in self.argv) > _MAX_ARGUMENT_BYTES:
            raise EngineWorkerError("engine launch argv exceeds its byte limit")
        executable = Path(self.argv[0])
        if not executable.is_absolute():
            raise EngineWorkerError("engine executable must be an absolute path")
        if len(self.environment) > _MAX_ENVIRONMENT_NAMES:
            raise EngineWorkerError("engine environment has too many fields")
        names = tuple(name for name, _value in self.environment)
        if names != tuple(sorted(set(names))):
            raise EngineWorkerError("engine environment names must be sorted and unique")
        total_environment = 0
        for name, value in self.environment:
            if _ENVIRONMENT_NAME.fullmatch(name) is None:
                raise EngineWorkerError("engine environment name is invalid")
            if (
                not isinstance(value, str)
                or "\x00" in value
                or "\r" in value
                or "\n" in value
                or len(value.encode("utf-8")) > 16 * 1024
            ):
                raise EngineWorkerError("engine environment value is invalid")
            total_environment += len(name.encode("ascii")) + len(value.encode("utf-8"))
        if total_environment > _MAX_ENVIRONMENT_BYTES:
            raise EngineWorkerError("engine environment exceeds its byte limit")
        if self.sensitive_environment_names != tuple(
            sorted(set(self.sensitive_environment_names))
        ) or any(name not in names for name in self.sensitive_environment_names):
            raise EngineWorkerError("sensitive engine environment names are invalid")
        for name, value in self.environment:
            if name in self.sensitive_environment_names and len(value.encode("utf-8")) < 8:
                raise EngineWorkerError("sensitive engine environment value is too short to redact")
        if (
            not isinstance(self.working_directory, Path)
            or not isinstance(self.attempt_root, Path)
            or not isinstance(self.control_root, Path)
        ):
            raise EngineWorkerError("engine working paths must be Path values")
        try:
            root = self.attempt_root.resolve(strict=True)
            working = self.working_directory.resolve(strict=True)
            control = self.control_root.resolve(strict=True)
        except OSError as exc:
            raise EngineWorkerError("engine working paths are unavailable") from exc
        if (
            not root.is_dir()
            or not working.is_dir()
            or not control.is_dir()
            or not working.is_relative_to(root)
        ):
            raise EngineWorkerError("engine working directory is outside its attempt root")
        if (
            self.attempt_root.is_symlink()
            or self.working_directory.is_symlink()
            or self.control_root.is_symlink()
        ):
            raise EngineWorkerError("engine working paths cannot be symbolic links")
        if control == root or control.is_relative_to(root) or root.is_relative_to(control):
            raise EngineWorkerError(
                "controller records must be outside the engine filesystem scope"
            )
        for limit_value, minimum, maximum, label in (
            (self.wall_time_seconds, 0.1, 24 * 60 * 60, "wall time"),
            (self.graceful_stop_seconds, 0.1, 30.0, "graceful stop time"),
            (self.hard_stop_seconds, 0.1, 30.0, "hard stop time"),
        ):
            if (
                isinstance(limit_value, bool)
                or not isinstance(limit_value, (int, float))
                or not minimum <= limit_value <= maximum
            ):
                raise EngineWorkerError(f"engine {label} is invalid")
        if (
            isinstance(self.output_limit_bytes, bool)
            or not isinstance(self.output_limit_bytes, int)
            or not 1024 <= self.output_limit_bytes <= 64 * 1024 * 1024
        ):
            raise EngineWorkerError("engine output byte limit is invalid")
        if type(self.requires_resource_custody) is not bool:
            raise EngineWorkerError("engine resource custody requirement must be boolean")
        custody_digests = (self.custody_identity_digest, self.network_policy_digest)
        if self.requires_resource_custody:
            if any(
                not isinstance(value, str) or _DIGEST.fullmatch(value) is None
                for value in custody_digests
            ):
                raise EngineWorkerError("engine custody and network policy digests are required")
        elif any(value is not None for value in custody_digests):
            raise EngineWorkerError("process-only launch cannot claim external custody bindings")

    @property
    def exact_environment(self) -> dict[str, str]:
        return dict(self.environment)

    def public_launch_receipt(self) -> dict[str, Any]:
        """Return persistence-safe metadata without arguments or environment values."""

        return {
            "schema_version": "bluefire.engine-launch-reservation.v1",
            "attempt_id": self.attempt_id,
            "plan_digest": self.plan_digest,
            "argv_sha256": _bytes_digest(canonical_json_bytes(list(self.argv))),
            "environment_names": list(name for name, _value in self.environment),
            "sensitive_environment_names": list(self.sensitive_environment_names),
            "requires_resource_custody": self.requires_resource_custody,
            "custody_identity_digest": self.custody_identity_digest,
            "network_policy_digest": self.network_policy_digest,
            "wall_time_seconds": self.wall_time_seconds,
        }

    @property
    def output_redactions(self) -> tuple[bytes, ...]:
        sensitive = set(self.sensitive_environment_names)
        return tuple(
            sorted(
                {value.encode("utf-8") for name, value in self.environment if name in sensitive},
                key=lambda value: (-len(value), value),
            )
        )


@dataclass(frozen=True, slots=True)
class EngineLogReceipt:
    name: str
    size_bytes: int
    sha256: str
    truncated: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "truncated": self.truncated,
        }


@dataclass(frozen=True, slots=True)
class EngineWorkerOutcome:
    attempt_id: str
    execution_state: EngineExecutionState
    cleanup_state: EngineCleanupState
    started: bool
    exit_code: int | None
    started_at: str | None
    completed_at: str
    stdout: EngineLogReceipt
    stderr: EngineLogReceipt
    custody_before: ResourceCustodySnapshot
    custody_after: ResourceCustodySnapshot
    issues: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "bluefire.engine-worker-outcome.v1",
            "attempt_id": self.attempt_id,
            "execution_state": self.execution_state.value,
            "cleanup_state": self.cleanup_state.value,
            "started": self.started,
            "exit_code": self.exit_code,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "stdout": self.stdout.to_dict(),
            "stderr": self.stderr.to_dict(),
            "custody_before": self.custody_before.to_dict(),
            "custody_after": self.custody_after.to_dict(),
            "issues": list(self.issues),
        }


@dataclass(slots=True)
class _LogDrain:
    stream: IO[bytes]
    target: Path
    maximum: int
    redactions: tuple[bytes, ...] = ()
    truncated: bool = False
    error: bool = False
    started: bool = False
    thread: threading.Thread = field(init=False)

    def __post_init__(self) -> None:
        self.thread = threading.Thread(
            target=self._run,
            name=f"bluefire-{self.target.name}",
            daemon=True,
        )

    def start(self) -> None:
        self.thread.start()
        self.started = True

    def _run(self) -> None:
        written = 0
        redactor = _StreamingRedactor(self.redactions)
        try:
            with self.target.open("xb") as destination:
                if os.name != "nt":
                    os.chmod(self.target, 0o600)
                while True:
                    chunk = self.stream.read(_READ_CHUNK)
                    if not chunk:
                        break
                    written = self._retain(destination, redactor.feed(chunk), written)
                written = self._retain(destination, redactor.finish(), written)
                destination.flush()
                os.fsync(destination.fileno())
        except (OSError, RuntimeError, ValueError):
            self.error = True

    def _retain(self, destination: IO[bytes], value: bytes, written: int) -> int:
        remaining = max(0, self.maximum - written)
        if remaining:
            retained = value[:remaining]
            destination.write(retained)
            written += len(retained)
        if len(value) > remaining:
            self.truncated = True
        return written


@dataclass(slots=True)
class _StreamingRedactor:
    """Remove exact sensitive values without exposing cross-chunk fragments."""

    patterns: tuple[bytes, ...]
    pending: bytearray = field(default_factory=bytearray)

    def feed(self, value: bytes) -> bytes:
        self.pending.extend(value)
        return self._drain(final=False)

    def finish(self) -> bytes:
        return self._drain(final=True)

    def _drain(self, *, final: bool) -> bytes:
        if not self.patterns:
            value = bytes(self.pending)
            self.pending.clear()
            return value
        value = bytes(self.pending)
        self.pending.clear()
        emitted = bytearray()
        index = 0
        maximum_pattern = max(len(pattern) for pattern in self.patterns)
        safe_limit = len(value) if final else max(0, len(value) - maximum_pattern + 1)
        while index < safe_limit:
            occurrences = tuple(
                (position, pattern)
                for pattern in self.patterns
                if (position := value.find(pattern, index)) >= 0 and position < safe_limit
            )
            if not occurrences:
                emitted.extend(value[index:safe_limit])
                index = safe_limit
                break
            earliest = min(position for position, _pattern in occurrences)
            emitted.extend(value[index:earliest])
            matches = tuple(pattern for position, pattern in occurrences if position == earliest)
            longest = max(matches, key=len)
            emitted.extend(b"[REDACTED]")
            index = earliest + len(longest)
        self.pending.extend(value[index:])
        return bytes(emitted)


class _EngineStartFailure(RuntimeError):
    """Internal failure retaining only cleanup facts, never launch values."""

    def __init__(
        self,
        *,
        cleanup_verified: bool,
        child_created_at: str | None,
        interrupted: BaseException | None = None,
    ) -> None:
        super().__init__("engine worker start failed")
        self.cleanup_verified = cleanup_verified
        self.child_created_at = child_created_at
        self.interrupted = interrupted


@dataclass(slots=True)
class _OwnedProcess:
    process: subprocess.Popen[bytes]
    windows_containment: WindowsJobContainment | None = None


class EngineWorkerRuntime:
    """Start and settle one engine process under a durable launch reservation."""

    def run(
        self,
        plan: EngineLaunchPlan,
        *,
        cancellation: CancellationSignal,
        custody: EngineResourceCustody | None = None,
    ) -> EngineWorkerOutcome:
        control = plan.control_root / plan.attempt_id
        try:
            control.mkdir(mode=0o700, exist_ok=False)
        except FileExistsError:
            return self._reserved_outcome(plan, control)
        except OSError as exc:
            raise EngineWorkerError("engine launch reservation could not be created") from exc

        if control.resolve(strict=True).parent != plan.control_root.resolve(strict=True):
            raise EngineWorkerError("engine launch reservation escaped its controller root")
        if os.name != "nt" and not _sync_directory(plan.control_root):
            raise EngineWorkerError("engine launch reservation was not made durable")
        launch = plan.public_launch_receipt()
        launch["reserved_at"] = _utc_now()
        _write_exclusive_json(control / _LAUNCH_RECEIPT, launch)
        if os.name != "nt" and not _sync_directory(control):
            raise EngineWorkerError("engine launch receipt was not made durable")

        stdout_path = control / _STDOUT_NAME
        stderr_path = control / _STDERR_NAME
        selected_custody: EngineResourceCustody = custody or UnavailableResourceCustody()
        custody_before = self._inspect_custody(selected_custody, plan)
        if (
            plan.requires_resource_custody
            and custody_before.state is not ResourceCustodyState.VERIFIED_ABSENT
        ):
            return self._finish_without_start(
                plan,
                control,
                stdout_path,
                stderr_path,
                EngineExecutionState.STARTUP_FAILED,
                custody_before,
                custody_before,
                (custody_before.issue or "resource_custody_not_absent",),
            )
        if cancellation.is_set():
            return self._finish_without_start(
                plan,
                control,
                stdout_path,
                stderr_path,
                EngineExecutionState.CANCELLED,
                custody_before,
                custody_before,
                (),
            )

        owned: _OwnedProcess | None = None
        stdout_drain: _LogDrain | None = None
        stderr_drain: _LogDrain | None = None
        execution_state = EngineExecutionState.STARTUP_FAILED
        started_at: str | None = None
        issues: list[str] = []
        process_cleanup = True
        deferred_interrupt: BaseException | None = None
        try:
            owned = self._start(plan)
            started_at = _utc_now()
            if owned.process.stdout is None or owned.process.stderr is None:
                raise EngineWorkerError("engine worker pipes are unavailable")
            stdout_drain = _LogDrain(
                owned.process.stdout,
                stdout_path,
                plan.output_limit_bytes,
                plan.output_redactions,
            )
            stderr_drain = _LogDrain(
                owned.process.stderr,
                stderr_path,
                plan.output_limit_bytes,
                plan.output_redactions,
            )
            stdout_drain.start()
            stderr_drain.start()
            deadline = time.monotonic() + plan.wall_time_seconds
            while True:
                if cancellation.is_set():
                    execution_state = EngineExecutionState.CANCELLED
                    break
                if time.monotonic() >= deadline:
                    execution_state = EngineExecutionState.TIMED_OUT
                    break
                if _peek_exit_code(owned.process) is not None:
                    execution_state = EngineExecutionState.EXITED
                    break
                time.sleep(_POLL_SECONDS)
        except _EngineStartFailure as exc:
            process_cleanup = exc.cleanup_verified
            started_at = exc.child_created_at
            if exc.interrupted is not None:
                deferred_interrupt = exc.interrupted
                execution_state = EngineExecutionState.INTERRUPTED
                issues.append("controller_interrupted")
            else:
                issues.append("worker_start_failed")
                execution_state = EngineExecutionState.STARTUP_FAILED
            if not process_cleanup:
                issues.append("process_cleanup_unknown")
        except (
            OSError,
            RuntimeError,
            subprocess.SubprocessError,
            RunnerTransportError,
            EngineWorkerError,
        ):
            issues.append(
                "worker_output_start_failed" if started_at is not None else "worker_start_failed"
            )
            execution_state = EngineExecutionState.STARTUP_FAILED
        except BaseException as exc:
            deferred_interrupt = exc
            issues.append("controller_interrupted")
            execution_state = EngineExecutionState.INTERRUPTED
        finally:
            if owned is not None:
                process_cleanup = self._settle_process(owned, plan)
                if not process_cleanup:
                    issues.append("process_cleanup_unknown")

        custody_after = custody_before
        if plan.requires_resource_custody and started_at is not None:
            self._stop_custody(selected_custody, plan)
            custody_after = self._inspect_custody(selected_custody, plan)
            if custody_after.state is not ResourceCustodyState.VERIFIED_ABSENT:
                issues.append(custody_after.issue or "resource_cleanup_unknown")
        if started_at is None and stdout_drain is None and stderr_drain is None:
            if not stdout_path.exists():
                _write_empty(stdout_path)
            if not stderr_path.exists():
                _write_empty(stderr_path)
            streams_drained = True
        else:
            streams_drained = self._finish_drains(
                stdout_drain,
                stderr_drain,
                timeout_seconds=plan.hard_stop_seconds,
            )
        if not streams_drained:
            issues.append("output_cleanup_unknown")
        for path, drain in ((stdout_path, stdout_drain), (stderr_path, stderr_drain)):
            if drain is None and not path.exists():
                try:
                    _write_empty(path)
                except EngineWorkerError:
                    issues.append("output_cleanup_unknown")
        stdout_receipt = _log_receipt(stdout_path, stdout_drain)
        stderr_receipt = _log_receipt(stderr_path, stderr_drain)

        custody_clean = (
            not plan.requires_resource_custody
            or custody_after.state is ResourceCustodyState.VERIFIED_ABSENT
        )
        cleanup_state = (
            EngineCleanupState.VERIFIED
            if process_cleanup and streams_drained and custody_clean
            else EngineCleanupState.UNKNOWN
        )
        outcome = EngineWorkerOutcome(
            attempt_id=plan.attempt_id,
            execution_state=execution_state,
            cleanup_state=cleanup_state,
            started=started_at is not None,
            exit_code=None if owned is None else owned.process.returncode,
            started_at=started_at,
            completed_at=_utc_now(),
            stdout=stdout_receipt,
            stderr=stderr_receipt,
            custody_before=custody_before,
            custody_after=custody_after,
            issues=tuple(sorted(set(issues))),
        )
        _write_exclusive_json(control / _OUTCOME_RECEIPT, outcome.to_dict())
        if os.name != "nt" and not _sync_directory(control):
            raise EngineWorkerError("engine outcome receipt was not made durable")
        if deferred_interrupt is not None:
            raise deferred_interrupt
        return outcome

    def _reserved_outcome(self, plan: EngineLaunchPlan, control: Path) -> EngineWorkerOutcome:
        """Refuse a duplicate launch without touching a possibly active attempt."""

        reservation = read_launch_reservation(plan.control_root, plan.attempt_id)
        expected = plan.public_launch_receipt()
        if reservation is not None and all(
            reservation.get(name) == value for name, value in expected.items()
        ):
            retained = read_worker_outcome(plan.control_root, plan.attempt_id)
            if retained is not None:
                return retained
            issue = "launch_already_reserved"
        else:
            issue = "launch_reservation_mismatch"

        unknown = ResourceCustodySnapshot(ResourceCustodyState.UNKNOWN, issue=issue)
        return EngineWorkerOutcome(
            attempt_id=plan.attempt_id,
            execution_state=EngineExecutionState.RESERVED,
            cleanup_state=EngineCleanupState.UNKNOWN,
            started=False,
            exit_code=None,
            started_at=None,
            completed_at=_utc_now(),
            stdout=_existing_log_receipt(control / _STDOUT_NAME),
            stderr=_existing_log_receipt(control / _STDERR_NAME),
            custody_before=unknown,
            custody_after=unknown,
            issues=(issue,),
        )

    def _finish_without_start(
        self,
        plan: EngineLaunchPlan,
        control: Path,
        stdout_path: Path,
        stderr_path: Path,
        state: EngineExecutionState,
        custody_before: ResourceCustodySnapshot,
        custody_after: ResourceCustodySnapshot,
        issues: tuple[str, ...],
    ) -> EngineWorkerOutcome:
        _write_empty(stdout_path)
        _write_empty(stderr_path)
        cleanup = (
            EngineCleanupState.VERIFIED
            if custody_after.state is ResourceCustodyState.VERIFIED_ABSENT
            or not plan.requires_resource_custody
            else EngineCleanupState.UNKNOWN
        )
        outcome = EngineWorkerOutcome(
            attempt_id=plan.attempt_id,
            execution_state=state,
            cleanup_state=cleanup,
            started=False,
            exit_code=None,
            started_at=None,
            completed_at=_utc_now(),
            stdout=_existing_log_receipt(stdout_path),
            stderr=_existing_log_receipt(stderr_path),
            custody_before=custody_before,
            custody_after=custody_after,
            issues=tuple(sorted(set(issues))),
        )
        _write_exclusive_json(control / _OUTCOME_RECEIPT, outcome.to_dict())
        if os.name != "nt" and not _sync_directory(control):
            raise EngineWorkerError("engine outcome receipt was not made durable")
        return outcome

    @staticmethod
    def _inspect_custody(
        custody: EngineResourceCustody, plan: EngineLaunchPlan
    ) -> ResourceCustodySnapshot:
        if not plan.requires_resource_custody:
            return ResourceCustodySnapshot(ResourceCustodyState.VERIFIED_ABSENT)
        try:
            value = custody.inspect(
                plan.attempt_id,
                custody_identity_digest=str(plan.custody_identity_digest),
                network_policy_digest=str(plan.network_policy_digest),
                timeout_seconds=min(plan.graceful_stop_seconds, 10.0),
            )
            if not isinstance(value, ResourceCustodySnapshot):
                raise TypeError
            return value
        except (OSError, RuntimeError, TypeError, ValueError):
            return ResourceCustodySnapshot(
                ResourceCustodyState.UNKNOWN, issue="custody_inspection_failed"
            )

    @staticmethod
    def _stop_custody(custody: EngineResourceCustody, plan: EngineLaunchPlan) -> None:
        try:
            custody.stop_owned(
                plan.attempt_id,
                custody_identity_digest=str(plan.custody_identity_digest),
                network_policy_digest=str(plan.network_policy_digest),
                timeout_seconds=plan.hard_stop_seconds,
            )
        except (OSError, RuntimeError, TypeError, ValueError):
            return

    @staticmethod
    def _start(plan: EngineLaunchPlan) -> _OwnedProcess:
        options: dict[str, Any] = {
            "cwd": plan.working_directory,
            "env": plan.exact_environment,
            "shell": False,
            "stdin": subprocess.DEVNULL,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "close_fds": True,
            "bufsize": 0,
        }
        containment: WindowsJobContainment | None = None
        job: int | None = None
        process: subprocess.Popen[bytes] | None = None
        assigned = False
        child_created_at: str | None = None
        if sys.platform == "win32":
            containment = WindowsJobContainment(kill_on_close=True)
            job = containment.create_job()
            options["creationflags"] = getattr(
                subprocess, "CREATE_NO_WINDOW", 0x08000000
            ) | getattr(subprocess, "CREATE_SUSPENDED", 0x00000004)
        else:
            options["start_new_session"] = True
            options["umask"] = 0o077
        try:
            process = subprocess.Popen(  # nosec B603 - immutable reviewed argv; no shell or ambient environment
                plan.argv,
                **options,
            )
            child_created_at = _utc_now()
            if containment is not None and job is not None:
                containment.assign(job, process)
                assigned = True
                WindowsJobContainment.resume_suspended(process)
            return _OwnedProcess(process, containment)
        except BaseException as exc:
            cleanup_verified = True
            if containment is not None and process is not None and assigned:
                cleanup_verified = containment.terminate(process)
                if not cleanup_verified and job is not None:
                    try:
                        containment.close_handle(job)
                    except OSError:
                        pass
            if process is not None and process.poll() is None:
                try:
                    process.kill()
                    process.wait(timeout=plan.hard_stop_seconds)
                except (OSError, subprocess.SubprocessError):
                    cleanup_verified = False
            if process is not None and process.poll() is None:
                cleanup_verified = False
            if containment is not None and job is not None and not assigned:
                try:
                    job_closed = containment.close_handle(job)
                except OSError:
                    job_closed = False
                cleanup_verified = job_closed and cleanup_verified
            raise _EngineStartFailure(
                cleanup_verified=cleanup_verified,
                child_created_at=child_created_at,
                interrupted=exc if not isinstance(exc, Exception) else None,
            ) from exc

    @staticmethod
    def _settle_process(owned: _OwnedProcess, plan: EngineLaunchPlan) -> bool:
        process = owned.process
        if owned.windows_containment is not None:
            # CREATE_NO_WINDOW children have no proven console-control channel.
            # Windows cancellation is therefore a Job-backed hard stop.
            return owned.windows_containment.finish(process)
        if sys.platform.startswith("linux"):
            return _settle_linux_group(process, plan)
        # The first qualified external-engine worker is Linux. On another POSIX
        # host, never claim descendant cleanup from the direct process alone.
        try:
            os.killpg(process.pid, signal.SIGTERM)  # type: ignore[attr-defined]
            process.wait(timeout=plan.graceful_stop_seconds)
        except (AttributeError, OSError, subprocess.SubprocessError):
            return False
        return False

    @staticmethod
    def _finish_drains(
        stdout: _LogDrain | None,
        stderr: _LogDrain | None,
        *,
        timeout_seconds: float,
    ) -> bool:
        clean = True
        for drain in (stdout, stderr):
            if drain is None:
                clean = False
                continue
            if not drain.started:
                clean = False
                drain.error = True
                try:
                    drain.stream.close()
                except OSError:
                    pass
                if not drain.target.exists():
                    try:
                        _write_empty(drain.target)
                    except EngineWorkerError:
                        pass
                continue
            drain.thread.join(timeout=timeout_seconds)
            if drain.thread.is_alive():
                clean = False
                try:
                    drain.stream.close()
                except OSError:
                    pass
                drain.thread.join(timeout=timeout_seconds)
            if drain.thread.is_alive() or drain.error:
                clean = False
            else:
                try:
                    drain.stream.close()
                except OSError:
                    clean = False
        return clean


def read_launch_reservation(control_root: Path, attempt_id: str) -> Mapping[str, Any] | None:
    """Read public launch metadata for reconnect without resubmitting work."""

    if _ATTEMPT_ID.fullmatch(attempt_id) is None:
        return None
    requested_attempt_id = attempt_id
    path = control_root / attempt_id / _LAUNCH_RECEIPT
    try:
        payload = path.read_bytes()
        if len(payload) > 16 * 1024:
            return None
        value = json.loads(payload, object_pairs_hook=_unique_object)
    except (OSError, UnicodeError, ValueError):
        return None
    fields = {
        "schema_version",
        "attempt_id",
        "plan_digest",
        "argv_sha256",
        "environment_names",
        "sensitive_environment_names",
        "requires_resource_custody",
        "custody_identity_digest",
        "network_policy_digest",
        "wall_time_seconds",
        "reserved_at",
    }
    if (
        not isinstance(value, Mapping)
        or set(value) != fields
        or value.get("schema_version") != "bluefire.engine-launch-reservation.v1"
    ):
        return None
    retained_attempt_id = value.get("attempt_id")
    plan_digest = value.get("plan_digest")
    if retained_attempt_id != requested_attempt_id:
        return None
    if not isinstance(plan_digest, str) or _DIGEST.fullmatch(plan_digest) is None:
        return None
    if (
        not isinstance(value.get("argv_sha256"), str)
        or _DIGEST.fullmatch(value["argv_sha256"]) is None
    ):
        return None
    names = value.get("environment_names")
    if (
        not isinstance(names, list)
        or len(names) > _MAX_ENVIRONMENT_NAMES
        or any(
            not isinstance(name, str) or _ENVIRONMENT_NAME.fullmatch(name) is None for name in names
        )
        or names != sorted(set(names))
    ):
        return None
    sensitive_names = value.get("sensitive_environment_names")
    if (
        not isinstance(sensitive_names, list)
        or len(sensitive_names) > _MAX_ENVIRONMENT_NAMES
        or any(not isinstance(name, str) for name in sensitive_names)
        or sensitive_names != sorted(set(sensitive_names))
        or any(name not in names for name in sensitive_names)
    ):
        return None
    required = value.get("requires_resource_custody")
    if type(required) is not bool:
        return None
    custody_digests = (value.get("custody_identity_digest"), value.get("network_policy_digest"))
    if required:
        if any(
            not isinstance(item, str) or _DIGEST.fullmatch(item) is None for item in custody_digests
        ):
            return None
    elif any(item is not None for item in custody_digests):
        return None
    wall_time = value.get("wall_time_seconds")
    if (
        isinstance(wall_time, bool)
        or not isinstance(wall_time, (int, float))
        or not 0.1 <= wall_time <= 86400
    ):
        return None
    timestamp = value.get("reserved_at")
    if not isinstance(timestamp, str) or len(timestamp) > 40:
        return None
    try:
        parsed = datetime.fromisoformat(timestamp.removesuffix("Z") + "+00:00")
    except ValueError:
        return None
    offset = parsed.utcoffset()
    if offset is None or offset.total_seconds() != 0:
        return None
    return dict(value)


def read_worker_outcome(control_root: Path, attempt_id: str) -> EngineWorkerOutcome | None:
    """Read one immutable final outcome without inferring process liveness."""

    if _ATTEMPT_ID.fullmatch(attempt_id) is None:
        return None
    path = control_root / attempt_id / _OUTCOME_RECEIPT
    try:
        payload = path.read_bytes()
        if len(payload) > 64 * 1024:
            return None
        value = json.loads(payload, object_pairs_hook=_unique_object)
    except (OSError, UnicodeError, ValueError):
        return None
    fields = {
        "schema_version",
        "attempt_id",
        "execution_state",
        "cleanup_state",
        "started",
        "exit_code",
        "started_at",
        "completed_at",
        "stdout",
        "stderr",
        "custody_before",
        "custody_after",
        "issues",
    }
    if (
        not isinstance(value, Mapping)
        or set(value) != fields
        or value.get("schema_version") != "bluefire.engine-worker-outcome.v1"
        or value.get("attempt_id") != attempt_id
    ):
        return None
    try:
        execution_state = EngineExecutionState(value.get("execution_state"))
        cleanup_state = EngineCleanupState(value.get("cleanup_state"))
    except (TypeError, ValueError):
        return None
    if execution_state is EngineExecutionState.RESERVED:
        return None
    started = value.get("started")
    exit_code = value.get("exit_code")
    started_at = value.get("started_at")
    completed_at = value.get("completed_at")
    if type(started) is not bool:
        return None
    if exit_code is not None and (type(exit_code) is not int or not -(2**31) <= exit_code < 2**31):
        return None
    if started:
        if not isinstance(started_at, str) or not _is_utc_timestamp(started_at):
            return None
    elif started_at is not None or exit_code is not None:
        return None
    if execution_state is EngineExecutionState.EXITED and exit_code is None:
        return None
    if not isinstance(completed_at, str) or not _is_utc_timestamp(completed_at):
        return None
    stdout = _parse_log_receipt(value.get("stdout"), expected_name=_STDOUT_NAME)
    stderr = _parse_log_receipt(value.get("stderr"), expected_name=_STDERR_NAME)
    custody_before = _parse_custody_snapshot(value.get("custody_before"))
    custody_after = _parse_custody_snapshot(value.get("custody_after"))
    if any(item is None for item in (stdout, stderr, custody_before, custody_after)):
        return None
    issues = value.get("issues")
    if (
        not isinstance(issues, list)
        or len(issues) > 64
        or any(
            not isinstance(issue, str) or _RESOURCE_ID.fullmatch(issue) is None for issue in issues
        )
        or issues != sorted(set(issues))
    ):
        return None
    assert stdout is not None
    assert stderr is not None
    assert custody_before is not None
    assert custody_after is not None
    if (
        cleanup_state is EngineCleanupState.VERIFIED
        and custody_after.state is not ResourceCustodyState.VERIFIED_ABSENT
    ):
        return None
    return EngineWorkerOutcome(
        attempt_id=attempt_id,
        execution_state=execution_state,
        cleanup_state=cleanup_state,
        started=started,
        exit_code=exit_code,
        started_at=started_at,
        completed_at=completed_at,
        stdout=stdout,
        stderr=stderr,
        custody_before=custody_before,
        custody_after=custody_after,
        issues=tuple(issues),
    )


def _parse_log_receipt(value: Any, *, expected_name: str) -> EngineLogReceipt | None:
    if not isinstance(value, Mapping) or set(value) != {
        "name",
        "size_bytes",
        "sha256",
        "truncated",
    }:
        return None
    size = value.get("size_bytes")
    digest = value.get("sha256")
    truncated = value.get("truncated")
    if (
        value.get("name") != expected_name
        or type(size) is not int
        or not 0 <= size <= 64 * 1024 * 1024
        or not isinstance(digest, str)
        or _DIGEST.fullmatch(digest) is None
        or type(truncated) is not bool
    ):
        return None
    return EngineLogReceipt(expected_name, size, digest, truncated)


def _parse_custody_snapshot(value: Any) -> ResourceCustodySnapshot | None:
    if not isinstance(value, Mapping) or set(value) != {"state", "resource_ids", "issue"}:
        return None
    resource_ids = value.get("resource_ids")
    if not isinstance(resource_ids, list) or any(
        not isinstance(item, str) for item in resource_ids
    ):
        return None
    try:
        return ResourceCustodySnapshot(
            ResourceCustodyState(value.get("state")),
            tuple(resource_ids),
            value.get("issue"),
        )
    except (TypeError, ValueError):
        return None


def _is_utc_timestamp(value: Any) -> bool:
    if not isinstance(value, str) or len(value) > 40:
        return False
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError:
        return False
    offset = parsed.utcoffset()
    return offset is not None and offset.total_seconds() == 0


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate engine lifecycle field")
        result[key] = value
    return result


def _write_exclusive_json(path: Path, value: Mapping[str, Any]) -> None:
    payload = canonical_json_bytes(value) + b"\n"
    if len(payload) > 64 * 1024:
        raise EngineWorkerError("engine lifecycle receipt exceeds its byte limit")
    try:
        with path.open("xb") as handle:
            if os.name != "nt":
                os.chmod(path, 0o600)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as exc:
        raise EngineWorkerError("engine lifecycle receipt could not be retained") from exc


def _write_empty(path: Path) -> None:
    try:
        with path.open("xb") as handle:
            if os.name != "nt":
                os.chmod(path, 0o600)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as exc:
        raise EngineWorkerError("engine lifecycle log could not be retained") from exc


def _sync_directory(path: Path) -> bool:
    descriptor: int | None = None
    try:
        flags = os.O_RDONLY | int(getattr(os, "O_DIRECTORY", 0))
        descriptor = os.open(path, flags)
        os.fsync(descriptor)
        return True
    except OSError:
        return False
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _bytes_digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(_READ_CHUNK), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _log_receipt(path: Path, drain: _LogDrain | None) -> EngineLogReceipt:
    if drain is not None and drain.started and drain.thread.is_alive():
        return EngineLogReceipt(path.name, 0, _bytes_digest(b""), True)
    if not path.is_file() or path.is_symlink():
        return EngineLogReceipt(path.name, 0, _bytes_digest(b""), True)
    try:
        size = path.stat().st_size
        digest = _file_digest(path)
    except OSError:
        return EngineLogReceipt(path.name, 0, _bytes_digest(b""), True)
    return EngineLogReceipt(
        path.name,
        size,
        digest,
        True if drain is None or drain.error else drain.truncated,
    )


def _existing_log_receipt(path: Path) -> EngineLogReceipt:
    if not path.is_file() or path.is_symlink():
        return EngineLogReceipt(path.name, 0, _bytes_digest(b""), True)
    try:
        return EngineLogReceipt(path.name, path.stat().st_size, _file_digest(path), False)
    except OSError:
        return EngineLogReceipt(path.name, 0, _bytes_digest(b""), True)


def _peek_exit_code(process: subprocess.Popen[bytes]) -> int | None:
    """Observe child exit without reaping the POSIX process-group leader."""

    if sys.platform == "win32" or not isinstance(process, subprocess.Popen):
        return process.poll()
    waitid = getattr(os, "waitid", None)
    pid_kind = getattr(os, "P_PID", None)
    exited = getattr(os, "WEXITED", None)
    nohang = getattr(os, "WNOHANG", None)
    nowait = getattr(os, "WNOWAIT", None)
    if not callable(waitid) or not all(
        isinstance(value, int) for value in (pid_kind, exited, nohang, nowait)
    ):
        # Without a non-reaping observation primitive, do not infer natural
        # completion. The wall/cancel path can still stop the owned group.
        return None
    try:
        value = waitid(pid_kind, process.pid, exited | nohang | nowait)
    except (ChildProcessError, OSError):
        return None
    if value is None:
        return None
    code = int(getattr(value, "si_code", 0))
    status = int(getattr(value, "si_status", 0))
    if code == int(getattr(os, "CLD_EXITED", -1)):
        return status
    return -status if status else -1


def _settle_linux_group(process: subprocess.Popen[bytes], plan: EngineLaunchPlan) -> bool:
    """Drain one private Linux session while its leader pins the PGID.

    ``waitid(WNOWAIT)`` observes without reaping. The leader therefore reserves
    its process-group identity during inventory and signalling. Two empty
    inventories are required before the leader is reaped. A child that creates
    another session is outside this proof and requires the separate worker-VM
    and external resource-custody boundary.
    """

    group = process.pid
    session = process.pid
    graceful_deadline = time.monotonic() + plan.graceful_stop_seconds
    final_deadline = graceful_deadline + plan.hard_stop_seconds
    termination_sent = False
    force_sent = False
    empty_inventories = 0
    while True:
        identity = _linux_process_identity(process.pid)
        if identity is None or identity[0] != group or identity[1] != session:
            return _linux_hard_stop_unknown(process, group, plan.hard_stop_seconds)
        leader_exited = _peek_exit_code(process) is not None
        inventory = _linux_private_session_inventory(group, session)
        if inventory is None:
            return _linux_hard_stop_unknown(process, group, plan.hard_stop_seconds)
        if leader_exited and not (set(inventory) - {process.pid}):
            empty_inventories += 1
            if empty_inventories >= 2:
                try:
                    process.wait(timeout=plan.hard_stop_seconds)
                except (OSError, subprocess.SubprocessError):
                    return False
                return process.returncode is not None
            time.sleep(_POLL_SECONDS)
            continue
        empty_inventories = 0
        now = time.monotonic()
        if now >= final_deadline:
            return _linux_hard_stop_unknown(process, group, plan.hard_stop_seconds)
        signal_number: int | None = None
        if not termination_sent:
            signal_number = int(getattr(signal, "SIGTERM", 15))
            termination_sent = True
        elif now >= graceful_deadline and not force_sent:
            signal_number = int(getattr(signal, "SIGKILL", 9))
            force_sent = True
        if signal_number is not None:
            try:
                # The unreaped leader prevents this exact PGID from being
                # reused between inventory and group signal.
                os.killpg(group, signal_number)  # type: ignore[attr-defined]
            except ProcessLookupError:
                pass
            except (AttributeError, OSError):
                # A member may exit between inventory and signal. Success still
                # requires two later empty inventories.
                pass
            for process_id, member_identity in inventory.items():
                member_group, member_session, _state, _start_time = member_identity
                if (
                    process_id != process.pid
                    and member_session == session
                    and member_group != group
                ):
                    _linux_signal_pidfd(process_id, member_identity, signal_number)
        time.sleep(_POLL_SECONDS)


def _linux_hard_stop_unknown(
    process: subprocess.Popen[bytes], group: int, timeout_seconds: float
) -> bool:
    """Best-effort hard stop after proof loss; never report verified cleanup."""

    try:
        os.killpg(group, int(getattr(signal, "SIGKILL", 9)))  # type: ignore[attr-defined]
    except (AttributeError, OSError):
        pass
    if _peek_exit_code(process) is None:
        try:
            process.kill()
        except OSError:
            pass
    try:
        process.wait(timeout=timeout_seconds)
    except (OSError, subprocess.SubprocessError):
        pass
    return False


def _linux_signal_pidfd(
    process_id: int,
    expected_identity: tuple[int, int, str, int],
    signal_number: int,
) -> bool:
    """Signal an exact Linux process identity without a PID-reuse window."""

    pidfd_open = getattr(os, "pidfd_open", None)
    pidfd_send_signal = getattr(signal, "pidfd_send_signal", None)
    if not callable(pidfd_open) or not callable(pidfd_send_signal):
        return False
    descriptor: int | None = None
    try:
        descriptor = int(pidfd_open(process_id, 0))
        if _linux_process_identity(process_id) != expected_identity:
            return False
        pidfd_send_signal(descriptor, signal_number, None, 0)
        return True
    except (OSError, TypeError, ValueError):
        return False
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _linux_process_identity(
    process_id: int, *, proc_root: Path = Path("/proc")
) -> tuple[int, int, str, int] | None:
    try:
        payload = (proc_root / str(process_id) / "stat").read_text(encoding="ascii")
    except (OSError, UnicodeError):
        return None
    close = payload.rfind(")")
    if close < 2 or close + 2 >= len(payload):
        return None
    fields = payload[close + 2 :].split()
    try:
        state = fields[0]
        group = int(fields[2])
        session = int(fields[3])
        start_time = int(fields[19])
    except (IndexError, TypeError, ValueError):
        return None
    # Linux exposes kernel-scoped 0 values and init-scoped 1 values in /proc.
    if len(state) != 1 or group < 0 or session < 0 or start_time < 0:
        return None
    return group, session, state, start_time


def _linux_private_session_members(
    group: int,
    session: int,
    *,
    proc_root: Path = Path("/proc"),
) -> set[int] | None:
    inventory = _linux_private_session_inventory(group, session, proc_root=proc_root)
    return None if inventory is None else set(inventory)


def _linux_private_session_inventory(
    group: int,
    session: int,
    *,
    proc_root: Path = Path("/proc"),
) -> dict[int, tuple[int, int, str, int]] | None:
    try:
        entries = tuple(proc_root.iterdir())
    except OSError:
        return None
    members: dict[int, tuple[int, int, str, int]] = {}
    for entry in entries:
        if not entry.name.isdecimal():
            continue
        process_id = int(entry.name)
        identity = _linux_process_identity(process_id, proc_root=proc_root)
        if identity is None:
            if not entry.exists():
                continue
            identity = _linux_process_identity(process_id, proc_root=proc_root)
            if identity is None:
                if entry.exists():
                    return None
                continue
        candidate_group, candidate_session, _state, _start_time = identity
        if candidate_group == group or candidate_session == session:
            members[process_id] = identity
    return members


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
