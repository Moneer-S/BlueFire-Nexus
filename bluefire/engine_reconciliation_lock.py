"""Crash-released, purpose-scoped locking for engine reconciliation.

The lock is keyed by the pinned ProductStore database identity rather than by a
mutable job or attempt pathname.  It is deliberately separate from SQLite and
from the action-catalog lease: POSIX uses a fixed namespace in the existing
owner-private identity-lock registry, while Windows locks a distinct byte past
SQLite's maximum database size.

Cancellation and deadlines apply only while waiting to enter a session.  Once
entered, the caller owns the session until its context exits; recovery code is
therefore free to keep the OS lock across external reconciliation and the final
short ProductStore settlement transaction.
"""

from __future__ import annotations

import errno
import math
import os
import stat
import sys
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

from . import local_lock as _local_lock
from .local_lock import DatabaseIdentity, LocalLockError
from .runner_trust import RunnerTrustError, _PinnedDirectory


class EngineReconciliationLockError(RuntimeError):
    """Raised when the reconciliation session cannot be acquired safely."""


_PURPOSE = "engine-reconciliation"
_WINDOWS_RECONCILIATION_LOCK_BYTE = (1 << 48) + 1
_POLL_SECONDS = 0.025


@dataclass
class _ReconciliationLockState:
    guard: threading.RLock = field(default_factory=threading.RLock)
    owner_pid: int | None = None
    owner_thread: int | None = None
    depth: int = 0
    descriptor: int | None = None


_STATES_GUARD = threading.Lock()
_STATES: dict[DatabaseIdentity, _ReconciliationLockState] = {}


def _before_fork() -> None:
    _STATES_GUARD.acquire()


def _after_fork_parent() -> None:
    _STATES_GUARD.release()


def _after_fork_child() -> None:
    # ``local_lock`` owns and closes the inherited descriptors.  Only discard
    # the copied Python ownership state here; a child must acquire a fresh OS
    # lock and must never treat a parent's session as reentrant.
    global _STATES
    global _STATES_GUARD

    _STATES = {}
    _STATES_GUARD = threading.Lock()


_register_at_fork = getattr(os, "register_at_fork", None)
if callable(_register_at_fork):
    _register_at_fork(
        before=_before_fork,
        after_in_parent=_after_fork_parent,
        after_in_child=_after_fork_child,
    )


def _valid_identity(identity: DatabaseIdentity) -> bool:
    return (
        isinstance(identity, tuple)
        and len(identity) == 2
        and all(
            isinstance(value, int) and not isinstance(value, bool) and value > 0
            for value in identity
        )
    )


def _state_for(identity: DatabaseIdentity) -> _ReconciliationLockState:
    with _STATES_GUARD:
        return _STATES.setdefault(identity, _ReconciliationLockState())


def _check_wait(cancel_event: threading.Event | None, deadline: float | None) -> None:
    if cancel_event is not None and cancel_event.is_set():
        raise EngineReconciliationLockError("Engine reconciliation lock wait was cancelled.")
    if deadline is not None and time.monotonic() >= deadline:
        raise EngineReconciliationLockError("Engine reconciliation lock admission expired.")


@contextmanager
def _thread_guard(
    state: _ReconciliationLockState,
    cancel_event: threading.Event | None,
    deadline: float | None,
) -> Iterator[None]:
    if cancel_event is None and deadline is None:
        with state.guard:
            yield
        return
    _check_wait(cancel_event, deadline)
    while not state.guard.acquire(timeout=_POLL_SECONDS):
        _check_wait(cancel_event, deadline)
    try:
        _check_wait(cancel_event, deadline)
        yield
    finally:
        state.guard.release()


def _purpose_lock_path(identity: DatabaseIdentity) -> Path:
    try:
        catalog_path = _local_lock._posix_identity_lock_path(identity)
        return catalog_path.with_name(f"{identity[0]:x}-{identity[1]:x}.{_PURPOSE}.lock")
    except LocalLockError as exc:
        raise EngineReconciliationLockError(
            "Engine reconciliation lock registry is unavailable or unsafe."
        ) from exc
    except (MemoryError, OSError, RunnerTrustError):
        raise EngineReconciliationLockError(
            "Engine reconciliation lock registry is unavailable or unsafe."
        ) from None


def _open_posix_purpose_descriptor(
    identity: DatabaseIdentity,
) -> tuple[int, Any]:
    path = _purpose_lock_path(identity)
    descriptor: int | None = None
    registration: Any = None
    created_identity: DatabaseIdentity | None = None
    try:
        with _PinnedDirectory(path.parent, private=True) as directory:
            try:
                created_identity = directory.create(path.name, b"")
            except RunnerTrustError:
                # Existing and concurrently created purpose locks are normal;
                # the pinned open below validates the exact entry independently.
                pass
        descriptor, lock_identity, registration = _local_lock._open_database_descriptor(
            path,
            expected=created_identity,
        )
        details = os.fstat(descriptor)
        getuid = getattr(os, "getuid", None)
        if (
            lock_identity != (int(details.st_dev), int(details.st_ino))
            or not stat.S_ISREG(details.st_mode)
            or details.st_nlink != 1
            or details.st_size != 0
            or stat.S_IMODE(details.st_mode) != 0o600
            or (callable(getuid) and details.st_uid != getuid())
        ):
            raise EngineReconciliationLockError(
                "Engine reconciliation identity lock is unavailable or unsafe."
            )
        return descriptor, registration
    except EngineReconciliationLockError:
        if descriptor is not None and registration is not None:
            _local_lock._close_database_descriptor(descriptor, registration)
        raise
    except (LocalLockError, MemoryError, OSError, RunnerTrustError):
        if descriptor is not None and registration is not None:
            _local_lock._close_database_descriptor(descriptor, registration)
        raise EngineReconciliationLockError(
            "Engine reconciliation identity lock is unavailable or unsafe."
        ) from None


def _lock_descriptor(
    descriptor: int,
    *,
    cancel_event: threading.Event | None,
    deadline: float | None,
) -> None:
    _check_wait(cancel_event, deadline)
    if sys.platform == "win32":
        import msvcrt

        os.lseek(descriptor, _WINDOWS_RECONCILIATION_LOCK_BYTE, os.SEEK_SET)
        retry_errors = {
            errno.EACCES,
            errno.EAGAIN,
            getattr(errno, "EDEADLK", errno.EACCES),
        }
        while True:
            _check_wait(cancel_event, deadline)
            try:
                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
                return
            except OSError as exc:
                if exc.errno not in retry_errors:
                    raise
                if cancel_event is None:
                    time.sleep(_POLL_SECONDS)
                else:
                    cancel_event.wait(_POLL_SECONDS)
    else:
        import fcntl

        if cancel_event is None and deadline is None:
            fcntl.flock(descriptor, fcntl.LOCK_EX)  # type: ignore[attr-defined]
            return
        while True:
            _check_wait(cancel_event, deadline)
            try:
                fcntl.flock(  # type: ignore[attr-defined]
                    descriptor,
                    fcntl.LOCK_EX | fcntl.LOCK_NB,
                )
                return
            except OSError as exc:
                if exc.errno not in {errno.EACCES, errno.EAGAIN}:
                    raise
                if cancel_event is None:
                    time.sleep(_POLL_SECONDS)
                else:
                    cancel_event.wait(_POLL_SECONDS)


def _unlock_descriptor(descriptor: int) -> None:
    try:
        if sys.platform == "win32":
            import msvcrt

            os.lseek(descriptor, _WINDOWS_RECONCILIATION_LOCK_BYTE, os.SEEK_SET)
            msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(descriptor, fcntl.LOCK_UN)  # type: ignore[attr-defined]
    except OSError:
        # Closing the exact descriptor releases the advisory lock on both
        # platforms; failure must not cause an unsafe second unlock attempt.
        pass


def _close_reconciliation_descriptor(
    descriptor: int,
    registration: Any,
    *,
    unlock: bool,
) -> bool:
    """Authenticate, unlock, and close one registered descriptor atomically.

    A context copied by ``fork`` may unwind after the child has reused the same
    numeric descriptor.  The allocation token and owner PID are therefore
    checked under the descriptor/fork guard before custom-byte unlock runs.
    """

    with _local_lock._DATABASE_FORK_GUARD:
        if getattr(registration, "owner_pid", None) != os.getpid():
            return False
        if _local_lock._DATABASE_DESCRIPTORS.get(descriptor) is not registration:
            return False
        try:
            if unlock:
                _unlock_descriptor(descriptor)
            os.close(descriptor)
        finally:
            if _local_lock._DATABASE_DESCRIPTORS.get(descriptor) is registration:
                del _local_lock._DATABASE_DESCRIPTORS[descriptor]
        return True


def _validate_locked_database(
    path: Path,
    descriptor: int,
    expected: DatabaseIdentity,
) -> None:
    try:
        _local_lock._validate_locked_database(path, descriptor, expected)
    except (LocalLockError, MemoryError, OSError, RunnerTrustError):
        raise EngineReconciliationLockError(
            "Pinned engine reconciliation database identity changed."
        ) from None


class EngineReconciliationLock:
    """One fixed-purpose lock over an exact ProductStore database identity."""

    def __init__(self, path: str | Path, *, expected: DatabaseIdentity) -> None:
        if not _valid_identity(expected):
            raise EngineReconciliationLockError(
                "Engine reconciliation database identity is invalid."
            )
        try:
            canonical = _local_lock._canonical_database_path(path)
            actual = _local_lock.pinned_regular_file_identity(
                canonical,
                expected=expected,
            )
        except (LocalLockError, MemoryError, OSError, RunnerTrustError):
            raise EngineReconciliationLockError(
                "Engine reconciliation database is unavailable or unsafe."
            ) from None
        if actual != expected:
            raise EngineReconciliationLockError("Engine reconciliation database identity changed.")
        self._path = canonical
        self._identity = expected

    @property
    def database_identity(self) -> DatabaseIdentity:
        """Return the pinned, non-secret database identity."""

        return self._identity

    @contextmanager
    def session(
        self,
        *,
        cancel_event: threading.Event | None = None,
        deadline: float | None = None,
    ) -> Iterator[None]:
        """Hold the reconciliation lock until the protected settlement exits.

        ``deadline`` is an absolute ``time.monotonic()`` deadline.  Cancellation
        and deadline expiry only interrupt contention; they never revoke a
        session after its body has started.
        """

        normalized_deadline: float | None = None
        if deadline is not None:
            if isinstance(deadline, bool) or not isinstance(deadline, (int, float)):
                raise EngineReconciliationLockError(
                    "Engine reconciliation lock deadline is invalid."
                )
            try:
                normalized_deadline = float(deadline)
            except (OverflowError, ValueError):
                raise EngineReconciliationLockError(
                    "Engine reconciliation lock deadline is invalid."
                ) from None
            if not math.isfinite(normalized_deadline):
                raise EngineReconciliationLockError(
                    "Engine reconciliation lock deadline is invalid."
                )
        _check_wait(cancel_event, normalized_deadline)

        database_descriptor: int | None = None
        database_registration: Any = None
        descriptor: int | None = None
        registration: Any = None
        locked = False
        try:
            try:
                database_descriptor, identity, database_registration = (
                    _local_lock._open_database_descriptor(
                        self._path,
                        expected=self._identity,
                    )
                )
            except (LocalLockError, MemoryError, OSError, RunnerTrustError):
                raise EngineReconciliationLockError(
                    "Engine reconciliation lock is unavailable or unsafe."
                ) from None

            state = _state_for(identity)
            with _thread_guard(state, cancel_event, normalized_deadline):
                process_id = os.getpid()
                thread_id = threading.get_ident()
                if state.owner_thread == thread_id:
                    if state.owner_pid != process_id or state.descriptor is None or state.depth < 1:
                        raise EngineReconciliationLockError(
                            "Engine reconciliation lock ownership is inconsistent."
                        )
                    _validate_locked_database(
                        self._path,
                        state.descriptor,
                        self._identity,
                    )
                    _local_lock._close_database_descriptor(
                        database_descriptor,
                        database_registration,
                    )
                    database_descriptor = None
                    database_registration = None
                    state.depth += 1
                    try:
                        _check_wait(cancel_event, normalized_deadline)
                        yield
                    finally:
                        state.depth -= 1
                    return

                if (
                    state.owner_pid is not None
                    or state.owner_thread is not None
                    or state.depth != 0
                    or state.descriptor is not None
                ):
                    raise EngineReconciliationLockError(
                        "Engine reconciliation lock ownership is inconsistent."
                    )

                if sys.platform == "win32":
                    descriptor = database_descriptor
                    registration = database_registration
                    database_descriptor = None
                    database_registration = None
                else:
                    _local_lock._close_database_descriptor(
                        database_descriptor,
                        database_registration,
                    )
                    database_descriptor = None
                    database_registration = None
                    descriptor, registration = _open_posix_purpose_descriptor(identity)

                try:
                    _lock_descriptor(
                        descriptor,
                        cancel_event=cancel_event,
                        deadline=normalized_deadline,
                    )
                    locked = True
                    _check_wait(cancel_event, normalized_deadline)
                    _validate_locked_database(
                        self._path,
                        descriptor,
                        self._identity,
                    )
                except EngineReconciliationLockError:
                    raise
                except (MemoryError, OSError, RunnerTrustError):
                    raise EngineReconciliationLockError(
                        "Engine reconciliation lock is unavailable or unsafe."
                    ) from None

                state.owner_pid = process_id
                state.owner_thread = thread_id
                state.depth = 1
                state.descriptor = descriptor
                try:
                    _check_wait(cancel_event, normalized_deadline)
                    yield
                finally:
                    state.depth = 0
                    state.owner_pid = None
                    state.owner_thread = None
                    state.descriptor = None
        finally:
            if database_descriptor is not None and database_registration is not None:
                _local_lock._close_database_descriptor(
                    database_descriptor,
                    database_registration,
                )
            if descriptor is not None and registration is not None:
                _close_reconciliation_descriptor(
                    descriptor,
                    registration,
                    unlock=locked,
                )


__all__ = [
    "EngineReconciliationLock",
    "EngineReconciliationLockError",
]
