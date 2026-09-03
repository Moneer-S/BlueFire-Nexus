"""Pinned, inode-bound locking for the local SQLite product database.

The database identity, rather than a sibling pathname, is the cooperative lock
authority.  On POSIX the OS lock lives in an owner-private runtime registry and
is named from the database device/inode pair.  That preserves contention after
a database move without colliding with SQLite's own advisory locks on macOS.
Windows uses a byte beyond SQLite's maximum database size on the pinned file.
"""

from __future__ import annotations

import errno
import os
import stat
import sys
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from .runner_trust import (
    RunnerTrustError,
    _is_link_or_reparse,
    _PinnedDirectory,
    _validate_windows_regular_information,
    _windows_close_handle,
    _windows_file_information,
    _windows_information_identity,
    _windows_open_pinned,
)


class LocalLockError(RuntimeError):
    """Raised when a pinned local database lock cannot be acquired safely."""


DatabaseIdentity = tuple[int, int]

# SQLite's absolute maximum database size is below 2**48 bytes.  Locking the
# first byte beyond that limit cannot overlap either database content or the
# Windows VFS lock range and does not extend the file.
_WINDOWS_DATABASE_LOCK_BYTE = 1 << 48
_MAX_DATABASE_BYTES = (1 << 63) - 1
_POSIX_LOCK_DIRECTORY_PREFIX = ".bluefire-database-locks-"
# The canonical root is pinned and validated before any lock entry is opened.
_POSIX_LOCK_PARENT = Path("/tmp")  # nosec B108


@dataclass
class _DatabaseLockState:
    guard: threading.RLock = field(default_factory=threading.RLock)
    owner_pid: int | None = None
    owner_thread: int | None = None
    depth: int = 0
    descriptor: int | None = None


@dataclass(frozen=True)
class _DatabaseDescriptorRegistration:
    """One process-local claim over an exact descriptor allocation."""

    owner_pid: int


_DATABASE_STATES_GUARD = threading.Lock()
_DATABASE_STATES: dict[DatabaseIdentity, _DatabaseLockState] = {}
_DATABASE_FORK_GUARD = threading.Lock()
_DATABASE_DESCRIPTORS: dict[int, _DatabaseDescriptorRegistration] = {}


def _before_fork() -> None:
    # Descriptor opens/closes use this same guard, so every descriptor inherited
    # by the child is already present in ``_DATABASE_DESCRIPTORS``.
    _DATABASE_FORK_GUARD.acquire()


def _after_fork_parent() -> None:
    _DATABASE_FORK_GUARD.release()


def _after_fork_child() -> None:
    """Discard inherited ownership without touching any inherited mutex.

    The parent's flock remains held because its descriptor still references the
    shared open-file description.  Closing only the child's duplicate prevents
    the child from extending that lock's lifetime or treating it as reentrant.
    All synchronization objects are replaced because another vanished thread
    may have owned any one of them when the fork occurred.
    """

    global _DATABASE_DESCRIPTORS
    global _DATABASE_FORK_GUARD
    global _DATABASE_STATES
    global _DATABASE_STATES_GUARD

    inherited_descriptors = set(_DATABASE_DESCRIPTORS)
    for state in _DATABASE_STATES.values():
        if state.descriptor is not None:
            inherited_descriptors.add(state.descriptor)

    _DATABASE_DESCRIPTORS = {}
    _DATABASE_STATES = {}
    _DATABASE_STATES_GUARD = threading.Lock()
    _DATABASE_FORK_GUARD = threading.Lock()
    for descriptor in inherited_descriptors:
        try:
            os.close(descriptor)
        except OSError:
            pass


_register_at_fork = getattr(os, "register_at_fork", None)
if callable(_register_at_fork):
    _register_at_fork(
        before=_before_fork,
        after_in_parent=_after_fork_parent,
        after_in_child=_after_fork_child,
    )


def _state_for(identity: DatabaseIdentity) -> _DatabaseLockState:
    with _DATABASE_STATES_GUARD:
        return _DATABASE_STATES.setdefault(identity, _DatabaseLockState())


def _has_stable_identity(identity: DatabaseIdentity) -> bool:
    return len(identity) == 2 and all(isinstance(value, int) and value > 0 for value in identity)


def _canonical_database_path(path: str | Path) -> Path:
    candidate = Path(path).expanduser()
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    candidate = Path(os.path.abspath(candidate))
    try:
        parent = candidate.parent.resolve(strict=True)
    except OSError:
        raise LocalLockError("Local database parent is unavailable.") from None
    if (
        os.path.normcase(str(parent)) != os.path.normcase(str(candidate.parent))
        or _is_link_or_reparse(candidate.parent)
        or not parent.is_dir()
        or not candidate.name
        or candidate.name in {".", ".."}
    ):
        raise LocalLockError("Local database parent is unavailable or unsafe.")
    return parent / candidate.name


def _validate_posix_database_descriptor(
    descriptor: int,
    *,
    expected: DatabaseIdentity | None,
) -> DatabaseIdentity:
    details = os.fstat(descriptor)
    identity = int(details.st_dev), int(details.st_ino)
    getuid = getattr(os, "getuid", None)
    if (
        not stat.S_ISREG(details.st_mode)
        or details.st_nlink != 1
        or not _has_stable_identity(identity)
        or (callable(getuid) and details.st_uid != getuid())
        or (expected is not None and identity != expected)
    ):
        raise LocalLockError("Pinned local database is unavailable or unsafe.")
    return identity


def _open_posix_database_descriptor(
    path: Path,
    *,
    expected: DatabaseIdentity | None,
) -> tuple[int, DatabaseIdentity]:
    parent_descriptor: int | None = None
    descriptor: int | None = None
    try:
        parent_descriptor = os.open(
            path.parent,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        parent_details = os.fstat(parent_descriptor)
        if not stat.S_ISDIR(parent_details.st_mode):
            raise LocalLockError("Local database parent is unavailable or unsafe.")
        descriptor = os.open(
            path.name,
            os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_descriptor,
        )
        identity = _validate_posix_database_descriptor(descriptor, expected=expected)
        current = os.stat(path.name, dir_fd=parent_descriptor, follow_symlinks=False)
        current_parent = path.parent.lstat()
        if (
            _is_link_or_reparse(path)
            or _is_link_or_reparse(path.parent)
            or not stat.S_ISREG(current.st_mode)
            or current.st_nlink != 1
            or (int(current.st_dev), int(current.st_ino)) != identity
            or not stat.S_ISDIR(current_parent.st_mode)
            or (int(current_parent.st_dev), int(current_parent.st_ino))
            != (int(parent_details.st_dev), int(parent_details.st_ino))
        ):
            raise LocalLockError("Pinned local database changed while it was opened.")
        return descriptor, identity
    except LocalLockError:
        if descriptor is not None:
            os.close(descriptor)
        raise
    except (MemoryError, OSError):
        if descriptor is not None:
            os.close(descriptor)
        raise LocalLockError("Pinned local database is unavailable or unsafe.") from None
    finally:
        if parent_descriptor is not None:
            os.close(parent_descriptor)


def _open_windows_database_descriptor(
    path: Path,
    *,
    expected: DatabaseIdentity | None,
) -> tuple[int, DatabaseIdentity]:
    if sys.platform != "win32":
        raise LocalLockError("Pinned local database is unavailable or unsafe.")
    handle = -1
    try:
        handle = _windows_open_pinned(
            path,
            directory=False,
            delete=False,
            write=True,
        )
        information = _validate_windows_regular_information(
            _windows_file_information(handle),
            maximum=_MAX_DATABASE_BYTES,
        )
        identity = _windows_information_identity(information)
        if (
            not _has_stable_identity(identity)
            or _is_link_or_reparse(path)
            or (expected is not None and identity != expected)
        ):
            raise LocalLockError("Pinned local database is unavailable or unsafe.")
        import msvcrt

        descriptor = msvcrt.open_osfhandle(
            handle,
            os.O_RDWR | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0),
        )
        handle = -1
        return descriptor, identity
    except LocalLockError:
        raise
    except (MemoryError, OSError, RunnerTrustError):
        raise LocalLockError("Pinned local database is unavailable or unsafe.") from None
    finally:
        if handle != -1:
            _windows_close_handle(handle)


def _open_database_descriptor(
    path: Path,
    *,
    expected: DatabaseIdentity | None,
) -> tuple[int, DatabaseIdentity, _DatabaseDescriptorRegistration]:
    # The fork prepare callback acquires this guard.  Therefore no fork can
    # occur after the OS opens a descriptor but before the descriptor becomes
    # visible to the child-reset callback.
    with _DATABASE_FORK_GUARD:
        if sys.platform == "win32":
            descriptor, identity = _open_windows_database_descriptor(path, expected=expected)
        else:
            descriptor, identity = _open_posix_database_descriptor(path, expected=expected)
        registration = _DatabaseDescriptorRegistration(owner_pid=os.getpid())
        try:
            _DATABASE_DESCRIPTORS[descriptor] = registration
        except BaseException:
            os.close(descriptor)
            raise
        return descriptor, identity, registration


def _canonical_posix_lock_parent() -> Path:
    """Pin the environment-independent system temporary directory."""

    getuid = getattr(os, "getuid", None)
    if not callable(getuid):
        raise LocalLockError("Local database lock identity is unavailable.")
    try:
        parent = _POSIX_LOCK_PARENT.resolve(strict=True)
        if not parent.is_absolute() or _is_link_or_reparse(parent):
            raise LocalLockError("Local database lock registry is unavailable or unsafe.")
        with _PinnedDirectory(parent, private=False) as directory:
            details = parent.lstat()
            identity = int(details.st_dev), int(details.st_ino)
            mode = stat.S_IMODE(details.st_mode)
            if (
                not stat.S_ISDIR(details.st_mode)
                or not _has_stable_identity(identity)
                or identity != directory.identity
                or details.st_uid not in {0, getuid()}
                or (mode & (stat.S_IWGRP | stat.S_IWOTH) and not mode & stat.S_ISVTX)
            ):
                raise LocalLockError("Local database lock registry is unavailable or unsafe.")
        return parent
    except LocalLockError:
        raise
    except (MemoryError, OSError, RunnerTrustError):
        raise LocalLockError("Local database lock registry is unavailable or unsafe.") from None


def _posix_identity_lock_path(identity: DatabaseIdentity) -> Path:
    getuid = getattr(os, "getuid", None)
    if not callable(getuid):
        raise LocalLockError("Local database lock identity is unavailable.")
    try:
        parent = _canonical_posix_lock_parent()
        root = parent / f"{_POSIX_LOCK_DIRECTORY_PREFIX}{getuid()}"
        try:
            root.mkdir(mode=0o700)
        except FileExistsError:
            pass
        with _PinnedDirectory(root, private=True) as directory:
            details = root.lstat()
            root_identity = int(details.st_dev), int(details.st_ino)
            if (
                _is_link_or_reparse(root)
                or not stat.S_ISDIR(details.st_mode)
                or not _has_stable_identity(root_identity)
                or root_identity != directory.identity
                or details.st_uid != getuid()
                or stat.S_IMODE(details.st_mode) != 0o700
            ):
                raise LocalLockError("Local database lock registry is unavailable or unsafe.")
        return root / f"{identity[0]:x}-{identity[1]:x}.lock"
    except LocalLockError:
        raise
    except (MemoryError, OSError, RunnerTrustError):
        raise LocalLockError("Local database lock registry is unavailable or unsafe.") from None


def _open_posix_identity_lock_descriptor(identity: DatabaseIdentity) -> int:
    path = _posix_identity_lock_path(identity)
    descriptor: int | None = None
    created_identity: DatabaseIdentity | None = None
    try:
        with _PinnedDirectory(path.parent, private=True) as directory:
            try:
                created_identity = directory.create(path.name, b"")
            except RunnerTrustError:
                # Existing and concurrently created identity locks are normal.
                # The pinned open independently validates the exact entry.
                pass
        descriptor, _lock_identity = _open_posix_database_descriptor(
            path,
            expected=created_identity,
        )
        details = os.fstat(descriptor)
        getuid = getattr(os, "getuid", None)
        if (
            details.st_size != 0
            or stat.S_IMODE(details.st_mode) != 0o600
            or (callable(getuid) and details.st_uid != getuid())
        ):
            raise LocalLockError("Local database identity lock is unavailable or unsafe.")
        return descriptor
    except LocalLockError:
        if descriptor is not None:
            os.close(descriptor)
        raise
    except (MemoryError, OSError, RunnerTrustError):
        if descriptor is not None:
            os.close(descriptor)
        raise LocalLockError("Local database identity lock is unavailable or unsafe.") from None


def _open_registered_posix_identity_lock_descriptor(
    identity: DatabaseIdentity,
) -> tuple[int, _DatabaseDescriptorRegistration]:
    with _DATABASE_FORK_GUARD:
        descriptor = _open_posix_identity_lock_descriptor(identity)
        registration = _DatabaseDescriptorRegistration(owner_pid=os.getpid())
        try:
            _DATABASE_DESCRIPTORS[descriptor] = registration
        except BaseException:
            os.close(descriptor)
            raise
        return descriptor, registration


def _close_database_descriptor(
    descriptor: int,
    registration: _DatabaseDescriptorRegistration,
    *,
    unlock: bool = False,
) -> bool:
    # Removal and close are atomic with respect to the fork prepare callback;
    # the child can never inherit an untracked database descriptor.  Both the
    # PID and allocation token must match: a context copied by fork must never
    # close a descriptor number that the child has since reused.
    with _DATABASE_FORK_GUARD:
        if registration.owner_pid != os.getpid():
            return False
        if _DATABASE_DESCRIPTORS.get(descriptor) is not registration:
            return False
        try:
            if unlock:
                _unlock_database_descriptor(descriptor)
            os.close(descriptor)
        finally:
            if _DATABASE_DESCRIPTORS.get(descriptor) is registration:
                del _DATABASE_DESCRIPTORS[descriptor]
        return True


def prepare_owner_private_database_file(
    path: str | Path,
) -> tuple[Path, DatabaseIdentity]:
    """Exclusively create a missing database, then return its pinned identity."""

    canonical = _canonical_database_path(path)
    created_identity: DatabaseIdentity | None = None
    try:
        for attempt in range(40):
            try:
                with _PinnedDirectory(canonical.parent, private=False) as directory:
                    if canonical.name not in set(directory.names()):
                        try:
                            created_identity = directory.create(canonical.name, b"")
                        except RunnerTrustError:
                            # A concurrent creator may have won the exclusive create.
                            if canonical.name not in set(directory.names()):
                                raise
                descriptor, identity, registration = _open_database_descriptor(
                    canonical,
                    expected=created_identity,
                )
                _close_database_descriptor(descriptor, registration)
                return canonical, identity
            except LocalLockError:
                if attempt == 39:
                    raise
                # Windows may briefly deny the pinned open while the winning
                # exclusive creator closes its no-delete-share handle.
                time.sleep(0.025)
        raise LocalLockError("Local database could not be pinned safely.")
    except LocalLockError:
        raise
    except (MemoryError, OSError, RunnerTrustError):
        raise LocalLockError("Local database could not be created or pinned safely.") from None


def pinned_regular_file_identity(
    path: str | Path,
    *,
    expected: DatabaseIdentity | None = None,
) -> DatabaseIdentity:
    """Open without following links and return one exact database identity."""

    canonical = _canonical_database_path(path)
    descriptor, identity, registration = _open_database_descriptor(canonical, expected=expected)
    _close_database_descriptor(descriptor, registration)
    return identity


def _lock_database_descriptor(descriptor: int) -> None:
    if sys.platform == "win32":
        import msvcrt

        os.lseek(descriptor, _WINDOWS_DATABASE_LOCK_BYTE, os.SEEK_SET)
        retry_errors = {
            errno.EACCES,
            errno.EAGAIN,
            getattr(errno, "EDEADLK", errno.EACCES),
        }
        while True:
            try:
                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
                return
            except OSError as exc:
                if exc.errno not in retry_errors:
                    raise
                time.sleep(0.025)
    else:
        import fcntl

        fcntl.flock(descriptor, fcntl.LOCK_EX)  # type: ignore[attr-defined]


def _unlock_database_descriptor(descriptor: int) -> None:
    try:
        if sys.platform == "win32":
            import msvcrt

            os.lseek(descriptor, _WINDOWS_DATABASE_LOCK_BYTE, os.SEEK_SET)
            msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(descriptor, fcntl.LOCK_UN)  # type: ignore[attr-defined]
    except OSError:
        # Closing the descriptor releases the advisory lock on both platforms.
        pass


def _validate_locked_database(
    path: Path,
    descriptor: int,
    expected: DatabaseIdentity,
) -> None:
    if sys.platform == "win32":
        import msvcrt

        information = _validate_windows_regular_information(
            _windows_file_information(msvcrt.get_osfhandle(descriptor)),
            maximum=_MAX_DATABASE_BYTES,
        )
        if _windows_information_identity(information) != expected:
            raise LocalLockError("Pinned local database identity changed.")
    else:
        lock_details = os.fstat(descriptor)
        getuid = getattr(os, "getuid", None)
        if (
            not stat.S_ISREG(lock_details.st_mode)
            or lock_details.st_nlink != 1
            or lock_details.st_size != 0
            or stat.S_IMODE(lock_details.st_mode) != 0o600
            or (callable(getuid) and lock_details.st_uid != getuid())
        ):
            raise LocalLockError("Pinned local database lock changed.")

    verification, identity, registration = _open_database_descriptor(path, expected=expected)
    _close_database_descriptor(verification, registration)
    if identity != expected:
        raise LocalLockError("Pinned local database identity changed.")


@contextmanager
def owner_private_database_lock(
    path: str | Path,
    *,
    expected: DatabaseIdentity,
) -> Iterator[None]:
    """Hold the exact database identity lock across a catalog transition/effect."""

    canonical = _canonical_database_path(path)
    database_descriptor: int | None = None
    database_registration: _DatabaseDescriptorRegistration | None = None
    descriptor: int | None = None
    registration: _DatabaseDescriptorRegistration | None = None
    locked = False
    try:
        try:
            database_descriptor, identity, database_registration = _open_database_descriptor(
                canonical,
                expected=expected,
            )
        except LocalLockError:
            raise
        except (MemoryError, OSError, RunnerTrustError):
            raise LocalLockError("Local database lock is unavailable or unsafe.") from None
        state = _state_for(identity)
        with state.guard:
            process_id = os.getpid()
            thread_id = threading.get_ident()
            if state.owner_thread == thread_id:
                try:
                    if state.owner_pid != process_id or state.descriptor is None or state.depth < 1:
                        raise LocalLockError("Local database lock ownership is inconsistent.")
                    _validate_locked_database(canonical, state.descriptor, expected)
                    _close_database_descriptor(database_descriptor, database_registration)
                except LocalLockError:
                    raise
                except (MemoryError, OSError, RunnerTrustError):
                    raise LocalLockError("Local database lock is unavailable or unsafe.") from None
                database_descriptor = None
                database_registration = None
                state.depth += 1
                try:
                    yield
                finally:
                    state.depth -= 1
                return
            try:
                if (
                    state.owner_pid is not None
                    or state.owner_thread is not None
                    or state.depth != 0
                    or state.descriptor is not None
                ):
                    raise LocalLockError("Local database lock ownership is inconsistent.")

                if sys.platform == "win32":
                    descriptor = database_descriptor
                    registration = database_registration
                    database_descriptor = None
                    database_registration = None
                else:
                    _close_database_descriptor(database_descriptor, database_registration)
                    database_descriptor = None
                    database_registration = None
                    descriptor, registration = _open_registered_posix_identity_lock_descriptor(
                        identity
                    )

                _lock_database_descriptor(descriptor)
                locked = True
                _validate_locked_database(canonical, descriptor, expected)
            except LocalLockError:
                raise
            except (MemoryError, OSError, RunnerTrustError):
                raise LocalLockError("Local database lock is unavailable or unsafe.") from None
            state.owner_pid = process_id
            state.owner_thread = thread_id
            state.depth = 1
            state.descriptor = descriptor
            try:
                yield
            finally:
                state.depth = 0
                state.owner_pid = None
                state.owner_thread = None
                state.descriptor = None
    finally:
        if database_descriptor is not None and database_registration is not None:
            _close_database_descriptor(database_descriptor, database_registration)
        if descriptor is not None and registration is not None:
            _close_database_descriptor(descriptor, registration, unlock=locked)


__all__ = [
    "DatabaseIdentity",
    "LocalLockError",
    "owner_private_database_lock",
    "pinned_regular_file_identity",
    "prepare_owner_private_database_file",
]
