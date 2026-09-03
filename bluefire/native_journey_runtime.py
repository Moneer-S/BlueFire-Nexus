"""Pinned runtime and result-journal lifecycle for native acceptance journeys."""

from __future__ import annotations

import os
import re
import stat
import tempfile
import time
from functools import partial
from pathlib import Path
from typing import Callable, Sequence, TypeVar

from .runner_private_files import _PinnedPrivateDirectory, _PrivateFileCleanupError
from .runner_transport_errors import RunnerTransportError

_TASK_RESULT = re.compile(r"^execute-[0-9a-f]{64}\.json$")
_MAX_REPORT_BYTES = 8 * 1024 * 1024
_MAX_SCAN_BYTES = 128 * 1024 * 1024
_CLEANUP_ATTEMPTS = 10
_CLEANUP_RETRY_SECONDS = 0.25
_CLEANUP_WINDOW_SECONDS = _CLEANUP_ATTEMPTS * _CLEANUP_RETRY_SECONDS
_CLEANUP_DEADLINE_MESSAGE = "the native cleanup exceeded its monotonic deadline"
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_MAX_RUNTIME_CLEANUP_DEPTH = 32
_MAX_RUNTIME_CLEANUP_ENTRIES = 16_384
_MAX_JOURNAL_ENTRIES = 256
_CleanupResult = TypeVar("_CleanupResult")


class DefenseFrontierError(ValueError):
    """Raised when a native acceptance journey cannot be proven safely."""


class _RuntimeCleanupError(DefenseFrontierError):
    """Retains every non-recoverable failure from bounded runtime cleanup."""

    def __init__(self, failures: Sequence[BaseException]) -> None:
        self.failures = tuple(failures)
        super().__init__("the BlueFire journey had multiple execution or cleanup failures")


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise DefenseFrontierError(message)


def _extend_cleanup_failures(
    failures: list[BaseException],
    failure: BaseException,
) -> None:
    if isinstance(failure, (_RuntimeCleanupError, _PrivateFileCleanupError)):
        for nested in failure.failures:
            _extend_cleanup_failures(failures, nested)
    else:
        failures.append(failure)


def _raise_cleanup_failures(failures: Sequence[BaseException]) -> None:
    if len(failures) == 1:
        raise failures[0]
    if failures:
        raise _RuntimeCleanupError(failures) from failures[0]


def _retry_cleanup(
    operation: Callable[[], _CleanupResult],
    message: str,
    *,
    deadline: float | None = None,
) -> _CleanupResult:
    """Retry a pinned cleanup operation without converting disappearance to success."""

    last_error: OSError | RunnerTransportError | None = None
    for attempt in range(_CLEANUP_ATTEMPTS):
        if deadline is not None and time.monotonic() >= deadline:
            break
        try:
            return operation()
        except _PrivateFileCleanupError:
            raise
        except (OSError, RunnerTransportError) as exc:
            last_error = exc
            if attempt + 1 < _CLEANUP_ATTEMPTS:
                if deadline is None:
                    time.sleep(_CLEANUP_RETRY_SECONDS)
                    continue
                now = time.monotonic()
                if now >= deadline:
                    break
                time.sleep(min(_CLEANUP_RETRY_SECONDS, deadline - now))
    if deadline is not None and time.monotonic() >= deadline:
        raise DefenseFrontierError(_CLEANUP_DEADLINE_MESSAGE) from last_error
    raise DefenseFrontierError(message) from last_error


def _is_windows_delete_pending_identity(identity: tuple[int, int]) -> bool:
    """Recognize Win32 metadata for a name whose final handle is still closing."""

    return os.name == "nt" and identity == (0, 0)


def _wait_for_pinned_name_absent(
    directory: _PinnedPrivateDirectory,
    name: str,
    *,
    expected_identity: tuple[int, int],
    expected_mount_identity: int | None,
    deadline: float,
    rebound_message: str,
    absence_message: str,
) -> None:
    """Wait for one removed child name to become terminally absent."""

    last_error: OSError | RunnerTransportError | None = None
    for attempt in range(_CLEANUP_ATTEMPTS):
        try:
            if not directory.has_name(name):
                return
            details, mount_identity = directory.entry_metadata_with_mount_identity(name)
        except FileNotFoundError:
            return
        except _PrivateFileCleanupError:
            raise
        except (OSError, RunnerTransportError) as exc:
            last_error = exc
        else:
            identity = int(details.st_dev), int(details.st_ino)
            delete_pending = os.name == "nt" and (
                identity == expected_identity or _is_windows_delete_pending_identity(identity)
            )
            if (
                stat.S_ISLNK(details.st_mode)
                or int(getattr(details, "st_file_attributes", 0)) & _REPARSE_POINT
                or mount_identity != expected_mount_identity
                or not delete_pending
            ):
                raise DefenseFrontierError(rebound_message)
            last_error = None
        now = time.monotonic()
        if attempt + 1 >= _CLEANUP_ATTEMPTS or now >= deadline:
            break
        time.sleep(min(_CLEANUP_RETRY_SECONDS, deadline - now))
    raise DefenseFrontierError(absence_message) from last_error


def _wait_for_path_absent(
    path: Path,
    *,
    expected_identity: tuple[int, int],
    deadline: float,
    rebound_message: str,
    absence_message: str,
) -> None:
    """Wait for a just-unpinned owned path to become terminally absent."""

    last_error: OSError | None = None
    for attempt in range(_CLEANUP_ATTEMPTS):
        try:
            details = path.lstat()
        except FileNotFoundError:
            return
        except OSError as exc:
            last_error = exc
        else:
            identity = int(details.st_dev), int(details.st_ino)
            delete_pending = os.name == "nt" and (
                identity == expected_identity or _is_windows_delete_pending_identity(identity)
            )
            if (
                stat.S_ISLNK(details.st_mode)
                or int(getattr(details, "st_file_attributes", 0)) & _REPARSE_POINT
                or not delete_pending
            ):
                raise DefenseFrontierError(rebound_message)
            last_error = None
        now = time.monotonic()
        if attempt + 1 >= _CLEANUP_ATTEMPTS or now >= deadline:
            break
        time.sleep(min(_CLEANUP_RETRY_SECONDS, deadline - now))
    raise DefenseFrontierError(absence_message) from last_error


def _safe_directory_details(path: Path, message: str) -> os.stat_result:
    details = _retry_cleanup(path.lstat, message)
    _require(
        stat.S_ISDIR(details.st_mode)
        and not stat.S_ISLNK(details.st_mode)
        and not int(getattr(details, "st_file_attributes", 0)) & _REPARSE_POINT,
        message,
    )
    return details


def _pin_owned_directory(path: Path, message: str) -> _PinnedPrivateDirectory:
    details = _safe_directory_details(path, message)
    expected_identity = int(details.st_dev), int(details.st_ino)

    def open_exact() -> _PinnedPrivateDirectory:
        pinned = _PinnedPrivateDirectory(
            path,
            delete=True,
            expected_identity=expected_identity,
        )
        try:
            return pinned.__enter__()
        except BaseException as exc:
            failures = [exc]
            try:
                pinned.close()
            except BaseException as close_exc:
                _extend_cleanup_failures(failures, close_exc)
            _raise_cleanup_failures(failures)
            raise AssertionError("unreachable") from exc

    pinned = _retry_cleanup(open_exact, message)
    try:
        if pinned.directory_mount_identity() != pinned.parent_mount_identity():
            raise DefenseFrontierError(f"{message}: mounted directory boundary")
        return pinned
    except BaseException as exc:
        failures = [exc]
        try:
            pinned.close()
        except BaseException as close_exc:
            _extend_cleanup_failures(failures, close_exc)
        _raise_cleanup_failures(failures)
        raise AssertionError("unreachable") from exc


def _pin_runtime_directory(runtime: Path) -> _PinnedPrivateDirectory:
    """Bind the exact newly created native runtime until verified removal."""

    return _pin_owned_directory(runtime, "the native runtime is unavailable or unsafe")


def _create_pinned_runtime(
    prefix: str,
    runtime_parent: Callable[[], Path],
) -> tuple[Path, _PinnedPrivateDirectory]:
    """Create a random runtime below a pinned parent and immediately bind it."""

    parent_path = runtime_parent()
    parent = _PinnedPrivateDirectory(parent_path)
    runtime: Path | None = None
    guard: _PinnedPrivateDirectory | None = None
    result: tuple[Path, _PinnedPrivateDirectory] | None = None
    failures: list[BaseException] = []
    try:
        _retry_cleanup(
            parent.__enter__,
            "the native runtime parent is unavailable or unsafe",
        )
        runtime = Path(tempfile.mkdtemp(prefix=prefix, dir=parent.path))
        details, mount_identity = _retry_cleanup(
            partial(parent.entry_metadata_with_mount_identity, runtime.name),
            "the native runtime identity is unavailable",
        )
        _require(
            stat.S_ISDIR(details.st_mode)
            and not stat.S_ISLNK(details.st_mode)
            and not int(getattr(details, "st_file_attributes", 0)) & _REPARSE_POINT
            and mount_identity == parent.directory_mount_identity(),
            "the native runtime identity is unsafe",
        )
        guard = _PinnedPrivateDirectory(
            runtime,
            delete=True,
            expected_identity=(int(details.st_dev), int(details.st_ino)),
            expected_mount_identity=mount_identity,
            parent=parent,
        )
        _retry_cleanup(
            guard.__enter__,
            "the native runtime could not be pinned after creation",
        )
        result = runtime, guard
    except BaseException as exc:
        _extend_cleanup_failures(failures, exc)
    try:
        parent.close()
    except BaseException as exc:
        _extend_cleanup_failures(failures, exc)
    if failures and guard is not None:
        try:
            guard.close()
        except BaseException as exc:
            _extend_cleanup_failures(failures, exc)
    _raise_cleanup_failures(failures)
    if result is None:
        raise AssertionError("native runtime creation returned no result")
    return result


def _create_pinned_runner_journal(runs_dir: Path) -> _PinnedPrivateDirectory:
    """Precreate and pin the exact result journal for one native journey."""

    parent = _PinnedPrivateDirectory(runs_dir)
    journal = runs_dir / ".bluefire-runner-results"
    pinned: _PinnedPrivateDirectory | None = None
    failures: list[BaseException] = []
    try:
        _retry_cleanup(
            parent.__enter__,
            "runner result parent is unavailable or unsafe",
        )
        _require(
            not parent.has_name(journal.name),
            "runner result journal already exists",
        )
        journal_identity, mount_identity = parent.create_directory(journal.name)
        details, observed_mount_identity = parent.entry_metadata_with_mount_identity(journal.name)
        _require(
            stat.S_ISDIR(details.st_mode)
            and (int(details.st_dev), int(details.st_ino)) == journal_identity
            and observed_mount_identity == mount_identity == parent.directory_mount_identity(),
            "runner result journal is unavailable or unsafe",
        )
        pinned = _PinnedPrivateDirectory(
            journal,
            delete=False,
            expected_identity=journal_identity,
            expected_mount_identity=mount_identity,
            parent=parent,
        )
        _retry_cleanup(
            pinned.__enter__,
            "runner result journal could not be pinned after creation",
        )
    except BaseException as exc:
        _extend_cleanup_failures(failures, exc)
    try:
        parent.close()
    except BaseException as exc:
        _extend_cleanup_failures(failures, exc)
    if failures and pinned is not None:
        try:
            pinned.close()
        except BaseException as exc:
            _extend_cleanup_failures(failures, exc)
    if len(failures) == 1 and isinstance(failures[0], OSError):
        raise DefenseFrontierError(
            "runner result journal could not be created safely"
        ) from failures[0]
    _raise_cleanup_failures(failures)
    if pinned is None:
        raise AssertionError("runner journal creation returned no guard")
    return pinned


def _remove_pinned_tree(
    directory: _PinnedPrivateDirectory,
    *,
    root_device: int | None = None,
    root_mount_identity: int | None = None,
    depth: int = 0,
    budget: list[int] | None = None,
    deadline: float | None = None,
) -> None:
    """Remove only entries proven to belong to one continuously pinned tree."""

    if depth > _MAX_RUNTIME_CLEANUP_DEPTH:
        raise DefenseFrontierError("the native runtime cleanup depth bound was exceeded")
    if budget is None:
        budget = [_MAX_RUNTIME_CLEANUP_ENTRIES]
    if deadline is None:
        deadline = time.monotonic() + _CLEANUP_WINDOW_SECONDS
    current_identity = _retry_cleanup(
        directory.directory_identity,
        "the native runtime directory identity changed during cleanup",
        deadline=deadline,
    )
    if root_device is None:
        root_device = current_identity[0]
    current_mount_identity = _retry_cleanup(
        directory.directory_mount_identity,
        "the native runtime mount identity changed during cleanup",
        deadline=deadline,
    )
    if root_mount_identity is None:
        root_mount_identity = current_mount_identity
    if current_mount_identity != root_mount_identity:
        raise DefenseFrontierError("the native runtime crossed a mounted directory boundary")
    names = sorted(
        _retry_cleanup(
            lambda: directory.names(maximum=budget[0]),
            "the native runtime could not be enumerated safely",
            deadline=deadline,
        )
    )
    for name in names:
        if budget[0] <= 0:
            raise DefenseFrontierError("the native runtime cleanup entry bound was exceeded")
        budget[0] -= 1
        details, mount_identity = _retry_cleanup(
            partial(directory.entry_metadata_with_mount_identity, name),
            "a native runtime entry disappeared before validation",
            deadline=deadline,
        )
        attributes = int(getattr(details, "st_file_attributes", 0))
        if (
            stat.S_ISLNK(details.st_mode)
            or attributes & _REPARSE_POINT
            or int(details.st_dev) != root_device
            or mount_identity != root_mount_identity
        ):
            raise DefenseFrontierError("the native runtime contains an unsafe entry")
        identity = int(details.st_dev), int(details.st_ino)
        if stat.S_ISREG(details.st_mode):
            if details.st_nlink != 1 or not 0 <= details.st_size <= _MAX_SCAN_BYTES:
                raise DefenseFrontierError("the native runtime contains an unsafe file")
            _retry_cleanup(
                partial(
                    directory.unlink,
                    name,
                    maximum=_MAX_SCAN_BYTES,
                    expected_identity=identity,
                    expected_mount_identity=root_mount_identity,
                ),
                "a native runtime file could not be removed exactly",
                deadline=deadline,
            )
            _wait_for_pinned_name_absent(
                directory,
                name,
                expected_identity=identity,
                expected_mount_identity=root_mount_identity,
                deadline=deadline,
                rebound_message="a native runtime file path was rebound during cleanup",
                absence_message="a native runtime file absence could not be verified",
            )
            continue
        if not stat.S_ISDIR(details.st_mode):
            raise DefenseFrontierError("the native runtime contains a special entry")

        def open_child(
            name: str = name, identity: tuple[int, int] = identity
        ) -> _PinnedPrivateDirectory:
            child = _PinnedPrivateDirectory(
                directory.path / name,
                delete=True,
                expected_identity=identity,
                expected_mount_identity=root_mount_identity,
                parent=directory,
            )
            try:
                return child.__enter__()
            except BaseException as exc:
                failures = [exc]
                try:
                    child.close()
                except BaseException as close_exc:
                    _extend_cleanup_failures(failures, close_exc)
                _raise_cleanup_failures(failures)
                raise AssertionError("unreachable") from exc

        child = _retry_cleanup(
            open_child,
            "a native runtime directory disappeared before it could be pinned",
            deadline=deadline,
        )
        child_failures: list[BaseException] = []
        try:
            _remove_pinned_tree(
                child,
                root_device=root_device,
                root_mount_identity=root_mount_identity,
                depth=depth + 1,
                budget=budget,
                deadline=deadline,
            )
        except BaseException as exc:
            _extend_cleanup_failures(child_failures, exc)
        try:
            child.close()
        except BaseException as exc:
            _extend_cleanup_failures(child_failures, exc)
        _raise_cleanup_failures(child_failures)
        _wait_for_pinned_name_absent(
            directory,
            name,
            expected_identity=identity,
            expected_mount_identity=root_mount_identity,
            deadline=deadline,
            rebound_message="a native runtime directory path was rebound during cleanup",
            absence_message="a native runtime directory absence could not be verified",
        )
    _retry_cleanup(
        directory.remove,
        "the native runtime directory could not be removed exactly",
        deadline=deadline,
    )


def _close_runtime_and_remove(
    runtime: Path,
    runtime_guard: _PinnedPrivateDirectory,
    close_service: Callable[[], None],
    *,
    remove_tree: Callable[[_PinnedPrivateDirectory, float], None] | None = None,
) -> None:
    """Close the service and remove only the continuously pinned runtime."""

    failures: list[BaseException] = []
    service_closed = False
    shutdown_failure: BaseException | None = None
    for attempt in range(_CLEANUP_ATTEMPTS):
        try:
            close_service()
            service_closed = True
            break
        except BaseException as exc:
            if shutdown_failure is None:
                shutdown_failure = exc
            if attempt + 1 < _CLEANUP_ATTEMPTS:
                time.sleep(_CLEANUP_RETRY_SECONDS)
    if not service_closed:
        failures.append(
            shutdown_failure or DefenseFrontierError("the BlueFire native service did not close")
        )

    cleanup_completed = False
    cleanup_failures: list[BaseException] = []
    runtime_identity: tuple[int, int] | None = None
    cleanup_deadline = time.monotonic() + _CLEANUP_WINDOW_SECONDS
    try:
        if runtime_guard.path != runtime:
            raise DefenseFrontierError("the native runtime cleanup guard is mismatched")
        runtime_identity = _retry_cleanup(
            runtime_guard.directory_identity,
            "the native runtime identity could not be verified before cleanup",
            deadline=cleanup_deadline,
        )
        if remove_tree is None:
            _remove_pinned_tree(runtime_guard, deadline=cleanup_deadline)
        else:
            remove_tree(runtime_guard, cleanup_deadline)
        cleanup_completed = True
    except BaseException as exc:
        _extend_cleanup_failures(cleanup_failures, exc)
    try:
        runtime_guard.close()
    except BaseException as exc:
        _extend_cleanup_failures(cleanup_failures, exc)

    if cleanup_completed and runtime_identity is not None:
        try:
            _wait_for_path_absent(
                runtime,
                expected_identity=runtime_identity,
                deadline=cleanup_deadline,
                rebound_message="the BlueFire native runtime path was rebound during cleanup",
                absence_message="the BlueFire native runtime absence could not be verified",
            )
        except BaseException as exc:
            _extend_cleanup_failures(cleanup_failures, exc)
    failures.extend(cleanup_failures)
    _raise_cleanup_failures(failures)


def _remove_runner_journal(
    runs_dir: Path,
    pinned: _PinnedPrivateDirectory,
) -> None:
    """Remove only the result files registered against the pinned journal."""

    journal = runs_dir / ".bluefire-runner-results"
    cleanup_completed = False
    pinned_closed = False
    deletion_guard: _PinnedPrivateDirectory | None = None
    deletion_guard_closed = False
    failures: list[BaseException] = []
    cleanup_deadline = time.monotonic() + _CLEANUP_WINDOW_SECONDS
    try:
        _require(pinned.path == journal, "runner result journal guard is mismatched")
        journal_identity = pinned.directory_identity()
        journal_mount_identity = pinned.directory_mount_identity()
        authorized_entries = pinned.authorized_cleanup_entries()
        names = sorted(
            _retry_cleanup(
                lambda: pinned.names(maximum=_MAX_JOURNAL_ENTRIES),
                "runner result journal could not be enumerated safely",
                deadline=cleanup_deadline,
            )
        )
        _require(
            set(names) == set(authorized_entries),
            "runner result journal contains an unexpected entry, unowned or unreconciled",
        )
        entries: list[tuple[str, tuple[int, int]]] = []
        for name in names:
            _require(
                _TASK_RESULT.fullmatch(name) is not None,
                "runner result journal contains an unexpected entry",
            )
            details, mount_identity = _retry_cleanup(
                partial(pinned.entry_metadata_with_mount_identity, name),
                "runner result journal entry disappeared before validation",
                deadline=cleanup_deadline,
            )
            _require(
                stat.S_ISREG(details.st_mode)
                and not stat.S_ISLNK(details.st_mode)
                and not int(getattr(details, "st_file_attributes", 0)) & _REPARSE_POINT
                and details.st_nlink == 1
                and 0 <= details.st_size <= _MAX_REPORT_BYTES
                and mount_identity == journal_mount_identity,
                "runner result journal contains an unexpected entry",
            )
            identity = int(details.st_dev), int(details.st_ino)
            _require(
                authorized_entries.get(name) == identity,
                "runner result journal entry identity was not authorized",
            )
            entries.append((name, identity))
        for name, identity in entries:
            _retry_cleanup(
                partial(
                    pinned.unlink,
                    name,
                    maximum=_MAX_REPORT_BYTES,
                    expected_identity=identity,
                    expected_mount_identity=journal_mount_identity,
                ),
                "runner result journal entry could not be removed exactly",
                deadline=cleanup_deadline,
            )
            _wait_for_pinned_name_absent(
                pinned,
                name,
                expected_identity=identity,
                expected_mount_identity=journal_mount_identity,
                deadline=cleanup_deadline,
                rebound_message=("runner result journal entry path was rebound during cleanup"),
                absence_message=("runner result journal entry absence could not be verified"),
            )

        # The request host and crash-surviving watchdog use compatible
        # non-DELETE, non-share-delete handles for a continuous lease. Once
        # every watchdog has exited, close that lease and reacquire DELETE on
        # the same identity. A replacement in the handoff window is retained.
        pinned_closed = True
        pinned.close()

        def open_deletion_guard() -> _PinnedPrivateDirectory:
            candidate = _PinnedPrivateDirectory(
                journal,
                delete=True,
                expected_identity=journal_identity,
                expected_mount_identity=journal_mount_identity,
            )
            return candidate.__enter__()

        deletion_guard = _retry_cleanup(
            open_deletion_guard,
            "runner result journal could not be rebound for exact removal",
            deadline=cleanup_deadline,
        )
        _retry_cleanup(
            deletion_guard.remove,
            "runner result journal could not be removed exactly",
            deadline=cleanup_deadline,
        )
        deletion_guard_closed = True
        deletion_guard.close()
        cleanup_completed = True
    except BaseException as exc:
        _extend_cleanup_failures(failures, exc)
    if not pinned_closed:
        pinned_closed = True
        try:
            pinned.close()
        except BaseException as exc:
            _extend_cleanup_failures(failures, exc)
    if deletion_guard is not None and not deletion_guard_closed:
        deletion_guard_closed = True
        try:
            deletion_guard.close()
        except BaseException as exc:
            _extend_cleanup_failures(failures, exc)
    if cleanup_completed:
        try:
            _wait_for_path_absent(
                journal,
                expected_identity=journal_identity,
                deadline=cleanup_deadline,
                rebound_message="runner result journal path was rebound during cleanup",
                absence_message="runner result journal absence could not be verified",
            )
        except BaseException as exc:
            _extend_cleanup_failures(failures, exc)
    _raise_cleanup_failures(failures)


__all__ = [
    "DefenseFrontierError",
    "_CLEANUP_ATTEMPTS",
    "_RuntimeCleanupError",
    "_close_runtime_and_remove",
    "_create_pinned_runner_journal",
    "_create_pinned_runtime",
    "_extend_cleanup_failures",
    "_pin_owned_directory",
    "_pin_runtime_directory",
    "_raise_cleanup_failures",
    "_remove_pinned_tree",
    "_remove_runner_journal",
    "_require",
    "_retry_cleanup",
    "_safe_directory_details",
]
