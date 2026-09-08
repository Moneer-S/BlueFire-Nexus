"""Identity-bound pending runner output and no-overwrite durable publication."""

from __future__ import annotations

import os
import re
from hashlib import sha256
from pathlib import Path
from typing import BinaryIO, cast

from .runner_private_files import (
    _is_link_or_reparse,
    _PinnedPrivateDirectory,
    _PrivateFileCleanupError,
    _windows_extended_path,
)
from .runner_transport_errors import (
    RunnerDurableResultExists,
    RunnerPendingResultExists,
    RunnerTransportError,
)

_TASK_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
_RESULT_FILE_LIMIT_BYTES = 8 * 1024 * 1024


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


class DurableRunnerResult:
    """Reconcile result files through pinned parent and file identities.

    The caller retains the borrowed parent guard and decides when validated
    output may be published or authorized for cleanup. This component owns
    the file transaction without interpreting the runner result document.
    """

    def __init__(self, *, parent_guard: _PinnedPrivateDirectory | None = None) -> None:
        self._borrowed_parent_guard = parent_guard

    def _parent_guard(self, parent: Path) -> _PinnedPrivateDirectory:
        live = self._borrowed_parent_guard
        if live is None:
            return _PinnedPrivateDirectory(parent)
        same_parent = live.path == parent
        if os.name == "nt" and live.path.is_absolute() and parent.is_absolute():
            # RunStore uses extended paths; a borrowed owner can retain the
            # equivalent raw spelling. This does not resolve filesystem aliases.
            same_parent = _windows_extended_path(live.path) == _windows_extended_path(parent)
        if not same_parent or live.delete or live.share_delete:
            raise RunnerTransportError(
                "runner durable result guard cannot provide an exclusive watchdog handoff"
            )
        identity = live.directory_identity()
        mount_identity = live.directory_mount_identity()
        return _PinnedPrivateDirectory(
            parent,
            expected_identity=identity,
            expected_mount_identity=mount_identity,
        )

    def read(self, path: Path, *, maximum: int) -> bytes:
        try:
            with self._parent_guard(path.parent) as pinned:
                return pinned.read(path.name, maximum=maximum)
        except (OSError, RunnerTransportError):
            raise RunnerTransportError("runner durable result is unavailable") from None

    def exists(self, path: Path) -> bool:
        try:
            with self._parent_guard(path.parent) as pinned:
                return pinned.has_name(path.name)
        except (OSError, RunnerTransportError):
            raise RunnerTransportError("runner durable result is unavailable") from None

    def prepare(
        self,
        durable_result_path: str | Path,
        task_id: str,
        *,
        retain_parent_guard: bool = False,
    ) -> tuple[Path, Path, _PinnedPrivateDirectory | None]:
        destination = Path(durable_result_path).expanduser()
        if not destination.is_absolute() or destination.name in {"", ".", ".."}:
            raise RunnerTransportError("runner durable result destination is invalid")
        try:
            requested_parent = destination.parent
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            if _is_link_or_reparse(destination.parent):
                raise OSError("durable result parent is linked")
            metadata = destination.parent.stat(follow_symlinks=False)
            parent = destination.parent.resolve(strict=True)
            if (
                os.path.normcase(os.path.normpath(str(requested_parent)))
                != os.path.normcase(os.path.normpath(str(parent)))
                or not parent.is_dir()
                or _is_link_or_reparse(parent)
            ):
                raise OSError("durable result parent is not a directory")
            destination = parent / destination.name
            pending = runner_pending_result_path(destination, task_id)
            pinned = self._parent_guard(parent)
            try:
                pinned.__enter__()
                if pinned.directory_identity() != (metadata.st_dev, metadata.st_ino):
                    raise OSError("durable result parent identity changed")
                if pinned.has_name(destination.name):
                    raise RunnerDurableResultExists(
                        "Runner durable result already exists and requires reconciliation."
                    )
                if pinned.has_name(pending.name):
                    raise RunnerPendingResultExists(
                        "Runner pending result requires recovery before the task can start."
                    )
            except BaseException as exc:
                pinned.__exit__(type(exc), exc, exc.__traceback__)
                raise
            if not retain_parent_guard:
                pinned.__exit__(None, None, None)
        except RunnerDurableResultExists:
            raise
        except RunnerPendingResultExists:
            raise
        except _PrivateFileCleanupError:
            raise
        except (OSError, RunnerTransportError):
            raise RunnerTransportError("runner durable result destination is unavailable") from None
        return destination, pending, pinned if retain_parent_guard else None

    def open_pending(self, path: Path) -> BinaryIO:
        pinned = self._parent_guard(path.parent)
        try:
            pinned.__enter__()
            return cast(
                BinaryIO,
                pinned.open_new(path.name, maximum=_RESULT_FILE_LIMIT_BYTES),
            )
        except FileExistsError:
            pinned.close()
            raise RunnerPendingResultExists(
                "Runner pending result requires recovery before the task can start."
            ) from None
        except (OSError, RunnerTransportError):
            pinned.close()
            raise RunnerTransportError("runner pending result is unavailable") from None

    def promote(
        self,
        pending: Path,
        destination: Path,
        *,
        pending_expected: bytes,
        pending_identity: tuple[int, int],
        final_payload: bytes,
    ) -> None:
        final_created = False
        try:
            if pending.parent != destination.parent:
                raise OSError("durable result directories differ")
            with self._parent_guard(destination.parent) as pinned:
                checked, checked_identity = pinned.read_with_identity(
                    pending.name,
                    maximum=_RESULT_FILE_LIMIT_BYTES,
                    expected_identity=pending_identity,
                )
                if checked != pending_expected or checked_identity != pending_identity:
                    raise OSError("runner pending result identity changed")
                pinned.create(
                    destination.name,
                    final_payload,
                    maximum=_RESULT_FILE_LIMIT_BYTES,
                )
                final_created = True
                pinned.unlink(
                    pending.name,
                    maximum=_RESULT_FILE_LIMIT_BYTES,
                    expected=pending_expected,
                    expected_identity=pending_identity,
                )
        except FileExistsError:
            raise RunnerDurableResultExists(
                "Runner durable result already exists and requires reconciliation."
            ) from None
        except (OSError, RunnerTransportError):
            if final_created:
                raise RunnerDurableResultExists(
                    "Runner durable result may be committed and requires reconciliation."
                ) from None
            raise RunnerTransportError("runner durable result could not be committed") from None

    def remove_pending(
        self,
        path: Path,
        *,
        expected_identity: tuple[int, int] | None,
    ) -> None:
        if expected_identity is None:
            return
        try:
            with self._parent_guard(path.parent) as pinned:
                pinned.unlink(
                    path.name,
                    maximum=_RESULT_FILE_LIMIT_BYTES,
                    expected_identity=expected_identity,
                )
        except (OSError, RunnerTransportError):
            pass
