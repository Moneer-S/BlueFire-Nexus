"""Bounded export of a stopped Strix worker's private run directory.

The native worker retains a descriptor for its private ``/workspace`` after
reaping.  This module copies only reviewed result files into the controller's
owner-private attempt directory.  The returned manifest records copied bytes;
native execution and source cessation still require their separate receipts.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Mapping

from .engine_artifact_store import EngineArtifactStoreError, _safe_name
from .source_intake import _posix_rename_no_replace
from .strix_adapter import StrixRunSnapshot, discover_run_snapshot
from .util import canonical_json_bytes, content_hash

_ATTEMPT = re.compile(r"engine-attempt-[0-9a-f]{32}\Z")
_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_RUN_BYTES = 2 * 1024 * 1024
_COVERAGE_BYTES = 4 * 1024 * 1024
_OPTIONAL_BYTES = 4 * 1024 * 1024
_TOTAL_BYTES = 16 * 1024 * 1024
_MAX_FILES = 64
_MAX_ENTRIES = 4096
_MAX_EXPORT_SECONDS = 30.0
_OPTIONAL_ROOT = (
    "findings.sarif",
    "penetration_test_report.md",
    "vulnerabilities.csv",
    "vulnerabilities.json",
)
_DIR_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
_FILE_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NONBLOCK", 0)
)


class StrixWorkspaceExportError(RuntimeError):
    """The worker result could not be exported within the reviewed bounds."""


class StrixWorkspaceExportUnknown(StrixWorkspaceExportError):
    """A private staged or published export needs exact recovery inspection."""


@dataclass(frozen=True, slots=True)
class _Deadline:
    end: float

    def check(self) -> None:
        if time.monotonic() >= self.end:
            raise StrixWorkspaceExportUnknown("Strix export exceeded its time budget")


def _deadline(value: float | None) -> _Deadline:
    now = time.monotonic()
    if value is None:
        return _Deadline(now + _MAX_EXPORT_SECONDS)
    if type(value) not in {int, float}:
        raise StrixWorkspaceExportError("Strix export time budget is invalid or expired")
    try:
        end = float(value)
    except OverflowError as exc:
        raise StrixWorkspaceExportError("Strix export time budget is invalid or expired") from exc
    if not math.isfinite(end) or end <= now:
        raise StrixWorkspaceExportError("Strix export time budget is invalid or expired")
    return _Deadline(min(end, now + _MAX_EXPORT_SECONDS))


@dataclass(frozen=True, slots=True)
class StrixWorkspaceExportFile:
    name: str
    size_bytes: int
    sha256: str

    def to_manifest_row(self) -> dict[str, Any]:
        return {"name": self.name, "size_bytes": self.size_bytes, "sha256": self.sha256}


@dataclass(frozen=True, slots=True)
class StrixWorkspaceExport:
    attempt_id: str
    upstream_run_id: str
    source_observation_ref: str
    worker_terminal_ref: str
    manifest_ref: str
    selected_names: tuple[str, ...]
    reviewed_files: tuple[StrixWorkspaceExportFile, ...]
    source_run_dir: Path
    run_directory: Path
    snapshot: StrixRunSnapshot


def inspect_guest_strix_run_presence(
    workspace_fd: int,
    *,
    deadline_monotonic: float | None = None,
) -> Literal["no_run_record", "run_record_present"]:
    """Distinguish no saved run record from a partial or ambiguous guest tree.

    This is a source-inventory result only. The caller must first verify worker
    cessation and the pinned directory's native identity.
    """

    if sys.platform != "linux" or type(workspace_fd) is not int or workspace_fd < 0:
        raise StrixWorkspaceExportError("Strix workspace descriptor is invalid")
    deadline = _deadline(deadline_monotonic)
    deadline.check()
    if not stat.S_ISDIR(os.fstat(workspace_fd).st_mode):
        raise StrixWorkspaceExportError("Strix workspace descriptor is not a directory")
    try:
        runs_fd = _source_directory(workspace_fd, "strix_runs", deadline)
    except FileNotFoundError:
        return "no_run_record"
    try:
        names = _entries(runs_fd, deadline)
        if not names:
            return "no_run_record"
        if len(names) != 1 or _LABEL.fullmatch(names[0]) is None:
            raise StrixWorkspaceExportUnknown("Strix saved run tree is ambiguous")
        run_fd = _source_directory(runs_fd, names[0], deadline)
        try:
            if "run.json" not in _entries(run_fd, deadline):
                raise StrixWorkspaceExportUnknown("Strix saved run is partial")
            return "run_record_present"
        finally:
            os.close(run_fd)
    finally:
        os.close(runs_fd)


def inspect_retained_strix_export_state(
    *,
    attempt_id: str,
    host_attempt_directory: Path,
    deadline_monotonic: float | None = None,
) -> Literal["absent", "pending", "published", "unknown"]:
    """Read the exact host export state without relaunching or mutating it."""

    if (
        sys.platform != "linux"
        or type(attempt_id) is not str
        or _ATTEMPT.fullmatch(attempt_id) is None
    ):
        raise StrixWorkspaceExportError("Strix export identity is invalid")
    deadline = _deadline(deadline_monotonic)
    deadline.check()
    _host, host_fd = _open_host_attempt(host_attempt_directory, attempt_id)
    try:

        def exists(name: str) -> bool:
            deadline.check()
            try:
                os.stat(name, dir_fd=host_fd, follow_symlinks=False)
            except FileNotFoundError:
                return False
            deadline.check()
            return True

        pending = exists(".pending-strix-export")
        published = exists("strix_runs")
        if pending and published:
            return "unknown"
        if pending:
            return "pending"
        if published:
            return "published"
        return "absent"
    finally:
        os.close(host_fd)


def _require_digest(value: object, label: str) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise StrixWorkspaceExportError(f"{label} is invalid")
    return value


def _source_directory(parent_fd: int, name: str, deadline: _Deadline | None = None) -> int:
    if deadline is not None:
        deadline.check()
    try:
        descriptor = os.open(name, _DIR_FLAGS, dir_fd=parent_fd)
        if deadline is not None:
            deadline.check()
        details = os.fstat(descriptor)
        if not stat.S_ISDIR(details.st_mode):
            raise StrixWorkspaceExportError("Strix source directory is not ordinary")
        return descriptor
    except BaseException:
        if "descriptor" in locals():
            os.close(descriptor)
        raise


def _entries(directory_fd: int, deadline: _Deadline | None = None) -> tuple[str, ...]:
    names: list[str] = []
    with os.scandir(directory_fd) as entries:
        for entry in entries:
            if deadline is not None:
                deadline.check()
            if len(names) >= _MAX_ENTRIES:
                raise StrixWorkspaceExportError("Strix source directory exceeds its entry bound")
            names.append(entry.name)
    return tuple(names)


def _read_source_file(
    parent_fd: int, name: str, maximum: int, deadline: _Deadline | None = None
) -> bytes:
    if deadline is not None:
        deadline.check()
    try:
        descriptor = os.open(name, _FILE_FLAGS, dir_fd=parent_fd)
    except OSError as exc:
        raise StrixWorkspaceExportError("Strix source artifact is unavailable") from exc
    try:
        if deadline is not None:
            deadline.check()
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or not 1 <= before.st_size <= maximum
        ):
            raise StrixWorkspaceExportError("Strix source artifact is unsafe or outside its bound")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            if deadline is not None:
                deadline.check()
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if deadline is not None:
            deadline.check()

        def identity(details: os.stat_result) -> tuple[int, int, int, int, int]:
            return (
                details.st_dev,
                details.st_ino,
                details.st_size,
                details.st_mtime_ns,
                details.st_ctime_ns,
            )

        if (
            len(payload) != before.st_size
            or len(payload) > maximum
            or identity(before) != identity(after)
            or identity(after) != identity(current)
            or not stat.S_ISREG(current.st_mode)
        ):
            raise StrixWorkspaceExportError("Strix source artifact changed while read")
        return payload
    finally:
        os.close(descriptor)


def _source_files(
    workspace_fd: int,
    *,
    max_files: int,
    max_total_bytes: int,
    deadline: _Deadline | None = None,
) -> tuple[str, tuple[tuple[str, bytes], ...]]:
    runs_fd = _source_directory(workspace_fd, "strix_runs", deadline)
    try:
        run_names = _entries(runs_fd, deadline)
        if len(run_names) != 1 or _LABEL.fullmatch(run_names[0]) is None:
            raise StrixWorkspaceExportError("Strix source has no unique upstream run")
        run_id = run_names[0]
        try:
            _safe_name(f"strix_runs/{run_id}/run.json")
        except EngineArtifactStoreError as exc:
            raise StrixWorkspaceExportError("Strix upstream run name is not portable") from exc
        run_fd = _source_directory(runs_fd, run_id, deadline)
        try:
            names = _entries(run_fd, deadline)
            known = frozenset((*_OPTIONAL_ROOT, "run.json", "coverage.json", "vulnerabilities"))
            for name in names:
                if name not in known and name.casefold() in {item.casefold() for item in known}:
                    raise StrixWorkspaceExportError("Strix source has a portable artifact alias")
            if "run.json" not in names:
                raise StrixWorkspaceExportError("Strix source run record is unavailable")
            files: list[tuple[str, bytes]] = []
            total = 0

            def select(parent_fd: int, name: str, relative: str, maximum: int) -> None:
                nonlocal total
                if len(files) >= max_files:
                    raise StrixWorkspaceExportError("Strix result exceeds its file budget")
                payload = _read_source_file(parent_fd, name, maximum, deadline)
                total += len(payload)
                if total > max_total_bytes:
                    raise StrixWorkspaceExportError("Strix result exceeds its byte budget")
                files.append((relative, payload))

            select(run_fd, "run.json", "run.json", _RUN_BYTES)
            if "coverage.json" in names:
                select(run_fd, "coverage.json", "coverage.json", _COVERAGE_BYTES)
            for name in _OPTIONAL_ROOT:
                if name in names:
                    select(run_fd, name, name, _OPTIONAL_BYTES)
            if "vulnerabilities" in names:
                reports_fd = _source_directory(run_fd, "vulnerabilities", deadline)
                try:
                    for name in sorted(_entries(reports_fd, deadline)):
                        if name.casefold().endswith(".md") and not name.endswith(".md"):
                            raise StrixWorkspaceExportError(
                                "Strix report has a portable artifact alias"
                            )
                        if name.endswith(".md"):
                            if _LABEL.fullmatch(name) is None:
                                raise StrixWorkspaceExportError("Strix report name is invalid")
                            select(reports_fd, name, "vulnerabilities/" + name, _OPTIONAL_BYTES)
                finally:
                    os.close(reports_fd)
            files.sort(key=lambda row: row[0])
            portable: set[str] = set()
            for name, _payload in files:
                try:
                    selected, _parts = _safe_name(f"strix_runs/{run_id}/{name}")
                except EngineArtifactStoreError as exc:
                    raise StrixWorkspaceExportError("Strix artifact name is not portable") from exc
                folded = selected.casefold()
                if folded in portable:
                    raise StrixWorkspaceExportError("Strix artifact names have a portable alias")
                portable.add(folded)
            return run_id, tuple(files)
        finally:
            os.close(run_fd)
    finally:
        os.close(runs_fd)


def _write_file(parent_fd: int, name: str, payload: bytes, deadline: _Deadline) -> None:
    deadline.check()
    descriptor = os.open(
        name,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
        0o600,
        dir_fd=parent_fd,
    )
    try:
        fchmod = getattr(os, "fchmod", None)
        if not callable(fchmod):
            raise StrixWorkspaceExportError("Linux private file permissions are unavailable")
        fchmod(descriptor, 0o600)
        view = memoryview(payload)
        while view:
            deadline.check()
            count = os.write(descriptor, view)
            if count <= 0:
                raise StrixWorkspaceExportUnknown("Strix result write did not complete")
            view = view[count:]
        os.fsync(descriptor)
        deadline.check()
    finally:
        os.close(descriptor)


def _publish(
    host_fd: int,
    run_id: str,
    files: tuple[tuple[str, bytes], ...],
    manifest: Mapping[str, Any],
    deadline: _Deadline,
) -> None:
    deadline.check()
    stage = ".pending-strix-export"
    try:
        os.stat("strix_runs", dir_fd=host_fd, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        raise StrixWorkspaceExportUnknown("An earlier Strix export requires recovery")
    try:
        os.mkdir(stage, mode=0o700, dir_fd=host_fd)
    except FileExistsError as exc:
        raise StrixWorkspaceExportUnknown("An earlier Strix export requires recovery") from exc
    try:
        stage_fd = _source_directory(host_fd, stage, deadline)
        try:
            os.mkdir(run_id, mode=0o700, dir_fd=stage_fd)
            run_fd = _source_directory(stage_fd, run_id, deadline)
            try:
                reports_fd: int | None = None
                try:
                    for name, payload in files:
                        deadline.check()
                        if name.startswith("vulnerabilities/"):
                            if reports_fd is None:
                                os.mkdir("vulnerabilities", mode=0o700, dir_fd=run_fd)
                                reports_fd = _source_directory(run_fd, "vulnerabilities", deadline)
                            _write_file(
                                reports_fd, name.removeprefix("vulnerabilities/"), payload, deadline
                            )
                        else:
                            _write_file(run_fd, name, payload, deadline)
                    if reports_fd is not None:
                        os.fsync(reports_fd)
                    _write_file(
                        run_fd,
                        "bluefire-export.json",
                        canonical_json_bytes(manifest) + b"\n",
                        deadline,
                    )
                    os.fsync(run_fd)
                finally:
                    if reports_fd is not None:
                        os.close(reports_fd)
            finally:
                os.close(run_fd)
            os.fsync(stage_fd)
        finally:
            os.close(stage_fd)
        os.fsync(host_fd)
        deadline.check()
        _posix_rename_no_replace(host_fd, stage, "strix_runs")
        os.fsync(host_fd)
        deadline.check()
    except BaseException as exc:
        raise StrixWorkspaceExportUnknown(
            "Strix export is staged or publication is uncertain"
        ) from exc


def _open_host_attempt(host_attempt_directory: Path, attempt_id: str) -> tuple[Path, int]:
    host = Path(host_attempt_directory)
    if not host.is_absolute() or host.name != attempt_id or host.is_symlink():
        raise StrixWorkspaceExportError("Strix export destination is not the bound attempt")
    try:
        host_fd = os.open(host, _DIR_FLAGS)
        host_stat = os.fstat(host_fd)
        path_stat = os.stat(host, follow_symlinks=False)
        get_effective_user = getattr(os, "geteuid", None)
        if (
            not stat.S_ISDIR(host_stat.st_mode)
            or stat.S_IMODE(host_stat.st_mode) != 0o700
            or not callable(get_effective_user)
            or host_stat.st_uid != get_effective_user()
            or (path_stat.st_dev, path_stat.st_ino) != (host_stat.st_dev, host_stat.st_ino)
        ):
            raise StrixWorkspaceExportError("Strix export destination is not owner-private")
        return host, host_fd
    except BaseException:
        if "host_fd" in locals():
            os.close(host_fd)
        raise


def _inspect_retained_run(
    host: Path,
    run_id: str,
    rows: tuple[dict[str, Any], ...],
    *,
    expected_target: str,
    instruction_ref: str,
    process_exit_code: int | None,
    cancellation_requested: bool,
    cessation_verified: bool,
    deadline: _Deadline,
) -> StrixRunSnapshot:
    try:
        deadline.check()
        snapshot = discover_run_snapshot(
            host,
            expected_target=expected_target,
            expected_instruction_sha256=instruction_ref,
            process_exit_code=process_exit_code,
            cancellation_requested=cancellation_requested,
            cessation_verified=cessation_verified,
        )
        by_name = {row["name"]: row["sha256"] for row in rows}
        if (
            snapshot.upstream_run_id != run_id
            or snapshot.run_record_sha256 != by_name[f"strix_runs/{run_id}/run.json"]
            or snapshot.coverage_sha256 != by_name.get(f"strix_runs/{run_id}/coverage.json")
        ):
            raise StrixWorkspaceExportError("Strix exported run bytes changed")
        deadline.check()
        return snapshot
    except Exception as exc:
        raise StrixWorkspaceExportUnknown("The retained Strix run needs exact review") from exc


def export_strix_workspace_run(
    *,
    workspace_fd: int,
    native_observed: Mapping[str, Any],
    worker_terminal_ref: str,
    attempt_id: str,
    host_attempt_directory: Path,
    expected_target: str,
    expected_instruction_sha256: str,
    process_exit_code: int | None,
    cancellation_requested: bool = False,
    cessation_verified: bool = False,
    max_files: int = _MAX_FILES,
    max_total_bytes: int = _TOTAL_BYTES,
    deadline_monotonic: float | None = None,
) -> StrixWorkspaceExport:
    """Copy a stopped native worker's reviewed files and inspect its saved run.

    The caller must retain and verify the native terminal receipt separately.
    A copied run record remains an engine assertion, not target observation.
    """

    if sys.platform != "linux":
        raise StrixWorkspaceExportError("Strix private workspace export requires Linux")
    if (
        type(attempt_id) is not str
        or _ATTEMPT.fullmatch(attempt_id) is None
        or type(workspace_fd) is not int
        or workspace_fd < 0
        or type(native_observed) is not dict
        or type(max_files) is not int
        or not 1 <= max_files <= _MAX_FILES
        or type(max_total_bytes) is not int
        or not 1 <= max_total_bytes <= _TOTAL_BYTES
    ):
        raise StrixWorkspaceExportError("Strix export binding or budget is invalid")
    terminal_ref = _require_digest(worker_terminal_ref, "worker terminal reference")
    instruction_ref = _require_digest(expected_instruction_sha256, "instruction digest")
    deadline = _deadline(deadline_monotonic)
    unsigned = {name: value for name, value in native_observed.items() if name != "observation_ref"}
    observation_ref = _require_digest(native_observed.get("observation_ref"), "native observation")
    workspace_fact = native_observed.get("workspace")
    source_stat = os.fstat(workspace_fd)
    source_identity = {
        "device": source_stat.st_dev,
        "inode": source_stat.st_ino,
        "mode": stat.S_IMODE(source_stat.st_mode),
        "uid": source_stat.st_uid,
        "gid": source_stat.st_gid,
    }
    if (
        native_observed.get("schema_version") != "bluefire.strix-worker-runtime-observation.v1"
        or native_observed.get("attempt_id") != attempt_id
        or observation_ref != content_hash(unsigned)
        or not stat.S_ISDIR(source_stat.st_mode)
        or workspace_fact != source_identity
        or native_observed.get("workspace_ref") != content_hash(source_identity)
    ):
        raise StrixWorkspaceExportError("Pinned Strix workspace differs from native observation")
    host, host_fd = _open_host_attempt(host_attempt_directory, attempt_id)
    try:
        run_id, files = _source_files(
            workspace_fd,
            max_files=max_files,
            max_total_bytes=max_total_bytes,
            deadline=deadline,
        )
        reviewed_files = tuple(
            StrixWorkspaceExportFile(
                name=f"strix_runs/{run_id}/{name}",
                size_bytes=len(payload),
                sha256="sha256:" + hashlib.sha256(payload).hexdigest(),
            )
            for name, payload in files
        )
        rows = tuple(item.to_manifest_row() for item in reviewed_files)
        body = {
            "schema_version": "bluefire.strix-workspace-export.v1",
            "attempt_id": attempt_id,
            "upstream_run_id": run_id,
            "native_observation_ref": observation_ref,
            "worker_terminal_ref": terminal_ref,
            "source_workspace": source_identity,
            "expected_target_ref": content_hash({"target": expected_target}),
            "expected_instruction_sha256": instruction_ref,
            "files": list(rows),
        }
        manifest_ref = content_hash(body)
        _publish(host_fd, run_id, files, {**body, "manifest_ref": manifest_ref}, deadline)
        try:
            retained_run_id, retained_files = _source_files(
                host_fd,
                max_files=max_files,
                max_total_bytes=max_total_bytes,
                deadline=deadline,
            )
        except Exception as exc:
            raise StrixWorkspaceExportUnknown("Retained Strix artifacts need review") from exc
        if retained_run_id != run_id or retained_files != files:
            raise StrixWorkspaceExportUnknown("Retained Strix artifact bytes changed")
    finally:
        os.close(host_fd)
    snapshot = _inspect_retained_run(
        host,
        run_id,
        rows,
        expected_target=expected_target,
        instruction_ref=instruction_ref,
        process_exit_code=process_exit_code,
        cancellation_requested=cancellation_requested,
        cessation_verified=cessation_verified,
        deadline=deadline,
    )
    return StrixWorkspaceExport(
        attempt_id=attempt_id,
        upstream_run_id=run_id,
        source_observation_ref=observation_ref,
        worker_terminal_ref=terminal_ref,
        manifest_ref=manifest_ref,
        selected_names=tuple(item.name for item in reviewed_files),
        reviewed_files=reviewed_files,
        source_run_dir=host,
        run_directory=host / "strix_runs" / run_id,
        snapshot=snapshot,
    )


def reopen_strix_workspace_export(
    *,
    attempt_id: str,
    host_attempt_directory: Path,
    native_observed: Mapping[str, Any],
    worker_terminal_ref: str,
    expected_target: str,
    expected_instruction_sha256: str,
    process_exit_code: int | None,
    cancellation_requested: bool = False,
    cessation_verified: bool = False,
    max_files: int = _MAX_FILES,
    max_total_bytes: int = _TOTAL_BYTES,
    deadline_monotonic: float | None = None,
) -> StrixWorkspaceExport:
    """Reopen an exact final export without accessing or relaunching the worker.

    The source owner must independently reopen the protected native observation
    and terminal records before treating this byte inventory as a stopped run.
    """

    if sys.platform != "linux":
        raise StrixWorkspaceExportError("Strix private workspace export requires Linux")
    if (
        type(attempt_id) is not str
        or _ATTEMPT.fullmatch(attempt_id) is None
        or type(native_observed) is not dict
        or type(max_files) is not int
        or not 1 <= max_files <= _MAX_FILES
        or type(max_total_bytes) is not int
        or not 1 <= max_total_bytes <= _TOTAL_BYTES
    ):
        raise StrixWorkspaceExportError("Strix export binding or budget is invalid")
    terminal_ref = _require_digest(worker_terminal_ref, "worker terminal reference")
    instruction_ref = _require_digest(expected_instruction_sha256, "instruction digest")
    deadline = _deadline(deadline_monotonic)
    observation_ref = _require_digest(native_observed.get("observation_ref"), "native observation")
    unsigned = {name: value for name, value in native_observed.items() if name != "observation_ref"}
    workspace_fact = native_observed.get("workspace")
    if (
        native_observed.get("schema_version") != "bluefire.strix-worker-runtime-observation.v1"
        or native_observed.get("attempt_id") != attempt_id
        or observation_ref != content_hash(unsigned)
        or type(workspace_fact) is not dict
        or native_observed.get("workspace_ref") != content_hash(workspace_fact)
    ):
        raise StrixWorkspaceExportError("Native Strix source identity changed")
    host, host_fd = _open_host_attempt(host_attempt_directory, attempt_id)
    try:
        try:
            os.stat(".pending-strix-export", dir_fd=host_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise StrixWorkspaceExportUnknown("Strix export has unresolved staging")
        run_id, files = _source_files(
            host_fd, max_files=max_files, max_total_bytes=max_total_bytes, deadline=deadline
        )
        runs_fd = _source_directory(host_fd, "strix_runs", deadline)
        try:
            run_fd = _source_directory(runs_fd, run_id, deadline)
            try:
                payload = _read_source_file(run_fd, "bluefire-export.json", 128 * 1024, deadline)
            finally:
                os.close(run_fd)
        finally:
            os.close(runs_fd)

        def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            value: dict[str, Any] = {}
            for name, item in pairs:
                if name in value:
                    raise StrixWorkspaceExportUnknown("Strix export manifest repeats a field")
                value[name] = item
            return value

        manifest = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=unique_pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                StrixWorkspaceExportUnknown("Strix export manifest contains a non-finite value")
            ),
        )
        deadline.check()
        if type(manifest) is not dict or payload != canonical_json_bytes(manifest) + b"\n":
            raise StrixWorkspaceExportUnknown("Strix export manifest is not canonical")
        body = {name: value for name, value in manifest.items() if name != "manifest_ref"}
        reviewed_files = tuple(
            StrixWorkspaceExportFile(
                name=f"strix_runs/{run_id}/{name}",
                size_bytes=len(item),
                sha256="sha256:" + hashlib.sha256(item).hexdigest(),
            )
            for name, item in files
        )
        rows = tuple(item.to_manifest_row() for item in reviewed_files)
        if (
            set(manifest)
            != {
                "schema_version",
                "attempt_id",
                "upstream_run_id",
                "native_observation_ref",
                "worker_terminal_ref",
                "source_workspace",
                "expected_target_ref",
                "expected_instruction_sha256",
                "files",
                "manifest_ref",
            }
            or manifest["schema_version"] != "bluefire.strix-workspace-export.v1"
            or manifest["attempt_id"] != attempt_id
            or manifest["upstream_run_id"] != run_id
            or manifest["native_observation_ref"] != observation_ref
            or manifest["worker_terminal_ref"] != terminal_ref
            or manifest["source_workspace"] != workspace_fact
            or manifest["expected_target_ref"] != content_hash({"target": expected_target})
            or manifest["expected_instruction_sha256"] != instruction_ref
            or manifest["files"] != list(rows)
            or manifest["manifest_ref"] != content_hash(body)
        ):
            raise StrixWorkspaceExportUnknown("Strix export manifest or bytes changed")
    except StrixWorkspaceExportUnknown:
        raise
    except Exception as exc:
        raise StrixWorkspaceExportUnknown("Retained Strix export cannot be reopened") from exc
    finally:
        os.close(host_fd)
    snapshot = _inspect_retained_run(
        host,
        run_id,
        rows,
        expected_target=expected_target,
        instruction_ref=instruction_ref,
        process_exit_code=process_exit_code,
        cancellation_requested=cancellation_requested,
        cessation_verified=cessation_verified,
        deadline=deadline,
    )
    return StrixWorkspaceExport(
        attempt_id=attempt_id,
        upstream_run_id=run_id,
        source_observation_ref=observation_ref,
        worker_terminal_ref=terminal_ref,
        manifest_ref=manifest["manifest_ref"],
        selected_names=tuple(item.name for item in reviewed_files),
        reviewed_files=reviewed_files,
        source_run_dir=host,
        run_directory=host / "strix_runs" / run_id,
        snapshot=snapshot,
    )


__all__ = [
    "StrixWorkspaceExport",
    "StrixWorkspaceExportError",
    "StrixWorkspaceExportFile",
    "StrixWorkspaceExportUnknown",
    "export_strix_workspace_run",
    "inspect_guest_strix_run_presence",
    "inspect_retained_strix_export_state",
    "reopen_strix_workspace_export",
]
