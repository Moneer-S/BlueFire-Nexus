"""Evidence provenance and independent sandbox observation."""

from __future__ import annotations

import errno
import hashlib
import os
import stat
import sys
import time
import weakref
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping

from .util import content_hash, json_clone


class EvidenceError(ValueError):
    pass


_WINDOWS_RESERVED_PATH_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{index}" for index in range(1, 10)}
    | {f"LPT{index}" for index in range(1, 10)}
)


class EvidenceProvenance(str, Enum):
    SYNTHETIC = "synthetic"
    EXECUTED = "executed"
    OBSERVED = "observed"
    CONTROL_BLOCKED = "control_blocked"
    COUNTERFACTUAL = "counterfactual"
    UNKNOWN = "unknown"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    schema_version: str
    evidence_id: str
    run_id: str
    step_id: str
    behavior_id: str
    action_id: str | None
    provenance: EvidenceProvenance
    producer: str
    runner_profile_id: str | None
    environment: Mapping[str, Any]
    timestamp: str
    parent_evidence_ids: tuple[str, ...]
    content: Mapping[str, Any]
    content_hash: str
    record_hash: str
    confidence: float
    limitations: tuple[str, ...]
    target_scope_ref: str

    @classmethod
    def create(
        cls,
        *,
        run_id: str,
        step_id: str,
        behavior_id: str,
        provenance: EvidenceProvenance,
        producer: str,
        content: Mapping[str, Any],
        target_scope_ref: str,
        action_id: str | None = None,
        runner_profile_id: str | None = None,
        environment: Mapping[str, Any] | None = None,
        parent_evidence_ids: Iterable[str] = (),
        confidence: float = 1.0,
        limitations: Iterable[str] = (),
        timestamp: str | None = None,
    ) -> "EvidenceRecord":
        if not 0.0 <= confidence <= 1.0:
            raise EvidenceError("evidence confidence must be between zero and one")
        content_copy = dict(content)
        content_digest = content_hash(content_copy)
        parents = tuple(parent_evidence_ids)
        limitation_rows = tuple(limitations)
        recorded_at = timestamp or _utc_now()
        base = {
            "schema_version": "bluefire.evidence.v1",
            "run_id": run_id,
            "step_id": step_id,
            "behavior_id": behavior_id,
            "action_id": action_id,
            "provenance": provenance,
            "producer": producer,
            "runner_profile_id": runner_profile_id,
            "environment": dict(environment or {}),
            "timestamp": recorded_at,
            "parent_evidence_ids": parents,
            "content": content_copy,
            "content_hash": content_digest,
            "confidence": confidence,
            "limitations": limitation_rows,
            "target_scope_ref": target_scope_ref,
        }
        record_digest = content_hash(base)
        evidence_id = "evidence-" + record_digest.removeprefix("sha256:")[:20]
        return cls(
            schema_version="bluefire.evidence.v1",
            evidence_id=evidence_id,
            run_id=run_id,
            step_id=step_id,
            behavior_id=behavior_id,
            action_id=action_id,
            provenance=provenance,
            producer=producer,
            runner_profile_id=runner_profile_id,
            environment=dict(environment or {}),
            timestamp=recorded_at,
            parent_evidence_ids=parents,
            content=content_copy,
            content_hash=content_digest,
            record_hash=record_digest,
            confidence=confidence,
            limitations=limitation_rows,
            target_scope_ref=target_scope_ref,
        )

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "EvidenceRecord":
        """Rehydrate and cryptographically verify an immutable evidence row."""

        expected_fields = {
            "schema_version",
            "evidence_id",
            "run_id",
            "step_id",
            "behavior_id",
            "action_id",
            "provenance",
            "producer",
            "runner_profile_id",
            "environment",
            "timestamp",
            "parent_evidence_ids",
            "content",
            "content_hash",
            "record_hash",
            "confidence",
            "limitations",
            "target_scope_ref",
        }
        if not isinstance(value, Mapping) or set(value) != expected_fields:
            raise EvidenceError("evidence record fields do not match the evidence contract")
        if value.get("schema_version") != "bluefire.evidence.v1":
            raise EvidenceError("unsupported evidence schema version")

        def required_string(name: str, maximum: int = 500) -> str:
            item = value.get(name)
            if not isinstance(item, str) or not item or len(item) > maximum or "\x00" in item:
                raise EvidenceError(f"evidence {name} is invalid")
            return item

        def optional_string(name: str, maximum: int = 500) -> str | None:
            item = value.get(name)
            if item is None:
                return None
            return required_string(name, maximum)

        try:
            provenance = EvidenceProvenance(value.get("provenance"))
        except (TypeError, ValueError) as exc:
            raise EvidenceError("evidence provenance is invalid") from exc
        environment = value.get("environment")
        content = value.get("content")
        if not isinstance(environment, Mapping) or not isinstance(content, Mapping):
            raise EvidenceError("evidence environment and content must be objects")
        try:
            environment_copy = json_clone(environment)
            content_copy = json_clone(content)
        except (TypeError, ValueError, RecursionError) as exc:
            raise EvidenceError("evidence must contain only finite JSON values") from exc
        if not isinstance(environment_copy, dict) or not isinstance(content_copy, dict):
            raise EvidenceError("evidence environment and content must be objects")

        def string_rows(name: str, maximum: int, item_maximum: int) -> tuple[str, ...]:
            rows = value.get(name)
            if not isinstance(rows, list) or len(rows) > maximum:
                raise EvidenceError(f"evidence {name} is invalid")
            result: list[str] = []
            for item in rows:
                if (
                    not isinstance(item, str)
                    or not item
                    or len(item) > item_maximum
                    or "\x00" in item
                ):
                    raise EvidenceError(f"evidence {name} is invalid")
                result.append(item)
            if len(set(result)) != len(result):
                raise EvidenceError(f"evidence {name} contains duplicates")
            return tuple(result)

        confidence = value.get("confidence")
        if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
            raise EvidenceError("evidence confidence is invalid")
        rebuilt = cls.create(
            run_id=required_string("run_id", 80),
            step_id=required_string("step_id", 200),
            behavior_id=required_string("behavior_id", 200),
            action_id=optional_string("action_id", 200),
            provenance=provenance,
            producer=required_string("producer", 200),
            runner_profile_id=optional_string("runner_profile_id", 200),
            environment=environment_copy,
            timestamp=required_string("timestamp", 40),
            parent_evidence_ids=string_rows("parent_evidence_ids", 256, 200),
            content=content_copy,
            confidence=confidence,
            limitations=string_rows("limitations", 64, 1_000),
            target_scope_ref=required_string("target_scope_ref", 500),
        )
        if value.get("content_hash") != rebuilt.content_hash:
            raise EvidenceError("evidence content hash does not match its content")
        if value.get("record_hash") != rebuilt.record_hash:
            raise EvidenceError("evidence record hash does not match its fields")
        if value.get("evidence_id") != rebuilt.evidence_id:
            raise EvidenceError("evidence identifier does not match its record hash")
        return rebuilt

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "evidence_id": self.evidence_id,
            "run_id": self.run_id,
            "step_id": self.step_id,
            "behavior_id": self.behavior_id,
            "action_id": self.action_id,
            "provenance": self.provenance.value,
            "producer": self.producer,
            "runner_profile_id": self.runner_profile_id,
            "environment": dict(self.environment),
            "timestamp": self.timestamp,
            "parent_evidence_ids": list(self.parent_evidence_ids),
            "content": dict(self.content),
            "content_hash": self.content_hash,
            "record_hash": self.record_hash,
            "confidence": self.confidence,
            "limitations": list(self.limitations),
            "target_scope_ref": self.target_scope_ref,
        }


@dataclass(slots=True)
class EvidenceGraph:
    _records: dict[str, EvidenceRecord] = field(default_factory=dict)

    def add(self, record: EvidenceRecord) -> None:
        if record.evidence_id in self._records:
            if self._records[record.evidence_id] != record:
                raise EvidenceError(f"conflicting evidence id: {record.evidence_id}")
            return
        missing = [parent for parent in record.parent_evidence_ids if parent not in self._records]
        if missing:
            raise EvidenceError(f"evidence references unknown parents: {missing}")
        cross_run = [
            parent
            for parent in record.parent_evidence_ids
            if self._records[parent].run_id != record.run_id
        ]
        if cross_run:
            raise EvidenceError(f"evidence references parents from another run: {cross_run}")
        self._records[record.evidence_id] = record

    def extend(self, records: Iterable[EvidenceRecord]) -> None:
        for record in records:
            self.add(record)

    def records(self) -> tuple[EvidenceRecord, ...]:
        return tuple(self._records.values())

    def by_step(self, step_id: str) -> tuple[EvidenceRecord, ...]:
        return tuple(record for record in self._records.values() if record.step_id == step_id)


class SandboxObserver:
    """Read-only collector that records declared artifacts under one root."""

    def __init__(
        self,
        sandbox_root: str | Path,
        *,
        max_file_bytes: int = 64 * 1024 * 1024,
        read_timeout_seconds: float = 5.0,
    ) -> None:
        candidate = Path(sandbox_root).expanduser().absolute()
        if max_file_bytes <= 0:
            raise EvidenceError("observer maximum file size must be positive")
        if read_timeout_seconds <= 0:
            raise EvidenceError("observer read timeout must be positive")
        self.root = candidate
        self.max_file_bytes = max_file_bytes
        self.read_timeout_seconds = read_timeout_seconds
        self._posix_root_descriptor: int | None = None
        self._windows_root_handle: int | None = None
        self._windows_root_final_path: str | None = None
        self._root_identity: tuple[int, int]
        try:
            if os.name == "nt":
                handle = _windows_open_directory_handle(self.root)
                try:
                    identity = _windows_directory_identity(handle)
                    try:
                        resolved = candidate.resolve(strict=True)
                    except OSError:
                        raise EvidenceError("sandbox observer root must already exist") from None
                    if os.path.normcase(os.path.normpath(str(candidate))) != os.path.normcase(
                        os.path.normpath(str(resolved))
                    ):
                        raise EvidenceError(
                            "sandbox observer root may not traverse links or junctions"
                        )
                    expected_root = os.path.normcase(os.path.normpath(str(resolved)))
                    opened_root = os.path.normcase(
                        os.path.normpath(_windows_handle_final_path(handle))
                    )
                    if opened_root != expected_root:
                        raise EvidenceError("sandbox observer root changed while it was pinned")
                    self.root = resolved
                    current = _windows_open_directory_handle(self.root)
                    try:
                        if (
                            _windows_directory_identity(current) != identity
                            or os.path.normcase(
                                os.path.normpath(_windows_handle_final_path(current))
                            )
                            != expected_root
                        ):
                            raise EvidenceError("sandbox observer root changed while it was pinned")
                    finally:
                        _windows_close_handle(current)
                    self._root_identity = identity
                    self._windows_root_final_path = expected_root
                except BaseException:
                    _windows_close_handle(handle)
                    raise
                self._windows_root_handle = handle
                self._root_finalizer = weakref.finalize(self, _windows_close_handle, handle)
            else:
                descriptor = self._open_posix_root()
                try:
                    identity = self._validated_posix_root_identity(descriptor)
                    try:
                        resolved = candidate.resolve(strict=True)
                    except OSError:
                        raise EvidenceError("sandbox observer root must already exist") from None
                    if os.path.normcase(os.path.normpath(str(candidate))) != os.path.normcase(
                        os.path.normpath(str(resolved))
                    ):
                        raise EvidenceError(
                            "sandbox observer root may not traverse links or junctions"
                        )
                    self.root = resolved
                    current = self._open_posix_root()
                    try:
                        if self._validated_posix_root_identity(current) != identity:
                            raise EvidenceError("sandbox observer root changed while it was pinned")
                    finally:
                        os.close(current)
                    self._root_identity = identity
                except BaseException:
                    os.close(descriptor)
                    raise
                self._posix_root_descriptor = descriptor
                self._root_finalizer = weakref.finalize(self, _close_posix_descriptor, descriptor)
            self._assert_root_identity()
        except EvidenceError:
            finalizer = getattr(self, "_root_finalizer", None)
            if finalizer is not None and finalizer.alive:
                finalizer()
            raise
        except (MemoryError, OSError):
            finalizer = getattr(self, "_root_finalizer", None)
            if finalizer is not None and finalizer.alive:
                finalizer()
            raise EvidenceError("sandbox observer root is unavailable or unsafe") from None

    def observe_file(
        self,
        *,
        relative_path: str,
        run_id: str,
        step_id: str,
        behavior_id: str,
        action_id: str,
        runner_profile_id: str,
        parent_evidence_ids: Iterable[str] = (),
        deadline_monotonic: float | None = None,
    ) -> EvidenceRecord:
        if deadline_monotonic is not None and (
            isinstance(deadline_monotonic, bool) or not isinstance(deadline_monotonic, (int, float))
        ):
            raise EvidenceError("observer deadline is invalid")
        if deadline_monotonic is not None and time.monotonic() >= deadline_monotonic:
            raise EvidenceError("observed file read exceeded the configured time limit")
        parts = self._validated_parts(relative_path)
        descriptor = self._open_file(parts)
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode):
                raise EvidenceError("observed path is not a regular file")
            if before.st_size > self.max_file_bytes:
                raise EvidenceError("observed file exceeds the configured byte limit")
            digest = hashlib.sha256()
            size = 0
            deadline = time.monotonic() + self.read_timeout_seconds
            if deadline_monotonic is not None:
                deadline = min(deadline, deadline_monotonic)
            with os.fdopen(descriptor, "rb", closefd=False) as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    size += len(chunk)
                    if size > self.max_file_bytes:
                        raise EvidenceError("observed file exceeded the configured byte limit")
                    if time.monotonic() > deadline:
                        raise EvidenceError("observed file read exceeded the configured time limit")
                    digest.update(chunk)
            after = os.fstat(descriptor)
            self._assert_root_identity()
        finally:
            os.close(descriptor)
        if (
            not stat.S_ISREG(after.st_mode)
            or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
            or (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            or size != after.st_size
        ):
            raise EvidenceError("observed file changed while it was being collected")
        return EvidenceRecord.create(
            run_id=run_id,
            step_id=step_id,
            behavior_id=behavior_id,
            action_id=action_id,
            provenance=EvidenceProvenance.OBSERVED,
            producer="sandbox-observer.v1",
            runner_profile_id=runner_profile_id,
            environment={"environment_type": "disposable"},
            parent_evidence_ids=parent_evidence_ids,
            content={
                "artifact_type": "file_observation",
                "path": PurePosixPath(relative_path).as_posix(),
                "size_bytes": size,
                "sha256": digest.hexdigest(),
                "modified_ns": after.st_mtime_ns,
            },
            confidence=1.0,
            limitations=("filesystem observation only; no host telemetry collector attached",),
            target_scope_ref=f"runner-profile:{runner_profile_id}",
        )

    @staticmethod
    def _validated_parts(relative_path: str) -> tuple[str, ...]:
        if not isinstance(relative_path, str) or "\x00" in relative_path or "\\" in relative_path:
            raise EvidenceError("observer paths must be normalized relative paths")
        logical = PurePosixPath(relative_path)
        if (
            logical.is_absolute()
            or not logical.parts
            or any(part in {"", ".", ".."} for part in logical.parts)
            or logical.as_posix() != relative_path
        ):
            raise EvidenceError("observer paths must be normalized relative paths")
        if os.name == "nt" and any(
            ":" in part
            or part != part.rstrip(" .")
            or part.upper().split(".", 1)[0] in _WINDOWS_RESERVED_PATH_NAMES
            for part in logical.parts
        ):
            # Drive-relative paths, alternate data streams, and DOS device
            # names do not have ordinary contained-file semantics on Windows.
            raise EvidenceError("observer paths must name ordinary Windows files")
        return tuple(logical.parts)

    def _open_file(self, parts: tuple[str, ...]) -> int:
        if os.name == "nt":
            return self._open_windows_file(parts)
        return self._open_posix_file(parts)

    def _open_posix_file(self, parts: tuple[str, ...]) -> int:
        no_follow = getattr(os, "O_NOFOLLOW", None)
        if no_follow is None or not os.supports_dir_fd or os.open not in os.supports_dir_fd:
            raise EvidenceError("secure sandbox traversal is unavailable on this platform")
        close_on_exec = getattr(os, "O_CLOEXEC", 0)
        directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | no_follow | close_on_exec
        file_flags = os.O_RDONLY | no_follow | close_on_exec
        root_descriptor = self._posix_root_descriptor
        if root_descriptor is None or not self._root_finalizer.alive:
            raise EvidenceError("observer sandbox root pin is unavailable")
        self._assert_root_identity()
        directory_fd = -1
        file_fd = -1
        try:
            directory_fd = os.dup(root_descriptor)
            if self._validated_posix_root_identity(directory_fd) != self._root_identity:
                raise EvidenceError("observer sandbox root identity changed")
            for part in parts[:-1]:
                next_fd = os.open(part, directory_flags, dir_fd=directory_fd)
                try:
                    if not stat.S_ISDIR(os.fstat(next_fd).st_mode):
                        raise EvidenceError("observer path component is not a directory")
                except BaseException:
                    os.close(next_fd)
                    raise
                os.close(directory_fd)
                directory_fd = next_fd
            file_fd = os.open(parts[-1], file_flags, dir_fd=directory_fd)
            self._assert_root_identity()
            result = file_fd
            file_fd = -1
            return result
        except OSError as exc:
            if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                raise EvidenceError("observer refuses symbolic-link paths") from exc
            raise
        finally:
            if file_fd >= 0:
                os.close(file_fd)
            if directory_fd >= 0:
                os.close(directory_fd)

    def _open_windows_file(self, parts: tuple[str, ...]) -> int:
        self._assert_root_identity()
        candidate = self.root.joinpath(*parts)
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0)
        descriptor = os.open(candidate, flags)
        try:
            final_path = _windows_final_path(descriptor)
            self._assert_root_identity()
            root_handle = self._windows_root_handle
            if root_handle is None or not self._root_finalizer.alive:
                raise EvidenceError("observer sandbox root pin is unavailable")
            root_text = os.path.normcase(os.path.normpath(_windows_handle_final_path(root_handle)))
            final_text = os.path.normcase(os.path.normpath(final_path))
            try:
                common = os.path.commonpath((root_text, final_text))
            except ValueError:
                common = ""
            if common != root_text or final_text == root_text:
                raise EvidenceError("observed file is outside the sandbox root")
        except BaseException:
            os.close(descriptor)
            raise
        return descriptor

    def _open_posix_root(self) -> int:
        no_follow = getattr(os, "O_NOFOLLOW", None)
        if no_follow is None or not os.supports_dir_fd or os.open not in os.supports_dir_fd:
            raise EvidenceError("secure sandbox traversal is unavailable on this platform")
        flags = (
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | no_follow | getattr(os, "O_CLOEXEC", 0)
        )
        anchor = self.root.anchor
        if not anchor:
            raise EvidenceError("sandbox observer root must be absolute")
        directory_fd = -1
        try:
            directory_fd = os.open(anchor, flags)
            for part in self.root.parts[1:]:
                next_fd = os.open(part, flags, dir_fd=directory_fd)
                try:
                    if not stat.S_ISDIR(os.fstat(next_fd).st_mode):
                        raise EvidenceError("observer sandbox root is not a directory")
                except BaseException:
                    os.close(next_fd)
                    raise
                os.close(directory_fd)
                directory_fd = next_fd
            result = directory_fd
            directory_fd = -1
            return result
        except OSError as exc:
            if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                raise EvidenceError("observer sandbox root is unavailable or unsafe") from exc
            raise
        finally:
            if directory_fd >= 0:
                os.close(directory_fd)

    @staticmethod
    def _validated_posix_root_identity(descriptor: int) -> tuple[int, int]:
        details = os.fstat(descriptor)
        if not stat.S_ISDIR(details.st_mode):
            raise EvidenceError("observer sandbox root is not a directory")
        return details.st_dev, details.st_ino

    def _assert_root_identity(self) -> None:
        try:
            if os.name == "nt":
                root_handle = self._windows_root_handle
                if root_handle is None or not self._root_finalizer.alive:
                    raise EvidenceError("observer sandbox root pin is unavailable")
                expected_path = self._windows_root_final_path
                if (
                    expected_path is None
                    or _windows_directory_identity(root_handle) != self._root_identity
                    or os.path.normcase(os.path.normpath(_windows_handle_final_path(root_handle)))
                    != expected_path
                ):
                    raise EvidenceError("observer sandbox root identity changed")
                current = _windows_open_directory_handle(self.root)
                try:
                    if (
                        _windows_directory_identity(current) != self._root_identity
                        or os.path.normcase(os.path.normpath(_windows_handle_final_path(current)))
                        != expected_path
                    ):
                        raise EvidenceError("observer sandbox root identity changed")
                finally:
                    _windows_close_handle(current)
                return

            root_descriptor = self._posix_root_descriptor
            if root_descriptor is None or not self._root_finalizer.alive:
                raise EvidenceError("observer sandbox root pin is unavailable")
            if self._validated_posix_root_identity(root_descriptor) != self._root_identity:
                raise EvidenceError("observer sandbox root identity changed")
            current = self._open_posix_root()
            try:
                if self._validated_posix_root_identity(current) != self._root_identity:
                    raise EvidenceError("observer sandbox root identity changed")
            finally:
                os.close(current)
        except EvidenceError:
            raise
        except (MemoryError, OSError):
            raise EvidenceError("observer sandbox root identity changed") from None


def _windows_final_path(descriptor: int) -> str:
    """Return the normalized DOS path for an already-open Windows file handle."""

    if sys.platform != "win32":  # pragma: no cover - guarded by SandboxObserver._open_file
        raise OSError("Windows handle paths are unavailable")
    import msvcrt

    raw_handle = msvcrt.get_osfhandle(descriptor)
    if raw_handle == -1:
        raise OSError("observed file handle is invalid")
    return _windows_handle_final_path(raw_handle)


def _windows_handle_final_path(raw_handle: int) -> str:
    """Return the normalized DOS path for an already-open Windows handle."""

    if sys.platform != "win32":  # pragma: no cover - guarded by Windows-only callers
        raise OSError("Windows handle paths are unavailable")
    import ctypes
    from ctypes import wintypes

    get_final_path = ctypes.WinDLL("kernel32", use_last_error=True).GetFinalPathNameByHandleW
    get_final_path.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
    get_final_path.restype = wintypes.DWORD
    size = 512
    while size <= 32768:
        buffer = ctypes.create_unicode_buffer(size)
        length = int(get_final_path(wintypes.HANDLE(raw_handle), buffer, size, 0))
        if length == 0:
            error = ctypes.get_last_error()
            raise OSError(error, "unable to resolve observed file handle")
        if length < size:
            value = buffer.value
            if value.startswith("\\\\?\\UNC\\"):
                return "\\\\" + value[8:]
            if value.startswith("\\\\?\\"):
                return value[4:]
            return value
        size = length + 1
    raise OSError("observed file handle path exceeds the platform bound")


def _windows_open_directory_handle(path: Path) -> int:
    """Pin a non-reparse directory for stable identity checks."""

    if sys.platform != "win32":  # pragma: no cover - guarded by SandboxObserver
        raise OSError("Windows directory handles are unavailable")
    import ctypes
    from ctypes import wintypes

    create_file = ctypes.WinDLL("kernel32", use_last_error=True).CreateFileW
    create_file.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    create_file.restype = wintypes.HANDLE
    handle = create_file(
        str(path),
        0,
        0x00000001 | 0x00000002,
        None,
        3,
        0x02000000 | 0x00200000,
        None,
    )
    invalid = ctypes.c_void_p(-1).value
    raw = ctypes.cast(handle, ctypes.c_void_p).value
    if raw is None or raw == invalid:
        raise OSError(ctypes.get_last_error(), "unable to pin observer sandbox root")
    return int(raw)


def _windows_directory_identity(handle: int) -> tuple[int, int]:
    """Return a stable volume/file identity for a pinned Windows directory."""

    if sys.platform != "win32":  # pragma: no cover - guarded by SandboxObserver
        raise OSError("Windows directory identities are unavailable")
    import ctypes
    from ctypes import wintypes

    class _FileInformation(ctypes.Structure):
        _fields_ = [
            ("dwFileAttributes", wintypes.DWORD),
            ("ftCreationTime", wintypes.FILETIME),
            ("ftLastAccessTime", wintypes.FILETIME),
            ("ftLastWriteTime", wintypes.FILETIME),
            ("dwVolumeSerialNumber", wintypes.DWORD),
            ("nFileSizeHigh", wintypes.DWORD),
            ("nFileSizeLow", wintypes.DWORD),
            ("nNumberOfLinks", wintypes.DWORD),
            ("nFileIndexHigh", wintypes.DWORD),
            ("nFileIndexLow", wintypes.DWORD),
        ]

    get_information = ctypes.WinDLL("kernel32", use_last_error=True).GetFileInformationByHandle
    get_information.argtypes = (wintypes.HANDLE, ctypes.POINTER(_FileInformation))
    get_information.restype = wintypes.BOOL
    information = _FileInformation()
    if not get_information(wintypes.HANDLE(handle), ctypes.byref(information)):
        raise OSError(ctypes.get_last_error(), "unable to inspect observer sandbox root")
    attributes = int(information.dwFileAttributes)
    if not attributes & 0x00000010 or attributes & 0x00000400:
        raise EvidenceError("observer sandbox root is unavailable or unsafe")
    file_index = (int(information.nFileIndexHigh) << 32) | int(information.nFileIndexLow)
    volume_serial = int(information.dwVolumeSerialNumber)
    if volume_serial <= 0 or file_index <= 0:
        raise EvidenceError("observer sandbox root is unavailable or unsafe")
    return volume_serial, file_index


def _windows_close_handle(handle: int) -> None:
    if sys.platform != "win32":  # pragma: no cover - guarded by SandboxObserver
        return
    import ctypes
    from ctypes import wintypes

    close_handle = ctypes.WinDLL("kernel32", use_last_error=True).CloseHandle
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL
    close_handle(wintypes.HANDLE(handle))


def _close_posix_descriptor(handle: int) -> None:
    os.close(handle)


__all__ = [
    "EvidenceError",
    "EvidenceGraph",
    "EvidenceProvenance",
    "EvidenceRecord",
    "SandboxObserver",
]
