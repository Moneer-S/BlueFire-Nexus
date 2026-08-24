"""Tamper-evident, path-contained storage for BlueFire run bundles."""

from __future__ import annotations

import json
import os
import re
import tempfile
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from .util import canonical_json_bytes, content_hash, file_hash, json_clone

RUN_ID_RE = re.compile(r"^run-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}$")
RECOVERY_ID_RE = re.compile(r"^recovery-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}$")
SAFE_BUNDLE_NAMES = frozenset(
    {
        "scenario.json",
        "plan.json",
        "policy.json",
        "profile.json",
        "result.json",
        "evidence.json",
        "detections.json",
        "comparison.json",
        "manifest.json",
    }
)


class RunStoreError(ValueError):
    """Raised when a bundle request violates a store invariant."""


@dataclass(frozen=True, slots=True)
class RunHandle:
    run_id: str
    created_at: str
    path: Path


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class RunStore:
    """Own immutable snapshots, append-only events, and final bundle hashes.

    Run identifiers are always generated internally. Directory creation is
    exclusive, writes are same-directory atomic replacements, and every path is
    validated before it is joined to the configured output root.
    """

    def __init__(self, root: str | Path) -> None:
        candidate = Path(root).expanduser()
        candidate.mkdir(parents=True, exist_ok=True)
        self.root = candidate.resolve(strict=True)
        if not self.root.is_dir():
            raise RunStoreError("run store root must be a directory")
        self._locks_guard = threading.Lock()
        self._locks: dict[str, threading.Lock] = {}

    def create_run(
        self,
        *,
        scenario: Mapping[str, Any],
        plan: Mapping[str, Any],
        policy: Mapping[str, Any],
        profile: Mapping[str, Any] | None,
        replay: Mapping[str, Any] | None = None,
    ) -> RunHandle:
        created_at = utc_now()
        for _attempt in range(8):
            run_id = self._new_run_id()
            path = self.root / run_id
            try:
                path.mkdir(mode=0o700, exist_ok=False)
            except FileExistsError:
                continue
            handle = RunHandle(run_id=run_id, created_at=created_at, path=path)
            metadata = {
                "schema_version": "1.0",
                "run_id": run_id,
                "created_at": created_at,
                "status": "created",
                "replay": json_clone(replay) if replay else None,
            }
            self.write_json(run_id, "result.json", metadata)
            self.write_json(run_id, "scenario.json", scenario)
            self.write_json(run_id, "plan.json", plan)
            self.write_json(run_id, "policy.json", policy)
            self.write_json(run_id, "profile.json", profile or {})
            self.write_json(run_id, "evidence.json", {"schema_version": "1.0", "records": []})
            self.write_json(
                run_id,
                "detections.json",
                {"schema_version": "1.0", "candidates": []},
            )
            self.append_event(run_id, "run.created", metadata)
            return handle
        raise RunStoreError("could not allocate a unique run identifier")

    def write_json(
        self,
        run_id: str,
        name: str,
        value: Mapping[str, Any] | list[Any],
    ) -> Path:
        if name not in SAFE_BUNDLE_NAMES:
            raise RunStoreError(f"unsupported bundle file name: {name!r}")
        run_path = self._run_path(run_id, must_exist=True)
        target = self._contained_child(run_path, name)
        payload = canonical_json_bytes(value) + b"\n"
        with self._lock(run_id):
            self._atomic_write(target, payload)
        return target

    def append_event(
        self,
        run_id: str,
        event_type: str,
        data: Mapping[str, Any],
    ) -> int:
        if not event_type or len(event_type) > 100:
            raise RunStoreError("event_type must contain 1-100 characters")
        run_path = self._run_path(run_id, must_exist=True)
        target = self._contained_child(run_path, "events.jsonl")
        with self._lock(run_id):
            previous_sequence, previous_hash = self._last_event_state(target)
            sequence = previous_sequence + 1
            body = {
                "schema_version": "1.0",
                "sequence": sequence,
                "timestamp": utc_now(),
                "event_type": event_type,
                "data": json_clone(data),
                "previous_event_hash": previous_hash,
            }
            row = {**body, "event_hash": content_hash(body)}
            with target.open("ab") as handle:
                handle.write(canonical_json_bytes(row) + b"\n")
                handle.flush()
                os.fsync(handle.fileno())
        return sequence

    def finalize(
        self,
        run_id: str,
        *,
        result: Mapping[str, Any],
        evidence: Iterable[Mapping[str, Any]],
        detections: Iterable[Mapping[str, Any]],
    ) -> Mapping[str, Any]:
        self.write_json(
            run_id, "evidence.json", {"schema_version": "1.0", "records": list(evidence)}
        )
        self.write_json(
            run_id,
            "detections.json",
            {"schema_version": "1.0", "candidates": list(detections)},
        )
        final_result = dict(result)
        final_result["run_id"] = run_id
        final_result["finalized_at"] = utc_now()
        self.write_json(run_id, "result.json", final_result)
        self.append_event(run_id, "run.finalized", final_result)

        run_path = self._run_path(run_id, must_exist=True)
        files: dict[str, dict[str, Any]] = {}
        for path in sorted(run_path.iterdir(), key=lambda item: item.name):
            if path.name == "manifest.json" or not path.is_file():
                continue
            files[path.name] = {"hash": file_hash(path), "size_bytes": path.stat().st_size}
        manifest = {
            "schema_version": "1.0",
            "run_id": run_id,
            "files": files,
            "bundle_hash": content_hash(files),
        }
        self.write_json(run_id, "manifest.json", manifest)
        return manifest

    def validate_bundle(self, run_id: str) -> Mapping[str, Any]:
        manifest = self.read_json(run_id, "manifest.json")
        files = manifest.get("files")
        if not isinstance(files, dict):
            raise RunStoreError("bundle manifest has no files mapping")
        if manifest.get("bundle_hash") != content_hash(files):
            raise RunStoreError("bundle manifest hash does not match its file table")
        run_path = self._run_path(run_id, must_exist=True)
        mismatches: list[str] = []
        for name, expected in files.items():
            if not isinstance(name, str) or Path(name).name != name:
                mismatches.append(str(name))
                continue
            path = self._contained_child(run_path, name)
            if not path.is_file() or not isinstance(expected, dict):
                mismatches.append(name)
                continue
            if expected.get("hash") != file_hash(path):
                mismatches.append(name)
            elif expected.get("size_bytes") != path.stat().st_size:
                mismatches.append(name)
        return {"valid": not mismatches, "mismatches": mismatches, "manifest": manifest}

    def read_json(self, run_id: str, name: str) -> Mapping[str, Any]:
        if name not in SAFE_BUNDLE_NAMES:
            raise RunStoreError(f"unsupported bundle file name: {name!r}")
        path = self._contained_child(self._run_path(run_id, must_exist=True), name)
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RunStoreError(f"cannot read {name}: {exc}") from exc
        if not isinstance(value, dict):
            raise RunStoreError(f"{name} must contain a JSON object")
        return value

    def read_events(
        self,
        run_id: str,
        *,
        after_sequence: int = 0,
        limit: int = 10_000,
    ) -> list[Mapping[str, Any]]:
        if isinstance(after_sequence, bool) or after_sequence < 0:
            raise RunStoreError("event cursor cannot be negative")
        if isinstance(limit, bool) or not 1 <= limit <= 10_000:
            raise RunStoreError("event page limit must be between 1 and 10000")
        path = self._contained_child(self._run_path(run_id, must_exist=True), "events.jsonl")
        if not path.exists():
            return []
        rows: list[Mapping[str, Any]] = []
        previous_hash: str | None = None
        expected_sequence = 1
        try:
            handle = path.open("r", encoding="utf-8")
        except OSError as exc:
            raise RunStoreError("event stream could not be read") from exc
        with handle:
            for line in handle:
                if not line.strip():
                    continue
                value = self._validated_event_row(
                    line,
                    expected_sequence=expected_sequence,
                    previous_hash=previous_hash,
                )
                previous_hash = str(value["event_hash"])
                expected_sequence += 1
                if int(value["sequence"]) > after_sequence and len(rows) < limit:
                    rows.append(value)
        return rows

    def read_event_page(
        self,
        run_id: str,
        *,
        after_sequence: int = 0,
        limit: int = 250,
    ) -> Mapping[str, Any]:
        if isinstance(limit, bool) or not 1 <= limit <= 1_000:
            raise RunStoreError("event page limit must be between 1 and 1000")
        rows = self.read_events(
            run_id,
            after_sequence=after_sequence,
            limit=limit + 1,
        )
        has_more = len(rows) > limit
        items = rows[:limit]
        next_sequence = int(items[-1]["sequence"]) if items else after_sequence
        return {
            "schema_version": "bluefire.event-page.v1",
            "run_id": run_id,
            "after_sequence": after_sequence,
            "next_sequence": next_sequence,
            "has_more": has_more,
            "items": items,
        }

    def get_run(self, run_id: str) -> Mapping[str, Any]:
        run_path = self._run_path(run_id, must_exist=True)
        manifest_path = self._contained_child(run_path, "manifest.json")
        manifest: Mapping[str, Any] | None = None
        if manifest_path.exists():
            integrity = self.validate_bundle(run_id)
            if not integrity.get("valid"):
                mismatches = ", ".join(str(name) for name in integrity.get("mismatches", []))
                detail = f": {mismatches}" if mismatches else ""
                raise RunStoreError(f"finalized run bundle failed integrity validation{detail}")
            manifest_value = integrity.get("manifest")
            if not isinstance(manifest_value, Mapping):
                raise RunStoreError("bundle integrity validation returned no manifest")
            manifest = manifest_value

        result = dict(self.read_json(run_id, "result.json"))
        result["scenario"] = self.read_json(run_id, "scenario.json")
        result["plan"] = self.read_json(run_id, "plan.json")
        result["policy"] = self.read_json(run_id, "policy.json")
        result["profile"] = self.read_json(run_id, "profile.json")
        result["evidence"] = self.read_json(run_id, "evidence.json")
        result["detections"] = self.read_json(run_id, "detections.json")
        result["events"] = self.read_events(run_id)
        if manifest is not None:
            result["manifest"] = manifest
        recovery_journal = self.read_recovery_records(run_id)
        if recovery_journal:
            result["recovery_journal"] = recovery_journal
            latest = recovery_journal[-1].get("record")
            if isinstance(latest, Mapping):
                result["cleanup_recovery"] = latest
        return result

    def append_recovery_record(
        self,
        run_id: str,
        record: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        """Atomically publish an independently hashed recovery sub-bundle.

        Finalized run files and their original manifest remain immutable.  Both
        recovery files are fsynced in a private staging directory before one
        same-volume directory rename makes the complete record visible.
        """

        run_path = self._run_path(run_id, must_exist=True)
        source = json_clone(record)
        if not isinstance(source, dict):
            raise RunStoreError("recovery record must be a JSON object")
        source["run_id"] = run_id
        source_digest = content_hash(source)
        for existing in self.read_recovery_records(run_id):
            manifest = existing.get("manifest")
            if isinstance(manifest, Mapping) and manifest.get("source_digest") == source_digest:
                return existing

        recovery_id = (
            "recovery-"
            + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            + "-"
            + uuid.uuid4().hex[:16]
        )
        source["recovery_id"] = recovery_id
        source["recorded_at"] = utc_now()
        final_path = self._contained_child(run_path, recovery_id)
        if final_path.exists():
            raise RunStoreError("recovery bundle identity already exists")

        temporary = Path(tempfile.mkdtemp(dir=run_path, prefix=".recovery-tmp-"))
        try:
            record_path = temporary / "record.json"
            self._atomic_write(record_path, canonical_json_bytes(source) + b"\n")
            files = {
                "record.json": {
                    "hash": file_hash(record_path),
                    "size_bytes": record_path.stat().st_size,
                }
            }
            recovery_manifest = {
                "schema_version": "bluefire.run-recovery-manifest.v1",
                "run_id": run_id,
                "recovery_id": recovery_id,
                "source_digest": source_digest,
                "files": files,
                "bundle_hash": content_hash(files),
            }
            self._atomic_write(
                temporary / "manifest.json",
                canonical_json_bytes(recovery_manifest) + b"\n",
            )
            self._fsync_directory(temporary)
            with self._lock(run_id):
                os.replace(temporary, final_path)
                self._fsync_directory(run_path)
        finally:
            if temporary.exists():
                for child in temporary.iterdir():
                    if child.is_file() and not child.is_symlink():
                        child.unlink(missing_ok=True)
                try:
                    temporary.rmdir()
                except OSError:
                    pass
        records = self.read_recovery_records(run_id)
        published = next(
            (item for item in records if item.get("recovery_id") == recovery_id),
            None,
        )
        if published is None:
            raise RunStoreError("recovery bundle was not published")
        return published

    def read_recovery_records(self, run_id: str) -> list[Mapping[str, Any]]:
        run_path = self._run_path(run_id, must_exist=True)
        rows: list[Mapping[str, Any]] = []
        for directory in sorted(run_path.iterdir(), key=lambda item: item.name):
            if not RECOVERY_ID_RE.fullmatch(directory.name):
                continue
            if directory.is_symlink() or not directory.is_dir():
                raise RunStoreError("recovery bundle path is unsafe")
            resolved = directory.resolve(strict=True)
            if resolved.parent != run_path:
                raise RunStoreError("recovery bundle escaped its run directory")
            record_path = self._contained_child(resolved, "record.json")
            manifest_path = self._contained_child(resolved, "manifest.json")
            if not record_path.is_file() or not manifest_path.is_file():
                raise RunStoreError("recovery bundle is incomplete")
            record = self._read_json_path(record_path, "recovery record")
            manifest = self._read_json_path(manifest_path, "recovery manifest")
            files = manifest.get("files")
            expected_files = {
                "record.json": {
                    "hash": file_hash(record_path),
                    "size_bytes": record_path.stat().st_size,
                }
            }
            if (
                manifest.get("schema_version") != "bluefire.run-recovery-manifest.v1"
                or manifest.get("run_id") != run_id
                or manifest.get("recovery_id") != directory.name
                or files != expected_files
                or manifest.get("bundle_hash") != content_hash(expected_files)
                or record.get("run_id") != run_id
                or record.get("recovery_id") != directory.name
            ):
                raise RunStoreError("recovery bundle failed integrity validation")
            source = dict(record)
            source.pop("recovery_id", None)
            source.pop("recorded_at", None)
            if manifest.get("source_digest") != content_hash(source):
                raise RunStoreError("recovery source digest does not match its record")
            rows.append(
                {
                    "schema_version": "bluefire.run-recovery.v1",
                    "recovery_id": directory.name,
                    "record": record,
                    "manifest": manifest,
                }
            )
        return rows

    def list_runs(self) -> list[Mapping[str, Any]]:
        items: list[Mapping[str, Any]] = []
        for path in sorted(self.root.iterdir(), reverse=True):
            if not path.is_dir() or not RUN_ID_RE.fullmatch(path.name):
                continue
            try:
                manifest_path = self._contained_child(path, "manifest.json")
            except RunStoreError as exc:
                items.append(self._corrupted_run_summary(path.name, error=str(exc)))
                continue
            if manifest_path.exists():
                try:
                    integrity = self.validate_bundle(path.name)
                except RunStoreError as exc:
                    items.append(self._corrupted_run_summary(path.name, error=str(exc)))
                    continue
                try:
                    self.read_recovery_records(path.name)
                except RunStoreError as exc:
                    items.append(self._corrupted_run_summary(path.name, error=str(exc)))
                    continue
                if not integrity.get("valid"):
                    mismatches = integrity.get("mismatches", [])
                    items.append(
                        self._corrupted_run_summary(
                            path.name,
                            mismatches=(str(name) for name in mismatches if isinstance(name, str)),
                        )
                    )
                    continue
            try:
                items.append(self.read_json(path.name, "result.json"))
            except RunStoreError:
                items.append({"run_id": path.name, "status": "incomplete"})
        return items

    @staticmethod
    def _corrupted_run_summary(
        run_id: str,
        *,
        mismatches: Iterable[str] = (),
        error: str | None = None,
    ) -> Mapping[str, Any]:
        integrity: dict[str, Any] = {
            "valid": False,
            "mismatches": sorted(set(mismatches)),
        }
        if error is not None:
            integrity["error"] = error
        return {
            "run_id": run_id,
            "status": "corrupted",
            "integrity": integrity,
        }

    def recover_interrupted_runs(self) -> int:
        """Mark created, unfinalized bundles as interrupted after a restart."""

        recovered = 0
        for path in sorted(self.root.iterdir()):
            if not path.is_dir() or not RUN_ID_RE.fullmatch(path.name):
                continue
            manifest = self._contained_child(path, "manifest.json")
            if manifest.exists():
                continue
            try:
                result = dict(self.read_json(path.name, "result.json"))
            except RunStoreError:
                continue
            if result.get("status") != "created":
                continue
            result.update(
                {
                    "status": "interrupted",
                    "interrupted_at": utc_now(),
                    "recovery": "No finalized manifest was present after restart.",
                }
            )
            self.write_json(path.name, "result.json", result)
            self.append_event(path.name, "run.interrupted", {"reason": "restart_recovery"})
            recovered += 1
        return recovered

    def _new_run_id(self) -> str:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        return f"run-{timestamp}-{uuid.uuid4().hex[:16]}"

    def _run_path(self, run_id: str, *, must_exist: bool) -> Path:
        if not RUN_ID_RE.fullmatch(run_id):
            raise RunStoreError("invalid run identifier")
        candidate = self.root / run_id
        if must_exist and not candidate.is_dir():
            raise RunStoreError(f"unknown run: {run_id}")
        resolved = candidate.resolve(strict=must_exist)
        if resolved.parent != self.root:
            raise RunStoreError("run path escapes the configured output root")
        return resolved

    @staticmethod
    def _contained_child(parent: Path, name: str) -> Path:
        if not name or Path(name).name != name or name in {".", ".."}:
            raise RunStoreError("bundle paths must be single safe file names")
        target = parent / name
        if target.parent.resolve(strict=True) != parent.resolve(strict=True):
            raise RunStoreError("bundle path escapes its run directory")
        if target.is_symlink():
            raise RunStoreError("bundle files may not be symbolic links")
        if target.exists() and target.resolve(strict=True).parent != parent.resolve(strict=True):
            raise RunStoreError("bundle file resolves outside its run directory")
        return target

    def _lock(self, run_id: str) -> threading.Lock:
        with self._locks_guard:
            return self._locks.setdefault(run_id, threading.Lock())

    @staticmethod
    def _atomic_write(target: Path, payload: bytes) -> None:
        descriptor, temporary_name = tempfile.mkstemp(
            dir=target.parent,
            prefix=f".{target.name}.",
            suffix=".tmp",
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, target)
        finally:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass

    @staticmethod
    def _read_json_path(path: Path, label: str) -> Mapping[str, Any]:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RunStoreError(f"cannot read {label}") from exc
        if not isinstance(value, dict):
            raise RunStoreError(f"{label} must contain a JSON object")
        return value

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        try:
            descriptor = os.open(path, os.O_RDONLY)
        except OSError:
            return
        try:
            os.fsync(descriptor)
        except OSError:
            pass
        finally:
            os.close(descriptor)

    @classmethod
    def _last_event_sequence(cls, path: Path) -> int:
        return cls._last_event_state(path)[0]

    @classmethod
    def _last_event_state(cls, path: Path) -> tuple[int, str | None]:
        if not path.exists():
            return 0, None
        last_sequence = 0
        previous_hash: str | None = None
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                row = cls._validated_event_row(
                    line,
                    expected_sequence=last_sequence + 1,
                    previous_hash=previous_hash,
                )
                last_sequence = int(row["sequence"])
                previous_hash = str(row["event_hash"])
        return last_sequence, previous_hash

    @staticmethod
    def _validated_event_row(
        line: str,
        *,
        expected_sequence: int,
        previous_hash: str | None,
    ) -> Mapping[str, Any]:
        try:
            row = json.loads(line)
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            raise RunStoreError("event stream is corrupt") from exc
        if not isinstance(row, dict):
            raise RunStoreError("event stream contains a non-object row")
        if row.get("schema_version") != "1.0":
            raise RunStoreError("event stream schema version is unsupported")
        if row.get("sequence") != expected_sequence:
            raise RunStoreError("event stream sequence is not contiguous")
        if row.get("previous_event_hash") != previous_hash:
            raise RunStoreError("event stream hash chain is broken")
        event_hash = row.get("event_hash")
        body = {key: value for key, value in row.items() if key != "event_hash"}
        if event_hash != content_hash(body):
            raise RunStoreError("event stream hash does not match its content")
        return row


__all__ = ["RunHandle", "RunStore", "RunStoreError", "utc_now"]
