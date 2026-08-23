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
            sequence = self._last_event_sequence(target) + 1
            row = {
                "schema_version": "1.0",
                "sequence": sequence,
                "timestamp": utc_now(),
                "event_type": event_type,
                "data": json_clone(data),
            }
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

    def read_events(self, run_id: str) -> list[Mapping[str, Any]]:
        path = self._contained_child(self._run_path(run_id, must_exist=True), "events.jsonl")
        if not path.exists():
            return []
        rows: list[Mapping[str, Any]] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            value = json.loads(line)
            if not isinstance(value, dict):
                raise RunStoreError("event stream contains a non-object row")
            rows.append(value)
        return rows

    def get_run(self, run_id: str) -> Mapping[str, Any]:
        result = dict(self.read_json(run_id, "result.json"))
        result["scenario"] = self.read_json(run_id, "scenario.json")
        result["plan"] = self.read_json(run_id, "plan.json")
        result["policy"] = self.read_json(run_id, "policy.json")
        result["profile"] = self.read_json(run_id, "profile.json")
        result["evidence"] = self.read_json(run_id, "evidence.json")
        result["detections"] = self.read_json(run_id, "detections.json")
        result["events"] = self.read_events(run_id)
        manifest_path = self._contained_child(
            self._run_path(run_id, must_exist=True), "manifest.json"
        )
        if manifest_path.is_file():
            result["manifest"] = self.read_json(run_id, "manifest.json")
        return result

    def list_runs(self) -> list[Mapping[str, Any]]:
        items: list[Mapping[str, Any]] = []
        for path in sorted(self.root.iterdir(), reverse=True):
            if not path.is_dir() or not RUN_ID_RE.fullmatch(path.name):
                continue
            try:
                items.append(self.read_json(path.name, "result.json"))
            except RunStoreError:
                items.append({"run_id": path.name, "status": "incomplete"})
        return items

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
    def _last_event_sequence(path: Path) -> int:
        if not path.exists():
            return 0
        last = 0
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                try:
                    row = json.loads(line)
                    sequence = int(row.get("sequence", 0))
                except (json.JSONDecodeError, TypeError, ValueError, AttributeError) as exc:
                    raise RunStoreError("event stream is corrupt") from exc
                if sequence <= last:
                    raise RunStoreError("event stream sequence is not monotonic")
                last = sequence
        return last


__all__ = ["RunHandle", "RunStore", "RunStoreError", "utc_now"]
