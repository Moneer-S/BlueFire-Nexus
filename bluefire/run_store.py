"""Tamper-evident, path-contained storage for BlueFire run bundles."""

from __future__ import annotations

import json
import os
import re
import stat
import tempfile
import threading
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Mapping, cast

from .retained_artifact_contract import MAX_BYTES as MAX_RETAINED_PAYLOAD_BYTES
from .util import canonical_json_bytes, content_hash, file_hash, json_clone
from .windows_owner_acl import (
    WindowsOwnerAclError,
    _windows_extended_path,
    _windows_open_descriptor,
    apply_owner_private_acl,
    verify_owner_private_acl,
)

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
        "artifacts.json",
    }
)
RETAINED_PAYLOAD_DIRECTORY = "retained"
RETAINED_PAYLOAD_NAME = "bundle.jsonl"
RETAINED_CAPTURE_NAME = "capture.json"
_RETAINED_TEMP_PREFIX = ".retained-tmp-"
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x00000400)
_ACCEPTANCE_BINDING_ENV = {
    "acceptance_id": "BLUEFIRE_ACCEPTANCE_ID",
    "gate_id": "BLUEFIRE_ACCEPTANCE_GATE_ID",
    "contract_sha256": "BLUEFIRE_ACCEPTANCE_CONTRACT_SHA256",
    "repository_commit": "BLUEFIRE_ACCEPTANCE_REPOSITORY_COMMIT",
    "repository_tree": "BLUEFIRE_ACCEPTANCE_REPOSITORY_TREE",
    "release": "BLUEFIRE_ACCEPTANCE_RELEASE",
}
_UNSEALED_FINALIZATION_ERROR = "run finalization was not sealed by a manifest"
_INTERRUPTED_RECOVERY_MESSAGE = "No finalized manifest was present after restart."


def file_hash_bytes(payload: bytes) -> str:
    return sha256(payload).hexdigest()


class RunStoreError(ValueError):
    """Raised when a bundle request violates a store invariant."""


@dataclass(frozen=True, slots=True)
class RunHandle:
    run_id: str
    created_at: str
    path: Path


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _acceptance_binding() -> dict[str, str] | None:
    values = {field: os.environ.get(name) for field, name in _ACCEPTANCE_BINDING_ENV.items()}
    if not any(value is not None for value in values.values()):
        return None
    if any(
        not isinstance(value, str) or not value or len(value) > 512 for value in values.values()
    ):
        raise RunStoreError("acceptance run binding is incomplete or invalid")
    return {
        "schema_version": "bluefire.product-acceptance-run-binding.v1",
        **{field: str(value) for field, value in values.items()},
    }


class RunStore:
    """Own immutable snapshots, append-only events, and final bundle hashes.

    Run identifiers are always generated internally. Directory creation is
    exclusive, writes are same-directory atomic replacements, and every path is
    validated before it is joined to the configured output root.
    """

    def __init__(self, root: str | Path) -> None:
        candidate = Path(root).expanduser()
        if os.name == "nt":
            # Normalize once so descendants, including longer atomic temporary
            # names and recovery directories, retain Win32 long-path support.
            # Resolve below still establishes the canonical containment root.
            candidate = _windows_extended_path(candidate)
        created = False
        try:
            if os.name == "nt":
                candidate.parent.mkdir(parents=True, exist_ok=True)
                self._windows_mkdir_private(candidate)
            else:
                candidate.mkdir(mode=0o700, parents=True, exist_ok=False)
            created = True
        except FileExistsError:
            pass
        self.root = candidate.resolve(strict=True)
        if not self.root.is_dir():
            raise RunStoreError("run store root must be a directory")
        if created:
            try:
                self._harden_retained_entry(self.root, directory=True)
            except RunStoreError:
                try:
                    self.root.rmdir()
                except OSError:
                    pass
                raise
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
        _reserved_run_id: str | None = None,
    ) -> RunHandle:
        if _reserved_run_id is not None and (
            not isinstance(_reserved_run_id, str) or RUN_ID_RE.fullmatch(_reserved_run_id) is None
        ):
            raise RunStoreError("reserved run identity is invalid")
        created_at = utc_now()
        acceptance_binding = _acceptance_binding()
        for _attempt in range(8):
            run_id = _reserved_run_id or self._new_run_id()
            path = self.root / run_id
            try:
                if os.name == "nt":
                    self._windows_mkdir_private(path)
                else:
                    path.mkdir(mode=0o700, exist_ok=False)
            except FileExistsError:
                if _reserved_run_id is not None:
                    raise RunStoreError("reserved run identity already exists") from None
                continue
            try:
                self._harden_retained_entry(path, directory=True)
            except RunStoreError:
                try:
                    path.rmdir()
                except OSError:
                    pass
                raise
            handle = RunHandle(run_id=run_id, created_at=created_at, path=path)
            metadata = {
                "schema_version": "1.0",
                "run_id": run_id,
                "created_at": created_at,
                "status": "created",
                "replay": json_clone(replay) if replay else None,
            }
            if acceptance_binding is not None:
                metadata["acceptance_binding"] = acceptance_binding
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
        initial_result = self.read_json(run_id, "result.json")
        binding = initial_result.get("acceptance_binding")
        created_at = initial_result.get("created_at")
        final_result = dict(result)
        if final_result.get("created_at", created_at) != created_at:
            raise RunStoreError("run creation timestamp changed before finalization")
        final_result["created_at"] = created_at
        if binding is not None:
            if (
                not isinstance(binding, Mapping)
                or final_result.get("acceptance_binding", binding) != binding
            ):
                raise RunStoreError("acceptance run binding changed before finalization")
            final_result["acceptance_binding"] = dict(binding)
        elif "acceptance_binding" in final_result:
            raise RunStoreError("acceptance run binding cannot be supplied by a caller")
        self.write_json(
            run_id, "evidence.json", {"schema_version": "1.0", "records": list(evidence)}
        )
        self.write_json(
            run_id,
            "detections.json",
            {"schema_version": "1.0", "candidates": list(detections)},
        )
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
        if manifest.get("run_id") != run_id:
            raise RunStoreError("bundle manifest run ID does not match its directory")
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

    def read_json(
        self, run_id: str, name: str, *, _max_bytes: int | None = None
    ) -> Mapping[str, Any]:
        if name not in SAFE_BUNDLE_NAMES:
            raise RunStoreError(f"unsupported bundle file name: {name!r}")
        path = self._contained_child(self._run_path(run_id, must_exist=True), name)
        try:
            if _max_bytes is None:
                value = json.loads(path.read_text(encoding="utf-8"))
            else:
                if type(_max_bytes) is not int or _max_bytes < 1:
                    raise RunStoreError("bundle JSON byte bound is invalid")
                with path.open("rb") as stream:
                    payload = stream.read(_max_bytes + 1)
                if len(payload) > _max_bytes:
                    raise RunStoreError("bundle JSON exceeds its reviewed byte bound")
                value = json.loads(payload.decode("utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RunStoreError(f"cannot read {name}: {exc}") from exc
        if not isinstance(value, dict):
            raise RunStoreError(f"{name} must contain a JSON object")
        return value

    def publish_retained_capture(
        self,
        run_id: str,
        *,
        payload: bytes,
        capture: Mapping[str, Any],
        artifacts: Mapping[str, Any],
        event: Mapping[str, Any],
        _expected_run_identity: tuple[int, int, int] | None = None,
    ) -> Mapping[str, Any]:
        """Publish one immutable private capture and reconcile its public projections.

        The payload and the exact reconciliation journal become visible together
        through one no-replace directory rename.  ``artifacts.json`` and the
        append-only event are projections of that private source of truth.  An
        exact retry repairs a missing projection; conflicting or partial data is
        preserved and refused.
        """

        if not isinstance(payload, bytes) or not 1 <= len(payload) <= MAX_RETAINED_PAYLOAD_BYTES:
            raise RunStoreError("retained payload exceeds its reviewed byte bound")
        journal = json_clone(capture)
        artifacts_document = json_clone(artifacts)
        event_document = json_clone(event)
        if not all(
            isinstance(value, dict) for value in (journal, artifacts_document, event_document)
        ):
            raise RunStoreError("retained capture documents must be JSON objects")
        if (
            journal.get("schema_version") != "bluefire.retained-capture-publication.v1"
            or journal.get("run_id") != run_id
            or journal.get("artifacts") != artifacts_document
            or journal.get("event") != event_document
            or journal.get("payload")
            != {
                "path": f"{RETAINED_PAYLOAD_DIRECTORY}/{RETAINED_PAYLOAD_NAME}",
                "sha256": file_hash_bytes(payload),
                "size_bytes": len(payload),
            }
            or journal.get("publication_digest")
            != content_hash(
                {key: value for key, value in journal.items() if key != "publication_digest"}
            )
        ):
            raise RunStoreError("retained capture publication binding is invalid")
        journal_bytes = canonical_json_bytes(journal) + b"\n"
        artifacts_bytes = canonical_json_bytes(artifacts_document) + b"\n"
        if len(journal_bytes) > 256 * 1024 or len(artifacts_bytes) > 256 * 1024:
            raise RunStoreError("retained capture metadata exceeds its reviewed byte bound")
        if (
            event_document.get("event_type") != "artifact.retained"
            or not isinstance(journal.get("receipt"), dict)
            or event_document.get("capture_digest") != journal["receipt"].get("capture_digest")
            or not isinstance(event_document.get("data"), dict)
        ):
            raise RunStoreError("retained capture event binding is invalid")

        run_path = self._run_path(run_id, must_exist=True)
        with self._lock(run_id):
            with self._retained_parent_custody(run_path) as run_descriptor:
                if (
                    _expected_run_identity is not None
                    and self._filesystem_identity(os.fstat(run_descriptor))
                    != _expected_run_identity
                ):
                    raise RunStoreError("retained run namespace changed before reconciliation")
                directory = self._contained_child(run_path, RETAINED_PAYLOAD_DIRECTORY)
                if os.name == "nt":
                    published = directory.exists()
                else:
                    try:
                        os.stat(
                            RETAINED_PAYLOAD_DIRECTORY,
                            dir_fd=run_descriptor,
                            follow_symlinks=False,
                        )
                        published = True
                    except FileNotFoundError:
                        published = False
                if published:
                    self._verify_retained_directory(
                        directory,
                        {
                            RETAINED_PAYLOAD_NAME: payload,
                            RETAINED_CAPTURE_NAME: journal_bytes,
                        },
                        run_descriptor=run_descriptor,
                    )
                else:
                    self._publish_retained_directory(
                        run_path,
                        {
                            RETAINED_PAYLOAD_NAME: payload,
                            RETAINED_CAPTURE_NAME: journal_bytes,
                        },
                        run_descriptor=run_descriptor,
                    )
                self._publish_exact_file(
                    run_path, "artifacts.json", artifacts_bytes, run_descriptor=run_descriptor
                )
                self._append_exact_retained_event(
                    run_id, run_path, event_document, run_descriptor=run_descriptor
                )
                # Verify every component again after all public projections exist.
                self._verify_retained_directory(
                    directory,
                    {
                        RETAINED_PAYLOAD_NAME: payload,
                        RETAINED_CAPTURE_NAME: journal_bytes,
                    },
                    run_descriptor=run_descriptor,
                )
                self._verify_exact_file(
                    run_path / "artifacts.json", artifacts_bytes, run_descriptor=run_descriptor
                )
        return cast(Mapping[str, Any], journal)

    def retained_capture(self, run_id: str, *, reconcile: bool = True) -> Mapping[str, Any]:
        """Read and optionally reconcile one exact private capture journal."""

        run_path = self._run_path(run_id, must_exist=True)
        with self._retained_parent_custody(run_path) as run_descriptor:
            run_identity = self._filesystem_identity(os.fstat(run_descriptor))
            directory = self._contained_child(run_path, RETAINED_PAYLOAD_DIRECTORY)
            capture_path = self._contained_child(directory, RETAINED_CAPTURE_NAME)
            if os.name == "nt":
                directory_descriptor, directory_details = self._open_verified_retained_entry(
                    directory, directory=True
                )
            else:
                directory_descriptor, directory_details = self._open_verified_retained_entry_at(
                    run_descriptor, RETAINED_PAYLOAD_DIRECTORY, directory=True
                )
            try:
                try:
                    journal_bytes = self._read_private_retained_entry(
                        capture_path,
                        directory=False,
                        parent_descriptor=directory_descriptor,
                    )
                    journal = json.loads(journal_bytes)
                except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise RunStoreError("retained capture journal is unavailable") from exc
                if not isinstance(journal, dict):
                    raise RunStoreError("retained capture journal must be a JSON object")
                payload = self._read_private_retained_entry(
                    self._contained_child(directory, RETAINED_PAYLOAD_NAME),
                    directory=False,
                    parent_descriptor=directory_descriptor,
                )
                if os.name != "nt":
                    self._verify_pinned_retained_directory(
                        run_descriptor,
                        RETAINED_PAYLOAD_DIRECTORY,
                        directory_descriptor,
                        directory_details,
                    )
                else:
                    current = directory.lstat()
                    if self._stable_private_identity(current) != self._stable_private_identity(
                        directory_details
                    ) or self._is_link_or_reparse(current):
                        raise RunStoreError("retained private directory changed")
            finally:
                os.close(directory_descriptor)
        if reconcile:
            self.publish_retained_capture(
                run_id,
                payload=payload,
                capture=journal,
                artifacts=journal.get("artifacts", {}),
                event=journal.get("event", {}),
                _expected_run_identity=run_identity,
            )
        return journal

    def retained_capture_run_ids(self) -> list[str]:
        """Return bounded run identities that contain a private capture journal."""

        result: list[str] = []
        for path in sorted(self.root.iterdir(), key=lambda item: item.name):
            if not path.is_dir() or RUN_ID_RE.fullmatch(path.name) is None:
                continue
            capture = path / RETAINED_PAYLOAD_DIRECTORY / RETAINED_CAPTURE_NAME
            if capture.is_file() and not capture.is_symlink():
                result.append(path.name)
        return result

    def write_retained_payload(self, run_id: str, payload: bytes) -> None:
        """Legacy refusal: retained bytes require their exact capture journal."""

        raise RunStoreError("retained payload publication requires an exact capture journal")

    def read_retained_payload(self, run_id: str) -> bytes:
        """Read only the fixed private payload after custody verification."""
        run_path = self._run_path(run_id, must_exist=True)
        with self._retained_parent_custody(run_path) as run_descriptor:
            directory = self._contained_child(run_path, RETAINED_PAYLOAD_DIRECTORY)
            payload = self._read_private_retained_entry(
                self._contained_child(directory, RETAINED_PAYLOAD_NAME),
                directory=False,
                run_descriptor=run_descriptor,
            )
        if not 1 <= len(payload) <= MAX_RETAINED_PAYLOAD_BYTES:
            raise RunStoreError("retained payload exceeds its reviewed byte bound")
        return payload

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

    def get_run(self, run_id: str, *, require_finalized: bool = False) -> Mapping[str, Any]:
        run_path = self._run_path(run_id, must_exist=True)
        manifest_path = self._contained_child(run_path, "manifest.json")
        manifest: Mapping[str, Any] | None = None
        if require_finalized or manifest_path.exists():
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
        if manifest is None and self._result_requires_manifest(result):
            raise RunStoreError(_UNSEALED_FINALIZATION_ERROR)
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
            validated_bundle_digest: str | None = None
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
                manifest = integrity.get("manifest")
                if isinstance(manifest, Mapping):
                    digest = manifest.get("bundle_hash")
                    if isinstance(digest, str):
                        validated_bundle_digest = digest
            try:
                result = self.read_json(path.name, "result.json")
            except RunStoreError:
                items.append({"run_id": path.name, "status": "incomplete"})
                continue
            if not manifest_path.exists() and self._result_requires_manifest(result):
                items.append(
                    {
                        "run_id": path.name,
                        "status": "interrupted",
                        "recovery": _INTERRUPTED_RECOVERY_MESSAGE,
                    }
                )
                continue
            # Present the title frozen with this run, not a mutable catalog name.
            # Enrich the response only; immutable result files and hashes stay intact.
            summary = dict(result)
            # Provenance comes only from the manifest validated above, never
            # from similarly named fields embedded in the result document.
            summary.pop("manifest", None)
            summary.pop("bundle_digest", None)
            if validated_bundle_digest is not None:
                summary["bundle_digest"] = validated_bundle_digest
            if manifest_path.exists():
                try:
                    scenario = self.read_json(path.name, "scenario.json")
                except RunStoreError:
                    scenario = {}
                title = scenario.get("title")
                if isinstance(title, str) and title.strip():
                    summary["scenario_title"] = title
            items.append(summary)
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
        """Mark every unfinalized bundle as interrupted after a restart."""

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
            if result.get("status") == "interrupted" and "finalized_at" not in result:
                continue
            result.pop("finalized_at", None)
            result.update(
                {
                    "status": "interrupted",
                    "interrupted_at": utc_now(),
                    "recovery": _INTERRUPTED_RECOVERY_MESSAGE,
                }
            )
            self.write_json(path.name, "result.json", result)
            self.append_event(path.name, "run.interrupted", {"reason": "restart_recovery"})
            recovered += 1
        return recovered

    @staticmethod
    def _result_requires_manifest(result: Mapping[str, Any]) -> bool:
        if "finalized_at" in result:
            return True
        status = result.get("status")
        return status not in ("created", "interrupted")

    def _new_run_id(self) -> str:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        return f"run-{timestamp}-{uuid.uuid4().hex[:16]}"

    @staticmethod
    def _filesystem_identity(details: os.stat_result) -> tuple[int, int, int]:
        return int(details.st_dev), int(details.st_ino), stat.S_IFMT(details.st_mode)

    @staticmethod
    def _windows_mkdir_private(path: Path) -> None:
        """Create a Windows directory with its private DACL at creation time."""

        if os.name != "nt":
            raise RunStoreError("Windows private directory creation is unavailable")
        import ctypes
        from ctypes import wintypes

        from .windows_owner_acl import _configure_apis, _converted_descriptor, current_user_sid

        class SecurityAttributes(ctypes.Structure):
            _fields_ = (
                ("length", wintypes.DWORD),
                ("descriptor", ctypes.c_void_p),
                ("inherit", wintypes.BOOL),
            )

        advapi32, kernel32 = _configure_apis()
        descriptor = _converted_descriptor(advapi32, f"D:P(A;OICI;FA;;;{current_user_sid()})")
        try:
            create_directory = kernel32.CreateDirectoryW
            create_directory.argtypes = (wintypes.LPCWSTR, ctypes.POINTER(SecurityAttributes))
            create_directory.restype = wintypes.BOOL
            attributes = SecurityAttributes(ctypes.sizeof(SecurityAttributes), descriptor, False)
            if not create_directory(str(_windows_extended_path(path)), ctypes.byref(attributes)):
                error = cast(Any, ctypes).get_last_error()
                if error in {80, 183}:
                    raise FileExistsError(error, "private directory already exists", str(path))
                raise OSError(error, "private directory creation failed", str(path))
        finally:
            kernel32.LocalFree(descriptor)

    @classmethod
    def _stable_private_identity(cls, details: os.stat_result) -> tuple[int, ...]:
        return (
            *cls._filesystem_identity(details),
            int(details.st_nlink),
            int(details.st_size),
            int(details.st_mtime_ns),
            int(details.st_ctime_ns),
        )

    @staticmethod
    def _is_link_or_reparse(details: os.stat_result) -> bool:
        return stat.S_ISLNK(details.st_mode) or bool(
            int(getattr(details, "st_file_attributes", 0)) & _REPARSE_POINT
        )

    @staticmethod
    def _posix_euid() -> int:
        getter = getattr(os, "geteuid", None)
        if not callable(getter):
            raise RunStoreError("retained POSIX owner identity is unavailable")
        return int(getter())

    @staticmethod
    def _posix_fchmod(descriptor: int, mode: int) -> None:
        chmod = getattr(os, "fchmod", None)
        if not callable(chmod):
            raise RunStoreError("retained POSIX permission hardening is unavailable")
        chmod(descriptor, mode)

    def _harden_retained_entry(self, path: Path, *, directory: bool) -> None:
        """Harden an exact object just created by this store, then verify it."""

        if os.name == "nt":
            descriptor: int | None = None
            try:
                details = path.lstat()
                if (
                    self._is_link_or_reparse(details)
                    or stat.S_ISDIR(details.st_mode) is not directory
                    or (not directory and details.st_nlink != 1)
                ):
                    raise RunStoreError("retained private object is unsafe")
                descriptor = _windows_open_descriptor(
                    path, directory=directory, write_dac=True, share_write=directory
                )
                if self._filesystem_identity(os.fstat(descriptor)) != self._filesystem_identity(
                    details
                ):
                    raise RunStoreError("retained private object changed")
                apply_owner_private_acl(descriptor, directory=directory)
                verify_owner_private_acl(descriptor, directory=directory)
            except (OSError, WindowsOwnerAclError):
                raise RunStoreError("retained private permissions are unavailable") from None
            finally:
                if descriptor is not None:
                    os.close(descriptor)
        else:
            try:
                os.chmod(path, 0o700 if directory else 0o600, follow_symlinks=False)
            except (NotImplementedError, OSError):
                raise RunStoreError("retained private permissions are unavailable") from None
        self._verify_retained_entry(path, directory=directory)

    def _verify_retained_entry(self, path: Path, *, directory: bool) -> os.stat_result:
        descriptor, details = self._open_verified_retained_entry(path, directory=directory)
        os.close(descriptor)
        return details

    def _open_verified_retained_entry(
        self, path: Path, *, directory: bool
    ) -> tuple[int, os.stat_result]:
        """Open and verify one private object, returning its pinned descriptor."""

        try:
            details = path.lstat()
        except OSError:
            raise RunStoreError("retained private object is unavailable") from None
        if (
            self._is_link_or_reparse(details)
            or stat.S_ISDIR(details.st_mode) is not directory
            or (not directory and details.st_nlink != 1)
        ):
            raise RunStoreError("retained private object is unsafe")
        descriptor: int | None = None
        try:
            if os.name == "nt":
                descriptor = _windows_open_descriptor(path, directory=directory)
                opened = os.fstat(descriptor)
                verify_owner_private_acl(descriptor, directory=directory)
                if self._filesystem_identity(opened) != self._filesystem_identity(details):
                    raise RunStoreError("retained private object changed")
            else:
                flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
                if directory:
                    flags |= getattr(os, "O_DIRECTORY", 0)
                descriptor = os.open(path, flags)
                opened = os.fstat(descriptor)
                get_effective_user = getattr(os, "geteuid", None)
                if (
                    self._filesystem_identity(opened) != self._filesystem_identity(details)
                    or stat.S_IMODE(opened.st_mode) != (0o700 if directory else 0o600)
                    or (callable(get_effective_user) and opened.st_uid != get_effective_user())
                ):
                    raise RunStoreError("retained private permissions are unsafe")
            return descriptor, details
        except RunStoreError:
            if descriptor is not None:
                os.close(descriptor)
            raise
        except (OSError, WindowsOwnerAclError):
            if descriptor is not None:
                os.close(descriptor)
            message = (
                "retained private DACL is unsafe"
                if os.name == "nt"
                else "retained private permissions are unsafe"
            )
            raise RunStoreError(message) from None

    def _open_verified_retained_entry_at(
        self, parent_descriptor: int, name: str, *, directory: bool
    ) -> tuple[int, os.stat_result]:
        """POSIX openat verification relative to an already pinned directory."""

        if os.name == "nt" or not name or Path(name).name != name:
            raise RunStoreError("retained descriptor-relative path is invalid")
        try:
            details = os.stat(
                name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except OSError:
            raise RunStoreError("retained private object is unavailable") from None
        if (
            self._is_link_or_reparse(details)
            or stat.S_ISDIR(details.st_mode) is not directory
            or (not directory and details.st_nlink != 1)
        ):
            raise RunStoreError("retained private object is unsafe")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        if directory:
            flags |= getattr(os, "O_DIRECTORY", 0)
        descriptor: int | None = None
        try:
            descriptor = os.open(name, flags, dir_fd=parent_descriptor)
            opened = os.fstat(descriptor)
            get_effective_user = getattr(os, "geteuid", None)
            if (
                self._filesystem_identity(opened) != self._filesystem_identity(details)
                or stat.S_IMODE(opened.st_mode) != (0o700 if directory else 0o600)
                or (callable(get_effective_user) and opened.st_uid != get_effective_user())
            ):
                raise RunStoreError("retained private permissions are unsafe")
            return descriptor, details
        except RunStoreError:
            if descriptor is not None:
                os.close(descriptor)
            raise
        except OSError:
            if descriptor is not None:
                os.close(descriptor)
            raise RunStoreError("retained private permissions are unsafe") from None

    @contextmanager
    def _retained_parent_custody(self, run_path: Path) -> Iterator[int]:
        """Pin the verified root and run namespace for one private operation."""

        if run_path.parent != self.root:
            raise RunStoreError("retained run path escaped its storage root")
        descriptors: list[int] = []
        try:
            if os.name == "nt":
                root_descriptor, _ = self._open_verified_retained_entry(self.root, directory=True)
                descriptors.append(root_descriptor)
            else:
                self._verify_posix_ancestor_custody()
                try:
                    root_details = self.root.lstat()
                except OSError:
                    raise RunStoreError("retained storage root is unavailable") from None
                get_effective_user = getattr(os, "geteuid", None)
                if (
                    self._is_link_or_reparse(root_details)
                    or not stat.S_ISDIR(root_details.st_mode)
                    or root_details.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
                    or (
                        callable(get_effective_user) and root_details.st_uid != get_effective_user()
                    )
                ):
                    raise RunStoreError("retained storage root permits replacement")
                flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
                flags |= getattr(os, "O_DIRECTORY", 0)
                root_descriptor = os.open(self.root, flags)
                descriptors.append(root_descriptor)
                if self._filesystem_identity(
                    os.fstat(root_descriptor)
                ) != self._filesystem_identity(root_details):
                    raise RunStoreError("retained storage root changed")
            if os.name == "nt":
                run_descriptor, run_details = self._open_verified_retained_entry(
                    run_path, directory=True
                )
            else:
                run_descriptor, run_details = self._open_verified_retained_entry_at(
                    root_descriptor, run_path.name, directory=True
                )
            descriptors.append(run_descriptor)
            yield run_descriptor
            if os.name != "nt":
                named_run = os.stat(run_path.name, dir_fd=root_descriptor, follow_symlinks=False)
                opened_run = os.fstat(run_descriptor)
                named_root = self.root.lstat()
                if (
                    self._filesystem_identity(named_run) != self._filesystem_identity(run_details)
                    or self._filesystem_identity(opened_run)
                    != self._filesystem_identity(run_details)
                    or self._filesystem_identity(named_root)
                    != self._filesystem_identity(root_details)
                    or self._is_link_or_reparse(named_run)
                    or self._is_link_or_reparse(named_root)
                    or stat.S_IMODE(named_run.st_mode) != 0o700
                    or named_run.st_uid != self._posix_euid()
                ):
                    raise RunStoreError("retained parent namespace changed")
        except RunStoreError:
            raise
        except OSError:
            raise RunStoreError("retained parent custody is unavailable") from None
        finally:
            for descriptor in reversed(descriptors):
                os.close(descriptor)

    def _verify_posix_ancestor_custody(self) -> None:
        """Reject an ancestor namespace replaceable by another POSIX principal."""

        get_effective_user = getattr(os, "geteuid", None)
        if not callable(get_effective_user):
            return
        effective_user = int(get_effective_user())
        try:
            child_details = self.root.lstat()
            for parent in self.root.parents:
                details = parent.lstat()
                if self._is_link_or_reparse(details) or not stat.S_ISDIR(details.st_mode):
                    raise RunStoreError("retained storage ancestor is unsafe")
                if details.st_uid not in {0, effective_user}:
                    raise RunStoreError("retained storage ancestor permits replacement")
                writable_by_others = details.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
                if writable_by_others and not (
                    details.st_mode & stat.S_ISVTX and child_details.st_uid in {0, effective_user}
                ):
                    raise RunStoreError("retained storage ancestor permits replacement")
                child_details = details
        except RunStoreError:
            raise
        except OSError:
            raise RunStoreError("retained storage ancestor is unavailable") from None

    def _verify_retained_parent_custody(self, run_path: Path) -> None:
        with self._retained_parent_custody(run_path):
            pass

    def _read_private_retained_entry(
        self,
        path: Path,
        *,
        directory: bool,
        run_descriptor: int | None = None,
        parent_descriptor: int | None = None,
    ) -> bytes:
        if directory:
            raise RunStoreError("retained private directory cannot be read as bytes")
        owned_parent_descriptor: int | None = None
        descriptor: int | None = None
        try:
            if os.name != "nt" and parent_descriptor is not None:
                descriptor, details = self._open_verified_retained_entry_at(
                    parent_descriptor, path.name, directory=False
                )

                def named_after() -> os.stat_result:
                    return os.stat(
                        path.name,
                        dir_fd=parent_descriptor,
                        follow_symlinks=False,
                    )

            elif os.name != "nt" and run_descriptor is not None:
                owned_parent_descriptor, parent_details = self._open_verified_retained_entry_at(
                    run_descriptor, path.parent.name, directory=True
                )
                descriptor, details = self._open_verified_retained_entry_at(
                    owned_parent_descriptor, path.name, directory=False
                )

                def named_after() -> os.stat_result:
                    return os.stat(
                        path.name,
                        dir_fd=owned_parent_descriptor,
                        follow_symlinks=False,
                    )

            else:
                owned_parent_descriptor, _ = self._open_verified_retained_entry(
                    path.parent, directory=True
                )
                descriptor, details = self._open_verified_retained_entry(path, directory=False)

                def named_after() -> os.stat_result:
                    return path.lstat()

            payload = self._read_pinned_private_entry(descriptor, details, named_after)
            if (
                os.name != "nt"
                and run_descriptor is not None
                and owned_parent_descriptor is not None
            ):
                self._verify_pinned_retained_directory(
                    run_descriptor,
                    path.parent.name,
                    owned_parent_descriptor,
                    parent_details,
                )
            return payload
        except RunStoreError:
            raise
        except OSError:
            raise RunStoreError("retained private object could not be read") from None
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if owned_parent_descriptor is not None:
                os.close(owned_parent_descriptor)

    def _read_pinned_private_entry(
        self,
        descriptor: int,
        details: os.stat_result,
        named_after: Callable[[], os.stat_result],
    ) -> bytes:
        opened = os.fstat(descriptor)
        chunks: list[bytes] = []
        remaining = max(MAX_RETAINED_PAYLOAD_BYTES, 256 * 1024) + 1
        while remaining > 0:
            block = os.read(descriptor, min(remaining, 64 * 1024))
            if not block:
                break
            chunks.append(block)
            remaining -= len(block)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
        named = named_after()
        if len(payload) != details.st_size or remaining == 0:
            raise RunStoreError("retained private object exceeds its reviewed bound")
        if (
            self._stable_private_identity(details) != self._stable_private_identity(opened)
            or self._stable_private_identity(opened) != self._stable_private_identity(after)
            or self._stable_private_identity(named) != self._stable_private_identity(after)
            or self._is_link_or_reparse(named)
            or named.st_nlink != 1
        ):
            raise RunStoreError("retained private object changed while it was read")
        if os.name == "nt":
            try:
                verify_owner_private_acl(descriptor, directory=False)
            except WindowsOwnerAclError:
                raise RunStoreError("retained private DACL changed while it was read") from None
        return payload

    def _verify_pinned_retained_directory(
        self, run_descriptor: int, name: str, descriptor: int, details: os.stat_result
    ) -> None:
        opened = os.fstat(descriptor)
        named = os.stat(name, dir_fd=run_descriptor, follow_symlinks=False)
        if (
            self._stable_private_identity(details) != self._stable_private_identity(opened)
            or self._stable_private_identity(named) != self._stable_private_identity(opened)
            or self._is_link_or_reparse(named)
            or stat.S_IMODE(named.st_mode) != 0o700
            or named.st_uid != self._posix_euid()
        ):
            raise RunStoreError("retained private directory changed")

    def _verify_retained_directory(
        self,
        directory: Path,
        expected: Mapping[str, bytes],
        *,
        run_descriptor: int | None = None,
    ) -> None:
        if os.name != "nt":
            if run_descriptor is None:
                raise RunStoreError("retained parent descriptor is unavailable")
            descriptor, details = self._open_verified_retained_entry_at(
                run_descriptor, directory.name, directory=True
            )
            try:
                try:
                    names = {entry.name for entry in os.scandir(descriptor)}
                except OSError:
                    raise RunStoreError("retained private inventory is unavailable") from None
                if names != set(expected):
                    raise RunStoreError("retained private inventory conflicts with this capture")
                for name, payload in expected.items():
                    if (
                        self._read_private_retained_entry(
                            directory / name, directory=False, parent_descriptor=descriptor
                        )
                        != payload
                    ):
                        raise RunStoreError("retained private capture is not byte-identical")
                self._verify_pinned_retained_directory(
                    run_descriptor, directory.name, descriptor, details
                )
            finally:
                os.close(descriptor)
            return
        descriptor, _ = self._open_verified_retained_entry(directory, directory=True)
        try:
            try:
                names = {entry.name for entry in os.scandir(directory)}
            except OSError:
                raise RunStoreError("retained private inventory is unavailable") from None
            if names != set(expected):
                raise RunStoreError("retained private inventory conflicts with this capture")
            for name, payload in expected.items():
                if self._read_private_retained_entry(directory / name, directory=False) != payload:
                    raise RunStoreError("retained private capture is not byte-identical")
        finally:
            os.close(descriptor)

    def _publish_retained_directory(
        self,
        run_path: Path,
        payloads: Mapping[str, bytes],
        *,
        run_descriptor: int | None = None,
    ) -> None:
        if os.name != "nt":
            if run_descriptor is None:
                raise RunStoreError("retained parent descriptor is unavailable")
            self._publish_retained_directory_at(run_path, run_descriptor, payloads)
            return
        temporary = Path(tempfile.mkdtemp(dir=run_path, prefix=_RETAINED_TEMP_PREFIX))
        published = False
        try:
            self._harden_retained_entry(temporary, directory=True)
            for name, payload in payloads.items():
                target = temporary / name
                self._atomic_write(target, payload)
                self._harden_retained_entry(target, directory=False)
            self._verify_retained_directory(temporary, payloads, run_descriptor=run_descriptor)
            self._fsync_directory(temporary)
            self._rename_retained_no_replace(
                run_path, temporary, RETAINED_PAYLOAD_DIRECTORY, directory=True
            )
            published = True
            self._fsync_directory(run_path)
        except FileExistsError:
            directory = run_path / RETAINED_PAYLOAD_DIRECTORY
            self._verify_retained_directory(directory, payloads, run_descriptor=run_descriptor)
        except RunStoreError:
            raise
        except OSError:
            raise RunStoreError("retained private capture publication failed safely") from None
        finally:
            if not published and temporary.exists():
                try:
                    for name in payloads:
                        child = temporary / name
                        if child.is_file() and not child.is_symlink():
                            child.unlink(missing_ok=True)
                    temporary.rmdir()
                except OSError:
                    pass

    def _publish_retained_directory_at(
        self, run_path: Path, run_descriptor: int, payloads: Mapping[str, bytes]
    ) -> None:
        temporary_name = _RETAINED_TEMP_PREFIX + uuid.uuid4().hex
        temporary_descriptor: int | None = None
        published = False
        try:
            os.mkdir(temporary_name, 0o700, dir_fd=run_descriptor)
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_DIRECTORY", 0)
            temporary_descriptor = os.open(temporary_name, flags, dir_fd=run_descriptor)
            self._posix_fchmod(temporary_descriptor, 0o700)
            temporary = run_path / temporary_name
            for name, payload in payloads.items():
                file_descriptor = os.open(
                    name,
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                    dir_fd=temporary_descriptor,
                )
                with os.fdopen(file_descriptor, "wb") as handle:
                    self._posix_fchmod(handle.fileno(), 0o600)
                    handle.write(payload)
                    handle.flush()
                    os.fsync(handle.fileno())
            self._verify_retained_directory(temporary, payloads, run_descriptor=run_descriptor)
            os.fsync(temporary_descriptor)
            self._rename_retained_no_replace(
                run_path,
                temporary,
                RETAINED_PAYLOAD_DIRECTORY,
                directory=True,
                parent_descriptor=run_descriptor,
            )
            published = True
            os.fsync(run_descriptor)
            self._verify_retained_directory(
                run_path / RETAINED_PAYLOAD_DIRECTORY,
                payloads,
                run_descriptor=run_descriptor,
            )
        except FileExistsError:
            self._verify_retained_directory(
                run_path / RETAINED_PAYLOAD_DIRECTORY,
                payloads,
                run_descriptor=run_descriptor,
            )
        except RunStoreError:
            raise
        except OSError:
            raise RunStoreError("retained private capture publication failed safely") from None
        finally:
            if not published and temporary_descriptor is not None:
                for name in payloads:
                    try:
                        os.unlink(name, dir_fd=temporary_descriptor)
                    except OSError:
                        pass
                try:
                    os.rmdir(temporary_name, dir_fd=run_descriptor)
                except OSError:
                    pass
            if temporary_descriptor is not None:
                os.close(temporary_descriptor)

    def _rename_retained_no_replace(
        self,
        parent: Path,
        source: Path,
        target_name: str,
        *,
        directory: bool,
        parent_descriptor: int | None = None,
    ) -> None:
        owned_parent_descriptor: int | None = None
        try:
            if os.name == "nt":
                owned_parent_descriptor = _windows_open_descriptor(parent, directory=True)
                # Windows ``rename`` is no-replace.  Holding the verified
                # owner-private parent without share-delete pins its namespace
                # for the operation; the source remains in that same parent.
                os.rename(source, parent / target_name)
            else:
                if parent_descriptor is None:
                    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_DIRECTORY", 0)
                    owned_parent_descriptor = os.open(parent, flags)
                    parent_descriptor = owned_parent_descriptor
                from .source_intake import _posix_rename_no_replace

                _posix_rename_no_replace(parent_descriptor, source.name, target_name)
        finally:
            if owned_parent_descriptor is not None:
                os.close(owned_parent_descriptor)

    def _read_run_file_at(self, run_descriptor: int, name: str) -> bytes | None:
        """Read a public run projection through the pinned POSIX run directory."""

        try:
            details = os.stat(name, dir_fd=run_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return None
        except OSError:
            raise RunStoreError("retained public projection is unavailable") from None
        if (
            self._is_link_or_reparse(details)
            or not stat.S_ISREG(details.st_mode)
            or details.st_nlink != 1
        ):
            raise RunStoreError("retained public projection is unsafe")
        descriptor: int | None = None
        try:
            descriptor = os.open(
                name,
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=run_descriptor,
            )
            opened = os.fstat(descriptor)
            chunks: list[bytes] = []
            while block := os.read(descriptor, 64 * 1024):
                chunks.append(block)
            after = os.fstat(descriptor)
            named = os.stat(name, dir_fd=run_descriptor, follow_symlinks=False)
            if (
                self._stable_private_identity(details) != self._stable_private_identity(opened)
                or self._stable_private_identity(opened) != self._stable_private_identity(after)
                or self._stable_private_identity(named) != self._stable_private_identity(after)
                or self._is_link_or_reparse(named)
                or len(b"".join(chunks)) != after.st_size
            ):
                raise RunStoreError("retained public projection changed while read")
            return b"".join(chunks)
        except RunStoreError:
            raise
        except OSError:
            raise RunStoreError("retained public projection is unavailable") from None
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def _write_run_file_at(
        self, run_descriptor: int, name: str, payload: bytes, *, replace: bool
    ) -> None:
        temporary_name = f".{name}.{uuid.uuid4().hex}.tmp"
        temporary_created = False
        try:
            descriptor = os.open(
                temporary_name,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=run_descriptor,
            )
            temporary_created = True
            with os.fdopen(descriptor, "wb") as handle:
                self._posix_fchmod(handle.fileno(), 0o600)
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            if replace:
                os.replace(
                    temporary_name,
                    name,
                    src_dir_fd=run_descriptor,
                    dst_dir_fd=run_descriptor,
                )
            else:
                from .source_intake import _posix_rename_no_replace

                _posix_rename_no_replace(run_descriptor, temporary_name, name)
            temporary_created = False
            os.fsync(run_descriptor)
        finally:
            if temporary_created:
                try:
                    os.unlink(temporary_name, dir_fd=run_descriptor)
                except OSError:
                    pass

    def _publish_exact_file(
        self,
        parent: Path,
        name: str,
        payload: bytes,
        *,
        run_descriptor: int | None = None,
    ) -> None:
        if os.name != "nt":
            if run_descriptor is None:
                raise RunStoreError("retained parent descriptor is unavailable")
            previous = self._read_run_file_at(run_descriptor, name)
            if previous is not None:
                if previous != payload:
                    raise RunStoreError("retained public projection conflicts with this capture")
                return
            try:
                self._write_run_file_at(run_descriptor, name, payload, replace=False)
            except FileExistsError:
                pass
            self._verify_exact_file(parent / name, payload, run_descriptor=run_descriptor)
            return
        target = self._contained_child(parent, name)
        if target.exists():
            self._verify_exact_file(target, payload)
            return
        descriptor, temporary_name = tempfile.mkstemp(dir=parent, prefix=f".{name}.", suffix=".tmp")
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            self._rename_retained_no_replace(parent, temporary, name, directory=False)
            self._fsync_directory(parent)
        except FileExistsError:
            self._verify_exact_file(target, payload)
        finally:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
        self._verify_exact_file(target, payload)

    def _verify_exact_file(
        self, path: Path, payload: bytes, *, run_descriptor: int | None = None
    ) -> None:
        if os.name != "nt":
            if run_descriptor is None:
                raise RunStoreError("retained parent descriptor is unavailable")
            if self._read_run_file_at(run_descriptor, path.name) != payload:
                raise RunStoreError("retained public projection conflicts with this capture")
            return
        try:
            if path.is_symlink() or path.read_bytes() != payload:
                raise RunStoreError("retained public projection conflicts with this capture")
        except RunStoreError:
            raise
        except OSError:
            raise RunStoreError("retained public projection is unavailable") from None

    def _append_exact_retained_event(
        self,
        run_id: str,
        run_path: Path,
        event: Mapping[str, Any],
        *,
        run_descriptor: int | None = None,
    ) -> None:
        if os.name != "nt":
            if run_descriptor is None:
                raise RunStoreError("retained parent descriptor is unavailable")
            self._append_exact_retained_event_at(run_descriptor, event)
            return
        expected_data = {
            **event["data"],
            "capture_digest": event["capture_digest"],
        }
        rows = self.read_events(run_id)
        matches = [
            row
            for row in rows
            if row.get("event_type") == event["event_type"]
            and row.get("data", {}).get("capture_digest") == event["capture_digest"]
        ]
        if matches:
            if len(matches) != 1 or matches[0].get("data") != expected_data:
                raise RunStoreError("retained event projection conflicts with this capture")
            return
        target = self._contained_child(run_path, "events.jsonl")
        previous_sequence, previous_hash = self._last_event_state(target)
        body = {
            "schema_version": "1.0",
            "sequence": previous_sequence + 1,
            "timestamp": utc_now(),
            "event_type": event["event_type"],
            "data": expected_data,
            "previous_event_hash": previous_hash,
        }
        row = {**body, "event_hash": content_hash(body)}
        try:
            previous = target.read_bytes() if target.exists() else b""
        except OSError:
            raise RunStoreError("retained event projection is unavailable") from None
        if previous and not previous.endswith(b"\n"):
            raise RunStoreError("retained event projection is incomplete")
        self._atomic_write(target, previous + canonical_json_bytes(row) + b"\n")
        self._fsync_directory(run_path)
        matches = [
            item
            for item in self.read_events(run_id)
            if item.get("event_type") == event["event_type"]
            and item.get("data", {}).get("capture_digest") == event["capture_digest"]
        ]
        if len(matches) != 1 or matches[0].get("data") != expected_data:
            raise RunStoreError("retained event projection was not published exactly once")

    def _append_exact_retained_event_at(
        self, run_descriptor: int, event: Mapping[str, Any]
    ) -> None:
        expected_data = {**event["data"], "capture_digest": event["capture_digest"]}
        previous = self._read_run_file_at(run_descriptor, "events.jsonl") or b""
        if previous and not previous.endswith(b"\n"):
            raise RunStoreError("retained event projection is incomplete")
        rows: list[Mapping[str, Any]] = []
        previous_hash: str | None = None
        try:
            lines = previous.decode("utf-8").splitlines()
        except UnicodeDecodeError:
            raise RunStoreError("retained event projection is unavailable") from None
        for line in lines:
            if not line.strip():
                continue
            row = self._validated_event_row(
                line, expected_sequence=len(rows) + 1, previous_hash=previous_hash
            )
            rows.append(row)
            previous_hash = str(row["event_hash"])
        matches = [
            row
            for row in rows
            if row.get("event_type") == event["event_type"]
            and row.get("data", {}).get("capture_digest") == event["capture_digest"]
        ]
        if matches:
            if len(matches) != 1 or matches[0].get("data") != expected_data:
                raise RunStoreError("retained event projection conflicts with this capture")
            return
        body = {
            "schema_version": "1.0",
            "sequence": len(rows) + 1,
            "timestamp": utc_now(),
            "event_type": event["event_type"],
            "data": expected_data,
            "previous_event_hash": previous_hash,
        }
        row = {**body, "event_hash": content_hash(body)}
        if self._read_run_file_at(run_descriptor, "events.jsonl") != (previous or None):
            raise RunStoreError("retained event projection changed before publication")
        desired = previous + canonical_json_bytes(row) + b"\n"
        self._write_run_file_at(run_descriptor, "events.jsonl", desired, replace=True)
        if self._read_run_file_at(run_descriptor, "events.jsonl") != desired:
            raise RunStoreError("retained event projection was not published exactly once")

    def _run_path(self, run_id: str, *, must_exist: bool) -> Path:
        if not RUN_ID_RE.fullmatch(run_id):
            raise RunStoreError("invalid run identifier")
        candidate = self.root / run_id
        try:
            details = candidate.lstat()
        except FileNotFoundError:
            details = None
        except OSError:
            raise RunStoreError("run path is unavailable") from None
        if details is not None and self._is_link_or_reparse(details):
            raise RunStoreError("run path escapes the configured output root")
        if details is not None and not stat.S_ISDIR(details.st_mode):
            raise RunStoreError("run path is not an exact directory")
        if must_exist and not candidate.is_dir():
            raise RunStoreError(f"unknown run: {run_id}")
        resolved = candidate.resolve(strict=must_exist)
        if resolved.parent != self.root or resolved.name != run_id:
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
