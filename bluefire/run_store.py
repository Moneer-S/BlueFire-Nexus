"""Tamper-evident, path-contained storage for BlueFire run bundles."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from .retained_artifact_contract import MAX_BYTES as MAX_RETAINED_PAYLOAD_BYTES
from .util import (
    canonical_json_bytes,
    content_hash,
    file_hash,
    json_clone,
    parse_iso8601_datetime,
)
from .windows_owner_acl import (
    WindowsOwnerAclError,
    _windows_extended_path,
    _windows_mark_delete_descriptor,
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
_PUBLICATION_TEMP_PREFIX = ".run-publish-tmp-"
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_MAX_PUBLICATION_RECORDS = 512
_MAX_PUBLICATION_RECORD_BYTES = 256 * 1024
_MAX_PUBLICATION_FILE_BYTES = 4 * 1024 * 1024
_MAX_PUBLICATION_TOTAL_BYTES = 16 * 1024 * 1024


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
        candidate.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        created_root_identity: tuple[int, int, int] | None = None
        try:
            candidate.mkdir(mode=0o700, exist_ok=False)
        except FileExistsError:
            pass
        else:
            created = candidate.lstat()
            if self._is_link_or_reparse(created) or not stat.S_ISDIR(created.st_mode):
                raise RunStoreError("new run store root is unsafe")
            created_root_identity = self._filesystem_identity(created)
        self.root = candidate.resolve(strict=True)
        if not self.root.is_dir():
            raise RunStoreError("run store root must be a directory")
        self._publication_created_root_identity = created_root_identity
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
                path.mkdir(mode=0o700, exist_ok=False)
            except FileExistsError:
                if _reserved_run_id is not None:
                    raise RunStoreError("reserved run identity already exists") from None
                continue
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

    def publish_finalized_run(
        self,
        run_id: str,
        *,
        created_at: str,
        finalized_at: str,
        scenario: Mapping[str, Any],
        plan: Mapping[str, Any],
        policy: Mapping[str, Any],
        profile: Mapping[str, Any] | None,
        result: Mapping[str, Any],
        evidence: Iterable[Mapping[str, Any]],
        detections: Iterable[Mapping[str, Any]],
        replay: Mapping[str, Any] | None = None,
    ) -> Mapping[str, Any]:
        """Atomically publish one complete, deterministic, preassigned run bundle.

        This is a narrow controller-side publication seam for work whose run
        identity is already retained before independent evidence is available.
        The complete bundle is staged and fsynced before one same-volume rename
        makes it visible. A retry may only reopen the byte-identical finalized
        bundle; an existing partial or conflicting directory is never adopted,
        repaired, replaced, or deleted.
        """

        temporary: Path | None = None
        temporary_identity: tuple[int, int, int] | None = None
        root_identity: tuple[int, int, int] | None = None
        staged_identities: dict[str, tuple[int, int, int]] = {}
        root_guard_descriptor: int | None = None
        try:
            self._prepare_publication_root()
            root_identity = self._validated_publication_root_identity()
            if os.name == "nt":
                root_guard_descriptor = _windows_open_descriptor(self.root, directory=True)
                guarded_root = os.fstat(root_guard_descriptor)
                verify_owner_private_acl(root_guard_descriptor, directory=True)
                if self._filesystem_identity(guarded_root) != root_identity:
                    raise RunStoreError("atomic run publication root changed during publication")
            payloads, manifest = self._finalized_publication_payloads(
                run_id,
                created_at=created_at,
                finalized_at=finalized_at,
                scenario=scenario,
                plan=plan,
                policy=policy,
                profile=profile,
                result=result,
                evidence=evidence,
                detections=detections,
                replay=replay,
            )
            temporary = Path(tempfile.mkdtemp(dir=self.root, prefix=_PUBLICATION_TEMP_PREFIX))
            self._require_publication_root_identity(root_identity)
            self._harden_publication_entry(temporary, directory=True)
            temporary_details = temporary.lstat()
            if self._is_link_or_reparse(temporary_details) or not stat.S_ISDIR(
                temporary_details.st_mode
            ):
                raise RunStoreError("atomic run staging identity is unsafe")
            temporary_identity = self._filesystem_identity(temporary_details)
            for name, payload in payloads.items():
                # On Windows the held root handle denies root replacement. On
                # POSIX the owner-private root makes same-UID writers trusted
                # cooperative peers; identity checks bracket every path write.
                self._require_publication_root_identity(root_identity)
                self._atomic_write(temporary / name, payload)
                self._harden_publication_entry(temporary / name, directory=False)
                staged = (temporary / name).lstat()
                if (
                    self._is_link_or_reparse(staged)
                    or not stat.S_ISREG(staged.st_mode)
                    or staged.st_nlink != 1
                ):
                    raise RunStoreError("atomic run staging inventory is unsafe")
                staged_identities[name] = self._filesystem_identity(staged)
                self._require_publication_root_identity(root_identity)
            self._verify_publication_directory(
                temporary,
                payloads,
                expected_directory_identity=temporary_identity,
                expected_root_identity=root_identity,
                staged_identities=staged_identities,
            )
            self._fsync_publication_directory(temporary, temporary_identity)
            target = self._publication_target(run_id)
            if target is not None:
                self._verify_exact_publication(
                    run_id,
                    payloads,
                    manifest,
                    expected_root_identity=root_identity,
                )
                self._fsync_publication_directory(self.root, root_identity)
                return dict(json_clone(manifest))
            try:
                published_root_identity = self._publish_directory_no_replace(
                    temporary,
                    self.root / run_id,
                    temporary_identity=temporary_identity,
                    expected_root_identity=root_identity,
                    payloads=payloads,
                    staged_identities=staged_identities,
                )
            except FileExistsError:
                if self._publication_target(run_id) is not None:
                    self._verify_exact_publication(
                        run_id,
                        payloads,
                        manifest,
                        expected_root_identity=root_identity,
                    )
                    self._fsync_publication_directory(self.root, root_identity)
                    return dict(json_clone(manifest))
                raise
            temporary = None
            temporary_identity = None
            staged_identities = {}
            self._fsync_publication_directory(self.root, published_root_identity)
            self._verify_exact_publication(
                run_id,
                payloads,
                manifest,
                expected_root_identity=root_identity,
            )
            return dict(json_clone(manifest))
        except RunStoreError:
            raise
        except Exception:
            raise RunStoreError("atomic run publication failed safely") from None
        finally:
            if temporary is not None and temporary_identity is not None:
                self._clean_publication_staging(
                    temporary,
                    temporary_identity,
                    staged_identities,
                    expected_root_identity=root_identity,
                )
            if root_guard_descriptor is not None:
                os.close(root_guard_descriptor)

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

    def write_retained_payload(self, run_id: str, payload: bytes) -> None:
        """Publish one private immutable payload, separately from sealed history."""
        if not isinstance(payload, bytes) or not 1 <= len(payload) <= MAX_RETAINED_PAYLOAD_BYTES:
            raise RunStoreError("retained payload exceeds its reviewed byte bound")
        run_path = self._run_path(run_id, must_exist=True)
        directory = self._contained_child(run_path, RETAINED_PAYLOAD_DIRECTORY)
        with self._lock(run_id):
            directory.mkdir(mode=0o700, exist_ok=False)
            target = self._contained_child(directory, RETAINED_PAYLOAD_NAME)
            self._atomic_write(target, payload)

    def read_retained_payload(self, run_id: str) -> bytes:
        """Read only the fixed private payload through the pinned observer."""
        from .evidence import SandboxObserver

        run_path = self._run_path(run_id, must_exist=True)
        captured: list[bytes] = []
        observer = SandboxObserver(run_path, max_file_bytes=MAX_RETAINED_PAYLOAD_BYTES)
        observer.observe_file(
            relative_path=f"{RETAINED_PAYLOAD_DIRECTORY}/{RETAINED_PAYLOAD_NAME}",
            run_id=run_id,
            step_id="retained_payload",
            behavior_id="bluefire.retained-payload-read.v1",
            action_id="bluefire.retained-payload-read.v1",
            runner_profile_id="bluefire.run-store.v1",
            _validated_content_sink=captured.append,
            _max_content_bytes=MAX_RETAINED_PAYLOAD_BYTES,
        )
        return captured[0]

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

    def _finalized_publication_payloads(
        self,
        run_id: str,
        *,
        created_at: str,
        finalized_at: str,
        scenario: Mapping[str, Any],
        plan: Mapping[str, Any],
        policy: Mapping[str, Any],
        profile: Mapping[str, Any] | None,
        result: Mapping[str, Any],
        evidence: Iterable[Mapping[str, Any]],
        detections: Iterable[Mapping[str, Any]],
        replay: Mapping[str, Any] | None,
    ) -> tuple[dict[str, bytes], dict[str, Any]]:
        if not isinstance(run_id, str) or RUN_ID_RE.fullmatch(run_id) is None:
            raise RunStoreError("reserved run identity is invalid")
        created = self._publication_timestamp(created_at, "run creation time")
        finalized = self._publication_timestamp(finalized_at, "run finalization time")
        if parse_iso8601_datetime(finalized) < parse_iso8601_datetime(created):
            raise RunStoreError("run finalization predates its creation")

        def document(value: Any, label: str) -> dict[str, Any]:
            try:
                copied = json_clone(value)
            except Exception:
                raise RunStoreError(f"{label} could not be read safely") from None
            if not isinstance(copied, dict):
                raise RunStoreError(f"{label} must contain a JSON object")
            return copied

        retained_record_bytes = 0
        retained_record_count = 0

        def records(values: Iterable[Mapping[str, Any]], label: str) -> list[dict[str, Any]]:
            nonlocal retained_record_bytes, retained_record_count
            copied: list[dict[str, Any]] = []
            try:
                iterator = iter(values)
            except Exception:
                raise RunStoreError(f"{label} input could not be read safely") from None
            while True:
                try:
                    value = next(iterator)
                except StopIteration:
                    break
                except Exception:
                    raise RunStoreError(f"{label} input could not be read safely") from None
                if retained_record_count >= _MAX_PUBLICATION_RECORDS:
                    raise RunStoreError(f"{label} count exceeds its reviewed bound")
                retained = document(value, label)
                try:
                    retained_bytes = len(canonical_json_bytes(retained))
                except Exception:
                    raise RunStoreError(f"{label} could not be serialized safely") from None
                if retained_bytes > _MAX_PUBLICATION_RECORD_BYTES:
                    raise RunStoreError(f"{label} exceeds its reviewed byte bound")
                retained_record_bytes += retained_bytes
                retained_record_count += 1
                if retained_record_bytes > _MAX_PUBLICATION_TOTAL_BYTES:
                    raise RunStoreError("publication records exceed their reviewed byte bound")
                copied.append(retained)
            return copied

        scenario_value = document(scenario, "scenario")
        plan_value = document(plan, "plan")
        policy_value = document(policy, "policy")
        profile_value = {} if profile is None else document(profile, "profile")
        replay_value = None if not replay else document(replay, "replay")
        result_value = document(result, "result")
        for name, expected in (
            ("run_id", run_id),
            ("created_at", created),
            ("finalized_at", finalized),
        ):
            supplied = result_value.get(name, expected)
            if supplied != expected:
                raise RunStoreError(f"run {name.replace('_', ' ')} changed before publication")
            result_value[name] = expected

        acceptance_binding = _acceptance_binding()
        supplied_binding = result_value.get("acceptance_binding")
        if acceptance_binding is None:
            if supplied_binding is not None:
                raise RunStoreError("acceptance run binding cannot be supplied by a caller")
        else:
            if supplied_binding not in (None, acceptance_binding):
                raise RunStoreError("acceptance run binding changed before publication")
            result_value["acceptance_binding"] = acceptance_binding

        evidence_values = records(evidence, "evidence record")
        detection_values = records(detections, "detection candidate")
        created_data: dict[str, Any] = {
            "schema_version": "1.0",
            "run_id": run_id,
            "created_at": created,
            "status": "created",
            "replay": replay_value,
        }
        if acceptance_binding is not None:
            created_data["acceptance_binding"] = acceptance_binding
        created_event = self._publication_event(
            sequence=1,
            timestamp=created,
            event_type="run.created",
            data=created_data,
            previous_event_hash=None,
        )
        finalized_event = self._publication_event(
            sequence=2,
            timestamp=finalized,
            event_type="run.finalized",
            data=result_value,
            previous_event_hash=str(created_event["event_hash"]),
        )
        payloads = {
            "scenario.json": canonical_json_bytes(scenario_value) + b"\n",
            "plan.json": canonical_json_bytes(plan_value) + b"\n",
            "policy.json": canonical_json_bytes(policy_value) + b"\n",
            "profile.json": canonical_json_bytes(profile_value) + b"\n",
            "result.json": canonical_json_bytes(result_value) + b"\n",
            "evidence.json": canonical_json_bytes(
                {"schema_version": "1.0", "records": evidence_values}
            )
            + b"\n",
            "detections.json": canonical_json_bytes(
                {"schema_version": "1.0", "candidates": detection_values}
            )
            + b"\n",
            "events.jsonl": b"".join(
                canonical_json_bytes(event) + b"\n" for event in (created_event, finalized_event)
            ),
        }
        files = {
            name: {
                "hash": "sha256:" + hashlib.sha256(payload).hexdigest(),
                "size_bytes": len(payload),
            }
            for name, payload in sorted(payloads.items())
        }
        manifest = {
            "schema_version": "1.0",
            "run_id": run_id,
            "files": files,
            "bundle_hash": content_hash(files),
        }
        payloads["manifest.json"] = canonical_json_bytes(manifest) + b"\n"
        if (
            any(
                not 1 <= len(payload) <= _MAX_PUBLICATION_FILE_BYTES
                for payload in payloads.values()
            )
            or sum(len(payload) for payload in payloads.values()) > _MAX_PUBLICATION_TOTAL_BYTES
        ):
            raise RunStoreError("atomic run publication exceeds its reviewed byte bound")
        return payloads, manifest

    @staticmethod
    def _publication_timestamp(value: Any, label: str) -> str:
        if not isinstance(value, str) or not value or len(value) > 40:
            raise RunStoreError(f"{label} is invalid")
        try:
            parsed = parse_iso8601_datetime(value)
        except ValueError as exc:
            raise RunStoreError(f"{label} is invalid") from exc
        if parsed.isoformat().replace("+00:00", "Z") != value:
            raise RunStoreError(f"{label} is not canonical")
        return value

    @staticmethod
    def _publication_event(
        *,
        sequence: int,
        timestamp: str,
        event_type: str,
        data: Mapping[str, Any],
        previous_event_hash: str | None,
    ) -> dict[str, Any]:
        body = {
            "schema_version": "1.0",
            "sequence": sequence,
            "timestamp": timestamp,
            "event_type": event_type,
            "data": dict(json_clone(data)),
            "previous_event_hash": previous_event_hash,
        }
        return {**body, "event_hash": content_hash(body)}

    def _publication_target(self, run_id: str) -> Path | None:
        if not isinstance(run_id, str) or RUN_ID_RE.fullmatch(run_id) is None:
            raise RunStoreError("invalid run identifier")
        target = self.root / run_id
        try:
            details = target.lstat()
        except FileNotFoundError:
            return None
        except OSError:
            raise RunStoreError("existing run publication is unreadable") from None
        if self._is_link_or_reparse(details) or not stat.S_ISDIR(details.st_mode):
            raise RunStoreError("existing run publication path is unsafe")
        try:
            resolved = target.resolve(strict=True)
        except OSError:
            raise RunStoreError("existing run publication is unreadable") from None
        if resolved.parent != self.root or resolved != target:
            raise RunStoreError("existing run publication path is unsafe")
        return resolved

    def _verify_exact_publication(
        self,
        run_id: str,
        payloads: Mapping[str, bytes],
        expected_manifest: Mapping[str, Any],
        *,
        expected_root_identity: tuple[int, int, int],
    ) -> None:
        self._require_publication_root_identity(expected_root_identity)
        run_path = self._publication_target(run_id)
        if run_path is None:
            raise RunStoreError("atomic run publication is unavailable")
        directory_identity = self._filesystem_identity(run_path.lstat())
        self._verify_publication_directory(
            run_path,
            payloads,
            expected_directory_identity=directory_identity,
            expected_root_identity=expected_root_identity,
            staged_identities=None,
        )
        try:
            manifest = json.loads(payloads["manifest.json"])
        except (KeyError, UnicodeDecodeError, json.JSONDecodeError):
            raise RunStoreError("existing run publication failed integrity validation") from None
        if manifest != expected_manifest:
            raise RunStoreError("existing run publication failed integrity validation")
        self._require_publication_root_identity(expected_root_identity)

    def _verify_publication_directory(
        self,
        directory: Path,
        payloads: Mapping[str, bytes],
        *,
        expected_directory_identity: tuple[int, int, int],
        expected_root_identity: tuple[int, int, int],
        staged_identities: Mapping[str, tuple[int, int, int]] | None,
    ) -> None:
        self._require_publication_root_identity(expected_root_identity)
        try:
            directory_details = directory.lstat()
        except OSError:
            raise RunStoreError("existing run publication is unreadable") from None
        if (
            self._is_link_or_reparse(directory_details)
            or not stat.S_ISDIR(directory_details.st_mode)
            or self._filesystem_identity(directory_details) != expected_directory_identity
        ):
            raise RunStoreError("existing run publication path is unsafe")
        expected_names = frozenset(payloads)
        names: list[str] = []
        try:
            with os.scandir(directory) as entries:
                for directory_entry in entries:
                    if len(names) >= len(expected_names) + 1:
                        raise RunStoreError("existing run publication is not byte-identical")
                    names.append(directory_entry.name)
        except RunStoreError:
            raise
        except OSError:
            raise RunStoreError("existing run publication is unreadable") from None
        if len(names) != len(expected_names) or frozenset(names) != expected_names:
            raise RunStoreError("existing run publication is not byte-identical")
        self._verify_private_publication_entry(directory, directory=True)
        if staged_identities is not None and frozenset(staged_identities) != expected_names:
            raise RunStoreError("atomic run staging inventory is incomplete")
        for name in names:
            expected_payload = payloads[name]
            entry_path = directory / name
            try:
                details = entry_path.lstat()
            except OSError:
                raise RunStoreError("existing run publication is unreadable") from None
            identity = self._filesystem_identity(details)
            if (
                self._is_link_or_reparse(details)
                or not stat.S_ISREG(details.st_mode)
                or details.st_nlink != 1
                or (staged_identities is not None and staged_identities.get(name) != identity)
            ):
                raise RunStoreError("existing run publication inventory is unsafe")
            if details.st_size != len(expected_payload):
                raise RunStoreError("existing run publication is not byte-identical")
            self._verify_private_publication_entry(entry_path, directory=False)
            if (
                self._read_exact_publication_entry(
                    entry_path,
                    expected_identity=identity,
                    expected_bytes=len(expected_payload),
                )
                != expected_payload
            ):
                raise RunStoreError("existing run publication is not byte-identical")
        if self._filesystem_identity(directory.lstat()) != expected_directory_identity:
            raise RunStoreError("existing run publication path changed during verification")
        self._require_publication_root_identity(expected_root_identity)

    def _read_exact_publication_entry(
        self,
        path: Path,
        *,
        expected_identity: tuple[int, int, int],
        expected_bytes: int,
    ) -> bytes:
        descriptor: int | None = None
        try:
            if os.name == "nt":
                descriptor = _windows_open_descriptor(path, directory=False)
            else:
                flags = os.O_RDONLY
                flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
                descriptor = os.open(path, flags)
            opened = os.fstat(descriptor)
            if (
                self._is_link_or_reparse(opened)
                or not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
                or opened.st_size != expected_bytes
                or self._filesystem_identity(opened) != expected_identity
            ):
                raise RunStoreError("existing run publication inventory is unsafe")
            chunks: list[bytes] = []
            remaining = expected_bytes + 1
            while remaining > 0:
                chunk = os.read(descriptor, min(remaining, 64 * 1024))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            payload = b"".join(chunks)
            if len(payload) != expected_bytes:
                raise RunStoreError("existing run publication is not byte-identical")
            return payload
        except RunStoreError:
            raise
        except OSError:
            raise RunStoreError("existing run publication is unreadable") from None
        finally:
            if descriptor is not None:
                os.close(descriptor)

    @staticmethod
    def _is_link_or_reparse(details: os.stat_result) -> bool:
        attributes = int(getattr(details, "st_file_attributes", 0))
        return stat.S_ISLNK(details.st_mode) or bool(attributes & _REPARSE_POINT)

    @staticmethod
    def _filesystem_identity(details: os.stat_result) -> tuple[int, int, int]:
        return int(details.st_dev), int(details.st_ino), stat.S_IFMT(details.st_mode)

    def _require_publication_root_identity(self, expected_identity: tuple[int, int, int]) -> None:
        if self._validated_publication_root_identity() != expected_identity:
            raise RunStoreError("atomic run publication root changed during publication")

    def _prepare_publication_root(self) -> None:
        """Harden only an exact root created by this store for atomic publication."""

        created_identity = self._publication_created_root_identity
        if created_identity is None:
            return
        try:
            current = self.root.lstat()
        except OSError:
            raise RunStoreError("new run store root changed before publication") from None
        if self._filesystem_identity(current) != created_identity:
            raise RunStoreError("new run store root changed before publication")
        if os.name != "nt":
            self._publication_created_root_identity = None
            return
        descriptor: int | None = None
        try:
            descriptor = _windows_open_descriptor(
                self.root,
                directory=True,
                write_dac=True,
            )
            if self._filesystem_identity(os.fstat(descriptor)) != created_identity:
                raise RunStoreError("new run store root changed before publication")
            apply_owner_private_acl(descriptor, directory=True)
            verify_owner_private_acl(descriptor, directory=True)
        except (OSError, WindowsOwnerAclError):
            raise RunStoreError("new run store root could not be made owner-private") from None
        finally:
            if descriptor is not None:
                os.close(descriptor)
        self._publication_created_root_identity = None

    def _validated_publication_root_identity(self) -> tuple[int, int, int]:
        try:
            details = self.root.lstat()
        except OSError:
            raise RunStoreError("atomic run publication root is unavailable") from None
        if self._is_link_or_reparse(details) or not stat.S_ISDIR(details.st_mode):
            raise RunStoreError("atomic run publication root is unsafe")
        if os.name == "nt":
            descriptor: int | None = None
            try:
                descriptor = _windows_open_descriptor(self.root, directory=True)
                verify_owner_private_acl(descriptor, directory=True)
            except (OSError, WindowsOwnerAclError):
                raise RunStoreError(
                    "atomic run publication root lacks an owner-private DACL"
                ) from None
            finally:
                if descriptor is not None:
                    os.close(descriptor)
        else:
            get_effective_user = getattr(os, "geteuid", None)
            if (
                callable(get_effective_user)
                and details.st_uid != get_effective_user()
                or details.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            ):
                raise RunStoreError("atomic run publication root is not owner-private")
            self._validate_publication_ancestor_chain()
        return self._filesystem_identity(details)

    def _validate_publication_ancestor_chain(self) -> None:
        """Prove another UID cannot rename the owner-private publication root."""

        get_effective_user = getattr(os, "geteuid", None)
        if not callable(get_effective_user):
            raise RunStoreError("atomic run publication owner identity is unavailable")
        owner = int(get_effective_user())
        child = self.root
        while True:
            parent = child.parent
            try:
                child_details = child.lstat()
                parent_details = parent.lstat()
            except OSError:
                raise RunStoreError(
                    "atomic run publication ancestor chain is unavailable"
                ) from None
            if (
                self._is_link_or_reparse(child_details)
                or self._is_link_or_reparse(parent_details)
                or not stat.S_ISDIR(child_details.st_mode)
                or not stat.S_ISDIR(parent_details.st_mode)
            ):
                raise RunStoreError("atomic run publication ancestor chain is unsafe")
            if parent_details.st_uid not in {0, owner}:
                raise RunStoreError("atomic run publication ancestor owner is untrusted")
            parent_writable = bool(parent_details.st_mode & (stat.S_IWGRP | stat.S_IWOTH))
            if parent_writable and (
                not parent_details.st_mode & stat.S_ISVTX or child_details.st_uid != owner
            ):
                raise RunStoreError("atomic run publication ancestor chain permits replacement")
            if parent == child:
                return
            child = parent

    def _harden_publication_entry(self, path: Path, *, directory: bool) -> None:
        if os.name == "nt":
            descriptor: int | None = None
            try:
                descriptor = _windows_open_descriptor(
                    path,
                    directory=directory,
                    write_dac=True,
                )
                apply_owner_private_acl(descriptor, directory=directory)
            except (OSError, WindowsOwnerAclError):
                raise RunStoreError("atomic run staging permissions are unavailable") from None
            finally:
                if descriptor is not None:
                    os.close(descriptor)
        self._verify_private_publication_entry(path, directory=directory)

    def _verify_private_publication_entry(self, path: Path, *, directory: bool) -> None:
        if os.name == "nt":
            descriptor: int | None = None
            try:
                descriptor = _windows_open_descriptor(path, directory=directory)
                verify_owner_private_acl(descriptor, directory=directory)
            except (OSError, WindowsOwnerAclError):
                raise RunStoreError("atomic run publication permissions are unsafe") from None
            finally:
                if descriptor is not None:
                    os.close(descriptor)
            return
        try:
            details = path.lstat()
        except OSError:
            raise RunStoreError("atomic run publication permissions are unavailable") from None
        get_effective_user = getattr(os, "geteuid", None)
        expected_mode = 0o700 if directory else 0o600
        if (
            self._is_link_or_reparse(details)
            or stat.S_ISDIR(details.st_mode) is not directory
            or stat.S_IMODE(details.st_mode) != expected_mode
            or (callable(get_effective_user) and details.st_uid != get_effective_user())
        ):
            raise RunStoreError("atomic run publication permissions are unsafe")

    def _publish_directory_no_replace(
        self,
        temporary: Path,
        target: Path,
        *,
        temporary_identity: tuple[int, int, int],
        expected_root_identity: tuple[int, int, int],
        payloads: Mapping[str, bytes],
        staged_identities: Mapping[str, tuple[int, int, int]],
    ) -> tuple[int, int, int]:
        root_descriptor: int | None = None
        temporary_descriptor: int | None = None
        try:
            self._verify_publication_directory(
                temporary,
                payloads,
                expected_directory_identity=temporary_identity,
                expected_root_identity=expected_root_identity,
                staged_identities=staged_identities,
            )
            root_details = self.root.lstat()
            temporary_details = temporary.lstat()
            root_identity = self._filesystem_identity(root_details)
            if (
                target.parent != self.root
                or target.name != target.name.strip()
                or not RUN_ID_RE.fullmatch(target.name)
                or temporary.parent != self.root
                or not temporary.name.startswith(_PUBLICATION_TEMP_PREFIX)
                or self._is_link_or_reparse(root_details)
                or not stat.S_ISDIR(root_details.st_mode)
                or root_identity != expected_root_identity
                or self._is_link_or_reparse(temporary_details)
                or not stat.S_ISDIR(temporary_details.st_mode)
                or self._filesystem_identity(temporary_details) != temporary_identity
            ):
                raise OSError("atomic run publication identity is unsafe")
            if os.name == "nt":
                root_descriptor = _windows_open_descriptor(
                    self.root,
                    directory=True,
                )
                temporary_descriptor = _windows_open_descriptor(
                    temporary,
                    directory=True,
                    delete=True,
                    share_delete=True,
                )
            else:
                flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
                root_descriptor = os.open(self.root, flags)
                temporary_descriptor = os.open(
                    temporary.name,
                    flags,
                    dir_fd=root_descriptor,
                )
            opened_root = os.fstat(root_descriptor)
            opened_temporary = os.fstat(temporary_descriptor)
            if (
                self._is_link_or_reparse(opened_root)
                or not stat.S_ISDIR(opened_root.st_mode)
                or self._filesystem_identity(opened_root) != root_identity
                or self._is_link_or_reparse(opened_temporary)
                or not stat.S_ISDIR(opened_temporary.st_mode)
                or self._filesystem_identity(opened_temporary) != temporary_identity
                or self._filesystem_identity(self.root.lstat()) != root_identity
                or self._filesystem_identity(temporary.lstat()) != temporary_identity
            ):
                raise OSError("atomic run publication identity changed")
            if os.name == "nt":
                self._windows_rename_directory_no_replace(temporary_descriptor, target)
            else:
                from .source_intake import _posix_rename_no_replace

                _posix_rename_no_replace(root_descriptor, temporary.name, target.name)
            published = target.lstat()
            if (
                self._is_link_or_reparse(published)
                or not stat.S_ISDIR(published.st_mode)
                or self._filesystem_identity(published) != temporary_identity
                or self._filesystem_identity(os.fstat(temporary_descriptor)) != temporary_identity
                or self._filesystem_identity(self.root.lstat()) != root_identity
            ):
                raise OSError("atomic run publication did not retain its identity")
            try:
                temporary.lstat()
            except FileNotFoundError:
                pass
            else:
                raise OSError("atomic run staging remained after publication")
            return root_identity
        finally:
            for descriptor in (temporary_descriptor, root_descriptor):
                if descriptor is not None:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass

    @staticmethod
    def _windows_rename_directory_no_replace(descriptor: int, target: Path) -> None:
        """Rename an exact Windows directory handle without replacing a target.

        The caller holds the destination root without FILE_SHARE_DELETE for the
        whole operation, so the fully qualified target cannot be redirected by
        renaming or replacing that root. The source descriptor carries DELETE
        access and remains pinned through post-publication identity checks.
        """

        if os.name != "nt":
            raise OSError("Windows run publication is unavailable")
        import ctypes
        import msvcrt
        from ctypes import wintypes

        target_name = os.path.abspath(os.fspath(target))
        if not target.is_absolute() or not target_name or "\x00" in target_name:
            raise OSError("atomic run publication target is invalid")

        class _FileRenameInfo(ctypes.Structure):
            _fields_ = [
                ("ReplaceIfExists", wintypes.BOOL),
                ("RootDirectory", wintypes.HANDLE),
                ("FileNameLength", wintypes.DWORD),
                ("FileName", wintypes.WCHAR * 1),
            ]

        encoded_name = target_name.encode("utf-16-le")
        name_offset = _FileRenameInfo.FileName.offset
        # SetFileInformationByHandle requires a terminating WCHAR even though
        # FileNameLength excludes it. The exact-sized zeroed buffer avoids
        # trailing structure padding being interpreted as part of the name.
        rename_buffer = ctypes.create_string_buffer(name_offset + len(encoded_name) + 2)
        rename = _FileRenameInfo.from_buffer(rename_buffer)
        rename.ReplaceIfExists = False
        rename.RootDirectory = None
        rename.FileNameLength = len(encoded_name)
        ctypes.memmove(
            ctypes.addressof(rename_buffer) + name_offset,
            encoded_name,
            len(encoded_name),
        )
        rename_file = ctypes.WinDLL("kernel32", use_last_error=True).SetFileInformationByHandle
        rename_file.argtypes = (
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
        )
        rename_file.restype = wintypes.BOOL
        if not rename_file(
            wintypes.HANDLE(msvcrt.get_osfhandle(descriptor)),
            3,  # FileRenameInfo
            rename_buffer,
            len(rename_buffer),
        ):
            error = ctypes.get_last_error()
            if error in {80, 183}:
                raise FileExistsError(error, "atomic run publication target exists")
            raise OSError(error, "atomic run publication rename failed")

    def _fsync_publication_directory(
        self,
        path: Path,
        expected_identity: tuple[int, int, int],
    ) -> None:
        """Strictly flush a pinned publication directory where supported."""

        details = path.lstat()
        if (
            self._is_link_or_reparse(details)
            or not stat.S_ISDIR(details.st_mode)
            or self._filesystem_identity(details) != expected_identity
        ):
            raise OSError("atomic run publication directory identity changed")
        if os.name == "nt":
            # Every staged file is flushed by _atomic_write. Windows does not
            # provide the POSIX directory-fsync durability contract; the
            # handle-bound rename and identity verification remain strict.
            return
        flags = os.O_RDONLY
        flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if (
                self._is_link_or_reparse(opened)
                or not stat.S_ISDIR(opened.st_mode)
                or self._filesystem_identity(opened) != expected_identity
            ):
                raise OSError("atomic run publication directory identity changed")
            os.fsync(descriptor)
            current = path.lstat()
            if (
                self._is_link_or_reparse(current)
                or self._filesystem_identity(current) != expected_identity
            ):
                raise OSError("atomic run publication directory identity changed")
        finally:
            os.close(descriptor)

    def _clean_publication_staging(
        self,
        temporary: Path,
        expected_identity: tuple[int, int, int],
        staged_identities: Mapping[str, tuple[int, int, int]],
        *,
        expected_root_identity: tuple[int, int, int] | None,
    ) -> None:
        # POSIX unlinkat/rmdir remain name based. The root and staging directory
        # are owner-private, so another process for the same OS principal is a
        # cooperative peer; every observed entry must still match the identity
        # captured immediately after this publisher wrote it.
        root_descriptor: int | None = None
        staging_descriptor: int | None = None
        try:
            try:
                details = temporary.lstat()
            except FileNotFoundError:
                return
            root_details = self.root.lstat()
            root_identity = self._validated_publication_root_identity()
            if (
                expected_root_identity is None
                or root_identity != expected_root_identity
                or temporary.parent.resolve(strict=True) != self.root
                or not temporary.name.startswith(_PUBLICATION_TEMP_PREFIX)
                or self._is_link_or_reparse(root_details)
                or not stat.S_ISDIR(root_details.st_mode)
                or self._is_link_or_reparse(details)
                or not stat.S_ISDIR(details.st_mode)
                or self._filesystem_identity(details) != expected_identity
            ):
                return
            if os.name == "nt":
                root_descriptor = _windows_open_descriptor(self.root, directory=True)
                staging_descriptor = _windows_open_descriptor(
                    temporary,
                    directory=True,
                    delete=True,
                )
            else:
                flags = os.O_RDONLY
                flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
                flags |= getattr(os, "O_NOFOLLOW", 0)
                root_descriptor = os.open(self.root, flags)
                staging_descriptor = os.open(
                    temporary.name,
                    flags,
                    dir_fd=root_descriptor,
                )
            if (
                self._filesystem_identity(os.fstat(root_descriptor)) != root_identity
                or self._filesystem_identity(os.fstat(staging_descriptor)) != expected_identity
            ):
                return

            names: list[str] = []
            if os.name == "nt":
                with os.scandir(temporary) as entries:
                    for entry in entries:
                        if len(names) >= len(staged_identities) + 1:
                            return
                        names.append(entry.name)
            else:
                for name in os.listdir(staging_descriptor):
                    if len(names) >= len(staged_identities) + 1:
                        return
                    names.append(name)
            if len(names) != len(staged_identities) or set(names) != set(staged_identities):
                return
            for name in names:
                if not name or Path(name).name != name or name in {".", ".."}:
                    return
                if os.name == "nt":
                    child = temporary / name
                    child_details = child.lstat()
                    if (
                        self._is_link_or_reparse(child_details)
                        or not stat.S_ISREG(child_details.st_mode)
                        or child_details.st_nlink != 1
                    ):
                        return
                    child_identity = self._filesystem_identity(child_details)
                    if staged_identities.get(name) != child_identity:
                        return
                    child_descriptor = _windows_open_descriptor(
                        child,
                        directory=False,
                        delete=True,
                    )
                    try:
                        opened_child = os.fstat(child_descriptor)
                        current_child = child.lstat()
                        if (
                            self._is_link_or_reparse(opened_child)
                            or not stat.S_ISREG(opened_child.st_mode)
                            or opened_child.st_nlink != 1
                            or self._filesystem_identity(opened_child) != child_identity
                            or self._filesystem_identity(current_child) != child_identity
                            or self._filesystem_identity(temporary.lstat()) != expected_identity
                        ):
                            return
                        _windows_mark_delete_descriptor(child_descriptor)
                    finally:
                        os.close(child_descriptor)
                    try:
                        child.lstat()
                    except FileNotFoundError:
                        pass
                    else:
                        return
                    continue

                child_details = os.stat(
                    name,
                    dir_fd=staging_descriptor,
                    follow_symlinks=False,
                )
                if (
                    self._is_link_or_reparse(child_details)
                    or not stat.S_ISREG(child_details.st_mode)
                    or child_details.st_nlink != 1
                ):
                    return
                child_identity = self._filesystem_identity(child_details)
                if staged_identities.get(name) != child_identity:
                    return
                child_flags = os.O_RDONLY
                child_flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
                child_descriptor = os.open(name, child_flags, dir_fd=staging_descriptor)
                try:
                    opened_child = os.fstat(child_descriptor)
                    current_child = os.stat(
                        name,
                        dir_fd=staging_descriptor,
                        follow_symlinks=False,
                    )
                    if (
                        self._is_link_or_reparse(opened_child)
                        or not stat.S_ISREG(opened_child.st_mode)
                        or opened_child.st_nlink != 1
                        or self._filesystem_identity(opened_child) != child_identity
                        or self._filesystem_identity(current_child) != child_identity
                        or self._filesystem_identity(os.fstat(staging_descriptor))
                        != expected_identity
                    ):
                        return
                    os.unlink(name, dir_fd=staging_descriptor)
                    if os.fstat(child_descriptor).st_nlink != 0:
                        return
                finally:
                    os.close(child_descriptor)

            if (
                self._filesystem_identity(temporary.lstat()) != expected_identity
                or self._filesystem_identity(self.root.lstat()) != root_identity
            ):
                return
            if os.name == "nt":
                if any(temporary.iterdir()):
                    return
                _windows_mark_delete_descriptor(staging_descriptor)
                os.close(staging_descriptor)
                staging_descriptor = None
            else:
                if os.listdir(staging_descriptor):
                    return
                os.rmdir(temporary.name, dir_fd=root_descriptor)
        except (OSError, RunStoreError):
            # An owned staging directory can be retried/inspected; never broaden
            # cleanup to an entry whose exact identity was not just verified.
            return
        finally:
            for descriptor in (staging_descriptor, root_descriptor):
                if descriptor is not None:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass

    @staticmethod
    def _result_requires_manifest(result: Mapping[str, Any]) -> bool:
        if "finalized_at" in result:
            return True
        status = result.get("status")
        return status not in ("created", "interrupted")

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
