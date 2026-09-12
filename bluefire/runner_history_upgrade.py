"""Explicit, authenticated upgrades that preserve a settled transport history.

The lifecycle owns admission and the real transport lock. This module never starts
a runner, migrates the ledger, or changes an execution authorization.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, ContextManager, Mapping, Protocol

from .runner_bootstrap_record import (
    _bootstrap_record_payload,
    _BootstrapRecord,
    _record_authentication,
)
from .runner_history_documents import validate_history_documents
from .runner_private_files import _PinnedPrivateDirectory
from .runner_transport import (
    _MAX_LEDGER_INSPECTION_BYTES,
    DEFAULT_MAX_FRAME_BYTES,
    AuthenticatedRunnerServer,
    _decode_durable_json_object,
    _decode_json_object,
    _enrollment_binding,
    _pinned_ledger_inspection,
    audit_runner_ledger,
    runner_result_namespace_path,
    validate_stored_execute_result,
)
from .util import canonical_json_bytes, content_hash, file_hash

if TYPE_CHECKING:
    from .runner_bootstrap import BootstrappedRunner
    from .runner_trust import RunnerEnrollment


class UpgradeLifecycle(Protocol):
    """Only stopped ownership, validation and staging capabilities are required."""

    bootstrap_factory: Callable[..., BootstrappedRunner]

    @property
    def runtime_root(self) -> Path: ...
    @property
    def control_root(self) -> Path: ...
    @property
    def ledger_path(self) -> Path: ...
    @property
    def bootstrap_record_path(self) -> Path: ...

    def _ledger_preflight(self, enrollment: RunnerEnrollment) -> str | None: ...
    def _require_no_live_watchdogs(
        self,
        enrollment: RunnerEnrollment,
        *,
        ledger_generation: str | None,
        require_namespace_empty: bool,
    ) -> None: ...
    def _require_no_receipt_obligations(self, sandbox: Path) -> None: ...
    def _require_stopped(self, operation: str) -> None: ...
    def _load_enrollment(self, *, require_active: bool) -> RunnerEnrollment: ...
    def _load_bootstrap(self, enrollment: RunnerEnrollment) -> _BootstrapRecord: ...
    def _parse_bootstrap_record(self, enrollment: RunnerEnrollment) -> _BootstrapRecord: ...
    def _require_live_bootstrap(self, record: _BootstrapRecord) -> _BootstrapRecord: ...
    def _validated_bootstrap_payload(self, bootstrapped: BootstrappedRunner) -> dict[str, Any]: ...


REVIEW_SCHEMA = "bluefire.runner-upgrade-review.v1"
JOURNAL_SCHEMA = "bluefire.runner-history-upgrade.v1"
MAX_RECORD_BYTES = 64 * 1024
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_IDENTITY_FIELDS = (
    "runner_id",
    "runner_version",
    "product_version",
    "binary_digest",
    "platform",
    "architecture",
    "inventory_schema",
    "action_sdk_version",
    "receipt_protocol",
)
_COMPATIBILITY_FIELDS = (
    "runner_id",
    "sandbox_path",
    "platform",
    "architecture",
    "inventory_schema",
    "action_sdk_version",
    "receipt_protocol",
)


class RunnerHistoryUpgradeError(RuntimeError):
    """A public, path-free refusal of a history-preserving upgrade."""


@dataclass(frozen=True)
class UpgradeIO:
    """Use the lifecycle's existing private publication and lock boundaries."""

    read: Callable[..., Any]
    write: Callable[..., None]
    unlink: Callable[[Path], None]
    ledger_lock: Callable[[], ContextManager[None]]


def _file_snapshot(directory: _PinnedPrivateDirectory, name: str, maximum: int) -> dict[str, Any]:
    descriptor = directory._open_existing(name, write_dac=False)
    try:
        before = directory._validate_file(
            name, descriptor, maximum=maximum, apply_permissions=False
        )
        digest = hashlib.sha256()
        count = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            count += len(chunk)
            if count > maximum:
                raise RunnerHistoryUpgradeError("Runner history exceeds its inspection limit.")
            digest.update(chunk)
        after = directory._validate_file(
            name,
            descriptor,
            maximum=maximum,
            apply_permissions=False,
            expected_identity=(before.st_dev, before.st_ino),
        )
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) or count != after.st_size:
            raise RunnerHistoryUpgradeError("Runner history changed during review.")
        return {
            "digest": "sha256:" + digest.hexdigest(),
            "bytes": count,
            "identity": [after.st_dev, after.st_ino],
            "modified_ns": after.st_mtime_ns,
            "changed_ns": after.st_ctime_ns,
        }
    finally:
        os.close(descriptor)


def _validated_history(
    lifecycle: UpgradeLifecycle,
    enrollment: RunnerEnrollment,
    platform: str,
    sandbox: Path,
) -> dict[str, Any]:
    """Audit all rows and the complete result namespace while the ledger is locked."""
    generation = lifecycle._ledger_preflight(enrollment)
    lifecycle._require_no_live_watchdogs(
        enrollment,
        ledger_generation=generation,
        require_namespace_empty=False,
    )
    empty = {
        "total_rows": 0,
        "execute_rows": 0,
        "completed_executions": 0,
        "undispatched_executions": 0,
        "durable_results": 0,
        "ledger_generation": generation,
    }
    if generation is None:
        return {**empty, "history_digest": content_hash({"ledger": None, "results": []})}
    with _PinnedPrivateDirectory(lifecycle.ledger_path.parent) as parent:
        before = _file_snapshot(parent, lifecycle.ledger_path.name, _MAX_LEDGER_INSPECTION_BYTES)
        audit = audit_runner_ledger(lifecycle.ledger_path, enrollment)
        if audit is None or audit["ledger_generation"] != generation:
            raise RunnerHistoryUpgradeError("Runner history changed during review.")
        expected: dict[str, str] = {}
        completed = undispatched = 0
        with _pinned_ledger_inspection(lifecycle.ledger_path) as connection:
            if connection is None:
                raise RunnerHistoryUpgradeError("Runner execution history is unavailable.")
            for raw in connection.execute("SELECT * FROM transport_tasks ORDER BY task_id"):
                row = dict(raw)
                if row["operation"] != "execute":
                    if row["state"] == "completed":
                        _decode_json_object(row["result_json"])
                    continue
                manifest, profile = AuthenticatedRunnerServer._stored_execute_payload(row)
                validate_history_documents(manifest, profile, platform=platform, sandbox=sandbox)
                if row["state"] != "completed":
                    if (
                        row["state"] not in {"failed", "cancelled", "timed_out"}
                        or row["effect_dispatched"]
                    ):
                        raise RunnerHistoryUpgradeError(
                            "Runner execution recovery remains unresolved."
                        )
                    undispatched += 1
                    continue
                wrapper = _decode_json_object(row["result_json"])
                if set(wrapper) != {"result"} or not isinstance(wrapper["result"], dict):
                    raise RunnerHistoryUpgradeError("Runner historical result is invalid.")
                result = validate_stored_execute_result(wrapper["result"], manifest, profile)
                name = hashlib.sha256(row["task_id"].encode("utf-8")).hexdigest()[:40] + ".json"
                expected[name] = content_hash(result)
                completed += 1
        namespace = runner_result_namespace_path(
            lifecycle.ledger_path,
            enrollment,
            ledger_generation=generation,
        )
        result_snapshots: dict[str, Any] = {}
        if namespace.exists():
            with _PinnedPrivateDirectory(namespace) as results:
                if set(results.names(maximum=1_000_000)) != set(expected):
                    raise RunnerHistoryUpgradeError(
                        "Runner durable results do not match settled history."
                    )
                for name in sorted(expected):
                    raw, identity, metadata = results.read_with_snapshot_identity(
                        name,
                        maximum=DEFAULT_MAX_FRAME_BYTES,
                        apply_permissions=False,
                    )
                    if content_hash(_decode_durable_json_object(raw)) != expected[name]:
                        raise RunnerHistoryUpgradeError(
                            "Runner durable result differs from its ledger result."
                        )
                    result_snapshots[name] = {
                        "digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
                        "identity": list(identity),
                        "metadata": list(metadata),
                    }
                if set(results.names(maximum=1_000_000)) != set(expected):
                    raise RunnerHistoryUpgradeError("Runner result state changed during review.")
                for name, captured in result_snapshots.items():
                    raw, identity, metadata = results.read_with_snapshot_identity(
                        name,
                        maximum=DEFAULT_MAX_FRAME_BYTES,
                        apply_permissions=False,
                    )
                    if captured != {
                        "digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
                        "identity": list(identity),
                        "metadata": list(metadata),
                    }:
                        raise RunnerHistoryUpgradeError("Runner result changed during review.")
        elif expected:
            raise RunnerHistoryUpgradeError("Runner durable results are missing.")
        after = _file_snapshot(parent, lifecycle.ledger_path.name, _MAX_LEDGER_INSPECTION_BYTES)
        if after != before:
            raise RunnerHistoryUpgradeError("Runner history changed during review.")
    return {
        **empty,
        "total_rows": audit["total_rows"],
        "execute_rows": audit["execute_rows"],
        "completed_executions": completed,
        "undispatched_executions": undispatched,
        "durable_results": len(result_snapshots),
        "history_digest": content_hash({"ledger": before, "results": result_snapshots}),
    }


def _bound_review(
    lifecycle: UpgradeLifecycle,
    enrollment: RunnerEnrollment,
    old: Mapping[str, Any],
    new: Mapping[str, Any],
    profile_binding: str | None,
) -> dict[str, Any]:
    if profile_binding is not None and (
        not isinstance(profile_binding, str) or _DIGEST.fullmatch(profile_binding) is None
    ):
        raise RunnerHistoryUpgradeError("Runner upgrade profile binding is invalid.")
    if any(old.get(key) != new.get(key) for key in _COMPATIBILITY_FIELDS):
        raise RunnerHistoryUpgradeError(
            "Runner upgrade cannot change the sandbox, identity or protocols."
        )
    if (
        old == new
        or old["binary_path"] == new["binary_path"]
        or not old["managed_binary"]
        or not new["managed_binary"]
        or old["source"] != "packaged"
        or new["source"] != "packaged"
    ):
        raise RunnerHistoryUpgradeError("A distinct verified managed native artifact is required.")
    for payload in (old, new):
        binary = Path(payload["binary_path"])
        if (
            binary.resolve(strict=True) != binary
            or not binary.is_relative_to(lifecycle.runtime_root.resolve(strict=True))
            or file_hash(binary) != payload["binary_digest"]
        ):
            raise RunnerHistoryUpgradeError("Reviewed runner artifacts are unavailable or changed.")
    lifecycle._require_no_receipt_obligations(Path(old["sandbox_path"]))
    history = _validated_history(
        lifecycle, enrollment, str(old["platform"]), Path(old["sandbox_path"])
    )
    lifecycle._require_no_receipt_obligations(Path(old["sandbox_path"]))
    lifecycle._require_no_live_watchdogs(
        enrollment,
        ledger_generation=history["ledger_generation"],
        require_namespace_empty=False,
    )
    return {
        "schema_version": JOURNAL_SCHEMA,
        "old": dict(old),
        "new": dict(new),
        "enrollment": _enrollment_binding(
            enrollment, str(enrollment.metadata["client_fingerprint"])
        ),
        "profiles": list(enrollment.allowed_profile_ids),
        "profile_binding": profile_binding,
        "history": history,
    }


def _public_review(bound: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": REVIEW_SCHEMA,
        "review_digest": content_hash(bound),
        "current": {key: bound["old"][key] for key in _IDENTITY_FIELDS},
        "candidate": {key: bound["new"][key] for key in _IDENTITY_FIELDS},
        "compatibility": dict.fromkeys(
            ("same_sandbox", "same_enrollment", "same_profiles", "same_protocols"), True
        ),
        "history": dict(bound["history"]),
        "preservation": dict.fromkeys(
            ("old_binary", "ledger", "durable_results", "product_history"), True
        ),
        "staging": {"candidate_verified": True, "activated": False, "execution_started": False},
    }


def review_upgrade(
    lifecycle: UpgradeLifecycle,
    io: UpgradeIO,
    options: Mapping[str, Any],
    *,
    profile_binding: str | None = None,
) -> Mapping[str, Any]:
    lifecycle._require_stopped("upgrade review")
    enrollment = lifecycle._load_enrollment(require_active=True)
    if tuple(options["allowed_profile_ids"]) != enrollment.allowed_profile_ids:
        raise RunnerHistoryUpgradeError("Existing enrollment does not match the reviewed profiles.")
    if pending_upgrade(lifecycle):
        with io.ledger_lock():
            reviewed = _pending_review(lifecycle, io, enrollment, profile_binding)
            return {**_public_review(reviewed), "recovery_required": True}
    old = _bootstrap_record_payload(lifecycle._load_bootstrap(enrollment))
    stage = {key: value for key, value in options.items() if key != "allowed_profile_ids"}
    new = lifecycle._validated_bootstrap_payload(
        lifecycle.bootstrap_factory(
            managed_root=lifecycle.runtime_root,
            **stage,
        )
    )
    with io.ledger_lock():
        return _public_review(_bound_review(lifecycle, enrollment, old, new, profile_binding))


def _authenticated(enrollment: RunnerEnrollment, payload: Mapping[str, Any]) -> dict[str, Any]:
    return {**payload, "authentication": _record_authentication(enrollment, payload)}


def _optional_bootstrap(path: Path) -> Mapping[str, Any] | None:
    with _PinnedPrivateDirectory(path.parent) as parent:
        try:
            return _decode_json_object(
                parent.read(path.name, maximum=MAX_RECORD_BYTES, apply_permissions=False)
            )
        except FileNotFoundError:
            return None


def _publish_bootstrap_switch(
    io: UpgradeIO,
    path: Path,
    expected: Mapping[str, Any],
    replacement: Mapping[str, Any],
) -> None:
    """Use exact deletion/no-replace publication, protected by the durable journal.

    A crash in the missing-record window is recoverable only through the
    authenticated exact pending review. Never replace an unknown raced entry.
    """
    expected_bytes = canonical_json_bytes(expected)
    with _PinnedPrivateDirectory(path.parent) as directory:
        before = directory.read_with_snapshot_identity(
            path.name, maximum=MAX_RECORD_BYTES, apply_permissions=False
        )
        if before[0] != expected_bytes:
            raise RunnerHistoryUpgradeError("Runner bootstrap changed after review.")
        directory.unlink(
            path.name,
            maximum=MAX_RECORD_BYTES,
            expected=before[0],
            expected_identity=before[1],
            expected_snapshot=before[2],
            apply_permissions=False,
        )
    io.write(path, replacement, maximum=MAX_RECORD_BYTES, replace=False)


def _finish_upgrade(
    lifecycle: UpgradeLifecycle,
    io: UpgradeIO,
    enrollment: RunnerEnrollment,
    bound: Mapping[str, Any],
) -> None:
    digest = content_hash(bound)
    old, new = _authenticated(enrollment, bound["old"]), _authenticated(enrollment, bound["new"])
    if (
        _bound_review(lifecycle, enrollment, bound["old"], bound["new"], bound["profile_binding"])
        != bound
    ):
        raise RunnerHistoryUpgradeError("Runner upgrade state changed before activation.")
    current = _optional_bootstrap(lifecycle.bootstrap_record_path)
    if current == old:
        _publish_bootstrap_switch(io, lifecycle.bootstrap_record_path, old, new)
    elif current is None:
        io.write(lifecycle.bootstrap_record_path, new, maximum=MAX_RECORD_BYTES, replace=False)
    elif current != new:
        raise RunnerHistoryUpgradeError(
            "Runner upgrade recovery does not match the approved artifacts."
        )
    archive = lifecycle.control_root / ("upgrade-" + digest.removeprefix("sha256:") + ".json")
    receipt = _authenticated(
        enrollment,
        {
            "schema_version": JOURNAL_SCHEMA,
            "state": "committed",
            "review_digest": digest,
            "review": dict(bound),
        },
    )
    if archive.exists():
        if io.read(archive, maximum=MAX_RECORD_BYTES) != receipt:
            raise RunnerHistoryUpgradeError("Runner upgrade provenance is inconsistent.")
    else:
        io.write(archive, receipt, maximum=MAX_RECORD_BYTES, replace=False)
    io.unlink(lifecycle.control_root / "upgrade-pending.json")


def apply_upgrade(
    lifecycle: UpgradeLifecycle,
    io: UpgradeIO,
    enrollment: RunnerEnrollment,
    old: Mapping[str, Any],
    new: Mapping[str, Any],
    digest: str,
    *,
    profile_binding: str | None = None,
) -> None:
    if not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None:
        raise RunnerHistoryUpgradeError("Runner upgrade review digest is invalid.")
    lifecycle._require_stopped("upgrade")
    lifecycle._require_live_bootstrap(lifecycle._parse_bootstrap_record(enrollment))
    with io.ledger_lock():
        bound = _bound_review(lifecycle, enrollment, old, new, profile_binding)
        if not hmac.compare_digest(content_hash(bound), digest):
            raise RunnerHistoryUpgradeError(
                "Runner upgrade review is stale; review the current state again."
            )
        pending = _authenticated(
            enrollment,
            {
                "schema_version": JOURNAL_SCHEMA,
                "state": "approved",
                "review_digest": digest,
                "review": bound,
            },
        )
        io.write(
            lifecycle.control_root / "upgrade-pending.json",
            pending,
            maximum=MAX_RECORD_BYTES,
            replace=False,
        )
        _finish_upgrade(lifecycle, io, enrollment, bound)


def pending_upgrade(lifecycle: UpgradeLifecycle) -> bool:
    path = lifecycle.control_root / "upgrade-pending.json"
    return path.exists() or path.is_symlink()


def _pending_review(
    lifecycle: UpgradeLifecycle,
    io: UpgradeIO,
    enrollment: RunnerEnrollment,
    profile_binding: str | None,
) -> dict[str, Any]:
    path = lifecycle.control_root / "upgrade-pending.json"
    pending = io.read(path, maximum=MAX_RECORD_BYTES)
    if not isinstance(pending, dict) or set(pending) != {
        "schema_version",
        "state",
        "review_digest",
        "review",
        "authentication",
    }:
        raise RunnerHistoryUpgradeError("Runner upgrade recovery record is invalid.")
    payload = {key: value for key, value in pending.items() if key != "authentication"}
    if (
        pending["schema_version"] != JOURNAL_SCHEMA
        or pending["state"] != "approved"
        or not isinstance(pending["authentication"], str)
        or not hmac.compare_digest(
            _record_authentication(enrollment, payload), pending["authentication"]
        )
        or not isinstance(pending["review"], dict)
        or content_hash(pending["review"]) != pending["review_digest"]
    ):
        raise RunnerHistoryUpgradeError("Runner upgrade recovery authentication failed.")
    reviewed = pending["review"]
    current = _bound_review(
        lifecycle, enrollment, reviewed["old"], reviewed["new"], profile_binding
    )
    if current != reviewed:
        raise RunnerHistoryUpgradeError(
            "Runner upgrade recovery state changed; activation is blocked."
        )
    bootstrap = _optional_bootstrap(lifecycle.bootstrap_record_path)
    if bootstrap is not None and bootstrap not in (
        _authenticated(enrollment, current["old"]),
        _authenticated(enrollment, current["new"]),
    ):
        raise RunnerHistoryUpgradeError(
            "Runner upgrade recovery found an unexpected bootstrap record."
        )
    return current


def recover_upgrade(
    lifecycle: UpgradeLifecycle,
    io: UpgradeIO,
    *,
    review_digest: str,
    profile_binding: str | None = None,
) -> None:
    """Complete a reviewed interruption only inside fresh product admission."""
    lifecycle._require_stopped("upgrade recovery")
    enrollment = lifecycle._load_enrollment(require_active=True)
    with io.ledger_lock():
        current = _pending_review(lifecycle, io, enrollment, profile_binding)
        if not isinstance(review_digest, str) or not hmac.compare_digest(
            content_hash(current), review_digest
        ):
            raise RunnerHistoryUpgradeError(
                "Runner upgrade recovery requires the exact reviewed digest."
            )
        _finish_upgrade(lifecycle, io, enrollment, current)


def upgrade_failure(exc: Exception) -> RunnerHistoryUpgradeError:
    if isinstance(exc, RunnerHistoryUpgradeError):
        return exc
    # Filesystem, SQLite, and document parsers can include paths or history material.
    return RunnerHistoryUpgradeError(
        "Runner settled history or upgrade state could not be verified."
    )
