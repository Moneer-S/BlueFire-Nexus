"""Durable local product metadata and approval state.

The run bundle store remains append-oriented and evidence focused.  This store
owns mutable product metadata: scenario versions, settings, runner inventory,
provider configuration, collectors, detections, research sources, comparisons,
background-job state, and one-time approval requests.

Only references to secrets are accepted.  Secret values belong in the local
environment (or a future operating-system secret provider), never in SQLite.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import threading
import uuid
from collections.abc import Collection
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Iterator, Mapping, cast

from .ai import (
    MUTATING_PROPOSAL_TYPES,
    AIProviderError,
    ProposalType,
    validate_persisted_proposal_record,
)
from .contracts import ScenarioDefinition
from .util import canonical_json_bytes, content_hash, json_clone

if TYPE_CHECKING:
    from .action_packages import VerifiedActionPackage


class ProductStoreError(ValueError):
    """Raised when product metadata or a state transition is invalid."""


class ResearchSourceIntegrityError(ProductStoreError):
    """Raised when a persisted research-source identity would be rewritten."""


class DetectionRevisionIntegrityError(ProductStoreError):
    """Raised when an immutable detection revision identity conflicts."""


class DetectionRevisionLimitError(DetectionRevisionIntegrityError):
    """Raised when a detection lineage has reached its configured bound."""


class ActionPackageIntegrityError(ProductStoreError):
    """Raised when package bytes or persisted package identity fail verification."""


class ActionPackageConflictError(ActionPackageIntegrityError):
    """Raised when an immutable package or publisher identity would be rewritten."""


SCHEMA_VERSION = 6
_IDENTIFIER = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_ACTION_PACKAGE_VERSION = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
_MAX_ACTION_PACKAGE_ENVELOPE_BYTES = 256 * 1024
_MAX_ACTION_PACKAGE_ACTOR_CHARS = 128
_MAX_OCCUPIED_PACKAGE_IDS = 4096
_PROPOSAL_RECORD_ID = re.compile(r"^proposal-review-[0-9a-f]{32}$")
_SOURCE_PROPOSAL_ID = re.compile(r"^proposal-[0-9a-f]{20}$")
_ENVIRONMENT_NAME = re.compile(r"^[A-Z][A-Z0-9_]*$")
_SECRET_FIELDS = {
    "auth",
    "authorization",
    "bearer",
    "cookie",
    "api_key",
    "apikey",
    "credential",
    "credentials",
    "password",
    "private_key",
    "secret",
    "secrets",
    "token",
}
_CREDENTIAL_VALUE_PATTERNS = (
    re.compile(r"\A(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]{20,}\Z"),
    re.compile(r"\Ask-[A-Za-z0-9_-]{20,}\Z"),
    re.compile(r"\Axox[baprs]-[A-Za-z0-9-]{10,}\Z"),
    re.compile(r"\AAKIA[0-9A-Z]{16}\Z"),
    re.compile(r"\AeyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\Z"),
    re.compile(r"-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----"),
    re.compile(r"\A[A-Za-z][A-Za-z0-9+.-]*://[^/\s:@]+:[^/\s@]+@"),
)
_RESOURCE_KINDS = {
    "action",
    "collector",
    "comparison",
    "detection",
    "detection_backend",
    "model_provider",
    "plugin",
    "research_source",
    "runner",
    "runner_profile",
}
_JOB_STATES = {
    "queued",
    "planning",
    "awaiting_approval",
    "running",
    "paused",
    "cancelling",
    "cancelled",
    "completed",
    "failed",
    "interrupted",
}
_EXECUTION_WORKSPACE_STATES = {
    "active",
    "completed",
    "recovered",
    "not_required",
    "deferred",
}
_RUN_ID = re.compile(r"^run-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}$")
_JOB_TRANSITIONS = {
    "queued": {"planning", "cancelled", "failed"},
    "planning": {"awaiting_approval", "running", "cancelled", "failed"},
    "awaiting_approval": {"planning", "running", "cancelled", "completed", "failed"},
    "running": {
        "awaiting_approval",
        "paused",
        "cancelling",
        "completed",
        "failed",
        "interrupted",
    },
    "paused": {"running", "cancelling", "cancelled", "failed", "interrupted"},
    # A separately supervised effect may report a durable terminal result while
    # an operator cancellation races with that acknowledgement.  Only the job
    # controller's explicit confirmed-completion path uses this transition.
    "cancelling": {"cancelled", "completed", "failed", "interrupted"},
    "interrupted": {"planning", "cancelling", "failed"},
    "cancelled": set(),
    "completed": set(),
    "failed": set(),
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _identifier(value: Any, context: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ProductStoreError(f"{context} must be a stable lowercase identifier")
    return value


def _exact_sha256_digest(value: Any, context: str) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise ActionPackageIntegrityError(f"{context} must be an exact lowercase sha256 digest")
    return value


def _sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _bounded_package_bytes(value: Any, context: str) -> bytes:
    if not isinstance(value, bytes):
        raise ActionPackageIntegrityError(f"{context} must be immutable bytes")
    if not value or len(value) > _MAX_ACTION_PACKAGE_ENVELOPE_BYTES:
        raise ActionPackageIntegrityError(
            f"{context} must contain 1 to {_MAX_ACTION_PACKAGE_ENVELOPE_BYTES} bytes"
        )
    return value


def _canonical_package_object(value: bytes, context: str) -> Mapping[str, Any]:
    try:
        document = json.loads(value)
        canonical = canonical_json_bytes(document)
    except (UnicodeDecodeError, TypeError, ValueError, RecursionError) as exc:
        raise ActionPackageIntegrityError(f"{context} is not canonical UTF-8 JSON") from exc
    if not isinstance(document, Mapping) or canonical != value:
        raise ActionPackageIntegrityError(f"{context} is not an exact canonical JSON object")
    return cast(Mapping[str, Any], document)


def _package_actor(value: Any, context: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > _MAX_ACTION_PACKAGE_ACTOR_CHARS
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ProductStoreError(
            f"{context} must be a non-empty printable string no longer than "
            f"{_MAX_ACTION_PACKAGE_ACTOR_CHARS} characters"
        )
    return value


def _package_trust_reason(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > 512
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ProductStoreError(
            "action-package trust reason must be a non-empty printable string no longer "
            "than 512 characters"
        )
    return value


def _occupied_package_ids(value: Any, context: str) -> tuple[str, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Collection):
        raise ProductStoreError(f"{context} must be a collection of stable identifiers")
    if len(value) > _MAX_OCCUPIED_PACKAGE_IDS:
        raise ProductStoreError(
            f"{context} cannot contain more than {_MAX_OCCUPIED_PACKAGE_IDS} identifiers"
        )
    normalized: set[str] = set()
    for item in value:
        stable_id = _identifier(item, context)
        if len(stable_id) > 128:
            raise ProductStoreError(f"{context} identifiers cannot exceed 128 characters")
        normalized.add(stable_id)
    return tuple(sorted(normalized))


def _safe_document(value: Any, *, context: str = "document") -> Any:
    """Clone JSON data and reject persisted plaintext secrets.

    A secret-shaped field may be null or an exact ``{"env": "NAME"}``
    reference.  This keeps configuration exportable without making the local
    database a credential store.
    """

    try:
        cloned = json_clone(value)
    except (TypeError, ValueError) as exc:
        raise ProductStoreError(f"{context} must contain only JSON values") from exc

    def inspect(item: Any, path: str) -> None:
        if isinstance(item, str):
            if any(pattern.search(item) for pattern in _CREDENTIAL_VALUE_PATTERNS):
                raise ProductStoreError(
                    f"{path} contains a credential-shaped plaintext value; "
                    "use an environment-variable reference"
                )
            return
        if isinstance(item, list):
            for index, child in enumerate(item):
                inspect(child, f"{path}[{index}]")
            return
        if not isinstance(item, dict):
            return
        for raw_key, child in item.items():
            if not isinstance(raw_key, str):
                raise ProductStoreError(f"{path} contains a non-string key")
            key = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", raw_key).lower().replace("-", "_")
            segments = tuple(part for part in re.split(r"[^a-z0-9]+", key) if part)
            secret_shaped = key in _SECRET_FIELDS or any(
                segment in _SECRET_FIELDS for segment in segments
            )
            if secret_shaped:
                if child is None:
                    continue
                if key.endswith(("_available", "_configured", "_present")) and isinstance(
                    child, bool
                ):
                    continue
                if (
                    key.endswith(("_reference", "_env"))
                    and isinstance(child, str)
                    and _ENVIRONMENT_NAME.fullmatch(child)
                ):
                    continue
                if (
                    key in {"credentials", "secrets"}
                    and isinstance(child, dict)
                    and all(
                        isinstance(reference, dict)
                        and set(reference) == {"env"}
                        and isinstance(reference["env"], str)
                        and _ENVIRONMENT_NAME.fullmatch(reference["env"])
                        for reference in child.values()
                    )
                ):
                    continue
                if (
                    not isinstance(child, dict)
                    or set(child) != {"env"}
                    or not isinstance(child["env"], str)
                    or not _ENVIRONMENT_NAME.fullmatch(child["env"])
                ):
                    raise ProductStoreError(
                        f"{path}.{raw_key} must be null or an environment-variable reference"
                    )
            inspect(child, f"{path}.{raw_key}")

    inspect(cloned, context)
    return cloned


def _detection_revision_identity(
    document: Mapping[str, Any],
    *,
    strict: bool,
) -> tuple[str, int, str] | None:
    """Return candidate, ordinal, and root identities for a v1/v2 document."""

    schema_version = document.get("schema_version")
    if schema_version not in {"bluefire.detection.v1", "bluefire.detection.v2"}:
        if strict:
            raise DetectionRevisionIntegrityError(
                "detection revisions require a supported v1 or v2 document"
            )
        return None
    try:
        candidate_id = _identifier(document.get("candidate_id"), "detection candidate ID")
        if schema_version == "bluefire.detection.v1":
            return candidate_id, 1, candidate_id
        revision = document.get("revision")
        if isinstance(revision, bool) or not isinstance(revision, int) or revision <= 0:
            raise DetectionRevisionIntegrityError("detection revision must be a positive integer")
        revision_root_id = _identifier(
            document.get("revision_root_id"), "detection revision root ID"
        )
        return candidate_id, revision, revision_root_id
    except ProductStoreError:
        if strict:
            raise
        return None


@dataclass(frozen=True, slots=True)
class ApprovalRequest:
    approval_id: str
    run_id: str
    state_digest: str
    plan_digest: str
    profile_id: str
    target_scope_digest: str
    maximum_tier: str
    status: str
    requested_at: str
    expires_at: str
    approved_at: str | None
    approved_by: str | None
    nonce: str | None
    consumed_at: str | None
    claimed_at: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "bluefire.approval-request.v1",
            "approval_id": self.approval_id,
            "run_id": self.run_id,
            "state_digest": self.state_digest,
            "plan_digest": self.plan_digest,
            "profile_id": self.profile_id,
            "target_scope_digest": self.target_scope_digest,
            "maximum_tier": self.maximum_tier,
            "status": self.status,
            "requested_at": self.requested_at,
            "expires_at": self.expires_at,
            "approved_at": self.approved_at,
            "approved_by": self.approved_by,
            "nonce": self.nonce,
            "consumed_at": self.consumed_at,
            "claimed_at": self.claimed_at,
        }


class ProductStore:
    """Thread-safe SQLite storage for local-first product state.

    Append-only tables are enforced transactionally by SQLite triggers for
    normal store and SQL use. They are not an external rollback anchor: an
    actor who can replace the database or drop its triggers and truncate its
    history can restore an older valid prefix. Protect the database with OS
    permissions and external backup/audit controls where rollback matters.
    """

    def __init__(self, path: str | Path) -> None:
        candidate = Path(path).expanduser()
        if candidate.is_symlink():
            raise ProductStoreError("product database cannot be a symbolic link")
        if candidate.exists() and not candidate.is_file():
            raise ProductStoreError("product database path must be a regular file")
        candidate.parent.mkdir(parents=True, exist_ok=True)
        self.path = candidate.resolve()
        self._lock = threading.RLock()
        self._migrate()

    @contextmanager
    def _connection(self, *, write: bool = False) -> Iterator[sqlite3.Connection]:
        with self._lock:
            connection = sqlite3.connect(self.path, timeout=5.0)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA busy_timeout = 5000")
            if write:
                connection.execute("BEGIN IMMEDIATE")
            try:
                yield connection
            except BaseException:
                if write:
                    connection.rollback()
                raise
            else:
                if write:
                    connection.commit()
            finally:
                connection.close()

    def _migrate(self) -> None:
        # Refuse future schemas before any DDL.  ``executescript`` commits its
        # own transaction boundary, so checking after it would already have
        # mutated a database this build does not understand.
        with self._connection() as preflight:
            migration_table = preflight.execute("""
                SELECT 1 FROM sqlite_master
                WHERE type = 'table' AND name = 'schema_migrations'
                """).fetchone()
            if migration_table is not None:
                try:
                    preflight_version = preflight.execute(
                        "SELECT MAX(version) FROM schema_migrations"
                    ).fetchone()[0]
                except sqlite3.DatabaseError as exc:
                    raise ProductStoreError(
                        "product database migration history is unreadable"
                    ) from exc
                if preflight_version is not None and int(preflight_version) > SCHEMA_VERSION:
                    raise ProductStoreError(
                        "product database schema is newer than this application"
                    )
        with self._connection(write=True) as connection:
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY,
                    applied_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS scenario_versions (
                    scenario_id TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    title TEXT NOT NULL,
                    document_json TEXT NOT NULL,
                    digest TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (scenario_id, version),
                    UNIQUE (scenario_id, digest)
                );

                CREATE TABLE IF NOT EXISTS scenario_heads (
                    scenario_id TEXT PRIMARY KEY,
                    active_version INTEGER NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY (scenario_id, active_version)
                        REFERENCES scenario_versions(scenario_id, version)
                );

                CREATE TABLE IF NOT EXISTS resources (
                    kind TEXT NOT NULL,
                    resource_id TEXT NOT NULL,
                    document_json TEXT NOT NULL,
                    digest TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (kind, resource_id)
                );

                CREATE TABLE IF NOT EXISTS detection_revisions (
                    revision_root_id TEXT NOT NULL,
                    revision INTEGER NOT NULL CHECK (revision > 0),
                    candidate_id TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (revision_root_id, revision)
                );

                CREATE TABLE IF NOT EXISTS approval_requests (
                    approval_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    state_digest TEXT NOT NULL,
                    plan_digest TEXT NOT NULL,
                    profile_id TEXT NOT NULL,
                    target_scope_digest TEXT NOT NULL,
                    maximum_tier TEXT NOT NULL,
                    status TEXT NOT NULL,
                    requested_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    approved_at TEXT,
                    approved_by TEXT,
                    nonce TEXT UNIQUE,
                    consumed_at TEXT,
                    claimed_at TEXT
                );

                CREATE INDEX IF NOT EXISTS approval_requests_run_idx
                    ON approval_requests(run_id, status);

                CREATE TABLE IF NOT EXISTS jobs (
                    job_id TEXT PRIMARY KEY,
                    kind TEXT NOT NULL,
                    state TEXT NOT NULL,
                    request_json TEXT NOT NULL,
                    progress_json TEXT NOT NULL,
                    result_ref TEXT,
                    error_json TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS jobs_state_idx ON jobs(state, updated_at);

                CREATE TABLE IF NOT EXISTS ai_proposal_reviews (
                    proposal_record_id TEXT PRIMARY KEY,
                    job_id TEXT NOT NULL,
                    source_run_id TEXT NOT NULL,
                    source_proposal_id TEXT NOT NULL,
                    state_digest TEXT NOT NULL,
                    plan_digest TEXT NOT NULL,
                    proposal_digest TEXT NOT NULL,
                    status TEXT NOT NULL,
                    record_json TEXT NOT NULL,
                    resolution_json TEXT,
                    created_at TEXT NOT NULL,
                    decided_at TEXT,
                    decided_by TEXT,
                    FOREIGN KEY (job_id) REFERENCES jobs(job_id),
                    UNIQUE (
                        job_id, source_run_id, source_proposal_id,
                        state_digest, plan_digest, proposal_digest
                    )
                );

                CREATE INDEX IF NOT EXISTS ai_proposal_reviews_job_idx
                    ON ai_proposal_reviews(job_id, status, created_at);

                CREATE TABLE IF NOT EXISTS execution_workspaces (
                    approval_id TEXT PRIMARY KEY,
                    profile_id TEXT NOT NULL,
                    workspace_path TEXT NOT NULL,
                    workspace_digest TEXT NOT NULL,
                    runner_identity_json TEXT NOT NULL,
                    recovery_context_json TEXT NOT NULL,
                    run_id TEXT,
                    state TEXT NOT NULL,
                    outcome_json TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY (approval_id) REFERENCES approval_requests(approval_id)
                );

                CREATE INDEX IF NOT EXISTS execution_workspaces_state_idx
                    ON execution_workspaces(state, updated_at);

                CREATE TABLE IF NOT EXISTS run_index (
                    run_id TEXT PRIMARY KEY,
                    scenario_id TEXT NOT NULL,
                    mode TEXT NOT NULL,
                    status TEXT NOT NULL,
                    objective_reached INTEGER,
                    bundle_digest TEXT,
                    summary_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS trusted_action_package_publishers (
                    publisher_id TEXT NOT NULL,
                    key_id TEXT NOT NULL,
                    public_key_bytes BLOB NOT NULL CHECK (length(public_key_bytes) = 32),
                    public_key_b64u TEXT NOT NULL UNIQUE,
                    key_fingerprint TEXT NOT NULL UNIQUE,
                    provenance_json TEXT NOT NULL,
                    trusted_by TEXT NOT NULL,
                    trusted_at TEXT NOT NULL,
                    PRIMARY KEY (publisher_id, key_id)
                );

                CREATE TABLE IF NOT EXISTS action_package_publisher_trust_events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL UNIQUE,
                    publisher_id TEXT NOT NULL,
                    key_id TEXT NOT NULL,
                    trust_state TEXT NOT NULL
                        CHECK (trust_state IN ('trusted', 'suspended', 'revoked')),
                    actor TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (publisher_id, key_id)
                        REFERENCES trusted_action_package_publishers(publisher_id, key_id)
                );

                CREATE INDEX IF NOT EXISTS action_package_trust_events_publisher_idx
                    ON action_package_publisher_trust_events(
                        publisher_id, key_id, sequence
                    );

                CREATE TABLE IF NOT EXISTS action_package_versions (
                    package_id TEXT NOT NULL,
                    version TEXT NOT NULL,
                    package_digest TEXT NOT NULL UNIQUE,
                    content_digest TEXT NOT NULL,
                    publisher_id TEXT NOT NULL,
                    key_id TEXT NOT NULL,
                    signer_fingerprint TEXT NOT NULL,
                    signature_b64u TEXT NOT NULL,
                    occupied_behavior_ids_json TEXT NOT NULL,
                    occupied_action_ids_json TEXT NOT NULL,
                    manifest_json TEXT NOT NULL,
                    canonical_envelope_bytes BLOB NOT NULL
                        CHECK (
                            length(canonical_envelope_bytes) > 0
                            AND length(canonical_envelope_bytes) <= 262144
                        ),
                    canonical_content_bytes BLOB NOT NULL
                        CHECK (
                            length(canonical_content_bytes) > 0
                            AND length(canonical_content_bytes) <= 262144
                        ),
                    installed_by TEXT NOT NULL,
                    installed_at TEXT NOT NULL,
                    PRIMARY KEY (package_id, version),
                    FOREIGN KEY (publisher_id, key_id)
                        REFERENCES trusted_action_package_publishers(publisher_id, key_id)
                );

                CREATE INDEX IF NOT EXISTS action_package_versions_publisher_idx
                    ON action_package_versions(publisher_id, key_id, installed_at);

                CREATE TABLE IF NOT EXISTS action_package_heads (
                    package_id TEXT PRIMARY KEY,
                    installed_version TEXT NOT NULL,
                    active_version TEXT,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY (package_id, installed_version)
                        REFERENCES action_package_versions(package_id, version),
                    FOREIGN KEY (package_id, active_version)
                        REFERENCES action_package_versions(package_id, version)
                );

                CREATE TABLE IF NOT EXISTS action_package_lifecycle_events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL UNIQUE,
                    package_id TEXT NOT NULL,
                    version TEXT NOT NULL,
                    event_type TEXT NOT NULL CHECK (event_type = 'installed'),
                    actor TEXT NOT NULL,
                    details_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE (package_id, version, event_type),
                    FOREIGN KEY (package_id, version)
                        REFERENCES action_package_versions(package_id, version)
                );

                CREATE INDEX IF NOT EXISTS action_package_lifecycle_events_package_idx
                    ON action_package_lifecycle_events(package_id, sequence);

                CREATE TABLE IF NOT EXISTS action_package_tombstones (
                    package_id TEXT NOT NULL,
                    version TEXT NOT NULL,
                    package_digest TEXT NOT NULL,
                    removed_by TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    removed_at TEXT NOT NULL,
                    PRIMARY KEY (package_id, version),
                    FOREIGN KEY (package_id, version)
                        REFERENCES action_package_versions(package_id, version)
                );

                CREATE TABLE IF NOT EXISTS legacy_action_package_metadata (
                    resource_id TEXT PRIMARY KEY,
                    document_json TEXT NOT NULL,
                    digest TEXT NOT NULL,
                    legacy_status TEXT NOT NULL,
                    resource_created_at TEXT NOT NULL,
                    resource_updated_at TEXT NOT NULL,
                    captured_at TEXT NOT NULL
                );

                CREATE TRIGGER IF NOT EXISTS action_package_events_no_update
                BEFORE UPDATE ON action_package_lifecycle_events
                BEGIN
                    SELECT RAISE(ABORT, 'action-package lifecycle events are append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS action_package_events_no_delete
                BEFORE DELETE ON action_package_lifecycle_events
                BEGIN
                    SELECT RAISE(ABORT, 'action-package lifecycle events are append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS action_package_tombstones_no_update
                BEFORE UPDATE ON action_package_tombstones
                BEGIN
                    SELECT RAISE(ABORT, 'action-package tombstones are append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS action_package_tombstones_no_delete
                BEFORE DELETE ON action_package_tombstones
                BEGIN
                    SELECT RAISE(ABORT, 'action-package tombstones are append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS action_package_publishers_no_update
                BEFORE UPDATE ON trusted_action_package_publishers
                BEGIN
                    SELECT RAISE(ABORT, 'action-package publisher trust is immutable');
                END;

                CREATE TRIGGER IF NOT EXISTS action_package_publishers_no_delete
                BEFORE DELETE ON trusted_action_package_publishers
                BEGIN
                    SELECT RAISE(ABORT, 'action-package publisher trust is immutable');
                END;

                CREATE TRIGGER IF NOT EXISTS action_package_trust_events_no_update
                BEFORE UPDATE ON action_package_publisher_trust_events
                BEGIN
                    SELECT RAISE(ABORT, 'action-package trust events are append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS action_package_trust_events_valid_transition
                BEFORE INSERT ON action_package_publisher_trust_events
                WHEN NOT (
                    (
                        NOT EXISTS (
                            SELECT 1 FROM action_package_publisher_trust_events
                            WHERE publisher_id = NEW.publisher_id AND key_id = NEW.key_id
                        )
                        AND NEW.trust_state = 'trusted'
                    )
                    OR (
                        (
                            SELECT trust_state FROM action_package_publisher_trust_events
                            WHERE publisher_id = NEW.publisher_id AND key_id = NEW.key_id
                            ORDER BY sequence DESC LIMIT 1
                        ) = 'trusted'
                        AND NEW.trust_state IN ('suspended', 'revoked')
                    )
                    OR (
                        (
                            SELECT trust_state FROM action_package_publisher_trust_events
                            WHERE publisher_id = NEW.publisher_id AND key_id = NEW.key_id
                            ORDER BY sequence DESC LIMIT 1
                        ) = 'suspended'
                        AND NEW.trust_state = 'revoked'
                    )
                )
                BEGIN
                    SELECT RAISE(ABORT, 'invalid action-package trust transition');
                END;

                CREATE TRIGGER IF NOT EXISTS action_package_trust_events_no_delete
                BEFORE DELETE ON action_package_publisher_trust_events
                BEGIN
                    SELECT RAISE(ABORT, 'action-package trust events are append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS action_package_versions_no_update
                BEFORE UPDATE ON action_package_versions
                BEGIN
                    SELECT RAISE(ABORT, 'action-package versions are immutable');
                END;

                CREATE TRIGGER IF NOT EXISTS action_package_versions_no_delete
                BEFORE DELETE ON action_package_versions
                BEGIN
                    SELECT RAISE(ABORT, 'action-package versions are immutable');
                END;

                CREATE TRIGGER IF NOT EXISTS legacy_action_package_metadata_no_update
                BEFORE UPDATE ON legacy_action_package_metadata
                BEGIN
                    SELECT RAISE(ABORT, 'legacy action-package metadata is immutable');
                END;

                CREATE TRIGGER IF NOT EXISTS legacy_action_package_metadata_no_delete
                BEFORE DELETE ON legacy_action_package_metadata
                BEGIN
                    SELECT RAISE(ABORT, 'legacy action-package metadata is immutable');
                END;
                """)
            # sqlite3.executescript commits a pending transaction before running
            # its script. Re-enter one write transaction so schema inspection,
            # backfill, and the migration marker commit atomically.
            if not connection.in_transaction:
                connection.execute("BEGIN IMMEDIATE")
            current = connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0]
            if current is not None and int(current) > SCHEMA_VERSION:
                raise ProductStoreError("product database schema is newer than this application")
            columns = {
                str(row["name"])
                for row in connection.execute("PRAGMA table_info(approval_requests)").fetchall()
            }
            if "claimed_at" not in columns:
                connection.execute("ALTER TABLE approval_requests ADD COLUMN claimed_at TEXT")
            self._backfill_detection_revisions(connection)
            if current is None or int(current) < 6:
                self._migrate_legacy_plugin_metadata(connection)
            if current is None or int(current) < SCHEMA_VERSION:
                connection.execute(
                    "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                    (SCHEMA_VERSION, utc_now()),
                )

    @staticmethod
    def _migrate_legacy_plugin_metadata(connection: sqlite3.Connection) -> None:
        """Quarantine v5 declarative plugins without discarding their history.

        The former ``resources/plugin`` records represented metadata only, but
        their ``active`` status could be mistaken for executable package state.
        Capture the exact legacy row before demoting its status.  No package
        version, installed head, trust record, or executable capability is
        synthesized by this migration.
        """

        captured_at = utc_now()
        rows = connection.execute("""
            SELECT resource_id, document_json, digest, status, created_at, updated_at
            FROM resources WHERE kind = 'plugin' ORDER BY resource_id
            """).fetchall()
        for row in rows:
            expected = (
                str(row["document_json"]),
                str(row["digest"]),
                str(row["status"]),
                str(row["created_at"]),
                str(row["updated_at"]),
            )
            existing = connection.execute(
                """
                SELECT document_json, digest, legacy_status,
                       resource_created_at, resource_updated_at
                FROM legacy_action_package_metadata WHERE resource_id = ?
                """,
                (row["resource_id"],),
            ).fetchone()
            if existing is not None:
                actual = tuple(str(existing[index]) for index in range(5))
                if actual != expected:
                    raise ActionPackageConflictError(
                        "legacy action-package metadata conflicts with its v5 resource"
                    )
            else:
                connection.execute(
                    """
                    INSERT INTO legacy_action_package_metadata(
                        resource_id, document_json, digest, legacy_status,
                        resource_created_at, resource_updated_at, captured_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        *(
                            (row[key])
                            for key in (
                                "resource_id",
                                "document_json",
                                "digest",
                                "status",
                                "created_at",
                                "updated_at",
                            )
                        ),
                        captured_at,
                    ),
                )
        if rows:
            connection.execute(
                """
                UPDATE resources SET status = 'legacy_metadata', updated_at = ?
                WHERE kind = 'plugin' AND status != 'legacy_metadata'
                """,
                (captured_at,),
            )

    @classmethod
    def _backfill_detection_revisions(cls, connection: sqlite3.Connection) -> None:
        """Index readable legacy/v2 resources without rewriting their documents."""

        rows = connection.execute("""
            SELECT resource_id, document_json, created_at
            FROM resources WHERE kind = 'detection'
            ORDER BY created_at, resource_id
            """).fetchall()
        for row in rows:
            try:
                document = json.loads(str(row["document_json"]))
            except (TypeError, ValueError, json.JSONDecodeError):
                continue
            if not isinstance(document, Mapping):
                continue
            identity = _detection_revision_identity(document, strict=False)
            if identity is None or identity[0] != str(row["resource_id"]):
                continue
            cls._register_detection_revision(
                connection,
                candidate_id=identity[0],
                revision=identity[1],
                revision_root_id=identity[2],
                created_at=str(row["created_at"]),
            )

    @staticmethod
    def _register_detection_revision(
        connection: sqlite3.Connection,
        *,
        candidate_id: str,
        revision: int,
        revision_root_id: str,
        created_at: str,
    ) -> None:
        ordinal = connection.execute(
            """
            SELECT candidate_id FROM detection_revisions
            WHERE revision_root_id = ? AND revision = ?
            """,
            (revision_root_id, revision),
        ).fetchone()
        if ordinal is not None and str(ordinal["candidate_id"]) != candidate_id:
            raise DetectionRevisionIntegrityError(
                "persisted detection lineage contains a duplicate revision ordinal"
            )
        candidate = connection.execute(
            """
            SELECT revision_root_id, revision FROM detection_revisions
            WHERE candidate_id = ?
            """,
            (candidate_id,),
        ).fetchone()
        if candidate is not None and (
            str(candidate["revision_root_id"]) != revision_root_id
            or int(candidate["revision"]) != revision
        ):
            raise DetectionRevisionIntegrityError(
                "persisted detection candidate has conflicting revision identities"
            )
        connection.execute(
            """
            INSERT INTO detection_revisions(
                revision_root_id, revision, candidate_id, created_at
            ) VALUES (?, ?, ?, ?)
            ON CONFLICT(revision_root_id, revision) DO NOTHING
            """,
            (revision_root_id, revision, candidate_id, created_at),
        )

    @property
    def schema_version(self) -> int:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT MAX(version) AS version FROM schema_migrations"
            ).fetchone()
        return int(row["version"])

    def set_setting(self, key: str, value: Any) -> Mapping[str, Any]:
        setting_key = _identifier(key, "setting key")
        document = _safe_document(value, context=f"setting.{setting_key}")
        now = utc_now()
        with self._connection(write=True) as connection:
            connection.execute(
                """
                INSERT INTO settings(key, value_json, updated_at) VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    value_json = excluded.value_json,
                    updated_at = excluded.updated_at
                """,
                (setting_key, _canonical_json(document), now),
            )
        return {"key": setting_key, "value": document, "updated_at": now}

    def get_setting(self, key: str, default: Any = None) -> Any:
        setting_key = _identifier(key, "setting key")
        with self._connection() as connection:
            row = connection.execute(
                "SELECT value_json FROM settings WHERE key = ?", (setting_key,)
            ).fetchone()
        return json.loads(row["value_json"]) if row else json_clone(default)

    def list_settings(self) -> list[Mapping[str, Any]]:
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT key, value_json, updated_at FROM settings ORDER BY key"
            ).fetchall()
        return [
            {
                "key": row["key"],
                "value": json.loads(row["value_json"]),
                "updated_at": row["updated_at"],
            }
            for row in rows
        ]

    def save_scenario(
        self,
        value: Mapping[str, Any],
        *,
        activate: bool = True,
    ) -> Mapping[str, Any]:
        """Persist one content-addressed version and optionally select it.

        Explicit product-management saves activate the persisted version.  Built-in
        bootstrap imports pass ``activate=False`` so an unseen packaged version is
        added without replacing an operator-selected head.  A scenario with no head
        is still activated on first import.
        """

        if not isinstance(activate, bool):
            raise ProductStoreError("scenario activation choice must be boolean")
        scenario = ScenarioDefinition.from_mapping(value)
        document = scenario.to_dict()
        digest = content_hash(document)
        now = utc_now()
        with self._connection(write=True) as connection:
            existing = connection.execute(
                """
                SELECT version, created_at FROM scenario_versions
                WHERE scenario_id = ? AND digest = ?
                """,
                (scenario.id, digest),
            ).fetchone()
            if existing:
                version = int(existing["version"])
                created_at = str(existing["created_at"])
            else:
                row = connection.execute(
                    "SELECT COALESCE(MAX(version), 0) AS version FROM scenario_versions WHERE scenario_id = ?",
                    (scenario.id,),
                ).fetchone()
                version = int(row["version"]) + 1
                created_at = now
                connection.execute(
                    """
                    INSERT INTO scenario_versions(
                        scenario_id, version, title, document_json, digest, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scenario.id,
                        version,
                        scenario.title,
                        _canonical_json(document),
                        digest,
                        created_at,
                    ),
                )
            if activate:
                connection.execute(
                    """
                    INSERT INTO scenario_heads(scenario_id, active_version, updated_at)
                    VALUES (?, ?, ?)
                    ON CONFLICT(scenario_id) DO UPDATE SET
                        active_version = excluded.active_version,
                        updated_at = excluded.updated_at
                    """,
                    (scenario.id, version, now),
                )
            else:
                connection.execute(
                    """
                    INSERT INTO scenario_heads(scenario_id, active_version, updated_at)
                    VALUES (?, ?, ?)
                    ON CONFLICT(scenario_id) DO NOTHING
                    """,
                    (scenario.id, version, now),
                )
        return {
            "scenario_id": scenario.id,
            "title": scenario.title,
            "version": version,
            "digest": digest,
            "created_at": created_at,
            "updated_at": now,
            "document": document,
        }

    def get_scenario(self, scenario_id: str, version: int | None = None) -> Mapping[str, Any]:
        stable_id = _identifier(scenario_id, "scenario ID")
        if version is not None and (isinstance(version, bool) or version <= 0):
            raise ProductStoreError("scenario version must be a positive integer")
        with self._connection() as connection:
            if version is None:
                row = connection.execute(
                    """
                    SELECT v.* FROM scenario_versions AS v
                    JOIN scenario_heads AS h
                      ON h.scenario_id = v.scenario_id AND h.active_version = v.version
                    WHERE v.scenario_id = ?
                    """,
                    (stable_id,),
                ).fetchone()
            else:
                row = connection.execute(
                    "SELECT * FROM scenario_versions WHERE scenario_id = ? AND version = ?",
                    (stable_id, version),
                ).fetchone()
        if row is None:
            raise ProductStoreError("scenario version was not found")
        return self._scenario_row(row)

    def list_scenarios(self) -> list[Mapping[str, Any]]:
        with self._connection() as connection:
            rows = connection.execute("""
                SELECT v.* FROM scenario_versions AS v
                JOIN scenario_heads AS h
                  ON h.scenario_id = v.scenario_id AND h.active_version = v.version
                ORDER BY v.title, v.scenario_id
                """).fetchall()
        return [self._scenario_row(row) for row in rows]

    @staticmethod
    def _scenario_row(row: sqlite3.Row) -> Mapping[str, Any]:
        return {
            "scenario_id": row["scenario_id"],
            "title": row["title"],
            "version": int(row["version"]),
            "digest": row["digest"],
            "created_at": row["created_at"],
            "document": json.loads(row["document_json"]),
        }

    def save_resource(
        self,
        kind: str,
        resource_id: str,
        document: Mapping[str, Any],
        *,
        status: str | None = None,
        replace_existing: bool = True,
    ) -> Mapping[str, Any]:
        if kind not in _RESOURCE_KINDS:
            raise ProductStoreError("resource kind is unsupported")
        stable_id = _identifier(resource_id, f"{kind} ID")
        persisted_status = "draft" if kind == "research_source" else "ready"
        if status is not None:
            persisted_status = status
        if not isinstance(persisted_status, str) or not persisted_status.strip():
            raise ProductStoreError("resource status is required")
        persisted_status = persisted_status.strip()
        if kind == "research_source" and persisted_status not in {"draft", "pinned"}:
            raise ResearchSourceIntegrityError("research source status must be draft or pinned")
        if not isinstance(replace_existing, bool):
            raise ProductStoreError("resource replacement choice must be boolean")
        payload = _safe_document(document, context=f"{kind}.{stable_id}")
        detection_identity = (
            _detection_revision_identity(payload, strict=True) if kind == "detection" else None
        )
        if detection_identity is not None and detection_identity[0] != stable_id:
            raise DetectionRevisionIntegrityError(
                "detection resource ID does not match its candidate identity"
            )
        digest = content_hash(payload)
        document_json = _canonical_json(payload)
        now = utc_now()
        with self._connection(write=True) as connection:
            row = connection.execute(
                "SELECT * FROM resources WHERE kind = ? AND resource_id = ?",
                (kind, stable_id),
            ).fetchone()
            if kind == "plugin" and row is not None:
                legacy = connection.execute(
                    """
                    SELECT 1 FROM legacy_action_package_metadata WHERE resource_id = ?
                    """,
                    (stable_id,),
                ).fetchone()
                if legacy is not None and persisted_status not in {
                    "legacy_metadata",
                    "inactive",
                }:
                    raise ProductStoreError(
                        "legacy plugin metadata cannot be activated as an action package"
                    )
            if row is not None and kind == "research_source":
                if str(row["document_json"]) != document_json:
                    raise ResearchSourceIntegrityError(
                        "research source documents are immutable; use a new research source ID"
                    )
                current_status = str(row["status"])
                if current_status == "pinned" and persisted_status != "pinned":
                    raise ResearchSourceIntegrityError(
                        "a pinned research source cannot be downgraded"
                    )
                if current_status not in {"draft", "pinned"}:
                    raise ResearchSourceIntegrityError(
                        "the existing research source has an invalid persisted status"
                    )
                if not replace_existing:
                    return self._resource_row(row)
                if current_status == persisted_status:
                    return self._resource_row(row)

                # The only mutable field for an existing research source is the
                # one-way review state. BEGIN IMMEDIATE serializes this exact
                # compare-and-promote operation across store instances/processes.
                connection.execute(
                    """
                    UPDATE resources SET status = ?, updated_at = ?
                    WHERE kind = ? AND resource_id = ? AND status = 'draft'
                    """,
                    (persisted_status, now, kind, stable_id),
                )
                promoted = connection.execute(
                    "SELECT * FROM resources WHERE kind = ? AND resource_id = ?",
                    (kind, stable_id),
                ).fetchone()
                if promoted is None:
                    raise ProductStoreError("research source promotion was not persisted")
                return self._resource_row(promoted)
            if row is not None and not replace_existing:
                return self._resource_row(row)
            if detection_identity is not None and row is None and detection_identity[1] != 1:
                raise DetectionRevisionIntegrityError(
                    "new detection revisions require atomic lineage allocation"
                )
            created_at = str(row["created_at"]) if row else now
            connection.execute(
                """
                INSERT INTO resources(
                    kind, resource_id, document_json, digest, status, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(kind, resource_id) DO UPDATE SET
                    document_json = excluded.document_json,
                    digest = excluded.digest,
                    status = excluded.status,
                    updated_at = excluded.updated_at
                """,
                (
                    kind,
                    stable_id,
                    document_json,
                    digest,
                    persisted_status,
                    created_at,
                    now,
                ),
            )
            if detection_identity is not None:
                self._register_detection_revision(
                    connection,
                    candidate_id=detection_identity[0],
                    revision=detection_identity[1],
                    revision_root_id=detection_identity[2],
                    created_at=created_at,
                )
        return {
            "kind": kind,
            "id": stable_id,
            "status": persisted_status,
            "digest": digest,
            "created_at": created_at,
            "updated_at": now,
            "document": payload,
        }

    def save_detection_revision(
        self,
        revision_root_id: str,
        build_document: Callable[[int], Mapping[str, Any]],
        *,
        max_revisions: int,
    ) -> Mapping[str, Any]:
        """Allocate and persist one immutable revision in a single write transaction."""

        stable_root_id = _identifier(revision_root_id, "detection revision root ID")
        if not callable(build_document):
            raise DetectionRevisionIntegrityError("detection revision builder must be callable")
        if (
            isinstance(max_revisions, bool)
            or not isinstance(max_revisions, int)
            or max_revisions < 2
        ):
            raise DetectionRevisionIntegrityError("detection revision bound is invalid")

        with self._connection(write=True) as connection:
            lineage = connection.execute(
                """
                SELECT COUNT(*) AS count, COALESCE(MAX(revision), 0) AS maximum
                FROM detection_revisions WHERE revision_root_id = ?
                """,
                (stable_root_id,),
            ).fetchone()
            count = int(lineage["count"])
            maximum = int(lineage["maximum"])
            if count == 0:
                raise DetectionRevisionIntegrityError(
                    "detection revision root is not durably indexed"
                )
            if count >= max_revisions or maximum >= max_revisions:
                raise DetectionRevisionLimitError(
                    f"detection revision lineage is limited to {max_revisions} definitions"
                )

            revision = maximum + 1
            document = build_document(revision)
            payload = _safe_document(
                document,
                context=f"detection revision {stable_root_id}.{revision}",
            )
            if not isinstance(payload, Mapping):
                raise DetectionRevisionIntegrityError(
                    "detection revision builder must return a JSON object"
                )
            candidate_id, document_revision, document_root_id = cast(
                tuple[str, int, str],
                _detection_revision_identity(payload, strict=True),
            )
            if document_revision != revision or document_root_id != stable_root_id:
                raise DetectionRevisionIntegrityError(
                    "allocated detection revision does not match its document identity"
                )
            if connection.execute(
                "SELECT 1 FROM resources WHERE kind = 'detection' AND resource_id = ?",
                (candidate_id,),
            ).fetchone():
                raise DetectionRevisionIntegrityError(
                    "allocated detection candidate identity already exists"
                )

            status = payload.get("state")
            if not isinstance(status, str) or not status:
                raise DetectionRevisionIntegrityError(
                    "detection revision document has no persisted lifecycle state"
                )
            document_json = _canonical_json(payload)
            digest = content_hash(payload)
            created_at = utc_now()
            connection.execute(
                """
                INSERT INTO resources(
                    kind, resource_id, document_json, digest, status, created_at, updated_at
                ) VALUES ('detection', ?, ?, ?, ?, ?, ?)
                """,
                (
                    candidate_id,
                    document_json,
                    digest,
                    status,
                    created_at,
                    created_at,
                ),
            )
            self._register_detection_revision(
                connection,
                candidate_id=candidate_id,
                revision=revision,
                revision_root_id=stable_root_id,
                created_at=created_at,
            )
            row = connection.execute(
                "SELECT * FROM resources WHERE kind = 'detection' AND resource_id = ?",
                (candidate_id,),
            ).fetchone()
            if row is None:
                raise DetectionRevisionIntegrityError(
                    "allocated detection revision was not persisted"
                )
            return self._resource_row(row)

    def get_resource(self, kind: str, resource_id: str) -> Mapping[str, Any]:
        stable_id = _identifier(resource_id, f"{kind} ID")
        rows = self._resource_rows(kind, resource_id=stable_id)
        if not rows:
            raise ProductStoreError("resource was not found")
        return rows[0]

    def list_resources(self, kind: str) -> list[Mapping[str, Any]]:
        return self._resource_rows(kind)

    def _resource_rows(
        self, kind: str, *, resource_id: str | None = None
    ) -> list[Mapping[str, Any]]:
        if kind not in _RESOURCE_KINDS:
            raise ProductStoreError("resource kind is unsupported")
        with self._connection() as connection:
            if resource_id is None:
                rows = connection.execute(
                    "SELECT * FROM resources WHERE kind = ? ORDER BY resource_id", (kind,)
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM resources WHERE kind = ? AND resource_id = ?",
                    (kind, resource_id),
                ).fetchall()
        return [self._resource_row(row) for row in rows]

    @staticmethod
    def _resource_row(row: sqlite3.Row) -> Mapping[str, Any]:
        return {
            "kind": row["kind"],
            "id": row["resource_id"],
            "status": row["status"],
            "digest": row["digest"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "document": json.loads(row["document_json"]),
        }

    @staticmethod
    def _trusted_action_package_publisher_select_sql() -> str:
        return """
            SELECT
                p.*,
                e.trust_state AS current_trust_state,
                e.sequence AS current_trust_event_sequence,
                e.created_at AS trust_updated_at
            FROM trusted_action_package_publishers AS p
            LEFT JOIN action_package_publisher_trust_events AS e
              ON e.sequence = (
                  SELECT MAX(latest.sequence)
                  FROM action_package_publisher_trust_events AS latest
                  WHERE latest.publisher_id = p.publisher_id
                    AND latest.key_id = p.key_id
              )
            """

    @staticmethod
    def _audit_action_package_publisher_trust(
        connection: sqlite3.Connection,
        publisher_id: str,
        key_id: str,
    ) -> Mapping[str, Any]:
        events = connection.execute(
            """
            SELECT sequence, trust_state, actor, reason, created_at
            FROM action_package_publisher_trust_events
            WHERE publisher_id = ? AND key_id = ? ORDER BY sequence
            """,
            (publisher_id, key_id),
        ).fetchall()
        if not events:
            raise ActionPackageIntegrityError(
                "action-package publisher has no durable local trust event"
            )
        previous: str | None = None
        for event in events:
            state = str(event["trust_state"])
            allowed = (
                {"trusted"}
                if previous is None
                else (
                    {"suspended", "revoked"}
                    if previous == "trusted"
                    else {"revoked"} if previous == "suspended" else set()
                )
            )
            if state not in allowed:
                raise ActionPackageIntegrityError(
                    "action-package publisher trust event chain is invalid"
                )
            try:
                _package_actor(event["actor"], "persisted action-package trust actor")
                _package_trust_reason(event["reason"])
            except ProductStoreError as exc:
                raise ActionPackageIntegrityError(
                    "persisted action-package trust event is malformed"
                ) from exc
            previous = state
        latest = events[-1]
        return {
            "trust_state": latest["trust_state"],
            "event_sequence": int(latest["sequence"]),
            "updated_at": latest["created_at"],
        }

    @classmethod
    def _trusted_action_package_publisher_with_audit(
        cls,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> Mapping[str, Any]:
        record = cls._trusted_action_package_publisher_from_row(row)
        audit = cls._audit_action_package_publisher_trust(
            connection,
            str(record["publisher_id"]),
            str(record["key_id"]),
        )
        if (
            record["trust_state"] != audit["trust_state"]
            or record["trust_event_sequence"] != audit["event_sequence"]
            or record["trust_updated_at"] != audit["updated_at"]
        ):
            raise ActionPackageIntegrityError(
                "action-package publisher trust projection failed its audit"
            )
        return record

    def trust_action_package_publisher(
        self,
        *,
        publisher_id: str,
        key_id: str,
        public_key: Any,
        provenance: Mapping[str, Any],
        trusted_by: str,
    ) -> Mapping[str, Any]:
        """Enroll one exact local publisher/key binding.

        A package envelope cannot create or modify this record.  Key bytes are
        normalized and fingerprinted locally, and an existing binding is
        immutable.  Repeating the exact enrollment is idempotent.
        """

        from .action_packages import (
            ActionPackageError,
            canonical_public_key_b64u,
            ed25519_public_key_fingerprint,
            normalize_ed25519_public_key,
        )

        stable_publisher_id = _identifier(publisher_id, "action-package publisher ID")
        stable_key_id = _identifier(key_id, "action-package publisher key ID")
        actor = _package_actor(trusted_by, "action-package trust actor")
        try:
            normalized_key = normalize_ed25519_public_key(public_key)
            public_key_b64u = canonical_public_key_b64u(normalized_key)
            fingerprint = ed25519_public_key_fingerprint(normalized_key)
        except ActionPackageError as exc:
            raise ActionPackageIntegrityError(
                "action-package publisher key is not a valid Ed25519 public key"
            ) from exc
        safe_provenance = _safe_document(
            provenance,
            context=f"action-package publisher {stable_publisher_id} provenance",
        )
        if not isinstance(safe_provenance, Mapping):
            raise ProductStoreError("action-package publisher provenance must be a JSON object")
        provenance_json = _canonical_json(safe_provenance)
        now = utc_now()
        with self._connection(write=True) as connection:
            existing = connection.execute(
                self._trusted_action_package_publisher_select_sql()
                + " WHERE p.publisher_id = ? AND p.key_id = ?",
                (stable_publisher_id, stable_key_id),
            ).fetchone()
            if existing is not None:
                immutable = (
                    bytes(existing["public_key_bytes"]),
                    str(existing["public_key_b64u"]),
                    str(existing["key_fingerprint"]),
                    str(existing["provenance_json"]),
                    str(existing["trusted_by"]),
                )
                requested = (
                    normalized_key,
                    public_key_b64u,
                    fingerprint,
                    provenance_json,
                    actor,
                )
                if immutable != requested:
                    raise ActionPackageConflictError(
                        "trusted action-package publisher binding is immutable"
                    )
                if existing["current_trust_state"] != "trusted":
                    raise ActionPackageConflictError(
                        "a suspended or revoked action-package signing key cannot be re-trusted"
                    )
                return self._trusted_action_package_publisher_with_audit(connection, existing)

            key_owner = connection.execute(
                """
                SELECT publisher_id, key_id FROM trusted_action_package_publishers
                WHERE public_key_b64u = ? OR key_fingerprint = ?
                """,
                (public_key_b64u, fingerprint),
            ).fetchone()
            if key_owner is not None:
                raise ActionPackageConflictError(
                    "action-package signing key is already bound to another publisher identity"
                )
            connection.execute(
                """
                INSERT INTO trusted_action_package_publishers(
                    publisher_id, key_id, public_key_bytes, public_key_b64u, key_fingerprint,
                    provenance_json, trusted_by, trusted_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    stable_publisher_id,
                    stable_key_id,
                    normalized_key,
                    public_key_b64u,
                    fingerprint,
                    provenance_json,
                    actor,
                    now,
                ),
            )
            event = connection.execute(
                """
                INSERT INTO action_package_publisher_trust_events(
                    event_id, publisher_id, key_id, trust_state,
                    actor, reason, created_at
                ) VALUES (?, ?, ?, 'trusted', ?, ?, ?)
                """,
                (
                    f"action-package-trust-event-{uuid.uuid4().hex}",
                    stable_publisher_id,
                    stable_key_id,
                    actor,
                    "initial local publisher enrollment",
                    now,
                ),
            )
            event_sequence = event.lastrowid
            if event_sequence is None:
                raise ProductStoreError("action-package trust event was not persisted")
            row = connection.execute(
                self._trusted_action_package_publisher_select_sql()
                + " WHERE p.publisher_id = ? AND p.key_id = ?",
                (stable_publisher_id, stable_key_id),
            ).fetchone()
            if row is None:
                raise ProductStoreError("action-package publisher trust was not persisted")
            return self._trusted_action_package_publisher_with_audit(connection, row)

    def get_trusted_action_package_publisher(
        self, publisher_id: str, key_id: str
    ) -> Mapping[str, Any]:
        stable_publisher_id = _identifier(publisher_id, "action-package publisher ID")
        stable_key_id = _identifier(key_id, "action-package publisher key ID")
        with self._connection() as connection:
            row = connection.execute(
                self._trusted_action_package_publisher_select_sql()
                + " WHERE p.publisher_id = ? AND p.key_id = ?",
                (stable_publisher_id, stable_key_id),
            ).fetchone()
            if row is None:
                raise ProductStoreError("trusted action-package publisher was not found")
            return self._trusted_action_package_publisher_with_audit(connection, row)

    def list_trusted_action_package_publishers(self) -> list[Mapping[str, Any]]:
        with self._connection() as connection:
            rows = connection.execute(
                self._trusted_action_package_publisher_select_sql()
                + " ORDER BY p.publisher_id, p.key_id"
            ).fetchall()
            return [
                self._trusted_action_package_publisher_with_audit(connection, row) for row in rows
            ]

    def suspend_action_package_publisher(
        self,
        publisher_id: str,
        key_id: str,
        *,
        suspended_by: str,
        reason: str,
    ) -> Mapping[str, Any]:
        return self._transition_action_package_publisher_trust(
            publisher_id,
            key_id,
            trust_state="suspended",
            actor=suspended_by,
            reason=reason,
        )

    def revoke_action_package_publisher(
        self,
        publisher_id: str,
        key_id: str,
        *,
        revoked_by: str,
        reason: str,
    ) -> Mapping[str, Any]:
        return self._transition_action_package_publisher_trust(
            publisher_id,
            key_id,
            trust_state="revoked",
            actor=revoked_by,
            reason=reason,
        )

    def _transition_action_package_publisher_trust(
        self,
        publisher_id: str,
        key_id: str,
        *,
        trust_state: str,
        actor: str,
        reason: str,
    ) -> Mapping[str, Any]:
        stable_publisher_id = _identifier(publisher_id, "action-package publisher ID")
        stable_key_id = _identifier(key_id, "action-package publisher key ID")
        if trust_state not in {"suspended", "revoked"}:
            raise ProductStoreError("action-package trust can only be suspended or revoked")
        trusted_actor = _package_actor(actor, "action-package trust actor")
        trusted_reason = _package_trust_reason(reason)
        now = utc_now()
        with self._connection(write=True) as connection:
            row = connection.execute(
                self._trusted_action_package_publisher_select_sql()
                + " WHERE p.publisher_id = ? AND p.key_id = ?",
                (stable_publisher_id, stable_key_id),
            ).fetchone()
            if row is None:
                raise ProductStoreError("trusted action-package publisher was not found")
            current = self._trusted_action_package_publisher_with_audit(connection, row)
            current_state = str(current["trust_state"])
            if current_state == trust_state:
                return current
            if current_state == "revoked":
                raise ActionPackageConflictError(
                    "revoked action-package publisher trust is permanent"
                )
            event = connection.execute(
                """
                INSERT INTO action_package_publisher_trust_events(
                    event_id, publisher_id, key_id, trust_state,
                    actor, reason, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    f"action-package-trust-event-{uuid.uuid4().hex}",
                    stable_publisher_id,
                    stable_key_id,
                    trust_state,
                    trusted_actor,
                    trusted_reason,
                    now,
                ),
            )
            event_sequence = event.lastrowid
            if event_sequence is None:
                raise ProductStoreError("action-package trust event was not persisted")
            transitioned = connection.execute(
                self._trusted_action_package_publisher_select_sql()
                + " WHERE p.publisher_id = ? AND p.key_id = ?",
                (stable_publisher_id, stable_key_id),
            ).fetchone()
            if transitioned is None:
                raise ProductStoreError("action-package trust transition was not persisted")
            return self._trusted_action_package_publisher_with_audit(connection, transitioned)

    def list_action_package_publisher_trust_events(
        self,
        publisher_id: str,
        key_id: str,
    ) -> list[Mapping[str, Any]]:
        stable_publisher_id = _identifier(publisher_id, "action-package publisher ID")
        stable_key_id = _identifier(key_id, "action-package publisher key ID")
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT * FROM action_package_publisher_trust_events
                WHERE publisher_id = ? AND key_id = ? ORDER BY sequence
                """,
                (stable_publisher_id, stable_key_id),
            ).fetchall()
        return [
            {
                "schema_version": "bluefire.action-package-publisher-trust-event.v1",
                "sequence": int(row["sequence"]),
                "event_id": row["event_id"],
                "publisher_id": row["publisher_id"],
                "key_id": row["key_id"],
                "trust_state": row["trust_state"],
                "actor": row["actor"],
                "reason": row["reason"],
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    def trusted_action_package_signers(self) -> dict[tuple[str, str], bytes]:
        """Return the locally enrolled verifier keyring, never envelope claims."""

        from .action_packages import normalize_ed25519_public_key

        signers: dict[tuple[str, str], bytes] = {}
        with self._connection() as connection:
            rows = connection.execute(
                self._trusted_action_package_publisher_select_sql()
                + " ORDER BY p.publisher_id, p.key_id"
            ).fetchall()
            for row in rows:
                record = self._trusted_action_package_publisher_with_audit(connection, row)
                if record["trust_state"] != "trusted":
                    continue
                signers[(str(record["publisher_id"]), str(record["key_id"]))] = (
                    normalize_ed25519_public_key(bytes(row["public_key_bytes"]))
                )
        return signers

    @staticmethod
    def _trusted_action_package_publisher_from_row(row: sqlite3.Row) -> Mapping[str, Any]:
        from .action_packages import (
            canonical_public_key_b64u,
            ed25519_public_key_fingerprint,
            normalize_ed25519_public_key,
        )

        try:
            public_key = normalize_ed25519_public_key(bytes(row["public_key_bytes"]))
            canonical_key = canonical_public_key_b64u(public_key)
            fingerprint = ed25519_public_key_fingerprint(public_key)
            provenance = json.loads(str(row["provenance_json"]))
            trust_state = str(row["current_trust_state"])
            trust_event_sequence = int(row["current_trust_event_sequence"])
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ActionPackageIntegrityError(
                "persisted action-package publisher trust is malformed"
            ) from exc
        if (
            canonical_key != str(row["public_key_b64u"])
            or fingerprint != str(row["key_fingerprint"])
            or not isinstance(provenance, Mapping)
            or _canonical_json(provenance) != str(row["provenance_json"])
            or trust_state not in {"trusted", "suspended", "revoked"}
        ):
            raise ActionPackageIntegrityError(
                "persisted action-package publisher trust failed its integrity check"
            )
        return {
            "schema_version": "bluefire.action-package-publisher-trust.v1",
            "publisher_id": row["publisher_id"],
            "key_id": row["key_id"],
            "public_key_b64u": canonical_key,
            "key_fingerprint": fingerprint,
            "provenance": provenance,
            "trust_state": trust_state,
            "trust_source": "local_operator",
            "trust_event_sequence": trust_event_sequence,
            "trust_updated_at": row["trust_updated_at"],
            "trusted_by": row["trusted_by"],
            "trusted_at": row["trusted_at"],
        }

    def install_action_package(
        self,
        verified: VerifiedActionPackage,
        *,
        installed_by: str,
        occupied_behavior_ids: Collection[str] = (),
        occupied_action_ids: Collection[str] = (),
    ) -> Mapping[str, Any]:
        """Atomically persist one already-verified immutable package version.

        The verifier result is still cross-bound to its exact canonical bytes
        and hashes here.  Installation additionally requires the signer to
        match an independently enrolled local publisher/key record.
        """

        from .action_packages import ActionPackageError, SemVer, verify_action_package

        package = self._validated_verified_action_package(verified)
        actor = _package_actor(installed_by, "action-package installation actor")
        occupied_behaviors = _occupied_package_ids(occupied_behavior_ids, "occupied behavior IDs")
        occupied_actions = _occupied_package_ids(occupied_action_ids, "occupied action IDs")
        package_id = str(package["package_id"])
        version = str(package["version"])
        now = utc_now()
        with self._connection(write=True) as connection:
            trust_row = connection.execute(
                self._trusted_action_package_publisher_select_sql()
                + " WHERE p.publisher_id = ? AND p.key_id = ?",
                (package["publisher_id"], package["key_id"]),
            ).fetchone()
            if trust_row is None:
                raise ActionPackageIntegrityError(
                    "action-package signer is not enrolled in local publisher trust"
                )
            trust = self._trusted_action_package_publisher_with_audit(connection, trust_row)
            if trust["trust_state"] != "trusted":
                raise ActionPackageIntegrityError(
                    "action-package signer local trust is suspended or revoked"
                )
            if trust["key_fingerprint"] != package["signer_fingerprint"]:
                raise ActionPackageIntegrityError(
                    "action-package signer fingerprint does not match local publisher trust"
                )
            try:
                independently_verified = verify_action_package(
                    bytes(package["canonical_envelope_bytes"]),
                    trusted_signers={
                        (str(package["publisher_id"]), str(package["key_id"])): bytes(
                            trust_row["public_key_bytes"]
                        )
                    },
                    bluefire_version=None,
                    platform=None,
                    occupied_behavior_ids=occupied_behaviors,
                    occupied_action_ids=occupied_actions,
                )
            except ActionPackageError as exc:
                raise ActionPackageIntegrityError(
                    "action package failed independent local cryptographic verification"
                ) from exc
            if independently_verified != verified:
                raise ActionPackageIntegrityError(
                    "action-package verifier result does not exactly match local verification"
                )

            existing = connection.execute(
                """
                SELECT * FROM action_package_versions
                WHERE package_id = ? AND version = ?
                """,
                (package_id, version),
            ).fetchone()
            if existing is not None:
                requested_identity = (
                    package["package_digest"],
                    package["content_digest"],
                    package["publisher_id"],
                    package["key_id"],
                    package["signer_fingerprint"],
                    package["signature_b64u"],
                    package["manifest_json"],
                    package["canonical_envelope_bytes"],
                    package["canonical_content_bytes"],
                )
                persisted_identity = (
                    str(existing["package_digest"]),
                    str(existing["content_digest"]),
                    str(existing["publisher_id"]),
                    str(existing["key_id"]),
                    str(existing["signer_fingerprint"]),
                    str(existing["signature_b64u"]),
                    str(existing["manifest_json"]),
                    bytes(existing["canonical_envelope_bytes"]),
                    bytes(existing["canonical_content_bytes"]),
                )
                if persisted_identity != requested_identity:
                    raise ActionPackageConflictError(
                        "action-package version already exists with different immutable content"
                    )
                # Idempotency preserves the original actor/time, installed head,
                # and append-only event count.
                return self._action_package_detail_from_connection(
                    connection,
                    package_id,
                    version,
                    include_bytes=True,
                )

            digest_owner = connection.execute(
                """
                SELECT package_id, version FROM action_package_versions
                WHERE package_digest = ?
                """,
                (package["package_digest"],),
            ).fetchone()
            if digest_owner is not None:
                raise ActionPackageConflictError(
                    "action-package digest is already bound to another package version"
                )
            publisher_owner = connection.execute(
                """
                SELECT publisher_id FROM action_package_versions
                WHERE package_id = ? ORDER BY installed_at, version LIMIT 1
                """,
                (package_id,),
            ).fetchone()
            if (
                publisher_owner is not None
                and str(publisher_owner["publisher_id"]) != package["publisher_id"]
            ):
                raise ActionPackageConflictError(
                    "action-package identity is already owned by another publisher"
                )

            new_precedence = SemVer.parse(version, "action-package version")
            version_rows = connection.execute(
                "SELECT version FROM action_package_versions WHERE package_id = ?",
                (package_id,),
            ).fetchall()
            for version_row in version_rows:
                installed_version = str(version_row["version"])
                installed_precedence = SemVer.parse(
                    installed_version, "installed action-package version"
                )
                if (
                    installed_version != version
                    and not new_precedence < installed_precedence
                    and not new_precedence > installed_precedence
                ):
                    raise ActionPackageConflictError(
                        "distinct action-package versions cannot share SemVer precedence"
                    )

            head = connection.execute(
                "SELECT installed_version, active_version FROM action_package_heads WHERE package_id = ?",
                (package_id,),
            ).fetchone()
            if head is not None and head["active_version"] is not None:
                raise ActionPackageIntegrityError(
                    "action-package active state has no append-only activation event"
                )
            previous_version = self._derived_action_package_installed_head(connection, package_id)
            selected_as_installed_head = previous_version is None or new_precedence > SemVer.parse(
                previous_version, "installed action-package version"
            )
            connection.execute(
                """
                INSERT INTO action_package_versions(
                    package_id, version, package_digest, content_digest,
                    publisher_id, key_id, signer_fingerprint, signature_b64u,
                    occupied_behavior_ids_json, occupied_action_ids_json,
                    manifest_json, canonical_envelope_bytes, canonical_content_bytes,
                    installed_by, installed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    package_id,
                    version,
                    package["package_digest"],
                    package["content_digest"],
                    package["publisher_id"],
                    package["key_id"],
                    package["signer_fingerprint"],
                    package["signature_b64u"],
                    _canonical_json(list(occupied_behaviors)),
                    _canonical_json(list(occupied_actions)),
                    package["manifest_json"],
                    package["canonical_envelope_bytes"],
                    package["canonical_content_bytes"],
                    actor,
                    now,
                ),
            )
            selected_version = (
                version if selected_as_installed_head else cast(str, previous_version)
            )
            connection.execute(
                """
                INSERT INTO action_package_heads(
                    package_id, installed_version, active_version, updated_at
                ) VALUES (?, ?, NULL, ?)
                ON CONFLICT(package_id) DO UPDATE SET
                    installed_version = excluded.installed_version,
                    updated_at = excluded.updated_at
                """,
                (package_id, selected_version, now),
            )
            event_details = {
                "schema_version": "bluefire.action-package-lifecycle-details.v1",
                "package_digest": package["package_digest"],
                "content_digest": package["content_digest"],
                "publisher_id": package["publisher_id"],
                "key_id": package["key_id"],
                "previous_installed_version": previous_version,
                "selected_as_installed_head": selected_as_installed_head,
            }
            connection.execute(
                """
                INSERT INTO action_package_lifecycle_events(
                    event_id, package_id, version, event_type,
                    actor, details_json, created_at
                ) VALUES (?, ?, ?, 'installed', ?, ?, ?)
                """,
                (
                    f"action-package-event-{uuid.uuid4().hex}",
                    package_id,
                    version,
                    actor,
                    _canonical_json(event_details),
                    now,
                ),
            )
            return self._action_package_detail_from_connection(
                connection,
                package_id,
                version,
                include_bytes=True,
            )

    @staticmethod
    def _validated_verified_action_package(
        verified: VerifiedActionPackage,
    ) -> Mapping[str, Any]:
        from .action_packages import VerifiedActionPackage

        if not isinstance(verified, VerifiedActionPackage):
            raise ActionPackageIntegrityError(
                "action-package installation requires a verifier result"
            )
        envelope_bytes = _bounded_package_bytes(
            verified.canonical_envelope_bytes,
            "canonical action-package envelope",
        )
        content_bytes = _bounded_package_bytes(
            verified.canonical_content_bytes,
            "canonical action-package content",
        )
        package_digest = _exact_sha256_digest(verified.package_digest, "action-package digest")
        content_digest = _exact_sha256_digest(
            verified.content_digest, "action-package content digest"
        )
        signer_fingerprint = _exact_sha256_digest(
            verified.public_key_fingerprint,
            "action-package signer fingerprint",
        )
        if _sha256_bytes(envelope_bytes) != package_digest:
            raise ActionPackageIntegrityError("action-package envelope digest does not match")
        if _sha256_bytes(content_bytes) != content_digest:
            raise ActionPackageIntegrityError("action-package content digest does not match")

        envelope = _canonical_package_object(envelope_bytes, "action-package envelope")
        content = _canonical_package_object(content_bytes, "action-package content")
        manifest = verified.manifest.to_dict()
        if not isinstance(manifest, Mapping):
            raise ActionPackageIntegrityError("verified action-package manifest is malformed")
        manifest_json = _canonical_json(manifest)
        expected_content = {
            "schema_version": envelope.get("schema_version"),
            "manifest": envelope.get("manifest"),
            "payload": envelope.get("payload"),
        }
        if content != expected_content or content.get("manifest") != manifest:
            raise ActionPackageIntegrityError(
                "verified action-package content is not bound to its envelope and manifest"
            )
        integrity = envelope.get("integrity")
        signature = envelope.get("signature")
        if (
            not isinstance(integrity, Mapping)
            or set(integrity) != {"algorithm", "content_digest"}
            or integrity.get("algorithm") != "sha256"
            or integrity.get("content_digest") != content_digest
        ):
            raise ActionPackageIntegrityError(
                "verified action-package integrity block is not exact"
            )
        if (
            not isinstance(signature, Mapping)
            or set(signature) != {"algorithm", "key_id", "value"}
            or signature.get("algorithm") != "ed25519"
            or signature.get("key_id") != verified.key_id
            or signature.get("value") != verified.signature_b64u
        ):
            raise ActionPackageIntegrityError(
                "verified action-package signature block is not exact"
            )
        provenance = manifest.get("provenance")
        package_id = _identifier(manifest.get("package_id"), "action-package ID")
        version = manifest.get("version")
        if not isinstance(version, str) or _ACTION_PACKAGE_VERSION.fullmatch(version) is None:
            raise ActionPackageIntegrityError("action-package version must be canonical SemVer")
        publisher_id = _identifier(verified.publisher_id, "action-package publisher ID")
        key_id = _identifier(verified.key_id, "action-package publisher key ID")
        if not isinstance(provenance, Mapping) or provenance.get("publisher_id") != publisher_id:
            raise ActionPackageIntegrityError(
                "verified action-package publisher is not bound to its manifest"
            )
        if verified.manifest.package_id != package_id or verified.manifest.version != version:
            raise ActionPackageIntegrityError(
                "verified action-package identity is not bound to its manifest"
            )
        if not isinstance(verified.signature_b64u, str) or not verified.signature_b64u:
            raise ActionPackageIntegrityError("action-package signature encoding is invalid")
        return {
            "package_id": package_id,
            "version": version,
            "package_digest": package_digest,
            "content_digest": content_digest,
            "publisher_id": publisher_id,
            "key_id": key_id,
            "signer_fingerprint": signer_fingerprint,
            "signature_b64u": verified.signature_b64u,
            "manifest": manifest,
            "manifest_json": manifest_json,
            "canonical_envelope_bytes": envelope_bytes,
            "canonical_content_bytes": content_bytes,
        }

    @staticmethod
    def _derived_action_package_installed_head(
        connection: sqlite3.Connection,
        package_id: str,
    ) -> str | None:
        from .action_packages import SemVer

        rows = connection.execute(
            "SELECT version FROM action_package_versions WHERE package_id = ?",
            (package_id,),
        ).fetchall()
        selected_text: str | None = None
        selected_precedence: SemVer | None = None
        for row in rows:
            version = str(row["version"])
            precedence = SemVer.parse(version, "persisted action-package version")
            if selected_precedence is None or precedence > selected_precedence:
                selected_text = version
                selected_precedence = precedence
                continue
            if precedence == selected_precedence and version != selected_text:
                raise ActionPackageIntegrityError(
                    "persisted action-package versions have ambiguous SemVer precedence"
                )
        return selected_text

    def get_action_package(
        self,
        package_id: str,
        version: str | None = None,
    ) -> Mapping[str, Any]:
        stable_id = _identifier(package_id, "action-package ID")
        if version is not None and (
            not isinstance(version, str) or _ACTION_PACKAGE_VERSION.fullmatch(version) is None
        ):
            raise ProductStoreError("action-package version must be canonical SemVer")
        with self._connection() as connection:
            if version is None:
                selected_version = self._derived_action_package_installed_head(
                    connection, stable_id
                )
                if selected_version is None:
                    raise ProductStoreError("installed action package was not found")
            else:
                selected_version = version
            return self._action_package_detail_from_connection(
                connection,
                stable_id,
                selected_version,
                include_bytes=True,
            )

    def list_action_packages(self) -> list[Mapping[str, Any]]:
        """List each installed package head without returning stored blobs."""

        with self._connection() as connection:
            package_ids = connection.execute(
                "SELECT DISTINCT package_id FROM action_package_versions ORDER BY package_id"
            ).fetchall()
            return [
                self._action_package_detail_from_connection(
                    connection,
                    str(item["package_id"]),
                    cast(
                        str,
                        self._derived_action_package_installed_head(
                            connection, str(item["package_id"])
                        ),
                    ),
                    include_bytes=False,
                )
                for item in package_ids
            ]

    def list_action_package_versions(self, package_id: str) -> list[Mapping[str, Any]]:
        stable_id = _identifier(package_id, "action-package ID")
        with self._connection() as connection:
            derived_head = self._derived_action_package_installed_head(connection, stable_id)
            rows = connection.execute(
                self._action_package_select_sql()
                + " WHERE v.package_id = ? ORDER BY v.installed_at, v.version",
                (stable_id,),
            ).fetchall()
            return [
                self._action_package_from_row(
                    row,
                    include_bytes=False,
                    derived_installed_version=derived_head,
                    audited_trust=self._audit_action_package_publisher_trust(
                        connection, str(row["publisher_id"]), str(row["key_id"])
                    ),
                )
                for row in rows
            ]

    def list_action_package_lifecycle_events(
        self,
        package_id: str,
    ) -> list[Mapping[str, Any]]:
        from .action_packages import SemVer

        stable_id = _identifier(package_id, "action-package ID")
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT
                    e.*,
                    v.package_digest AS version_package_digest,
                    v.content_digest AS version_content_digest,
                    v.publisher_id AS version_publisher_id,
                    v.key_id AS version_key_id,
                    v.installed_by AS version_installed_by,
                    v.installed_at AS version_installed_at
                FROM action_package_lifecycle_events AS e
                JOIN action_package_versions AS v
                  ON v.package_id = e.package_id AND v.version = e.version
                WHERE e.package_id = ? ORDER BY e.sequence
                """,
                (stable_id,),
            ).fetchall()
            version_count = int(
                connection.execute(
                    "SELECT COUNT(*) FROM action_package_versions WHERE package_id = ?",
                    (stable_id,),
                ).fetchone()[0]
            )
        if len(rows) != version_count:
            raise ActionPackageIntegrityError(
                "action-package install events do not cover every immutable version"
            )
        events: list[Mapping[str, Any]] = []
        previous_version: str | None = None
        previous_precedence: SemVer | None = None
        for row in rows:
            try:
                details = json.loads(str(row["details_json"]))
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                raise ActionPackageIntegrityError(
                    "persisted action-package lifecycle event is malformed"
                ) from exc
            precedence = SemVer.parse(str(row["version"]), "persisted action-package version")
            selected_as_head = previous_precedence is None or precedence > previous_precedence
            expected_details = {
                "schema_version": "bluefire.action-package-lifecycle-details.v1",
                "package_digest": row["version_package_digest"],
                "content_digest": row["version_content_digest"],
                "publisher_id": row["version_publisher_id"],
                "key_id": row["version_key_id"],
                "previous_installed_version": previous_version,
                "selected_as_installed_head": selected_as_head,
            }
            if (
                not isinstance(details, Mapping)
                or _canonical_json(details) != str(row["details_json"])
                or details != expected_details
                or row["event_type"] != "installed"
                or re.fullmatch(r"action-package-event-[0-9a-f]{32}", str(row["event_id"])) is None
                or row["actor"] != row["version_installed_by"]
                or row["created_at"] != row["version_installed_at"]
            ):
                raise ActionPackageIntegrityError(
                    "persisted action-package lifecycle event failed its integrity check"
                )
            events.append(
                {
                    "schema_version": "bluefire.action-package-lifecycle-event.v1",
                    "sequence": int(row["sequence"]),
                    "event_id": row["event_id"],
                    "package_id": row["package_id"],
                    "version": row["version"],
                    "event_type": row["event_type"],
                    "actor": row["actor"],
                    "details": details,
                    "created_at": row["created_at"],
                }
            )
            if selected_as_head:
                previous_version = str(row["version"])
                previous_precedence = precedence
        return events

    def list_legacy_action_package_metadata(self) -> list[Mapping[str, Any]]:
        """Return quarantined v5 plugin metadata; never executable inventory."""

        with self._connection() as connection:
            rows = connection.execute("""
                SELECT * FROM legacy_action_package_metadata ORDER BY resource_id
                """).fetchall()
        records: list[Mapping[str, Any]] = []
        for row in rows:
            try:
                document = json.loads(str(row["document_json"]))
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                raise ActionPackageIntegrityError(
                    "legacy action-package metadata is malformed"
                ) from exc
            records.append(
                {
                    "schema_version": "bluefire.legacy-action-package-metadata.v1",
                    "resource_id": row["resource_id"],
                    "document": document,
                    "digest": row["digest"],
                    "legacy_status": row["legacy_status"],
                    "status": "legacy_metadata",
                    "executable": False,
                    "resource_created_at": row["resource_created_at"],
                    "resource_updated_at": row["resource_updated_at"],
                    "captured_at": row["captured_at"],
                }
            )
        return records

    @staticmethod
    def _action_package_select_sql() -> str:
        return """
            SELECT
                v.*,
                h.installed_version AS head_installed_version,
                h.active_version AS head_active_version,
                h.updated_at AS head_updated_at,
                p.public_key_bytes AS trusted_public_key_bytes,
                p.public_key_b64u AS trusted_public_key_b64u,
                p.key_fingerprint AS trusted_key_fingerprint,
                p.provenance_json AS trusted_provenance_json,
                p.trusted_by AS publisher_trusted_by,
                p.trusted_at AS publisher_trusted_at,
                pe.trust_state AS publisher_trust_state,
                pe.sequence AS publisher_trust_event_sequence,
                pe.created_at AS publisher_trust_updated_at,
                t.package_digest AS tombstone_package_digest,
                t.removed_by AS tombstone_removed_by,
                t.reason AS tombstone_reason,
                t.removed_at AS tombstone_removed_at
            FROM action_package_versions AS v
            LEFT JOIN action_package_heads AS h ON h.package_id = v.package_id
            LEFT JOIN trusted_action_package_publishers AS p
              ON p.publisher_id = v.publisher_id AND p.key_id = v.key_id
            LEFT JOIN action_package_publisher_trust_events AS pe
              ON pe.sequence = (
                  SELECT MAX(latest.sequence)
                  FROM action_package_publisher_trust_events AS latest
                  WHERE latest.publisher_id = v.publisher_id
                    AND latest.key_id = v.key_id
              )
            LEFT JOIN action_package_tombstones AS t
              ON t.package_id = v.package_id AND t.version = v.version
            """

    @classmethod
    def _action_package_detail_from_connection(
        cls,
        connection: sqlite3.Connection,
        package_id: str,
        version: str,
        *,
        include_bytes: bool,
    ) -> Mapping[str, Any]:
        row = connection.execute(
            cls._action_package_select_sql() + " WHERE v.package_id = ? AND v.version = ?",
            (package_id, version),
        ).fetchone()
        if row is None:
            raise ProductStoreError("action-package version was not found")
        return cls._action_package_from_row(
            row,
            include_bytes=include_bytes,
            derived_installed_version=cls._derived_action_package_installed_head(
                connection, package_id
            ),
            audited_trust=cls._audit_action_package_publisher_trust(
                connection, str(row["publisher_id"]), str(row["key_id"])
            ),
        )

    @staticmethod
    def _action_package_from_row(
        row: sqlite3.Row,
        *,
        include_bytes: bool,
        derived_installed_version: str | None,
        audited_trust: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        from .action_packages import (
            ActionPackageError,
            audit_action_package,
            canonical_public_key_b64u,
            ed25519_public_key_fingerprint,
            normalize_ed25519_public_key,
        )

        try:
            envelope_bytes = _bounded_package_bytes(
                bytes(row["canonical_envelope_bytes"]),
                "persisted canonical action-package envelope",
            )
            content_bytes = _bounded_package_bytes(
                bytes(row["canonical_content_bytes"]),
                "persisted canonical action-package content",
            )
            package_digest = _exact_sha256_digest(
                str(row["package_digest"]), "persisted action-package digest"
            )
            content_digest = _exact_sha256_digest(
                str(row["content_digest"]), "persisted action-package content digest"
            )
            signer_fingerprint = _exact_sha256_digest(
                str(row["signer_fingerprint"]),
                "persisted action-package signer fingerprint",
            )
            manifest = json.loads(str(row["manifest_json"]))
            trusted_provenance = json.loads(str(row["trusted_provenance_json"]))
            trusted_key = normalize_ed25519_public_key(bytes(row["trusted_public_key_bytes"]))
            publisher_trust_state = str(row["publisher_trust_state"])
            publisher_trust_event_sequence = int(row["publisher_trust_event_sequence"])
            occupied_behaviors_raw = json.loads(str(row["occupied_behavior_ids_json"]))
            occupied_actions_raw = json.loads(str(row["occupied_action_ids_json"]))
            occupied_behaviors = _occupied_package_ids(
                occupied_behaviors_raw, "persisted occupied behavior IDs"
            )
            occupied_actions = _occupied_package_ids(
                occupied_actions_raw, "persisted occupied action IDs"
            )
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ActionPackageIntegrityError(
                "persisted action-package version is malformed"
            ) from exc
        if publisher_trust_state not in {"trusted", "suspended", "revoked"}:
            raise ActionPackageIntegrityError(
                "persisted action-package publisher trust state is invalid"
            )
        if (
            publisher_trust_state != audited_trust["trust_state"]
            or publisher_trust_event_sequence != audited_trust["event_sequence"]
            or row["publisher_trust_updated_at"] != audited_trust["updated_at"]
        ):
            raise ActionPackageIntegrityError(
                "persisted action-package publisher trust projection failed its audit"
            )
        try:
            independently_verified = audit_action_package(
                envelope_bytes,
                trusted_signers={(str(row["publisher_id"]), str(row["key_id"])): trusted_key},
            )
        except ActionPackageError as exc:
            raise ActionPackageIntegrityError(
                "persisted action package failed cryptographic verification"
            ) from exc
        if _sha256_bytes(envelope_bytes) != package_digest:
            raise ActionPackageIntegrityError(
                "persisted action-package envelope failed its digest check"
            )
        if _sha256_bytes(content_bytes) != content_digest:
            raise ActionPackageIntegrityError(
                "persisted action-package content failed its digest check"
            )
        if (
            not isinstance(manifest, Mapping)
            or _canonical_json(manifest) != str(row["manifest_json"])
            or not isinstance(trusted_provenance, Mapping)
            or _canonical_json(trusted_provenance) != str(row["trusted_provenance_json"])
            or _canonical_json(list(occupied_behaviors)) != str(row["occupied_behavior_ids_json"])
            or _canonical_json(list(occupied_actions)) != str(row["occupied_action_ids_json"])
        ):
            raise ActionPackageIntegrityError(
                "persisted action-package metadata failed its canonical integrity check"
            )
        if (
            independently_verified.canonical_envelope_bytes != envelope_bytes
            or independently_verified.canonical_content_bytes != content_bytes
            or independently_verified.package_digest != package_digest
            or independently_verified.content_digest != content_digest
            or independently_verified.publisher_id != row["publisher_id"]
            or independently_verified.key_id != row["key_id"]
            or independently_verified.public_key_fingerprint != signer_fingerprint
            or independently_verified.signature_b64u != row["signature_b64u"]
            or independently_verified.manifest.to_dict() != manifest
        ):
            raise ActionPackageIntegrityError(
                "persisted action-package verifier result does not match stored metadata"
            )
        envelope = _canonical_package_object(envelope_bytes, "persisted action-package envelope")
        content = _canonical_package_object(content_bytes, "persisted action-package content")
        expected_content = {
            "schema_version": envelope.get("schema_version"),
            "manifest": envelope.get("manifest"),
            "payload": envelope.get("payload"),
        }
        integrity = envelope.get("integrity")
        signature = envelope.get("signature")
        if (
            content != expected_content
            or content.get("manifest") != manifest
            or not isinstance(integrity, Mapping)
            or integrity.get("algorithm") != "sha256"
            or integrity.get("content_digest") != content_digest
            or not isinstance(signature, Mapping)
            or signature.get("algorithm") != "ed25519"
            or signature.get("key_id") != row["key_id"]
            or signature.get("value") != row["signature_b64u"]
        ):
            raise ActionPackageIntegrityError(
                "persisted action-package bytes are not bound to their metadata"
            )
        provenance = manifest.get("provenance")
        if (
            manifest.get("package_id") != row["package_id"]
            or manifest.get("version") != row["version"]
            or not isinstance(provenance, Mapping)
            or provenance.get("publisher_id") != row["publisher_id"]
        ):
            raise ActionPackageIntegrityError(
                "persisted action-package identity is not bound to its manifest"
            )
        canonical_key = canonical_public_key_b64u(trusted_key)
        trusted_fingerprint = ed25519_public_key_fingerprint(trusted_key)
        if (
            canonical_key != row["trusted_public_key_b64u"]
            or trusted_fingerprint != row["trusted_key_fingerprint"]
            or trusted_fingerprint != signer_fingerprint
        ):
            raise ActionPackageIntegrityError(
                "persisted action-package signer no longer matches local publisher trust"
            )
        tombstone_digest = row["tombstone_package_digest"]
        if tombstone_digest is not None and str(tombstone_digest) != package_digest:
            raise ActionPackageIntegrityError(
                "persisted action-package tombstone has a conflicting digest"
            )
        installed_head = derived_installed_version == row["version"]
        if row["head_active_version"] is not None:
            raise ActionPackageIntegrityError(
                "action-package active state has no append-only activation event"
            )
        active = row["head_active_version"] == row["version"]
        if tombstone_digest is not None:
            status = "removed"
        elif active:
            status = "active"
        elif installed_head:
            status = "installed"
        else:
            status = "superseded"
        result: dict[str, Any] = {
            "schema_version": "bluefire.action-package-installation.v1",
            "package_id": row["package_id"],
            "version": row["version"],
            "status": status,
            "package_digest": package_digest,
            "content_digest": content_digest,
            "publisher_id": row["publisher_id"],
            "key_id": row["key_id"],
            "signer_fingerprint": signer_fingerprint,
            "signature_b64u": row["signature_b64u"],
            "manifest": manifest,
            "installed_by": row["installed_by"],
            "installed_at": row["installed_at"],
            "installed_head": installed_head,
            "active": active,
            "active_version": row["head_active_version"],
            "trust": {
                "state": publisher_trust_state,
                "source": "local_operator",
                "publisher_id": row["publisher_id"],
                "key_id": row["key_id"],
                "key_fingerprint": trusted_fingerprint,
                "trusted_by": row["publisher_trusted_by"],
                "trusted_at": row["publisher_trusted_at"],
                "event_sequence": publisher_trust_event_sequence,
                "updated_at": row["publisher_trust_updated_at"],
                "provenance": trusted_provenance,
            },
            "verification": {
                "compatibility": "deferred_to_activation",
                "occupied_behavior_ids": list(occupied_behaviors),
                "occupied_action_ids": list(occupied_actions),
            },
            "tombstone": (
                None
                if tombstone_digest is None
                else {
                    "package_digest": tombstone_digest,
                    "removed_by": row["tombstone_removed_by"],
                    "reason": row["tombstone_reason"],
                    "removed_at": row["tombstone_removed_at"],
                }
            ),
        }
        if include_bytes:
            result["canonical_envelope_bytes"] = envelope_bytes
            result["canonical_content_bytes"] = content_bytes
        return result

    def create_approval_request(
        self,
        *,
        run_id: str,
        state_digest: str,
        plan_digest: str,
        profile_id: str,
        target_scope_digest: str,
        maximum_tier: str,
        expires_at: str,
    ) -> Mapping[str, Any]:
        if not all(
            isinstance(item, str) and item.strip()
            for item in (run_id, state_digest, plan_digest, target_scope_digest, expires_at)
        ):
            raise ProductStoreError("approval binding fields are required")
        stable_profile = _identifier(profile_id, "approval profile ID")
        if maximum_tier not in {"safe", "controlled", "restricted"}:
            raise ProductStoreError("approval maximum tier is invalid")
        requested_at = utc_now()
        if _timestamp(expires_at) <= _timestamp(requested_at):
            raise ProductStoreError("approval expiry must be in the future")
        approval_id = "approval-" + uuid.uuid4().hex
        with self._connection(write=True) as connection:
            connection.execute(
                """
                INSERT INTO approval_requests(
                    approval_id, run_id, state_digest, plan_digest, profile_id,
                    target_scope_digest, maximum_tier, status, requested_at, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)
                """,
                (
                    approval_id,
                    run_id.strip(),
                    state_digest.strip(),
                    plan_digest.strip(),
                    stable_profile,
                    target_scope_digest.strip(),
                    maximum_tier,
                    requested_at,
                    expires_at,
                ),
            )
        return self.get_approval_request(approval_id)

    def approve(
        self,
        approval_id: str,
        *,
        approved_by: str,
        expected_state_digest: str,
        expected_plan_digest: str,
        expected_target_scope_digest: str,
        expires_at: str | None = None,
    ) -> Mapping[str, Any]:
        if not isinstance(approved_by, str) or not approved_by.strip():
            raise ProductStoreError("approval identity is required")
        nonce = uuid.uuid4().hex
        now = utc_now()
        with self._connection(write=True) as connection:
            row = self._approval_row(connection, approval_id)
            self._validate_approval_binding(
                row,
                expected_state_digest=expected_state_digest,
                expected_plan_digest=expected_plan_digest,
                expected_target_scope_digest=expected_target_scope_digest,
            )
            if row["status"] != "pending":
                raise ProductStoreError("approval request is not pending")
            if _timestamp(str(row["expires_at"])) <= _timestamp(now):
                raise ProductStoreError("approval request has expired")
            execution_expiry = str(row["expires_at"])
            if expires_at is not None:
                if not isinstance(expires_at, str) or _timestamp(expires_at) <= _timestamp(now):
                    raise ProductStoreError("approval execution expiry must be in the future")
                execution_expiry = expires_at
            connection.execute(
                """
                UPDATE approval_requests
                SET status = 'approved', approved_at = ?, approved_by = ?, nonce = ?,
                    expires_at = ?
                WHERE approval_id = ?
                """,
                (now, approved_by.strip(), nonce, execution_expiry, approval_id),
            )
        return self.get_approval_request(approval_id)

    def consume_approval(
        self,
        approval_id: str,
        *,
        nonce: str,
        expected_state_digest: str,
        expected_plan_digest: str,
        expected_target_scope_digest: str,
    ) -> Mapping[str, Any]:
        now = utc_now()
        with self._connection(write=True) as connection:
            row = self._approval_row(connection, approval_id)
            self._validate_approval_binding(
                row,
                expected_state_digest=expected_state_digest,
                expected_plan_digest=expected_plan_digest,
                expected_target_scope_digest=expected_target_scope_digest,
            )
            if row["status"] != "approved" or row["nonce"] != nonce:
                raise ProductStoreError("approval is unavailable or has already been consumed")
            if _timestamp(str(row["expires_at"])) <= _timestamp(now):
                raise ProductStoreError("approval request has expired")
            connection.execute(
                """
                UPDATE approval_requests
                SET status = 'consumed', consumed_at = ?
                WHERE approval_id = ? AND status = 'approved'
                """,
                (now, approval_id),
            )
            if connection.total_changes != 1:
                raise ProductStoreError("approval consumption lost a concurrent race")
        return self.get_approval_request(approval_id)

    def claim_consumed_approval(
        self,
        approval_id: str,
        *,
        nonce: str,
        approved_by: str,
        expected_state_digest: str,
        expected_plan_digest: str,
        expected_target_scope_digest: str,
        expected_profile_id: str,
        expected_maximum_tier: str,
    ) -> Mapping[str, Any]:
        """Atomically claim a consumed approval for exactly one orchestration."""

        now = utc_now()
        with self._connection(write=True) as connection:
            row = self._approval_row(connection, approval_id)
            self._validate_approval_binding(
                row,
                expected_state_digest=expected_state_digest,
                expected_plan_digest=expected_plan_digest,
                expected_target_scope_digest=expected_target_scope_digest,
            )
            if (
                row["status"] != "consumed"
                or row["nonce"] != nonce
                or row["approved_by"] != approved_by
                or row["profile_id"] != expected_profile_id
                or row["maximum_tier"] != expected_maximum_tier
            ):
                raise ProductStoreError(
                    "approval capability is unavailable, mismatched, or already claimed"
                )
            if _timestamp(str(row["expires_at"])) <= _timestamp(now):
                raise ProductStoreError("approval request has expired")
            cursor = connection.execute(
                """
                UPDATE approval_requests
                SET status = 'claimed', claimed_at = ?
                WHERE approval_id = ? AND status = 'consumed' AND nonce = ?
                """,
                (now, approval_id, nonce),
            )
            if cursor.rowcount != 1:
                raise ProductStoreError("approval claim lost a concurrent race")
        return self.get_approval_request(approval_id)

    def renew_claimed_approval_for_cleanup(
        self,
        approval_id: str,
        *,
        expires_at: str,
        expected_state_digest: str,
        expected_plan_digest: str,
        expected_target_scope_digest: str,
        expected_profile_id: str,
        expected_maximum_tier: str,
    ) -> Mapping[str, Any]:
        """Bound a claimed run capability to a short crash-cleanup window."""

        now = utc_now()
        if _timestamp(expires_at) <= _timestamp(now):
            raise ProductStoreError("cleanup recovery expiry must be in the future")
        with self._connection(write=True) as connection:
            row = self._approval_row(connection, approval_id)
            self._validate_approval_binding(
                row,
                expected_state_digest=expected_state_digest,
                expected_plan_digest=expected_plan_digest,
                expected_target_scope_digest=expected_target_scope_digest,
            )
            if (
                row["status"] != "claimed"
                or row["profile_id"] != expected_profile_id
                or row["maximum_tier"] != expected_maximum_tier
                or not row["nonce"]
                or not row["approved_by"]
            ):
                raise ProductStoreError("claimed approval is unavailable for cleanup recovery")
            cursor = connection.execute(
                """
                UPDATE approval_requests SET expires_at = ?
                WHERE approval_id = ? AND status = 'claimed'
                """,
                (expires_at, approval_id),
            )
            if cursor.rowcount != 1:
                raise ProductStoreError("cleanup recovery renewal lost a concurrent race")
        return self.get_approval_request(approval_id)

    def get_approval_request(self, approval_id: str) -> Mapping[str, Any]:
        with self._connection() as connection:
            row = self._approval_row(connection, approval_id)
        return self._approval_from_row(row).to_dict()

    def bind_execution_workspace(
        self,
        approval_id: str,
        *,
        profile_id: str,
        workspace_path: str | Path,
        runner_identity: Mapping[str, Any],
        recovery_context: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        """Privately bind one consumed approval to its exact resolved workspace.

        The absolute path is intentionally kept out of job/API documents.  It is
        durable local recovery state used only to reconcile runner receipts after
        a process or host restart.
        """

        if not isinstance(profile_id, str) or not _IDENTIFIER.fullmatch(profile_id):
            raise ProductStoreError("execution workspace profile ID is invalid")
        candidate = Path(workspace_path)
        if not candidate.is_absolute():
            raise ProductStoreError("execution workspace path must be absolute")
        resolved = str(candidate.resolve(strict=True))
        identity = _safe_document(runner_identity, context="execution runner identity")
        context = _safe_document(recovery_context, context="execution recovery context")
        digest = content_hash(
            {
                "approval_id": approval_id,
                "profile_id": profile_id,
                "workspace_path": resolved,
            }
        )
        now = utc_now()
        with self._connection(write=True) as connection:
            approval = self._approval_row(connection, approval_id)
            if approval["status"] not in {"consumed", "claimed"}:
                raise ProductStoreError("approval is unavailable for workspace binding")
            if approval["profile_id"] != profile_id:
                raise ProductStoreError("workspace profile does not match its approval")
            existing = connection.execute(
                "SELECT * FROM execution_workspaces WHERE approval_id = ?",
                (approval_id,),
            ).fetchone()
            immutable = (
                profile_id,
                resolved,
                digest,
                _canonical_json(identity),
                _canonical_json(context),
            )
            if existing is not None:
                actual = (
                    existing["profile_id"],
                    existing["workspace_path"],
                    existing["workspace_digest"],
                    existing["runner_identity_json"],
                    existing["recovery_context_json"],
                )
                if actual != immutable:
                    raise ProductStoreError("execution workspace binding is immutable")
            else:
                connection.execute(
                    """
                    INSERT INTO execution_workspaces(
                        approval_id, profile_id, workspace_path, workspace_digest,
                        runner_identity_json, recovery_context_json, state,
                        created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?)
                    """,
                    (approval_id, *immutable, now, now),
                )
        return self.get_execution_workspace(approval_id)

    def transition_execution_workspace(
        self,
        approval_id: str,
        state: str,
        *,
        run_id: str | None = None,
        outcome: Mapping[str, Any] | None = None,
    ) -> Mapping[str, Any]:
        """Update mutable recovery state without changing the bound identity."""

        if state not in _EXECUTION_WORKSPACE_STATES:
            raise ProductStoreError("execution workspace state is invalid")
        if run_id is not None and not _RUN_ID.fullmatch(run_id):
            raise ProductStoreError("execution workspace run ID is invalid")
        outcome_json = (
            _canonical_json(_safe_document(outcome, context="execution recovery outcome"))
            if outcome is not None
            else None
        )
        with self._connection(write=True) as connection:
            row = connection.execute(
                "SELECT * FROM execution_workspaces WHERE approval_id = ?",
                (approval_id,),
            ).fetchone()
            if row is None:
                raise ProductStoreError("execution workspace binding was not found")
            current = str(row["state"])
            terminal = {"completed", "recovered", "not_required"}
            if current in terminal and state != current:
                raise ProductStoreError("completed execution workspace binding is immutable")
            existing_run = str(row["run_id"]) if row["run_id"] else None
            if existing_run is not None and run_id is not None and existing_run != run_id:
                raise ProductStoreError("execution workspace run binding is immutable")
            connection.execute(
                """
                UPDATE execution_workspaces
                SET state = ?, run_id = ?, outcome_json = ?, updated_at = ?
                WHERE approval_id = ?
                """,
                (
                    state,
                    run_id or existing_run,
                    outcome_json if outcome_json is not None else row["outcome_json"],
                    utc_now(),
                    approval_id,
                ),
            )
        return self.get_execution_workspace(approval_id)

    def get_execution_workspace(self, approval_id: str) -> Mapping[str, Any]:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM execution_workspaces WHERE approval_id = ?",
                (approval_id,),
            ).fetchone()
        if row is None:
            raise ProductStoreError("execution workspace binding was not found")
        return self._execution_workspace_from_row(row)

    def list_execution_workspaces(
        self,
        *,
        states: set[str] | frozenset[str] | None = None,
    ) -> list[Mapping[str, Any]]:
        selected = set(states or _EXECUTION_WORKSPACE_STATES)
        if not selected or not selected.issubset(_EXECUTION_WORKSPACE_STATES):
            raise ProductStoreError("execution workspace state filter is invalid")
        with self._connection() as connection:
            rows = connection.execute("""
                SELECT * FROM execution_workspaces
                ORDER BY updated_at, approval_id
                """).fetchall()
        return [
            self._execution_workspace_from_row(row) for row in rows if str(row["state"]) in selected
        ]

    @staticmethod
    def _execution_workspace_from_row(row: sqlite3.Row) -> Mapping[str, Any]:
        return {
            "schema_version": "bluefire.execution-workspace.v1",
            "approval_id": str(row["approval_id"]),
            "profile_id": str(row["profile_id"]),
            "workspace_path": str(row["workspace_path"]),
            "workspace_digest": str(row["workspace_digest"]),
            "runner_identity": json.loads(row["runner_identity_json"]),
            "recovery_context": json.loads(row["recovery_context_json"]),
            "run_id": str(row["run_id"]) if row["run_id"] else None,
            "state": str(row["state"]),
            "outcome": json.loads(row["outcome_json"]) if row["outcome_json"] else None,
            "created_at": str(row["created_at"]),
            "updated_at": str(row["updated_at"]),
        }

    @staticmethod
    def _approval_row(connection: sqlite3.Connection, approval_id: str) -> sqlite3.Row:
        if not isinstance(approval_id, str) or not approval_id.startswith("approval-"):
            raise ProductStoreError("approval ID is invalid")
        row = connection.execute(
            "SELECT * FROM approval_requests WHERE approval_id = ?", (approval_id,)
        ).fetchone()
        if row is None:
            raise ProductStoreError("approval request was not found")
        return cast(sqlite3.Row, row)

    @staticmethod
    def _validate_approval_binding(
        row: sqlite3.Row,
        *,
        expected_state_digest: str,
        expected_plan_digest: str,
        expected_target_scope_digest: str,
    ) -> None:
        expected = (
            expected_state_digest,
            expected_plan_digest,
            expected_target_scope_digest,
        )
        actual = (row["state_digest"], row["plan_digest"], row["target_scope_digest"])
        if actual != expected:
            raise ProductStoreError("approval is not bound to this exact plan and target scope")

    @staticmethod
    def _approval_from_row(row: sqlite3.Row) -> ApprovalRequest:
        return ApprovalRequest(
            approval_id=str(row["approval_id"]),
            run_id=str(row["run_id"]),
            state_digest=str(row["state_digest"]),
            plan_digest=str(row["plan_digest"]),
            profile_id=str(row["profile_id"]),
            target_scope_digest=str(row["target_scope_digest"]),
            maximum_tier=str(row["maximum_tier"]),
            status=str(row["status"]),
            requested_at=str(row["requested_at"]),
            expires_at=str(row["expires_at"]),
            approved_at=str(row["approved_at"]) if row["approved_at"] else None,
            approved_by=str(row["approved_by"]) if row["approved_by"] else None,
            nonce=str(row["nonce"]) if row["nonce"] else None,
            consumed_at=str(row["consumed_at"]) if row["consumed_at"] else None,
            claimed_at=str(row["claimed_at"]) if row["claimed_at"] else None,
        )

    def create_job(self, kind: str, request: Mapping[str, Any]) -> Mapping[str, Any]:
        job_kind = _identifier(kind, "job kind")
        document = _safe_document(request, context=f"job.{job_kind}.request")
        job_id = "job-" + uuid.uuid4().hex
        now = utc_now()
        with self._connection(write=True) as connection:
            connection.execute(
                """
                INSERT INTO jobs(
                    job_id, kind, state, request_json, progress_json, created_at, updated_at
                ) VALUES (?, ?, 'queued', ?, '{}', ?, ?)
                """,
                (job_id, job_kind, _canonical_json(document), now, now),
            )
        return self.get_job(job_id)

    def transition_job(
        self,
        job_id: str,
        state: str,
        *,
        progress: Mapping[str, Any] | None = None,
        result_ref: str | None = None,
        error: Mapping[str, Any] | None = None,
        completion_confirmed: bool = False,
    ) -> Mapping[str, Any]:
        if state not in _JOB_STATES:
            raise ProductStoreError("job state is invalid")
        if type(completion_confirmed) is not bool:
            raise ProductStoreError("job completion confirmation is invalid")
        with self._connection(write=True) as connection:
            row = connection.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
            if row is None:
                raise ProductStoreError("job was not found")
            current = str(row["state"])
            if state != current and state not in _JOB_TRANSITIONS[current]:
                raise ProductStoreError(f"job cannot transition from {current} to {state}")
            if current == "cancelling" and state == "completed" and not completion_confirmed:
                raise ProductStoreError("a cancelling job requires confirmed durable completion")
            if completion_confirmed and (
                state != "completed" or current not in {"running", "cancelling"}
            ):
                raise ProductStoreError(
                    "job completion confirmation is invalid for this transition"
                )
            next_progress = (
                _safe_document(progress, context=f"job.{job_id}.progress")
                if progress is not None
                else json.loads(row["progress_json"])
            )
            next_error = (
                _canonical_json(_safe_document(error, context=f"job.{job_id}.error"))
                if error is not None
                else row["error_json"]
            )
            connection.execute(
                """
                UPDATE jobs
                SET state = ?, progress_json = ?, result_ref = ?, error_json = ?, updated_at = ?
                WHERE job_id = ?
                """,
                (
                    state,
                    _canonical_json(next_progress),
                    result_ref if result_ref is not None else row["result_ref"],
                    next_error,
                    utc_now(),
                    job_id,
                ),
            )
        return self.get_job(job_id)

    def get_job(self, job_id: str) -> Mapping[str, Any]:
        with self._connection() as connection:
            row = connection.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
        if row is None:
            raise ProductStoreError("job was not found")
        return {
            "schema_version": "bluefire.job.v1",
            "job_id": row["job_id"],
            "kind": row["kind"],
            "state": row["state"],
            "request": json.loads(row["request_json"]),
            "progress": json.loads(row["progress_json"]),
            "result_ref": row["result_ref"],
            "error": json.loads(row["error_json"]) if row["error_json"] else None,
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def list_jobs(self, *, state: str | None = None) -> list[Mapping[str, Any]]:
        if state is not None and state not in _JOB_STATES:
            raise ProductStoreError("job state filter is invalid")
        with self._connection() as connection:
            if state is None:
                rows = connection.execute("SELECT job_id FROM jobs ORDER BY created_at").fetchall()
            else:
                rows = connection.execute(
                    "SELECT job_id FROM jobs WHERE state = ? ORDER BY created_at",
                    (state,),
                ).fetchall()
        return [self.get_job(str(row["job_id"])) for row in rows]

    def create_ai_proposal_review(
        self,
        *,
        job_id: str,
        source_run_id: str,
        record: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        """Persist one bounded proposal at the operator-review boundary.

        The three digests are copied from the immutable run record and checked
        here before any later operator decision can refer to them.
        """

        if not _RUN_ID.fullmatch(source_run_id):
            raise ProductStoreError("proposal source run ID is invalid")
        document = _safe_document(record, context="AI proposal review")
        if document.get("run_id") != source_run_id:
            raise ProductStoreError("proposal source run identity is mismatched")
        if document.get("application_status") != "awaiting_operator_approval":
            raise ProductStoreError("only pending registered proposals can be reviewed")
        try:
            validated_proposal = validate_persisted_proposal_record(document)
        except AIProviderError as exc:
            raise ProductStoreError("proposal review failed strict contract validation") from exc
        proposal = validated_proposal.to_dict()
        source_proposal_id = validated_proposal.proposal_id
        if not isinstance(source_proposal_id, str) or not _SOURCE_PROPOSAL_ID.fullmatch(
            source_proposal_id
        ):
            raise ProductStoreError("proposal content identity is invalid")
        if validated_proposal.proposal_type not in MUTATING_PROPOSAL_TYPES:
            raise ProductStoreError("only registered runtime proposals can be reviewed")
        role = (
            "retry" if validated_proposal.proposal_type is ProposalType.RETRY_REGISTERED else "next"
        )
        options = document.get("registered_options")
        option = (
            next(
                (
                    item
                    for item in options
                    if isinstance(item, Mapping)
                    and item.get("role") == role
                    and item.get("step_id") == validated_proposal.selected_step_id
                ),
                None,
            )
            if isinstance(options, list)
            else None
        )
        if option is None or validated_proposal.selected_behavior_id not in option.get(
            "behavior_ids", []
        ):
            raise ProductStoreError("proposal tuple is outside its registered option envelope")
        if validated_proposal.selected_action_id is not None:
            action_map = option.get("action_ids_by_behavior")
            allowed_actions = (
                action_map.get(validated_proposal.selected_behavior_id, [])
                if isinstance(action_map, Mapping)
                else []
            )
            if validated_proposal.selected_action_id not in allowed_actions:
                raise ProductStoreError(
                    "proposal action is outside its behavior/profile option envelope"
                )
        evaluation = document.get("proposal_policy_evaluation")
        if (
            not isinstance(evaluation, Mapping)
            or evaluation.get("status") != "permitted"
            or evaluation.get("policy_digest") != document.get("proposal_policy_digest")
        ):
            raise ProductStoreError("proposal was not permitted by its recorded policy")
        state_digest = document.get("state_digest")
        plan_digest = document.get("plan_digest")
        proposal_digest = document.get("proposal_digest")
        if not all(
            isinstance(value, str) and _DIGEST.fullmatch(value)
            for value in (state_digest, plan_digest, proposal_digest)
        ):
            raise ProductStoreError("proposal review digests are invalid")
        if content_hash(proposal) != proposal_digest:
            raise ProductStoreError("proposal content digest is mismatched")
        now = utc_now()
        proposal_record_id = "proposal-review-" + uuid.uuid4().hex
        with self._connection(write=True) as connection:
            if (
                connection.execute("SELECT 1 FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
                is None
            ):
                raise ProductStoreError("proposal review job was not found")
            existing = connection.execute(
                """
                SELECT proposal_record_id FROM ai_proposal_reviews
                WHERE job_id = ? AND source_run_id = ? AND source_proposal_id = ?
                  AND state_digest = ? AND plan_digest = ? AND proposal_digest = ?
                """,
                (
                    job_id,
                    source_run_id,
                    source_proposal_id,
                    state_digest,
                    plan_digest,
                    proposal_digest,
                ),
            ).fetchone()
            if existing is not None:
                proposal_record_id = str(existing["proposal_record_id"])
            else:
                connection.execute(
                    """
                    INSERT INTO ai_proposal_reviews(
                        proposal_record_id, job_id, source_run_id, source_proposal_id,
                        state_digest, plan_digest, proposal_digest, status,
                        record_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)
                    """,
                    (
                        proposal_record_id,
                        job_id,
                        source_run_id,
                        source_proposal_id,
                        state_digest,
                        plan_digest,
                        proposal_digest,
                        _canonical_json(document),
                        now,
                    ),
                )
        return self.get_ai_proposal_review(proposal_record_id)

    def get_ai_proposal_review(self, proposal_record_id: str) -> Mapping[str, Any]:
        if not isinstance(proposal_record_id, str) or not _PROPOSAL_RECORD_ID.fullmatch(
            proposal_record_id
        ):
            raise ProductStoreError("proposal review ID is invalid")
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM ai_proposal_reviews WHERE proposal_record_id = ?",
                (proposal_record_id,),
            ).fetchone()
        if row is None:
            raise ProductStoreError("proposal review was not found")
        return self._ai_proposal_review_from_row(row)

    def list_ai_proposal_reviews(self, job_id: str) -> list[Mapping[str, Any]]:
        with self._connection() as connection:
            if (
                connection.execute("SELECT 1 FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
                is None
            ):
                raise ProductStoreError("proposal review job was not found")
            rows = connection.execute(
                """
                SELECT * FROM ai_proposal_reviews
                WHERE job_id = ? ORDER BY created_at, proposal_record_id
                """,
                (job_id,),
            ).fetchall()
        return [self._ai_proposal_review_from_row(row) for row in rows]

    def resolve_ai_proposal_review(
        self,
        proposal_record_id: str,
        *,
        job_id: str,
        decision: str,
        decided_by: str,
        expected_state_digest: str,
        expected_plan_digest: str,
        expected_proposal_digest: str,
        resolution: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        if decision not in {"accepted", "rejected"}:
            raise ProductStoreError("proposal decision is invalid")
        identity = decided_by.strip() if isinstance(decided_by, str) else ""
        if not identity or len(identity) > 128:
            raise ProductStoreError("proposal decision identity is invalid")
        if not _PROPOSAL_RECORD_ID.fullmatch(proposal_record_id):
            raise ProductStoreError("proposal review ID is invalid")
        resolution_document = _safe_document(resolution, context="AI proposal resolution")
        expected = (
            expected_state_digest,
            expected_plan_digest,
            expected_proposal_digest,
        )
        if not all(isinstance(value, str) and _DIGEST.fullmatch(value) for value in expected):
            raise ProductStoreError("proposal decision digests are invalid")
        now = utc_now()
        with self._connection(write=True) as connection:
            row = connection.execute(
                "SELECT * FROM ai_proposal_reviews WHERE proposal_record_id = ?",
                (proposal_record_id,),
            ).fetchone()
            if row is None or row["job_id"] != job_id:
                raise ProductStoreError("proposal review was not found for this job")
            if row["status"] != "pending":
                raise ProductStoreError("proposal review is stale or already resolved")
            if (
                row["state_digest"],
                row["plan_digest"],
                row["proposal_digest"],
            ) != expected:
                raise ProductStoreError("proposal decision does not match the reviewed digests")
            cursor = connection.execute(
                """
                UPDATE ai_proposal_reviews
                SET status = ?, resolution_json = ?, decided_at = ?, decided_by = ?
                WHERE proposal_record_id = ? AND status = 'pending'
                """,
                (
                    decision,
                    _canonical_json(resolution_document),
                    now,
                    identity,
                    proposal_record_id,
                ),
            )
            if cursor.rowcount != 1:
                raise ProductStoreError("proposal decision lost a concurrent race")
        return self.get_ai_proposal_review(proposal_record_id)

    @staticmethod
    def _ai_proposal_review_from_row(row: sqlite3.Row) -> Mapping[str, Any]:
        return {
            "schema_version": "bluefire.ai-proposal-review.v1",
            "proposal_record_id": str(row["proposal_record_id"]),
            "job_id": str(row["job_id"]),
            "source_run_id": str(row["source_run_id"]),
            "source_proposal_id": str(row["source_proposal_id"]),
            "state_digest": str(row["state_digest"]),
            "plan_digest": str(row["plan_digest"]),
            "proposal_digest": str(row["proposal_digest"]),
            "status": str(row["status"]),
            "record": json.loads(row["record_json"]),
            "resolution": (json.loads(row["resolution_json"]) if row["resolution_json"] else None),
            "created_at": str(row["created_at"]),
            "decided_at": str(row["decided_at"]) if row["decided_at"] else None,
            "decided_by": str(row["decided_by"]) if row["decided_by"] else None,
        }

    def recover_interrupted_jobs(self) -> int:
        """Mark non-terminal in-flight jobs as interrupted after a restart."""

        now = utc_now()
        with self._connection(write=True) as connection:
            cursor = connection.execute(
                """
                UPDATE jobs SET state = 'interrupted', updated_at = ?
                WHERE state IN (
                    'queued', 'planning', 'awaiting_approval',
                    'running', 'paused', 'cancelling'
                )
                """,
                (now,),
            )
            return int(cursor.rowcount)

    def index_run(self, summary: Mapping[str, Any]) -> Mapping[str, Any]:
        required = {"run_id", "scenario_id", "mode", "status", "created_at"}
        if not required.issubset(summary):
            raise ProductStoreError("run summary is missing required fields")
        document = _safe_document(summary, context="run summary")
        mode = document["mode"]
        if mode not in {"simulate", "execute"}:
            raise ProductStoreError("run mode must be simulate or execute")
        now = utc_now()
        objective = document.get("objective_reached")
        objective_value = None if objective is None else int(bool(objective))
        with self._connection(write=True) as connection:
            connection.execute(
                """
                INSERT INTO run_index(
                    run_id, scenario_id, mode, status, objective_reached, bundle_digest,
                    summary_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(run_id) DO UPDATE SET
                    status = excluded.status,
                    objective_reached = excluded.objective_reached,
                    bundle_digest = excluded.bundle_digest,
                    summary_json = excluded.summary_json,
                    updated_at = excluded.updated_at
                """,
                (
                    str(document["run_id"]),
                    str(document["scenario_id"]),
                    mode,
                    str(document["status"]),
                    objective_value,
                    document.get("bundle_digest"),
                    _canonical_json(document),
                    str(document["created_at"]),
                    now,
                ),
            )
        return cast(Mapping[str, Any], document)

    def list_runs(self, *, limit: int = 100, offset: int = 0) -> list[Mapping[str, Any]]:
        if isinstance(limit, bool) or not 1 <= limit <= 500:
            raise ProductStoreError("run list limit must be between 1 and 500")
        if isinstance(offset, bool) or offset < 0:
            raise ProductStoreError("run list offset cannot be negative")
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT summary_json FROM run_index
                ORDER BY created_at DESC, run_id DESC LIMIT ? OFFSET ?
                """,
                (limit, offset),
            ).fetchall()
        return [json.loads(row["summary_json"]) for row in rows]


def _timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise ProductStoreError("timestamp is invalid") from exc
    if parsed.tzinfo is None:
        raise ProductStoreError("timestamp must be timezone-aware")
    return parsed.astimezone(timezone.utc)


__all__ = [
    "ApprovalRequest",
    "DetectionRevisionIntegrityError",
    "DetectionRevisionLimitError",
    "ProductStore",
    "ProductStoreError",
    "ResearchSourceIntegrityError",
    "SCHEMA_VERSION",
    "utc_now",
]
