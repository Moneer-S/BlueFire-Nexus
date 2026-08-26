"""Durable local product metadata and approval state.

The run bundle store remains append-oriented and evidence focused.  This store
owns mutable product metadata: scenario versions, settings, runner inventory,
provider configuration, collectors, detections, research sources, comparisons,
background-job state, and one-time approval requests.

Only references to secrets are accepted.  Secret values belong in the local
environment (or a future operating-system secret provider), never in SQLite.
"""

from __future__ import annotations

import json
import re
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, cast

from .ai import (
    MUTATING_PROPOSAL_TYPES,
    AIProviderError,
    ProposalType,
    validate_persisted_proposal_record,
)
from .contracts import ScenarioDefinition
from .util import content_hash, json_clone


class ProductStoreError(ValueError):
    """Raised when product metadata or a state transition is invalid."""


class ResearchSourceIntegrityError(ProductStoreError):
    """Raised when a persisted research-source identity would be rewritten."""


class DetectionRevisionIntegrityError(ProductStoreError):
    """Raised when an immutable detection revision identity conflicts."""


class DetectionRevisionLimitError(DetectionRevisionIntegrityError):
    """Raised when a detection lineage has reached its configured bound."""


SCHEMA_VERSION = 5
_IDENTIFIER = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
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
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _identifier(value: Any, context: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ProductStoreError(f"{context} must be a stable lowercase identifier")
    return value


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
    """Thread-safe SQLite storage for local-first product state."""

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
            if current is None or int(current) < SCHEMA_VERSION:
                connection.execute(
                    "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                    (SCHEMA_VERSION, utc_now()),
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
