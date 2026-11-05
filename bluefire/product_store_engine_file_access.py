"""Protected, append-only accounting for a saved engine file-read attempt.

This store binds a reviewed target policy to the latest saved experiment and
counts proposed native requests. It does not prove live enrollment or control
provenance, admit a target, grant execution authority, or dispatch a read. A
controller must independently reopen those facts before using either record.
"""

from __future__ import annotations

import json
import re
import sqlite3
import time
from collections.abc import Mapping
from contextlib import AbstractContextManager
from typing import Any, Protocol, cast

from . import product_store_engine_jobs as engine_jobs
from . import product_store_file_access_records as file_access_records
from .engine_attempt_contract import AttemptRole, AttemptState
from .engine_experiment import (
    ENGINE_CAPABILITY_SCOPE_VERSION,
    EngineAttemptEntry,
    EngineExperiment,
    EngineExperimentError,
)
from .engine_file_access_snapshot import CURRENT_HARDENED, HISTORICAL_BASELINE
from .engine_file_access_target import EngineFileReadTargetPolicy
from .file_access_contract import PROBE_ACTION
from .product_store_capability_grants import control_usages_settled
from .product_store_errors import ProductStoreError, ResourceConflictError
from .product_store_serialization import canonical_json
from .util import content_hash, parse_iso8601_datetime

_RESERVATION_SCHEMA = "bluefire.engine-file-access-target-reservation.v1"
_CLAIM_SCHEMA = "bluefire.engine-file-access-request-claim.v1"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_ATTEMPT_ID = re.compile(r"engine-attempt-[0-9a-f]{32}\Z")
_TASK_ID = re.compile(r"execute-[0-9a-f]{64}\Z")
_MAX_DOCUMENT_BYTES = 24 * 1024
_ACTIVE_STATES = frozenset({AttemptState.QUEUED, AttemptState.PREFLIGHT, AttemptState.RUNNING})
_RESERVATION_FIELDS = frozenset(
    {
        "schema_version",
        "reservation_ref",
        "experiment_id",
        "attempt_id",
        "job_id",
        "run_id",
        "role",
        "action_id",
        "binding_digest",
        "mechanism_ref",
        "historical_snapshot_ref",
        "target_snapshot_ref",
        "target_policy_version",
        "policy_digest",
        "request_budget",
        "issued_at_ms",
        "deadline_ms",
        "policy",
        "created_at_ms",
    }
)
_CLAIM_FIELDS = frozenset(
    {
        "schema_version",
        "claim_ref",
        "reservation_ref",
        "policy_digest",
        "attempt_id",
        "ordinal",
        "task_id",
        "request_hash",
        "transport_request_hash",
        "claimed_at_ms",
    }
)


class EngineFileAccessStore(Protocol):
    def _connection(self, *, write: bool = False) -> AbstractContextManager[sqlite3.Connection]: ...


def initialize_schema(connection: sqlite3.Connection) -> None:
    """Install both ledgers in the product database migration transaction."""

    if not connection.in_transaction:
        raise ProductStoreError("engine file-access migration requires one transaction")
    statements = (
        """CREATE TABLE IF NOT EXISTS engine_file_access_target_reservations (
            attempt_id TEXT PRIMARY KEY,
            experiment_id TEXT NOT NULL,
            job_id TEXT NOT NULL,
            run_id TEXT NOT NULL,
            role TEXT NOT NULL CHECK (role IN ('baseline', 'adaptive_search')),
            action_id TEXT NOT NULL CHECK (action_id = 'file_access.probe.non_owner.v1'),
            binding_digest TEXT NOT NULL
                CHECK (length(binding_digest) = 71 AND substr(binding_digest, 1, 7) = 'sha256:'),
            mechanism_ref TEXT NOT NULL
                CHECK (length(mechanism_ref) = 71 AND substr(mechanism_ref, 1, 7) = 'sha256:'),
            historical_snapshot_ref TEXT NOT NULL
                CHECK (length(historical_snapshot_ref) = 71 AND
                       substr(historical_snapshot_ref, 1, 7) = 'sha256:'),
            target_snapshot_ref TEXT NOT NULL
                CHECK (length(target_snapshot_ref) = 71 AND
                       substr(target_snapshot_ref, 1, 7) = 'sha256:'),
            target_policy_version TEXT NOT NULL
                CHECK (target_policy_version = 'file-access.uid1002-read.v1'),
            policy_digest TEXT NOT NULL
                CHECK (length(policy_digest) = 71 AND substr(policy_digest, 1, 7) = 'sha256:'),
            reservation_ref TEXT NOT NULL UNIQUE
                CHECK (length(reservation_ref) = 71 AND substr(reservation_ref, 1, 7) = 'sha256:'),
            request_budget INTEGER NOT NULL CHECK (request_budget BETWEEN 1 AND 64),
            issued_at_ms INTEGER NOT NULL CHECK (issued_at_ms > 0),
            deadline_ms INTEGER NOT NULL CHECK (deadline_ms > issued_at_ms),
            document_json TEXT NOT NULL
                CHECK (json_valid(document_json))
                CHECK (length(CAST(document_json AS BLOB)) <= 24576),
            record_digest TEXT NOT NULL UNIQUE
                CHECK (length(record_digest) = 71 AND substr(record_digest, 1, 7) = 'sha256:'),
            FOREIGN KEY (experiment_id) REFERENCES engine_experiment_heads(experiment_id)
        )""",
        """CREATE TABLE IF NOT EXISTS engine_file_access_request_claims (
            attempt_id TEXT NOT NULL,
            ordinal INTEGER NOT NULL CHECK (ordinal > 0),
            claim_ref TEXT NOT NULL UNIQUE
                CHECK (length(claim_ref) = 71 AND substr(claim_ref, 1, 7) = 'sha256:'),
            reservation_ref TEXT NOT NULL
                CHECK (length(reservation_ref) = 71 AND substr(reservation_ref, 1, 7) = 'sha256:'),
            policy_digest TEXT NOT NULL
                CHECK (length(policy_digest) = 71 AND substr(policy_digest, 1, 7) = 'sha256:'),
            task_id TEXT NOT NULL UNIQUE
                CHECK (length(task_id) = 72 AND substr(task_id, 1, 8) = 'execute-'),
            request_hash TEXT NOT NULL UNIQUE
                CHECK (length(request_hash) = 71 AND substr(request_hash, 1, 7) = 'sha256:'),
            transport_request_hash TEXT NOT NULL UNIQUE
                CHECK (length(transport_request_hash) = 71 AND
                       substr(transport_request_hash, 1, 7) = 'sha256:'),
            claimed_at_ms INTEGER NOT NULL CHECK (claimed_at_ms > 0),
            document_json TEXT NOT NULL
                CHECK (json_valid(document_json))
                CHECK (length(CAST(document_json AS BLOB)) <= 24576),
            record_digest TEXT NOT NULL UNIQUE
                CHECK (length(record_digest) = 71 AND substr(record_digest, 1, 7) = 'sha256:'),
            PRIMARY KEY (attempt_id, ordinal),
            FOREIGN KEY (attempt_id)
                REFERENCES engine_file_access_target_reservations(attempt_id)
        )""",
        """CREATE TRIGGER IF NOT EXISTS engine_file_access_target_reservations_no_update
        BEFORE UPDATE ON engine_file_access_target_reservations BEGIN
            SELECT RAISE(ABORT, 'engine file-access reservations are immutable');
        END""",
        """CREATE TRIGGER IF NOT EXISTS engine_file_access_target_reservations_no_delete
        BEFORE DELETE ON engine_file_access_target_reservations BEGIN
            SELECT RAISE(ABORT, 'engine file-access reservations are append-only');
        END""",
        """CREATE TRIGGER IF NOT EXISTS engine_file_access_request_claims_no_update
        BEFORE UPDATE ON engine_file_access_request_claims BEGIN
            SELECT RAISE(ABORT, 'engine file-access request claims are immutable');
        END""",
        """CREATE TRIGGER IF NOT EXISTS engine_file_access_request_claims_no_delete
        BEFORE DELETE ON engine_file_access_request_claims BEGIN
            SELECT RAISE(ABORT, 'engine file-access request claims are append-only');
        END""",
        """CREATE TRIGGER IF NOT EXISTS engine_file_access_target_reservations_valid_insert
        BEFORE INSERT ON engine_file_access_target_reservations BEGIN
            SELECT CASE WHEN NOT EXISTS (
                SELECT 1 FROM engine_experiment_heads AS head
                JOIN engine_experiment_versions AS version
                  ON version.experiment_id = head.experiment_id
                 AND version.revision = head.active_revision
                 AND version.digest = head.active_digest
                JOIN json_each(version.document_json, '$.attempts') AS attempt
                WHERE head.experiment_id = NEW.experiment_id
                  AND json_extract(version.document_json, '$.scope_ref')
                      = NEW.mechanism_ref
                  AND json_extract(version.document_json, '$.initial_target_snapshot_ref')
                      = NEW.historical_snapshot_ref
                  AND json_extract(version.document_json, '$.current_target_snapshot_ref')
                      = NEW.target_snapshot_ref
                  AND json_extract(attempt.value, '$.record.binding.attempt_id')
                      = NEW.attempt_id
                  AND json_extract(attempt.value, '$.job_id') = NEW.job_id
                  AND json_extract(attempt.value, '$.record.binding.run_id') = NEW.run_id
                  AND json_extract(attempt.value, '$.record.binding.role') = NEW.role
                  AND json_extract(attempt.value, '$.record.binding_digest')
                      = NEW.binding_digest
                  AND json_extract(attempt.value, '$.record.binding.scope_ref')
                      = NEW.mechanism_ref
                  AND json_extract(attempt.value, '$.record.binding.target_snapshot_ref')
                      = NEW.target_snapshot_ref
                  AND json_extract(attempt.value, '$.record.state')
                      IN ('queued', 'preflight', 'running')
            ) THEN RAISE(ABORT, 'engine file-access attempt is not saved') END;
            SELECT CASE WHEN
                json_extract(NEW.document_json, '$.schema_version')
                    IS NOT 'bluefire.engine-file-access-target-reservation.v1'
                OR json_extract(NEW.document_json, '$.attempt_id') IS NOT NEW.attempt_id
                OR json_extract(NEW.document_json, '$.experiment_id') IS NOT NEW.experiment_id
                OR json_extract(NEW.document_json, '$.job_id') IS NOT NEW.job_id
                OR json_extract(NEW.document_json, '$.run_id') IS NOT NEW.run_id
                OR json_extract(NEW.document_json, '$.role') IS NOT NEW.role
                OR json_extract(NEW.document_json, '$.action_id') IS NOT NEW.action_id
                OR json_extract(NEW.document_json, '$.binding_digest') IS NOT NEW.binding_digest
                OR json_extract(NEW.document_json, '$.mechanism_ref') IS NOT NEW.mechanism_ref
                OR json_extract(NEW.document_json, '$.historical_snapshot_ref')
                    IS NOT NEW.historical_snapshot_ref
                OR json_extract(NEW.document_json, '$.target_snapshot_ref')
                    IS NOT NEW.target_snapshot_ref
                OR json_extract(NEW.document_json, '$.target_policy_version')
                    IS NOT NEW.target_policy_version
                OR json_extract(NEW.document_json, '$.policy_digest') IS NOT NEW.policy_digest
                OR json_extract(NEW.document_json, '$.reservation_ref')
                    IS NOT NEW.reservation_ref
                OR json_extract(NEW.document_json, '$.request_budget')
                    IS NOT NEW.request_budget
                OR json_extract(NEW.document_json, '$.issued_at_ms') IS NOT NEW.issued_at_ms
                OR json_extract(NEW.document_json, '$.deadline_ms') IS NOT NEW.deadline_ms
            THEN RAISE(ABORT, 'engine file-access reservation document changed') END;
        END""",
        """CREATE TRIGGER IF NOT EXISTS engine_file_access_request_claims_valid_insert
        BEFORE INSERT ON engine_file_access_request_claims BEGIN
            SELECT CASE WHEN NOT EXISTS (
                SELECT 1 FROM engine_file_access_target_reservations
                WHERE attempt_id = NEW.attempt_id
                  AND reservation_ref = NEW.reservation_ref
                  AND policy_digest = NEW.policy_digest
                  AND NEW.ordinal <= request_budget
                  AND NEW.claimed_at_ms >= issued_at_ms
                  AND NEW.claimed_at_ms < deadline_ms
            ) THEN RAISE(ABORT, 'engine file-access request exceeds reservation') END;
            SELECT CASE WHEN NEW.ordinal != COALESCE((
                SELECT MAX(ordinal) + 1 FROM engine_file_access_request_claims
                WHERE attempt_id = NEW.attempt_id
            ), 1) THEN RAISE(ABORT, 'engine file-access request ordinal is not next') END;
            SELECT CASE WHEN NEW.task_id != 'execute-' || substr(NEW.request_hash, 8)
            THEN RAISE(ABORT, 'engine file-access task identity changed') END;
            SELECT CASE WHEN
                json_extract(NEW.document_json, '$.schema_version')
                    IS NOT 'bluefire.engine-file-access-request-claim.v1'
                OR json_extract(NEW.document_json, '$.attempt_id') IS NOT NEW.attempt_id
                OR json_extract(NEW.document_json, '$.ordinal') IS NOT NEW.ordinal
                OR json_extract(NEW.document_json, '$.claim_ref') IS NOT NEW.claim_ref
                OR json_extract(NEW.document_json, '$.reservation_ref')
                    IS NOT NEW.reservation_ref
                OR json_extract(NEW.document_json, '$.policy_digest') IS NOT NEW.policy_digest
                OR json_extract(NEW.document_json, '$.task_id') IS NOT NEW.task_id
                OR json_extract(NEW.document_json, '$.request_hash') IS NOT NEW.request_hash
                OR json_extract(NEW.document_json, '$.transport_request_hash')
                    IS NOT NEW.transport_request_hash
                OR json_extract(NEW.document_json, '$.claimed_at_ms')
                    IS NOT NEW.claimed_at_ms
            THEN RAISE(ABORT, 'engine file-access request claim document changed') END;
        END""",
    )
    for statement in statements:
        connection.execute(statement)


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ProductStoreError(f"{label} must be an exact lowercase sha256 digest")
    return value


def _attempt_id(value: Any) -> str:
    if not isinstance(value, str) or _ATTEMPT_ID.fullmatch(value) is None:
        raise ProductStoreError("engine file-access attempt ID is invalid")
    return value


def _policy(value: EngineFileReadTargetPolicy | Mapping[str, Any]) -> EngineFileReadTargetPolicy:
    try:
        document: Mapping[str, Any] = (
            value.to_dict() if isinstance(value, EngineFileReadTargetPolicy) else value
        )
        return EngineFileReadTargetPolicy.from_mapping(document)
    except (AttributeError, TypeError, ValueError) as exc:
        raise ProductStoreError("engine file-access target policy is invalid") from exc


def _server_now_ms() -> int:
    return time.time_ns() // 1_000_000


def _active_owner_at(
    connection: sqlite3.Connection,
    experiment_id: str,
    attempt_id: str,
    policy: EngineFileReadTargetPolicy,
    now_ms: int,
) -> tuple[EngineExperiment, EngineAttemptEntry]:
    """Reopen the current protected head; caller-owned objects prove nothing."""

    experiment = engine_jobs._active_experiment_at(connection, experiment_id)
    try:
        _index, entry = experiment._attempt(attempt_id)
    except EngineExperimentError as exc:
        raise ResourceConflictError("engine file-access attempt is not saved") from exc
    binding = entry.record.binding
    if (
        binding.experiment_id != experiment_id
        or binding.attempt_id != attempt_id
        or entry.record.state not in _ACTIVE_STATES
        or binding.engine_id != "strix"
        or binding.scope_version != ENGINE_CAPABILITY_SCOPE_VERSION
        or experiment.scope_ref != binding.scope_ref
        or experiment.current_target_snapshot_ref != binding.target_snapshot_ref
    ):
        raise ResourceConflictError("engine file-access attempt is no longer current")
    expected_phase = (
        HISTORICAL_BASELINE
        if binding.role is AttemptRole.BASELINE
        else CURRENT_HARDENED if binding.role is AttemptRole.ADAPTIVE_SEARCH else None
    )
    created_at_ms = int(parse_iso8601_datetime(binding.created_at).timestamp() * 1000)
    if (
        policy.attempt_id != attempt_id
        or policy.attempt_binding_digest != binding.binding_digest
        or policy.mechanism.mechanism_ref != binding.scope_ref
        or policy.historical_snapshot.target_snapshot_ref != experiment.initial_target_snapshot_ref
        or policy.snapshot.target_snapshot_ref != binding.target_snapshot_ref
        or policy.snapshot.to_dict()["phase"] != expected_phase
        or policy.request_budget > binding.action_limit
        or policy.max_read_bytes > binding.artifact_byte_limit
        or policy.issued_at_ms < created_at_ms
        or policy.issued_at_ms > now_ms
        or policy.deadline_ms > created_at_ms + binding.wall_clock_seconds * 1000
        or now_ms >= policy.deadline_ms
    ):
        raise ResourceConflictError("engine file-access target differs from saved attempt")
    return experiment, entry


def _reservation_document(
    experiment: EngineExperiment,
    entry: EngineAttemptEntry,
    policy: EngineFileReadTargetPolicy,
    now_ms: int,
) -> dict[str, Any]:
    binding = entry.record.binding
    policy_document = policy.to_dict()
    policy_digest = content_hash(policy_document)
    reservation_ref = content_hash(
        {
            "schema_version": _RESERVATION_SCHEMA,
            "experiment_id": experiment.experiment_id,
            "attempt_id": binding.attempt_id,
            "policy_digest": policy_digest,
        }
    )
    return {
        "schema_version": _RESERVATION_SCHEMA,
        "reservation_ref": reservation_ref,
        "experiment_id": experiment.experiment_id,
        "attempt_id": binding.attempt_id,
        "job_id": entry.job_id,
        "run_id": binding.run_id,
        "role": binding.role.value,
        "action_id": PROBE_ACTION,
        "binding_digest": binding.binding_digest,
        "mechanism_ref": policy.mechanism.mechanism_ref,
        "historical_snapshot_ref": policy.historical_snapshot.target_snapshot_ref,
        "target_snapshot_ref": policy.snapshot.target_snapshot_ref,
        "target_policy_version": policy.target_policy_version,
        "policy_digest": policy_digest,
        "request_budget": policy.request_budget,
        "issued_at_ms": policy.issued_at_ms,
        "deadline_ms": policy.deadline_ms,
        "policy": policy_document,
        "created_at_ms": now_ms,
    }


def _encoded(document: Mapping[str, Any]) -> tuple[str, str]:
    encoded = canonical_json(document)
    if not encoded or len(encoded.encode("utf-8")) > _MAX_DOCUMENT_BYTES:
        raise ProductStoreError("engine file-access record exceeds its finite bound")
    return encoded, content_hash(document)


def _decoded(row: sqlite3.Row, fields: frozenset[str], label: str) -> dict[str, Any]:
    try:
        document = json.loads(row["document_json"])
        if (
            not isinstance(document, dict)
            or set(document) != fields
            or canonical_json(document) != row["document_json"]
            or content_hash(document) != row["record_digest"]
        ):
            raise ValueError("record digest or fields changed")
    except (TypeError, ValueError, KeyError) as exc:
        raise ProductStoreError(f"saved engine file-access {label} is invalid") from exc
    return cast(dict[str, Any], document)


def _reservation_from_row(row: sqlite3.Row) -> dict[str, Any]:
    document = _decoded(row, _RESERVATION_FIELDS, "reservation")
    try:
        policy = _policy(document["policy"])
        expected_ref = content_hash(
            {
                "schema_version": _RESERVATION_SCHEMA,
                "experiment_id": document["experiment_id"],
                "attempt_id": document["attempt_id"],
                "policy_digest": policy.policy_digest,
            }
        )
        if (
            document["schema_version"] != _RESERVATION_SCHEMA
            or document["reservation_ref"] != expected_ref
            or document["attempt_id"] != row["attempt_id"]
            or document["experiment_id"] != row["experiment_id"]
            or document["job_id"] != row["job_id"]
            or document["run_id"] != row["run_id"]
            or document["role"] != row["role"]
            or document["action_id"] != PROBE_ACTION
            or document["action_id"] != row["action_id"]
            or document["binding_digest"] != policy.attempt_binding_digest
            or document["binding_digest"] != row["binding_digest"]
            or document["mechanism_ref"] != policy.mechanism.mechanism_ref
            or document["mechanism_ref"] != row["mechanism_ref"]
            or document["historical_snapshot_ref"] != policy.historical_snapshot.target_snapshot_ref
            or document["historical_snapshot_ref"] != row["historical_snapshot_ref"]
            or document["target_snapshot_ref"] != policy.snapshot.target_snapshot_ref
            or document["target_snapshot_ref"] != row["target_snapshot_ref"]
            or document["target_policy_version"] != policy.target_policy_version
            or document["target_policy_version"] != row["target_policy_version"]
            or document["policy_digest"] != policy.policy_digest
            or document["policy_digest"] != row["policy_digest"]
            or document["reservation_ref"] != row["reservation_ref"]
            or document["request_budget"] != policy.request_budget
            or document["request_budget"] != row["request_budget"]
            or document["issued_at_ms"] != policy.issued_at_ms
            or document["issued_at_ms"] != row["issued_at_ms"]
            or document["deadline_ms"] != policy.deadline_ms
            or document["deadline_ms"] != row["deadline_ms"]
            or type(document["created_at_ms"]) is not int
            or not policy.issued_at_ms <= document["created_at_ms"] < policy.deadline_ms
        ):
            raise ValueError("reservation identity changed")
    except (TypeError, ValueError, ProductStoreError) as exc:
        raise ProductStoreError("saved engine file-access reservation is invalid") from exc
    return document


def _claim_from_row(row: sqlite3.Row, reservation: Mapping[str, Any]) -> dict[str, Any]:
    document = _decoded(row, _CLAIM_FIELDS, "request claim")
    expected_ref = content_hash(
        {
            "schema_version": _CLAIM_SCHEMA,
            "reservation_ref": document["reservation_ref"],
            "ordinal": document["ordinal"],
            "task_id": document["task_id"],
            "request_hash": document["request_hash"],
            "transport_request_hash": document["transport_request_hash"],
        }
    )
    if (
        document["schema_version"] != _CLAIM_SCHEMA
        or document["claim_ref"] != expected_ref
        or document["claim_ref"] != row["claim_ref"]
        or document["reservation_ref"] != reservation["reservation_ref"]
        or document["reservation_ref"] != row["reservation_ref"]
        or document["policy_digest"] != reservation["policy_digest"]
        or document["policy_digest"] != row["policy_digest"]
        or document["attempt_id"] != reservation["attempt_id"]
        or document["attempt_id"] != row["attempt_id"]
        or type(document["ordinal"]) is not int
        or not 1 <= document["ordinal"] <= reservation["request_budget"]
        or document["ordinal"] != row["ordinal"]
        or document["task_id"] != row["task_id"]
        or document["request_hash"] != row["request_hash"]
        or document["transport_request_hash"] != row["transport_request_hash"]
        or not isinstance(document["task_id"], str)
        or not isinstance(document["request_hash"], str)
        or not isinstance(document["transport_request_hash"], str)
        or document["task_id"] != "execute-" + document["request_hash"][7:]
        or _DIGEST.fullmatch(document["request_hash"]) is None
        or _DIGEST.fullmatch(document["transport_request_hash"]) is None
        or type(document["claimed_at_ms"]) is not int
        or not reservation["issued_at_ms"] <= document["claimed_at_ms"] < reservation["deadline_ms"]
        or document["claimed_at_ms"] != row["claimed_at_ms"]
    ):
        raise ProductStoreError("saved engine file-access request claim is invalid")
    return document


class EngineFileAccessStoreMixin:
    """No service route or dispatch method; only durable intent and budget claims."""

    def reserve_engine_file_access_target(
        self: EngineFileAccessStore,
        experiment_id: str,
        attempt_id: str,
        policy: EngineFileReadTargetPolicy | Mapping[str, Any],
    ) -> Mapping[str, Any]:
        """Pin exact policy review material to a reopened, active saved attempt.

        This does not authenticate live target state. The later admission
        coordinator must rebuild the immutable historical and current control
        state and compare it with this independently stored policy digest.
        """

        attempt_id = _attempt_id(attempt_id)
        parsed = _policy(policy)
        with self._connection(write=True) as connection:
            now_ms = _server_now_ms()
            experiment, entry = _active_owner_at(
                connection, experiment_id, attempt_id, parsed, now_ms
            )
            candidate = _reservation_document(experiment, entry, parsed, now_ms)
            existing = connection.execute(
                "SELECT * FROM engine_file_access_target_reservations WHERE attempt_id = ?",
                (attempt_id,),
            ).fetchone()
            if existing is not None:
                saved = _reservation_from_row(existing)
                identity_fields = _RESERVATION_FIELDS - {"created_at_ms"}
                if any(saved[field] != candidate[field] for field in identity_fields):
                    raise ResourceConflictError(
                        "engine file-access attempt has another reservation"
                    )
                return saved
            encoded, record_digest = _encoded(candidate)
            try:
                connection.execute(
                    """INSERT INTO engine_file_access_target_reservations (
                        attempt_id, experiment_id, job_id, run_id, role, action_id,
                        binding_digest, mechanism_ref, historical_snapshot_ref,
                        target_snapshot_ref, target_policy_version, policy_digest,
                        reservation_ref, request_budget, issued_at_ms, deadline_ms,
                        document_json, record_digest
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        attempt_id,
                        candidate["experiment_id"],
                        candidate["job_id"],
                        candidate["run_id"],
                        candidate["role"],
                        candidate["action_id"],
                        candidate["binding_digest"],
                        candidate["mechanism_ref"],
                        candidate["historical_snapshot_ref"],
                        candidate["target_snapshot_ref"],
                        candidate["target_policy_version"],
                        candidate["policy_digest"],
                        candidate["reservation_ref"],
                        candidate["request_budget"],
                        candidate["issued_at_ms"],
                        candidate["deadline_ms"],
                        encoded,
                        record_digest,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ResourceConflictError("engine file-access reservation lost a race") from exc
        return candidate

    def get_engine_file_access_target_reservation(
        self: EngineFileAccessStore, attempt_id: str
    ) -> Mapping[str, Any]:
        """Read historical accounting only; this record grants no dispatch authority.

        A consumable claim always reopens the latest experiment, attempt, and
        stored policy. Callers cannot infer current admission from this getter.
        """

        attempt_id = _attempt_id(attempt_id)
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM engine_file_access_target_reservations WHERE attempt_id = ?",
                (attempt_id,),
            ).fetchone()
        if row is None:
            raise ProductStoreError("engine file-access reservation was not found")
        return _reservation_from_row(row)

    def claim_engine_file_access_request(
        self: EngineFileAccessStore,
        attempt_id: str,
        *,
        ordinal: int,
        task_id: str,
        request_hash: str,
        transport_request_hash: str,
    ) -> Mapping[str, Any]:
        """Consume one ordinal against current database control state atomically.

        This guard does not prove live filesystem state or launch a read. The
        controller must perform its separate live admission checks first.
        """

        attempt_id = _attempt_id(attempt_id)
        request_hash = _digest(request_hash, "file-access request hash")
        transport_request_hash = _digest(transport_request_hash, "file-access transport hash")
        if (
            type(ordinal) is not int
            or ordinal < 1
            or not isinstance(task_id, str)
            or _TASK_ID.fullmatch(task_id) is None
            or task_id != "execute-" + request_hash[7:]
        ):
            raise ProductStoreError("engine file-access request identity is invalid")
        with self._connection(write=True) as connection:
            now_ms = _server_now_ms()
            row = connection.execute(
                "SELECT * FROM engine_file_access_target_reservations WHERE attempt_id = ?",
                (attempt_id,),
            ).fetchone()
            if row is None:
                raise ProductStoreError("engine file-access reservation was not found")
            reservation = _reservation_from_row(row)
            stored_policy = _policy(reservation["policy"])
            experiment, entry = _active_owner_at(
                connection,
                str(reservation["experiment_id"]),
                attempt_id,
                stored_policy,
                now_ms,
            )
            binding = entry.record.binding
            if (
                entry.job_id != reservation["job_id"]
                or binding.run_id != reservation["run_id"]
                or binding.role.value != reservation["role"]
                or binding.binding_digest != reservation["binding_digest"]
                or binding.scope_ref != reservation["mechanism_ref"]
                or binding.target_snapshot_ref != reservation["target_snapshot_ref"]
                or experiment.initial_target_snapshot_ref != reservation["historical_snapshot_ref"]
                or now_ms < reservation["issued_at_ms"]
                or now_ms >= reservation["deadline_ms"]
            ):
                raise ResourceConflictError("engine file-access reservation is no longer current")
            snapshot = stored_policy.snapshot.to_dict()
            owner_id = snapshot["control_owner_id"]
            control_view = file_access_records._control_at(connection, owner_id)
            control = control_view["document"]
            expected_status = (
                "baseline_verified" if binding.role is AttemptRole.BASELINE else "hardened"
            )
            if (
                control_view["document_digest"] != snapshot["control_digest"]
                or control["control_owner_id"] != owner_id
                or control["revision"] != snapshot["control_revision"]
                or control["binding_digest"] != snapshot["binding_digest"]
                or content_hash(control["binding"]) != snapshot["binding_digest"]
                or control["status"] != expected_status
                or file_access_records._pending(connection, owner_id)
                or not control_usages_settled(self, connection, owner_id)
            ):
                raise ResourceConflictError("engine file-access control is no longer settled")
            latest = connection.execute(
                """SELECT COALESCE(MAX(ordinal), 0) AS latest
                FROM engine_file_access_request_claims WHERE attempt_id = ?""",
                (attempt_id,),
            ).fetchone()
            if ordinal != int(latest["latest"]) + 1 or ordinal > reservation["request_budget"]:
                raise ResourceConflictError("engine file-access request budget or ordinal exceeded")
            claim_ref = content_hash(
                {
                    "schema_version": _CLAIM_SCHEMA,
                    "reservation_ref": reservation["reservation_ref"],
                    "ordinal": ordinal,
                    "task_id": task_id,
                    "request_hash": request_hash,
                    "transport_request_hash": transport_request_hash,
                }
            )
            document = {
                "schema_version": _CLAIM_SCHEMA,
                "claim_ref": claim_ref,
                "reservation_ref": reservation["reservation_ref"],
                "policy_digest": reservation["policy_digest"],
                "attempt_id": attempt_id,
                "ordinal": ordinal,
                "task_id": task_id,
                "request_hash": request_hash,
                "transport_request_hash": transport_request_hash,
                "claimed_at_ms": now_ms,
            }
            encoded, record_digest = _encoded(document)
            try:
                connection.execute(
                    """INSERT INTO engine_file_access_request_claims (
                        attempt_id, ordinal, claim_ref, reservation_ref, policy_digest,
                        task_id, request_hash, transport_request_hash, claimed_at_ms,
                        document_json, record_digest
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        attempt_id,
                        ordinal,
                        claim_ref,
                        reservation["reservation_ref"],
                        reservation["policy_digest"],
                        task_id,
                        request_hash,
                        transport_request_hash,
                        now_ms,
                        encoded,
                        record_digest,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ResourceConflictError(
                    "engine file-access request identity was replayed"
                ) from exc
        return document

    def list_engine_file_access_request_claims(
        self: EngineFileAccessStore, attempt_id: str
    ) -> list[Mapping[str, Any]]:
        """List historical accounting, never current admission or dispatch authority.

        Presence in this list does not authorize a read. The claim writer
        reopens and revalidates the current owner and exact protected policy.
        """

        attempt_id = _attempt_id(attempt_id)
        with self._connection() as connection:
            reservation_row = connection.execute(
                "SELECT * FROM engine_file_access_target_reservations WHERE attempt_id = ?",
                (attempt_id,),
            ).fetchone()
            if reservation_row is None:
                raise ProductStoreError("engine file-access reservation was not found")
            reservation = _reservation_from_row(reservation_row)
            rows = connection.execute(
                """SELECT * FROM engine_file_access_request_claims
                WHERE attempt_id = ? ORDER BY ordinal""",
                (attempt_id,),
            ).fetchall()
        claims: list[Mapping[str, Any]] = [_claim_from_row(row, reservation) for row in rows]
        if [claim["ordinal"] for claim in claims] != list(range(1, len(claims) + 1)):
            raise ProductStoreError("saved engine file-access request claim sequence changed")
        return claims


__all__ = ["EngineFileAccessStoreMixin", "initialize_schema"]
