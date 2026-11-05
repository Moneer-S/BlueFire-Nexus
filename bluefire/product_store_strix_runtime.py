"""Private v20 Strix runtime authority and admission persistence.

The tables in this module are controller-only.  They are deliberately absent
from generic resources, HTTP routes, exports, and presentation projections.
They retain authority and custody provenance; they never allocate a runtime,
resolve an opaque location, acquire credentials, or launch work.
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Mapping
from contextlib import AbstractContextManager
from typing import Any, Protocol, cast

from .product_store_contracts import safe_document
from .product_store_errors import ProductStoreError, ResourceConflictError
from .product_store_serialization import canonical_json
from .strix_adapter import StrixAdapterError, StrixBudgets, StrixBuildIdentity, StrixRuntimeLimits
from .util import content_hash, parse_iso8601_datetime

AUTHORITY_EVENT_SCHEMA = "bluefire.strix-runtime-authority-event.v1"
ADMISSION_RESERVATION_SCHEMA = "bluefire.strix-runtime-admission-reservation.v1"
ADMISSION_EVENT_SCHEMA = "bluefire.strix-runtime-admission-event.v1"
ADMISSION_RECORD_SCHEMA = "bluefire.strix-runtime-admission-record.v1"
MAX_AUTHORITY_EVENTS = 4096
MAX_ADMISSION_EVENTS = 4096
MAX_DOCUMENT_BYTES = 256 * 1024

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_ATTEMPT = re.compile(r"^engine-attempt-[0-9a-f]{32}$")
_EXPERIMENT = re.compile(r"^experiment-[0-9a-f]{32}$")
_REVISION = re.compile(r"^[0-9a-f]{40}$")
_ARTIFACT_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{31,127}$")
_AUTHORITY_STATES = {"active", "revoked"}
_ADMISSION_STATES = {"reserved", "preparing", "verified", "unknown", "revoked", "cleaned"}
_ADMISSION_TRANSITIONS = {
    "reserved": {"preparing", "revoked", "cleaned"},
    "preparing": {"verified", "unknown", "revoked"},
    "verified": {"unknown", "revoked", "cleaned"},
    "unknown": {"verified", "revoked", "cleaned"},
    "revoked": {"cleaned"},
    "cleaned": set(),
}
_AUTHORITY_FIELDS = {
    "schema_version",
    "generation",
    "state",
    "qualification_manifest_ref",
    "protected_artifact_key",
    "installed_bluefire_revision",
    "strix_build_digest",
    "threat_review_ref",
    "recorded_at",
    "revocation_reason",
}
_RESERVATION_FIELDS = {
    "schema_version",
    "attempt_id",
    "experiment_id",
    "experiment_revision",
    "experiment_digest",
    "binding_digest",
    "delegation_digest",
    "objective_ref",
    "environment_ref",
    "authority_ref",
    "authority_generation",
    "authority_record_digest",
    "qualification_ref",
    "target_snapshot_digest",
    "request_digest",
    "created_at",
    "expires_at",
}
_ADMISSION_FIELDS = {
    "schema_version",
    "attempt_id",
    "experiment_id",
    "experiment_revision",
    "experiment_digest",
    "binding_digest",
    "delegation_digest",
    "objective_ref",
    "environment_ref",
    "authority_ref",
    "authority_generation",
    "authority_record_digest",
    "qualification_ref",
    "target_snapshot_digest",
    "build",
    "build_digest",
    "model_id",
    "scope_record_ref",
    "scope_record_digest",
    "gateway_record_ref",
    "gateway_record_digest",
    "budgets",
    "limits",
    "network_plan_ref",
    "network_plan_digest",
    "network_snapshot_ref",
    "network_snapshot_digest",
    "network_verification_ref",
    "network_verification_digest",
    "custody_plan_ref",
    "custody_plan_digest",
    "protected_roots_ref",
    "protected_roots_digest",
    "containment_ref",
    "containment_digest",
    "runtime_install_ref",
    "runtime_install_digest",
    "workspace_ref",
    "workspace_digest",
    "executable_ref",
    "executable_digest",
    "path_environment_ref",
    "path_environment_digest",
    "control_root_ref",
    "control_root_digest",
    "artifact_root_ref",
    "artifact_root_digest",
    "custody_source_ref",
    "custody_record_ref",
    "custody_record_digest",
    "admission_proof_bundle_digest",
    "created_at",
    "expires_at",
}
_ADMISSION_DIGEST_FIELDS = {
    name
    for name in _ADMISSION_FIELDS
    if name.endswith(("_ref", "_digest"))
    and name
    not in {
        "authority_ref",
        "runtime_install_ref",
        "workspace_ref",
        "executable_ref",
        "path_environment_ref",
        "control_root_ref",
        "artifact_root_ref",
        "custody_source_ref",
        "custody_record_ref",
    }
}
_OPAQUE_DIGEST_FIELDS = {
    "authority_ref",
    "runtime_install_ref",
    "workspace_ref",
    "executable_ref",
    "path_environment_ref",
    "control_root_ref",
    "artifact_root_ref",
    "custody_source_ref",
    "custody_record_ref",
}


class StrixRuntimeStore(Protocol):
    def _connection(self, *, write: bool = False) -> AbstractContextManager[sqlite3.Connection]: ...


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ProductStoreError(f"{label} must be an exact lowercase sha256 digest")
    return value


def _positive_int(value: Any, label: str, *, maximum: int = 2**63 - 1) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        raise ProductStoreError(f"{label} is invalid")
    return value


def _timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise ProductStoreError(f"{label} is invalid")
    try:
        parsed = parse_iso8601_datetime(value)
    except (TypeError, ValueError, RecursionError) as exc:
        raise ProductStoreError(f"{label} is invalid") from exc
    if parsed.isoformat().replace("+00:00", "Z") != value:
        raise ProductStoreError(f"{label} must use canonical UTC text")
    return value


def _bounded_document(value: Mapping[str, Any], *, context: str) -> dict[str, Any]:
    try:
        cloned = safe_document(value, context=context)
    except ProductStoreError:
        raise
    except (TypeError, ValueError, RecursionError) as exc:
        raise ProductStoreError(f"{context} is invalid") from exc
    if not isinstance(cloned, dict):
        raise ProductStoreError(f"{context} must be an object")
    try:
        encoded = canonical_json(cloned)
    except (TypeError, ValueError, RecursionError) as exc:
        raise ProductStoreError(f"{context} is invalid") from exc
    if not 1 <= len(encoded.encode("utf-8")) <= MAX_DOCUMENT_BYTES:
        raise ProductStoreError(f"{context} exceeds its byte bound")
    return cloned


def _authority(value: Mapping[str, Any]) -> dict[str, Any]:
    row = _bounded_document(value, context="Strix runtime authority")
    if set(row) != _AUTHORITY_FIELDS:
        raise ProductStoreError("Strix runtime authority fields are invalid")
    generation = _positive_int(
        row["generation"], "Strix authority generation", maximum=MAX_AUTHORITY_EVENTS
    )
    state = row["state"]
    if (
        row["schema_version"] != "bluefire.strix-runtime-authority.v1"
        or state not in _AUTHORITY_STATES
    ):
        raise ProductStoreError("Strix runtime authority contract is invalid")
    for name in ("qualification_manifest_ref", "strix_build_digest", "threat_review_ref"):
        _digest(row[name], f"Strix authority {name}")
    if (
        not isinstance(row["protected_artifact_key"], str)
        or _ARTIFACT_KEY.fullmatch(row["protected_artifact_key"]) is None
    ):
        raise ProductStoreError("Strix authority artifact key is invalid")
    if (
        not isinstance(row["installed_bluefire_revision"], str)
        or _REVISION.fullmatch(row["installed_bluefire_revision"]) is None
    ):
        raise ProductStoreError("Strix authority BlueFire revision is invalid")
    _timestamp(row["recorded_at"], "Strix authority timestamp")
    reason = row["revocation_reason"]
    if state == "active":
        if reason is not None:
            raise ProductStoreError("active Strix authority cannot have a revocation reason")
    elif (
        not isinstance(reason, str)
        or not reason
        or len(reason) > 200
        or any(ord(char) < 32 or ord(char) == 127 for char in reason)
    ):
        raise ProductStoreError("revoked Strix authority reason is invalid")
    row["generation"] = generation
    return row


def _authority_event_document(
    *,
    authority_ref: str,
    authority: Mapping[str, Any],
    authority_basis_ref: str,
    previous_event_digest: str | None,
) -> dict[str, Any]:
    checked = _authority(authority)
    return {
        "schema_version": AUTHORITY_EVENT_SCHEMA,
        "authority_ref": _digest(authority_ref, "Strix authority ref"),
        "authority": checked,
        "authority_record_digest": content_hash(checked),
        "authority_basis_ref": _digest(authority_basis_ref, "Strix authority basis"),
        "previous_event_digest": None
        if previous_event_digest is None
        else _digest(previous_event_digest, "previous Strix authority event"),
    }


def _reservation(value: Mapping[str, Any]) -> dict[str, Any]:
    row = _bounded_document(value, context="Strix admission reservation")
    if set(row) != _RESERVATION_FIELDS or row["schema_version"] != ADMISSION_RESERVATION_SCHEMA:
        raise ProductStoreError("Strix admission reservation fields are invalid")
    if not isinstance(row["attempt_id"], str) or _ATTEMPT.fullmatch(row["attempt_id"]) is None:
        raise ProductStoreError("Strix admission attempt is invalid")
    if (
        not isinstance(row["experiment_id"], str)
        or _EXPERIMENT.fullmatch(row["experiment_id"]) is None
    ):
        raise ProductStoreError("Strix admission experiment is invalid")
    _positive_int(row["experiment_revision"], "Strix experiment revision", maximum=10000)
    for name in (
        "experiment_digest",
        "binding_digest",
        "delegation_digest",
        "authority_ref",
        "authority_record_digest",
        "qualification_ref",
        "target_snapshot_digest",
        "request_digest",
    ):
        _digest(row[name], f"Strix reservation {name}")
    _positive_int(
        row["authority_generation"],
        "Strix admitted authority generation",
        maximum=MAX_AUTHORITY_EVENTS,
    )
    for name in ("objective_ref", "environment_ref"):
        if (
            not isinstance(row[name], str)
            or not row[name]
            or len(row[name]) > 256
            or any(ord(char) < 32 or ord(char) == 127 for char in row[name])
        ):
            raise ProductStoreError(f"Strix reservation {name} is invalid")
    created = _timestamp(row["created_at"], "Strix reservation creation time")
    expires = _timestamp(row["expires_at"], "Strix reservation expiry")
    if parse_iso8601_datetime(expires) <= parse_iso8601_datetime(created):
        raise ProductStoreError("Strix admission reservation expiry is not after creation")
    return row


def _admission(value: Mapping[str, Any]) -> dict[str, Any]:
    row = _bounded_document(value, context="Strix verified admission")
    if set(row) != _ADMISSION_FIELDS or row["schema_version"] != ADMISSION_RECORD_SCHEMA:
        raise ProductStoreError("Strix verified admission fields are invalid")
    if not isinstance(row["attempt_id"], str) or _ATTEMPT.fullmatch(row["attempt_id"]) is None:
        raise ProductStoreError("Strix admission attempt is invalid")
    if (
        not isinstance(row["experiment_id"], str)
        or _EXPERIMENT.fullmatch(row["experiment_id"]) is None
    ):
        raise ProductStoreError("Strix admission experiment is invalid")
    _positive_int(row["experiment_revision"], "Strix experiment revision", maximum=10000)
    _positive_int(
        row["authority_generation"],
        "Strix admitted authority generation",
        maximum=MAX_AUTHORITY_EVENTS,
    )
    for name in (
        _ADMISSION_DIGEST_FIELDS
        | _OPAQUE_DIGEST_FIELDS
        | {
            "experiment_digest",
            "binding_digest",
            "delegation_digest",
        }
    ):
        _digest(row[name], f"Strix admission {name}")
    for name in ("objective_ref", "environment_ref", "model_id"):
        if (
            not isinstance(row[name], str)
            or not row[name]
            or len(row[name]) > 256
            or any(ord(char) < 32 or ord(char) == 127 for char in row[name])
        ):
            raise ProductStoreError(f"Strix admission {name} is invalid")
    build = row["build"]
    if not isinstance(build, dict) or build.get("engine") != "strix":
        raise ProductStoreError("Strix admission build identity is invalid")
    try:
        checked_build = StrixBuildIdentity(
            **{name: item for name, item in build.items() if name != "engine"}
        )
        checked_budgets = StrixBudgets(**cast(dict[str, Any], row["budgets"]))
        checked_limits = StrixRuntimeLimits(**cast(dict[str, Any], row["limits"]))
    except (StrixAdapterError, TypeError, ValueError) as exc:
        raise ProductStoreError("Strix admission runtime bounds are invalid") from exc
    if checked_build.to_dict() != build or content_hash(build) != row["build_digest"]:
        raise ProductStoreError("Strix admission build digest changed")
    if {
        name: getattr(checked_budgets, name) for name in checked_budgets.__dataclass_fields__
    } != row["budgets"]:
        raise ProductStoreError("Strix admission budgets are not canonical")
    if {name: getattr(checked_limits, name) for name in checked_limits.__dataclass_fields__} != row[
        "limits"
    ]:
        raise ProductStoreError("Strix admission limits are not canonical")
    created = _timestamp(row["created_at"], "Strix admission creation time")
    expires = _timestamp(row["expires_at"], "Strix admission expiry")
    if parse_iso8601_datetime(expires) <= parse_iso8601_datetime(created):
        raise ProductStoreError("Strix admission expiry is not after creation")
    return row


def _event_document(
    *,
    attempt_id: str,
    sequence: int,
    state: str,
    lifecycle_basis_ref: str,
    recorded_at: str,
    previous_event_digest: str | None,
    admission_record_ref: str | None,
) -> dict[str, Any]:
    if not isinstance(attempt_id, str) or _ATTEMPT.fullmatch(attempt_id) is None:
        raise ProductStoreError("Strix admission event attempt is invalid")
    _positive_int(sequence, "Strix admission event sequence", maximum=MAX_ADMISSION_EVENTS)
    if state not in _ADMISSION_STATES:
        raise ProductStoreError("Strix admission lifecycle state is invalid")
    _digest(lifecycle_basis_ref, "Strix admission lifecycle basis")
    _timestamp(recorded_at, "Strix admission lifecycle time")
    if previous_event_digest is not None:
        _digest(previous_event_digest, "previous Strix admission event")
    if admission_record_ref is not None:
        _digest(admission_record_ref, "Strix admission record ref")
    return {
        "schema_version": ADMISSION_EVENT_SCHEMA,
        "attempt_id": attempt_id,
        "sequence": sequence,
        "state": state,
        "lifecycle_basis_ref": lifecycle_basis_ref,
        "recorded_at": recorded_at,
        "previous_event_digest": previous_event_digest,
        "admission_record_ref": admission_record_ref,
    }


def initialize_schema(connection: sqlite3.Connection) -> None:
    """Install private v20 tables inside ProductStore's migration transaction."""
    if not connection.in_transaction:
        raise ProductStoreError("Strix runtime migration requires one transaction")
    statements = (
        """CREATE TABLE IF NOT EXISTS strix_runtime_authority_events (
          authority_ref TEXT NOT NULL,
          generation INTEGER NOT NULL CHECK(generation BETWEEN 1 AND 4096),
          document_json TEXT NOT NULL CHECK(json_valid(document_json))
            CHECK(length(CAST(document_json AS BLOB)) BETWEEN 1 AND 262144),
          authority_record_digest TEXT NOT NULL UNIQUE,
          event_digest TEXT NOT NULL UNIQUE,
          authority_basis_ref TEXT NOT NULL,
          previous_event_digest TEXT,
          recorded_at TEXT NOT NULL,
          PRIMARY KEY(authority_ref,generation)
        )""",
        """CREATE TABLE IF NOT EXISTS strix_runtime_authority_heads (
          authority_ref TEXT PRIMARY KEY,
          active_generation INTEGER NOT NULL,
          active_record_digest TEXT NOT NULL,
          active_event_digest TEXT NOT NULL,
          authority_basis_ref TEXT NOT NULL,
          FOREIGN KEY(authority_ref,active_generation)
            REFERENCES strix_runtime_authority_events(authority_ref,generation)
        )""",
        """CREATE TABLE IF NOT EXISTS strix_runtime_admission_reservations (
          attempt_id TEXT PRIMARY KEY,
          experiment_id TEXT NOT NULL,
          experiment_revision INTEGER NOT NULL,
          experiment_digest TEXT NOT NULL,
          authority_ref TEXT NOT NULL,
          authority_generation INTEGER NOT NULL,
          authority_record_digest TEXT NOT NULL,
          binding_digest TEXT NOT NULL UNIQUE,
          delegation_digest TEXT NOT NULL,
          runtime_qualification_ref TEXT NOT NULL,
          document_json TEXT NOT NULL CHECK(json_valid(document_json))
            CHECK(length(CAST(document_json AS BLOB)) BETWEEN 1 AND 262144),
          reservation_digest TEXT NOT NULL UNIQUE,
          reservation_ref TEXT NOT NULL UNIQUE,
          created_at TEXT NOT NULL,
          expires_at TEXT NOT NULL,
          FOREIGN KEY(experiment_id,experiment_revision)
            REFERENCES engine_experiment_versions(experiment_id,revision),
          FOREIGN KEY(authority_ref,authority_generation)
            REFERENCES strix_runtime_authority_events(authority_ref,generation)
        )""",
        """CREATE TABLE IF NOT EXISTS strix_runtime_admissions (
          attempt_id TEXT PRIMARY KEY,
          document_json TEXT NOT NULL CHECK(json_valid(document_json))
            CHECK(length(CAST(document_json AS BLOB)) BETWEEN 1 AND 262144),
          admission_record_ref TEXT NOT NULL UNIQUE,
          admission_record_digest TEXT NOT NULL UNIQUE,
          custody_source_ref TEXT NOT NULL,
          custody_record_ref TEXT NOT NULL,
          custody_record_digest TEXT NOT NULL,
          workspace_ref TEXT NOT NULL UNIQUE,
          control_root_ref TEXT NOT NULL UNIQUE,
          artifact_root_ref TEXT NOT NULL UNIQUE,
          network_plan_ref TEXT NOT NULL UNIQUE,
          network_snapshot_ref TEXT NOT NULL UNIQUE,
          network_verification_ref TEXT NOT NULL UNIQUE,
          custody_plan_ref TEXT NOT NULL UNIQUE,
          protected_roots_ref TEXT NOT NULL UNIQUE,
          containment_ref TEXT NOT NULL UNIQUE,
          admission_proof_bundle_digest TEXT NOT NULL,
          created_at TEXT NOT NULL,
          expires_at TEXT NOT NULL,
          FOREIGN KEY(attempt_id) REFERENCES strix_runtime_admission_reservations(attempt_id)
        )""",
        """CREATE TABLE IF NOT EXISTS strix_runtime_admission_events (
          attempt_id TEXT NOT NULL,
          sequence INTEGER NOT NULL CHECK(sequence BETWEEN 1 AND 4096),
          state TEXT NOT NULL CHECK(state IN
            ('reserved','preparing','verified','unknown','revoked','cleaned')),
          document_json TEXT NOT NULL CHECK(json_valid(document_json))
            CHECK(length(CAST(document_json AS BLOB)) BETWEEN 1 AND 262144),
          event_digest TEXT NOT NULL UNIQUE,
          previous_event_digest TEXT,
          admission_record_ref TEXT,
          lifecycle_basis_ref TEXT NOT NULL,
          recorded_at TEXT NOT NULL,
          PRIMARY KEY(attempt_id,sequence),
          FOREIGN KEY(attempt_id) REFERENCES strix_runtime_admission_reservations(attempt_id),
          FOREIGN KEY(admission_record_ref) REFERENCES strix_runtime_admissions(admission_record_ref)
        )""",
        """CREATE TABLE IF NOT EXISTS strix_runtime_admission_heads (
          attempt_id TEXT PRIMARY KEY,
          active_sequence INTEGER NOT NULL,
          active_state TEXT NOT NULL,
          active_event_digest TEXT NOT NULL,
          admission_record_ref TEXT,
          FOREIGN KEY(attempt_id,active_sequence)
            REFERENCES strix_runtime_admission_events(attempt_id,sequence),
          FOREIGN KEY(admission_record_ref) REFERENCES strix_runtime_admissions(admission_record_ref)
        )""",
    )
    for statement in statements:
        connection.execute(statement)
    triggers = {
        "strix_runtime_authority_events_no_replace": "BEFORE INSERT ON strix_runtime_authority_events WHEN EXISTS(SELECT 1 FROM strix_runtime_authority_events WHERE authority_ref=NEW.authority_ref AND generation=NEW.generation OR authority_record_digest=NEW.authority_record_digest OR event_digest=NEW.event_digest) BEGIN SELECT RAISE(ABORT,'Strix authority events cannot be replaced'); END",
        "strix_runtime_authority_events_no_update": "BEFORE UPDATE ON strix_runtime_authority_events BEGIN SELECT RAISE(ABORT,'Strix authority events are immutable'); END",
        "strix_runtime_authority_events_no_delete": "BEFORE DELETE ON strix_runtime_authority_events BEGIN SELECT RAISE(ABORT,'Strix authority events are append-only'); END",
        "strix_runtime_authority_heads_no_replace": "BEFORE INSERT ON strix_runtime_authority_heads WHEN EXISTS(SELECT 1 FROM strix_runtime_authority_heads WHERE authority_ref=NEW.authority_ref) BEGIN SELECT RAISE(ABORT,'Strix authority heads cannot be replaced'); END",
        "strix_runtime_authority_heads_valid_update": "BEFORE UPDATE ON strix_runtime_authority_heads WHEN NEW.authority_ref IS NOT OLD.authority_ref OR NEW.active_generation != OLD.active_generation + 1 OR NOT EXISTS(SELECT 1 FROM strix_runtime_authority_events e WHERE e.authority_ref=OLD.authority_ref AND e.generation=NEW.active_generation AND e.authority_record_digest=NEW.active_record_digest AND e.event_digest=NEW.active_event_digest AND e.authority_basis_ref=NEW.authority_basis_ref AND e.previous_event_digest=OLD.active_event_digest) BEGIN SELECT RAISE(ABORT,'invalid Strix authority head transition'); END",
        "strix_runtime_authority_heads_no_delete": "BEFORE DELETE ON strix_runtime_authority_heads BEGIN SELECT RAISE(ABORT,'Strix authority heads cannot be deleted'); END",
        "strix_runtime_admission_reservations_no_replace": "BEFORE INSERT ON strix_runtime_admission_reservations WHEN EXISTS(SELECT 1 FROM strix_runtime_admission_reservations WHERE attempt_id=NEW.attempt_id OR binding_digest=NEW.binding_digest OR reservation_digest=NEW.reservation_digest OR reservation_ref=NEW.reservation_ref) BEGIN SELECT RAISE(ABORT,'Strix admission reservations cannot be replaced'); END",
        "strix_runtime_admission_reservations_no_update": "BEFORE UPDATE ON strix_runtime_admission_reservations BEGIN SELECT RAISE(ABORT,'Strix admission reservations are immutable'); END",
        "strix_runtime_admission_reservations_no_delete": "BEFORE DELETE ON strix_runtime_admission_reservations BEGIN SELECT RAISE(ABORT,'Strix admission reservations are append-only'); END",
        "strix_runtime_admissions_no_replace": "BEFORE INSERT ON strix_runtime_admissions WHEN EXISTS(SELECT 1 FROM strix_runtime_admissions WHERE attempt_id=NEW.attempt_id OR admission_record_ref=NEW.admission_record_ref OR admission_record_digest=NEW.admission_record_digest OR custody_record_ref=NEW.custody_record_ref OR workspace_ref=NEW.workspace_ref OR control_root_ref=NEW.control_root_ref OR artifact_root_ref=NEW.artifact_root_ref OR network_plan_ref=NEW.network_plan_ref OR network_snapshot_ref=NEW.network_snapshot_ref OR network_verification_ref=NEW.network_verification_ref OR custody_plan_ref=NEW.custody_plan_ref OR protected_roots_ref=NEW.protected_roots_ref OR containment_ref=NEW.containment_ref) BEGIN SELECT RAISE(ABORT,'Strix admissions cannot be replaced or share attempt custody'); END",
        "strix_runtime_admissions_no_update": "BEFORE UPDATE ON strix_runtime_admissions BEGIN SELECT RAISE(ABORT,'Strix admissions are immutable'); END",
        "strix_runtime_admissions_no_delete": "BEFORE DELETE ON strix_runtime_admissions BEGIN SELECT RAISE(ABORT,'Strix admissions are append-only'); END",
        "strix_runtime_admission_events_no_replace": "BEFORE INSERT ON strix_runtime_admission_events WHEN EXISTS(SELECT 1 FROM strix_runtime_admission_events WHERE attempt_id=NEW.attempt_id AND sequence=NEW.sequence OR event_digest=NEW.event_digest) BEGIN SELECT RAISE(ABORT,'Strix admission events cannot be replaced'); END",
        "strix_runtime_admission_events_no_update": "BEFORE UPDATE ON strix_runtime_admission_events BEGIN SELECT RAISE(ABORT,'Strix admission events are immutable'); END",
        "strix_runtime_admission_events_no_delete": "BEFORE DELETE ON strix_runtime_admission_events BEGIN SELECT RAISE(ABORT,'Strix admission events are append-only'); END",
        "strix_runtime_admission_heads_no_replace": "BEFORE INSERT ON strix_runtime_admission_heads WHEN EXISTS(SELECT 1 FROM strix_runtime_admission_heads WHERE attempt_id=NEW.attempt_id) BEGIN SELECT RAISE(ABORT,'Strix admission heads cannot be replaced'); END",
        "strix_runtime_admission_heads_valid_update": "BEFORE UPDATE ON strix_runtime_admission_heads WHEN NEW.attempt_id IS NOT OLD.attempt_id OR NEW.active_sequence != OLD.active_sequence + 1 OR NOT EXISTS(SELECT 1 FROM strix_runtime_admission_events e WHERE e.attempt_id=OLD.attempt_id AND e.sequence=NEW.active_sequence AND e.state=NEW.active_state AND e.event_digest=NEW.active_event_digest AND e.admission_record_ref IS NEW.admission_record_ref AND e.previous_event_digest=OLD.active_event_digest) BEGIN SELECT RAISE(ABORT,'invalid Strix admission head transition'); END",
        "strix_runtime_admission_heads_no_delete": "BEFORE DELETE ON strix_runtime_admission_heads BEGIN SELECT RAISE(ABORT,'Strix admission heads cannot be deleted'); END",
    }
    for name, body in triggers.items():
        connection.execute(f"CREATE TRIGGER IF NOT EXISTS {name} {body}")


def _canonical_row(row: sqlite3.Row, *, field: str = "document_json") -> dict[str, Any]:
    try:
        document = json.loads(row[field])
    except (TypeError, ValueError, RecursionError) as exc:
        raise ProductStoreError("private Strix runtime record is not valid JSON") from exc
    if not isinstance(document, dict) or canonical_json(document) != row[field]:
        raise ProductStoreError("private Strix runtime record is not canonical")
    return document


def _read_authority_chain(
    connection: sqlite3.Connection, authority_ref: str
) -> list[dict[str, Any]]:
    _digest(authority_ref, "Strix authority ref")
    rows = connection.execute(
        "SELECT * FROM strix_runtime_authority_events WHERE authority_ref=? ORDER BY generation",
        (authority_ref,),
    ).fetchall()
    previous: dict[str, Any] | None = None
    result: list[dict[str, Any]] = []
    for expected_generation, raw in enumerate(rows, 1):
        document = _canonical_row(raw)
        authority = _authority(document.get("authority", {}))
        expected = _authority_event_document(
            authority_ref=authority_ref,
            authority=authority,
            authority_basis_ref=cast(str, document.get("authority_basis_ref")),
            previous_event_digest=document.get("previous_event_digest"),
        )
        if (
            document != expected
            or authority["generation"] != expected_generation
            or raw["generation"] != expected_generation
            or raw["authority_record_digest"] != document["authority_record_digest"]
            or raw["event_digest"] != content_hash(document)
            or raw["authority_basis_ref"] != document["authority_basis_ref"]
            or raw["previous_event_digest"] != document["previous_event_digest"]
            or raw["recorded_at"] != authority["recorded_at"]
        ):
            raise ProductStoreError("Strix runtime authority chain integrity check failed")
        if previous is None:
            if document["previous_event_digest"] is not None:
                raise ProductStoreError("Strix authority initial predecessor is invalid")
        else:
            prior_authority = previous["document"]["authority"]
            if (
                document["previous_event_digest"] != previous["event_digest"]
                or authority["state"] == prior_authority["state"]
                or document["authority_basis_ref"] == previous["document"]["authority_basis_ref"]
                or parse_iso8601_datetime(authority["recorded_at"])
                <= parse_iso8601_datetime(prior_authority["recorded_at"])
            ):
                raise ProductStoreError("Strix runtime authority transition is invalid")
            if authority["state"] == "revoked" and any(
                authority[name] != prior_authority[name]
                for name in (
                    "qualification_manifest_ref",
                    "protected_artifact_key",
                    "installed_bluefire_revision",
                    "strix_build_digest",
                    "threat_review_ref",
                )
            ):
                raise ProductStoreError("Strix runtime revocation changed candidate anchors")
        current = {
            "authority": authority,
            "authority_record_digest": raw["authority_record_digest"],
            "event_digest": raw["event_digest"],
            "authority_basis_ref": raw["authority_basis_ref"],
            "document": document,
        }
        result.append(current)
        previous = current
    head = connection.execute(
        "SELECT * FROM strix_runtime_authority_heads WHERE authority_ref=?", (authority_ref,)
    ).fetchone()
    if not result:
        if head is not None:
            raise ProductStoreError("Strix runtime authority head has no history")
    elif (
        head is None
        or head["active_generation"] != result[-1]["authority"]["generation"]
        or head["active_record_digest"] != result[-1]["authority_record_digest"]
        or head["active_event_digest"] != result[-1]["event_digest"]
        or head["authority_basis_ref"] != result[-1]["authority_basis_ref"]
    ):
        raise ProductStoreError("Strix runtime authority head integrity check failed")
    return result


def _read_reservation(connection: sqlite3.Connection, attempt_id: str) -> dict[str, Any] | None:
    row = connection.execute(
        "SELECT * FROM strix_runtime_admission_reservations WHERE attempt_id=?", (attempt_id,)
    ).fetchone()
    if row is None:
        return None
    document = _reservation(_canonical_row(row))
    reservation_digest = content_hash(document)
    reservation_ref = content_hash(
        {
            "schema_version": "bluefire.strix-runtime-admission-reservation-ref.v1",
            "attempt_id": attempt_id,
            "reservation_digest": reservation_digest,
        }
    )
    if (
        row["reservation_digest"] != reservation_digest
        or row["reservation_ref"] != reservation_ref
        or any(
            row[name] != document[name]
            for name in (
                "attempt_id",
                "experiment_id",
                "experiment_revision",
                "experiment_digest",
                "authority_ref",
                "authority_generation",
                "authority_record_digest",
                "binding_digest",
                "delegation_digest",
                "created_at",
                "expires_at",
            )
        )
        or row["runtime_qualification_ref"] != document["qualification_ref"]
    ):
        raise ProductStoreError("Strix admission reservation integrity check failed")
    chain = _read_authority_chain(connection, document["authority_ref"])
    generation = document["authority_generation"]
    if generation > len(chain):
        raise ProductStoreError("Strix admission reservation authority is missing")
    admitted = chain[generation - 1]
    if (
        admitted["authority_record_digest"] != document["authority_record_digest"]
        or admitted["authority"]["state"] != "active"
        or admitted["authority"]["qualification_manifest_ref"] != document["qualification_ref"]
        or parse_iso8601_datetime(admitted["authority"]["recorded_at"])
        > parse_iso8601_datetime(document["created_at"])
    ):
        raise ProductStoreError("Strix admission reservation authority provenance changed")
    return {
        "document": document,
        "reservation_digest": reservation_digest,
        "reservation_ref": reservation_ref,
    }


def _read_admission(connection: sqlite3.Connection, attempt_id: str) -> dict[str, Any] | None:
    row = connection.execute(
        "SELECT * FROM strix_runtime_admissions WHERE attempt_id=?", (attempt_id,)
    ).fetchone()
    if row is None:
        return None
    document = _admission(_canonical_row(row))
    digest = content_hash(document)
    reference = content_hash(
        {
            "schema_version": "bluefire.strix-runtime-admission-record-ref.v1",
            "attempt_id": attempt_id,
            "admission_record_digest": digest,
        }
    )
    if (
        document["attempt_id"] != attempt_id
        or row["admission_record_digest"] != digest
        or row["admission_record_ref"] != reference
        or row["custody_source_ref"] != document["custody_source_ref"]
        or row["custody_record_ref"] != document["custody_record_ref"]
        or row["custody_record_digest"] != document["custody_record_digest"]
        or any(
            row[name] != document[name]
            for name in (
                "workspace_ref",
                "control_root_ref",
                "artifact_root_ref",
                "network_plan_ref",
                "network_snapshot_ref",
                "network_verification_ref",
                "custody_plan_ref",
                "protected_roots_ref",
                "containment_ref",
            )
        )
        or row["admission_proof_bundle_digest"] != document["admission_proof_bundle_digest"]
        or row["created_at"] != document["created_at"]
        or row["expires_at"] != document["expires_at"]
    ):
        raise ProductStoreError("Strix admission record integrity check failed")
    return {
        "document": document,
        "admission_record_digest": digest,
        "admission_record_ref": reference,
    }


def _read_admission_chain(connection: sqlite3.Connection, attempt_id: str) -> list[dict[str, Any]]:
    rows = connection.execute(
        "SELECT * FROM strix_runtime_admission_events WHERE attempt_id=? ORDER BY sequence",
        (attempt_id,),
    ).fetchall()
    previous: dict[str, Any] | None = None
    result: list[dict[str, Any]] = []
    for expected_sequence, row in enumerate(rows, 1):
        document = _canonical_row(row)
        expected = _event_document(
            attempt_id=attempt_id,
            sequence=expected_sequence,
            state=cast(str, document.get("state")),
            lifecycle_basis_ref=cast(str, document.get("lifecycle_basis_ref")),
            recorded_at=cast(str, document.get("recorded_at")),
            previous_event_digest=document.get("previous_event_digest"),
            admission_record_ref=document.get("admission_record_ref"),
        )
        event_digest = content_hash(document)
        if (
            document != expected
            or row["sequence"] != expected_sequence
            or row["state"] != document["state"]
            or row["event_digest"] != event_digest
            or row["previous_event_digest"] != document["previous_event_digest"]
            or row["admission_record_ref"] != document["admission_record_ref"]
            or row["lifecycle_basis_ref"] != document["lifecycle_basis_ref"]
            or row["recorded_at"] != document["recorded_at"]
        ):
            raise ProductStoreError("Strix admission lifecycle integrity check failed")
        if previous is None:
            if document["state"] != "reserved" or document["previous_event_digest"] is not None:
                raise ProductStoreError("Strix admission initial lifecycle event is invalid")
        elif (
            document["previous_event_digest"] != previous["event_digest"]
            or (
                document["state"] not in _ADMISSION_TRANSITIONS[previous["document"]["state"]]
                and not (
                    previous["document"]["state"] == "preparing"
                    and _issuer_preparing_event(connection, document, event_digest)
                )
            )
            or parse_iso8601_datetime(document["recorded_at"])
            < parse_iso8601_datetime(previous["document"]["recorded_at"])
        ):
            raise ProductStoreError("Strix admission lifecycle transition is invalid")
        reference = document["admission_record_ref"]
        prior_reference = None if previous is None else previous["document"]["admission_record_ref"]
        if document["state"] == "verified" and reference is None:
            raise ProductStoreError("verified Strix admission lifecycle lacks its record")
        if prior_reference is not None and reference != prior_reference:
            raise ProductStoreError("Strix admission lifecycle changed its retained record")
        if reference is not None:
            owner = connection.execute(
                "SELECT attempt_id FROM strix_runtime_admissions WHERE admission_record_ref=?",
                (reference,),
            ).fetchone()
            if owner is None or owner["attempt_id"] != attempt_id:
                raise ProductStoreError("Strix admission lifecycle record ownership changed")
        current = {"document": document, "event_digest": event_digest}
        result.append(current)
        previous = current
    head = connection.execute(
        "SELECT * FROM strix_runtime_admission_heads WHERE attempt_id=?", (attempt_id,)
    ).fetchone()
    if not result:
        if head is not None:
            raise ProductStoreError("Strix admission lifecycle head has no history")
    elif (
        head is None
        or head["active_sequence"] != len(result)
        or head["active_state"] != result[-1]["document"]["state"]
        or head["active_event_digest"] != result[-1]["event_digest"]
        or head["admission_record_ref"] != result[-1]["document"]["admission_record_ref"]
    ):
        raise ProductStoreError("Strix admission lifecycle head integrity check failed")
    return result


class StrixRuntimeStoreMixin:
    """Controller-private exact reads and append-only writes."""

    def _append_strix_runtime_authority(
        self: StrixRuntimeStore,
        *,
        authority_ref: str,
        authority: Mapping[str, Any],
        authority_basis_ref: str,
        expected_previous_event_digest: str | None,
    ) -> Mapping[str, Any]:
        checked = _authority(authority)
        with self._connection(write=True) as connection:
            chain = _read_authority_chain(connection, authority_ref)
            if checked["generation"] <= len(chain):
                existing = chain[checked["generation"] - 1]
                expected = _authority_event_document(
                    authority_ref=authority_ref,
                    authority=checked,
                    authority_basis_ref=authority_basis_ref,
                    previous_event_digest=expected_previous_event_digest,
                )
                if existing["document"] == expected:
                    return cast(Mapping[str, Any], existing)
                raise ResourceConflictError("Strix runtime authority event conflicts")
            previous = chain[-1] if chain else None
            if (previous is None) != (expected_previous_event_digest is None) or (
                previous is not None and previous["event_digest"] != expected_previous_event_digest
            ):
                raise ResourceConflictError("Strix runtime authority head changed")
            if checked["generation"] != len(chain) + 1:
                raise ResourceConflictError("Strix runtime authority generation changed")
            document = _authority_event_document(
                authority_ref=authority_ref,
                authority=checked,
                authority_basis_ref=authority_basis_ref,
                previous_event_digest=expected_previous_event_digest,
            )
            if previous is not None:
                prior = previous["authority"]
                if checked["state"] == prior["state"]:
                    raise ResourceConflictError("Strix runtime authority transition is invalid")
                if authority_basis_ref == previous["authority_basis_ref"]:
                    raise ResourceConflictError("Strix runtime authority requires a fresh basis")
                if checked["state"] == "revoked" and any(
                    checked[name] != prior[name]
                    for name in (
                        "qualification_manifest_ref",
                        "protected_artifact_key",
                        "installed_bluefire_revision",
                        "strix_build_digest",
                        "threat_review_ref",
                    )
                ):
                    raise ResourceConflictError(
                        "Strix runtime revocation changed candidate anchors"
                    )
            record_digest = document["authority_record_digest"]
            event_digest = content_hash(document)
            connection.execute(
                """INSERT INTO strix_runtime_authority_events VALUES(?,?,?,?,?,?,?,?)""",
                (
                    authority_ref,
                    checked["generation"],
                    canonical_json(document),
                    record_digest,
                    event_digest,
                    authority_basis_ref,
                    expected_previous_event_digest,
                    checked["recorded_at"],
                ),
            )
            if previous is None:
                connection.execute(
                    "INSERT INTO strix_runtime_authority_heads VALUES(?,?,?,?,?)",
                    (
                        authority_ref,
                        checked["generation"],
                        record_digest,
                        event_digest,
                        authority_basis_ref,
                    ),
                )
            else:
                updated = connection.execute(
                    """UPDATE strix_runtime_authority_heads SET active_generation=?,
                    active_record_digest=?,active_event_digest=?,authority_basis_ref=?
                    WHERE authority_ref=? AND active_generation=? AND active_event_digest=?""",
                    (
                        checked["generation"],
                        record_digest,
                        event_digest,
                        authority_basis_ref,
                        authority_ref,
                        previous["authority"]["generation"],
                        previous["event_digest"],
                    ),
                )
                if updated.rowcount != 1:
                    raise ResourceConflictError("Strix runtime authority head changed")
            return cast(Mapping[str, Any], _read_authority_chain(connection, authority_ref)[-1])

    def _read_current_strix_runtime_authority(
        self: StrixRuntimeStore, authority_ref: str
    ) -> Mapping[str, Any] | None:
        with self._connection() as connection:
            chain = _read_authority_chain(connection, authority_ref)
            return None if not chain else chain[-1]

    def _read_strix_runtime_authority_event(
        self: StrixRuntimeStore, authority_ref: str, generation: int, record_digest: str
    ) -> Mapping[str, Any] | None:
        _positive_int(generation, "Strix authority generation", maximum=MAX_AUTHORITY_EVENTS)
        _digest(record_digest, "Strix authority record digest")
        with self._connection() as connection:
            chain = _read_authority_chain(connection, authority_ref)
            if generation > len(chain):
                return None
            record = chain[generation - 1]
            return record if record["authority_record_digest"] == record_digest else None

    def _is_strix_runtime_authority_descendant(
        self: StrixRuntimeStore,
        *,
        authority_ref: str,
        ancestor_generation: int,
        ancestor_record_digest: str,
        descendant_generation: int,
        descendant_record_digest: str,
    ) -> bool:
        _positive_int(
            ancestor_generation, "ancestor Strix authority generation", maximum=MAX_AUTHORITY_EVENTS
        )
        _positive_int(
            descendant_generation,
            "descendant Strix authority generation",
            maximum=MAX_AUTHORITY_EVENTS,
        )
        _digest(ancestor_record_digest, "ancestor Strix authority digest")
        _digest(descendant_record_digest, "descendant Strix authority digest")
        with self._connection() as connection:
            chain = _read_authority_chain(connection, authority_ref)
            if ancestor_generation > descendant_generation or descendant_generation > len(chain):
                return False
            return bool(
                chain[ancestor_generation - 1]["authority_record_digest"] == ancestor_record_digest
                and chain[descendant_generation - 1]["authority_record_digest"]
                == descendant_record_digest
            )

    def _reserve_strix_runtime_admission(
        self: StrixRuntimeStore, document: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        checked = _reservation(document)
        with self._connection(write=True) as connection:
            _refuse_issuer_owned(connection, checked["attempt_id"])
            return _reserve_strix_runtime_admission_at(connection, checked)

    def _append_strix_runtime_admission_event(
        self: StrixRuntimeStore,
        *,
        attempt_id: str,
        state: str,
        lifecycle_basis_ref: str,
        recorded_at: str,
        expected_head_digest: str,
    ) -> Mapping[str, Any]:
        with self._connection(write=True) as connection:
            _refuse_issuer_owned(connection, attempt_id)
            _append_strix_runtime_admission_event_at(
                connection,
                attempt_id=attempt_id,
                state=state,
                lifecycle_basis_ref=lifecycle_basis_ref,
                recorded_at=recorded_at,
                expected_head_digest=expected_head_digest,
            )
            return cast(Mapping[str, Any], _read_admission_chain(connection, attempt_id)[-1])

    def _retain_verified_strix_runtime_admission(
        self: StrixRuntimeStore,
        *,
        document: Mapping[str, Any],
        lifecycle_basis_ref: str,
        recorded_at: str,
        expected_head_digest: str,
    ) -> Mapping[str, Any]:
        checked = _admission(document)
        with self._connection(write=True) as connection:
            _refuse_issuer_owned(connection, checked["attempt_id"])
            return _retain_verified_strix_runtime_admission_at(
                connection,
                document=checked,
                lifecycle_basis_ref=lifecycle_basis_ref,
                recorded_at=recorded_at,
                expected_head_digest=expected_head_digest,
            )

    def _read_strix_runtime_admission_envelope(
        self: StrixRuntimeStore, attempt_id: str
    ) -> Mapping[str, Any] | None:
        if not isinstance(attempt_id, str) or _ATTEMPT.fullmatch(attempt_id) is None:
            raise ProductStoreError("Strix admission attempt is invalid")
        with self._connection() as connection:
            if not connection.in_transaction:
                connection.execute("BEGIN")
            if _read_reservation(connection, attempt_id) is None:
                return None
            if _issuer_owned(connection, attempt_id):
                from .product_store_strix_admission_issuer import _read_at

                _read_at(connection, attempt_id)
            return _read_strix_runtime_admission_state(connection, attempt_id)


def _read_strix_runtime_admission_state(
    connection: sqlite3.Connection, attempt_id: str
) -> dict[str, Any]:
    reservation = _read_reservation(connection, attempt_id)
    if reservation is None:
        raise ProductStoreError("Strix admission reservation not found")
    chain = _read_admission_chain(connection, attempt_id)
    admission = _read_admission(connection, attempt_id)
    final_reference = chain[-1]["document"]["admission_record_ref"]
    if (admission is None and final_reference is not None) or (
        admission is not None and admission["admission_record_ref"] != final_reference
    ):
        raise ProductStoreError("Strix admission lifecycle and record differ")
    if admission is not None:
        document = admission["document"]
        reserved = reservation["document"]
        for name in (
            "attempt_id",
            "experiment_id",
            "experiment_revision",
            "experiment_digest",
            "binding_digest",
            "delegation_digest",
            "objective_ref",
            "environment_ref",
            "authority_ref",
            "authority_generation",
            "authority_record_digest",
            "target_snapshot_digest",
            "created_at",
            "expires_at",
        ):
            if document[name] != reserved[name]:
                raise ProductStoreError("Strix admission and reservation provenance differ")
        if document["qualification_ref"] != reserved["qualification_ref"]:
            raise ProductStoreError("Strix admission qualification provenance differs")
    return {
        "reservation": reservation,
        "admission": admission,
        "lifecycle_state": chain[-1]["document"]["state"],
        "lifecycle_head_digest": chain[-1]["event_digest"],
        "lifecycle_sequence": len(chain),
    }


def _reserve_strix_runtime_admission_at(
    connection: sqlite3.Connection, document: Mapping[str, Any]
) -> Mapping[str, Any]:
    checked = _reservation(document)
    attempt_id = checked["attempt_id"]
    if not connection.in_transaction:
        raise ProductStoreError("Strix admission write requires an owning transaction")
    existing = _read_reservation(connection, attempt_id)
    if existing is not None:
        if existing["document"] != checked:
            raise ResourceConflictError("Strix admission reservation conflicts")
        return existing
    experiment = connection.execute(
        """SELECT active_revision,active_digest FROM engine_experiment_heads
        WHERE experiment_id=?""",
        (checked["experiment_id"],),
    ).fetchone()
    if (
        experiment is None
        or experiment["active_revision"] != checked["experiment_revision"]
        or experiment["active_digest"] != checked["experiment_digest"]
    ):
        raise ResourceConflictError("Strix admission experiment head changed")
    authority = _read_authority_chain(connection, checked["authority_ref"])
    if not authority:
        raise ResourceConflictError("Strix runtime authority is missing")
    current = authority[-1]
    if (
        current["authority"]["state"] != "active"
        or current["authority"]["generation"] != checked["authority_generation"]
        or current["authority_record_digest"] != checked["authority_record_digest"]
        or current["authority"]["qualification_manifest_ref"] != checked["qualification_ref"]
        or parse_iso8601_datetime(current["authority"]["recorded_at"])
        > parse_iso8601_datetime(checked["created_at"])
    ):
        raise ResourceConflictError("Strix runtime authority changed before reservation")
    digest = content_hash(checked)
    reference = content_hash(
        {
            "schema_version": "bluefire.strix-runtime-admission-reservation-ref.v1",
            "attempt_id": attempt_id,
            "reservation_digest": digest,
        }
    )
    connection.execute(
        """INSERT INTO strix_runtime_admission_reservations VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            attempt_id,
            checked["experiment_id"],
            checked["experiment_revision"],
            checked["experiment_digest"],
            checked["authority_ref"],
            checked["authority_generation"],
            checked["authority_record_digest"],
            checked["binding_digest"],
            checked["delegation_digest"],
            checked["qualification_ref"],
            canonical_json(checked),
            digest,
            reference,
            checked["created_at"],
            checked["expires_at"],
        ),
    )
    event = _event_document(
        attempt_id=attempt_id,
        sequence=1,
        state="reserved",
        lifecycle_basis_ref=checked["request_digest"],
        recorded_at=checked["created_at"],
        previous_event_digest=None,
        admission_record_ref=None,
    )
    event_digest = content_hash(event)
    connection.execute(
        "INSERT INTO strix_runtime_admission_events VALUES(?,?,?,?,?,?,?,?,?)",
        (
            attempt_id,
            1,
            "reserved",
            canonical_json(event),
            event_digest,
            None,
            None,
            checked["request_digest"],
            checked["created_at"],
        ),
    )
    connection.execute(
        "INSERT INTO strix_runtime_admission_heads VALUES(?,?,?,?,NULL)",
        (attempt_id, 1, "reserved", event_digest),
    )
    return cast(Mapping[str, Any], _read_reservation(connection, attempt_id))


def _append_strix_runtime_admission_event_at(
    connection: sqlite3.Connection,
    *,
    attempt_id: str,
    state: str,
    lifecycle_basis_ref: str,
    recorded_at: str,
    expected_head_digest: str,
    issuer_evidence: bool = False,
) -> Mapping[str, Any]:
    checked_recorded_at = _timestamp(recorded_at, "Strix admission lifecycle time")
    if not connection.in_transaction:
        raise ProductStoreError("Strix admission write requires an owning transaction")
    reservation = _read_reservation(connection, attempt_id)
    if reservation is None:
        raise ProductStoreError("Strix admission reservation not found")
    if state == "verified":
        raise ProductStoreError("verified Strix lifecycle requires exact admission retention")
    chain = _read_admission_chain(connection, attempt_id)
    previous = chain[-1]
    checked_head = _digest(expected_head_digest, "Strix admission head")
    if (
        len(chain) >= 2
        and previous["document"]["state"] == state
        and previous["document"]["lifecycle_basis_ref"] == lifecycle_basis_ref
        and previous["document"]["recorded_at"] == checked_recorded_at
        and previous["document"]["previous_event_digest"] == checked_head
    ):
        return cast(Mapping[str, Any], previous)
    if previous["event_digest"] != checked_head:
        raise ResourceConflictError("Strix admission lifecycle head changed")
    if state == "preparing" and not (
        parse_iso8601_datetime(reservation["document"]["created_at"])
        <= parse_iso8601_datetime(checked_recorded_at)
        < parse_iso8601_datetime(reservation["document"]["expires_at"])
    ):
        raise ResourceConflictError("Strix admission preparation is outside its lifetime")
    if parse_iso8601_datetime(checked_recorded_at) < parse_iso8601_datetime(
        previous["document"]["recorded_at"]
    ):
        raise ResourceConflictError("Strix admission lifecycle time precedes its head")
    if state not in _ADMISSION_TRANSITIONS[previous["document"]["state"]] and not (
        issuer_evidence and state == previous["document"]["state"] == "preparing"
    ):
        raise ResourceConflictError("Strix admission lifecycle transition is invalid")
    admission = _read_admission(connection, attempt_id)
    reference = None if admission is None else admission["admission_record_ref"]
    if state == "verified" and admission is None:
        raise ResourceConflictError("Strix verified lifecycle requires an admission")
    document = _event_document(
        attempt_id=attempt_id,
        sequence=len(chain) + 1,
        state=state,
        lifecycle_basis_ref=lifecycle_basis_ref,
        recorded_at=checked_recorded_at,
        previous_event_digest=previous["event_digest"],
        admission_record_ref=reference,
    )
    digest = content_hash(document)
    connection.execute(
        "INSERT INTO strix_runtime_admission_events VALUES(?,?,?,?,?,?,?,?,?)",
        (
            attempt_id,
            document["sequence"],
            state,
            canonical_json(document),
            digest,
            previous["event_digest"],
            reference,
            lifecycle_basis_ref,
            checked_recorded_at,
        ),
    )
    updated = connection.execute(
        """UPDATE strix_runtime_admission_heads SET active_sequence=?,active_state=?,
        active_event_digest=?,admission_record_ref=? WHERE attempt_id=?
        AND active_sequence=? AND active_event_digest=?""",
        (
            document["sequence"],
            state,
            digest,
            reference,
            attempt_id,
            len(chain),
            previous["event_digest"],
        ),
    )
    if updated.rowcount != 1:
        raise ResourceConflictError("Strix admission lifecycle head changed")
    return {"document": document, "event_digest": digest}


def _retain_verified_strix_runtime_admission_at(
    connection: sqlite3.Connection,
    *,
    document: Mapping[str, Any],
    lifecycle_basis_ref: str,
    recorded_at: str,
    expected_head_digest: str,
) -> Mapping[str, Any]:
    checked = _admission(document)
    checked_recorded_at = _timestamp(recorded_at, "Strix admission verification time")
    attempt_id = checked["attempt_id"]
    if not connection.in_transaction:
        raise ProductStoreError("Strix admission write requires an owning transaction")
    reservation = _read_reservation(connection, attempt_id)
    if reservation is None:
        raise ProductStoreError("Strix admission reservation not found")
    for name in (
        "attempt_id",
        "experiment_id",
        "experiment_revision",
        "experiment_digest",
        "binding_digest",
        "delegation_digest",
        "objective_ref",
        "environment_ref",
        "authority_ref",
        "authority_generation",
        "authority_record_digest",
        "target_snapshot_digest",
        "created_at",
        "expires_at",
    ):
        if checked[name] != reservation["document"][name]:
            raise ResourceConflictError("Strix admission differs from its reservation")
    if checked["qualification_ref"] != reservation["document"]["qualification_ref"]:
        raise ResourceConflictError("Strix admission qualification changed")
    chain = _read_admission_chain(connection, attempt_id)
    previous = chain[-1]
    existing = _read_admission(connection, attempt_id)
    digest = content_hash(checked)
    reference = content_hash(
        {
            "schema_version": "bluefire.strix-runtime-admission-record-ref.v1",
            "attempt_id": attempt_id,
            "admission_record_digest": digest,
        }
    )
    if existing is not None and existing["document"] != checked:
        raise ResourceConflictError("Strix verified admission conflicts")
    checked_head = _digest(expected_head_digest, "Strix admission head")
    if (
        existing is not None
        and previous["document"]["state"] == "verified"
        and previous["document"]["admission_record_ref"] == reference
        and previous["document"]["previous_event_digest"] == checked_head
        and previous["document"]["lifecycle_basis_ref"] == lifecycle_basis_ref
        and previous["document"]["recorded_at"] == checked_recorded_at
    ):
        return cast(Mapping[str, Any], _read_strix_runtime_admission_state(connection, attempt_id))
    if not (
        parse_iso8601_datetime(reservation["document"]["created_at"])
        <= parse_iso8601_datetime(checked_recorded_at)
        < parse_iso8601_datetime(reservation["document"]["expires_at"])
    ):
        raise ResourceConflictError("Strix admission verification is outside its lifetime")
    authority = _read_authority_chain(connection, checked["authority_ref"])
    current = authority[-1] if authority else None
    if (
        current is None
        or current["authority"]["state"] != "active"
        or current["authority"]["generation"] != checked["authority_generation"]
        or current["authority_record_digest"] != checked["authority_record_digest"]
    ):
        raise ResourceConflictError("Strix runtime authority changed before admission")
    if current["authority"]["strix_build_digest"] != checked["build_digest"]:
        raise ResourceConflictError("Strix admission build differs from runtime authority")
    if previous["event_digest"] != checked_head:
        raise ResourceConflictError("Strix admission lifecycle head changed")
    if existing is None:
        connection.execute(
            "INSERT INTO strix_runtime_admissions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                attempt_id,
                canonical_json(checked),
                reference,
                digest,
                checked["custody_source_ref"],
                checked["custody_record_ref"],
                checked["custody_record_digest"],
                checked["workspace_ref"],
                checked["control_root_ref"],
                checked["artifact_root_ref"],
                checked["network_plan_ref"],
                checked["network_snapshot_ref"],
                checked["network_verification_ref"],
                checked["custody_plan_ref"],
                checked["protected_roots_ref"],
                checked["containment_ref"],
                checked["admission_proof_bundle_digest"],
                checked["created_at"],
                checked["expires_at"],
            ),
        )
    if "verified" not in _ADMISSION_TRANSITIONS[previous["document"]["state"]]:
        raise ResourceConflictError("Strix admission cannot become verified")
    event = _event_document(
        attempt_id=attempt_id,
        sequence=len(chain) + 1,
        state="verified",
        lifecycle_basis_ref=lifecycle_basis_ref,
        recorded_at=checked_recorded_at,
        previous_event_digest=previous["event_digest"],
        admission_record_ref=reference,
    )
    event_digest = content_hash(event)
    connection.execute(
        "INSERT INTO strix_runtime_admission_events VALUES(?,?,?,?,?,?,?,?,?)",
        (
            attempt_id,
            event["sequence"],
            "verified",
            canonical_json(event),
            event_digest,
            previous["event_digest"],
            reference,
            lifecycle_basis_ref,
            checked_recorded_at,
        ),
    )
    updated = connection.execute(
        """UPDATE strix_runtime_admission_heads SET active_sequence=?,active_state='verified',
        active_event_digest=?,admission_record_ref=? WHERE attempt_id=?
        AND active_sequence=? AND active_event_digest=?""",
        (
            event["sequence"],
            event_digest,
            reference,
            attempt_id,
            len(chain),
            previous["event_digest"],
        ),
    )
    if updated.rowcount != 1:
        raise ResourceConflictError("Strix admission lifecycle head changed")
    return cast(Mapping[str, Any], _read_strix_runtime_admission_state(connection, attempt_id))


def _issuer_owned(connection: sqlite3.Connection, attempt_id: Any) -> bool:
    if (
        connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='strix_runtime_issuance_records'"
        ).fetchone()
        is None
    ):
        return False
    return (
        connection.execute(
            "SELECT 1 FROM strix_runtime_issuance_records WHERE attempt_id=? LIMIT 1", (attempt_id,)
        ).fetchone()
        is not None
    )


def _refuse_issuer_owned(connection: sqlite3.Connection, attempt_id: Any) -> None:
    if _issuer_owned(connection, attempt_id):
        raise ResourceConflictError(
            "Strix issuer-owned lifecycle requires atomic issuance persistence"
        )


def _issuer_preparing_event(
    connection: sqlite3.Connection, document: Mapping[str, Any], event_digest: str
) -> bool:
    if document["state"] != "preparing" or not _issuer_owned(connection, document["attempt_id"]):
        return False
    return (
        connection.execute(
            "SELECT 1 FROM strix_runtime_issuance_records WHERE attempt_id=? AND sequence=? AND record_digest=? AND runtime_event_digest=?",
            (
                document["attempt_id"],
                document["sequence"],
                document["lifecycle_basis_ref"],
                event_digest,
            ),
        ).fetchone()
        is not None
    )
