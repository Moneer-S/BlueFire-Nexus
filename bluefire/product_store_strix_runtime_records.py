"""SQL records and validators for private v20 Strix runtime persistence.

The tables in this module are controller-only.  They are deliberately absent
from generic resources, HTTP routes, exports, and presentation projections.
They retain authority and custody provenance; they never allocate a runtime,
resolve an opaque location, acquire credentials, or launch work.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Mapping
from typing import Any, cast

from .product_store_errors import ProductStoreError, ResourceConflictError
from .product_store_serialization import canonical_json
from .product_store_strix_runtime_contracts import (
    _ADMISSION_DIGEST_FIELDS as _ADMISSION_DIGEST_FIELDS,
)
from .product_store_strix_runtime_contracts import (
    _ADMISSION_FIELDS as _ADMISSION_FIELDS,
)
from .product_store_strix_runtime_contracts import (
    _ADMISSION_STATES as _ADMISSION_STATES,
)
from .product_store_strix_runtime_contracts import (
    _ADMISSION_TRANSITIONS as _ADMISSION_TRANSITIONS,
)
from .product_store_strix_runtime_contracts import (
    _ARTIFACT_KEY as _ARTIFACT_KEY,
)
from .product_store_strix_runtime_contracts import (
    _ATTEMPT as _ATTEMPT,
)
from .product_store_strix_runtime_contracts import (
    _AUTHORITY_FIELDS as _AUTHORITY_FIELDS,
)
from .product_store_strix_runtime_contracts import (
    _AUTHORITY_STATES as _AUTHORITY_STATES,
)
from .product_store_strix_runtime_contracts import (
    _DIGEST as _DIGEST,
)
from .product_store_strix_runtime_contracts import (
    _EXPERIMENT as _EXPERIMENT,
)
from .product_store_strix_runtime_contracts import (
    _OPAQUE_DIGEST_FIELDS as _OPAQUE_DIGEST_FIELDS,
)
from .product_store_strix_runtime_contracts import (
    _RESERVATION_FIELDS as _RESERVATION_FIELDS,
)
from .product_store_strix_runtime_contracts import (
    _REVISION as _REVISION,
)
from .product_store_strix_runtime_contracts import (
    ADMISSION_EVENT_SCHEMA as ADMISSION_EVENT_SCHEMA,
)
from .product_store_strix_runtime_contracts import (
    ADMISSION_RECORD_SCHEMA as ADMISSION_RECORD_SCHEMA,
)
from .product_store_strix_runtime_contracts import (
    ADMISSION_RESERVATION_SCHEMA as ADMISSION_RESERVATION_SCHEMA,
)
from .product_store_strix_runtime_contracts import (
    AUTHORITY_EVENT_SCHEMA as AUTHORITY_EVENT_SCHEMA,
)
from .product_store_strix_runtime_contracts import (
    MAX_ADMISSION_EVENTS as MAX_ADMISSION_EVENTS,
)
from .product_store_strix_runtime_contracts import (
    MAX_AUTHORITY_EVENTS as MAX_AUTHORITY_EVENTS,
)
from .product_store_strix_runtime_contracts import (
    MAX_DOCUMENT_BYTES as MAX_DOCUMENT_BYTES,
)
from .product_store_strix_runtime_contracts import (
    StrixRuntimeStore as StrixRuntimeStore,
)
from .product_store_strix_runtime_contracts import (
    _admission as _admission,
)
from .product_store_strix_runtime_contracts import (
    _authority as _authority,
)
from .product_store_strix_runtime_contracts import (
    _authority_event_document as _authority_event_document,
)
from .product_store_strix_runtime_contracts import (
    _bounded_document as _bounded_document,
)
from .product_store_strix_runtime_contracts import (
    _digest as _digest,
)
from .product_store_strix_runtime_contracts import (
    _event_document as _event_document,
)
from .product_store_strix_runtime_contracts import (
    _positive_int as _positive_int,
)
from .product_store_strix_runtime_contracts import (
    _reservation as _reservation,
)
from .product_store_strix_runtime_contracts import (
    _timestamp as _timestamp,
)
from .util import content_hash, parse_iso8601_datetime


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
