"""Capability schema and ProductStore facades over append-only records."""

from __future__ import annotations

import re
import sqlite3
from typing import Any, Mapping, cast

from . import product_store_capability_cleanup as cleanup
from . import product_store_capability_dependencies as dependencies
from . import product_store_capability_grants as capability_grant_store
from .capability_packs import FILE_ACCESS_PACK, MACOS_FILE_ACCESS_PACK, grant_pack, review_pack
from .capability_resources import CapabilityContractError, digest, identifier
from .product_store_contracts import safe_document
from .product_store_errors import ProductStoreError
from .product_store_serialization import canonical_json, utc_now
from .retained_artifact_contract import source_reference
from .util import content_hash

_TABLES = {
    "capability_file_access_bindings": "attempt_id TEXT PRIMARY KEY REFERENCES capability_attempts(attempt_id), document_json TEXT NOT NULL, document_digest TEXT NOT NULL",
    "capability_file_access_terminals": "task_id TEXT PRIMARY KEY REFERENCES capability_task_claims(task_id), document_json TEXT NOT NULL, document_digest TEXT NOT NULL",
    "capability_lineages": "lineage_id TEXT PRIMARY KEY, binding_digest TEXT NOT NULL UNIQUE, document_json TEXT NOT NULL, document_digest TEXT NOT NULL",
    "capability_grants": "grant_id TEXT PRIMARY KEY, lineage_id TEXT NOT NULL REFERENCES capability_lineages(lineage_id), control_owner_id TEXT NOT NULL, document_json TEXT NOT NULL, document_digest TEXT NOT NULL, created_at_ms INTEGER NOT NULL, expires_at_ms INTEGER NOT NULL",
    "capability_grant_events": "sequence INTEGER PRIMARY KEY AUTOINCREMENT, grant_id TEXT NOT NULL REFERENCES capability_grants(grant_id), status TEXT NOT NULL CHECK(status IN ('active','paused','revoked','interrupted','completed')), at_ms INTEGER NOT NULL",
    "capability_attempts": "attempt_id TEXT PRIMARY KEY, grant_id TEXT NOT NULL REFERENCES capability_grants(grant_id), lineage_id TEXT NOT NULL REFERENCES capability_lineages(lineage_id), control_owner_id TEXT NOT NULL, endpoint_digest TEXT NOT NULL, job_id TEXT NOT NULL UNIQUE, run_id TEXT NOT NULL UNIQUE, document_json TEXT NOT NULL, document_digest TEXT NOT NULL, compiled_json TEXT NOT NULL, compiled_digest TEXT NOT NULL, created_at_ms INTEGER NOT NULL",
    "capability_control_usages": "attempt_id TEXT PRIMARY KEY REFERENCES capability_attempts(attempt_id), control_owner_id TEXT NOT NULL, document_json TEXT NOT NULL, document_digest TEXT NOT NULL",
    "capability_attempt_claims": "attempt_id TEXT PRIMARY KEY REFERENCES capability_attempts(attempt_id), document_json TEXT NOT NULL, document_digest TEXT NOT NULL, claimed_at_ms INTEGER NOT NULL",
    "capability_preparation_starts": "attempt_id TEXT PRIMARY KEY REFERENCES capability_attempts(attempt_id), started_at_ms INTEGER NOT NULL",
    "capability_receiver_bindings": "attempt_id TEXT PRIMARY KEY REFERENCES capability_attempts(attempt_id), document_json TEXT NOT NULL, document_digest TEXT NOT NULL",
    "capability_task_claims": "task_id TEXT PRIMARY KEY, attempt_id TEXT NOT NULL REFERENCES capability_attempts(attempt_id), step_id TEXT NOT NULL, request_hash TEXT NOT NULL, claimed_at_ms INTEGER NOT NULL, UNIQUE(attempt_id,step_id)",
    "capability_task_payloads": "task_id TEXT PRIMARY KEY REFERENCES capability_task_claims(task_id), payload_json TEXT NOT NULL, payload_digest TEXT NOT NULL",
    "capability_task_dispatch_intents": "task_id TEXT PRIMARY KEY REFERENCES capability_task_claims(task_id), document_json TEXT NOT NULL, document_digest TEXT NOT NULL",
    "capability_task_terminals": "task_id TEXT PRIMARY KEY REFERENCES capability_task_claims(task_id), document_json TEXT NOT NULL, document_digest TEXT NOT NULL",
    "capability_attempt_settlements": "attempt_id TEXT PRIMARY KEY REFERENCES capability_attempts(attempt_id), document_json TEXT NOT NULL, document_digest TEXT NOT NULL",
    "capability_retained_capture_intents": "attempt_id TEXT PRIMARY KEY REFERENCES capability_attempts(attempt_id), job_id TEXT NOT NULL UNIQUE, run_id TEXT NOT NULL UNIQUE, document_json TEXT NOT NULL, document_digest TEXT NOT NULL",
    "capability_retained_capture_receipts": "attempt_id TEXT PRIMARY KEY REFERENCES capability_attempts(attempt_id), intent_digest TEXT NOT NULL UNIQUE, document_json TEXT NOT NULL, document_digest TEXT NOT NULL",
    "capability_workspace_bindings": "attempt_id TEXT PRIMARY KEY REFERENCES capability_attempts(attempt_id), document_json TEXT NOT NULL, document_digest TEXT NOT NULL, bound_at_ms INTEGER NOT NULL",
    "capability_cleanup_obligations": "attempt_id TEXT PRIMARY KEY REFERENCES capability_attempts(attempt_id), document_json TEXT NOT NULL, document_digest TEXT NOT NULL",
    "capability_cleanup_claims": "attempt_id TEXT PRIMARY KEY REFERENCES capability_attempts(attempt_id), document_json TEXT NOT NULL, document_digest TEXT NOT NULL, claimed_at_ms INTEGER NOT NULL, expires_at_ms INTEGER NOT NULL",
    "capability_cleanup_task_claims": "task_id TEXT PRIMARY KEY, attempt_id TEXT NOT NULL UNIQUE REFERENCES capability_attempts(attempt_id), request_hash TEXT NOT NULL, claim_digest TEXT NOT NULL, claimed_at_ms INTEGER NOT NULL",
    "capability_cleanup_task_payloads": "task_id TEXT PRIMARY KEY REFERENCES capability_cleanup_task_claims(task_id), payload_json TEXT NOT NULL, payload_digest TEXT NOT NULL",
    "capability_cleanup_terminals": "task_id TEXT PRIMARY KEY REFERENCES capability_cleanup_task_claims(task_id), document_json TEXT NOT NULL, document_digest TEXT NOT NULL",
    "capability_recovery_generations": "generation TEXT PRIMARY KEY, attempt_id TEXT NOT NULL REFERENCES capability_attempts(attempt_id), created_at_ms INTEGER NOT NULL, UNIQUE(attempt_id,generation)",
    "capability_recovery_obligations": "generation TEXT PRIMARY KEY REFERENCES capability_recovery_generations(generation), attempt_id TEXT NOT NULL REFERENCES capability_attempts(attempt_id), document_json TEXT NOT NULL, document_digest TEXT NOT NULL",
    "capability_recovery_claims": "generation TEXT PRIMARY KEY REFERENCES capability_recovery_generations(generation), attempt_id TEXT NOT NULL REFERENCES capability_attempts(attempt_id), document_json TEXT NOT NULL, document_digest TEXT NOT NULL, claimed_at_ms INTEGER NOT NULL, expires_at_ms INTEGER NOT NULL",
    "capability_recovery_task_claims": "task_id TEXT PRIMARY KEY, attempt_id TEXT NOT NULL REFERENCES capability_attempts(attempt_id), generation TEXT NOT NULL UNIQUE REFERENCES capability_recovery_claims(generation), document_json TEXT NOT NULL, document_digest TEXT NOT NULL",
    "capability_recovery_terminals": "task_id TEXT PRIMARY KEY REFERENCES capability_recovery_task_claims(task_id), document_json TEXT NOT NULL, document_digest TEXT NOT NULL",
    "capability_receiver_closure_proofs": "attempt_id TEXT PRIMARY KEY REFERENCES capability_attempts(attempt_id), document_json TEXT NOT NULL, document_digest TEXT NOT NULL",
    "capability_recovery_closures": "attempt_id TEXT PRIMARY KEY REFERENCES capability_attempts(attempt_id), generation TEXT NOT NULL REFERENCES capability_recovery_generations(generation), document_json TEXT NOT NULL, document_digest TEXT NOT NULL",
}


def initialize_schema(connection: sqlite3.Connection) -> None:
    if not connection.in_transaction:
        raise ProductStoreError("Capability migration requires one transaction.")
    for table, definition in _TABLES.items():
        connection.execute(f"CREATE TABLE IF NOT EXISTS {table}({definition})")
        for operation in ("UPDATE", "DELETE"):
            connection.execute(
                f"CREATE TRIGGER IF NOT EXISTS {table}_no_{operation.lower()} "
                f"BEFORE {operation} ON {table} BEGIN "
                "SELECT RAISE(ABORT, 'capability history is append-only'); END"
            )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS capability_attempts_owner ON capability_attempts(control_owner_id)"
    )


def _retained_capture_intent(value: Mapping[str, Any]) -> dict[str, Any]:
    document = safe_document(value, context="retained capture intent")
    fields = {
        "schema_version",
        "job_id",
        "run_id",
        "attempt_id",
        "lineage_id",
        "step_id",
        "source",
        "artifacts_digest",
        "producer_evidence_id",
        "producer_record_hash",
        "observation_evidence_id",
        "observation_record_hash",
        "intent_digest",
    }
    if (
        not isinstance(document, dict)
        or set(document) != fields
        or document.get("schema_version") != "bluefire.retained-artifact-capture-intent.v1"
        or document.get("intent_digest")
        != content_hash({key: value for key, value in document.items() if key != "intent_digest"})
    ):
        raise ProductStoreError("Retained capture intent is invalid.")
    try:
        source = source_reference(document.get("source"))
        digest(document.get("artifacts_digest"), "retained artifacts digest")
        for field in ("producer_record_hash", "observation_record_hash"):
            digest(document.get(field), "retained evidence digest")
        for field in ("producer_evidence_id", "observation_evidence_id"):
            identifier(document.get(field), "retained evidence identity")
    except CapabilityContractError as exc:
        raise ProductStoreError("Retained capture intent binding is invalid.") from exc
    if (
        source != document.get("source")
        or source.get("run_id") != document["run_id"]
        or source.get("attempt_id") != document["attempt_id"]
        or source.get("lineage_id") != document["lineage_id"]
        or source.get("step_id") != document["step_id"]
        or any(
            not isinstance(document.get(field), str)
            for field in (
                "job_id",
                "run_id",
                "attempt_id",
                "lineage_id",
                "step_id",
                "producer_evidence_id",
                "producer_record_hash",
                "observation_evidence_id",
                "observation_record_hash",
            )
        )
    ):
        raise ProductStoreError("Retained capture intent binding is invalid.")
    return document


def _retained_capture_intent_row(row: sqlite3.Row) -> dict[str, Any]:
    document = _retained_capture_intent(capability_grant_store._document(row))
    if (
        row["attempt_id"] != document["attempt_id"]
        or row["job_id"] != document["job_id"]
        or row["run_id"] != document["run_id"]
    ):
        raise ProductStoreError("Retained capture intent row binding changed.")
    return document


def _retained_capture_receipt(
    value: Mapping[str, Any], intent: Mapping[str, Any]
) -> dict[str, Any]:
    document = safe_document(value, context="retained capture receipt")
    if (
        not isinstance(document, dict)
        or set(document)
        != {
            "schema_version",
            "source",
            "producer_record_hash",
            "observation_record_hash",
            "capture_digest",
        }
        or document.get("schema_version") != "bluefire.retained-artifact-capture.v1"
        or document.get("source") != intent["source"]
        or document.get("producer_record_hash") != intent["producer_record_hash"]
        or document.get("observation_record_hash") != intent["observation_record_hash"]
        or document.get("capture_digest")
        != content_hash({key: value for key, value in document.items() if key != "capture_digest"})
    ):
        raise ProductStoreError("Retained capture receipt is invalid.")
    return document


class CapabilityStoreMixin:
    def _capability_objective_at(self, connection, job_id):
        row = connection.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone()
        if row is None:
            raise ProductStoreError("The capability objective submission is absent.")
        store = cast(Any, self)
        owner = store._job_from_row(row)
        submitted = owner["progress"].get("submitted_request")
        marker = {key: value for key, value in owner["request"].items() if key != "_submission"}
        if (
            owner["kind"] != "composition.objective"
            or not isinstance(submitted, dict)
            or set(submitted) != {"submission_id", "review", "reviewed_by", "review_digest"}
            or safe_document(submitted, context="saved composition submission") != submitted
            or not isinstance(submitted["review"], dict)
        ):
            raise ProductStoreError("The saved capability objective binding is invalid.")
        review_pack(submitted["review"])
        expected_id, binding = store._job_submission_binding(
            submitted["submission_id"], content_hash(marker)
        )
        if expected_id != job_id or owner["request"].get("_submission") != binding:
            raise ProductStoreError("The saved objective submission identity changed.")
        grant_id = "grant-" + job_id[4:]
        if marker.get("schema_version") == "bluefire.composition-objective-request.v1":
            valid = (
                set(marker) == {"schema_version", "grant_id", "grant_digest"}
                and marker["grant_id"] == grant_id
                and isinstance(marker["grant_digest"], str)
                and re.fullmatch(r"sha256:[0-9a-f]{64}", marker["grant_digest"])
            )
        else:
            valid = (
                set(marker) == {"schema_version", "control_owner_id", "submitted_request_digest"}
                and marker["schema_version"] == "bluefire.composition-objective-refusal.v1"
                and marker["control_owner_id"] == submitted["review"]["control_owner_id"]
                and marker["submitted_request_digest"] == content_hash(submitted)
            )
        if not valid:
            raise ProductStoreError("The saved objective authority marker changed.")
        return owner, grant_id

    def _guard_capability_objective(self, connection, grant, job_id):
        owner, grant_id = self._capability_objective_at(connection, job_id)
        submitted = owner["progress"]["submitted_request"]
        if (
            owner["state"] != "queued"
            or owner["progress"].get("admission", {}).get("accepted") is not False
            or owner["progress"].get("stopped")
            or owner["request"].get("grant_id") != grant_id
            or grant["grant_id"] != grant_id
            or owner["request"].get("grant_digest") != grant["grant_digest"]
            or submitted["reviewed_by"] != grant["approved_by"]
            or submitted["review"]["control_owner_id"] != grant["environment"]["control_owner_id"]
        ):
            raise ProductStoreError(
                "The capability objective is no longer pending grant admission."
            )

    def finish_capability_objective_submission(
        self, job_id: str, *, expected_state: str, admission: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        """Publish admission only with the matching grant state in the same transaction."""
        store = cast(Any, self)
        decision = safe_document(admission, context="composition admission")
        if (
            expected_state not in {"queued", "interrupted"}
            or not isinstance(decision, dict)
            or set(decision) != {"accepted", "problem"}
            or type(decision["accepted"]) is not bool
            or (decision["accepted"] and decision["problem"] is not None)
            or (
                not decision["accepted"]
                and (
                    not isinstance(decision["problem"], dict)
                    or set(decision["problem"]) != {"code", "message"}
                    or any(
                        not isinstance(value, str) or not 1 <= len(value) <= 1000
                        for value in decision["problem"].values()
                    )
                )
            )
        ):
            raise ProductStoreError("Capability admission completion is invalid.")
        with store._connection(write=True) as connection:
            owner, grant_id = self._capability_objective_at(connection, job_id)
            if owner["state"] == "completed":
                if owner["progress"].get("admission") != decision:
                    raise ProductStoreError("The objective already has another terminal admission.")
            elif owner["state"] != expected_state:
                raise ProductStoreError("The objective admission state changed.")
            present = connection.execute(
                "SELECT 1 FROM capability_grants WHERE grant_id=?", (grant_id,)
            ).fetchone()
            if decision["accepted"]:
                if present is None:
                    raise ProductStoreError(
                        "An admitted capability objective requires its saved grant."
                    )
                _, grant, _ = capability_grant_store._grant_at(connection, grant_id)
                if (
                    owner["request"].get("grant_id") != grant_id
                    or owner["request"].get("grant_digest") != grant["grant_digest"]
                ):
                    raise ProductStoreError("The admitted capability grant binding differs.")
            elif present is not None:
                raise ProductStoreError("A capability grant exists; absence cannot be published.")
            if owner["state"] == "completed":
                return cast(Mapping[str, Any], owner)
            progress = {
                **owner["progress"],
                "admission": decision,
                "review_digest": owner["progress"]["submitted_request"]["review_digest"],
                "stopped": owner["progress"].get("stopped") is True,
            }
            connection.execute(
                "UPDATE jobs SET state='completed',progress_json=?,updated_at=? WHERE job_id=?",
                (canonical_json(progress), utc_now(), job_id),
            )
            row = connection.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone()
            return cast(Mapping[str, Any], store._job_from_row(row))

    def create_capability_objective_submission(
        self, owner_request: Mapping[str, Any], submitted_request: Mapping[str, Any]
    ) -> tuple[Mapping[str, Any], bool]:
        """Publish the exact reviewed submission before any grant is persisted."""
        store = cast(Any, self)
        document = safe_document(owner_request, context="composition objective marker")
        submitted = safe_document(submitted_request, context="composition authorization")
        if (
            not isinstance(document, dict)
            or not isinstance(submitted, dict)
            or set(submitted) != {"submission_id", "review", "reviewed_by", "review_digest"}
        ):
            raise ProductStoreError("Composition objective submission is invalid.")
        job_id, binding = store._job_submission_binding(
            submitted["submission_id"], content_hash(document)
        )
        if document.get("schema_version") == "bluefire.composition-objective-request.v1":
            valid = (
                set(document) == {"schema_version", "grant_id", "grant_digest"}
                and document["grant_id"] == "grant-" + job_id[4:]
                and isinstance(document["grant_digest"], str)
                and re.fullmatch(r"sha256:[0-9a-f]{64}", document["grant_digest"])
            )
        else:
            valid = (
                set(document) == {"schema_version", "control_owner_id", "submitted_request_digest"}
                and document["schema_version"] == "bluefire.composition-objective-refusal.v1"
                and isinstance(submitted["review"], dict)
                and isinstance(document["control_owner_id"], str)
                and re.fullmatch(r"job-[0-9a-f]{32}", document["control_owner_id"])
                and document["control_owner_id"] == submitted["review"].get("control_owner_id")
                and document["submitted_request_digest"] == content_hash(submitted)
            )
        if not valid:
            raise ProductStoreError("Composition objective marker does not bind this submission.")
        document["_submission"] = dict(binding)
        progress = {
            "submitted_request": submitted,
            "admission": {
                "accepted": False,
                "problem": {
                    "code": "composition_admission_pending",
                    "message": "The saved delegation is not admitted.",
                },
            },
        }
        with store._connection(write=True) as connection:
            row = connection.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone()
            if row is not None:
                existing = store._matching_job_submission(row, "composition.objective", binding)
                if (
                    existing["request"] != document
                    or existing["progress"].get("submitted_request") != submitted
                ):
                    raise ProductStoreError(
                        "Composition submission ID has a different reviewed request."
                    )
                return existing, False
            now = utc_now()
            connection.execute(
                "INSERT INTO jobs(job_id,kind,state,request_json,progress_json,created_at,updated_at) "
                "VALUES (?,'composition.objective','queued',?,?,?,?)",
                (job_id, canonical_json(document), canonical_json(progress), now, now),
            )
            row = connection.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone()
            return store._job_from_row(row), True

    @staticmethod
    def _capability_workspace_at(connection, attempt_id, lease):
        return cleanup.workspace_at(connection, attempt_id, lease)

    @staticmethod
    def _validate_capability_cleanup_settlement(connection, attempt_id, lease, native):
        cleanup.validate_settlement(connection, attempt_id, lease, native)

    def _validate_macos_capability_settlement(
        self, connection: sqlite3.Connection, attempt_id: str, receipt: Mapping[str, Any]
    ) -> dict[str, Any]:
        from .product_store_macos_settlement import validate

        return validate(self, connection, attempt_id, receipt)

    def save_capability_grant(self, document: Mapping[str, Any], **context: Any) -> dict[str, Any]:
        return capability_grant_store.save_grant(self, document, **context)

    def _guard_capability_control(
        self, connection: sqlite3.Connection, grant: Mapping[str, Any]
    ) -> None:
        if grant_pack(grant) == FILE_ACCESS_PACK:
            from .product_store_file_access import guard_control

            guard_control(self, connection, grant)
            return
        if grant_pack(grant) == MACOS_FILE_ACCESS_PACK:
            from .product_store_macos_composition import guard_control

            guard_control(self, connection, grant)
            return
        from .product_store_receiver_defense import guard_capability_control

        guard_capability_control(self, connection, grant)

    @staticmethod
    def _capability_dependency_at(connection, attempt_id, lease):
        return dependencies.dependency_at(connection, attempt_id, lease)

    @staticmethod
    def _validate_capability_dependency(connection, attempt_id, lease, receipt):
        dependencies.validate_dependency(connection, attempt_id, lease, receipt)

    def bind_capability_file_access(self, attempt_id: str, **context: Any) -> None:
        dependencies.bind_file_access(self, attempt_id, **context)

    def record_capability_file_access_terminal(self, attempt_id: str, **context: Any) -> None:
        dependencies.record_file_access_terminal(self, attempt_id, **context)

    def capability_file_access_closure(self, attempt_id: str) -> dict[str, Any]:
        return dependencies.file_access_closure(self, attempt_id)

    def capability_file_access_evidence(self, attempt_id: str) -> dict[str, Any]:
        store = cast(Any, self)
        with store._connection() as connection:
            _, lease, _ = capability_grant_store._attempt_at(connection, attempt_id)
            binding = dependencies.dependency_at(connection, attempt_id, lease)
            return {
                "binding": binding,
                "terminals": dependencies._file_terminals(connection, attempt_id, binding),
            }

    def bind_macos_capability_file_access(self, attempt_id: str) -> dict[str, Any]:
        from .product_store_capability_dependencies import bind_macos_file_access

        return bind_macos_file_access(self, attempt_id)

    def get_capability_grant(self, grant_id: str, *, now_ms: int) -> dict[str, Any]:
        return capability_grant_store.get_grant(self, grant_id, now_ms=now_ms)

    def reserve_capability_attempt(
        self, grant_id: str, compiled: Mapping[str, Any], **context: Any
    ) -> dict[str, Any]:
        return capability_grant_store.reserve_attempt(self, grant_id, compiled, **context)

    def claim_capability_attempt(self, attempt_id: str, **context: Any) -> dict[str, Any]:
        return capability_grant_store.claim_attempt(self, attempt_id, **context)

    def get_capability_attempt(self, attempt_id: str) -> dict[str, Any]:
        return capability_grant_store.get_attempt(self, attempt_id)

    def get_capability_attempt_for_run(self, run_id: str) -> dict[str, Any] | None:
        """Read the unique persisted attempt for a run without granting new authority."""
        return capability_grant_store.get_attempt_for_run(self, run_id)

    def begin_retained_artifact_capture(
        self, job_id: str, intent: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        """Append one exact intent before private filesystem publication."""

        store = cast(Any, self)
        document = _retained_capture_intent(intent)
        if document["job_id"] != job_id:
            raise ProductStoreError("Retained capture intent job binding is invalid.")
        with store._connection(write=True) as connection:
            row, lease, _ = capability_grant_store._attempt_at(connection, document["attempt_id"])
            child, request = capability_grant_store._submitted_job(
                store, connection, job_id, "composition.attempt"
            )
            marker = request.get("composition_attempt")
            task = connection.execute(
                "SELECT * FROM capability_task_claims WHERE attempt_id=? AND step_id=?",
                (document["attempt_id"], document["step_id"]),
            ).fetchone()
            terminal = (
                None
                if task is None
                else connection.execute(
                    "SELECT * FROM capability_task_terminals WHERE task_id=?",
                    (task["task_id"],),
                ).fetchone()
            )
            if (
                row["job_id"] != job_id
                or row["run_id"] != document["run_id"]
                or row["lineage_id"] != document["lineage_id"]
                or lease["attempt_id"] != document["attempt_id"]
                or not isinstance(marker, dict)
                or marker.get("attempt_id") != document["attempt_id"]
                or marker.get("run_id") != document["run_id"]
                or task is None
                or terminal is None
            ):
                raise ProductStoreError("Retained capture intent is outside its claimed attempt.")
            previous = connection.execute(
                "SELECT * FROM capability_retained_capture_intents WHERE attempt_id=?",
                (document["attempt_id"],),
            ).fetchone()
            if previous is not None:
                if _retained_capture_intent_row(previous) != document:
                    raise ProductStoreError("Retained capture intent is already immutable.")
                return document
            if child["state"] not in {"running", "interrupted", "failed"}:
                raise ProductStoreError("Retained capture intent is outside its claimed attempt.")
            connection.execute(
                "INSERT INTO capability_retained_capture_intents VALUES(?,?,?,?,?)",
                (
                    document["attempt_id"],
                    job_id,
                    document["run_id"],
                    canonical_json(document),
                    content_hash(document),
                ),
            )
            return document

    def commit_retained_artifact_capture(
        self, job_id: str, receipt: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        """Atomically append the receipt and mirror it into compatible job progress."""

        store = cast(Any, self)
        with store._connection(write=True) as connection:
            intent_row = connection.execute(
                "SELECT * FROM capability_retained_capture_intents WHERE job_id=?", (job_id,)
            ).fetchone()
            if intent_row is None:
                raise ProductStoreError("Retained capture has no durable intent.")
            intent = _retained_capture_intent_row(intent_row)
            document = _retained_capture_receipt(receipt, intent)
            child, _ = capability_grant_store._submitted_job(
                store, connection, job_id, "composition.attempt"
            )
            previous = connection.execute(
                "SELECT * FROM capability_retained_capture_receipts WHERE attempt_id=?",
                (intent["attempt_id"],),
            ).fetchone()
            if previous is None:
                connection.execute(
                    "INSERT INTO capability_retained_capture_receipts VALUES(?,?,?,?)",
                    (
                        intent["attempt_id"],
                        intent["intent_digest"],
                        canonical_json(document),
                        content_hash(document),
                    ),
                )
            elif (
                previous["intent_digest"] != intent["intent_digest"]
                or capability_grant_store._document(previous) != document
            ):
                raise ProductStoreError("Retained capture receipt is already immutable.")
            existing = child["progress"].get("retained_artifact_capture")
            if existing is not None and existing != document:
                raise ProductStoreError("Retained capture progress mirror conflicts.")
            if existing is None:
                progress = {**child["progress"], "retained_artifact_capture": document}
                connection.execute(
                    "UPDATE jobs SET progress_json=?,updated_at=? WHERE job_id=?",
                    (canonical_json(progress), utc_now(), job_id),
                )
            return document

    def get_retained_artifact_capture(self, attempt_id: str) -> Mapping[str, Any] | None:
        """Read the append-only receipt and require its compatibility mirror."""

        store = cast(Any, self)
        with store._connection() as connection:
            intent_row = connection.execute(
                "SELECT * FROM capability_retained_capture_intents WHERE attempt_id=?",
                (attempt_id,),
            ).fetchone()
            receipt_row = connection.execute(
                "SELECT * FROM capability_retained_capture_receipts WHERE attempt_id=?",
                (attempt_id,),
            ).fetchone()
            if intent_row is None and receipt_row is None:
                return None
            if intent_row is None:
                raise ProductStoreError("Retained capture receipt lost its exact intent.")
            if receipt_row is None:
                return None
            intent = _retained_capture_intent_row(intent_row)
            receipt = _retained_capture_receipt(
                capability_grant_store._document(receipt_row), intent
            )
            if (
                receipt_row["attempt_id"] != intent["attempt_id"]
                or receipt_row["intent_digest"] != intent["intent_digest"]
            ):
                raise ProductStoreError("Retained capture receipt intent changed.")
            child, _ = capability_grant_store._submitted_job(
                store, connection, intent["job_id"], "composition.attempt"
            )
            if child["progress"].get("retained_artifact_capture") != receipt:
                raise ProductStoreError("Retained capture progress mirror changed.")
            return receipt

    def list_retained_artifact_capture_intents(self) -> list[Mapping[str, Any]]:
        """Return pending intents, including rows beyond the first recovery page."""

        store = cast(Any, self)
        with store._connection() as connection:
            rows = connection.execute(
                """SELECT intent.* FROM capability_retained_capture_intents AS intent
                LEFT JOIN capability_retained_capture_receipts AS receipt
                  ON receipt.attempt_id=intent.attempt_id
                WHERE receipt.attempt_id IS NULL
                ORDER BY intent.rowid"""
            ).fetchall()
        return [_retained_capture_intent_row(row) for row in rows]

    def start_capability_preparation(self, attempt_id: str, **context: Any) -> None:
        capability_grant_store.start_preparation(self, attempt_id, **context)

    def register_capability_task(self, attempt_id: str, **context: Any) -> dict[str, Any]:
        return capability_grant_store.register_task(self, attempt_id, **context)

    def mark_capability_task_dispatch(self, attempt_id: str, **context: Any) -> dict[str, Any]:
        from .product_store_retained_recovery import mark_task_dispatch

        return mark_task_dispatch(self, attempt_id, **context)

    def record_capability_task_no_send(self, attempt_id: str, **context: Any) -> dict[str, Any]:
        from .product_store_retained_recovery import record_task_no_send

        return record_task_no_send(self, attempt_id, **context)

    def get_capability_task_payload(
        self, task_id: str, transport_request_hash: str
    ) -> dict[str, Any]:
        from .product_store_capability_payloads import read_payload

        return read_payload(self, task_id, transport_request_hash, purpose="business")

    def bind_capability_workspace(self, attempt_id: str, **context: Any) -> dict[str, Any]:
        from .product_store_capability_cleanup import bind_workspace

        return bind_workspace(self, attempt_id, **context)

    def record_capability_cleanup_obligation(
        self, attempt_id: str, **context: Any
    ) -> dict[str, Any]:
        from .product_store_capability_cleanup import record_obligation

        return record_obligation(self, attempt_id, **context)

    def claim_capability_cleanup(self, attempt_id: str, **context: Any) -> dict[str, Any]:
        from .product_store_capability_cleanup import claim_cleanup

        return claim_cleanup(self, attempt_id, **context)

    def register_capability_cleanup_task(self, attempt_id: str, **context: Any) -> dict[str, Any]:
        from .product_store_capability_cleanup import register_cleanup_task

        return register_cleanup_task(self, attempt_id, **context)

    def get_capability_cleanup_task_payload(
        self, task_id: str, transport_request_hash: str
    ) -> dict[str, Any]:
        from .product_store_capability_payloads import read_payload

        return read_payload(self, task_id, transport_request_hash, purpose="cleanup")

    def record_capability_cleanup_terminal(self, task_id: str, **context: Any) -> None:
        from .product_store_capability_cleanup import record_cleanup_terminal

        record_cleanup_terminal(self, task_id, **context)

    def get_capability_cleanup(self, attempt_id: str) -> dict[str, Any]:
        from .product_store_capability_cleanup import get_cleanup

        return get_cleanup(self, attempt_id)

    def bind_capability_receiver(self, attempt_id: str, **context: Any) -> None:
        capability_grant_store.bind_receiver(self, attempt_id, **context)

    def record_capability_task_terminal(self, task_id: str, **context: Any) -> None:
        capability_grant_store.record_task_terminal(self, task_id, **context)

    def settle_capability_attempt(self, attempt_id: str, receipt: Mapping[str, Any]) -> None:
        capability_grant_store.settle_attempt(self, attempt_id, receipt)

    def change_capability_grant_state(self, grant_id: str, **context: Any) -> dict[str, Any]:
        return capability_grant_store.change_state(self, grant_id, **context)

    def interrupt_active_capability_grants(self, *, now_ms: int) -> None:
        capability_grant_store.interrupt_active(self, now_ms=now_ms)

    def reserve_macos_capability_attempt(self, attempt_id: str, **context: Any) -> dict[str, Any]:
        from .product_store_macos_composition import reserve_macos_capability_attempt

        return reserve_macos_capability_attempt(self, attempt_id, **context)

    def begin_macos_capability_dispatch(
        self, task_id: str, transport_request_hash: str, **context: Any
    ) -> dict[str, Any]:
        from .product_store_macos_composition import begin_macos_capability_dispatch

        return begin_macos_capability_dispatch(self, task_id, transport_request_hash, **context)

    def claim_macos_capability_cleanup(self, attempt_id: str, **context: Any) -> dict[str, Any]:
        from .product_store_macos_composition import claim_macos_capability_cleanup

        return claim_macos_capability_cleanup(self, attempt_id, **context)

    def register_macos_capability_cleanup_task(
        self, attempt_id: str, **context: Any
    ) -> dict[str, Any]:
        from .product_store_macos_composition import register_macos_capability_cleanup_task

        return register_macos_capability_cleanup_task(self, attempt_id, **context)

    def get_macos_capability_cleanup_task_payload(
        self, task_id: str, transport_request_hash: str
    ) -> dict[str, Any]:
        from .product_store_capability_payloads import read_payload

        return read_payload(self, task_id, transport_request_hash, purpose="macos_cleanup")

    def record_macos_capability_terminal(self, task_id: str, **context: Any) -> dict[str, Any]:
        from .product_store_macos_composition import record_macos_capability_terminal

        return record_macos_capability_terminal(self, task_id, **context)

    def close_macos_capability_attempt(self, attempt_id: str, **context: Any) -> dict[str, Any]:
        from .product_store_macos_composition import close_macos_capability_attempt

        return close_macos_capability_attempt(self, attempt_id, **context)

    def get_macos_capability_closure(self, attempt_id: str) -> dict[str, Any]:
        from .product_store_macos_composition import get_macos_capability_closure

        return get_macos_capability_closure(self, attempt_id)
