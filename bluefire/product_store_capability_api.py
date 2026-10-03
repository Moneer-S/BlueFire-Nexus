"""Capability schema and ProductStore facades over append-only records."""

from __future__ import annotations

import re
import sqlite3
from typing import Any, Mapping, cast

from . import product_store_capability_cleanup as cleanup
from . import product_store_capability_grants as capability_grant_store
from .product_store_contracts import safe_document
from .product_store_errors import ProductStoreError
from .product_store_serialization import canonical_json, utc_now
from .util import content_hash

_TABLES = {
    "capability_lineages": "lineage_id TEXT PRIMARY KEY, binding_digest TEXT NOT NULL UNIQUE, document_json TEXT NOT NULL, document_digest TEXT NOT NULL",
    "capability_grants": "grant_id TEXT PRIMARY KEY, lineage_id TEXT NOT NULL REFERENCES capability_lineages(lineage_id), control_owner_id TEXT NOT NULL, document_json TEXT NOT NULL, document_digest TEXT NOT NULL, created_at_ms INTEGER NOT NULL, expires_at_ms INTEGER NOT NULL",
    "capability_grant_events": "sequence INTEGER PRIMARY KEY AUTOINCREMENT, grant_id TEXT NOT NULL REFERENCES capability_grants(grant_id), status TEXT NOT NULL CHECK(status IN ('active','paused','revoked','interrupted','completed')), at_ms INTEGER NOT NULL",
    "capability_attempts": "attempt_id TEXT PRIMARY KEY, grant_id TEXT NOT NULL REFERENCES capability_grants(grant_id), lineage_id TEXT NOT NULL REFERENCES capability_lineages(lineage_id), control_owner_id TEXT NOT NULL, endpoint_digest TEXT NOT NULL, job_id TEXT NOT NULL UNIQUE, run_id TEXT NOT NULL UNIQUE, document_json TEXT NOT NULL, document_digest TEXT NOT NULL, compiled_json TEXT NOT NULL, compiled_digest TEXT NOT NULL, created_at_ms INTEGER NOT NULL",
    "capability_control_usages": "attempt_id TEXT PRIMARY KEY REFERENCES capability_attempts(attempt_id), control_owner_id TEXT NOT NULL, document_json TEXT NOT NULL, document_digest TEXT NOT NULL",
    "capability_attempt_claims": "attempt_id TEXT PRIMARY KEY REFERENCES capability_attempts(attempt_id), document_json TEXT NOT NULL, document_digest TEXT NOT NULL, claimed_at_ms INTEGER NOT NULL",
    "capability_preparation_starts": "attempt_id TEXT PRIMARY KEY REFERENCES capability_attempts(attempt_id), started_at_ms INTEGER NOT NULL",
    "capability_receiver_bindings": "attempt_id TEXT PRIMARY KEY REFERENCES capability_attempts(attempt_id), document_json TEXT NOT NULL, document_digest TEXT NOT NULL",
    "capability_task_claims": "task_id TEXT PRIMARY KEY, attempt_id TEXT NOT NULL REFERENCES capability_attempts(attempt_id), step_id TEXT NOT NULL, request_hash TEXT NOT NULL, claimed_at_ms INTEGER NOT NULL, UNIQUE(attempt_id,step_id)",
    "capability_task_terminals": "task_id TEXT PRIMARY KEY REFERENCES capability_task_claims(task_id), document_json TEXT NOT NULL, document_digest TEXT NOT NULL",
    "capability_attempt_settlements": "attempt_id TEXT PRIMARY KEY REFERENCES capability_attempts(attempt_id), document_json TEXT NOT NULL, document_digest TEXT NOT NULL",
    "capability_workspace_bindings": "attempt_id TEXT PRIMARY KEY REFERENCES capability_attempts(attempt_id), document_json TEXT NOT NULL, document_digest TEXT NOT NULL, bound_at_ms INTEGER NOT NULL",
    "capability_cleanup_obligations": "attempt_id TEXT PRIMARY KEY REFERENCES capability_attempts(attempt_id), document_json TEXT NOT NULL, document_digest TEXT NOT NULL",
    "capability_cleanup_claims": "attempt_id TEXT PRIMARY KEY REFERENCES capability_attempts(attempt_id), document_json TEXT NOT NULL, document_digest TEXT NOT NULL, claimed_at_ms INTEGER NOT NULL, expires_at_ms INTEGER NOT NULL",
    "capability_cleanup_task_claims": "task_id TEXT PRIMARY KEY, attempt_id TEXT NOT NULL UNIQUE REFERENCES capability_attempts(attempt_id), request_hash TEXT NOT NULL, claim_digest TEXT NOT NULL, claimed_at_ms INTEGER NOT NULL",
    "capability_cleanup_terminals": "task_id TEXT PRIMARY KEY REFERENCES capability_cleanup_task_claims(task_id), document_json TEXT NOT NULL, document_digest TEXT NOT NULL",
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
            or set(submitted["review"]) != {"control_owner_id", "question", "limits"}
        ):
            raise ProductStoreError("The saved capability objective binding is invalid.")
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

    def save_capability_grant(self, document: Mapping[str, Any], **context: Any) -> dict[str, Any]:
        return capability_grant_store.save_grant(self, document, **context)

    def _guard_capability_control(
        self, connection: sqlite3.Connection, grant: Mapping[str, Any]
    ) -> None:
        from .product_store_receiver_defense import guard_capability_control

        guard_capability_control(self, connection, grant)

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

    def start_capability_preparation(self, attempt_id: str, **context: Any) -> None:
        capability_grant_store.start_preparation(self, attempt_id, **context)

    def register_capability_task(self, attempt_id: str, **context: Any) -> dict[str, Any]:
        return capability_grant_store.register_task(self, attempt_id, **context)

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
