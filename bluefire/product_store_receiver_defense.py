"""Receiver phase reservations and Stop guards in the existing jobs transaction."""

from __future__ import annotations

import uuid
from typing import Any, Mapping

from .product_store_assistance import job_at, patch
from .product_store_errors import ProductStoreError
from .product_store_serialization import canonical_json, utc_now
from .receiver_defense_contract import OWNER_KIND, PHASES, PREPARE_KIND
from .util import content_hash

ADMISSION_PROBLEM = {
    "code": "receiver_context_unavailable",
    "message": "The selected graph or native settings changed or are unavailable. Review current settings and create a new test; this request started no receiver or run.",
}


def refuse_admission(store, document, submission_id, intent):
    from .product_store_contracts import safe_document as _safe_document

    identifier, binding = store._job_submission_binding(submission_id, intent)
    safe = _safe_document({**document, "_submission": binding}, context="receiver admission")
    with store._connection(write=True) as connection:
        row = connection.execute("SELECT * FROM jobs WHERE job_id = ?", (identifier,)).fetchone()
        if row is not None:
            return store._matching_job_submission(row, OWNER_KIND, binding)
        if "assistance_turn" in safe:
            from .product_store_assistance import publication_guard

            publication_guard(store, connection, OWNER_KIND, safe)
        now = utc_now()
        progress = {
            "admission": {"accepted": False, "problem": ADMISSION_PROBLEM},
            "receiver_settled": True,
        }
        connection.execute(
            "INSERT INTO jobs(job_id,kind,state,request_json,progress_json,error_json,created_at,updated_at) VALUES(?,?,'failed',?,?,?,?,?)",
            (
                identifier,
                OWNER_KIND,
                canonical_json(safe),
                canonical_json(progress),
                canonical_json(ADMISSION_PROBLEM),
                now,
                now,
            ),
        )
        return job_at(store, connection, identifier)


def safe_patch(connection, job, values):
    from .product_store_contracts import safe_document as _safe_document

    patch(connection, job, _safe_document(values, context="receiver defense progress"))


def owner_at(store, connection, job_id, *, active=False):
    job = job_at(store, connection, job_id)
    if active:
        from .product_store_assistance import require_active

        require_active(store, connection, job)
    if job["kind"] != OWNER_KIND or (
        active
        and (
            job["progress"].get("stopped")
            or job["state"] != "completed"
            or job["progress"].get("admission") != {"accepted": True, "problem": None}
        )
    ):
        raise ProductStoreError("The receiver comparison is unavailable or stopped.")
    return job


def cancellation_owner(store, job_id):
    """Resolve reciprocal ownership only; damaged evidence must not prevent Stop."""
    with store._connection() as connection:
        job = job_at(store, connection, job_id)
        if job["kind"] == OWNER_KIND:
            return job
        marker = job["request"].get("receiver_defense")
        if (
            not isinstance(marker, dict)
            or set(marker) != {"parent_job_id", "receiver_job_id", "phase"}
            or marker["phase"] not in PHASES
        ):
            raise ProductStoreError("Receiver cancellation lineage is invalid.")
        owner = owner_at(store, connection, marker["parent_job_id"])
        candidates = [
            {"phase": phase, **value}
            for phase, value in owner["progress"].get("phases", {}).items()
        ] + owner["progress"].get("attempt_history", [])
        matches = [
            row
            for row in candidates
            if row["receiver_job_id"] == marker["receiver_job_id"]
            and row["phase"] == marker["phase"]
        ]
        if len(matches) != 1:
            raise ProductStoreError("Receiver cancellation lacks its exact reserved phase.")
        receiver = job_at(store, connection, marker["receiver_job_id"])
        submitted = matches[0]["prepare_request"]
        identifier = submitted["submission_id"]
        if (
            receiver["kind"] != PREPARE_KIND
            or receiver["request"].get("receiver_defense") != marker
            or receiver["request"].get("submitted_request") != submitted
            or receiver["job_id"] != "job-" + uuid.UUID(identifier).hex
            or receiver["request"]["_submission"]
            != {
                "schema_version": "bluefire.job-submission.v1",
                "submission_id": identifier,
                "intent_digest": content_hash({"parent_job_id": owner["job_id"], **submitted}),
            }
        ):
            raise ProductStoreError("Receiver cancellation preparation binding is invalid.")
        if job["kind"] == PREPARE_KIND:
            if job["job_id"] != receiver["job_id"]:
                raise ProductStoreError("Receiver cancellation names another preparation.")
        else:
            execution = str(uuid.uuid5(uuid.UUID(identifier), "receiver-execution"))
            if (
                job["kind"]
                != ("scenario.run" if marker["phase"] == "baseline" else "scenario.replay")
                or job["job_id"] != "job-" + uuid.UUID(execution).hex
                or receiver["progress"].get("execution_job_id") != job["job_id"]
                or receiver["progress"].get("execution_submission_id") != execution
                or job["request"].get("_submission", {}).get("submission_id") != execution
            ):
                raise ProductStoreError("Receiver cancellation names an unreserved execution.")
        return owner


def reserve(store, parent_id, request):
    phase = request["phase"]
    if phase not in PHASES:
        raise ProductStoreError("Select a named receiver comparison phase.")
    identifier = "job-" + uuid.UUID(request["submission_id"]).hex
    with store._connection(write=True) as connection:
        parent = owner_at(store, connection, parent_id, active=True)
        phases = dict(parent["progress"].get("phases", {}))
        old = phases.get(phase)
        reservation = {"receiver_job_id": identifier, "prepare_request": dict(request)}
        if old is not None:
            if old == reservation:
                return identifier
            previous = job_at(store, connection, old["receiver_job_id"])
            if (
                previous["progress"].get("receiver_closed") is not True
                or previous["progress"].get("execution_started")
                or previous["progress"].get("task_binding")
                or previous["state"] not in {"completed", "interrupted", "cancelled", "failed"}
            ):
                raise ProductStoreError(
                    "The previous receiver attempt must be verified closed without execution before explicit preparation."
                )
            execution_id = previous["progress"].get("execution_job_id")
            if execution_id:
                row = connection.execute(
                    "SELECT * FROM jobs WHERE job_id = ?", (execution_id,)
                ).fetchone()
                if row is not None and store._job_from_row(row)["state"] not in {
                    "cancelled",
                    "failed",
                    "interrupted",
                }:
                    raise ProductStoreError(
                        "The previous native approval must settle before a new receiver preparation."
                    )
            history = list(parent["progress"].get("attempt_history", []))
            if len(history) >= 12:
                raise ProductStoreError(
                    "Receiver preparation history reached its bounded limit. Start a new test after cleanup."
                )
            history.append({"phase": phase, **old})
            safe_patch(connection, parent, {"attempt_history": history})
            parent = owner_at(store, connection, parent_id, active=True)
        index = PHASES.index(phase)
        if index:
            previous = phases.get(PHASES[index - 1])
            if previous is None:
                raise ProductStoreError("Complete the preceding receiver phase first.")
            completed = job_at(store, connection, previous["receiver_job_id"])
            if not phase_verified(completed, PHASES[index - 1]):
                raise ProductStoreError(
                    "The preceding phase lacks its expected authenticated decision and verified cleanup."
                )
        phases[phase] = reservation
        safe_patch(connection, parent, {"phases": phases})
    return identifier


def phase_verified(job, phase):
    result = job["progress"].get("result")
    if not isinstance(result, Mapping) or job["progress"].get("result_digest") != content_hash(
        result
    ):
        return False
    cleanup = dict(result.get("cleanup", {}))
    if cleanup.get("receiver") == "uncertain" and job["progress"].get("receiver_closed") is True:
        session = job["progress"].get("session", {})
        expected = {
            "schema_version": "bluefire.receiver-cleanup.v1",
            "receiver_job_id": job["job_id"],
            "review_digest": session.get("review_digest"),
            "process_id": session.get("receiver_process_id"),
            "creation_identity": session.get("creation_identity"),
            "verified_closed": True,
        }
        if job["progress"].get("receiver_cleanup_receipt") == expected:
            cleanup["receiver"] = "verified_closed"
    if cleanup != {"receiver": "verified_closed", "run": "complete"}:
        return False
    if result.get("decision") != ("policy_refused" if phase == "protected" else "accepted"):
        return False
    if phase == "baseline":
        semantics = (
            result.get("receiver_observation", {})
            .get("terminal", {})
            .get("decision", {})
            .get("semantics", {})
        )
        if semantics.get("retained_record_count", 0) <= 0:
            return False
    return True


def guard(store, connection, kind, request):
    binding = request.get("receiver_defense")
    if (
        not isinstance(binding, Mapping)
        or set(binding) != {"parent_job_id", "receiver_job_id", "phase"}
        or binding["phase"] not in PHASES
    ):
        raise ProductStoreError("Receiver job ownership binding is invalid.")
    parent = owner_at(store, connection, binding["parent_job_id"], active=True)
    reservation = parent["progress"].get("phases", {}).get(binding["phase"])
    if not reservation or reservation["receiver_job_id"] != binding["receiver_job_id"]:
        raise ProductStoreError("Receiver phase reservation changed.")
    if kind == PREPARE_KIND:
        if request.get("submitted_request") != reservation["prepare_request"]:
            raise ProductStoreError("Receiver preparation differs from its reservation.")
        return
    receiver = job_at(store, connection, binding["receiver_job_id"])
    prepared = preparation(receiver)
    decision = receiver["progress"].get("decision", {})
    if (
        prepared is None
        or decision.get("decision") != "accept"
        or receiver["progress"].get("stopped")
    ):
        raise ProductStoreError("Receiver native review is unavailable or stopped.")
    expected_id = receiver["progress"].get("execution_submission_id")
    if (
        request.get("_submission", {}).get("submission_id") != expected_id
        or kind != prepared["execution_kind"]
    ):
        raise ProductStoreError("Receiver execution differs from its unique reviewed submission.")


def preparation(job):
    value = job["progress"].get("preparation")
    if value is not None and (
        value.get("receiver_job_id") != job["job_id"]
        or value.get("parent_job_id") != job["request"]["receiver_defense"]["parent_job_id"]
        or value.get("phase") != job["request"]["receiver_defense"]["phase"]
        or value.get("preparation_digest")
        != content_hash({key: item for key, item in value.items() if key != "preparation_digest"})
    ):
        raise ProductStoreError("The receiver native preparation failed integrity validation.")
    return value


def update(store, receiver_id, values, *, active=False):
    with store._connection(write=True) as connection:
        child = job_at(store, connection, receiver_id)
        if child["kind"] != PREPARE_KIND:
            raise ProductStoreError("The job is not a receiver preparation.")
        owner_at(
            store, connection, child["request"]["receiver_defense"]["parent_job_id"], active=active
        )
        safe_patch(connection, child, values)


def decide(store, receiver_id, decision):
    with store._connection(write=True) as connection:
        job = job_at(store, connection, receiver_id)
        previous = job["progress"].get("decision")
        if previous is not None:
            if previous != decision:
                raise ProductStoreError("This receiver preparation already has another decision.")
            return job
        owner_at(
            store, connection, job["request"]["receiver_defense"]["parent_job_id"], active=True
        )
        prepared = preparation(job)
        if (
            job["state"] not in {"completed", "interrupted"}
            or prepared is None
            or decision["preparation_digest"] != prepared["preparation_digest"]
        ):
            raise ProductStoreError("The receiver preparation is not settled for native review.")
        identifier = str(
            uuid.uuid5(
                uuid.UUID(job["request"]["_submission"]["submission_id"]), "receiver-execution"
            )
        )
        values = {"decision": dict(decision)}
        if decision["decision"] == "accept":
            values.update(
                execution_submission_id=identifier,
                execution_job_id="job-" + uuid.UUID(identifier).hex,
            )
        safe_patch(connection, job, values)
        return job_at(store, connection, receiver_id)


def stop(store, parent_id):
    with store._connection(write=True) as connection:
        parent = owner_at(store, connection, parent_id)
        safe_patch(connection, parent, {"stopped": True})
        return tuple(
            dict.fromkeys(
                value["receiver_job_id"]
                for value in [
                    *parent["progress"].get("phases", {}).values(),
                    *parent["progress"].get("attempt_history", []),
                ]
            )
        )


def list_owners(store, cursor=None):
    """Bounded keyset pagination; unfinished owners precede settled history."""
    rank, created_at = 0, ""
    with store._connection() as connection:
        if cursor is not None:
            previous = owner_at(store, connection, cursor)
            rank = int(previous["progress"].get("receiver_settled") is True)
            created_at = previous["created_at"]
        rows = connection.execute(
            """WITH receiver_owners AS (
                SELECT *, CASE WHEN json_extract(progress_json, '$.receiver_settled') = 1
                    THEN 1 ELSE 0 END AS receiver_priority
                FROM jobs WHERE kind = ?
            )
            SELECT * FROM receiver_owners
            WHERE ? IS NULL OR receiver_priority > ?
                OR (receiver_priority = ? AND (created_at < ? OR (created_at = ? AND job_id < ?)))
            ORDER BY receiver_priority, created_at DESC, job_id DESC LIMIT 129""",
            (OWNER_KIND, cursor, rank, rank, created_at, created_at, cursor),
        ).fetchall()
        return [store._job_from_row(row) for row in rows[:128]], len(rows) > 128


def settle_owner(store, parent_id):
    with store._connection(write=True) as connection:
        parent = owner_at(store, connection, parent_id)
        phases = parent["progress"].get("phases", {})
        children = [
            job_at(store, connection, entry["receiver_job_id"])
            for entry in [*phases.values(), *parent["progress"].get("attempt_history", [])]
        ]
        completed = all(
            phase in phases
            and phase_verified(job_at(store, connection, phases[phase]["receiver_job_id"]), phase)
            for phase in PHASES
        )
        closed = all(
            (
                child["progress"].get("receiver_closed") is True
                or not child["progress"].get("prepare_started")
            )
            and (
                not child["progress"].get("execution_started")
                or child["progress"].get("result", {}).get("cleanup", {}).get("run") == "complete"
            )
            for child in children
        )
        inactive = True
        for child in children:
            execution_id = child["progress"].get("execution_job_id")
            if not execution_id or child["progress"].get("result"):
                continue
            row = connection.execute(
                "SELECT state FROM jobs WHERE job_id = ?", (execution_id,)
            ).fetchone()
            if row and row["state"] not in {"failed", "cancelled", "interrupted", "completed"}:
                inactive = False
        safe_patch(
            connection,
            parent,
            {
                "receiver_settled": closed
                and inactive
                and (completed or parent["progress"].get("stopped") is True),
                "receiver_completed": completed,
            },
        )
