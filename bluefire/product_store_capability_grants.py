"""Durable capability delegation, conservative reservations and owned-effect lineage.

These are trusted controller APIs, not endpoints accepting client authority documents.
The store cannot authenticate observations; callers must verify native evidence before
recording it. Missing or inconsistent records deny business work but never deny Stop.
"""

from __future__ import annotations

import json
import re
import sqlite3
from datetime import datetime, timezone
from typing import Any, Mapping

from .capability_dependency import endpoint_digest as _endpoint_digest
from .capability_dependency import usage_document
from .capability_grant import authority_id, digest, identifier, validate_grant
from .capability_packs import grant_pack
from .capability_resources import RESERVATION_LIMITS, accumulate_reservation, reserve_resources
from .product_store_errors import ProductStoreError
from .product_store_serialization import canonical_json
from .util import content_hash, json_clone

ISSUER = "capability-grant-controller.v1"


def _time(value: Any) -> int:
    if type(value) is not int or not 0 < value < 2**63:
        raise ProductStoreError("Capability time is invalid.")
    return value


def _document(
    row: sqlite3.Row, *, field: str = "document_json", digest_field: str = "document_digest"
) -> dict[str, Any]:
    try:
        result = json.loads(row[field])
        if not isinstance(result, dict) or content_hash(result) != row[digest_field]:
            raise ValueError("digest")
        return result
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        raise ProductStoreError("Capability history failed integrity validation.") from exc


def _body(value: Mapping[str, Any], key: str) -> dict[str, Any]:
    body = {name: item for name, item in value.items() if name != key}
    if value.get(key) != content_hash(body):
        raise ProductStoreError("Capability document digest is invalid.")
    return body


def _one(connection, statement, value):
    row = connection.execute(statement, (value,)).fetchone()
    if row is None:
        raise ProductStoreError("Capability history is missing a required record.")
    return row


def _insert_document(connection, statement, value, document):
    connection.execute(
        statement,
        (value, canonical_json(document), content_hash(document)),
    )


def _lineage_binding(grant):
    environment = grant["environment"]
    return {
        "control_owner_id": environment["control_owner_id"],
        "environment_id": environment["environment_id"],
        "runner_id": environment["runner_id"],
        "target_scope_digest": environment["target_scope_digest"],
        "predicate": grant["objective"]["predicate"],
    }


def _grant_at(connection, grant_id):
    row = _one(connection, "SELECT * FROM capability_grants WHERE grant_id=?", grant_id)
    document = _document(row)
    _body(document, "grant_digest")
    if (
        document.get("grant_id") != row["grant_id"]
        or document["environment"]["control_owner_id"] != row["control_owner_id"]
        or document["created_at_ms"] != row["created_at_ms"]
        or document["expires_at_ms"] != row["expires_at_ms"]
    ):
        raise ProductStoreError("Capability grant binding changed.")
    lineage_row = _one(
        connection, "SELECT * FROM capability_lineages WHERE lineage_id=?", row["lineage_id"]
    )
    lineage = _document(lineage_row)
    if (
        lineage["binding"] != _lineage_binding(document)
        or content_hash(lineage["binding"]) != lineage_row["binding_digest"]
        or lineage["limits"] != document["limits"]
    ):
        raise ProductStoreError("Capability lineage or limits changed.")
    event = connection.execute(
        "SELECT * FROM capability_grant_events WHERE grant_id=? ORDER BY sequence DESC LIMIT 1",
        (grant_id,),
    ).fetchone()
    if event is None:
        raise ProductStoreError("Capability grant state is missing.")
    return row, document, event


def _live(connection, grant_id, now_ms, current_environment):
    _time(now_ms)
    row, document, event = _grant_at(connection, grant_id)
    latest = _lineage_time(connection, row["lineage_id"])
    if (
        event["status"] != "active"
        or not max(document["created_at_ms"], event["at_ms"], latest or 0)
        <= now_ms
        < document["expires_at_ms"]
        or not isinstance(current_environment, Mapping)
        or current_environment != document["environment"]
    ):
        raise ProductStoreError("Capability grant is stopped, expired or its context changed.")
    return row, document


def _lineage_time(connection, lineage_id):
    return (
        connection.execute(
            """SELECT MAX(observed) FROM (
        SELECT created_at_ms AS observed FROM capability_attempts WHERE lineage_id=?
        UNION ALL SELECT e.at_ms FROM capability_grant_events e
            JOIN capability_grants g USING(grant_id) WHERE g.lineage_id=?
        UNION ALL SELECT c.claimed_at_ms FROM capability_attempt_claims c
            JOIN capability_attempts a USING(attempt_id) WHERE a.lineage_id=?
        UNION ALL SELECT p.started_at_ms FROM capability_preparation_starts p
            JOIN capability_attempts a USING(attempt_id) WHERE a.lineage_id=?
        UNION ALL SELECT t.claimed_at_ms FROM capability_task_claims t
            JOIN capability_attempts a USING(attempt_id) WHERE a.lineage_id=?
        UNION ALL SELECT c.claimed_at_ms FROM capability_cleanup_claims c
            JOIN capability_attempts a USING(attempt_id) WHERE a.lineage_id=?
        UNION ALL SELECT c.claimed_at_ms FROM capability_cleanup_task_claims c
            JOIN capability_attempts a USING(attempt_id) WHERE a.lineage_id=?
        UNION ALL SELECT w.bound_at_ms FROM capability_workspace_bindings w
            JOIN capability_attempts a USING(attempt_id) WHERE a.lineage_id=?)""",
            (lineage_id,) * 8,
        ).fetchone()[0]
        or 0
    )


def _attempt_at(connection, attempt_id):
    row = _one(connection, "SELECT * FROM capability_attempts WHERE attempt_id=?", attempt_id)
    lease = _document(row)
    _body(lease, "lease_digest")
    compiled = _document(row, field="compiled_json", digest_field="compiled_digest")
    if any(
        lease.get(key) != row[key]
        for key in (
            "attempt_id",
            "grant_id",
            "lineage_id",
            "control_owner_id",
            "endpoint_digest",
            "job_id",
            "run_id",
        )
    ) or lease["compiled_digest"] != compiled.get("compiled_digest"):
        raise ProductStoreError("Capability attempt binding changed.")
    _body(compiled, "compiled_digest")
    grant_row, grant, _ = _grant_at(connection, row["grant_id"])
    if (
        grant_row["lineage_id"] != row["lineage_id"]
        or grant["grant_digest"] != lease["grant_digest"]
        or _endpoint_digest(grant["environment"]) != row["endpoint_digest"]
    ):
        raise ProductStoreError("Capability attempt belongs to another grant.")
    expected_usage = usage_document(grant, compiled, lease)
    usage = _one(
        connection, "SELECT * FROM capability_control_usages WHERE attempt_id=?", attempt_id
    )
    if usage["control_owner_id"] != row["control_owner_id"] or _document(usage) != expected_usage:
        raise ProductStoreError("Capability receiver usage binding changed.")
    if connection.execute(
        "SELECT 1 FROM capability_attempt_claims WHERE attempt_id=?", (attempt_id,)
    ).fetchone():
        _claim_at(connection, attempt_id, lease)
    elif any(
        connection.execute(statement, (attempt_id,)).fetchone()
        for statement in (
            "SELECT 1 FROM capability_preparation_starts WHERE attempt_id=?",
            "SELECT 1 FROM capability_receiver_bindings WHERE attempt_id=?",
            "SELECT 1 FROM capability_task_claims WHERE attempt_id=?",
        )
    ):
        raise ProductStoreError("Capability effect history lost its unique authority claim.")
    return row, lease, compiled


def _usage(connection, lineage_id, limits):
    result = dict.fromkeys(RESERVATION_LIMITS, 0)
    for row in connection.execute(
        "SELECT attempt_id FROM capability_attempts WHERE lineage_id=? ORDER BY rowid",
        (lineage_id,),
    ):
        _, lease, compiled = _attempt_at(connection, row["attempt_id"])
        _, grant, _ = _grant_at(connection, lease["grant_id"])
        if lease["reservation"] != reserve_resources(
            compiled["scenario"]["steps"], limits, pack=grant_pack(grant)
        ):
            raise ProductStoreError("Capability reservation differs from its graph.")
        result = accumulate_reservation(result, lease["reservation"], limits)
    return result


def _control_current(store, connection, grant):
    store._guard_capability_control(connection, grant)


def save_grant(
    store,
    document,
    *,
    lineage_id,
    registry,
    implementation_digests,
    current_environment,
    now_ms,
    objective_job_id=None,
) -> dict[str, Any]:
    """Persist a grant after the controller's explicit operator-review boundary."""
    identifier(lineage_id, "capability lineage")
    grant = validate_grant(
        document,
        expected_digest=document["grant_digest"],
        registry=registry,
        implementation_digests=implementation_digests,
        current_environment=current_environment,
        now_ms=now_ms,
    )
    binding = _lineage_binding(grant)
    lineage = {
        "schema_version": "bluefire.capability-lineage.v1",
        "binding": binding,
        "limits": grant["limits"],
    }
    with store._connection(write=True) as connection:
        if objective_job_id is not None:
            store._guard_capability_objective(connection, grant, objective_job_id)
        _control_current(store, connection, grant)
        existing = connection.execute(
            "SELECT * FROM capability_lineages WHERE lineage_id=? OR binding_digest=?",
            (lineage_id, content_hash(binding)),
        ).fetchall()
        if existing:
            if (
                len(existing) != 1
                or existing[0]["lineage_id"] != lineage_id
                or _document(existing[0]) != lineage
            ):
                raise ProductStoreError(
                    "Use the existing capability lineage without resetting its limits."
                )
            if now_ms < _lineage_time(connection, lineage_id):
                raise ProductStoreError("Capability lineage clock moved backwards.")
        else:
            connection.execute(
                "INSERT INTO capability_lineages VALUES(?,?,?,?)",
                (lineage_id, content_hash(binding), canonical_json(lineage), content_hash(lineage)),
            )
        if connection.execute(
            "SELECT 1 FROM capability_grants WHERE grant_id=?", (grant["grant_id"],)
        ).fetchone():
            raise ProductStoreError("A capability grant is immutable and already exists.")
        connection.execute(
            "INSERT INTO capability_grants VALUES(?,?,?,?,?,?,?)",
            (
                grant["grant_id"],
                lineage_id,
                grant["environment"]["control_owner_id"],
                canonical_json(grant),
                content_hash(grant),
                grant["created_at_ms"],
                grant["expires_at_ms"],
            ),
        )
        connection.execute(
            "INSERT INTO capability_grant_events(grant_id,status,at_ms) VALUES(?,'active',?)",
            (grant["grant_id"], _time(now_ms)),
        )
    return get_grant(store, grant["grant_id"], now_ms=now_ms)


def get_grant(store, grant_id, *, now_ms) -> dict[str, Any]:
    _time(now_ms)
    with store._connection() as connection:
        row, grant, event = _grant_at(connection, grant_id)
        usage = _usage(connection, row["lineage_id"], grant["limits"])
        status = event["status"]
        if status == "active" and now_ms < _lineage_time(connection, row["lineage_id"]):
            status = "clock_uncertain"
        if status == "active" and now_ms >= grant["expires_at_ms"]:
            status = "expired"
        if status == "active" and any(
            usage[key] >= grant["limits"][bound] for key, bound in RESERVATION_LIMITS.items()
        ):
            status = "exhausted"
        return {
            "document": grant,
            "lineage_id": row["lineage_id"],
            "status": status,
            "usage": usage,
            "cleanup_state": _cleanup_state(store, connection, grant_id),
        }


def reserve_attempt(
    store,
    grant_id,
    compiled,
    *,
    expected_compiled_digest,
    attempt_id,
    job_id,
    run_id,
    plan_digest,
    native_envelope_digest,
    current_environment,
    now_ms,
) -> dict[str, Any]:
    """Reserve the full fresh attempt and receiver dependency before any preparation."""
    authority_id(attempt_id, "attempt")
    identifier(job_id, "composition job")
    if (
        not isinstance(run_id, str)
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", run_id) is None
    ):
        raise ProductStoreError("Composition run identity is invalid.")
    compiled = dict(json_clone(compiled))
    for value in (expected_compiled_digest, plan_digest, native_envelope_digest):
        digest(value, "compiled authority")
    _body(compiled, "compiled_digest")
    with store._connection(write=True) as connection:
        grant_row, grant = _live(connection, grant_id, now_ms, current_environment)
        if (
            compiled.get("compiled_digest") != expected_compiled_digest
            or compiled.get("grant_id") != grant_id
            or compiled.get("grant_digest") != grant["grant_digest"]
            or compiled.get("environment_digest") != content_hash(grant["environment"])
            or compiled.get("snapshot_digest") != grant["snapshot"]["snapshot_digest"]
        ):
            raise ProductStoreError("The compiled attempt differs from its trusted grant.")
        _job_owner(store, connection, job_id, grant, attempt_id, expected_compiled_digest, run_id)
        reservation = reserve_resources(
            compiled["scenario"]["steps"], grant["limits"], pack=grant_pack(grant)
        )
        if compiled["reservation"] != reservation:
            raise ProductStoreError("The compiled resource reservation changed.")
        _control_current(store, connection, grant)
        owner_id = grant["environment"]["control_owner_id"]
        if not control_usages_settled(store, connection, owner_id):
            raise ProductStoreError("Settle every previous capability receiver usage first.")
        _endpoint_settled(store, connection, grant["environment"])
        previous_id = compiled.get("prior_attempt_id")
        if previous_id is not None:
            previous, _, _ = _attempt_at(connection, previous_id)
            if previous["lineage_id"] != grant_row["lineage_id"] or not _settled(
                store, connection, previous_id
            ):
                raise ProductStoreError(
                    "The proposed prior attempt is not settled in this lineage."
                )
        accumulate_reservation(
            _usage(connection, grant_row["lineage_id"], grant["limits"]),
            reservation,
            grant["limits"],
        )
        business_end = min(
            grant["expires_at_ms"],
            now_ms + reservation["reserved_attempt_ms"] - reservation["cleanup_reserve_ms"],
        )
        body = {
            "schema_version": "bluefire.capability-attempt-lease.v1",
            "issuer": ISSUER,
            "attempt_id": attempt_id,
            "grant_id": grant_id,
            "grant_digest": grant["grant_digest"],
            "lineage_id": grant_row["lineage_id"],
            "control_owner_id": owner_id,
            "endpoint_digest": _endpoint_digest(grant["environment"]),
            "compiled_digest": expected_compiled_digest,
            "facts_digest": compiled["facts_digest"],
            "plan_digest": plan_digest,
            "native_envelope_digest": native_envelope_digest,
            "job_id": job_id,
            "run_id": run_id,
            "created_at_ms": now_ms,
            "business_expires_at_ms": business_end,
            "attempt_expires_at_ms": now_ms + reservation["reserved_attempt_ms"],
            "reservation": reservation,
        }
        lease = {**body, "lease_digest": content_hash(body)}
        connection.execute(
            "INSERT INTO capability_attempts VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                attempt_id,
                grant_id,
                grant_row["lineage_id"],
                owner_id,
                body["endpoint_digest"],
                job_id,
                run_id,
                canonical_json(lease),
                content_hash(lease),
                canonical_json(compiled),
                content_hash(compiled),
                now_ms,
            ),
        )
        usage = usage_document(grant, compiled, lease)
        connection.execute(
            "INSERT INTO capability_control_usages VALUES(?,?,?,?)",
            (attempt_id, owner_id, canonical_json(usage), content_hash(usage)),
        )
        return dict(json_clone(lease))


def _endpoint_settled(store, connection, environment):
    for row in connection.execute(
        "SELECT attempt_id FROM capability_attempts WHERE endpoint_digest=?",
        (_endpoint_digest(environment),),
    ):
        _attempt_at(connection, row["attempt_id"])
        if not _settled(store, connection, row["attempt_id"]):
            raise ProductStoreError("The owned loopback endpoint has an unsettled attempt.")


def _iso(milliseconds):
    return (
        datetime.fromtimestamp(milliseconds / 1000, timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _claim_at(connection, attempt_id, lease):
    row = _one(connection, "SELECT * FROM capability_attempt_claims WHERE attempt_id=?", attempt_id)
    document = _document(row)
    expected = {
        "schema_version": "bluefire.runner-grant-attempt.v1",
        "issuer": ISSUER,
        **{
            key: lease[key]
            for key in (
                "grant_id",
                "grant_digest",
                "attempt_id",
                "lease_digest",
                "compiled_digest",
                "plan_digest",
                "native_envelope_digest",
                "run_id",
            )
        },
        "issued_at": _iso(row["claimed_at_ms"]),
        "expires_at": _iso(lease["business_expires_at_ms"]),
    }
    if (
        document != expected
        or not lease["created_at_ms"] <= row["claimed_at_ms"] < lease["business_expires_at_ms"]
    ):
        raise ProductStoreError("The persisted grant-attempt authority changed.")
    return row, document


def _attempt_live(store, connection, attempt_id, now_ms, current_environment):
    row, lease, compiled = _attempt_at(connection, attempt_id)
    _, grant = _live(connection, row["grant_id"], now_ms, current_environment)
    if (
        not lease["created_at_ms"] <= now_ms < lease["business_expires_at_ms"]
        or _settled(store, connection, attempt_id)
        or connection.execute(
            "SELECT 1 FROM capability_cleanup_obligations WHERE attempt_id=?", (attempt_id,)
        ).fetchone()
    ):
        raise ProductStoreError("Capability attempt is expired or already settled.")
    _control_current(store, connection, grant)
    _job_owner(
        store,
        connection,
        row["job_id"],
        grant,
        attempt_id,
        lease["compiled_digest"],
        lease["run_id"],
    )
    return row, lease, compiled


def _submitted_job(store, connection, job_id, kind):
    job = store._job_from_row(_one(connection, "SELECT * FROM jobs WHERE job_id=?", job_id))
    request = job["request"]
    if job["kind"] != kind or not isinstance(request, dict):
        raise ProductStoreError("Capability job ownership changed.")
    binding = request.get("_submission")
    if not isinstance(binding, dict):
        raise ProductStoreError("Capability job submission is missing.")
    intent = {key: value for key, value in request.items() if key != "_submission"}
    expected_id, expected_binding = store._job_submission_binding(
        binding.get("submission_id"), content_hash(intent)
    )
    if job_id != expected_id or binding != expected_binding:
        raise ProductStoreError("Capability job submission binding changed.")
    return job, intent


def _job_owner(store, connection, job_id, grant, attempt_id, compiled_digest, run_id):
    child, request = _submitted_job(store, connection, job_id, "composition.attempt")
    marker = request.get("composition_attempt")
    if set(request) != {"composition_attempt"} or not isinstance(marker, dict):
        raise ProductStoreError("Capability attempt ownership is missing.")
    parent_id = marker.get("parent_job_id")
    identifier(parent_id, "composition objective job")
    expected = {
        "parent_job_id": parent_id,
        "grant_id": grant["grant_id"],
        "grant_digest": grant["grant_digest"],
        "attempt_id": attempt_id,
        "compiled_digest": compiled_digest,
        "run_id": run_id,
    }
    parent, parent_request = _submitted_job(store, connection, parent_id, "composition.objective")
    if (
        marker != expected
        or child["state"] not in {"queued", "running"}
        or parent_request
        != {
            "schema_version": "bluefire.composition-objective-request.v1",
            "grant_id": grant["grant_id"],
            "grant_digest": grant["grant_digest"],
        }
        or parent["state"] != "completed"
        or parent["progress"].get("admission") != {"accepted": True, "problem": None}
        or parent["progress"].get("stopped")
        or child["progress"].get("stopped")
    ):
        raise ProductStoreError(
            "Capability objective or attempt is not admitted for business work."
        )


def claim_attempt(
    store, attempt_id, *, lease_digest, now_ms, current_environment
) -> dict[str, Any]:
    with store._connection(write=True) as connection:
        row, lease, _ = _attempt_live(store, connection, attempt_id, now_ms, current_environment)
        if (
            lease["lease_digest"] != lease_digest
            or connection.execute(
                "SELECT 1 FROM capability_attempt_claims WHERE attempt_id=?", (attempt_id,)
            ).fetchone()
        ):
            raise ProductStoreError("The capability attempt lease changed or was already claimed.")
        document = {
            "schema_version": "bluefire.runner-grant-attempt.v1",
            "issuer": ISSUER,
            **{
                key: lease[key]
                for key in (
                    "grant_id",
                    "grant_digest",
                    "attempt_id",
                    "lease_digest",
                    "compiled_digest",
                    "plan_digest",
                    "native_envelope_digest",
                    "run_id",
                )
            },
            "issued_at": _iso(now_ms),
            "expires_at": _iso(lease["business_expires_at_ms"]),
        }
        binding = content_hash(document)
        connection.execute(
            "INSERT INTO capability_attempt_claims VALUES(?,?,?,?)",
            (row["attempt_id"], canonical_json(document), binding, now_ms),
        )
        return {"document": document, "document_digest": binding}


def register_task(
    store, attempt_id, *, task_id, step_id, request_hash, now_ms, current_environment
) -> dict[str, Any]:
    identifier(task_id, "composition task")
    digest(request_hash, "task request hash")
    with store._connection(write=True) as connection:
        _, lease, compiled = _attempt_live(
            store, connection, attempt_id, now_ms, current_environment
        )
        _, claim = _claim_at(connection, attempt_id, lease)
        store._capability_workspace_at(connection, attempt_id, lease)
        _one(
            connection, "SELECT * FROM capability_preparation_starts WHERE attempt_id=?", attempt_id
        )
        store._capability_dependency_at(connection, attempt_id, lease)
        if claim["lease_digest"] != lease["lease_digest"] or step_id not in {
            step["id"] for step in compiled["scenario"]["steps"]
        }:
            raise ProductStoreError("The task is outside its claimed compiled attempt.")
        if (
            connection.execute(
                "SELECT 1 FROM capability_task_claims WHERE task_id=? OR (attempt_id=? AND step_id=?)",
                (task_id, attempt_id, step_id),
            ).fetchone()
            or connection.execute(
                "SELECT 1 FROM capability_cleanup_task_claims WHERE task_id=?", (task_id,)
            ).fetchone()
        ):
            raise ProductStoreError("This capability task or step was already claimed.")
        connection.execute(
            "INSERT INTO capability_task_claims VALUES(?,?,?,?,?)",
            (task_id, attempt_id, step_id, request_hash, now_ms),
        )
        return {
            "task_id": task_id,
            "attempt_id": attempt_id,
            "step_id": step_id,
            "request_hash": request_hash,
        }


def start_preparation(store, attempt_id, *, now_ms, current_environment):
    """Record the preparation boundary before creating a receiver or workspace."""
    with store._connection(write=True) as connection:
        _, lease, _ = _attempt_live(store, connection, attempt_id, now_ms, current_environment)
        _claim_at(connection, attempt_id, lease)
        if connection.execute(
            "SELECT 1 FROM capability_preparation_starts WHERE attempt_id=?", (attempt_id,)
        ).fetchone():
            raise ProductStoreError(
                "Capability preparation already started; reconcile, do not replay."
            )
        connection.execute(
            "INSERT INTO capability_preparation_starts VALUES(?,?)", (attempt_id, now_ms)
        )


def bind_receiver(store, attempt_id, *, session_generation, review_digest):
    """Publish already-owned process identity even when Stop won during preparation."""
    identifier(session_generation, "receiver session generation")
    digest(review_digest, "receiver review")
    with store._connection(write=True) as connection:
        _, lease, _ = _attempt_at(connection, attempt_id)
        _claim_at(connection, attempt_id, lease)
        _one(
            connection, "SELECT * FROM capability_preparation_starts WHERE attempt_id=?", attempt_id
        )
        if _settled(store, connection, attempt_id):
            raise ProductStoreError("A settled attempt cannot acquire another receiver.")
        document = {
            "schema_version": "bluefire.capability-receiver-binding.v1",
            "attempt_id": attempt_id,
            "lease_digest": lease["lease_digest"],
            "session_generation": session_generation,
            "review_digest": review_digest,
        }
        previous = connection.execute(
            "SELECT * FROM capability_receiver_bindings WHERE attempt_id=?", (attempt_id,)
        ).fetchone()
        if previous is not None:
            if _document(previous) != document:
                raise ProductStoreError("The attempt already owns another receiver generation.")
            return
        _insert_document(
            connection,
            "INSERT INTO capability_receiver_bindings(attempt_id,document_json,document_digest) VALUES(?,?,?)",
            attempt_id,
            document,
        )


def record_task_terminal(store, task_id, *, request_hash, terminal_digest):
    digest(terminal_digest, "authenticated task terminal")
    with store._connection(write=True) as connection:
        task = _one(connection, "SELECT * FROM capability_task_claims WHERE task_id=?", task_id)
        if task["request_hash"] != request_hash:
            raise ProductStoreError("Task terminal belongs to another request.")
        document = {
            "schema_version": "bluefire.capability-task-terminal.v1",
            "task_id": task_id,
            "attempt_id": task["attempt_id"],
            "request_hash": request_hash,
            "terminal_digest": terminal_digest,
        }
        previous = connection.execute(
            "SELECT * FROM capability_task_terminals WHERE task_id=?", (task_id,)
        ).fetchone()
        if previous is not None:
            if _document(previous) != document:
                raise ProductStoreError("Task terminal differs from retained evidence.")
            return
        _insert_document(
            connection,
            "INSERT INTO capability_task_terminals(task_id,document_json,document_digest) VALUES(?,?,?)",
            task_id,
            document,
        )


def _settlement(store, connection, attempt_id, receipt):
    _, lease, _ = _attempt_at(connection, attempt_id)
    store._validate_capability_dependency(connection, attempt_id, lease, receipt)
    native = receipt["native"]
    tasks = connection.execute(
        "SELECT * FROM capability_task_claims WHERE attempt_id=? ORDER BY task_id", (attempt_id,)
    ).fetchall()
    if not tasks:
        if native != {"state": "not_started", "run_id": lease["run_id"]}:
            raise ProductStoreError("Unused native settlement has an invalid run binding.")
    else:
        _claim_at(connection, attempt_id, lease)
        store._capability_workspace_at(connection, attempt_id, lease)
        if (
            not isinstance(native, dict)
            or set(native) != {"state", "run_id", "task_ids", "cleanup_digest"}
            or native["state"] != "complete"
            or native["run_id"] != lease["run_id"]
            or native["task_ids"] != [task["task_id"] for task in tasks]
        ):
            raise ProductStoreError("Native run cleanup lacks its exact registered tasks.")
        digest(native["cleanup_digest"], "native cleanup evidence")
        for task in tasks:
            terminal = _document(
                _one(
                    connection,
                    "SELECT * FROM capability_task_terminals WHERE task_id=?",
                    task["task_id"],
                )
            )
            if (
                terminal["task_id"] != task["task_id"]
                or terminal["attempt_id"] != attempt_id
                or terminal["request_hash"] != task["request_hash"]
                or terminal.get("schema_version") != "bluefire.capability-task-terminal.v1"
            ):
                raise ProductStoreError("Native task terminal binding changed.")
    store._validate_capability_cleanup_settlement(connection, attempt_id, lease, native)
    return receipt


def _settled(store, connection, attempt_id):
    row = connection.execute(
        "SELECT * FROM capability_attempt_settlements WHERE attempt_id=?", (attempt_id,)
    ).fetchone()
    if row is None:
        return False
    _settlement(store, connection, attempt_id, _document(row))
    return True


def settle_attempt(store, attempt_id, receipt):
    receipt = dict(json_clone(receipt))
    with store._connection(write=True) as connection:
        receipt = _settlement(store, connection, attempt_id, receipt)
        previous = connection.execute(
            "SELECT * FROM capability_attempt_settlements WHERE attempt_id=?", (attempt_id,)
        ).fetchone()
        if previous is not None:
            if _document(previous) != receipt:
                raise ProductStoreError("Capability settlement is already immutable.")
            return
        _insert_document(
            connection,
            "INSERT INTO capability_attempt_settlements(attempt_id,document_json,document_digest) VALUES(?,?,?)",
            attempt_id,
            receipt,
        )


def get_attempt(store, attempt_id) -> dict[str, Any]:
    with store._connection() as connection:
        _, lease, compiled = _attempt_at(connection, attempt_id)
        claimed = connection.execute(
            "SELECT * FROM capability_attempt_claims WHERE attempt_id=?", (attempt_id,)
        ).fetchone()
        claim = _claim_at(connection, attempt_id, lease)[1] if claimed else None
        settled = _settled(store, connection, attempt_id)
        tasks = connection.execute(
            "SELECT task_id,step_id,request_hash FROM capability_task_claims WHERE attempt_id=? ORDER BY task_id",
            (attempt_id,),
        ).fetchall()
        return {
            "lease": lease,
            "compiled": compiled,
            "state": "settled" if settled else "claimed" if claimed else "reserved",
            "claim": (
                {"document": claim, "document_digest": claimed["document_digest"]}
                if claimed
                else None
            ),
            "tasks": [dict(task) for task in tasks],
        }


def control_usage_view(store, connection, owner_id):
    """Persisted bindings cannot establish that a receiver process is live now."""
    try:
        rows = connection.execute(
            "SELECT attempt_id FROM capability_attempts WHERE control_owner_id=? UNION SELECT attempt_id FROM capability_control_usages WHERE control_owner_id=?",
            (owner_id, owner_id),
        ).fetchall()
        settled = all(
            _attempt_at(connection, row["attempt_id"])[0]["control_owner_id"] == owner_id
            and _settled(store, connection, row["attempt_id"])
            for row in rows
        )
    except (
        ProductStoreError,
        ValueError,
        TypeError,
        KeyError,
        OverflowError,
        OSError,
        sqlite3.DatabaseError,
    ):
        settled = False
    return {"settled": settled, "receiver_state": "stopped" if settled else "unknown"}


def control_usages_settled(store, connection, owner_id):
    """Missing or damaged usage relations fail closed for rollback and fresh work."""
    return control_usage_view(store, connection, owner_id)["settled"]


def _cleanup_state(store, connection, grant_id):
    try:
        attempts = connection.execute(
            "SELECT attempt_id FROM capability_attempts WHERE grant_id=?", (grant_id,)
        ).fetchall()
        return (
            "settled"
            if all(_settled(store, connection, row["attempt_id"]) for row in attempts)
            else "pending_cleanup"
        )
    except (
        ProductStoreError,
        ValueError,
        TypeError,
        KeyError,
        OverflowError,
        OSError,
        sqlite3.DatabaseError,
    ):
        return "unknown"


def change_state(store, grant_id, *, status, now_ms, current_environment=None) -> dict[str, Any]:
    if status not in {"active", "paused", "revoked", "interrupted", "completed"}:
        raise ProductStoreError("Capability state transition is unsupported.")
    _time(now_ms)
    stopping = status in {"paused", "revoked", "interrupted"}
    with store._connection(write=True) as connection:
        # Stop/Revoke use stable relational keys, not possibly damaged effect evidence.
        row = _one(connection, "SELECT * FROM capability_grants WHERE grant_id=?", grant_id)
        event = connection.execute(
            "SELECT * FROM capability_grant_events WHERE grant_id=? ORDER BY sequence DESC LIMIT 1",
            (grant_id,),
        ).fetchone()
        if status in {"active", "completed"}:
            _, grant, previous = _grant_at(connection, grant_id)
            if previous["status"] in {"revoked", "completed"}:
                raise ProductStoreError("A terminal grant cannot be continued.")
            if (
                current_environment != grant["environment"]
                or not max(
                    previous["at_ms"],
                    grant["created_at_ms"],
                    _lineage_time(connection, row["lineage_id"]),
                )
                <= now_ms
                < grant["expires_at_ms"]
            ):
                raise ProductStoreError("Review current capability scope before continuing.")
            _control_current(store, connection, grant)
            if not control_usages_settled(store, connection, row["control_owner_id"]):
                raise ProductStoreError("Settle every owned effect before continuing.")
        elif event is not None and event["status"] in {"revoked", "completed"}:
            status = event["status"]
        enumeration_complete = True
        try:
            latest = _lineage_time(connection, row["lineage_id"])
        except sqlite3.DatabaseError:
            if not stopping:
                raise
            latest = 0
            enumeration_complete = False
        at_ms = max(now_ms, event["at_ms"] if event else now_ms, latest)
        connection.execute(
            "INSERT INTO capability_grant_events(grant_id,status,at_ms) VALUES(?,?,?)",
            (grant_id, status, at_ms),
        )
        attempts, tasks = [], []
        try:
            attempts = connection.execute(
                "SELECT attempt_id,job_id,run_id FROM capability_attempts WHERE grant_id=?",
                (grant_id,),
            ).fetchall()
            tasks = connection.execute(
                "SELECT task_id,request_hash,attempt_id FROM capability_task_claims WHERE attempt_id IN (SELECT attempt_id FROM capability_attempts WHERE grant_id=?)",
                (grant_id,),
            ).fetchall()
        except sqlite3.DatabaseError:
            if not stopping:
                raise
            enumeration_complete = False
        return {
            "grant_id": grant_id,
            "status": status,
            "cleanup_state": (
                _cleanup_state(store, connection, grant_id) if enumeration_complete else "unknown"
            ),
            "cancellation_enumeration_complete": enumeration_complete,
            "attempts": [dict(item) for item in attempts],
            "tasks": [dict(item) for item in tasks],
        }


def interrupt_active(store, *, now_ms):
    """Service startup calls this explicitly; store reopen alone changes no authority."""
    with store._connection(write=True) as connection:
        rows = connection.execute("SELECT grant_id FROM capability_grants").fetchall()
        for row in rows:
            event = connection.execute(
                "SELECT status,at_ms FROM capability_grant_events WHERE grant_id=? ORDER BY sequence DESC LIMIT 1",
                (row["grant_id"],),
            ).fetchone()
            if event is None or event["status"] == "active":
                connection.execute(
                    "INSERT INTO capability_grant_events(grant_id,status,at_ms) VALUES(?,'interrupted',?)",
                    (row["grant_id"], max(_time(now_ms), event["at_ms"] if event else 0)),
                )
