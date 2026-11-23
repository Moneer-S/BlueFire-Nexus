"""Darwin validators and persistence on the original owner-workspace journal.

The protected workspace sends committed provenance on its original channel.
Historical documents never reconstruct that endpoint or authorize replay.
"""

from __future__ import annotations

import json
from copy import deepcopy
from typing import Any, cast

from .capability_resources import digest, exact
from .execution_contracts import execution_task_identity
from .macos_file_access_contract import (
    MAX_MESSAGE,
    REQUEST_SCHEMA,
    validate_binding,
    validate_observation,
    validate_request,
)
from .macos_file_access_intent import ReviewedMacOSTaskIntent
from .product_store_errors import ProductStoreError as ProductStoreError
from .product_store_file_access_records import imported_at as imported_at
from .product_store_macos_setup import CONTROL_SCHEMA as CONTROL_SCHEMA
from .product_store_macos_setup import SETUP_SCHEMA as SETUP_SCHEMA
from .product_store_macos_setup import enrollment_document as enrollment_document
from .product_store_macos_setup import imported_control as imported_control
from .product_store_macos_setup import is_control as is_control
from .product_store_macos_setup import require as require
from .product_store_macos_setup import setup_document as setup_document
from .product_store_serialization import canonical_json
from .util import canonical_json_bytes, content_hash

CONTEXT_SCHEMA = "bluefire.macos-file-access-control-context.v1"
PREPARATION_SCHEMA = "bluefire.macos-file-access-preparation.v1"
PLANS = {
    "baseline": ("read_reader", "read_owner"),
    "harden": ("harden",),
    "rollback": ("rollback", "read_reader", "read_owner"),
}


def _require_original_monotonic_deadline(prepared: dict) -> None:
    from .macos_file_access_clock import darwin_clock_ns

    observed = darwin_clock_ns()
    require(
        type(observed) is int
        and prepared["issued_monotonic_ns"] <= observed < prepared["deadline_ns"]
    )


def permitted(control: dict) -> list[str]:
    return {
        "created": ["baseline"],
        "baseline_verified": ["harden"],
        "hardened": ["rollback"],
        "rolled_back": ["baseline", "harden"],
    }.get(control["status"], [])


def validate_review(control, reviewed, now_ms):
    exact(
        reviewed,
        {"schema_version", "operation", "enrollment_digest", "control_digest", "creator_context"},
        "Darwin control context",
    )
    creator = reviewed["creator_context"]
    exact(
        creator,
        {"schema_version", "operation", "state", "binding", "probe_digest", "context_digest"},
        "Darwin creator context",
    )
    require(
        is_control(control)
        and reviewed["schema_version"] == CONTEXT_SCHEMA
        and reviewed["control_digest"] == content_hash(control)
        and reviewed["operation"] in permitted(control)
        and creator["schema_version"] == "bluefire.macos-file-access-creator-context.v1"
        and creator["state"] == control["status"]
        and creator["operation"] == reviewed["operation"]
        and creator["binding"] == control["binding"]
        and validate_binding(creator["binding"]) == control["binding"]
        and creator["context_digest"]
        == content_hash({k: v for k, v in creator.items() if k != "context_digest"})
        and now_ms < control["binding"]["expires_at_ms"]
    )


def validate_preparation(operation, original, prepared, enrolled, prior, now_ms):
    exact(
        prepared,
        {
            "schema_version",
            "job_id",
            "operation",
            "run_id",
            "creator_context",
            "manifest",
            "runner_profile",
            "issued_at_ms",
            "expires_at_ms",
            "issued_monotonic_ns",
            "deadline_ns",
        },
        "Darwin preparation",
    )
    validate_review(prior, original["review_context"], now_ms)
    creator = prepared["creator_context"]
    op = prepared["operation"]
    require(
        prepared["schema_version"] == PREPARATION_SCHEMA
        and prepared["job_id"] == operation["job_id"]
        and op == operation["operation"]
        and creator == original["review_context"]["creator_context"]
        and enrolled == enrollment_document(setup_document(enrolled["setup"]))
        and original["enrollment_digest"] == content_hash(enrolled)
        and original["review"]["context_digest"] == content_hash(original["review_context"])
    )
    profile = prepared["runner_profile"]
    exact(
        profile,
        {"schema_version", "macos_file_access_binding", "policy_digest"},
        "Darwin task profile",
    )
    require(
        profile["schema_version"] == "bluefire.macos-file-access-task-profile.v1"
        and profile["macos_file_access_binding"] == prior["binding"]
        and profile["policy_digest"]
        == content_hash({k: v for k, v in profile.items() if k != "policy_digest"})
    )
    manifest = prepared["manifest"]
    exact(
        manifest,
        {"schema_version", "run_id", "step_id", "action_id", "request_hash", "params", "approval"},
        "Darwin fixed manifest",
    )
    require(
        manifest["schema_version"] == "bluefire.macos-file-access-task.v1"
        and manifest["run_id"] == prepared["run_id"]
        and manifest["step_id"] == op
        and manifest["action_id"] == "macos.file_access." + op + ".v1"
        and manifest["params"] == {}
        and manifest["approval"] == {"review_digest": original["review"]["review_digest"]}
        and manifest["request_hash"]
        == content_hash({k: v for k, v in manifest.items() if k != "request_hash"})
    )
    task_id, transport_hash = execution_task_identity(manifest, profile)
    ReviewedMacOSTaskIntent.from_document(intent_document(prepared, task_id, transport_hash))
    require(
        prepared["issued_at_ms"] <= now_ms < prepared["expires_at_ms"]
        and prepared["expires_at_ms"] <= original["review"]["expires_at_ms"]
        and prepared["deadline_ns"] <= prior["binding"]["original_deadline_ns"]
    )


def intent_document(prepared, task_id, transport_hash):
    creator = prepared["creator_context"]
    return {
        "schema_version": "bluefire.macos-file-access-reviewed-task.v1",
        "operation": prepared["operation"],
        "task_id": task_id,
        "transport_request_hash": transport_hash,
        "context_digest": creator["context_digest"],
        "binding_digest": content_hash(creator["binding"]),
        "control_revision": creator["binding"]["control_revision"],
        **{
            k: prepared[k]
            for k in ("issued_at_ms", "expires_at_ms", "issued_monotonic_ns", "deadline_ns")
        },
    }


def register_task(
    connection,
    operation,
    original,
    prepared,
    prior,
    enrolled,
    task_id,
    step_id,
    manifest,
    profile,
    now_ms,
    validate_context,
):
    validate_preparation(operation, original, prepared, enrolled, prior, now_ms)
    require(
        (task_id, execution_task_identity(manifest, profile)[1])
        == execution_task_identity(manifest, profile)
        and step_id == prepared["operation"]
        and manifest == prepared["manifest"]
        and profile == prepared["runner_profile"]
        and not connection.execute(
            "SELECT 1 FROM file_access_task_claims WHERE job_id=?", (operation["job_id"],)
        ).fetchone()
    )
    validate_context()
    claim = {
        "job_id": operation["job_id"],
        "task_id": task_id,
        "step_id": step_id,
        "request_hash": manifest["request_hash"],
        "transport_request_hash": execution_task_identity(manifest, profile)[1],
        "manifest": manifest,
        "runner_profile": profile,
    }
    connection.execute(
        "INSERT INTO file_access_task_claims VALUES(?,?,?,?,?,?)",
        (
            task_id,
            operation["job_id"],
            step_id,
            manifest["request_hash"],
            canonical_json(claim),
            content_hash(claim),
        ),
    )


def original_task(connection, task_id):
    from .product_store_file_access_records import _document

    claim = _document(
        connection.execute(
            "SELECT * FROM file_access_task_claims WHERE task_id=?", (task_id,)
        ).fetchone()
    )
    prepared = _document(
        connection.execute(
            "SELECT * FROM file_access_preparations WHERE job_id=?", (claim["job_id"],)
        ).fetchone()
    )
    require(prepared["schema_version"] == PREPARATION_SCHEMA)
    require(
        execution_task_identity(claim["manifest"], claim["runner_profile"])
        == (task_id, claim["transport_request_hash"])
        and claim["manifest"] == prepared["manifest"]
        and claim["runner_profile"] == prepared["runner_profile"]
    )
    return claim, prepared


def validate_terminal_at(connection, claim, result):
    from .product_store_file_access_records import _document

    claim, prepared = original_task(connection, claim["task_id"])
    dispatch = connection.execute(
        "SELECT * FROM file_access_task_evidence WHERE task_id=? AND stage='macos_dispatch'",
        (claim["task_id"],),
    ).fetchone()
    if result.get("schema_version") == "bluefire.task-not-sent.v1":
        require(
            dispatch is None
            and result
            == {
                "schema_version": "bluefire.task-not-sent.v1",
                "task_id": claim["task_id"],
                "request_hash": claim["request_hash"],
            }
        )
        return
    frame = _document(dispatch)
    require(
        frame["claim"] == claim
        and frame["preparation_digest"] == content_hash(prepared)
        and frame["dispatch_digest"]
        == content_hash({k: v for k, v in frame.items() if k != "dispatch_digest"})
    )
    validate_receipt(claim, prepared, result)


def record_closure_at(connection, task_id, request_hash, proof):
    from .product_store_file_access_records import _document

    claim, prepared = original_task(connection, task_id)
    terminal = _document(
        connection.execute(
            "SELECT * FROM file_access_task_terminals WHERE task_id=?", (task_id,)
        ).fetchone()
    )
    require(claim["request_hash"] == request_hash)
    result = terminal["result"]
    validate_terminal_at(connection, claim, result)
    if result.get("schema_version") == "bluefire.task-not-sent.v1":
        expected = {
            "state": "not_sent",
            "binding_digest": content_hash(prepared["creator_context"]["binding"]),
            "evidence_digest": content_hash(result),
        }
    else:
        receipt = validate_receipt(claim, prepared, result)
        require(receipt["state"] == "complete")
        expected = {
            "state": "verified_closed",
            "binding_digest": receipt["binding_digest"],
            "evidence_digest": content_hash(receipt),
        }
    require(proof == expected)
    document = {
        "task_id": task_id,
        "request_hash": request_hash,
        "terminal_digest": content_hash(result),
        "proof": proof,
    }
    previous = connection.execute(
        "SELECT * FROM file_access_worker_closures WHERE task_id=?", (task_id,)
    ).fetchone()
    if previous is not None:
        require(_document(previous) == document)
        return
    connection.execute(
        "INSERT INTO file_access_worker_closures VALUES(?,?,?)",
        (task_id, canonical_json(document), content_hash(document)),
    )


def finish_at(
    connection,
    operation,
    original,
    outcome,
    control,
    expected_outcome_digest,
    verified_observation,
    now_ms,
):
    from .product_store_file_access_records import _control_at, _document, _outcome_at

    require(
        outcome["state"] in ("complete", "unknown", "refused_no_effect")
        and verified_observation is None
        and expected_outcome_digest is None
    )
    record = {**outcome, "control_digest": content_hash(control) if control is not None else None}
    previous = _outcome_at(connection, operation["job_id"])
    if previous is not None:
        require(_document(previous) == record)
        return
    tasks = connection.execute(
        "SELECT * FROM file_access_task_claims WHERE job_id=?", (operation["job_id"],)
    ).fetchall()
    dispatched = any(
        connection.execute(
            "SELECT 1 FROM file_access_task_evidence WHERE task_id=?", (row["task_id"],)
        ).fetchone()
        for row in tasks
    )
    if outcome["state"] == "complete":
        require(len(tasks) == 1 and dispatched and control is not None)
        job = connection.execute(
            "SELECT * FROM jobs WHERE job_id=?", (operation["job_id"],)
        ).fetchone()
        require(
            job["state"] in ("queued", "running")
            and not json.loads(job["progress_json"]).get("stopped")
        )
        claim, prepared = original_task(connection, tasks[0]["task_id"])
        terminal = _document(
            connection.execute(
                "SELECT * FROM file_access_task_terminals WHERE task_id=?", (claim["task_id"],)
            ).fetchone()
        )
        validate_terminal_at(connection, claim, terminal["result"])
        receipt = validate_receipt(claim, prepared, terminal["result"])
        closure = _document(
            connection.execute(
                "SELECT * FROM file_access_worker_closures WHERE task_id=?", (claim["task_id"],)
            ).fetchone()
        )
        prior = _control_at(connection, operation["control_owner_id"])
        require(
            receipt["state"] == "complete"
            and type(now_ms) is int
            and prepared["issued_at_ms"] <= now_ms < prepared["expires_at_ms"]
            and closure["terminal_digest"] == content_hash(terminal["result"])
            and closure["proof"]
            == {
                "state": "verified_closed",
                "binding_digest": receipt["binding_digest"],
                "evidence_digest": content_hash(receipt),
            }
            and prior["document_digest"] == original["review"]["control_digest"]
            and outcome["evidence_digest"] == content_hash(receipt)
            and control == next_control(prior["document"], prepared, receipt)
        )
        _require_original_monotonic_deadline(prepared)
        connection.execute(
            "INSERT INTO file_access_revisions VALUES(?,?,?,?,?)",
            (
                operation["control_owner_id"],
                control["revision"],
                operation["job_id"],
                canonical_json(control),
                content_hash(control),
            ),
        )
    elif outcome["state"] == "refused_no_effect":
        require(not dispatched and control is None)
        for row in tasks:
            claim, _ = original_task(connection, row["task_id"])
            terminal = _document(
                connection.execute(
                    "SELECT * FROM file_access_task_terminals WHERE task_id=?", (row["task_id"],)
                ).fetchone()
            )
            require(terminal["result"].get("schema_version") == "bluefire.task-not-sent.v1")
            validate_terminal_at(connection, claim, terminal["result"])
    else:
        require(control is None)
    connection.execute(
        "INSERT INTO file_access_outcomes(job_id,document_json,document_digest) VALUES(?,?,?)",
        (operation["job_id"], canonical_json(record), content_hash(record)),
    )
    if outcome["state"] == "complete":
        # Check after the journal writes too, while an expired acceptance can
        # still roll back both the outcome and the proposed control revision.
        _require_original_monotonic_deadline(prepared)


def validate_receipt(claim, prepared, result):
    require(
        isinstance(result, dict)
        and result.get("schema_version") == "bluefire.runner-result.v1"
        and result.get("request_hash") == claim["request_hash"]
    )
    receipt = result.get("output", {}).get("macos_receipt")
    exact(
        receipt,
        {
            "schema_version",
            "task_id",
            "transport_request_hash",
            "context_digest",
            "binding_digest",
            "operation",
            "state",
            "dispatch",
            "producer_request_usage",
            "settlement_scope",
            "original_workers",
            "namespace",
            "whole_enrollment_cleanup",
            "control_revision_before",
            "control_revision_after",
            "requests",
            "terminals",
            "shared_request_budget_used",
        },
        "Darwin creator receipt",
    )
    intent = intent_document(prepared, claim["task_id"], claim["transport_request_hash"])
    require(
        receipt["schema_version"] == "bluefire.macos-file-access-task-receipt.v1"
        and len(canonical_json_bytes(receipt)) <= MAX_MESSAGE
        and all(
            receipt[k] == intent[k]
            for k in (
                "task_id",
                "transport_request_hash",
                "context_digest",
                "binding_digest",
                "operation",
            )
        )
        and receipt["settlement_scope"] == "producer_local_only"
        and receipt["whole_enrollment_cleanup"] is False
        and receipt["state"] in ("complete", "unknown")
    )
    if receipt["state"] != "complete":
        require(result["status"] != "success")
        return receipt
    plan = PLANS[prepared["operation"]]
    require(
        result["status"] == "success"
        and receipt["dispatch"] == "attempted"
        and receipt["producer_request_usage"] == "settled"
        and receipt["original_workers"] == "retained"
        and receipt["namespace"] == "original_creator_held"
        and receipt["control_revision_before"] == intent["control_revision"]
        and receipt["control_revision_after"] == intent["control_revision"] + 1
        and type(receipt["shared_request_budget_used"]) is int
        and len(plan) <= receipt["shared_request_budget_used"] <= 64
        and len(receipt["requests"]) == len(receipt["terminals"]) == len(plan)
    )
    binding = deepcopy(prepared["creator_context"]["binding"])
    seen = set()
    for primitive, row, observed in zip(
        plan, receipt["requests"], receipt["terminals"], strict=True
    ):
        exact(
            row,
            {"request_id", "sequence", "operation", "request_digest"},
            "Darwin primitive receipt",
        )
        require(row["operation"] == primitive and row["request_id"] not in seen)
        seen.add(row["request_id"])
        request = validate_request(
            {
                "schema_version": REQUEST_SCHEMA,
                "binding": binding,
                "binding_digest": content_hash(binding),
                "request_id": row["request_id"],
                "sequence": row["sequence"],
                "operation": primitive,
                **{
                    k: prepared[k]
                    for k in ("issued_at_ms", "expires_at_ms", "issued_monotonic_ns", "deadline_ns")
                },
            }
        )
        require(row["request_digest"] == content_hash(request))
        observed = validate_observation(observed, request)
        require(
            observed["held_handle_cleanup"] == "retained"
            and observed["request_handle_cleanup"] != "unknown"
        )
        if primitive in ("harden", "rollback"):
            require(observed["outcome"] == "mode_changed")
            binding = {
                **binding,
                "control_revision": binding["control_revision"] + 1,
                "mode": "0600" if primitive == "harden" else "0640",
            }
        else:
            require(observed["outcome"] == "allowed")
    return receipt


def next_control(prior, prepared, receipt):
    op = prepared["operation"]
    binding = {
        **prior["binding"],
        "control_revision": receipt["control_revision_after"],
        "mode": "0600" if op == "harden" else "0640",
    }
    baseline = prior["baseline"]
    if op == "baseline":
        baseline = {
            "baseline_digest": content_hash(receipt),
            "non_owner": "allowed",
            "owner": "allowed",
            "record_count": binding["resource"]["record_count"],
            "sha256": binding["resource"]["sha256"],
        }
    return {
        **prior,
        "revision": binding["control_revision"],
        "binding": binding,
        "binding_digest": content_hash(binding),
        "baseline": baseline,
        "status": {
            "baseline": "baseline_verified",
            "harden": "hardened",
            "rollback": "rolled_back",
        }[op],
    }


class MacOSFileAccessStoreMixin:
    def import_macos_file_access_setup(self, setup, *, now_ms):
        """Called only with the original protected endpoint's initial setup."""
        from .product_store_file_access_records import _document

        store = cast(Any, self)
        setup = setup_document(setup)
        enrolled, control = enrollment_document(setup), imported_control(setup)
        require(now_ms < enrolled["expires_at_ms"])
        with store._connection(write=True) as connection:
            row = connection.execute(
                "SELECT * FROM file_access_setup_imports WHERE enrollment_id=?",
                (enrolled["enrollment_id"],),
            ).fetchone()
            if row is not None:
                require(_document(row) == control)
                return control
            previous = connection.execute(
                "SELECT * FROM file_access_enrollments WHERE enrollment_id=?",
                (enrolled["enrollment_id"],),
            ).fetchone()
            if previous is None:
                connection.execute(
                    "INSERT INTO file_access_enrollments VALUES(?,?,?)",
                    (enrolled["enrollment_id"], canonical_json(enrolled), content_hash(enrolled)),
                )
            else:
                require(_document(previous) == enrolled)
            connection.execute(
                "INSERT INTO file_access_setup_imports VALUES(?,?,?,?,?)",
                (
                    control["control_owner_id"],
                    control["enrollment_id"],
                    control["generation"],
                    canonical_json(control),
                    content_hash(control),
                ),
            )
            return control

    def begin_macos_file_access_dispatch(self, task_id, transport_request_hash, *, now_ms):
        from .product_store_capability_grants import control_usages_settled as _usage_settled
        from .product_store_file_access_records import _control_at, _document, _outcome_at

        store = cast(Any, self)
        digest(transport_request_hash, "Darwin transport identity")
        with store._connection(write=True) as connection:
            claim = _document(
                connection.execute(
                    "SELECT * FROM file_access_task_claims WHERE task_id=?", (task_id,)
                ).fetchone()
            )
            job_id = claim["job_id"]
            operation = connection.execute(
                "SELECT * FROM file_access_operations WHERE job_id=?", (job_id,)
            ).fetchone()
            original = _document(operation)
            prepared_row = connection.execute(
                "SELECT * FROM file_access_preparations WHERE job_id=?", (job_id,)
            ).fetchone()
            prepared = _document(prepared_row)
            prior = _control_at(connection, operation["control_owner_id"])["document"]
            enrolled = _document(
                connection.execute(
                    "SELECT * FROM file_access_enrollments WHERE enrollment_id=?",
                    (operation["enrollment_id"],),
                ).fetchone()
            )
            validate_preparation(operation, original, prepared, enrolled, prior, now_ms)
            job = store._job_from_row(
                connection.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone()
            )
            require(
                job["state"] in ("queued", "running")
                and not job["progress"].get("stopped")
                and _outcome_at(connection, job_id) is None
                and _usage_settled(store, connection, operation["control_owner_id"])
                and execution_task_identity(claim["manifest"], claim["runner_profile"])
                == (task_id, transport_request_hash)
                and claim["transport_request_hash"] == transport_request_hash
                and claim["manifest"] == prepared["manifest"]
                and claim["runner_profile"] == prepared["runner_profile"]
                and not connection.execute(
                    "SELECT 1 FROM file_access_task_terminals WHERE task_id=?", (task_id,)
                ).fetchone()
                and not connection.execute(
                    "SELECT 1 FROM file_access_task_evidence WHERE task_id=?", (task_id,)
                ).fetchone()
            )
            body = {
                "schema_version": "bluefire.macos-file-access-committed-task.v1",
                "intent": intent_document(prepared, task_id, transport_request_hash),
                "claim": claim,
                "preparation_digest": prepared_row["document_digest"],
                "job_id": job_id,
                "attempt": None,
                "cancelled": False,
            }
            frame = {**body, "dispatch_digest": content_hash(body)}
            connection.execute(
                "INSERT INTO file_access_task_evidence VALUES(?,?,?,?)",
                (task_id, "macos_dispatch", canonical_json(frame), content_hash(frame)),
            )
            return frame


def has_dispatch(store, job_id):
    with store._connection() as connection:
        return (
            connection.execute(
                "SELECT 1 FROM file_access_task_evidence e JOIN file_access_task_claims t ON t.task_id=e.task_id "
                "WHERE t.job_id=? AND e.stage='macos_dispatch' LIMIT 1",
                (job_id,),
            ).fetchone()
            is not None
        )


def build_preparation(job_id, run_id, operation, reviewed, now_ms, now_ns):
    creator = reviewed["review_context"]["creator_context"]
    body = {
        "schema_version": "bluefire.macos-file-access-task.v1",
        "run_id": run_id,
        "step_id": operation,
        "action_id": "macos.file_access." + operation + ".v1",
        "params": {},
        "approval": {"review_digest": reviewed["review"]["review_digest"]},
    }
    profile = {
        "schema_version": "bluefire.macos-file-access-task-profile.v1",
        "macos_file_access_binding": creator["binding"],
    }
    return {
        "schema_version": PREPARATION_SCHEMA,
        "job_id": job_id,
        "operation": operation,
        "run_id": run_id,
        "creator_context": creator,
        "manifest": {**body, "request_hash": content_hash(body)},
        "runner_profile": {**profile, "policy_digest": content_hash(profile)},
        "issued_at_ms": now_ms,
        "expires_at_ms": min(now_ms + 5000, reviewed["review"]["expires_at_ms"]),
        "issued_monotonic_ns": now_ns,
        "deadline_ns": min(now_ns + 5_000_000_000, creator["binding"]["original_deadline_ns"]),
    }
