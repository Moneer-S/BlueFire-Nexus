"""Darwin validators and adapters on the original owner-workspace journal.

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
from .macos_file_access_creator import ReviewedMacOSTaskIntent
from .product_store_errors import ProductStoreError
from .product_store_serialization import canonical_json
from .util import canonical_json_bytes, content_hash

SETUP_SCHEMA = "bluefire.macos-file-access-setup.v1"
CONTROL_SCHEMA = "bluefire.macos-file-access-control.v1"
CONTEXT_SCHEMA = "bluefire.macos-file-access-control-context.v1"
PREPARATION_SCHEMA = "bluefire.macos-file-access-preparation.v1"
PLANS = {
    "baseline": ("read_reader", "read_owner"),
    "harden": ("harden",),
    "rollback": ("rollback", "read_reader", "read_owner"),
}


def require(value: bool) -> None:
    if not value:
        raise ProductStoreError("The original committed Darwin operation is unavailable.")


def _require_original_monotonic_deadline(prepared: dict) -> None:
    from .macos_file_access_peer import darwin_clock_ns

    observed = darwin_clock_ns()
    require(
        type(observed) is int
        and prepared["issued_monotonic_ns"] <= observed < prepared["deadline_ns"]
    )


def is_control(value: Any) -> bool:
    return isinstance(value, dict) and value.get("schema_version") == CONTROL_SCHEMA


def permitted(control: dict) -> list[str]:
    return {
        "created": ["baseline"],
        "baseline_verified": ["harden"],
        "hardened": ["rollback"],
        "rolled_back": ["baseline", "harden"],
    }.get(control["status"], [])


def endpoint(service):
    from .macos_file_access_workspace_bootstrap import OriginalWorkspaceEndpoint

    current = getattr(service, "_macos_workspace_endpoint", None)
    require(type(current) is OriginalWorkspaceEndpoint)
    current.assert_current()
    return current


def setup_document(value: Any) -> dict:
    exact(value, {"schema_version", "binding"}, "Darwin setup")
    require(value["schema_version"] == SETUP_SCHEMA)
    binding = validate_binding(value["binding"])
    require(binding["control_revision"] == 1 and binding["mode"] == "0640")
    return {"schema_version": SETUP_SCHEMA, "binding": binding}


def enrollment_document(setup: dict) -> dict:
    binding = setup["binding"]
    return {
        "schema_version": "bluefire.macos-file-access-enrollment.v1",
        "enrollment_id": binding["enrollment_id"],
        "expires_at_ms": binding["expires_at_ms"],
        "setup": setup,
    }


def imported_control(setup: dict) -> dict:
    binding = setup["binding"]
    return {
        "schema_version": CONTROL_SCHEMA,
        "control_owner_id": "file-control-" + content_hash(setup)[7:],
        "enrollment_id": binding["enrollment_id"],
        "generation": binding["generation"],
        "revision": 1,
        "status": "created",
        "binding": binding,
        "binding_digest": content_hash(binding),
        "setup_digest": content_hash(setup),
        "baseline": None,
    }


def imported_at(connection, owner_id):
    from .product_store_file_access import _document

    row = connection.execute(
        "SELECT * FROM file_access_setup_imports WHERE control_owner_id=?", (owner_id,)
    ).fetchone()
    if row is None:
        return None
    value = _document(row)
    if not is_control(value):
        return None
    require(
        value["control_owner_id"] == row["control_owner_id"]
        and value["enrollment_id"] == row["enrollment_id"]
        and value["generation"] == row["generation"]
        and value["revision"] == 1
    )
    enrolled = _document(
        connection.execute(
            "SELECT * FROM file_access_enrollments WHERE enrollment_id=?", (row["enrollment_id"],)
        ).fetchone()
    )
    require(value == imported_control(setup_document(enrolled["setup"])))
    return {"document": value, "document_digest": row["document_digest"]}


def import_setup(service, request, now_ms):
    exact(request, {"enrollment_id", "enrollment_digest"}, "Darwin setup selection")
    setup = setup_document(endpoint(service).current_setup())
    enrolled = enrollment_document(setup)
    require(
        request
        == {"enrollment_id": enrolled["enrollment_id"], "enrollment_digest": content_hash(enrolled)}
    )
    return service.product_store.import_macos_file_access_setup(setup, now_ms=now_ms)


def enrollment(service, now_ms):
    setup = setup_document(endpoint(service).current_setup())
    expected = enrollment_document(setup)
    require(now_ms < expected["expires_at_ms"])
    saved = service.product_store.get_file_access_enrollment(expected["enrollment_id"])
    require(saved == {"document": expected, "document_digest": content_hash(expected)})
    return saved


def status(service, now_ms) -> dict[str, Any]:
    try:
        setup = setup_document(endpoint(service).current_setup())
        enrolled = enrollment_document(setup)
        require(now_ms < enrolled["expires_at_ms"])
    except (OSError, ValueError, ProductStoreError):
        return {
            "schema_version": "bluefire.file-access-status.v1",
            "platform": "macos",
            "available": False,
            "problem": {
                "code": "file_access_enrollment_unavailable",
                "message": "The original protected macOS workspace is required.",
            },
            "enrollment": None,
            "allowed_operations": [],
        }
    return {
        "schema_version": "bluefire.file-access-status.v1",
        "platform": "macos",
        "available": True,
        "problem": None,
        "enrollment": {
            "enrollment_id": enrolled["enrollment_id"],
            "enrollment_digest": content_hash(enrolled),
            "expires_at_ms": enrolled["expires_at_ms"],
            "owner_uid": setup["binding"]["owner"]["effective_uid"],
            "probe_uid": setup["binding"]["reader"]["effective_uid"],
        },
        "allowed_operations": [],
    }


def context(service, operation, owner_id, now_ms):
    require(operation in PLANS)
    enrolled = enrollment(service, now_ms)
    control = service.product_store.get_file_access_control(owner_id)
    require(is_control(control["document"]) and operation in permitted(control["document"]))
    creator = endpoint(service).review_context(operation)
    exact(
        creator,
        {"schema_version", "operation", "state", "binding", "probe_digest", "context_digest"},
        "Darwin creator context",
    )
    require(
        creator["schema_version"] == "bluefire.macos-file-access-creator-context.v1"
        and creator["operation"] == operation
        and creator["binding"] == control["document"]["binding"]
        and creator["context_digest"]
        == content_hash({k: v for k, v in creator.items() if k != "context_digest"})
    )
    reviewed = {
        "schema_version": CONTEXT_SCHEMA,
        "operation": operation,
        "enrollment_digest": enrolled["document_digest"],
        "control_digest": control["document_digest"],
        "creator_context": creator,
    }
    return {
        "enrollment": enrolled,
        "control": control,
        "review_context": reviewed,
        "context_digest": content_hash(reviewed),
        "expires_at_ms": enrolled["document"]["expires_at_ms"],
        "allowed_operations": permitted(control["document"]),
    }


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
    from .product_store_file_access import _document

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
    from .product_store_file_access import _document

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
    from .product_store_file_access import _document

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
    from .product_store_file_access import _control_at, _document, _outcome_at

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
        from .product_store_file_access import _document

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
        from .product_store_file_access import _control_at, _document, _outcome_at, _usage_settled

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


def projection(service, view, now_ms) -> dict[str, Any]:
    control = view["document"]
    pending = view["pending_operation"] or not view["usages_settled"]
    live = False
    try:
        live = endpoint(service).review_context("baseline")["binding"] == control["binding"]
    except (OSError, ValueError, ProductStoreError):
        pass
    binding = control["binding"]
    return {
        "schema_version": "bluefire.file-access-control.v1",
        "platform": "macos",
        "control_owner_id": control["control_owner_id"],
        "control_digest": view["document_digest"],
        "revision": control["revision"],
        "status": "uncertain" if pending else control["status"],
        "resource": {
            "resource_id": binding["generation"],
            "resource_generation": binding["generation"],
            "sha256": binding["resource"]["sha256"],
            "size": binding["resource"]["size_bytes"],
            "record_count": binding["resource"]["record_count"],
            "mode": binding["mode"],
        },
        "baseline": control["baseline"],
        "usage_state": "pending" if pending else "settled",
        "allowed_operations": (
            permitted(control) if live and not pending and now_ms < binding["expires_at_ms"] else []
        ),
        "operations": [
            job
            for job in service.product_store.list_jobs()
            if job["kind"] == "file_access.operation"
            and job["request"].get("control_owner_id") == control["control_owner_id"]
        ],
    }


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


def execute(control, ctx, request):
    from .macos_file_access_bridge import MacOSWorkspaceTaskTransport
    from .macos_file_access_peer import darwin_clock_ns

    store = control.store
    task_id = None
    prepared = None
    try:
        ctx.checkpoint()
        op, owner_id = request["review"]["operation"], request["review"]["control_owner_id"]
        current = context(control.service, op, owner_id, control.clock())
        require(current["context_digest"] == request["review"]["context_digest"])
        reviewed = store.file_access_operation_records(ctx.job_id)["document"]
        prepared = build_preparation(
            ctx.job_id,
            control.service.store._new_run_id(),
            op,
            reviewed,
            control.clock(),
            darwin_clock_ns(),
        )
        store.prepare_file_access_operation(ctx.job_id, prepared, now_ms=control.clock())
        manifest, profile = prepared["manifest"], prepared["runner_profile"]
        task_id, _ = execution_task_identity(manifest, profile)

        def validate_context():
            endpoint(control.service).assert_current()
            require(not ctx.cancellation_event.is_set())

        ctx.checkpoint()
        store.register_file_access_task(
            ctx.job_id,
            task_id=task_id,
            step_id=op,
            manifest=manifest,
            runner_profile=profile,
            now_ms=control.clock(),
            validate_context=validate_context,
        )
        # Task registration has committed before the transport can commit its
        # attempted-dispatch marker and write on the original inherited channel.
        transport = MacOSWorkspaceTaskTransport(endpoint(control.service), store)
        result = transport.execute_task(
            manifest, profile, task_id=task_id, cancel_event=ctx.cancellation_event
        )
        store.record_file_access_task_terminal(
            task_id, request_hash=manifest["request_hash"], result=result
        )
        claim = store.file_access_task_record(
            task_id, execution_task_identity(manifest, profile)[1]
        )["task"]
        receipt = validate_receipt(claim, prepared, result)
        require(receipt["state"] == "complete")
        store.record_file_access_worker_closure(
            task_id,
            request_hash=manifest["request_hash"],
            proof={
                "state": "verified_closed",
                "binding_digest": receipt["binding_digest"],
                "evidence_digest": content_hash(receipt),
            },
        )
        ctx.checkpoint()
        endpoint(control.service).assert_current()
        _require_original_monotonic_deadline(prepared)
        store.finish_file_access_operation(
            ctx.job_id,
            outcome={"state": "complete", "evidence_digest": content_hash(receipt)},
            control=next_control(current["control"]["document"], prepared, receipt),
            now_ms=control.clock(),
        )
        control._publish(ctx.job_id, {"phase": "completed"})
    except BaseException:
        records = store.file_access_operation_records(ctx.job_id)
        if records["outcome"] is None:
            dispatched = has_dispatch(store, ctx.job_id)
            if not dispatched:
                for row in records["tasks"]:
                    claim = row["task"]
                    not_sent = {
                        "schema_version": "bluefire.task-not-sent.v1",
                        "task_id": claim["task_id"],
                        "request_hash": claim["request_hash"],
                    }
                    store.record_file_access_task_terminal(
                        claim["task_id"], request_hash=claim["request_hash"], result=not_sent
                    )
                    store.record_file_access_worker_closure(
                        claim["task_id"],
                        request_hash=claim["request_hash"],
                        proof={
                            "state": "not_sent",
                            "binding_digest": content_hash(
                                claim["runner_profile"]["macos_file_access_binding"]
                            ),
                            "evidence_digest": content_hash(not_sent),
                        },
                    )
            store.finish_file_access_operation(
                ctx.job_id,
                outcome={
                    "state": "unknown" if dispatched else "refused_no_effect",
                    "evidence_digest": content_hash(records["tasks"]),
                },
            )
        control._publish(
            ctx.job_id,
            {"phase": "uncertain" if has_dispatch(store, ctx.job_id) else "not_dispatched"},
        )
        raise
