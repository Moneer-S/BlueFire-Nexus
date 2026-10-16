"""Historical joins for metadata-only macOS attempt closure, not native cleanup."""

from typing import Any, Mapping

from . import product_store_macos_composition as macos
from .capability_packs import MACOS_FILE_ACCESS_PACK, grant_pack
from .capability_resources import digest
from .execution_contracts import execution_task_identity
from .macos_file_access_intent import ReviewedMacOSTaskIntent
from .macos_file_access_method import validate_closure, validate_metadata, validate_read_receipt
from .product_store_capability_cleanup import workspace_at
from .product_store_capability_dependencies import dependency_at
from .product_store_capability_grants import _attempt_at, _claim_at, _document, _grant_at, _one
from .product_store_errors import ProductStoreError
from .runner_contracts import _canonical_macos_cleanup, seal_manifest, seal_profile
from .util import content_hash

SCHEMA = "bluefire.macos-composition-attempt-settlement.v1"


def _authenticated_result(value, payload, terminal_digest):
    result = macos._result_document(value)
    manifest, profile = payload["manifest"], payload["runner_profile"]
    if (
        content_hash(result) != terminal_digest
        or result.get("schema_version") != "bluefire.runner-result.v1"
        or result.get("status") != "success"
        or any(
            result.get(key) != manifest[key]
            for key in (
                "request_id",
                "run_id",
                "step_id",
                "behavior_id",
                "action_id",
                "runner_id",
                "runner_profile_id",
                "request_hash",
            )
        )
        or result.get("platform") != profile["platform"]
        or result.get("policy_digest") != profile["policy_digest"]
        or result.get("receipt_ids") != []
        or result.get("error") is not None
    ):
        raise ProductStoreError(
            "The retained macOS result differs from its authenticated terminal."
        )
    return result


def _reservation(reservation, lease, compiled, dependency, workspace, binding):
    fixed = {
        "schema_version": "bluefire.macos-file-access-attempt-dispatch.v1",
        **{
            key: lease[key]
            for key in (
                "attempt_id",
                "grant_id",
                "grant_digest",
                "lease_digest",
                "compiled_digest",
                "job_id",
                "run_id",
                "control_owner_id",
            )
        },
        "workspace_binding_digest": content_hash(workspace),
        "dependency_digest": content_hash(dependency),
        **{
            key: compiled["macos_file_access"][key]
            for key in (
                "probe_step_id",
                "owner_step_id",
                "cleanup_step_id",
            )
        },
        "business_expires_at_ms": min(lease["business_expires_at_ms"], binding["expires_at_ms"]),
        "cleanup_expires_at_ms": min(lease["attempt_expires_at_ms"], binding["expires_at_ms"]),
        "primitive_budget": {"probe": 1, "verify_owner": 1, "total": 2},
    }
    timing = {"issued_at_ms", "issued_monotonic_ns", "business_deadline_ns", "cleanup_deadline_ns"}
    if (
        set(reservation) != set(fixed) | timing
        or any(reservation[key] != value for key, value in fixed.items())
        or any(type(reservation[key]) is not int for key in timing)
        or any(type(value) is not int for value in reservation["primitive_budget"].values())
        or not max(lease["created_at_ms"], binding["issued_at_ms"])
        <= reservation["issued_at_ms"]
        < fixed["business_expires_at_ms"]
        < fixed["cleanup_expires_at_ms"]
        or not 0
        < reservation["issued_monotonic_ns"]
        < reservation["business_deadline_ns"]
        < reservation["cleanup_deadline_ns"]
        <= binding["original_deadline_ns"]
    ):
        raise ProductStoreError("The macOS reservation differs from its original authority.")
    actions = macos._step_actions(compiled)
    for operation, field in (
        ("probe", "probe_step_id"),
        ("verify_owner", "owner_step_id"),
        ("close_attempt", "cleanup_step_id"),
    ):
        if actions.get(fixed[field]) != macos._ACTIONS[operation]:
            raise ProductStoreError("The macOS reserved graph changed.")


def _task_payload(store, connection, task, lease, compiled, reservation, binding):
    close = task["step_id"] == reservation["cleanup_step_id"]
    payload = macos._payload_at(
        store, connection, task, lease, compiled, purpose="macos_cleanup" if close else "business"
    )
    manifest, profile = payload["manifest"], payload["runner_profile"]
    operation = next(
        (
            operation
            for operation, field in (
                ("probe", "probe_step_id"),
                ("verify_owner", "owner_step_id"),
                ("close_attempt", "cleanup_step_id"),
            )
            if task["step_id"] == reservation[field]
        ),
        None,
    )
    if (
        operation is None
        or profile.get("macos_file_access_binding") != binding
        or seal_profile(profile) != profile
        or seal_manifest(manifest) != manifest
        or manifest["action_id"] != macos._ACTIONS[operation]
        or manifest["step_id"] != task["step_id"]
        or manifest["request_hash"] != task["request_hash"]
        or execution_task_identity(manifest, profile)
        != (task["task_id"], payload["transport_request_hash"])
    ):
        raise ProductStoreError("The historical macOS task payload changed.")
    dispatch = macos._event(connection, task["attempt_id"], "dispatch", task["task_id"])
    receipt = (
        None if close else macos._event(connection, task["attempt_id"], "receipt", task["step_id"])
    )
    if (
        not close
        and receipt is not None
        and (
            receipt.get("task_id") != task["task_id"]
            or receipt.get("request_hash") != task["request_hash"]
            or receipt.get("transport_request_hash") != payload["transport_request_hash"]
        )
    ):
        raise ProductStoreError("The historical macOS receipt changed its task identity.")
    if not close and receipt is not None and receipt["state"] == "not_sent":
        result = macos._result_document(receipt.get("result"))
        if (
            dispatch is not None
            or result
            != {
                "schema_version": "bluefire.task-not-sent.v1",
                "task_id": task["task_id"],
                "request_hash": task["request_hash"],
            }
            or content_hash(result) != receipt["terminal_digest"]
        ):
            raise ProductStoreError("An attempted macOS task cannot become not-sent.")
        return payload, dispatch
    if not isinstance(dispatch, dict):
        raise ProductStoreError("The macOS task lacks its committed dispatch marker.")
    intent = ReviewedMacOSTaskIntent.from_document(dispatch.get("intent")).document()
    fixed = {
        "schema_version": "bluefire.macos-file-access-dispatch-marker.v1",
        "attempt_id": task["attempt_id"],
        "task_id": task["task_id"],
        "step_id": task["step_id"],
        "request_hash": task["request_hash"],
        "transport_request_hash": payload["transport_request_hash"],
        "operation": operation,
        "intent": intent,
        "creator_context_digest": intent["context_digest"],
        "marked_at_ms": intent["issued_at_ms"],
        "marked_monotonic_ns": intent["issued_monotonic_ns"],
    }
    if (
        dispatch != fixed
        or intent["task_id"] != task["task_id"]
        or intent["transport_request_hash"] != payload["transport_request_hash"]
        or intent["operation"] != operation
        or intent["binding_digest"] != content_hash(binding)
        or intent["control_revision"] != binding["control_revision"]
        or not reservation["issued_at_ms"]
        <= intent["issued_at_ms"]
        < intent["expires_at_ms"]
        <= reservation["cleanup_expires_at_ms" if close else "business_expires_at_ms"]
        or not reservation["issued_monotonic_ns"]
        <= intent["issued_monotonic_ns"]
        < intent["deadline_ns"]
        <= reservation["cleanup_deadline_ns" if close else "business_deadline_ns"]
    ):
        raise ProductStoreError("The historical macOS dispatch changed its original request.")
    if not close and (
        receipt is None
        or receipt["state"] != "complete"
        or receipt["request_hash"] != task["request_hash"]
        or receipt["transport_request_hash"] != payload["transport_request_hash"]
    ):
        raise ProductStoreError("The original macOS business receipt changed.")
    if not close:
        result = _authenticated_result(receipt.get("result"), payload, receipt["terminal_digest"])
        output = result.get("output")
        if not isinstance(output, dict) or set(output) != {"macos_receipt", "observation"}:
            raise ProductStoreError("The historical macOS read output changed.")
        native = validate_read_receipt(output["macos_receipt"], intent, binding)
        metadata = validate_metadata(output["observation"], native)
        probe = macos._event(
            connection, task["attempt_id"], "receipt", reservation["probe_step_id"]
        )
        if (
            content_hash(native) != receipt["native_receipt_digest"]
            or content_hash(metadata) != receipt["observation_digest"]
            or native["shared_request_budget_used"] != receipt.get("shared_request_budget_used")
            or metadata["attempt_id"] != task["attempt_id"]
            or metadata["run_id"] != lease["run_id"]
            or metadata["step_id"] != task["step_id"]
            or metadata["request_hash"] != task["request_hash"]
            or metadata["binding"] != binding
            or metadata["intent"] != intent
            or metadata["probe_task_id"]
            != (task["task_id"] if operation == "probe" else probe["task_id"])
            or metadata["probe_receipt_digest"]
            != (None if operation == "probe" else probe["native_receipt_digest"])
        ):
            raise ProductStoreError("The original macOS read receipt or observation changed.")
    return payload, dispatch


def _expected(store, connection, attempt_id) -> dict[str, Any]:
    _, lease, compiled = _attempt_at(connection, attempt_id)
    _, grant, _ = _grant_at(connection, lease["grant_id"])
    if grant_pack(grant) != MACOS_FILE_ACCESS_PACK:
        raise ProductStoreError("The macOS closure belongs to another capability pack.")
    _claim_at(connection, attempt_id, lease)
    if any(
        connection.execute(f"SELECT 1 FROM {table} WHERE attempt_id=?", (attempt_id,)).fetchone()
        for table in (
            "capability_cleanup_obligations",
            "capability_cleanup_claims",
            "capability_cleanup_task_claims",
        )
    ):
        raise ProductStoreError("Metadata-only macOS closure cannot omit native cleanup authority.")
    dependency = dependency_at(connection, attempt_id, lease)
    expected_dependency = macos._mac_dependency(compiled)
    _, _, original_binding = macos._original_macos_control(connection, expected_dependency)
    if dependency != {
        "schema_version": "bluefire.capability-macos-file-access-binding.v1",
        "attempt_id": attempt_id,
        "lease_digest": lease["lease_digest"],
        **{
            key: expected_dependency[key]
            for key in (
                "binding_digest",
                "resource_generation",
                "control_revision",
                "resource_digest",
                "workspace_custody_digest",
            )
        },
    }:
        raise ProductStoreError("The original macOS retained dependency changed.")
    reservation = _document(
        _one(
            connection,
            "SELECT * FROM capability_macos_file_access_attempts WHERE attempt_id=?",
            attempt_id,
        )
    )
    workspace = workspace_at(connection, attempt_id, lease)
    _reservation(reservation, lease, compiled, dependency, workspace, original_binding)
    closure = _document(
        _one(
            connection,
            "SELECT * FROM capability_macos_file_access_closures WHERE attempt_id=?",
            attempt_id,
        )
    )
    task_id = closure["cleanup_task_id"]
    producer = macos._event(connection, attempt_id, "producer_closure", task_id)
    claim = macos._event(connection, attempt_id, "cleanup_claim", "close_attempt")
    dispatch = macos._event(connection, attempt_id, "dispatch", task_id)
    if producer is None or claim is None or dispatch is None:
        raise ProductStoreError("The macOS attempt closure has incomplete original provenance.")
    if (
        set(claim) != {"claim", "claim_digest", "task_closures"}
        or _canonical_macos_cleanup(claim["claim"]) != claim["claim"]
        or content_hash(claim["claim"]) != claim["claim_digest"]
    ):
        raise ProductStoreError("The retained macOS cleanup claim changed.")
    raw = validate_closure(producer["closure"])
    tasks = connection.execute(
        "SELECT * FROM capability_task_claims WHERE attempt_id=? ORDER BY task_id", (attempt_id,)
    ).fetchall()
    terminals = []
    close_task = None
    close_payload = None
    for task in tasks:
        payload, task_dispatch = _task_payload(
            store, connection, task, lease, compiled, reservation, original_binding
        )
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
            or terminal["schema_version"] != "bluefire.capability-task-terminal.v1"
        ):
            raise ProductStoreError("The original macOS task terminal changed.")
        terminals.append(terminal)
        if task["task_id"] == task_id:
            close_task = task
            close_payload = payload
            if task_dispatch != dispatch:
                raise ProductStoreError("The macOS close task dispatch changed.")
    if (
        close_task is None
        or close_payload is None
        or close_task["step_id"] != expected_dependency["cleanup_step_id"]
    ):
        raise ProductStoreError("The exact macOS close task is missing.")
    payload = close_payload
    result = _authenticated_result(producer.get("result"), payload, producer["terminal_digest"])
    if result.get("output") != {"attempt_closure": raw}:
        raise ProductStoreError(
            "The authenticated macOS terminal contains another producer closure."
        )
    task_closures = macos._task_closures(connection, attempt_id, reservation)
    cleanup_claim = claim["claim"]
    if (
        any(
            cleanup_claim[key] != lease[key]
            for key in ("attempt_id", "lease_digest", "compiled_digest", "run_id")
        )
        or cleanup_claim["cleanup_step_id"] != expected_dependency["cleanup_step_id"]
        or not reservation["issued_at_ms"]
        <= cleanup_claim["issued_at_ms"]
        <= dispatch["intent"]["issued_at_ms"]
        < dispatch["intent"]["expires_at_ms"]
        <= cleanup_claim["expires_at_ms"]
        <= reservation["cleanup_expires_at_ms"]
        or not reservation["issued_monotonic_ns"]
        <= cleanup_claim["issued_monotonic_ns"]
        <= dispatch["intent"]["issued_monotonic_ns"]
        < dispatch["intent"]["deadline_ns"]
        <= cleanup_claim["deadline_ns"]
        <= reservation["cleanup_deadline_ns"]
        or payload["manifest"].get("macos_file_access_cleanup") != cleanup_claim
    ):
        raise ProductStoreError(
            "The macOS closure changed its independent original cleanup allowance."
        )
    proofs = [
        macos._event(connection, attempt_id, event, key)
        for event, key in (
            ("workspace_reserved", attempt_id),
            ("workspace_pre_close", task_id),
            ("workspace_post_close", task_id),
        )
    ]
    identity = None
    for phase, proof in zip(("reserve", "pre_close", "post_close"), proofs, strict=True):
        if (
            not isinstance(proof, dict)
            or set(proof)
            != {
                "schema_version",
                "attempt_id",
                "lease_digest",
                "compiled_digest",
                "workspace_path_digest",
                "workspace_identity_digest",
                "phase",
                "entry_count",
                "state",
            }
            or proof
            != {
                "schema_version": "bluefire.macos-file-access-empty-workspace.v1",
                "attempt_id": attempt_id,
                "lease_digest": lease["lease_digest"],
                "compiled_digest": compiled["compiled_digest"],
                "workspace_path_digest": workspace["workspace_path_digest"],
                "workspace_identity_digest": proof.get("workspace_identity_digest"),
                "phase": phase,
                "entry_count": 0,
                "state": "verified_empty",
            }
            or type(proof["entry_count"]) is not int
        ):
            raise ProductStoreError("The original empty-workspace inventory proof changed.")
        digest(proof["workspace_identity_digest"], "original macOS workspace identity")
        if identity is not None and proof["workspace_identity_digest"] != identity:
            raise ProductStoreError("The macOS attempt changed its original directory identity.")
        identity = proof["workspace_identity_digest"]
    macos._validate_closure_budget(connection, attempt_id, reservation, raw)
    checks = {
        "schema_version": "bluefire.macos-file-access-settlement.v1",
        "attempt_id": attempt_id,
        "lease_digest": lease["lease_digest"],
        "compiled_digest": compiled["compiled_digest"],
        "cleanup_task_id": task_id,
        "cleanup_claim_digest": claim["claim_digest"],
        "cleanup_dispatch_digest": content_hash(dispatch),
        "cleanup_terminal_digest": producer["terminal_digest"],
        "closure_digest": content_hash(raw),
        "workspace_attestation_digest": content_hash(proofs[2]),
        "pre_close_workspace_attestation_digest": content_hash(proofs[1]),
        "workspace_binding_digest": content_hash(workspace),
        "task_closures_digest": content_hash(task_closures),
        "artifact_state": "not_created",
        "producer_scope": "attempt_artifact_closure_only",
    }
    if closure != checks or (
        raw["attempt_id"] != attempt_id
        or raw["lease_digest"] != lease["lease_digest"]
        or raw["compiled_digest"] != compiled["compiled_digest"]
        or raw["run_id"] != lease["run_id"]
        or raw["cleanup_task_id"] != task_id
        or raw["task_closures"] != task_closures
        or claim["task_closures"] != task_closures
        or raw["cleanup_claim_digest"] != claim["claim_digest"]
        or raw["binding_digest"] != dependency["binding_digest"]
        or raw["control_revision"] != dependency["control_revision"]
        or raw["cleanup_transport_request_hash"] != payload["transport_request_hash"]
        or producer["closure_digest"] != content_hash(raw)
        or producer.get("schema_version") != "bluefire.macos-file-access-producer-closure.v1"
        or producer.get("attempt_id") != attempt_id
        or producer.get("task_id") != task_id
        or producer["terminal_digest"]
        != next(t["terminal_digest"] for t in terminals if t["task_id"] == task_id)
    ):
        raise ProductStoreError(
            "The macOS closure does not join its exact tasks and original workspace."
        )
    return {
        "schema_version": SCHEMA,
        "attempt_id": attempt_id,
        "lease_digest": lease["lease_digest"],
        "run_id": lease["run_id"],
        "macos_closure_digest": content_hash(closure),
        "task_terminals_digest": content_hash(terminals),
    }


def receipt(store, attempt_id) -> dict[str, Any]:
    with store._connection() as connection:
        return _expected(store, connection, attempt_id)


def validate(store, connection, attempt_id, value: Mapping[str, Any]) -> dict[str, Any]:
    expected = _expected(store, connection, attempt_id)
    if value != expected:
        raise ProductStoreError("The metadata-only macOS settlement changed.")
    return expected
