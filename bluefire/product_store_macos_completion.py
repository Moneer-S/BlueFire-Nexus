"""Terminal acceptance and closure with the owner journal supplied by its wrappers.

Dynamic module lookups retain the original clock, validation and journal hooks
without importing the caller back into this persistence helper.
"""

from __future__ import annotations

from contextlib import nullcontext
from types import ModuleType
from typing import Any, Mapping

from . import product_store_capability_cleanup as cleanup
from . import product_store_capability_grants as records
from .capability_resources import digest
from .product_store_errors import ProductStoreError
from .product_store_serialization import canonical_json
from .util import content_hash, json_clone


def claim_macos_capability_cleanup(
    store, attempt_id: str, *, journal: ModuleType, now_ms: int, now_monotonic_ns: int
) -> dict[str, Any]:
    now_ms, now_monotonic_ns = journal._time_pair(now_ms, now_monotonic_ns, "cleanup claim")
    with store._connection(write=True) as connection:
        reservation_row = records._one(
            connection,
            "SELECT * FROM capability_macos_file_access_attempts WHERE attempt_id=?",
            attempt_id,
        )
        reservation = records._document(reservation_row)
        _, lease, compiled = records._attempt_at(connection, attempt_id)
        records._claim_at(connection, attempt_id, lease)
        journal._step_actions(compiled)
        if (
            now_ms < reservation["issued_at_ms"]
            or now_monotonic_ns < reservation["issued_monotonic_ns"]
            or now_ms < records._lineage_time(connection, lease["lineage_id"])
            or now_ms >= reservation["cleanup_expires_at_ms"]
            or now_monotonic_ns >= reservation["cleanup_deadline_ns"]
            or connection.execute(
                "SELECT 1 FROM capability_attempt_settlements WHERE attempt_id=?", (attempt_id,)
            ).fetchone()
        ):
            raise ProductStoreError(
                "Darwin attempt-closure authority is expired or already settled."
            )
        if connection.execute(
            "SELECT 1 FROM capability_task_claims WHERE attempt_id=? AND step_id=?",
            (attempt_id, reservation["cleanup_step_id"]),
        ).fetchone():
            raise ProductStoreError(
                "The Mac closure step was registered without its dedicated claim."
            )
        closures = journal._task_closures(connection, attempt_id, reservation)
        claim = {
            "schema_version": journal._CLEANUP_SCHEMA,
            "attempt_id": attempt_id,
            "lease_digest": lease["lease_digest"],
            "compiled_digest": lease["compiled_digest"],
            "run_id": lease["run_id"],
            "cleanup_step_id": reservation["cleanup_step_id"],
            "issued_at_ms": now_ms,
            "expires_at_ms": reservation["cleanup_expires_at_ms"],
            "issued_monotonic_ns": now_monotonic_ns,
            "deadline_ns": reservation["cleanup_deadline_ns"],
            "scope": "attempt_artifact_closure_only",
        }
        digest_value = content_hash(claim)
        event = {"claim": claim, "claim_digest": digest_value, "task_closures": closures}
        previous = journal._event(connection, attempt_id, "cleanup_claim", "close_attempt")
        if previous is not None:
            if previous != event:
                raise ProductStoreError("Darwin attempt-closure authority is already immutable.")
            return {"document": claim, "document_digest": digest_value}
        journal._append(
            connection,
            "capability_macos_file_access_events",
            attempt_id,
            "cleanup_claim",
            "close_attempt",
            event,
        )
        return {"document": claim, "document_digest": digest_value}


def register_macos_capability_cleanup_task(
    store,
    attempt_id: str,
    *,
    journal: ModuleType,
    task_id: str,
    step_id: str,
    request_hash: str,
    expected_document_digest: str,
    now_ms: int,
    now_monotonic_ns: int,
    manifest: Mapping[str, Any],
    runner_profile: Mapping[str, Any],
) -> dict[str, Any]:
    """Register only the distinct attempt-closure task, using the normal runner payload journal."""
    records.identifier(task_id, "Mac attempt-closure task")
    digest(request_hash, "Mac attempt-closure request")
    digest(expected_document_digest, "Mac attempt-closure claim")
    now_ms, now_monotonic_ns = journal._time_pair(
        now_ms, now_monotonic_ns, "attempt-closure registration"
    )
    if not isinstance(manifest, Mapping) or not isinstance(runner_profile, Mapping):
        raise ProductStoreError("The exact Mac attempt-closure manifest and profile are required.")
    from .execution_contracts import execution_task_identity
    from .product_store_capability_transport import insert_payload, payload_document

    with store._connection(write=True) as connection:
        _, lease, compiled = records._attempt_at(connection, attempt_id)
        records._claim_at(connection, attempt_id, lease)
        reservation_row = records._one(
            connection,
            "SELECT * FROM capability_macos_file_access_attempts WHERE attempt_id=?",
            attempt_id,
        )
        reservation = records._document(reservation_row)
        dependency = journal._mac_dependency(compiled)
        if step_id != reservation["cleanup_step_id"]:
            raise ProductStoreError("The Mac closure task differs from its compiled cleanup step.")
        actions = journal._step_actions(compiled)
        if actions.get(step_id) != journal._ACTIONS["close_attempt"]:
            raise ProductStoreError("The compiled Mac closure action changed.")
        cleanup_event = journal._event(connection, attempt_id, "cleanup_claim", "close_attempt")
        if (
            cleanup_event is None
            or cleanup_event["claim_digest"] != expected_document_digest
            or content_hash(cleanup_event["claim"]) != expected_document_digest
            or manifest.get("macos_file_access_cleanup") != cleanup_event["claim"]
            or "grant_attempt" in manifest
            or "grant_cleanup" in manifest
            or manifest.get("approval") is not None
            or manifest.get("run_id") != lease["run_id"]
            or manifest.get("step_id") != step_id
            or manifest.get("action_id") != journal._ACTIONS["close_attempt"]
            or manifest.get("params") != {}
            or manifest.get("platform") != "macos"
            or runner_profile.get("platform") != "macos"
            or runner_profile.get("macos_file_access_binding") is None
            or runner_profile.get("macos_file_access_binding")
            != journal._original_macos_control(connection, dependency)[2]
            or now_ms < cleanup_event["claim"]["issued_at_ms"]
            or now_ms >= cleanup_event["claim"]["expires_at_ms"]
            or now_monotonic_ns < cleanup_event["claim"]["issued_monotonic_ns"]
            or now_monotonic_ns >= cleanup_event["claim"]["deadline_ns"]
            or now_ms < records._lineage_time(connection, lease["lineage_id"])
            or connection.execute(
                "SELECT 1 FROM capability_attempt_settlements WHERE attempt_id=?", (attempt_id,)
            ).fetchone()
        ):
            raise ProductStoreError(
                "The exact Mac attempt-closure claim is unavailable or changed."
            )
        journal._task_closures(connection, attempt_id, reservation)
        if (
            connection.execute(
                "SELECT 1 FROM capability_task_claims WHERE task_id=? OR (attempt_id=? AND step_id=?)",
                (task_id, attempt_id, step_id),
            ).fetchone()
            or connection.execute(
                "SELECT 1 FROM capability_cleanup_task_claims WHERE task_id=?", (task_id,)
            ).fetchone()
        ):
            raise ProductStoreError("The Mac attempt-closure task or step was already registered.")
        claim_row, claim = records._claim_at(connection, attempt_id, lease)
        workspace = cleanup.workspace_at(connection, attempt_id, lease)
        retained_dependency = store._capability_dependency_at(connection, attempt_id, lease)
        identity = execution_task_identity(manifest, runner_profile)
        if identity[0] != task_id or manifest.get("request_hash") != request_hash:
            raise ProductStoreError("The Mac attempt-closure transport identity changed.")
        payload = payload_document(
            purpose="macos_cleanup",
            task_id=task_id,
            attempt_id=attempt_id,
            lease=lease,
            step_id=step_id,
            request_hash=request_hash,
            manifest=manifest,
            runner_profile=runner_profile,
            attempt_claim=claim,
            attempt_claim_digest=claim_row["document_digest"],
            workspace=workspace,
            dependency=retained_dependency,
            macos_cleanup_claim=cleanup_event["claim"],
            macos_cleanup_claim_digest=cleanup_event["claim_digest"],
        )
        if identity[1] != payload["transport_request_hash"]:
            raise ProductStoreError("The Mac attempt-closure payload identity changed.")
        connection.execute(
            "INSERT INTO capability_task_claims VALUES(?,?,?,?,?)",
            (task_id, attempt_id, step_id, request_hash, now_ms),
        )
        insert_payload(connection, purpose="macos_cleanup", task_id=task_id, document=payload)
        registration = {
            "task_id": task_id,
            "step_id": step_id,
            "request_hash": request_hash,
            "transport_request_hash": payload["transport_request_hash"],
            "cleanup_claim_digest": expected_document_digest,
            "payload_digest": content_hash(payload),
        }
        journal._append(
            connection,
            "capability_macos_file_access_events",
            attempt_id,
            "cleanup_task_registered",
            task_id,
            registration,
        )
        return {
            "task_id": task_id,
            "attempt_id": attempt_id,
            "step_id": step_id,
            "request_hash": request_hash,
            "transport_request_hash": payload["transport_request_hash"],
            "payload_digest": content_hash(payload),
        }


def record_macos_capability_terminal(
    store, task_id: str, *, journal: ModuleType, result: Mapping[str, Any]
) -> dict[str, Any]:
    from . import macos_file_access_method as method

    result = journal._result_document(result)
    with store._connection(write=True) as connection:
        task = records._one(
            connection, "SELECT * FROM capability_task_claims WHERE task_id=?", task_id
        )
        attempt_id = task["attempt_id"]
        reservation = records._document(
            records._one(
                connection,
                "SELECT * FROM capability_macos_file_access_attempts WHERE attempt_id=?",
                attempt_id,
            )
        )
        _, lease, compiled = records._attempt_at(connection, attempt_id)
        operation = next(
            (
                name
                for name, step in (
                    ("probe", reservation["probe_step_id"]),
                    ("verify_owner", reservation["owner_step_id"]),
                    ("close_attempt", reservation["cleanup_step_id"]),
                )
                if step == task["step_id"]
            ),
            None,
        )
        if operation is None:
            raise ProductStoreError("The terminal belongs to an unexpected Darwin task.")
        payload_purpose = "macos_cleanup" if operation == "close_attempt" else "business"
        payload = journal._payload_at(
            store, connection, task, lease, compiled, purpose=payload_purpose
        )
        execution_task_hash = payload["transport_request_hash"]
        terminal = records._document(
            records._one(
                connection,
                "SELECT * FROM capability_task_terminals WHERE task_id=?",
                task_id,
            )
        )
        terminal_digest = content_hash(result)
        if (
            terminal["attempt_id"] != attempt_id
            or terminal["request_hash"] != task["request_hash"]
            or terminal["terminal_digest"] != terminal_digest
            or result.get("request_hash") != task["request_hash"]
        ):
            raise ProductStoreError(
                "The runner result differs from its authenticated task terminal."
            )
        if operation == "close_attempt":
            frame_event = journal._event(connection, attempt_id, "dispatch", task_id)
            if (
                frame_event is None
                or frame_event["transport_request_hash"] != execution_task_hash
                or result.get("status") != "success"
            ):
                raise ProductStoreError("The close task has no committed dispatch boundary.")
            output = result.get("output")
            if not isinstance(output, Mapping) or set(output) != {"attempt_closure"}:
                raise ProductStoreError(
                    "The Mac closure result cannot carry native receipt output."
                )
            closure = output["attempt_closure"]
            validated = method.validate_closure(closure)
            cleanup_event = journal._event(connection, attempt_id, "cleanup_claim", "close_attempt")
            if cleanup_event is None:
                raise ProductStoreError("The retained Darwin cleanup authority is absent.")
            expected_closures = cleanup_event["task_closures"]
            journal._validate_closure_budget(connection, attempt_id, reservation, validated)
            checks = {
                "attempt_id": attempt_id,
                "lease_digest": lease["lease_digest"],
                "compiled_digest": lease["compiled_digest"],
                "run_id": lease["run_id"],
                "cleanup_task_id": task_id,
                "cleanup_transport_request_hash": frame_event["transport_request_hash"],
                "cleanup_claim_digest": cleanup_event["claim_digest"],
                "task_closures": expected_closures,
                "control_revision": journal._mac_dependency(compiled)["control_revision"],
                "state": "closed",
                "producer_request_usage": "settled",
                "attempt_artifacts": "not_created",
                "original_workers": "retained",
                "namespace": "original_creator_held",
                "whole_enrollment_cleanup": False,
            }
            if any(validated.get(key) != value for key, value in checks.items()):
                raise ProductStoreError(
                    "The original producer closure differs from retained tasks."
                )
            close_document = {
                "schema_version": "bluefire.macos-file-access-producer-closure.v1",
                "attempt_id": attempt_id,
                "task_id": task_id,
                "terminal_digest": terminal_digest,
                "closure": validated,
                "closure_digest": content_hash(validated),
                "result": result,
            }
            with journal._success_acceptance(
                frame_event,
                payload["runner_profile"]["macos_file_access_binding"],
                cleanup_event["claim"],
            ):
                previous = journal._event(connection, attempt_id, "producer_closure", task_id)
                if previous is not None:
                    if previous != close_document:
                        raise ProductStoreError(
                            "The original Darwin producer closure is immutable."
                        )
                    return close_document
                journal._append(
                    connection,
                    "capability_macos_file_access_events",
                    attempt_id,
                    "producer_closure",
                    task_id,
                    close_document,
                )
                return close_document
        dispatch = journal._event(connection, attempt_id, "dispatch", task_id)
        if dispatch is None and result.get("schema_version") != "bluefire.task-not-sent.v1":
            raise ProductStoreError("The Darwin result has no committed dispatch boundary.")
        if dispatch is not None and dispatch["transport_request_hash"] != execution_task_hash:
            raise ProductStoreError("The Darwin terminal transport identity changed.")
        state = "not_sent"
        native_receipt_digest = None
        observation_digest = None
        shared_request_budget_used = None
        if dispatch is not None:
            output = result.get("output")
            if not isinstance(output, Mapping):
                raise ProductStoreError("The Darwin read task has no retained result output.")
            raw_receipt = output.get("macos_receipt")
            intent = journal._intent_for_dispatch(dispatch)
            binding = payload["runner_profile"].get("macos_file_access_binding")
            if not isinstance(binding, Mapping):
                raise ProductStoreError("The task profile lacks its exact Darwin binding.")
            if not isinstance(raw_receipt, Mapping):
                raise ProductStoreError("The original Darwin receipt is absent.")
            expected_receipt_fields = {
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
            }
            if (
                set(raw_receipt) != expected_receipt_fields
                or raw_receipt.get("schema_version") != "bluefire.macos-file-access-task-receipt.v1"
                or any(
                    raw_receipt.get(key) != intent[key]
                    for key in (
                        "task_id",
                        "transport_request_hash",
                        "context_digest",
                        "binding_digest",
                        "operation",
                    )
                )
                or raw_receipt.get("settlement_scope") != "producer_local_only"
                or raw_receipt.get("whole_enrollment_cleanup") is not False
            ):
                raise ProductStoreError("The original Darwin receipt identity is invalid.")
            native_receipt_digest = content_hash(dict(raw_receipt))
            if raw_receipt.get("state") == "unknown":
                if raw_receipt.get("dispatch") not in {"attempted", "unknown"}:
                    raise ProductStoreError("Unknown Darwin dispatch lacks an attempted boundary.")
                state = "unknown"
                if result.get("status") == "success":
                    raise ProductStoreError("Unknown Darwin producer state cannot be successful.")
            else:
                receipt = method.validate_read_receipt(raw_receipt, intent, binding)
                metadata = method.validate_metadata(output.get("observation"), receipt)
                prior_probe = journal._event(
                    connection, attempt_id, "receipt", reservation["probe_step_id"]
                )
                expected_probe_task_id = task_id if operation == "probe" else prior_probe["task_id"]
                expected_probe_digest = (
                    None if operation == "probe" else prior_probe["native_receipt_digest"]
                )
                if (
                    metadata["attempt_id"] != attempt_id
                    or metadata["run_id"] != lease["run_id"]
                    or metadata["step_id"] != task["step_id"]
                    or metadata["request_hash"] != task["request_hash"]
                    or metadata["binding"] != binding
                    or metadata["intent"] != intent
                    or metadata["probe_task_id"] != expected_probe_task_id
                    or metadata["probe_receipt_digest"] != expected_probe_digest
                ):
                    raise ProductStoreError(
                        "The Darwin observation differs from its committed task frame."
                    )
                native_receipt_digest = content_hash(receipt)
                observation_digest = content_hash(metadata)
                shared_request_budget_used = receipt["shared_request_budget_used"]
                state = "complete"
            if state == "complete" and result.get("status") != "success":
                raise ProductStoreError(
                    "A verified Darwin receipt must have a successful task result."
                )
        elif result.get("schema_version") != "bluefire.task-not-sent.v1":
            raise ProductStoreError(
                "The unattempted Darwin terminal is not an exact not-sent result."
            )
        document = {
            "schema_version": "bluefire.macos-file-access-task-closure.v1",
            "attempt_id": attempt_id,
            "task_id": task_id,
            "step_id": task["step_id"],
            "request_hash": task["request_hash"],
            "transport_request_hash": execution_task_hash,
            "terminal_digest": terminal_digest,
            "state": state,
            "native_receipt_digest": native_receipt_digest,
            "observation_digest": observation_digest,
            "shared_request_budget_used": shared_request_budget_used,
            "result": result,
        }
        event_key = task["step_id"]
        window = (
            journal._success_acceptance(dispatch, binding) if state == "complete" else nullcontext()
        )
        with window:
            previous = journal._event(connection, attempt_id, "receipt", event_key)
            if previous is not None:
                if previous != document:
                    raise ProductStoreError("Darwin task closure is already immutable.")
                return document
            journal._append(
                connection,
                "capability_macos_file_access_events",
                attempt_id,
                "receipt",
                event_key,
                document,
            )
            return document


def close_macos_capability_attempt(
    store,
    attempt_id: str,
    *,
    journal: ModuleType,
    cleanup_task_id: str,
    result: Mapping[str, Any],
    workspace_attestation: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Settle only with the exact producer closure and trusted empty workspace proof."""
    from . import macos_file_access_method as method

    if not isinstance(result, Mapping) or (
        workspace_attestation is not None and not isinstance(workspace_attestation, Mapping)
    ):
        raise ProductStoreError("The final Darwin closure evidence is incomplete.")
    with store._connection(write=True) as connection:
        _, lease, compiled = records._attempt_at(connection, attempt_id)
        reservation = records._document(
            records._one(
                connection,
                "SELECT * FROM capability_macos_file_access_attempts WHERE attempt_id=?",
                attempt_id,
            )
        )
        task = records._one(
            connection,
            "SELECT * FROM capability_task_claims WHERE task_id=?",
            cleanup_task_id,
        )
        if task["attempt_id"] != attempt_id or task["step_id"] != reservation["cleanup_step_id"]:
            raise ProductStoreError("The close task belongs to another compiled attempt.")
        result_value = result.get("output")
        closure = result_value.get("attempt_closure") if isinstance(result_value, Mapping) else None
        validated = method.validate_closure(closure)
        post_attestation = journal._verify_workspace_attestation(
            store, connection, attempt_id, lease, compiled, "post_close", workspace_attestation
        )
        cleanup_event = journal._event(connection, attempt_id, "cleanup_claim", "close_attempt")
        dispatch = journal._event(connection, attempt_id, "dispatch", cleanup_task_id)
        if cleanup_event is None or dispatch is None:
            raise ProductStoreError(
                "The exact Mac cleanup authority or dispatch boundary is absent."
            )
        _, _, original_binding = journal._original_macos_control(
            connection, journal._mac_dependency(compiled)
        )
        journal._require_current_acceptance(dispatch, original_binding, cleanup_event["claim"])
        attempt_closures = journal._task_closures(connection, attempt_id, reservation)
        journal._validate_closure_budget(connection, attempt_id, reservation, validated)
        producer_event = journal._event(connection, attempt_id, "producer_closure", cleanup_task_id)
        cleanup_terminal = records._document(
            records._one(
                connection,
                "SELECT * FROM capability_task_terminals WHERE task_id=?",
                cleanup_task_id,
            )
        )
        if (
            producer_event is None
            or producer_event["closure"] != validated
            or result.get("status") != "success"
            or result.get("request_hash") != task["request_hash"]
            or cleanup_terminal["attempt_id"] != attempt_id
            or cleanup_terminal["request_hash"] != task["request_hash"]
            or cleanup_terminal["terminal_digest"] != producer_event["terminal_digest"]
            or content_hash(dict(json_clone(dict(result)))) != cleanup_terminal["terminal_digest"]
            or validated["task_closures"] != attempt_closures
            or validated["binding_digest"] != dispatch["intent"]["binding_digest"]
            or validated["cleanup_claim_digest"] != cleanup_event["claim_digest"]
            or validated["cleanup_transport_request_hash"] != dispatch["transport_request_hash"]
            or validated["control_revision"]
            != journal._mac_dependency(compiled)["control_revision"]
        ):
            raise ProductStoreError("The Darwin attempt task closures changed after dispatch.")
        pre_attestation = journal._event(
            connection, attempt_id, "workspace_pre_close", cleanup_task_id
        )
        if not isinstance(pre_attestation, Mapping):
            raise ProductStoreError("The pre-close empty workspace inventory proof is absent.")
        closure_digest = content_hash(validated)
        document = {
            "schema_version": "bluefire.macos-file-access-settlement.v1",
            "attempt_id": attempt_id,
            "lease_digest": lease["lease_digest"],
            "compiled_digest": lease["compiled_digest"],
            "cleanup_task_id": cleanup_task_id,
            "cleanup_claim_digest": cleanup_event["claim_digest"],
            "cleanup_dispatch_digest": content_hash(dispatch),
            "cleanup_terminal_digest": producer_event["terminal_digest"],
            "closure_digest": closure_digest,
            "workspace_attestation_digest": content_hash(post_attestation),
            "pre_close_workspace_attestation_digest": content_hash(pre_attestation),
            "workspace_binding_digest": content_hash(
                cleanup.workspace_at(connection, attempt_id, lease)
            ),
            "task_closures_digest": content_hash(attempt_closures),
            "artifact_state": "not_created",
            "producer_scope": "attempt_artifact_closure_only",
        }
        with journal._success_acceptance(dispatch, original_binding, cleanup_event["claim"]):
            retained_post = journal._event(
                connection, attempt_id, "workspace_post_close", cleanup_task_id
            )
            if retained_post is not None and retained_post != post_attestation:
                raise ProductStoreError("The post-close original workspace inventory is immutable.")
            previous = connection.execute(
                "SELECT * FROM capability_macos_file_access_closures WHERE attempt_id=?",
                (attempt_id,),
            ).fetchone()
            if previous is not None:
                if records._document(previous) != document or retained_post is None:
                    raise ProductStoreError("Darwin attempt closure is already immutable.")
                return document
            if retained_post is None:
                journal._append(
                    connection,
                    "capability_macos_file_access_events",
                    attempt_id,
                    "workspace_post_close",
                    cleanup_task_id,
                    post_attestation,
                )
            connection.execute(
                "INSERT INTO capability_macos_file_access_closures VALUES(?,?,?)",
                (attempt_id, canonical_json(document), content_hash(document)),
            )
            return document
