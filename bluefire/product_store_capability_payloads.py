"""Read exact retained task payloads against their append-only capability records."""

from __future__ import annotations

from typing import Any, Mapping

from .product_store_capability_transport import _require_digest, cleanup_step_id, payload_document
from .product_store_errors import ProductStoreError
from .util import content_hash


def read_payload(
    store,
    task_id: str,
    transport_request_hash: str,
    *,
    purpose: str,
) -> dict[str, Any]:
    from . import product_store_capability_cleanup as cleanup
    from . import product_store_capability_grants as records

    transport_request_hash = _require_digest(transport_request_hash, "transport request hash")
    if purpose in {"business", "macos_cleanup"}:
        table = "capability_task_payloads"
        claim_table = "capability_task_claims"
    elif purpose == "cleanup":
        table = "capability_cleanup_task_payloads"
        claim_table = "capability_cleanup_task_claims"
    else:
        raise ProductStoreError("The task payload purpose is invalid.")

    with store._connection() as connection:
        payload_row = records._one(connection, f"SELECT * FROM {table} WHERE task_id=?", task_id)
        payload = records._document(
            payload_row, field="payload_json", digest_field="payload_digest"
        )
        task = records._one(connection, f"SELECT * FROM {claim_table} WHERE task_id=?", task_id)
        row, lease, compiled = records._attempt_at(connection, task["attempt_id"])
        attempt_claim_row, attempt_claim = records._claim_at(connection, task["attempt_id"], lease)
        workspace = cleanup.workspace_at(connection, task["attempt_id"], lease)
        dependency = store._capability_dependency_at(connection, task["attempt_id"], lease)

        macos_cleanup_claim = None
        macos_cleanup_claim_digest = None
        if purpose in {"business", "macos_cleanup"}:
            cleanup_claim = None
            cleanup_claim_digest = None
            cleanup_obligation_digest = None
            step_id = task["step_id"]
            request_hash = task["request_hash"]
            if purpose == "macos_cleanup":
                from . import product_store_macos_composition as macos

                claim_event = macos._event(
                    connection, task["attempt_id"], "cleanup_claim", "close_attempt"
                )
                registration = macos._event(
                    connection, task["attempt_id"], "cleanup_task_registered", task_id
                )
                if claim_event is None or registration is None:
                    raise ProductStoreError(
                        "The retained Mac cleanup task lacks its dedicated claim."
                    )
                macos_cleanup_claim = claim_event["claim"]
                macos_cleanup_claim_digest = claim_event["claim_digest"]
                if (
                    registration.get("task_id") != task_id
                    or registration.get("step_id") != step_id
                    or registration.get("request_hash") != request_hash
                    or registration.get("cleanup_claim_digest") != macos_cleanup_claim_digest
                    or registration.get("payload_digest") != content_hash(payload)
                ):
                    raise ProductStoreError("The retained Mac cleanup task registration changed.")
        else:
            cleanup_claim_row, cleanup_claim = cleanup.claim_at(
                connection, task["attempt_id"], lease
            )
            obligation_row, _ = cleanup.obligation_at(connection, task["attempt_id"], lease)
            cleanup_claim_digest = cleanup_claim_row["document_digest"]
            cleanup_obligation_digest = obligation_row["document_digest"]
            step_id = cleanup_step_id(compiled)
            request_hash = task["request_hash"]

        manifest, runner_profile = payload.get("manifest"), payload.get("runner_profile")
        if not isinstance(manifest, Mapping) or not isinstance(runner_profile, Mapping):
            raise ProductStoreError("The retained runner task payload is incomplete.")
        expected = payload_document(
            purpose=purpose,
            task_id=task_id,
            attempt_id=task["attempt_id"],
            lease=lease,
            step_id=step_id,
            request_hash=request_hash,
            manifest=manifest,
            runner_profile=runner_profile,
            attempt_claim=attempt_claim,
            attempt_claim_digest=attempt_claim_row["document_digest"],
            workspace=workspace,
            dependency=dependency,
            cleanup_claim=cleanup_claim,
            cleanup_claim_digest=cleanup_claim_digest,
            cleanup_obligation_digest=cleanup_obligation_digest,
            macos_cleanup_claim=macos_cleanup_claim,
            macos_cleanup_claim_digest=macos_cleanup_claim_digest,
        )
        if (
            row["attempt_id"] != payload["attempt_id"]
            or payload != expected
            or payload["transport_request_hash"] != transport_request_hash
            or task["request_hash"] != payload["request_hash"]
            or task["attempt_id"] != payload["attempt_id"]
            or purpose in {"business", "macos_cleanup"}
            and task["step_id"] != payload["step_id"]
            or purpose == "cleanup"
            and task["claim_digest"] != payload["cleanup_claim_digest"]
        ):
            raise ProductStoreError("The retained task payload binding changed.")
        return {"payload": payload, "document_digest": content_hash(payload)}
