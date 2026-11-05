"""Append-only restart authority for retained composition attempts."""

from __future__ import annotations

import secrets
from typing import Any, Mapping

from . import product_store_capability_grants as records
from .capability_packs import RECEIVER_RETAINED_PACK, grant_pack
from .execution_contracts import execution_task_identity
from .product_store_capability_cleanup import workspace_at
from .product_store_capability_transport import cleanup_step_id
from .product_store_errors import ProductStoreError
from .product_store_serialization import canonical_json, utc_now
from .util import content_hash, json_clone


def _retained(connection, attempt_id):
    row, lease, compiled = records._attempt_at(connection, attempt_id)
    _, grant, _ = records._grant_at(connection, lease["grant_id"])
    if grant_pack(grant) != RECEIVER_RETAINED_PACK:
        raise ProductStoreError("Only a retained composition attempt can be recovered.")
    return row, lease, compiled


_OPTIONAL_QUERIES = {
    ("capability_attempt_settlements", "attempt_id"): (
        "SELECT * FROM capability_attempt_settlements WHERE attempt_id=?"
    ),
    ("capability_cleanup_task_payloads", "task_id"): (
        "SELECT * FROM capability_cleanup_task_payloads WHERE task_id=?"
    ),
    ("capability_cleanup_terminals", "task_id"): (
        "SELECT * FROM capability_cleanup_terminals WHERE task_id=?"
    ),
    ("capability_receiver_bindings", "attempt_id"): (
        "SELECT * FROM capability_receiver_bindings WHERE attempt_id=?"
    ),
    ("capability_receiver_closure_proofs", "attempt_id"): (
        "SELECT * FROM capability_receiver_closure_proofs WHERE attempt_id=?"
    ),
    ("capability_recovery_claims", "generation"): (
        "SELECT * FROM capability_recovery_claims WHERE generation=?"
    ),
    ("capability_recovery_closures", "attempt_id"): (
        "SELECT * FROM capability_recovery_closures WHERE attempt_id=?"
    ),
    ("capability_recovery_obligations", "generation"): (
        "SELECT * FROM capability_recovery_obligations WHERE generation=?"
    ),
    ("capability_recovery_task_claims", "generation"): (
        "SELECT * FROM capability_recovery_task_claims WHERE generation=?"
    ),
    ("capability_recovery_task_claims", "task_id"): (
        "SELECT * FROM capability_recovery_task_claims WHERE task_id=?"
    ),
    ("capability_recovery_terminals", "task_id"): (
        "SELECT * FROM capability_recovery_terminals WHERE task_id=?"
    ),
    ("capability_task_dispatch_intents", "task_id"): (
        "SELECT * FROM capability_task_dispatch_intents WHERE task_id=?"
    ),
    ("capability_task_payloads", "task_id"): (
        "SELECT * FROM capability_task_payloads WHERE task_id=?"
    ),
    ("capability_task_terminals", "task_id"): (
        "SELECT * FROM capability_task_terminals WHERE task_id=?"
    ),
}


def _optional(connection, table, key, value, *, payload=False):
    query = _OPTIONAL_QUERIES.get((table, key))
    if query is None:
        raise ProductStoreError("Retained recovery lookup is invalid.")
    row = connection.execute(query, (value,)).fetchone()
    return (
        None
        if row is None
        else records._document(
            row,
            field="payload_json" if payload else "document_json",
            digest_field="payload_digest" if payload else "document_digest",
        )
    )


def _latest_generation(connection, attempt_id):
    return connection.execute(
        "SELECT * FROM capability_recovery_generations WHERE attempt_id=? "
        "ORDER BY created_at_ms DESC,rowid DESC LIMIT 1",
        (attempt_id,),
    ).fetchone()


def no_dispatch_digest(attempt_id, lease_digest):
    return content_hash(
        {
            "schema_version": "bluefire.capability-no-native-dispatch.v1",
            "attempt_id": attempt_id,
            "lease_digest": lease_digest,
        }
    )


def list_pending(store, *, after_rowid=0, limit=128):
    if (
        type(after_rowid) is not int
        or after_rowid < 0
        or type(limit) is not int
        or not 1 <= limit <= 256
    ):
        raise ProductStoreError("Recovery page is invalid.")
    with store._connection() as connection:
        rows = connection.execute(
            "SELECT rowid,attempt_id FROM capability_attempts WHERE rowid>? ORDER BY rowid LIMIT ?",
            (after_rowid, limit),
        ).fetchall()
        return [(int(row["rowid"]), str(row["attempt_id"])) for row in rows]


def snapshot(store, attempt_id):
    with store._connection() as connection:
        row, lease, compiled = _retained(connection, attempt_id)
        workspace = connection.execute(
            "SELECT 1 FROM capability_workspace_bindings WHERE attempt_id=?", (attempt_id,)
        ).fetchone()
        workspace = workspace_at(connection, attempt_id, lease) if workspace else None
        receiver = _optional(connection, "capability_receiver_bindings", "attempt_id", attempt_id)
        if receiver is not None and (
            receiver.get("attempt_id") != attempt_id
            or receiver.get("lease_digest") != lease["lease_digest"]
        ):
            raise ProductStoreError("Retained receiver binding changed.")
        tasks = connection.execute(
            "SELECT * FROM capability_task_claims WHERE attempt_id=? ORDER BY task_id",
            (attempt_id,),
        ).fetchall()
        generation = _latest_generation(connection, attempt_id)
        history = [
            {
                "task": records._document(task),
                "terminal": _optional(
                    connection, "capability_recovery_terminals", "task_id", task["task_id"]
                ),
            }
            for task in connection.execute(
                "SELECT * FROM capability_recovery_task_claims WHERE attempt_id=? ORDER BY rowid",
                (attempt_id,),
            ).fetchall()
        ]
        latest_task = next(
            (
                entry
                for entry in reversed(history)
                if generation is not None
                and entry["task"]["generation"] == generation["generation"]
            ),
            None,
        )
        return {
            "lease": lease,
            "compiled": compiled,
            "workspace": workspace,
            "receiver": receiver,
            "tasks": [
                {
                    **dict(task),
                    "terminal": _optional(
                        connection, "capability_task_terminals", "task_id", task["task_id"]
                    ),
                    "payload": _optional(
                        connection,
                        "capability_task_payloads",
                        "task_id",
                        task["task_id"],
                        payload=True,
                    ),
                }
                for task in tasks
            ],
            "settlement": _optional(
                connection, "capability_attempt_settlements", "attempt_id", attempt_id
            ),
            "generation": generation,
            "recovery_claim": (
                lambda row: (
                    None
                    if row is None
                    else _optional(
                        connection, "capability_recovery_claims", "generation", row["generation"]
                    )
                )
            )(generation),
            "recovery_task": latest_task["task"] if latest_task else None,
            "recovery_terminal": latest_task["terminal"] if latest_task else None,
            "recovery_history": history,
            "receiver_closure": _optional(
                connection, "capability_receiver_closure_proofs", "attempt_id", attempt_id
            ),
            "recovery_closure": _optional(
                connection, "capability_recovery_closures", "attempt_id", attempt_id
            ),
            "original_cleanup_task": (
                lambda cleanup_task: (
                    None
                    if cleanup_task is None
                    else {
                        "task_id": cleanup_task["task_id"],
                        "terminal": _optional(
                            connection,
                            "capability_cleanup_terminals",
                            "task_id",
                            cleanup_task["task_id"],
                        ),
                    }
                )
            )(
                connection.execute(
                    "SELECT task_id FROM capability_cleanup_task_claims WHERE attempt_id=?",
                    (attempt_id,),
                ).fetchone()
            ),
        }


def _optional_transport_hash(store, task_id):
    with store._connection() as connection:
        payload = _optional(
            connection,
            "capability_cleanup_task_payloads",
            "task_id",
            task_id,
            payload=True,
        )
        if payload is None:
            raise ProductStoreError("Original cleanup WAL request is unavailable.")
        return payload["transport_request_hash"]


def _original_task_at(connection, attempt_id, task_id, request_hash, transport_request_hash):
    task = records._one(connection, "SELECT * FROM capability_task_claims WHERE task_id=?", task_id)
    payload = _optional(connection, "capability_task_payloads", "task_id", task_id, payload=True)
    if (
        task["attempt_id"] != attempt_id
        or task["request_hash"] != request_hash
        or payload is None
        or payload.get("schema_version") != "bluefire.capability-task-payload.v2"
        or payload.get("dispatch_protocol") != "bluefire.capability-task-dispatch-intent.v1"
        or payload.get("transport_request_hash") != transport_request_hash
    ):
        raise ProductStoreError("Original task has another exact dispatch request.")
    return task, payload


def mark_task_dispatch(store, attempt_id, *, task_id, request_hash, transport_request_hash):
    """Commit the send boundary before the runner can receive a retained task."""

    with store._connection(write=True) as connection:
        _, lease, _ = _retained(connection, attempt_id)
        _, payload = _original_task_at(
            connection, attempt_id, task_id, request_hash, transport_request_hash
        )
        if _optional(connection, "capability_task_terminals", "task_id", task_id) is not None:
            raise ProductStoreError("Original task already has a terminal before dispatch.")
        if (
            connection.execute(
                "SELECT 1 FROM capability_receiver_closure_proofs WHERE attempt_id=?",
                (attempt_id,),
            ).fetchone()
            or connection.execute(
                "SELECT 1 FROM capability_attempt_settlements WHERE attempt_id=?", (attempt_id,)
            ).fetchone()
        ):
            raise ProductStoreError("Original attempt has already entered recovery closure.")
        document = {
            "schema_version": "bluefire.capability-task-dispatch-intent.v1",
            "attempt_id": attempt_id,
            "lease_digest": lease["lease_digest"],
            "task_id": task_id,
            "request_hash": request_hash,
            "transport_request_hash": transport_request_hash,
            "payload_digest": content_hash(payload),
        }
        previous = _optional(connection, "capability_task_dispatch_intents", "task_id", task_id)
        if previous is not None:
            if previous != document:
                raise ProductStoreError("Original task dispatch intent changed.")
            raise ProductStoreError("Original task dispatch was already claimed; do not replay.")
        records._insert_document(
            connection,
            "INSERT INTO capability_task_dispatch_intents VALUES(?,?,?)",
            task_id,
            document,
        )
        return document


def record_task_no_send(store, attempt_id, *, task_id, request_hash, transport_request_hash):
    """Atomically bar a late send when no dispatcher crossed the send boundary."""

    with store._connection(write=True) as connection:
        _retained(connection, attempt_id)
        _original_task_at(connection, attempt_id, task_id, request_hash, transport_request_hash)
        if (
            _optional(connection, "capability_task_dispatch_intents", "task_id", task_id)
            is not None
        ):
            raise ProductStoreError("Original task may already have been sent.")
        no_send = {
            "schema_version": "bluefire.task-not-sent.v1",
            "task_id": task_id,
            "request_hash": request_hash,
        }
        document = {
            "schema_version": "bluefire.capability-task-terminal.v1",
            "task_id": task_id,
            "attempt_id": attempt_id,
            "request_hash": request_hash,
            "terminal_digest": content_hash(no_send),
        }
        previous = _optional(connection, "capability_task_terminals", "task_id", task_id)
        if previous is not None:
            if previous != document:
                raise ProductStoreError("Original task has another terminal.")
            return previous
        records._insert_document(
            connection,
            "INSERT INTO capability_task_terminals VALUES(?,?,?)",
            task_id,
            document,
        )
        return document


def record_receiver_closure(store, attempt_id, proof: Mapping[str, Any]):
    proof = json_clone(proof)
    with store._connection(write=True) as connection:
        _, lease, _ = _retained(connection, attempt_id)
        binding = records._document(
            records._one(
                connection,
                "SELECT * FROM capability_receiver_bindings WHERE attempt_id=?",
                attempt_id,
            )
        )
        if (
            binding.get("schema_version") != "bluefire.capability-receiver-binding.v2"
            or binding.get("lease_digest") != lease["lease_digest"]
            or proof.get("process_id") != binding.get("process_id")
            or proof.get("creation_identity") != binding.get("creation_identity")
            or proof.get("verified_closed") is not True
            or proof.get("schema_version")
            not in {"bluefire.receiver-closure-proof.v1", "bluefire.receiver-cleanup.v1"}
            or (
                proof.get("schema_version") == "bluefire.receiver-closure-proof.v1"
                and (
                    set(proof)
                    != {
                        "schema_version",
                        "process_id",
                        "creation_identity",
                        "session_member_count",
                        "verified_closed",
                    }
                    or proof.get("session_member_count") != 0
                )
            )
            or (
                proof.get("schema_version") == "bluefire.receiver-cleanup.v1"
                and (
                    proof.get("review_digest") != binding["review_digest"]
                    or proof.get("receiver_job_id") != lease["job_id"]
                )
            )
        ):
            raise ProductStoreError("Receiver closure does not prove its exact generation.")
        document = {
            "schema_version": "bluefire.capability-receiver-closure.v1",
            "attempt_id": attempt_id,
            "lease_digest": lease["lease_digest"],
            "session_generation": binding["session_generation"],
            "review_digest": binding["review_digest"],
            "process_id": binding["process_id"],
            "creation_identity": binding["creation_identity"],
            "proof_digest": content_hash(proof),
            "verified_closed": True,
        }
        previous = _optional(
            connection, "capability_receiver_closure_proofs", "attempt_id", attempt_id
        )
        if previous is not None:
            if previous != document:
                # A completed live close and a later independently observed close
                # can coexist; the first durable proof stays authoritative.
                return previous
            return previous
        records._insert_document(
            connection,
            "INSERT INTO capability_receiver_closure_proofs VALUES(?,?,?)",
            attempt_id,
            document,
        )
        return document


def begin_generation(store, attempt_id, now_ms):
    records._time(now_ms)
    with store._connection(write=True) as connection:
        _retained(connection, attempt_id)
        row = _latest_generation(connection, attempt_id)
        if row is not None:
            claim = connection.execute(
                "SELECT expires_at_ms FROM capability_recovery_claims WHERE generation=?",
                (row["generation"],),
            ).fetchone()
            task = connection.execute(
                "SELECT * FROM capability_recovery_task_claims WHERE generation=?",
                (row["generation"],),
            ).fetchone()
            terminal = (
                _optional(connection, "capability_recovery_terminals", "task_id", task["task_id"])
                if task is not None
                else None
            )
            partial_progress = (
                terminal is not None
                and bool(terminal.get("remaining_receipts"))
                and len(terminal["remaining_receipts"])
                < len(
                    _optional(
                        connection, "capability_recovery_claims", "generation", row["generation"]
                    )["receipts"]
                )
            )
            if (
                claim is None
                or task is None
                and claim["expires_at_ms"] > now_ms
                or task is not None
                and not partial_progress
            ):
                return str(row["generation"])
            # The expired claim never acquired a task. Preserve it and create
            # another finite cleanup authority with a fresh generation.
            count = connection.execute(
                "SELECT count(*) FROM capability_recovery_generations WHERE attempt_id=?",
                (attempt_id,),
            ).fetchone()[0]
            if count >= 512:
                raise ProductStoreError("Recovery cleanup generation limit is exhausted.")
        generation = "recovery-" + secrets.token_hex(16)
        connection.execute(
            "INSERT INTO capability_recovery_generations VALUES(?,?,?)",
            (generation, attempt_id, now_ms),
        )
        return generation


def claim_cleanup(store, attempt_id, *, generation, workspace_id, receipts, now_ms, timeout_ms):
    from .product_store_capability_cleanup import _claim_document, _native_id

    records._time(now_ms)
    _native_id(workspace_id)
    receipts = json_clone(receipts)
    if not isinstance(receipts, list) or not 1 <= len(receipts) <= 512:
        raise ProductStoreError("Recovery cleanup requires a bounded receipt list.")
    with store._connection(write=True) as connection:
        _, lease, compiled = _retained(connection, attempt_id)
        binding = workspace_at(connection, attempt_id, lease)
        if binding["schema_version"] != "bluefire.capability-workspace-binding.v2":
            raise ProductStoreError("Original workspace has no exact recovery binding.")
        saved_generation = _latest_generation(connection, attempt_id)
        if (
            saved_generation is None
            or generation != saved_generation["generation"]
            or connection.execute(
                "SELECT 1 FROM capability_attempt_settlements WHERE attempt_id=?", (attempt_id,)
            ).fetchone()
        ):
            raise ProductStoreError("Recovery generation is changed or settled.")
        previous_generation = connection.execute(
            "SELECT generation FROM capability_recovery_generations "
            "WHERE attempt_id=? AND generation<>? ORDER BY created_at_ms DESC,rowid DESC LIMIT 1",
            (attempt_id, generation),
        ).fetchone()
        if previous_generation is not None:
            previous_task = connection.execute(
                "SELECT * FROM capability_recovery_task_claims WHERE generation=?",
                (previous_generation["generation"],),
            ).fetchone()
            if previous_task is not None:
                previous_terminal = _optional(
                    connection,
                    "capability_recovery_terminals",
                    "task_id",
                    previous_task["task_id"],
                )
                if (
                    previous_terminal is None
                    or previous_terminal.get("remaining_receipts") != receipts
                    or len(receipts)
                    >= len(
                        _optional(
                            connection,
                            "capability_recovery_claims",
                            "generation",
                            previous_generation["generation"],
                        )["receipts"]
                    )
                ):
                    raise ProductStoreError("Recovery survivor list changed between generations.")
        task_rows = connection.execute(
            "SELECT * FROM capability_task_claims WHERE attempt_id=?", (attempt_id,)
        ).fetchall()
        task_by_id = {row["task_id"]: row for row in task_rows}
        seen = set()
        for receipt in receipts:
            if not isinstance(receipt, dict) or set(receipt) != {
                "receipt_id",
                "source_request_hash",
                "source_task_id",
            }:
                raise ProductStoreError("Recovery receipt lineage is invalid.")
            _native_id(receipt["receipt_id"])
            task = task_by_id.get(receipt["source_task_id"])
            if (
                task is None
                or task["request_hash"] != receipt["source_request_hash"]
                or receipt["receipt_id"] in seen
            ):
                raise ProductStoreError("Recovery receipt has no exact original task.")
            seen.add(receipt["receipt_id"])
        for task in task_rows:
            if (
                _optional(connection, "capability_task_terminals", "task_id", task["task_id"])
                is None
            ):
                raise ProductStoreError("Original task outcome remains unknown.")
        if type(timeout_ms) is not int or not 1 <= timeout_ms <= 120000:
            raise ProductStoreError("Recovery cleanup timeout is invalid.")
        existing = _optional(connection, "capability_recovery_claims", "generation", generation)
        if existing is not None:
            obligation = _optional(
                connection, "capability_recovery_obligations", "generation", generation
            )
            if (
                obligation is None
                or obligation.get("receipts") != receipts
                or obligation.get("workspace_id") != workspace_id
            ):
                raise ProductStoreError("Recovery cleanup claim is already immutable.")
            return {"document": existing, "document_digest": content_hash(existing)}
        obligation = {
            "schema_version": "bluefire.capability-recovery-obligation.v1",
            "attempt_id": attempt_id,
            "generation": generation,
            "lease_digest": lease["lease_digest"],
            "workspace_binding_digest": content_hash(binding),
            "workspace_id": workspace_id,
            "receipts": receipts,
        }
        expires = now_ms + timeout_ms
        claim = _claim_document(
            lease,
            {
                "runner_policy_digest": binding["runner_policy_digest"],
                "workspace_id": workspace_id,
                "receipts": receipts,
            },
            content_hash(obligation),
            now_ms,
            expires,
            timeout_ms,
        )
        from .runner_contracts import _verified_grant_cleanup

        _verified_grant_cleanup(claim, expected_document_digest=content_hash(claim))
        connection.execute(
            "INSERT INTO capability_recovery_obligations VALUES(?,?,?,?)",
            (generation, attempt_id, canonical_json(obligation), content_hash(obligation)),
        )
        connection.execute(
            "INSERT INTO capability_recovery_claims VALUES(?,?,?,?,?,?)",
            (generation, attempt_id, canonical_json(claim), content_hash(claim), now_ms, expires),
        )
        return {"document": claim, "document_digest": content_hash(claim)}


def register_cleanup_task(store, attempt_id, *, generation, task_id, manifest, profile, now_ms):
    records._time(now_ms)
    with store._connection(write=True) as connection:
        _, lease, compiled = _retained(connection, attempt_id)
        workspace = workspace_at(connection, attempt_id, lease)
        latest = _latest_generation(connection, attempt_id)
        claim = _optional(connection, "capability_recovery_claims", "generation", generation)
        claim_row = records._one(
            connection, "SELECT * FROM capability_recovery_claims WHERE generation=?", generation
        )
        if (
            latest is None
            or latest["generation"] != generation
            or claim is None
            or claim_row["attempt_id"] != attempt_id
            or workspace.get("runner_profile") != profile
        ):
            raise ProductStoreError("Recovery task lost its exact original profile or claim.")
        if not claim_row["claimed_at_ms"] <= now_ms < claim_row["expires_at_ms"]:
            raise ProductStoreError("Recovery cleanup task claim has expired.")
        from .runner_contracts import _canonical_grant_cleanup, seal_manifest

        expected_claim = {
            **_canonical_grant_cleanup(claim, wire=False),
            "request_hash": manifest.get("request_hash"),
        }
        if (
            manifest.get("grant_cleanup") != expected_claim
            or manifest.get("action_id") != "sandbox.cleanup.v1"
            or manifest.get("behavior_id") != "sandbox.cleanup.v1"
            or manifest.get("run_id") != lease["run_id"]
            or manifest.get("step_id") != cleanup_step_id(compiled)
            or manifest.get("params")
            != {"receipt_ids": [row["receipt_id"] for row in claim["receipts"]]}
            or manifest.get("target_scope") != {"filesystem": [], "network": []}
            or manifest.get("approval") is not None
            or "grant_attempt" in manifest
            or "execution_binding" in manifest
            or "provider_binding" in manifest
        ):
            raise ProductStoreError("Recovery task is outside its cleanup-only claim.")
        if seal_manifest(manifest) != manifest:
            raise ProductStoreError("Recovery cleanup manifest is not sealed.")
        exact_task_id, transport_hash = execution_task_identity(manifest, profile)
        if task_id != exact_task_id:
            raise ProductStoreError("Recovery task ID changed.")
        document = {
            "schema_version": "bluefire.capability-recovery-task.v1",
            "attempt_id": attempt_id,
            "generation": generation,
            "task_id": task_id,
            "request_hash": manifest["request_hash"],
            "transport_request_hash": transport_hash,
            "claim_digest": content_hash(claim),
            "manifest": json_clone(manifest),
            "runner_profile": json_clone(profile),
        }
        previous = _optional(
            connection, "capability_recovery_task_claims", "generation", generation
        )
        if previous is not None:
            if previous != document:
                raise ProductStoreError("Recovery cleanup task is already consumed.")
            return previous, False
        connection.execute(
            "INSERT INTO capability_recovery_task_claims VALUES(?,?,?,?,?)",
            (task_id, attempt_id, generation, canonical_json(document), content_hash(document)),
        )
        return document, True


def record_cleanup_terminal(
    store, attempt_id, *, task_id, result, remaining_receipts, inspection_digest
):
    records.digest(inspection_digest, "recovery post-cleanup inspection")
    remaining_receipts = json_clone(remaining_receipts)
    with store._connection(write=True) as connection:
        _retained(connection, attempt_id)
        task = _optional(connection, "capability_recovery_task_claims", "task_id", task_id)
        if task is None or task["attempt_id"] != attempt_id:
            raise ProductStoreError("Recovery terminal has no claimed task.")
        claim = _optional(
            connection, "capability_recovery_claims", "generation", task["generation"]
        )
        if claim is None:
            raise ProductStoreError("Recovery terminal lost its finite cleanup claim.")
        expected = {row["receipt_id"]: row for row in claim["receipts"]}
        if (
            not isinstance(remaining_receipts, list)
            or len(remaining_receipts)
            != len({row.get("receipt_id") for row in remaining_receipts if isinstance(row, dict)})
            or any(
                expected.get(row.get("receipt_id")) != row
                for row in remaining_receipts
                if isinstance(row, dict)
            )
            or any(not isinstance(row, dict) for row in remaining_receipts)
        ):
            raise ProductStoreError("Recovery terminal has another survivor list.")
        from .execution_progress import validate_cleanup_result
        from .orchestrator import Orchestrator

        Orchestrator._validate_runner_result(task["manifest"], task["runner_profile"], result)
        validate_cleanup_result(task["manifest"], result)
        report = result.get("cleanup")
        removed_count = len(expected) - len(remaining_receipts)
        removed_ids = set(expected) - {row["receipt_id"] for row in remaining_receipts}
        if (
            not isinstance(report, Mapping)
            or report.get("verification_performed") is not True
            or report.get("requested_receipts") != len(expected)
            or report.get("verified_receipts") != removed_count
            or (
                report.get("verified_receipt_ids") is not None
                and set(report["verified_receipt_ids"]) != removed_ids
            )
            or (
                result.get("status") != "success"
                and removed_count > 0
                and report.get("verified_receipt_ids") is None
            )
            or report.get("already_absent_receipts") != []
            or result.get("status") == "success"
            and remaining_receipts
            or result.get("status") in {"partial", "cleanup_failed"}
            and not remaining_receipts
            or result.get("status") not in {"success", "partial", "cleanup_failed"}
        ):
            raise ProductStoreError("Recovery cleanup result and survivors disagree.")
        document = {
            "schema_version": "bluefire.capability-recovery-terminal.v1",
            "attempt_id": attempt_id,
            "generation": task["generation"],
            "task_id": task_id,
            "request_hash": task["request_hash"],
            "claim_digest": task["claim_digest"],
            "terminal_digest": content_hash(result),
            "result": json_clone(result),
            "remaining_receipts": remaining_receipts,
            "inspection_digest": inspection_digest,
        }
        previous = _optional(connection, "capability_recovery_terminals", "task_id", task_id)
        if previous is not None:
            if previous != document:
                raise ProductStoreError("Recovery cleanup terminal changed.")
            return previous
        records._insert_document(
            connection, "INSERT INTO capability_recovery_terminals VALUES(?,?,?)", task_id, document
        )
        return document


def _validate_cleanup_chain(connection, attempt_id, generation, inspection_digest, terminal_digest):
    generations = connection.execute(
        "SELECT generation FROM capability_recovery_generations WHERE attempt_id=? "
        "ORDER BY created_at_ms,rowid",
        (attempt_id,),
    ).fetchall()
    if not generations or generations[-1]["generation"] != generation:
        raise ProductStoreError("Recovery cleanup generation changed.")
    expected_receipts = None
    latest_task = None
    latest_terminal = None
    any_claim = False
    for row in generations:
        current = row["generation"]
        claim = _optional(connection, "capability_recovery_claims", "generation", current)
        task = _optional(connection, "capability_recovery_task_claims", "generation", current)
        if claim is None:
            if task is not None or current != generation or expected_receipts is not None:
                raise ProductStoreError("Recovery cleanup generation has no claim.")
            continue
        any_claim = True
        if expected_receipts is not None and claim["receipts"] != expected_receipts:
            raise ProductStoreError("Recovery survivor chain changed.")
        if task is None:
            if current == generation:
                raise ProductStoreError("Latest recovery cleanup claim has no task.")
            expected_receipts = claim["receipts"]
            continue
        terminal = _optional(
            connection, "capability_recovery_terminals", "task_id", task["task_id"]
        )
        if terminal is None:
            raise ProductStoreError("Recovery cleanup task outcome is unknown.")
        claimed = {receipt["receipt_id"]: receipt for receipt in claim["receipts"]}
        remaining = terminal.get("remaining_receipts")
        remaining_ids = (
            {receipt["receipt_id"] for receipt in remaining}
            if isinstance(remaining, list)
            and all(isinstance(receipt, dict) for receipt in remaining)
            else set()
        )
        if (
            task.get("generation") != current
            or terminal.get("generation") != current
            or task.get("claim_digest") != content_hash(claim)
            or terminal.get("claim_digest") != content_hash(claim)
            or terminal.get("task_id") != task["task_id"]
            or terminal.get("request_hash") != task["request_hash"]
            or terminal.get("terminal_digest") != content_hash(terminal.get("result"))
            or task.get("manifest", {}).get("params", {}).get("receipt_ids") != list(claimed)
            or not isinstance(remaining, list)
            or len(remaining_ids) != len(remaining)
            or any(claimed.get(receipt.get("receipt_id")) != receipt for receipt in remaining)
        ):
            raise ProductStoreError("Recovery cleanup task chain changed.")
        result = terminal["result"]
        report = result.get("cleanup") if isinstance(result, dict) else None
        removed = set(claimed) - remaining_ids
        if (
            not isinstance(report, dict)
            or report.get("verification_performed") is not True
            or report.get("requested_receipts") != len(claimed)
            or report.get("verified_receipts") != len(removed)
            or report.get("already_absent_receipts") != []
            or (
                report.get("verified_receipt_ids") is not None
                and set(report["verified_receipt_ids"]) != removed
            )
            or (
                result.get("status") != "success"
                and removed
                and report.get("verified_receipt_ids") is None
            )
            or (result.get("status") == "success") != (remaining == [])
        ):
            raise ProductStoreError("Recovery cleanup terminal proof changed.")
        expected_receipts = remaining
        latest_task, latest_terminal = task, terminal
    original = connection.execute(
        "SELECT task_id FROM capability_cleanup_task_claims WHERE attempt_id=?", (attempt_id,)
    ).fetchone()
    if (
        original is not None
        and _optional(connection, "capability_cleanup_terminals", "task_id", original["task_id"])
        is None
    ):
        raise ProductStoreError("Original cleanup outcome remains unknown.")
    if latest_task is None:
        if any_claim or terminal_digest is not None:
            raise ProductStoreError("Recovery cleanup lacks a final task.")
    elif (
        latest_task["generation"] != generation
        or latest_terminal["result"]["status"] != "success"
        or latest_terminal["remaining_receipts"] != []
        or latest_terminal["terminal_digest"] != terminal_digest
        or latest_terminal["inspection_digest"] != inspection_digest
    ):
        raise ProductStoreError("Latest recovery cleanup is not verified clean.")


def record_cleanup_closure(
    store, attempt_id, *, generation, inspection_digest, terminal_digest=None
):
    records.digest(inspection_digest, "recovery receipt inspection")
    with store._connection(write=True) as connection:
        _, lease, _ = _retained(connection, attempt_id)
        saved = _latest_generation(connection, attempt_id)
        if saved is None or generation != saved["generation"]:
            raise ProductStoreError("Recovery generation changed before cleanup closure.")
        _validate_cleanup_chain(
            connection, attempt_id, generation, inspection_digest, terminal_digest
        )
        task = _optional(connection, "capability_recovery_task_claims", "generation", generation)
        claim = _optional(connection, "capability_recovery_claims", "generation", generation)
        if claim is not None and task is None:
            raise ProductStoreError("Recovery cleanup authority has no completed task.")
        if (
            task is None
            and connection.execute(
                "SELECT 1 FROM capability_recovery_claims WHERE attempt_id=?",
                (attempt_id,),
            ).fetchone()
        ):
            raise ProductStoreError("Earlier cleanup authority has no final cleanup proof.")
        if task is not None:
            terminal = _optional(
                connection, "capability_recovery_terminals", "task_id", task["task_id"]
            )
            if (
                terminal is None
                or terminal["terminal_digest"] != terminal_digest
                or terminal["inspection_digest"] != inspection_digest
                or terminal["remaining_receipts"] != []
                or terminal["result"]["status"] != "success"
            ):
                raise ProductStoreError("Recovery cleanup has no exact terminal.")
        elif terminal_digest is not None:
            raise ProductStoreError("Recovery cleanup terminal is unclaimed.")
        for prior in connection.execute(
            "SELECT task_id FROM capability_recovery_task_claims WHERE attempt_id=?",
            (attempt_id,),
        ).fetchall():
            if (
                _optional(connection, "capability_recovery_terminals", "task_id", prior["task_id"])
                is None
            ):
                raise ProductStoreError("A recovery cleanup task has an unknown outcome.")
        workspace_bound = connection.execute(
            "SELECT 1 FROM capability_workspace_bindings WHERE attempt_id=?", (attempt_id,)
        ).fetchone()
        if workspace_bound is None:
            if (
                inspection_digest != no_dispatch_digest(attempt_id, lease["lease_digest"])
                or terminal_digest is not None
                or connection.execute(
                    "SELECT 1 FROM capability_task_claims WHERE attempt_id=?", (attempt_id,)
                ).fetchone()
                or connection.execute(
                    "SELECT 1 FROM capability_cleanup_claims WHERE attempt_id=?", (attempt_id,)
                ).fetchone()
                or connection.execute(
                    "SELECT 1 FROM capability_recovery_claims WHERE attempt_id=?", (attempt_id,)
                ).fetchone()
            ):
                raise ProductStoreError("Missing workspace has no no-dispatch proof.")
        document = {
            "schema_version": "bluefire.capability-recovery-closure.v1",
            "attempt_id": attempt_id,
            "generation": generation,
            "lease_digest": lease["lease_digest"],
            "inspection_digest": inspection_digest,
            "terminal_digest": terminal_digest,
            "outstanding_receipt_count": 0,
        }
        previous = _optional(connection, "capability_recovery_closures", "attempt_id", attempt_id)
        if previous is not None:
            if previous != document:
                raise ProductStoreError("Recovery cleanup closure is immutable.")
            return previous
        connection.execute(
            "INSERT INTO capability_recovery_closures VALUES(?,?,?,?)",
            (attempt_id, generation, canonical_json(document), content_hash(document)),
        )
        return document


def validate_interrupted_settlement(connection, attempt_id, lease, receipt):
    if not isinstance(receipt, dict) or set(receipt) != {
        "schema_version",
        "attempt_id",
        "lease_digest",
        "generation",
        "disposition",
        "native",
        "receiver",
    }:
        raise ProductStoreError("Interrupted recovery settlement has invalid fields.")
    if (
        receipt["schema_version"] != "bluefire.capability-attempt-settlement.v2"
        or receipt["attempt_id"] != attempt_id
        or receipt["lease_digest"] != lease["lease_digest"]
        or receipt["disposition"] != "interrupted_unusable"
    ):
        raise ProductStoreError("Interrupted recovery settlement changed.")
    generation = _latest_generation(connection, attempt_id)
    cleanup = records._document(
        records._one(
            connection, "SELECT * FROM capability_recovery_closures WHERE attempt_id=?", attempt_id
        )
    )
    receiver = records._document(
        records._one(
            connection,
            "SELECT * FROM capability_receiver_closure_proofs WHERE attempt_id=?",
            attempt_id,
        )
    )
    receiver_binding = records._document(
        records._one(
            connection, "SELECT * FROM capability_receiver_bindings WHERE attempt_id=?", attempt_id
        )
    )
    workspace_bound = connection.execute(
        "SELECT 1 FROM capability_workspace_bindings WHERE attempt_id=?", (attempt_id,)
    ).fetchone()
    workspace = workspace_at(connection, attempt_id, lease) if workspace_bound else None
    if (
        generation is None
        or generation["generation"] != receipt["generation"]
        or cleanup.get("generation") != receipt["generation"]
        or cleanup.get("outstanding_receipt_count") != 0
        or receiver.get("verified_closed") is not True
        or receiver_binding.get("schema_version") != "bluefire.capability-receiver-binding.v2"
        or any(
            receiver.get(key) != receiver_binding.get(key)
            for key in ("session_generation", "review_digest", "process_id", "creation_identity")
        )
        or receipt["native"] != {"state": "verified_clean", "closure_digest": content_hash(cleanup)}
        or receipt["receiver"]
        != {"state": "verified_closed", "closure_digest": content_hash(receiver)}
    ):
        raise ProductStoreError("Interrupted settlement lacks exact cleanup and receiver closure.")
    if workspace is None:
        if (
            cleanup.get("inspection_digest")
            != no_dispatch_digest(attempt_id, lease["lease_digest"])
            or cleanup.get("terminal_digest") is not None
            or connection.execute(
                "SELECT 1 FROM capability_cleanup_claims WHERE attempt_id=?", (attempt_id,)
            ).fetchone()
            or connection.execute(
                "SELECT 1 FROM capability_recovery_claims WHERE attempt_id=?", (attempt_id,)
            ).fetchone()
        ):
            raise ProductStoreError("Interrupted settlement has an unbound workspace.")
    elif workspace.get("schema_version") != "bluefire.capability-workspace-binding.v2":
        raise ProductStoreError("Interrupted settlement has no exact workspace.")
    _validate_cleanup_chain(
        connection,
        attempt_id,
        receipt["generation"],
        cleanup["inspection_digest"],
        cleanup["terminal_digest"],
    )
    tasks = connection.execute(
        "SELECT * FROM capability_task_claims WHERE attempt_id=?", (attempt_id,)
    ).fetchall()
    for task in tasks:
        terminal = _optional(connection, "capability_task_terminals", "task_id", task["task_id"])
        if terminal is None or terminal.get("request_hash") != task["request_hash"]:
            raise ProductStoreError("Interrupted settlement has an unknown original task.")
    return receipt


def repair_progress(store, attempt_id, settlement):
    with store._connection(write=True) as connection:
        row, lease, _ = _retained(connection, attempt_id)
        saved = _optional(connection, "capability_attempt_settlements", "attempt_id", attempt_id)
        if saved != settlement:
            raise ProductStoreError("Settlement changed before progress repair.")
        job = records._one(connection, "SELECT * FROM jobs WHERE job_id=?", lease["job_id"])
        current = store._job_from_row(job)
        progress = dict(current["progress"])
        desired = (
            "interrupted_unusable" if settlement["schema_version"].endswith(".v2") else "settled"
        )
        if progress.get("settlement") == desired:
            return
        progress["settlement"] = desired
        connection.execute(
            "UPDATE jobs SET progress_json=?,updated_at=? WHERE job_id=?",
            (canonical_json(progress), utc_now(), lease["job_id"]),
        )
