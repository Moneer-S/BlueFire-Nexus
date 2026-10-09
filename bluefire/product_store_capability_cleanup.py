"""Receipt-scoped cleanup authority for one already-reserved capability attempt."""

from __future__ import annotations

import re
from typing import Any

from . import product_store_capability_grants as records
from .capability_grant import digest, identifier
from .product_store_errors import ProductStoreError
from .product_store_serialization import canonical_json
from .util import content_hash, json_clone


def _native_id(value):
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ProductStoreError(
            "Native receipt and workspace IDs must be 64 lowercase hex characters."
        )


def workspace_at(connection, attempt_id, lease):
    row = records._one(
        connection, "SELECT * FROM capability_workspace_bindings WHERE attempt_id=?", attempt_id
    )
    document = records._document(row)
    if (
        set(document)
        != {
            "schema_version",
            "attempt_id",
            "lease_digest",
            "runner_policy_digest",
            "workspace_path_digest",
            "bound_at_ms",
        }
        or document["schema_version"] != "bluefire.capability-workspace-binding.v1"
        or document["attempt_id"] != attempt_id
        or document["lease_digest"] != lease["lease_digest"]
        or document["bound_at_ms"] != row["bound_at_ms"]
        or not lease["created_at_ms"] <= document["bound_at_ms"] < lease["business_expires_at_ms"]
    ):
        raise ProductStoreError("Capability workspace binding changed.")
    digest(document["runner_policy_digest"], "sealed runner policy")
    digest(document["workspace_path_digest"], "owned workspace path")
    return document


def bind_workspace(
    store, attempt_id, *, runner_policy_digest, workspace_path_digest, now_ms, current_environment
) -> dict[str, Any]:
    digest(runner_policy_digest, "sealed runner policy")
    digest(workspace_path_digest, "owned workspace path")
    with store._connection(write=True) as connection:
        _, lease, _ = records._attempt_live(
            store, connection, attempt_id, now_ms, current_environment
        )
        records._claim_at(connection, attempt_id, lease)
        records._one(
            connection, "SELECT * FROM capability_preparation_starts WHERE attempt_id=?", attempt_id
        )
        if connection.execute(
            "SELECT 1 FROM capability_workspace_bindings WHERE attempt_id=?", (attempt_id,)
        ).fetchone():
            raise ProductStoreError("The capability workspace is already bound; do not replay.")
        document = {
            "schema_version": "bluefire.capability-workspace-binding.v1",
            "attempt_id": attempt_id,
            "lease_digest": lease["lease_digest"],
            "runner_policy_digest": runner_policy_digest,
            "workspace_path_digest": workspace_path_digest,
            "bound_at_ms": now_ms,
        }
        connection.execute(
            "INSERT INTO capability_workspace_bindings VALUES(?,?,?,?)",
            (attempt_id, canonical_json(document), content_hash(document), now_ms),
        )
        return document


def _receipt_sources(connection, attempt_id, receipts):
    if not isinstance(receipts, list) or not receipts or len(receipts) > 64:
        raise ProductStoreError(
            "Cleanup requires a bounded, independently reconciled receipt list."
        )
    seen = set()
    for receipt in receipts:
        if not isinstance(receipt, dict) or set(receipt) != {
            "receipt_id",
            "source_request_hash",
            "source_task_id",
        }:
            raise ProductStoreError("Cleanup receipt provenance is invalid.")
        _native_id(receipt["receipt_id"])
        digest(receipt["source_request_hash"], "source request")
        if receipt["receipt_id"] in seen:
            raise ProductStoreError("Cleanup receipts must be unique.")
        seen.add(receipt["receipt_id"])
        source = records._one(
            connection,
            "SELECT * FROM capability_task_claims WHERE task_id=?",
            receipt["source_task_id"],
        )
        if (
            source["attempt_id"] != attempt_id
            or source["request_hash"] != receipt["source_request_hash"]
        ):
            raise ProductStoreError("Cleanup receipt belongs to another task or attempt.")
    tasks = connection.execute(
        "SELECT * FROM capability_task_claims WHERE attempt_id=?", (attempt_id,)
    ).fetchall()
    for task in tasks:
        terminal = records._document(
            records._one(
                connection,
                "SELECT * FROM capability_task_terminals WHERE task_id=?",
                task["task_id"],
            )
        )
        if (
            terminal.get("task_id") != task["task_id"]
            or terminal.get("attempt_id") != attempt_id
            or terminal.get("request_hash") != task["request_hash"]
            or terminal.get("schema_version") != "bluefire.capability-task-terminal.v1"
        ):
            raise ProductStoreError("Reconcile every business task before cleanup authority.")
        digest(terminal.get("terminal_digest"), "business terminal")


def obligation_at(connection, attempt_id, lease):
    row = records._one(
        connection, "SELECT * FROM capability_cleanup_obligations WHERE attempt_id=?", attempt_id
    )
    document = records._document(row)
    binding = workspace_at(connection, attempt_id, lease)
    if (
        set(document)
        != {
            "schema_version",
            "attempt_id",
            "lease_digest",
            "runner_policy_digest",
            "workspace_path_digest",
            "workspace_id",
            "receipts",
        }
        or document["schema_version"] != "bluefire.capability-cleanup-obligation.v1"
        or document["attempt_id"] != attempt_id
        or document["lease_digest"] != lease["lease_digest"]
        or any(
            document[key] != binding[key]
            for key in ("runner_policy_digest", "workspace_path_digest")
        )
    ):
        raise ProductStoreError("Cleanup obligation binding changed.")
    _native_id(document["workspace_id"])
    _receipt_sources(connection, attempt_id, document["receipts"])
    return row, document


def record_obligation(store, attempt_id, *, workspace_id, receipts) -> dict[str, Any]:
    """The trusted adapter verifies all native receipts and workspace identity first."""
    _native_id(workspace_id)
    receipts = json_clone(receipts)
    with store._connection(write=True) as connection:
        _, lease, _ = records._attempt_at(connection, attempt_id)
        records._claim_at(connection, attempt_id, lease)
        if records._settled(store, connection, attempt_id):
            raise ProductStoreError("A settled attempt cannot acquire cleanup authority.")
        binding = workspace_at(connection, attempt_id, lease)
        _receipt_sources(connection, attempt_id, receipts)
        document = {
            "schema_version": "bluefire.capability-cleanup-obligation.v1",
            "attempt_id": attempt_id,
            "lease_digest": lease["lease_digest"],
            "runner_policy_digest": binding["runner_policy_digest"],
            "workspace_path_digest": binding["workspace_path_digest"],
            "workspace_id": workspace_id,
            "receipts": receipts,
        }
        previous = connection.execute(
            "SELECT * FROM capability_cleanup_obligations WHERE attempt_id=?", (attempt_id,)
        ).fetchone()
        if previous is not None:
            if records._document(previous) != document:
                raise ProductStoreError("Cleanup obligation is already immutable.")
        else:
            records._insert_document(
                connection,
                "INSERT INTO capability_cleanup_obligations VALUES(?,?,?)",
                attempt_id,
                document,
            )
        return {"document": document, "document_digest": content_hash(document)}


def _claim_document(lease, obligation, obligation_digest, issued_ms, expires_ms, timeout_ms):
    return {
        "schema_version": "bluefire.runner-grant-cleanup.v1",
        "issuer": records.ISSUER,
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
        "obligation_digest": obligation_digest,
        "runner_policy_digest": obligation["runner_policy_digest"],
        "workspace_id": obligation["workspace_id"],
        "receipts": obligation["receipts"],
        "issued_at": records._iso(issued_ms),
        "expires_at": records._iso(expires_ms),
        "timeout_ms": timeout_ms,
    }


def claim_at(connection, attempt_id, lease):
    row = records._one(
        connection, "SELECT * FROM capability_cleanup_claims WHERE attempt_id=?", attempt_id
    )
    obligation_row, obligation = obligation_at(connection, attempt_id, lease)
    document = records._document(row)
    remaining = row["expires_at_ms"] - row["claimed_at_ms"]
    if (
        not lease["created_at_ms"] <= row["claimed_at_ms"] < row["expires_at_ms"]
        or row["expires_at_ms"]
        != min(
            lease["attempt_expires_at_ms"],
            row["claimed_at_ms"] + lease["reservation"]["cleanup_reserve_ms"],
        )
        or not 1 <= remaining <= 120000
        or type(document.get("timeout_ms")) is not int
        or not 1 <= document["timeout_ms"] <= remaining
        or document
        != _claim_document(
            lease,
            obligation,
            obligation_row["document_digest"],
            row["claimed_at_ms"],
            row["expires_at_ms"],
            document["timeout_ms"],
        )
    ):
        raise ProductStoreError("Persisted cleanup authority changed.")
    return row, document


def claim_cleanup(store, attempt_id, *, now_ms, timeout_ms) -> dict[str, Any]:
    records._time(now_ms)
    with store._connection(write=True) as connection:
        row, lease, _ = records._attempt_at(connection, attempt_id)
        obligation_row, obligation = obligation_at(connection, attempt_id, lease)
        expires = min(
            lease["attempt_expires_at_ms"], now_ms + lease["reservation"]["cleanup_reserve_ms"]
        )
        if (
            records._settled(store, connection, attempt_id)
            or now_ms < records._lineage_time(connection, row["lineage_id"])
            or not 1 <= expires - now_ms <= 120000
            or type(timeout_ms) is not int
            or not 1 <= timeout_ms <= expires - now_ms
            or connection.execute(
                "SELECT 1 FROM capability_cleanup_claims WHERE attempt_id=?", (attempt_id,)
            ).fetchone()
        ):
            raise ProductStoreError(
                "Cleanup authority is expired, already claimed, or outside its reserve."
            )
        document = _claim_document(
            lease, obligation, obligation_row["document_digest"], now_ms, expires, timeout_ms
        )
        connection.execute(
            "INSERT INTO capability_cleanup_claims VALUES(?,?,?,?,?)",
            (attempt_id, canonical_json(document), content_hash(document), now_ms, expires),
        )
        return {"document": document, "document_digest": content_hash(document)}


def register_cleanup_task(
    store, attempt_id, *, task_id, request_hash, expected_document_digest, now_ms
) -> dict[str, Any]:
    identifier(task_id, "cleanup task")
    digest(request_hash, "cleanup request")
    records._time(now_ms)
    with store._connection(write=True) as connection:
        row, lease, _ = records._attempt_at(connection, attempt_id)
        claim, _ = claim_at(connection, attempt_id, lease)
        if (
            claim["document_digest"] != expected_document_digest
            or not max(claim["claimed_at_ms"], records._lineage_time(connection, row["lineage_id"]))
            <= now_ms
            < claim["expires_at_ms"]
            or records._settled(store, connection, attempt_id)
            or connection.execute(
                "SELECT 1 FROM capability_task_claims WHERE task_id=?", (task_id,)
            ).fetchone()
            or connection.execute(
                "SELECT 1 FROM capability_cleanup_task_claims WHERE task_id=? OR attempt_id=?",
                (task_id, attempt_id),
            ).fetchone()
        ):
            raise ProductStoreError(
                "Cleanup task authority is expired, changed or already consumed."
            )
        connection.execute(
            "INSERT INTO capability_cleanup_task_claims VALUES(?,?,?,?,?)",
            (task_id, attempt_id, request_hash, expected_document_digest, now_ms),
        )
        return {"task_id": task_id, "attempt_id": attempt_id, "request_hash": request_hash}


def record_cleanup_terminal(store, task_id, *, request_hash, terminal_digest):
    digest(terminal_digest, "authenticated cleanup terminal")
    with store._connection(write=True) as connection:
        task = records._one(
            connection, "SELECT * FROM capability_cleanup_task_claims WHERE task_id=?", task_id
        )
        if task["request_hash"] != request_hash:
            raise ProductStoreError("Cleanup terminal belongs to another request.")
        document = {
            "schema_version": "bluefire.capability-cleanup-terminal.v1",
            "task_id": task_id,
            "attempt_id": task["attempt_id"],
            "request_hash": request_hash,
            "claim_digest": task["claim_digest"],
            "terminal_digest": terminal_digest,
        }
        previous = connection.execute(
            "SELECT * FROM capability_cleanup_terminals WHERE task_id=?", (task_id,)
        ).fetchone()
        if previous is not None:
            if records._document(previous) != document:
                raise ProductStoreError("Cleanup terminal is already immutable.")
            return
        records._insert_document(
            connection, "INSERT INTO capability_cleanup_terminals VALUES(?,?,?)", task_id, document
        )


def validate_settlement(connection, attempt_id, lease, native):
    if not connection.execute(
        "SELECT 1 FROM capability_cleanup_obligations WHERE attempt_id=?", (attempt_id,)
    ).fetchone():
        if any(
            connection.execute(sql, (attempt_id,)).fetchone()
            for sql in (
                "SELECT 1 FROM capability_cleanup_claims WHERE attempt_id=?",
                "SELECT 1 FROM capability_cleanup_task_claims WHERE attempt_id=?",
            )
        ):
            raise ProductStoreError("Cleanup authority is missing its original obligation.")
        return
    claim, _ = claim_at(connection, attempt_id, lease)
    task = records._one(
        connection, "SELECT * FROM capability_cleanup_task_claims WHERE attempt_id=?", attempt_id
    )
    terminal = records._document(
        records._one(
            connection,
            "SELECT * FROM capability_cleanup_terminals WHERE task_id=?",
            task["task_id"],
        )
    )
    if (
        task["claim_digest"] != claim["document_digest"]
        or not claim["claimed_at_ms"] <= task["claimed_at_ms"] < claim["expires_at_ms"]
        or terminal
        != {
            "schema_version": "bluefire.capability-cleanup-terminal.v1",
            "task_id": task["task_id"],
            "attempt_id": attempt_id,
            "request_hash": task["request_hash"],
            "claim_digest": task["claim_digest"],
            "terminal_digest": native.get("cleanup_digest"),
        }
    ):
        raise ProductStoreError("Native settlement does not prove the exact owned cleanup task.")


def get_cleanup(store, attempt_id) -> dict[str, Any]:
    with store._connection() as connection:
        _, lease, _ = records._attempt_at(connection, attempt_id)
        claim, document = claim_at(connection, attempt_id, lease)
        task = connection.execute(
            "SELECT * FROM capability_cleanup_task_claims WHERE attempt_id=?", (attempt_id,)
        ).fetchone()
        return {
            "document": document,
            "document_digest": claim["document_digest"],
            "task": dict(task) if task else None,
        }
