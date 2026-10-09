"""Durable, pack-specific dependency closure behind the shared attempt ledger."""

from typing import Any

from .capability_packs import FILE_ACCESS_PACK, grant_pack
from .capability_resources import digest
from .product_store_capability_grants import (
    _attempt_at,
    _claim_at,
    _document,
    _grant_at,
    _insert_document,
    _one,
)
from .product_store_errors import ProductStoreError
from .util import content_hash


def _file_access(connection, lease):
    _, grant, _ = _grant_at(connection, lease["grant_id"])
    return grant_pack(grant) == FILE_ACCESS_PACK


def _dependency_query(is_file):
    return (
        "SELECT * FROM capability_file_access_bindings WHERE attempt_id=?"
        if is_file
        else "SELECT * FROM capability_receiver_bindings WHERE attempt_id=?"
    )


def dependency_at(connection, attempt_id, lease):
    query = _dependency_query(_file_access(connection, lease))
    return _document(_one(connection, query, attempt_id))


def bind_file_access(store, attempt_id, *, binding_digest, resource_generation, control_revision):
    digest(binding_digest, "file-access execution binding")
    with store._connection(write=True) as connection:
        _, lease, compiled = _attempt_at(connection, attempt_id)
        _claim_at(connection, attempt_id, lease)
        _one(
            connection, "SELECT * FROM capability_preparation_starts WHERE attempt_id=?", attempt_id
        )
        if (
            not _file_access(connection, lease)
            or connection.execute(
                "SELECT 1 FROM capability_attempt_settlements WHERE attempt_id=?", (attempt_id,)
            ).fetchone()
        ):
            raise ProductStoreError("The exact file-access attempt cannot acquire a dependency.")
        dependency = compiled["file_access"]
        if (
            resource_generation != dependency["resource_generation"]
            or control_revision != dependency["control_revision"]
        ):
            raise ProductStoreError("File-access preparation changed resource or control revision.")
        document = {
            "schema_version": "bluefire.capability-file-access-binding.v1",
            "attempt_id": attempt_id,
            "lease_digest": lease["lease_digest"],
            "binding_digest": binding_digest,
            "resource_generation": resource_generation,
            "control_revision": control_revision,
        }
        previous = connection.execute(
            "SELECT * FROM capability_file_access_bindings WHERE attempt_id=?", (attempt_id,)
        ).fetchone()
        if previous is not None:
            if _document(previous) != document:
                raise ProductStoreError("The attempt already owns another resource dependency.")
            return
        _insert_document(
            connection,
            "INSERT INTO capability_file_access_bindings VALUES(?,?,?)",
            attempt_id,
            document,
        )


def record_file_access_terminal(
    store, attempt_id, *, task_id, request_hash, terminal_digest, proof
):
    with store._connection(write=True) as connection:
        _, lease, _ = _attempt_at(connection, attempt_id)
        binding = dependency_at(connection, attempt_id, lease)
        task = _one(connection, "SELECT * FROM capability_task_claims WHERE task_id=?", task_id)
        terminal = _document(
            _one(connection, "SELECT * FROM capability_task_terminals WHERE task_id=?", task_id)
        )
        if (
            not _file_access(connection, lease)
            or task["attempt_id"] != attempt_id
            or task["request_hash"] != request_hash
            or terminal["terminal_digest"] != terminal_digest
        ):
            raise ProductStoreError(
                "File-access closure lacks its exact authenticated task terminal."
            )
        if (
            not isinstance(proof, dict)
            or set(proof) != {"state", "binding_digest", "observation_digest"}
            or proof["state"] not in ("verified_closed", "not_sent")
            or proof["binding_digest"] != binding["binding_digest"]
        ):
            raise ProductStoreError(
                "File-access request closure is not bound to its enrolled resource."
            )
        digest(proof["observation_digest"], "file-access request closure evidence")
        document = {
            "attempt_id": attempt_id,
            "task_id": task_id,
            "request_hash": request_hash,
            "terminal_digest": terminal_digest,
            "proof": proof,
        }
        previous = connection.execute(
            "SELECT * FROM capability_file_access_terminals WHERE task_id=?", (task_id,)
        ).fetchone()
        if previous is not None:
            if _document(previous) != document:
                raise ProductStoreError("File-access closure is already immutable.")
            return
        _insert_document(
            connection,
            "INSERT INTO capability_file_access_terminals VALUES(?,?,?)",
            task_id,
            document,
        )


def file_access_closure(store, attempt_id: str) -> dict[str, Any]:
    with store._connection() as connection:
        _, lease, _ = _attempt_at(connection, attempt_id)
        binding = dependency_at(connection, attempt_id, lease)
        if not _file_access(connection, lease):
            raise ProductStoreError("The attempt has no enrolled file-access dependency.")
        terminals = _file_terminals(connection, attempt_id, binding)
        return {
            "state": "verified_closed",
            **{
                key: binding[key]
                for key in ("binding_digest", "resource_generation", "control_revision")
            },
            "task_terminals_digest": content_hash(terminals),
        }


def _file_terminals(connection, attempt_id, binding):
    terminals = []
    for task in connection.execute(
        "SELECT * FROM capability_task_claims WHERE attempt_id=? ORDER BY task_id", (attempt_id,)
    ):
        terminal = _document(
            _one(
                connection,
                "SELECT * FROM capability_task_terminals WHERE task_id=?",
                task["task_id"],
            )
        )
        closure = _document(
            _one(
                connection,
                "SELECT * FROM capability_file_access_terminals WHERE task_id=?",
                task["task_id"],
            )
        )
        if (
            terminal["request_hash"] != task["request_hash"]
            or closure["terminal_digest"] != terminal["terminal_digest"]
            or closure["request_hash"] != task["request_hash"]
            or closure["proof"]["binding_digest"] != binding["binding_digest"]
        ):
            raise ProductStoreError("The file-access request terminal or closure changed.")
        terminals.append(closure)
    return terminals


def validate_dependency(connection, attempt_id, lease, receipt):
    is_file = _file_access(connection, lease)
    dependency_key = "file_access" if is_file else "receiver"
    schema = (
        "bluefire.file-access-attempt-settlement.v1"
        if is_file
        else "bluefire.capability-attempt-settlement.v1"
    )
    if (
        not isinstance(receipt, dict)
        or set(receipt)
        != {"schema_version", "attempt_id", "lease_digest", dependency_key, "native"}
        or receipt.get("schema_version") != schema
        or receipt["attempt_id"] != attempt_id
        or receipt["lease_digest"] != lease["lease_digest"]
    ):
        raise ProductStoreError("Capability settlement does not bind its exact attempt and pack.")
    binding_row = connection.execute(_dependency_query(is_file), (attempt_id,)).fetchone()
    dependency = receipt[dependency_key]
    if binding_row is None:
        if connection.execute(
            "SELECT 1 FROM capability_preparation_starts WHERE attempt_id=?", (attempt_id,)
        ).fetchone() or dependency != {"state": "not_started"}:
            raise ProductStoreError("Dependency settlement lacks its reserved identity.")
        return
    binding = _document(binding_row)
    _claim_at(connection, attempt_id, lease)
    _one(connection, "SELECT * FROM capability_preparation_starts WHERE attempt_id=?", attempt_id)
    if (
        binding.get("attempt_id") != attempt_id
        or binding.get("lease_digest") != lease["lease_digest"]
    ):
        raise ProductStoreError("Dependency belongs to another capability attempt.")
    if is_file:
        if (
            not isinstance(dependency, dict)
            or set(dependency)
            != {
                "state",
                "binding_digest",
                "resource_generation",
                "control_revision",
                "task_terminals_digest",
            }
            or dependency["state"] != "verified_closed"
            or any(
                dependency[key] != binding[key]
                for key in ("binding_digest", "resource_generation", "control_revision")
            )
        ):
            raise ProductStoreError("The exact file-access requests are not verified closed.")
        terminals = _file_terminals(connection, attempt_id, binding)
        if dependency["task_terminals_digest"] != content_hash(terminals):
            raise ProductStoreError("The file-access closure omits registered request terminals.")
    else:
        if (
            not isinstance(dependency, dict)
            or set(dependency) != {"state", "session_generation", "review_digest", "receipt_digest"}
            or dependency["state"] != "verified_closed"
            or any(
                dependency[key] != binding[key] for key in ("session_generation", "review_digest")
            )
        ):
            raise ProductStoreError("The exact owned receiver is not verified closed.")
        digest(dependency["receipt_digest"], "receiver cleanup receipt")
