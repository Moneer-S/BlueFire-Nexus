"""Thin publication and cancellation guards in the existing durable jobs database."""

from __future__ import annotations

import sqlite3
import uuid
from contextlib import AbstractContextManager
from typing import Any, Mapping, Protocol

from .product_store_errors import ProductStoreError
from .product_store_serialization import canonical_json, utc_now
from .util import content_hash

KIND = "assistance.turn"


class AssistanceStore(Protocol):
    def _connection(self, *, write: bool = False) -> AbstractContextManager[sqlite3.Connection]: ...

    @staticmethod
    def _job_from_row(row: sqlite3.Row) -> Mapping[str, Any]: ...


def job_at(
    store: AssistanceStore, connection: sqlite3.Connection, job_id: str
) -> Mapping[str, Any]:
    row = connection.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
    if row is None:
        raise ProductStoreError("Assistance operation job was not found.")
    return store._job_from_row(row)


def patch(
    connection: sqlite3.Connection, job: Mapping[str, Any], values: Mapping[str, Any]
) -> None:
    connection.execute(
        "UPDATE jobs SET progress_json = ?, updated_at = ? WHERE job_id = ?",
        (canonical_json({**job["progress"], **values}), utc_now(), job["job_id"]),
    )


def _original_child(
    store: AssistanceStore, connection: sqlite3.Connection, child: Mapping[str, Any]
) -> Mapping[str, Any]:
    """Follow only the existing explicit detection retry contract, never arbitrary ancestry."""
    for _ in range(32):
        previous_id = child["request"].get("retry_of_job_id")
        if previous_id is None:
            return child
        previous = job_at(store, connection, previous_id)
        expected = {
            key: value for key, value in previous["request"].items() if key != "_submission"
        }
        expected["retry_of_job_id"] = previous_id
        identifier = str(uuid.uuid5(uuid.NAMESPACE_URL, "bluefire.detection.retry:" + previous_id))
        if (
            previous["state"] != "interrupted"
            or child["kind"] != previous["kind"]
            or child["kind"] not in {"detection.ai.propose", "detection.ai.apply"}
            or {key: value for key, value in child["request"].items() if key != "_submission"}
            != expected
            or child["request"]["_submission"]["submission_id"] != identifier
            or child["request"]["_submission"]["intent_digest"] != content_hash(expected)
        ):
            raise ProductStoreError("Assistance detection retry lineage is invalid.")
        child = previous
    raise ProductStoreError("Assistance detection retry lineage exceeds its bound.")


def turn_at(
    store: AssistanceStore, connection: sqlite3.Connection, job_id: str
) -> Mapping[str, Any]:
    job = job_at(store, connection, job_id)
    if job["kind"] != KIND:
        raise ProductStoreError("The saved job is not an assistance turn.")
    return job


def require_active(
    store: AssistanceStore, connection: sqlite3.Connection, child: Mapping[str, Any]
) -> None:
    binding = child["request"].get("assistance_turn")
    if binding is None:
        return
    parent = turn_at(store, connection, binding["parent_job_id"])
    reserved = parent["progress"].get("children", {}).get(binding["step_id"])
    if (
        parent["progress"].get("stopped")
        or parent["state"] in {"cancelled", "cancelling"}
        or not reserved
        or _original_child(store, connection, child)["job_id"] != reserved["job_id"]
    ):
        raise ProductStoreError("The assistance turn no longer authorizes this child operation.")


def publication_guard(
    store: AssistanceStore, connection: sqlite3.Connection, kind: str, document: Mapping[str, Any]
) -> None:
    binding = document["assistance_turn"]
    if not isinstance(binding, dict) or set(binding) != {"parent_job_id", "step_id"}:
        raise ProductStoreError("Assistance lineage is invalid.")
    parent = turn_at(store, connection, binding["parent_job_id"])
    reserved = parent["progress"].get("children", {}).get(binding["step_id"])
    if (
        parent["progress"].get("stopped")
        or parent["state"] in {"cancelled", "cancelling"}
        or not isinstance(reserved, dict)
    ):
        raise ProductStoreError("The assistance child is stopped or was not reserved.")
    if kind == "detection.ai.apply":
        proposal = job_at(store, connection, document["proposal_job_id"])
        require_active(store, connection, proposal)
        if proposal["request"].get("assistance_turn") != binding:
            raise ProductStoreError("Assistance application has a different proposal lineage.")
        return
    if kind == "detection.ai.propose" and document.get("retry_of_job_id"):
        original = _original_child(
            store,
            connection,
            {
                "job_id": "job-" + uuid.UUID(document["_submission"]["submission_id"]).hex,
                "kind": kind,
                "request": document,
            },
        )
        if original["job_id"] != reserved["job_id"]:
            raise ProductStoreError("Assistance retry has a different reserved original child.")
        return
    if (
        kind != reserved["kind"]
        or document.get("submitted_request") != reserved["request"]
        or document.get("_submission", {}).get("submission_id") != reserved["submission_id"]
    ):
        raise ProductStoreError("Assistance child differs from its reserved intent.")
    identity = (
        document.get("candidate_id")
        if kind == "detection.ai.propose"
        else document.get("source_run_id")
    )
    if identity != reserved["object_id"]:
        raise ProductStoreError("Assistance child uses a different selected object.")


def reserve(
    store: AssistanceStore, parent_id: str, step_id: str, child: Mapping[str, Any]
) -> Mapping[str, Any]:
    with store._connection(write=True) as connection:
        parent = turn_at(store, connection, parent_id)
        if parent["progress"].get("stopped") or parent["state"] in {"cancelled", "cancelling"}:
            raise ProductStoreError("Assistance turn is cancelled.")
        if not any(step["step_id"] == step_id for step in parent["progress"].get("plan", [])):
            raise ProductStoreError("Assistance step is not in its retained plan.")
        children = dict(parent["progress"].get("children", {}))
        previous = children.get(step_id)
        if previous is not None and previous != child:
            raise ProductStoreError("Assistance step already has a different bound child.")
        children[step_id] = dict(child)
        patch(connection, parent, {"children": children})
        return child


def update(store: AssistanceStore, parent_id: str, values: Mapping[str, Any]) -> None:
    with store._connection(write=True) as connection:
        parent = turn_at(store, connection, parent_id)
        patch(connection, parent, values)


def stop(store: AssistanceStore, parent_id: str) -> Mapping[str, Any]:
    with store._connection(write=True) as connection:
        parent = turn_at(store, connection, parent_id)
        patch(connection, parent, {"stopped": True})
        return turn_at(store, connection, parent_id)
