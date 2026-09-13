"""Receiver analysis reservations in the existing Assistant writer transaction."""

import uuid

from .product_store_assistance import job_at, patch, turn_at
from .product_store_contracts import safe_document
from .product_store_errors import ProductStoreError
from .receiver_defense_contract import INSPECT_KIND
from .util import content_hash

TERMINAL = {"completed", "failed", "cancelled", "interrupted"}


def active(store, connection, parent_id):
    parent = turn_at(store, connection, parent_id)
    if parent["progress"].get("stopped") or parent["state"] in {"cancelling", "cancelled"}:
        raise ProductStoreError("The Assistant receiver operation was stopped.")
    return parent


def reserve(store, parent_id, request, *, recovery=False):
    with store._connection(write=True) as connection:
        parent = active(store, connection, parent_id)
        items = list(parent["progress"].get("receiver_inspections", []))
        matches = [
            row for row in items if row["request"]["prefix_digest"] == request["prefix_digest"]
        ]
        if matches:
            previous = matches[-1]
            row = connection.execute(
                "SELECT * FROM jobs WHERE job_id = ?", (previous["job_id"],)
            ).fetchone()
            job = store._job_from_row(row) if row else None
            if (
                not recovery
                or job is None
                or job["state"] not in {"failed", "interrupted"}
                or job["progress"].get("interpretation")
            ):
                return previous
        if len(matches) >= 3 or len(items) >= 9:
            raise ProductStoreError(
                "The bounded receiver analysis recovery allowance is exhausted."
            )
        identifier = str(
            uuid.uuid5(
                uuid.UUID(parent["request"]["submitted_request"]["submission_id"]),
                "receiver-inspection:" + request["prefix_digest"] + ":" + str(len(matches)),
            )
        )
        receipt = {
            "job_id": "job-" + uuid.UUID(identifier).hex,
            "submission_id": identifier,
            "request": {**request, "submission_id": identifier},
        }
        safe = safe_document(
            {"receiver_inspections": [*items, receipt]}, context="receiver inspection reservation"
        )
        patch(connection, parent, safe)
        return receipt


def publication_guard(store, connection, kind, document):
    marker = document["assistance_receiver"]
    if not isinstance(marker, dict) or set(marker) != {"parent_job_id", "owner_job_id"}:
        raise ProductStoreError("Receiver analysis lineage is invalid.")
    parent = active(store, connection, marker["parent_job_id"])
    selected = parent["request"]["context"]["selected"]
    if selected["kind"] == "receiver_test":
        owner_id = selected["receiver_job_id"]
    elif selected["kind"] == "receiver_scenario":
        plan = parent["progress"]["plan"]
        owner_id = parent["progress"]["children"][plan[0]["step_id"]]["job_id"]
    else:
        raise ProductStoreError("Receiver analysis parent has another capability context.")
    if marker["owner_job_id"] != owner_id:
        raise ProductStoreError("Receiver analysis has another selected owner.")
    submission = document.get("_submission", {})
    matches = [
        row
        for row in parent["progress"].get("receiver_inspections", [])
        if row["submission_id"] == submission.get("submission_id")
    ]
    if (
        kind != INSPECT_KIND
        or len(matches) != 1
        or document.get("submitted_request") != matches[0]["request"]
        or marker["owner_job_id"] != matches[0]["request"]["owner_job_id"]
        or submission.get("intent_digest") != content_hash(document["submitted_request"])
    ):
        raise ProductStoreError("Receiver analysis differs from its exact reserved request.")


def retain(store, job_id, interpretation):
    with store._connection(write=True) as connection:
        job = job_at(store, connection, job_id)
        publication_guard(store, connection, job["kind"], job["request"])
        if job["state"] in {"cancelled", "cancelling"}:
            raise ProductStoreError("Receiver analysis was cancelled.")
        patch(
            connection,
            job,
            safe_document(
                {
                    "interpretation": interpretation,
                    "interpretation_digest": content_hash(interpretation),
                },
                context="receiver model interpretation",
            ),
        )
