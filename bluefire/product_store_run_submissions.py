"""Atomic closure of a refused run UUID; a publication winner always wins."""

from __future__ import annotations

from typing import Any, Mapping

from .product_store import ProductStore
from .product_store_serialization import canonical_json, utc_now


def close_refused(
    store: ProductStore,
    submitted: Mapping[str, Any],
    submission_id: str,
    intent: str,
    *,
    assistance_run: Mapping[str, Any] | None,
    refusal: Mapping[str, Any],
    report: Mapping[str, Any] | None,
    receiver_defense: Mapping[str, Any] | None = None,
) -> Mapping[str, Any]:
    job_id, binding = store._job_submission_binding(submission_id, intent)
    with store._connection(write=True) as connection:
        row = connection.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
        if row is not None:
            return store._matching_job_submission(row, "scenario.run", binding)
        now = utc_now()
        request = {
            "_run_submission_request": dict(submitted),
            "_submission": dict(binding),
            "_run_submission_preflight": report,
        }
        if assistance_run is not None:
            request["assistance_run"] = dict(assistance_run)
        if receiver_defense is not None:
            request["receiver_defense"] = dict(receiver_defense)
        connection.execute(
            "INSERT INTO jobs(job_id,kind,state,request_json,progress_json,error_json,created_at,updated_at) "
            "VALUES(?,'scenario.run','failed',?,?,?,?,?)",
            (
                job_id,
                canonical_json(request),
                canonical_json(
                    {
                        "phase": "closed_submission",
                        "effects_started": False,
                        "refusal": dict(refusal),
                    }
                ),
                canonical_json({key: refusal[key] for key in ("code", "message")}),
                now,
                now,
            ),
        )
        row = connection.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
        return store._job_from_row(row)
