"""Verify one finalized native run and its immutable evidence before inspection."""

from __future__ import annotations

from typing import Any, Mapping

from .assistance_run_protocol import AssistanceRunService
from .detection_evaluations import _source
from .product_store_errors import ProductStoreError
from .util import content_hash


def source(service: AssistanceRunService, operation: Mapping[str, Any]) -> Mapping[str, Any]:
    run_id = operation["progress"]["run_id"]
    run, records, observed = _source(service.detection_lab, run_id)
    runtime_changes = verify_lineage(service, operation, run)
    digest = run["manifest"]["bundle_hash"]
    if operation["progress"].get("run_digest") != digest:
        raise ProductStoreError(
            "The retained run manifest differs from its durable result binding."
        )
    cleanup = run.get("cleanup", {})
    cleanup_state = (
        "simulated"
        if run["mode"] == "simulate"
        else "complete"
        if cleanup.get("success") is True and cleanup.get("outstanding_receipt_count") == 0
        else "incomplete"
    )
    return {
        "run": run,
        "records": records,
        "observed": observed,
        "run_digest": digest,
        "cleanup_state": cleanup_state,
        "runtime_changes": runtime_changes,
    }


def verify_lineage(
    service: AssistanceRunService, operation: Mapping[str, Any], run: Mapping[str, Any]
) -> list[str]:
    """Follow only exact accepted native runtime reviews back to the prepared graph."""
    prepared = operation["progress"]["preparation"]
    current = run
    changes: list[str] = []
    seen: set[str] = set()
    for _ in range(32):
        if current["run_id"] in seen or current["mode"] != prepared["run_request"]["mode"]:
            raise ProductStoreError("Runtime run lineage is repeated or changes the reviewed mode.")
        seen.add(current["run_id"])
        replay = current.get("replay")
        resolution = replay.get("proposal_resolution") if isinstance(replay, Mapping) else None
        if not isinstance(resolution, Mapping):
            if (
                current["scenario"] != prepared["scenario"]
                or current["plan"]["autonomy"] != prepared["run_request"]["autonomy"]
            ):
                raise ProductStoreError(
                    "The retained run differs from its exact accepted preparation."
                )
            return changes
        identifier = resolution.get("proposal_record_id")
        if not isinstance(identifier, str):
            raise ProductStoreError("Runtime continuation lacks a native review identity.")
        review = service.product_store.get_ai_proposal_review(identifier)
        accepted = review.get("resolution", {})
        audit = accepted.get("continuation", {})
        if (
            review.get("job_id") != operation["progress"].get("run_job_id")
            or review.get("status") != "accepted"
            or accepted.get("decision") != "accepted"
            or audit.get("replay") != replay
            or audit.get("scenario_digest") != content_hash(current["scenario"])
            or audit.get("continuation_plan_digest") != content_hash(current["plan"])
            or audit.get("autonomy") != current["plan"]["autonomy"]
            or any(
                review.get(key) != resolution.get(key)
                for key in (
                    "proposal_record_id",
                    "source_proposal_id",
                    "state_digest",
                    "plan_digest",
                    "proposal_digest",
                )
            )
            or review.get("source_run_id") != replay.get("source_run_id")
        ):
            raise ProductStoreError("Runtime continuation differs from its exact accepted review.")
        current = service.store.get_run(review["source_run_id"])
        if content_hash(current["scenario"]) != replay.get("source_scenario_digest"):
            raise ProductStoreError("Runtime continuation source scenario differs from its review.")
        changes.append(identifier)
    raise ProductStoreError("Runtime continuation lineage exceeds its bound.")
