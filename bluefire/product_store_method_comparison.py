"""Atomic decisions, publication guards and receipts for one method experiment."""

from __future__ import annotations

import json
import sqlite3
from contextlib import AbstractContextManager
from typing import Any, Callable, Mapping, Protocol

from .ai_method_comparison import PROPOSAL_SCHEMA
from .product_store_detection_evaluations import _read_row, save_report
from .product_store_errors import ProductStoreError
from .product_store_serialization import canonical_json, utc_now
from .util import content_hash

PROPOSE_KIND = "replay.ai.propose"
RECOVER_KIND = "replay.comparison.recover"


class MethodComparisonStore(Protocol):
    """Caller-owned transaction and durable-job decoding for comparison receipts."""

    def _connection(self, *, write: bool = False) -> AbstractContextManager[sqlite3.Connection]: ...

    @staticmethod
    def _job_from_row(row: sqlite3.Row) -> Mapping[str, Any]: ...


def job_at(
    store: MethodComparisonStore, connection: sqlite3.Connection, job_id: str
) -> Mapping[str, Any]:
    row = connection.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
    if row is None:
        raise ProductStoreError("Method operation job was not found.")
    return store._job_from_row(row)


def proposal_at(job: Mapping[str, Any]) -> Mapping[str, Any]:
    proposal = job["progress"].get("proposal")
    if (
        job["kind"] != PROPOSE_KIND
        or not isinstance(proposal, Mapping)
        or proposal.get("schema_version") != PROPOSAL_SCHEMA
        or proposal.get("proposal_digest")
        != content_hash({key: value for key, value in proposal.items() if key != "proposal_digest"})
    ):
        raise ProductStoreError("Retained method proposal is invalid.")
    request = job["request"]
    if (
        proposal.get("source_run") != request.get("source_run")
        or proposal.get("detector") != request.get("detector")
        or proposal.get("provider_binding_digest") != request.get("provider_binding_digest")
    ):
        raise ProductStoreError("Method proposal does not match its saved context.")
    options = request.get("options", [])
    option = next(
        (value for value in options if value.get("option_id") == proposal.get("option_id")), None
    )
    if (
        option is None
        or proposal.get("replay_preparation") != option.get("replay_preparation")
        or proposal.get("option")
        != {key: value for key, value in option.items() if key != "replay_preparation"}
    ):
        raise ProductStoreError("Method proposal differs from its prepared allowed option.")
    return proposal


def patch(
    connection: sqlite3.Connection,
    job: Mapping[str, Any],
    update: Mapping[str, Any],
    *,
    result_ref: str | None = None,
) -> None:
    connection.execute(
        "UPDATE jobs SET progress_json = ?, result_ref = COALESCE(?, result_ref), updated_at = ? WHERE job_id = ?",
        (canonical_json({**job["progress"], **update}), result_ref, utc_now(), job["job_id"]),
    )


def decide(
    store: MethodComparisonStore,
    job_id: str,
    request: Mapping[str, Any],
    *,
    automatic: bool = False,
) -> Mapping[str, Any]:
    with store._connection(write=True) as connection:
        job = job_at(store, connection, job_id)
        proposal = proposal_at(job)
        if request["decision"] == "accept":
            from .product_store_assistance import require_active

            require_active(store, connection, job)
        if proposal["proposal_digest"] != request["proposal_digest"]:
            raise ProductStoreError("Method proposal changed before review.")
        previous = job["progress"].get("decision")
        if previous is not None:
            if any(previous.get(key) != value for key, value in request.items()):
                raise ProductStoreError("This method proposal already has a different decision.")
            return job
        if job["progress"].get("stopped") or (
            job["state"] != "completed"
            and not (
                automatic and job["state"] == "running" and job["request"].get("autonomy") == "auto"
            )
        ):
            raise ProductStoreError("Method proposal is unavailable or stopped.")
        row = connection.execute(
            "SELECT digest FROM resources WHERE kind = 'detection' AND resource_id = ?",
            (proposal["detector"]["candidate_id"],),
        ).fetchone()
        if row is None or row["digest"] != proposal["detector"]["resource_digest"]:
            raise ProductStoreError("The reviewed detector changed.")
        patch(
            connection,
            job,
            {
                "decision": {
                    "schema_version": "bluefire.method-comparison-decision.v1",
                    **request,
                    "basis": "bounded_auto_policy" if automatic else "operator_review",
                    "reviewed_at": utc_now(),
                }
            },
        )
        return job_at(store, connection, job_id)


def publication_guard(
    store: MethodComparisonStore, connection: sqlite3.Connection, document: Mapping[str, Any]
) -> None:
    """Called inside the same writer transaction that inserts the replay job."""
    binding = document["method_comparison"]
    job = job_at(store, connection, binding["proposal_job_id"])
    proposal = proposal_at(job)
    from .product_store_assistance import require_active

    require_active(store, connection, job)
    if (
        job["progress"].get("stopped")
        or job["progress"].get("decision", {}).get("decision") != "accept"
        or binding["proposal_digest"] != proposal["proposal_digest"]
        or document["replay_preparation"] != proposal["replay_preparation"]
        or document["source_run_id"] != proposal["source_run"]["run_id"]
    ):
        raise ProductStoreError("Method replay publication is no longer authorized.")
    if document["_submission"]["submission_id"] != job["request"]["replay_submission_id"]:
        raise ProductStoreError("Method replay identity does not match its reservation.")
    row = connection.execute(
        "SELECT digest FROM resources WHERE kind = 'detection' AND resource_id = ?",
        (proposal["detector"]["candidate_id"],),
    ).fetchone()
    if row is None or row["digest"] != proposal["detector"]["resource_digest"]:
        raise ProductStoreError("The reviewed detector changed before publication.")


def stop(store: MethodComparisonStore, job_id: str) -> Mapping[str, Any]:
    with store._connection(write=True) as connection:
        job = job_at(store, connection, job_id)
        if job["kind"] != PROPOSE_KIND:
            raise ProductStoreError("Only a method proposal can own this stop receipt.")
        patch(
            connection,
            job,
            {"stopped": True, "stop_generation": job["progress"].get("stop_generation", 0) + 1},
        )
        return job_at(store, connection, job_id)


def recovery_guard(
    store: MethodComparisonStore, connection: sqlite3.Connection, document: Mapping[str, Any]
) -> None:
    parent = job_at(store, connection, document["proposal_job_id"])
    proposal_at(parent)
    if document.get("stop_generation") != parent["progress"].get("stop_generation", 0):
        raise ProductStoreError("A newer Stop invalidated comparison recovery publication.")
    if document["replay_job_id"] != parent["progress"].get("replay_result", {}).get(
        "replay_job_id"
    ):
        raise ProductStoreError("Comparison recovery has a different replay owner.")


def retain_run(
    store: MethodComparisonStore,
    *,
    proposal_job_id: str,
    replay_job_id: str,
    run_binding: Mapping[str, Any],
) -> None:
    with store._connection(write=True) as connection:
        parent = job_at(store, connection, proposal_job_id)
        child = job_at(store, connection, replay_job_id)
        if child["request"].get("method_comparison", {}).get("proposal_job_id") != proposal_job_id:
            raise ProductStoreError("Replay result has the wrong operation owner.")
        receipt = {"replay_job_id": replay_job_id, "source": dict(run_binding)}
        existing = parent["progress"].get("replay_result")
        if existing is not None and existing != receipt:
            raise ProductStoreError("An operation cannot acquire another replay result.")
        patch(connection, child, {"replay_result": receipt}, result_ref=run_binding["run_id"])
        patch(connection, parent, {"replay_result": receipt})


def commit_comparison(
    store: MethodComparisonStore,
    *,
    proposal_job_id: str,
    application_job_id: str,
    build: Callable[[], tuple[list[Mapping[str, Any]], Mapping[str, Any]]],
    check_cancelled: Callable[[], None],
) -> Mapping[str, Any]:
    with store._connection(write=True) as connection:
        parent = job_at(store, connection, proposal_job_id)
        proposal = proposal_at(parent)
        application = job_at(store, connection, application_job_id)
        owner = (
            application["request"].get("method_comparison", {}).get("proposal_job_id")
            if application["kind"] == "scenario.replay"
            else (
                application["request"].get("proposal_job_id")
                if application["kind"] == RECOVER_KIND
                else None
            )
        )
        if owner != proposal_job_id:
            raise ProductStoreError("Comparison application belongs to another operation.")
        replay_result = parent["progress"]["replay_result"]
        detector = proposal["detector"]
        expected = {
            "schema_version": "bluefire.method-comparison-result.v1",
            "proposal_job_id": proposal_job_id,
            "proposal_digest": proposal["proposal_digest"],
            "replay_job_id": replay_result["replay_job_id"],
            "source_run_id": proposal["source_run"]["run_id"],
            "child_run_id": replay_result["source"]["run_id"],
            "candidate_id": detector["candidate_id"],
            "candidate_definition_digest": detector["definition_digest"],
        }
        existing = parent["progress"].get("comparison")
        if existing is not None:
            if not isinstance(existing, Mapping) or any(
                existing.get(key) != value for key, value in expected.items()
            ):
                raise ProductStoreError("Retained comparison belongs to another operation or run.")
            row = connection.execute(
                "SELECT document_json, digest FROM resources WHERE kind = 'comparison' AND resource_id = ?",
                (existing["comparison_id"],),
            ).fetchone()
            if (
                row is None
                or row["digest"] != existing["comparison_digest"]
                or content_hash(json.loads(row["document_json"])) != row["digest"]
                or json.loads(row["document_json"]).get("run_ids")
                != [expected["source_run_id"], expected["child_run_id"]]
            ):
                raise ProductStoreError("Retained comparison failed integrity validation.")
            for key in ("baseline_evaluation_id", "child_evaluation_id"):
                report_row = connection.execute(
                    "SELECT * FROM detection_run_evaluations WHERE evaluation_id = ?",
                    (existing[key],),
                ).fetchone()
                if report_row is None:
                    raise ProductStoreError("Retained evaluation is missing.")
                report = _read_row(report_row)
                expected_source = (
                    proposal["source_run"]
                    if key == "baseline_evaluation_id"
                    else replay_result["source"]
                )
                if (
                    report["candidate"]["definition_digest"]
                    != existing["candidate_definition_digest"]
                    or report["candidate"]["candidate_id"] != detector["candidate_id"]
                    or report["source"] != expected_source
                ):
                    raise ProductStoreError("Retained evaluation has a different binding.")
            patch(connection, application, {"comparison": existing})
            return dict(existing)
        check_cancelled()
        if parent["progress"].get("stopped") and not (
            application["kind"] == RECOVER_KIND
            and application["request"].get("stop_generation")
            == parent["progress"].get("stop_generation", 0)
        ):
            raise ProductStoreError("Method comparison was stopped.")
        row = connection.execute(
            "SELECT digest FROM resources WHERE kind = 'detection' AND resource_id = ?",
            (detector["candidate_id"],),
        ).fetchone()
        if row is None or row["digest"] != detector["resource_digest"]:
            raise ProductStoreError(
                "The detector changed before comparison; the replay is retained."
            )
        reports, comparison = build()
        saved = [save_report(connection, report) for report in reports]
        comparison_id = comparison["comparison_id"]
        digest = content_hash(comparison)
        row = connection.execute(
            "SELECT digest FROM resources WHERE kind = 'comparison' AND resource_id = ?",
            (comparison_id,),
        ).fetchone()
        if row is not None and row["digest"] != digest:
            raise ProductStoreError("Comparison identity has conflicting content.")
        now = utc_now()
        connection.execute(
            "INSERT INTO resources(kind, resource_id, status, digest, document_json, created_at, updated_at) VALUES ('comparison', ?, 'ready', ?, ?, ?, ?) ON CONFLICT(kind, resource_id) DO NOTHING",
            (comparison_id, digest, canonical_json(comparison), now, now),
        )
        replay_result = parent["progress"]["replay_result"]
        receipt = {
            **expected,
            "baseline_evaluation_id": saved[0]["evaluation_id"],
            "child_evaluation_id": saved[1]["evaluation_id"],
            "comparison_id": comparison_id,
            "comparison_digest": digest,
        }
        check_cancelled()
        patch(connection, parent, {"comparison": receipt})
        patch(connection, application, {"comparison": receipt})
        return receipt
