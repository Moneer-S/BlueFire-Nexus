"""Read existing native receipts without evaluating, replaying, or creating reports."""

from __future__ import annotations

from typing import Any, Mapping
from urllib.parse import urlencode

from .ai_assistance import REVISE
from .assistance_context import AssistanceContext, detection_path
from .product_store_detection_ai import proposal_from_job
from .product_store_errors import ProductStoreError
from .product_store_method_comparison import proposal_at
from .util import content_hash

TERMINAL = {"completed", "cancelled", "failed", "interrupted"}


def child_path(child: Mapping[str, Any]) -> str:
    if child["kind"] == "detection.ai.propose":
        return detection_path(
            child["request"]["submitted_request"]["run_id"],
            child["request"]["candidate_id"],
            child["job_id"],
        )
    return "/compare?" + urlencode(
        {"source": child["request"]["source_run_id"], "method_job": child["job_id"]}
    )


def child_job(
    service: AssistanceContext, parent: Mapping[str, Any], step: Mapping[str, Any]
) -> Mapping[str, Any] | None:
    reserved = parent["progress"].get("children", {}).get(step["step_id"])
    if reserved is None:
        return None
    try:
        child = service.product_store.get_job(reserved["job_id"])
    except ProductStoreError:
        return None
    if (
        child["kind"] != reserved["kind"]
        or child["request"].get("assistance_turn")
        != {"parent_job_id": parent["job_id"], "step_id": step["step_id"]}
        or child["request"].get("submitted_request") != reserved["request"]
    ):
        raise ProductStoreError("Assistance child lineage differs from its reserved request.")
    if child["kind"] == "detection.ai.propose":
        for _ in range(32):
            if child["state"] != "interrupted":
                return child
            request, submission = service.detection_ai._retry_intent(child)
            successor = service.product_store.get_job_submission(
                child["kind"], submission_id=submission, intent_digest=content_hash(request)
            )
            if successor is None:
                return child
            if {
                key: value for key, value in successor["request"].items() if key != "_submission"
            } != request:
                raise ProductStoreError(
                    "The detection retry differs from its retained assistance child."
                )
            child = successor
        raise ProductStoreError("Assistance detection retry lineage exceeds its bound.")
    return child


def result(
    service: AssistanceContext, child: Mapping[str, Any], step: Mapping[str, Any]
) -> Mapping[str, Any] | None:
    if step["capability_id"] == REVISE:
        receipt = child["progress"].get("application")
        if receipt is None:
            return None
        proposal = proposal_from_job(child)
        resource = service.detection_lab._resource(receipt["candidate_id"])
        reports = service.detection_lab.run_evaluations(resource["id"])["evaluations"]
        matched = [row for row in reports if row["evaluation_id"] == receipt["evaluation_id"]]
        if (
            child["progress"].get("decision", {}).get("decision") != "accept"
            or receipt.get("proposal_job_id") != child["job_id"]
            or receipt.get("proposal_digest") != proposal["proposal_digest"]
            or len(matched) != 1
        ):
            raise ProductStoreError("The reviewed rule has no exact committed application receipt.")
        report = matched[0]
        if (
            report["source"] != proposal["source_run"]
            or report["candidate"]["candidate_id"] != resource["id"]
            or report["candidate"]["definition_digest"] != resource["document"]["definition_digest"]
            or report["candidate"]["resource_digest_at_evaluation"] != resource["digest"]
            or resource["document"].get("rule_source") != proposal["source"]
            or resource["document"].get("parent_candidate_id") != proposal["parent"]["candidate_id"]
            or not report.get("development_case")
        ):
            raise ProductStoreError(
                "The revised rule or measured source differs from its application receipt."
            )
        return {
            "kind": "detection_revision",
            "step_id": step["step_id"],
            "candidate_id": resource["id"],
            "evaluation_ids": [report["evaluation_id"]],
            "run_ids": [report["source"]["run_id"]],
            "comparison_id": None,
            "native_path": detection_path(
                report["source"]["run_id"], resource["id"], child["job_id"]
            ),
        }
    receipt = child["progress"].get("comparison")
    if receipt is None:
        return None
    proposal = proposal_at(child)
    comparison = service.product_store.get_resource("comparison", receipt["comparison_id"])
    run_ids = [proposal["source_run"]["run_id"], receipt["child_run_id"]]
    if (
        receipt.get("proposal_job_id") != child["job_id"]
        or receipt.get("proposal_digest") != proposal["proposal_digest"]
        or receipt["candidate_id"] != proposal["detector"]["candidate_id"]
        or receipt["candidate_definition_digest"] != proposal["detector"]["definition_digest"]
        or comparison["digest"] != receipt["comparison_digest"]
        or content_hash(comparison["document"]) != receipt["comparison_digest"]
        or comparison["document"]["run_ids"] != run_ids
        or comparison["document"]["baseline_run_id"] != run_ids[0]
    ):
        raise ProductStoreError("The saved comparison has different source or detector bindings.")
    reports = service.detection_lab.run_evaluations(receipt["candidate_id"])["evaluations"]
    selected = [
        [row for row in reports if row["evaluation_id"] == receipt[key]]
        for key in ("baseline_evaluation_id", "child_evaluation_id")
    ]
    if any(len(rows) != 1 for rows in selected):
        raise ProductStoreError("The comparison is missing an exact retained evaluation.")
    baseline, replay = selected[0][0], selected[1][0]
    if (
        baseline["candidate"] != replay["candidate"]
        or baseline["candidate"]["definition_digest"] != receipt["candidate_definition_digest"]
        or baseline["source"] != proposal["source_run"]
        or replay["source"] != child["progress"].get("replay_result", {}).get("source")
        or replay["source"]["run_id"] != run_ids[1]
    ):
        raise ProductStoreError(
            "The method evaluations do not use the same rule and bound sources."
        )
    return {
        "kind": "method_comparison",
        "step_id": step["step_id"],
        "candidate_id": receipt["candidate_id"],
        "evaluation_ids": [baseline["evaluation_id"], replay["evaluation_id"]],
        "run_ids": run_ids,
        "comparison_id": receipt["comparison_id"],
        "native_path": child_path(child),
    }


def active(
    service: AssistanceContext, child: Mapping[str, Any], step: Mapping[str, Any]
) -> Mapping[str, Any]:
    actual = child
    if (
        child["kind"] == "detection.ai.propose"
        and child["progress"].get("decision", {}).get("decision") == "accept"
    ):
        import uuid

        application_id = "job-" + uuid.UUID(child["request"]["application_submission_id"]).hex
        try:
            actual = service.detection_ai._latest_application(
                service.product_store.get_job(application_id)
            )
        except ProductStoreError:
            pass
    if (
        child["kind"] == "replay.ai.propose"
        and child["progress"].get("decision", {}).get("decision") == "accept"
    ):
        import uuid

        try:
            actual = service.product_store.get_job(
                "job-" + uuid.UUID(child["request"]["replay_submission_id"]).hex
            )
        except ProductStoreError:
            pass
    return {
        "job_id": actual["job_id"],
        "kind": actual["kind"],
        "state": actual["state"],
        "step_id": step["step_id"],
        "native_path": (
            f"/runs?job={actual['job_id']}"
            if actual["kind"] == "scenario.replay"
            else child_path(child)
        ),
    }
