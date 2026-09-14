"""Separate operator activity labels from recorded development use and run lineage."""

from __future__ import annotations

from typing import Any, Mapping

from .application_errors import APIError
from .detection_context import DetectionContext
from .detections import DetectionCandidate, DetectionError
from .product_store_errors import ProductStoreError
from .run_store import RUN_ID_RE


def classify(
    service: DetectionContext,
    candidate: DetectionCandidate,
    run: Mapping[str, Any],
    evidence_ids: set[str],
    request: Mapping[str, Any],
    *,
    development_case: bool,
) -> Mapping[str, Any]:
    """Only recorded source use can override a claimed independent test."""
    replay = run.get("replay")
    replay_source = replay.get("source_run_id") if isinstance(replay, Mapping) else None
    lineage = (
        "replay"
        if isinstance(replay_source, str) and RUN_ID_RE.fullmatch(replay_source)
        else "original" if "replay" in run and replay is None else "unknown"
    )
    sources = {run["run_id"]}
    if lineage == "replay":
        sources.add(replay_source)
    reasons: set[str] = {"proposal_source"} if development_case else set()
    complete = True
    visited: set[str] = set()
    current = candidate
    for _ in range(64):
        if current.candidate_id in visited:
            complete = False
            break
        visited.add(current.candidate_id)
        if evidence_ids.intersection(current.observed_evidence_ids):
            reasons.add("observed_during_development")
        if any(row.get("run_id") in sources for row in current.lifecycle_history):
            reasons.add("recorded_source_context")
        try:
            for report in service.product_store.detection_evaluations(current.candidate_id):
                if report.get("development_case") and report["source"]["run_id"] in sources:
                    reasons.add("retained_development_evaluation")
            if not current.parent_candidate_id:
                break
            current = service._candidate_from_resource(
                service._resource(current.parent_candidate_id)
            )
        except (APIError, ProductStoreError, DetectionError, KeyError, TypeError):
            complete = False
            break
    else:
        complete = False
    requested = request.get("evaluation_use", "unspecified")
    use = "development" if reasons else requested
    if not complete and use == "independent":
        use = "unspecified"
    return {
        "activity_label": request.get(
            "activity_label",
            request["case_role"] if request["case_role"] in {"attack", "benign"} else "unknown",
        ),
        "activity_basis": "operator_declared",
        "source_lineage": lineage,
        "lineage_basis": "immutable_run" if lineage != "unknown" else "unavailable",
        "replay_source_run_id": replay_source if lineage == "replay" else None,
        "evaluation_use": use,
        "requested_use": requested,
        "use_basis": (
            "recorded_development"
            if reasons
            else "operator_declared" if use != "unspecified" else "unknown"
        ),
        "development_reasons": sorted(reasons),
        "development_history_complete": complete,
        "independence_verified": False,
    }
