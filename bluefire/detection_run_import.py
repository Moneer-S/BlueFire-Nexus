"""Import a definition from a verified run without copying its lifecycle claims."""

from __future__ import annotations

from http import HTTPStatus
from typing import TYPE_CHECKING, Any, Mapping

from .application_errors import APIError
from .detections import DetectionCandidate, DetectionError
from .product_store import ProductStoreError
from .run_store import RUN_ID_RE, RunStoreError

if TYPE_CHECKING:
    from .detection_lab import DetectionLabService


def hypothesis_from_run(
    service: DetectionLabService, request: Mapping[str, Any]
) -> Mapping[str, Any]:
    service._fields(
        request, required={"run_id", "candidate_id"}, optional=set(), context="run hypothesis"
    )
    run_id = request.get("run_id")
    candidate_id = request.get("candidate_id")
    if not isinstance(run_id, str) or not RUN_ID_RE.fullmatch(run_id):
        raise APIError(
            HTTPStatus.BAD_REQUEST, "detection_run_id_invalid", "A valid source run is required."
        )
    if not isinstance(candidate_id, str) or not candidate_id:
        raise APIError(
            HTTPStatus.BAD_REQUEST,
            "detection_candidate_id_invalid",
            "A source candidate is required.",
        )
    try:
        run = service.run_store.get_run(run_id)
    except RunStoreError as exc:
        raise APIError(
            HTTPStatus.UNPROCESSABLE_ENTITY,
            "detection_source_run_unavailable",
            "The source run could not be verified.",
        ) from exc
    if not isinstance(run.get("manifest"), Mapping):
        raise APIError(
            HTTPStatus.CONFLICT,
            "detection_run_not_immutable",
            "A finalized immutable source run is required.",
        )
    detections = run.get("detections")
    candidates = detections.get("candidates") if isinstance(detections, Mapping) else None
    if not isinstance(candidates, list):
        raise APIError(
            HTTPStatus.UNPROCESSABLE_ENTITY,
            "detection_source_invalid",
            "The source run has no valid candidate collection.",
        )
    matching = [
        row
        for row in candidates
        if isinstance(row, Mapping) and row.get("candidate_id") == candidate_id
    ]
    if len(matching) != 1:
        raise APIError(
            HTTPStatus.NOT_FOUND,
            "detection_source_candidate_missing",
            "The selected candidate is not unique in the source run.",
        )
    try:
        source = DetectionCandidate.from_mapping(matching[0])
    except DetectionError as exc:
        raise APIError(
            HTTPStatus.UNPROCESSABLE_ENTITY,
            "detection_source_candidate_invalid",
            "The source candidate identity could not be verified.",
        ) from exc
    definition: dict[str, Any] = {
        "behavior_id": source.behavior_id,
        "title": source.title,
        "target_language": source.target_language,
        "logsource": dict(source.logsource),
        "selection": dict(source.selection),
        "provenance": {
            **dict(source.provenance),
            "source_run_id": run_id,
            "source_candidate_id": candidate_id,
        },
        "known_misses": list(source.known_misses),
        "predicted_fields": list(source.predicted_fields),
        "public_baselines": [dict(item) for item in source.public_baselines],
    }
    # Origin IDs identify rule semantics. Provenance is part of the immutable
    # definition digest, so a second run's source binding requires a clone.
    try:
        origin = DetectionCandidate.hypothesis(**definition)
    except DetectionError as exc:
        raise APIError(
            HTTPStatus.UNPROCESSABLE_ENTITY,
            "detection_source_definition_invalid",
            "The source definition cannot accept the bounded run provenance.",
        ) from exc
    with service._lock:
        try:
            service.product_store.get_resource("detection", origin.candidate_id)
            exists = True
        except ProductStoreError:
            exists = False
        try:
            envelope = service.upsert_hypothesis(definition)
            operation = "reused" if exists else "created"
        except APIError as exc:
            if exc.code != "detection_revision_required":
                raise
            envelope = service.clone(
                origin.candidate_id,
                {
                    "reason": "Create a separate hypothesis from a verified immutable run.",
                    **{
                        key: value
                        for key, value in definition.items()
                        if key not in {"behavior_id", "target_language", "selection", "logsource"}
                    },
                },
            )
            operation = "cloned"
    return {
        **envelope,
        "source_run_id": run_id,
        "source_candidate_id": candidate_id,
        "operation": operation,
    }
