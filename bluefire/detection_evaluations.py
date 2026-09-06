"""Immutable per-run query results, separate from candidate lifecycle promotion."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from http import HTTPStatus
from typing import TYPE_CHECKING, Any, Mapping

from .application_errors import APIError
from .detections import DetectionCandidate, DetectionError, DetectionState
from .evidence import EvidenceError, EvidenceProvenance, EvidenceRecord
from .product_store_detection_evaluations import EVALUATION_SCHEMA, bind_report
from .product_store_errors import ProductStoreError
from .run_store import RUN_ID_RE, RunStoreError
from .util import content_hash

if TYPE_CHECKING:
    from .detection_lab import DetectionLabService

_ROLES = {"attack", "benign", "replay", "heldout"}
_MAX_SOURCE_RECORDS = 10_000
_MAX_OBSERVED = 128  # Existing bounded SQLite executor limit; never truncate a case.
_LANGUAGES = {"sqlite", "sigma"}
_EXECUTABLE_STATES = {
    DetectionState.PARSED,
    DetectionState.FIXTURE_EXERCISED,
    DetectionState.OBSERVED_EXERCISED,
    DetectionState.BENIGN_EVALUATED,
}


def _source(
    service: DetectionLabService, run_id: object
) -> tuple[Mapping[str, Any], list[EvidenceRecord], list[EvidenceRecord]]:
    if not isinstance(run_id, str) or not RUN_ID_RE.fullmatch(run_id):
        raise APIError(
            HTTPStatus.BAD_REQUEST,
            "detection_run_id_invalid",
            "A valid immutable run ID is required.",
        )
    try:
        run = service.run_store.get_run(run_id)
    except RunStoreError as exc:
        raise APIError(
            HTTPStatus.UNPROCESSABLE_ENTITY,
            "detection_evaluation_source_invalid",
            "The source run bundle could not be verified.",
        ) from exc
    manifest = run.get("manifest")
    evidence = run.get("evidence")
    rows = evidence.get("records") if isinstance(evidence, Mapping) else None
    if (
        not isinstance(manifest, Mapping)
        or manifest.get("run_id") != run_id
        or run.get("run_id") != run_id
    ):
        raise APIError(
            HTTPStatus.CONFLICT,
            "detection_run_not_immutable",
            "Evaluation requires a finalized immutable run bundle.",
        )
    if not isinstance(rows, list) or len(rows) > _MAX_SOURCE_RECORDS:
        raise APIError(
            HTTPStatus.UNPROCESSABLE_ENTITY,
            "detection_evaluation_evidence_invalid",
            "The source evidence collection is invalid or exceeds its bound.",
        )
    try:
        records = [EvidenceRecord.from_mapping(row) for row in rows]
        if any(record.run_id != run_id for record in records):
            raise EvidenceError("run identity mismatch")
        if len({record.evidence_id for record in records}) != len(records):
            raise EvidenceError("duplicate evidence identity")
    except (EvidenceError, TypeError, AttributeError) as exc:
        raise APIError(
            HTTPStatus.UNPROCESSABLE_ENTITY,
            "detection_evaluation_evidence_invalid",
            "The source has invalid evidence identities or hashes.",
        ) from exc
    observed = [record for record in records if record.provenance is EvidenceProvenance.OBSERVED]
    return run, records, observed


def _field_names(values: Any) -> list[str]:
    if not isinstance(values, (tuple, list)):
        return []
    return sorted(
        {
            value
            for value in values
            if isinstance(value, str)
            and len(value) <= 200
            and not any(ord(char) < 32 for char in value)
        }
    )[:256]


def _candidate_binding(
    candidate: DetectionCandidate, resource: Mapping[str, Any]
) -> dict[str, Any]:
    return {
        "candidate_id": candidate.candidate_id,
        "revision_root_id": candidate.revision_root_id,
        "revision": candidate.revision,
        "definition_digest": candidate.definition_digest,
        "resource_digest_at_evaluation": resource["digest"],
        "target_language": candidate.target_language,
        "source_sha256": candidate.validation.get("source_sha256"),
        "query_sha256": candidate.validation.get("query_sha256"),
        "parser_backend": dict(candidate.parser_backend),
    }


def _source_binding(
    run: Mapping[str, Any], records: list[EvidenceRecord], observed: list[EvidenceRecord]
) -> dict[str, Any]:
    excluded = Counter(
        record.provenance.value
        for record in records
        if record.provenance is not EvidenceProvenance.OBSERVED
    )
    return {
        "run_id": run["run_id"],
        "manifest_digest": content_hash(run["manifest"]),
        "evidence_digest": content_hash(run["evidence"]),
        "observed_records_digest": content_hash([record.to_dict() for record in observed]),
        "mode": run.get("mode"),
        "finalized_at": run.get("finalized_at"),
        "evidence_count": len(records),
        "observed_count": len(observed),
        "excluded_provenance_counts": dict(sorted(excluded.items())),
    }


def evaluate_run(
    service: DetectionLabService, candidate_id: str, request: Mapping[str, Any]
) -> Mapping[str, Any]:
    service._fields(
        request,
        required={"run_id", "question", "case_role"},
        optional=set(),
        context="run evaluation",
    )
    question = request.get("question")
    role = request.get("case_role")
    if (
        not isinstance(question, str)
        or not 1 <= len(question.strip()) <= 1000
        or any(ord(char) < 32 for char in question)
    ):
        raise APIError(
            HTTPStatus.BAD_REQUEST,
            "detection_evaluation_question_invalid",
            "Describe the experiment question in 1–1000 printable characters.",
        )
    if not isinstance(role, str) or role not in _ROLES:
        raise APIError(
            HTTPStatus.BAD_REQUEST,
            "detection_evaluation_role_invalid",
            "Case role must be attack, benign, replay, or heldout.",
        )
    with service._lock:
        resource = service._resource(candidate_id)
        candidate = service._candidate_from_resource(resource)
        if candidate.target_language not in _LANGUAGES:
            raise APIError(
                HTTPStatus.CONFLICT,
                "detection_evaluation_language_unsupported",
                "Immutable run evaluation supports SQLite and Sigma converted to bounded SQLite. Internal matcher and YARA metadata are not executable query evidence.",
            )
        if candidate.state not in _EXECUTABLE_STATES or not candidate.rule_source:
            raise APIError(
                HTTPStatus.CONFLICT,
                "detection_evaluation_parse_required",
                "Parse this query candidate before evaluating a run.",
            )
        run, records, observed = _source(service, request.get("run_id"))
        gaps = [
            record.evidence_id
            for record in records
            if record.provenance is EvidenceProvenance.UNKNOWN
        ]
        diagnostics: list[str] = []
        if not observed:
            diagnostics.append("observed_evidence_unavailable")
        if gaps:
            diagnostics.append("source_contains_evidence_gaps")
        if len(observed) > _MAX_OBSERVED:
            diagnostics.append("observed_evidence_limit_exceeded")
        objective = run.get("objective_evaluation")
        integrity = (
            objective.get("observation_integrity") if isinstance(objective, Mapping) else None
        )
        if isinstance(integrity, Mapping) and integrity.get("satisfied") is False:
            diagnostics.append("source_file_postconditions_unobserved")
        result: dict[str, Any] = {
            "state": "insufficient_evidence",
            "match_count": None,
            "evaluated_evidence_ids": [],
            "matched_evidence_ids": [],
            "gap_evidence_ids": gaps[:_MAX_OBSERVED],
            "gap_count": len(gaps),
            "mapped_fields": _field_names(candidate.validation.get("mapped_fields")),
            "available_fields": [],
            "unsupported_fields": [],
            "missing_fields": [],
            "diagnostic_codes": diagnostics,
        }
        backend: dict[str, Any] = {"name": "SQLite in-memory bounded executor", "executed": False}
        if not diagnostics:
            try:
                execution = service.validator._execute_candidate_query(
                    candidate,
                    [dict(record.content, fixture_id=record.evidence_id) for record in observed],
                )
            except DetectionError:
                result["state"] = "backend_error"
                diagnostics.append("bounded_query_execution_refused")
            else:
                mapped = _field_names(execution["mapped_fields"])
                available = _field_names(execution["mapped_fixture_fields"])
                missing = sorted(set(mapped) - set(available) - {"fixture_id"})
                backend.update(
                    executed=True,
                    version=execution["sqlite_version"],
                    query_only=execution["query_only"],
                    authorizer=execution["authorizer"],
                    limits=execution["limits"],
                )
                result.update(
                    evaluated_evidence_ids=list(execution["fixture_ids"]),
                    mapped_fields=mapped,
                    available_fields=available,
                    unsupported_fields=_field_names(execution["unsupported_fixture_fields"]),
                    missing_fields=missing,
                )
                if missing:
                    diagnostics.append("required_observation_fields_unavailable")
                else:
                    matched = list(execution["matched_fixture_ids"])
                    result.update(
                        state="matched" if matched else "not_matched",
                        match_count=len(matched),
                        matched_evidence_ids=matched,
                    )
        report = bind_report(
            {
                "schema_version": EVALUATION_SCHEMA,
                "question": question.strip(),
                "case_role": role,
                "case_role_basis": "operator_declared",
                "candidate": _candidate_binding(candidate, resource),
                "source": _source_binding(run, records, observed),
                "result": result,
                "backend": backend,
                "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "limitations": [
                    "Case role is operator-declared context, not observed intent or an expected-result assertion.",
                    "Matches describe the bounded query against independently observed run metadata; they do not establish host detection deployment or prevention.",
                    "All observed records in this bundle are included; excluded provenance cannot supply missing observations.",
                    "This report does not promote, reject, or rewrite the candidate lifecycle or source run.",
                ],
            }
        )
        try:
            persisted = service.product_store.save_detection_evaluation(report)
        except ProductStoreError as exc:
            raise APIError(
                HTTPStatus.UNPROCESSABLE_ENTITY,
                "detection_evaluation_persistence_refused",
                "The bounded immutable evaluation could not be retained.",
            ) from exc
    return {
        "schema_version": "bluefire.detection-run-evaluation-result.v1",
        "evaluation": persisted,
    }


def evaluations(service: DetectionLabService, candidate_id: str) -> Mapping[str, Any]:
    with service._lock:
        resource = service._resource(candidate_id)
        candidate = service._candidate_from_resource(resource)
        try:
            reports = service.product_store.detection_evaluations(candidate_id)
        except ProductStoreError as exc:
            raise APIError(
                HTTPStatus.UNPROCESSABLE_ENTITY,
                "detection_evaluation_integrity_invalid",
                "The retained evaluation history failed integrity validation.",
            ) from exc
        checked_sources: dict[str, dict[str, Any]] = {}
        current = _candidate_binding(candidate, resource)
        for report in reports:
            saved_candidate = report.get("candidate")
            source = report.get("source")
            if (
                not isinstance(saved_candidate, Mapping)
                or not isinstance(source, Mapping)
                or any(
                    saved_candidate.get(key) != current.get(key)
                    for key in (
                        "candidate_id",
                        "revision_root_id",
                        "revision",
                        "definition_digest",
                        "target_language",
                        "source_sha256",
                        "query_sha256",
                        "parser_backend",
                    )
                )
            ):
                raise APIError(
                    HTTPStatus.UNPROCESSABLE_ENTITY,
                    "detection_evaluation_candidate_mismatch",
                    "A retained evaluation does not match its candidate definition and query identity.",
                )
            run_id = str(source.get("run_id", ""))
            if run_id not in checked_sources:
                run, records, observed = _source(service, run_id)
                checked_sources[run_id] = _source_binding(run, records, observed)
            if dict(source) != checked_sources[run_id]:
                raise APIError(
                    HTTPStatus.UNPROCESSABLE_ENTITY,
                    "detection_evaluation_source_mismatch",
                    "A retained evaluation does not match its immutable source bundle.",
                )
    return {
        "schema_version": "bluefire.detection-run-evaluation-list.v1",
        "candidate_id": candidate_id,
        "evaluations": reports,
    }
