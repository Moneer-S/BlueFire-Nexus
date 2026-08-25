"""Strict persisted lifecycle boundary for the Detection Lab."""

from __future__ import annotations

import re
import threading
from dataclasses import replace
from datetime import datetime, timezone
from http import HTTPStatus
from typing import Any, Mapping, NoReturn, Sequence

from .api import APIError
from .detections import (
    DetectionCandidate,
    DetectionError,
    DetectionPipeline,
    DetectionState,
    ExternalDetectionValidator,
    PublicBaselineReference,
)
from .evidence import EvidenceError, EvidenceProvenance, EvidenceRecord
from .product_store import (
    DetectionRevisionIntegrityError,
    DetectionRevisionLimitError,
    ProductStore,
    ProductStoreError,
)
from .registry import BehaviorRegistry, RegistryError
from .research import ResearchSource, ResearchSourceError
from .run_store import RUN_ID_RE, RunStore, RunStoreError
from .util import canonical_json_bytes, content_hash, json_clone

_DETECTION_ID = re.compile(r"^detection-[0-9a-f]{20}$")
_EVIDENCE_ID = re.compile(r"^evidence-[0-9a-f]{20}$")
_FIXTURE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
_MAX_FIXTURES = 128
_MAX_FIXTURE_BYTES = 1024 * 1024
_MAX_NOTES = 64
_MAX_NOTE_LENGTH = 1_000
_MAX_EVIDENCE = 256
_MAX_HISTORY = 256
_MAX_REVISIONS = 256


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class DetectionLabService:
    """Own read/validate/transition/write operations for persisted candidates."""

    def __init__(
        self,
        *,
        product_store: ProductStore,
        run_store: RunStore,
        registry: BehaviorRegistry,
    ) -> None:
        self.product_store = product_store
        self.run_store = run_store
        self.registry = registry
        self.pipeline = DetectionPipeline()
        self.validator = ExternalDetectionValidator()
        self._lock = threading.RLock()

    def health(self) -> Mapping[str, Any]:
        backends = self.validator.health()
        sigma = dict(backends["pySigma"])
        yara = dict(backends["YARA-Python"])
        spl = dict(backends["SPL structural checker"])
        persistence_ready = True
        resource_count = 0
        invalid_resources = 0
        try:
            with self._lock:
                resources = self.product_store.list_resources("detection")
                resource_count = len(resources)
                for resource in resources:
                    try:
                        self._validated_resource(resource)
                    except APIError:
                        invalid_resources += 1
        except ProductStoreError:
            persistence_ready = False
        persistence_ready = persistence_ready and invalid_resources == 0
        return {
            "schema_version": "bluefire.detection-lab-health.v1",
            "ready": persistence_ready,
            "persistence_ready": persistence_ready,
            "candidate_resources": resource_count,
            "invalid_candidate_resources": invalid_resources,
            "languages": {
                "internal": {
                    "ready": True,
                    "authoritative": True,
                    "backend": self.pipeline.parser_name,
                    "version": self.pipeline.parser_version,
                },
                "sigma": {
                    "ready": bool(sigma.get("ready")),
                    "authoritative": bool(sigma.get("ready")),
                    "backend": "pySigma",
                    "version": sigma.get("version"),
                },
                "yara": {
                    "ready": bool(yara.get("ready")),
                    "authoritative": bool(yara.get("ready")),
                    "backend": "YARA-Python",
                    "version": yara.get("version"),
                },
                "yara-l": {
                    "ready": bool(yara.get("ready")),
                    "authoritative": bool(yara.get("ready")),
                    "backend": "YARA-Python",
                    "version": yara.get("version"),
                },
                "spl": {
                    "ready": bool(spl.get("ready")),
                    "authoritative": False,
                    "backend": "structural-only",
                    "version": spl.get("version"),
                    "lifecycle_ceiling": DetectionState.HYPOTHESIS.value,
                },
            },
            "limits": {
                "source_bytes": self.validator.max_source_bytes,
                "fixture_bytes": _MAX_FIXTURE_BYTES,
                "fixtures_per_action": _MAX_FIXTURES,
                "evidence_per_action": _MAX_EVIDENCE,
                "notes_per_action": _MAX_NOTES,
            },
        }

    def candidates(self) -> Mapping[str, Any]:
        with self._lock:
            resources = [
                self._validated_resource(resource)
                for resource in self.product_store.list_resources("detection")
            ]
        return {
            "schema_version": "bluefire.detection-list.v1",
            "candidates": resources,
        }

    def candidate(self, candidate_id: str) -> Mapping[str, Any]:
        with self._lock:
            return self._envelope(self._resource(candidate_id))

    def upsert_hypothesis(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        required = {
            "behavior_id",
            "title",
            "target_language",
            "logsource",
            "selection",
            "provenance",
        }
        optional = {"known_misses", "public_baselines", "predicted_fields"}
        self._fields(request, required=required, optional=optional, context="hypothesis")
        if not all(
            isinstance(request.get(name), str)
            for name in ("behavior_id", "title", "target_language")
        ) or not all(
            isinstance(request.get(name), Mapping)
            for name in ("logsource", "selection", "provenance")
        ):
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "detection_hypothesis_invalid",
                "Hypothesis identity, title, language, logsource, selection, and provenance are required.",
            )
        known_misses = request.get("known_misses", [])
        public_baseline_rows = request.get("public_baselines", [])
        predicted_fields = request.get("predicted_fields", [])
        if (
            not isinstance(known_misses, list)
            or not isinstance(public_baseline_rows, list)
            or not all(isinstance(row, Mapping) for row in public_baseline_rows)
            or not isinstance(predicted_fields, list)
        ):
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "detection_hypothesis_invalid",
                "Hypothesis misses, baselines, and predicted fields must be bounded JSON lists.",
            )
        public_baselines = self._validated_public_baselines(public_baseline_rows)
        behavior_id = str(request["behavior_id"])
        try:
            self.registry.get_behavior(behavior_id)
        except RegistryError as exc:
            raise APIError(
                HTTPStatus.UNPROCESSABLE_ENTITY,
                "detection_behavior_unknown",
                "Detection behavior is not registered.",
            ) from exc
        try:
            proposed = DetectionCandidate.hypothesis(
                behavior_id=behavior_id,
                title=str(request["title"]),
                target_language=str(request["target_language"]),
                logsource=request["logsource"],
                selection=request["selection"],
                provenance=request["provenance"],
                known_misses=known_misses,
                public_baselines=public_baselines,
                predicted_fields=predicted_fields,
            )
            proposed = DetectionCandidate.from_mapping(proposed.to_dict())
        except (DetectionError, TypeError, ValueError) as exc:
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "detection_hypothesis_invalid",
                "Detection hypothesis is invalid.",
                [str(exc)],
            ) from exc

        with self._lock:
            try:
                existing_resource = self.product_store.get_resource(
                    "detection", proposed.candidate_id
                )
            except ProductStoreError:
                existing_resource = None
            if existing_resource is None:
                before: DetectionCandidate | None = None
                candidate = proposed
            else:
                before = self._candidate_from_resource(self._validated_resource(existing_resource))
                if before.definition_digest == proposed.definition_digest:
                    return self._envelope(existing_resource)
                raise APIError(
                    HTTPStatus.CONFLICT,
                    "detection_revision_required",
                    "An existing candidate definition is immutable; clone or tune it explicitly.",
                )
            recorded = self._record(
                before,
                candidate,
                action="hypothesis_upsert",
                outcome="created",
                request=request,
            )
            return self._envelope(self._save(recorded))

    def clone(self, candidate_id: str, request: Mapping[str, Any]) -> Mapping[str, Any]:
        self._fields(
            request,
            required={"reason"},
            optional={
                "title",
                "provenance",
                "known_misses",
                "public_baselines",
                "predicted_fields",
            },
            context="revision clone",
        )
        return self._create_revision(candidate_id, request, revision_kind="clone")

    def tune(self, candidate_id: str, request: Mapping[str, Any]) -> Mapping[str, Any]:
        self._fields(
            request,
            required={"reason", "selection"},
            optional={
                "title",
                "logsource",
                "provenance",
                "known_misses",
                "public_baselines",
                "predicted_fields",
            },
            context="revision tune",
        )
        return self._create_revision(candidate_id, request, revision_kind="tune")

    def compare(self, candidate_id: str, request: Mapping[str, Any]) -> Mapping[str, Any]:
        self._fields(
            request,
            required={"candidate_id"},
            optional=set(),
            context="revision comparison",
        )
        compared_id = request.get("candidate_id")
        if not isinstance(compared_id, str):
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "detection_comparison_invalid",
                "Detection comparison requires one candidate_id.",
            )
        with self._lock:
            baseline = self._candidate_from_resource(self._resource(candidate_id))
            candidate = self._candidate_from_resource(self._resource(compared_id))
            if baseline.revision_root_id != candidate.revision_root_id:
                raise APIError(
                    HTTPStatus.CONFLICT,
                    "detection_revision_lineage_mismatch",
                    "Detection comparison requires candidates from the same revision lineage.",
                )
            return self._comparison(baseline, candidate)

    def parse(self, candidate_id: str, request: Mapping[str, Any]) -> Mapping[str, Any]:
        with self._lock:
            resource = self._resource(candidate_id)
            before = self._candidate_from_resource(resource)
            if before.target_language == "internal":
                self._fields(request, required=set(), optional=set(), context="parse")
            else:
                self._fields(request, required={"source"}, optional=set(), context="parse")
                if not isinstance(request.get("source"), str):
                    raise APIError(
                        HTTPStatus.BAD_REQUEST,
                        "detection_source_invalid",
                        "Detection source must be text.",
                    )
            try:
                if before.target_language == "internal":
                    after = self.pipeline.parse(before)
                elif before.target_language == "sigma":
                    after = self.validator.parse_sigma(before, str(request["source"]))
                elif before.target_language in {"yara", "yara-l"}:
                    after = self.validator.compile_yara(before, str(request["source"]))
                elif before.target_language == "spl":
                    after = self.validator.check_spl(before, str(request["source"]))
                else:  # pragma: no cover - guarded by strict rehydration
                    raise DetectionError("unsupported detection language")
            except DetectionError as exc:
                self._raise_detection_error(exc, action="parse")
            recorded = self._record_transition(before, after, "parse", request)
            return self._envelope(self._save(recorded))

    def exercise_fixtures(self, candidate_id: str, request: Mapping[str, Any]) -> Mapping[str, Any]:
        self._fields(
            request,
            required={"fixtures"},
            optional=set(),
            context="malicious fixture exercise",
        )
        fixtures = self._fixtures(request.get("fixtures"))
        with self._lock:
            resource = self._resource(candidate_id)
            before = self._candidate_from_resource(resource)
            try:
                if before.target_language in {"internal", "sigma"}:
                    after = self.pipeline.exercise_fixtures(before, fixtures)
                    after = replace(
                        after,
                        validation={
                            **dict(after.validation),
                            "fixture_backend": self.pipeline.parser_name,
                            "source_rule_executed": before.target_language == "internal",
                        },
                    )
                elif before.target_language in {"yara", "yara-l"}:
                    self._yara_fixture_shape(fixtures)
                    after = self.validator.exercise_yara_fixtures(before, fixtures)
                else:
                    raise DetectionError(
                        "SPL structural validation cannot advance to fixture exercise"
                    )
            except DetectionError as exc:
                self._raise_detection_error(exc, action="exercise fixtures")
            after = replace(after, malicious_fixtures=tuple(fixtures))
            recorded = self._record_transition(before, after, "exercise_fixtures", request)
            return self._envelope(self._save(recorded))

    def exercise_observed(self, candidate_id: str, request: Mapping[str, Any]) -> Mapping[str, Any]:
        self._fields(
            request,
            required={"run_id"},
            optional={"evidence_ids"},
            context="observed evidence exercise",
        )
        run_id = request.get("run_id")
        if not isinstance(run_id, str) or not RUN_ID_RE.fullmatch(run_id):
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "detection_run_id_invalid",
                "Observed exercise requires a valid run identifier.",
            )
        if "evidence_ids" in request and request.get("evidence_ids") is None:
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "detection_evidence_ids_invalid",
                "evidence_ids must be omitted or supplied as a non-empty unique list.",
            )
        selected_ids = self._evidence_ids(request.get("evidence_ids"))
        with self._lock:
            resource = self._resource(candidate_id)
            before = self._candidate_from_resource(resource)
            if before.target_language not in {"internal", "sigma"}:
                raise APIError(
                    HTTPStatus.CONFLICT,
                    "detection_observed_unsupported",
                    "Observed JSON evidence can be evaluated only by internal or normalized Sigma selection semantics.",
                )
            records = self._immutable_evidence(run_id, selected_ids)
            try:
                after = self.pipeline.exercise_observed(before, records)
            except DetectionError as exc:
                self._raise_detection_error(exc, action="exercise observed evidence")
            observed_fields = tuple(sorted(self._observed_fields(records)))
            predicted_fields = before.predicted_fields or tuple(
                sorted(str(name).partition("|")[0] for name in before.selection)
            )
            drift = self.validator.field_drift(predicted_fields, observed_fields)
            after = replace(
                after,
                predicted_fields=predicted_fields,
                observed_fields=observed_fields,
                field_drift=drift,
                validation={
                    **dict(after.validation),
                    "observed_exercise": {
                        "run_id": run_id,
                        "evidence_ids": [record.evidence_id for record in records],
                        "immutable_bundle_validated": True,
                        "source_rule_executed": before.target_language == "internal",
                    },
                },
            )
            recorded = self._record_transition(
                before,
                after,
                "exercise_observed",
                request,
                run_id=run_id,
            )
            return self._envelope(self._save(recorded))

    def evaluate_benign(self, candidate_id: str, request: Mapping[str, Any]) -> Mapping[str, Any]:
        self._fields(
            request,
            required={"fixtures", "notes"},
            optional=set(),
            context="benign evaluation",
        )
        fixtures = self._fixtures(request.get("fixtures"))
        notes = self._notes(request.get("notes"), context="benign notes")
        with self._lock:
            resource = self._resource(candidate_id)
            before = self._candidate_from_resource(resource)
            try:
                if before.target_language in {"internal", "sigma"}:
                    after = self.pipeline.evaluate_benign(before, fixtures, notes=notes)
                    after = replace(
                        after,
                        validation={
                            **dict(after.validation),
                            "benign_fixture_backend": self.pipeline.parser_name,
                            "source_rule_executed": before.target_language == "internal",
                        },
                    )
                elif before.target_language in {"yara", "yara-l"}:
                    self._yara_fixture_shape(fixtures)
                    after = self.validator.evaluate_yara_benign(before, fixtures, notes=notes)
                else:
                    raise DetectionError("SPL structural validation cannot be benign-evaluated")
            except DetectionError as exc:
                self._raise_detection_error(exc, action="evaluate benign fixtures")
            after = replace(after, benign_fixtures=tuple(fixtures))
            recorded = self._record_transition(before, after, "evaluate_benign", request)
            return self._envelope(self._save(recorded))

    def reject(self, candidate_id: str, request: Mapping[str, Any]) -> Mapping[str, Any]:
        self._fields(
            request,
            required={"reason"},
            optional={"notes"},
            context="rejection",
        )
        reason = request.get("reason")
        if (
            not isinstance(reason, str)
            or not reason.strip()
            or len(reason) > _MAX_NOTE_LENGTH
            or "\x00" in reason
        ):
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "detection_rejection_invalid",
                "Rejection reason must contain 1-1000 characters.",
            )
        notes = self._notes(request.get("notes", []), context="rejection notes")
        with self._lock:
            resource = self._resource(candidate_id)
            before = self._candidate_from_resource(resource)
            decisions = tuple(dict.fromkeys((*before.tuning_decisions, *notes)))
            if len(decisions) > _MAX_NOTES:
                raise APIError(
                    HTTPStatus.BAD_REQUEST,
                    "detection_notes_invalid",
                    "The combined tuning-decision history exceeds its limit.",
                )
            try:
                after = before.transition(
                    DetectionState.REJECTED,
                    rejection_reason=reason,
                    tuning_decisions=decisions,
                )
            except DetectionError as exc:
                self._raise_detection_error(exc, action="reject")
            recorded = self._record_transition(before, after, "reject", request)
            return self._envelope(self._save(recorded))

    def _create_revision(
        self,
        candidate_id: str,
        request: Mapping[str, Any],
        *,
        revision_kind: str,
    ) -> Mapping[str, Any]:
        reason = request.get("reason")
        if (
            not isinstance(reason, str)
            or not reason.strip()
            or len(reason) > _MAX_NOTE_LENGTH
            or "\x00" in reason
        ):
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "detection_revision_reason_invalid",
                "Detection revision reason must contain 1-1000 characters.",
            )
        with self._lock:
            source = self._candidate_from_resource(self._resource(candidate_id))
            title = request.get("title", source.title)
            logsource = request.get("logsource", source.logsource)
            selection = request.get("selection", source.selection)
            provenance = request.get("provenance", source.provenance)
            known_misses = request.get("known_misses", list(source.known_misses))
            predicted_fields = request.get("predicted_fields", list(source.predicted_fields))
            public_baseline_rows = request.get(
                "public_baselines", [dict(row) for row in source.public_baselines]
            )
            if (
                not isinstance(title, str)
                or not isinstance(logsource, Mapping)
                or not isinstance(selection, Mapping)
                or not isinstance(provenance, Mapping)
                or not isinstance(known_misses, list)
                or not isinstance(predicted_fields, list)
                or not isinstance(public_baseline_rows, list)
                or not all(isinstance(row, Mapping) for row in public_baseline_rows)
            ):
                raise APIError(
                    HTTPStatus.BAD_REQUEST,
                    "detection_revision_invalid",
                    "Detection revision fields have invalid JSON types.",
                )
            public_baselines = self._validated_public_baselines(public_baseline_rows)
            if revision_kind == "tune" and (
                dict(selection) == dict(source.selection)
                and dict(logsource) == dict(source.logsource)
            ):
                raise APIError(
                    HTTPStatus.BAD_REQUEST,
                    "detection_tune_no_change",
                    "A tune revision must change selection or logsource semantics.",
                )
            decisions = tuple(dict.fromkeys((*source.tuning_decisions, reason.strip())))
            action = "revision_clone" if revision_kind == "clone" else "revision_tune"

            def build_document(revision: int) -> Mapping[str, Any]:
                try:
                    candidate = DetectionCandidate.hypothesis(
                        behavior_id=source.behavior_id,
                        title=title,
                        target_language=source.target_language,
                        logsource=logsource,
                        selection=selection,
                        provenance=provenance,
                        known_misses=known_misses,
                        public_baselines=public_baselines,
                        predicted_fields=predicted_fields,
                        tuning_decisions=decisions,
                        revision=revision,
                        revision_root_id=source.revision_root_id,
                        parent_candidate_id=source.candidate_id,
                        revision_kind=revision_kind,
                    )
                    candidate = DetectionCandidate.from_mapping(candidate.to_dict())
                except (DetectionError, TypeError, ValueError) as exc:
                    raise APIError(
                        HTTPStatus.BAD_REQUEST,
                        "detection_revision_invalid",
                        "Detection revision is invalid.",
                        [str(exc)],
                    ) from exc
                return self._record(
                    None,
                    candidate,
                    action=action,
                    outcome="created",
                    request=request,
                ).to_dict()

            try:
                resource = self.product_store.save_detection_revision(
                    source.revision_root_id,
                    build_document,
                    max_revisions=_MAX_REVISIONS,
                )
            except DetectionRevisionLimitError as exc:
                raise APIError(
                    HTTPStatus.CONFLICT,
                    "detection_revision_limit",
                    f"Detection revision lineage is limited to {_MAX_REVISIONS} immutable definitions.",
                ) from exc
            except DetectionRevisionIntegrityError as exc:
                raise APIError(
                    HTTPStatus.CONFLICT,
                    "detection_revision_conflict",
                    "Detection revision identity could not be allocated atomically.",
                    [str(exc)],
                ) from exc
            except ProductStoreError as exc:
                raise APIError(
                    HTTPStatus.UNPROCESSABLE_ENTITY,
                    "detection_persistence_rejected",
                    "Detection revision persistence was rejected.",
                    [str(exc)],
                ) from exc
            return self._envelope(resource)

    def _validated_public_baselines(
        self, value: Sequence[Mapping[str, Any]]
    ) -> tuple[Mapping[str, str], ...]:
        try:
            references = tuple(
                PublicBaselineReference.from_mapping(row, f"public_baselines[{index}]")
                for index, row in enumerate(value)
            )
        except DetectionError as exc:
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "detection_public_baseline_invalid",
                "Public baseline references are invalid.",
                [str(exc)],
            ) from exc
        if len(references) > 32 or len({row.research_source_id for row in references}) != len(
            references
        ):
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "detection_public_baseline_invalid",
                "Public baselines must contain at most 32 unique research sources.",
            )
        result: list[Mapping[str, str]] = []
        for reference in references:
            try:
                resource = self.product_store.get_resource(
                    "research_source", reference.research_source_id
                )
            except ProductStoreError as exc:
                raise APIError(
                    HTTPStatus.UNPROCESSABLE_ENTITY,
                    "detection_baseline_source_missing",
                    "A referenced public baseline source is not registered.",
                    [reference.research_source_id],
                ) from exc
            document = resource.get("document")
            try:
                if not isinstance(document, Mapping):
                    raise ResearchSourceError("research source document is unavailable")
                source = ResearchSource.from_mapping(
                    document, f"research source {reference.research_source_id}"
                )
            except ResearchSourceError as exc:
                raise APIError(
                    HTTPStatus.UNPROCESSABLE_ENTITY,
                    "detection_baseline_source_invalid",
                    "A referenced public baseline source failed strict validation.",
                    [reference.research_source_id],
                ) from exc
            expected = PublicBaselineReference(
                schema_version="bluefire.public-baseline.v1",
                research_source_id=source.id,
                source_digest=str(resource.get("digest")),
                pin=source.pin,
                version=source.version,
                license=source.license,
                license_review=source.license_review.value,
                relationship=source.relationship.value,
                use="comparison",
            )
            if (
                resource.get("id") != source.id
                or resource.get("status") != "pinned"
                or resource.get("digest") != content_hash(document)
                or "comparison" not in source.uses
                or reference != expected
            ):
                raise APIError(
                    HTTPStatus.UNPROCESSABLE_ENTITY,
                    "detection_baseline_source_mismatch",
                    "Public baseline metadata does not match its pinned registered source.",
                    [reference.research_source_id],
                )
            result.append(expected.to_dict())
        return tuple(result)

    @classmethod
    def _comparison(
        cls, baseline: DetectionCandidate, candidate: DetectionCandidate
    ) -> Mapping[str, Any]:
        baseline_rule = {
            "target_language": baseline.target_language,
            "logsource_digest": content_hash(baseline.logsource),
            "selection_digest": content_hash(baseline.selection),
            "rule_source_digest": (
                content_hash({"source": baseline.rule_source})
                if baseline.rule_source is not None
                else None
            ),
        }
        candidate_rule = {
            "target_language": candidate.target_language,
            "logsource_digest": content_hash(candidate.logsource),
            "selection_digest": content_hash(candidate.selection),
            "rule_source_digest": (
                content_hash({"source": candidate.rule_source})
                if candidate.rule_source is not None
                else None
            ),
        }
        source_delta = cls._baseline_delta(baseline.public_baselines, candidate.public_baselines)
        baseline_actions = [str(row.get("action")) for row in baseline.lifecycle_history]
        candidate_actions = [str(row.get("action")) for row in candidate.lifecycle_history]
        baseline_run_ids = {
            str(row["run_id"])
            for row in baseline.lifecycle_history
            if isinstance(row.get("run_id"), str)
        }
        candidate_run_ids = {
            str(row["run_id"])
            for row in candidate.lifecycle_history
            if isinstance(row.get("run_id"), str)
        }
        deltas = {
            "source": {
                "changed": (baseline.provenance != candidate.provenance or source_delta["changed"]),
                "provenance": {
                    "baseline_digest": content_hash(baseline.provenance),
                    "candidate_digest": content_hash(candidate.provenance),
                    "changed": baseline.provenance != candidate.provenance,
                },
                "public_baselines": source_delta,
            },
            "rule": {
                "changed": baseline_rule != candidate_rule,
                "changed_fields": sorted(
                    key for key in baseline_rule if baseline_rule[key] != candidate_rule[key]
                ),
                "baseline": baseline_rule,
                "candidate": candidate_rule,
            },
            "fields": {
                "changed": (
                    baseline.predicted_fields != candidate.predicted_fields
                    or baseline.observed_fields != candidate.observed_fields
                    or baseline.field_drift != candidate.field_drift
                ),
                "predicted": cls._set_delta(baseline.predicted_fields, candidate.predicted_fields),
                "observed": cls._set_delta(baseline.observed_fields, candidate.observed_fields),
                "drift": {
                    "changed": baseline.field_drift != candidate.field_drift,
                    "baseline": {key: list(value) for key, value in baseline.field_drift.items()},
                    "candidate": {key: list(value) for key, value in candidate.field_drift.items()},
                },
            },
            "lifecycle": {
                "changed": (
                    baseline.state is not candidate.state
                    or baseline_actions != candidate_actions
                    or baseline.lifecycle_history != candidate.lifecycle_history
                ),
                "baseline_state": baseline.state.value,
                "candidate_state": candidate.state.value,
                "baseline_actions": baseline_actions,
                "candidate_actions": candidate_actions,
                "baseline_history_digest": content_hash(list(baseline.lifecycle_history)),
                "candidate_history_digest": content_hash(list(candidate.lifecycle_history)),
            },
            "fixtures": {
                "changed": (
                    baseline.malicious_fixtures != candidate.malicious_fixtures
                    or baseline.malicious_fixture_ids != candidate.malicious_fixture_ids
                    or baseline.match_count != candidate.match_count
                ),
                **cls._fixture_delta(baseline.malicious_fixtures, candidate.malicious_fixtures),
                "fixture_ids": cls._set_delta(
                    baseline.malicious_fixture_ids, candidate.malicious_fixture_ids
                ),
                "baseline_match_count": baseline.match_count,
                "candidate_match_count": candidate.match_count,
            },
            "observed": {
                "changed": (
                    baseline.observed_evidence_ids != candidate.observed_evidence_ids
                    or baseline_run_ids != candidate_run_ids
                ),
                "evidence_ids": cls._set_delta(
                    baseline.observed_evidence_ids, candidate.observed_evidence_ids
                ),
                "run_ids": cls._set_delta(baseline_run_ids, candidate_run_ids),
            },
            "benign": {
                "changed": (
                    baseline.benign_fixtures != candidate.benign_fixtures
                    or baseline.benign_fixture_ids != candidate.benign_fixture_ids
                    or baseline.benign_match_count != candidate.benign_match_count
                    or baseline.false_positive_notes != candidate.false_positive_notes
                ),
                **cls._fixture_delta(baseline.benign_fixtures, candidate.benign_fixtures),
                "fixture_ids": cls._set_delta(
                    baseline.benign_fixture_ids, candidate.benign_fixture_ids
                ),
                "notes": cls._set_delta(
                    baseline.false_positive_notes, candidate.false_positive_notes
                ),
                "baseline_match_count": baseline.benign_match_count,
                "candidate_match_count": candidate.benign_match_count,
            },
        }
        snapshot: dict[str, Any] = {
            "schema_version": "bluefire.detection-comparison.v1",
            "revision_root_id": baseline.revision_root_id,
            "baseline": cls._comparison_identity(baseline),
            "candidate": cls._comparison_identity(candidate),
            "deltas": deltas,
        }
        comparison_digest = content_hash(snapshot)
        return {
            **snapshot,
            "comparison_id": "detection-comparison-"
            + comparison_digest.removeprefix("sha256:")[:20],
        }

    @staticmethod
    def _comparison_identity(candidate: DetectionCandidate) -> Mapping[str, Any]:
        return {
            "candidate_id": candidate.candidate_id,
            "revision": candidate.revision,
            "revision_kind": candidate.revision_kind,
            "state": candidate.state.value,
            "definition_digest": candidate.definition_digest,
        }

    @staticmethod
    def _set_delta(
        before: Sequence[str] | set[str], after: Sequence[str] | set[str]
    ) -> Mapping[str, Any]:
        before_set = set(before)
        after_set = set(after)
        return {
            "added": sorted(after_set - before_set),
            "removed": sorted(before_set - after_set),
            "unchanged": sorted(before_set & after_set),
        }

    @classmethod
    def _baseline_delta(
        cls,
        before: Sequence[Mapping[str, str]],
        after: Sequence[Mapping[str, str]],
    ) -> Mapping[str, Any]:
        before_rows = {row["research_source_id"]: dict(row) for row in before}
        after_rows = {row["research_source_id"]: dict(row) for row in after}
        added = sorted(set(after_rows) - set(before_rows))
        removed = sorted(set(before_rows) - set(after_rows))
        changed = sorted(
            source_id
            for source_id in set(before_rows) & set(after_rows)
            if before_rows[source_id] != after_rows[source_id]
        )
        return {
            "changed": bool(added or removed or changed),
            "added": [after_rows[source_id] for source_id in added],
            "removed": [before_rows[source_id] for source_id in removed],
            "modified": [
                {
                    "research_source_id": source_id,
                    "baseline": before_rows[source_id],
                    "candidate": after_rows[source_id],
                }
                for source_id in changed
            ],
        }

    @staticmethod
    def _fixture_delta(
        before: Sequence[Mapping[str, Any]],
        after: Sequence[Mapping[str, Any]],
    ) -> Mapping[str, Any]:
        before_rows = {str(row.get("fixture_id")): row for row in before}
        after_rows = {str(row.get("fixture_id")): row for row in after}
        shared = set(before_rows) & set(after_rows)
        return {
            "added_fixture_ids": sorted(set(after_rows) - set(before_rows)),
            "removed_fixture_ids": sorted(set(before_rows) - set(after_rows)),
            "changed_fixture_ids": sorted(
                fixture_id
                for fixture_id in shared
                if content_hash(before_rows[fixture_id]) != content_hash(after_rows[fixture_id])
            ),
        }

    @staticmethod
    def _fields(
        request: Mapping[str, Any],
        *,
        required: set[str],
        optional: set[str],
        context: str,
    ) -> None:
        fields = set(request)
        if not required.issubset(fields) or not fields.issubset(required | optional):
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "detection_request_invalid",
                f"Detection {context} request fields are invalid.",
            )

    @staticmethod
    def _evidence_ids(value: Any) -> tuple[str, ...] | None:
        if value is None:
            return None
        if (
            not isinstance(value, list)
            or not value
            or len(value) > _MAX_EVIDENCE
            or not all(isinstance(item, str) and _EVIDENCE_ID.fullmatch(item) for item in value)
            or len(set(value)) != len(value)
        ):
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "detection_evidence_ids_invalid",
                "evidence_ids must be a unique list of at most 256 evidence identifiers.",
            )
        return tuple(value)

    @staticmethod
    def _notes(value: Any, *, context: str) -> tuple[str, ...]:
        if not isinstance(value, list) or len(value) > _MAX_NOTES:
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "detection_notes_invalid",
                f"{context} must be a list of at most {_MAX_NOTES} strings.",
            )
        notes: list[str] = []
        for note in value:
            if (
                not isinstance(note, str)
                or not note.strip()
                or len(note) > _MAX_NOTE_LENGTH
                or "\x00" in note
            ):
                raise APIError(
                    HTTPStatus.BAD_REQUEST,
                    "detection_notes_invalid",
                    f"Each {context} entry must contain 1-{_MAX_NOTE_LENGTH} characters.",
                )
            notes.append(note)
        if len(set(notes)) != len(notes):
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "detection_notes_invalid",
                f"{context} must not contain duplicates.",
            )
        return tuple(notes)

    @staticmethod
    def _fixtures(value: Any) -> tuple[Mapping[str, Any], ...]:
        if not isinstance(value, list) or not 1 <= len(value) <= _MAX_FIXTURES:
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "detection_fixtures_invalid",
                f"fixtures must contain between 1 and {_MAX_FIXTURES} objects.",
            )
        try:
            fixtures = json_clone(value)
            size = len(canonical_json_bytes(fixtures))
        except (TypeError, ValueError, RecursionError) as exc:
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "detection_fixtures_invalid",
                "fixtures must contain only finite JSON values.",
            ) from exc
        if not isinstance(fixtures, list) or size > _MAX_FIXTURE_BYTES:
            raise APIError(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                "detection_fixtures_too_large",
                "Detection fixtures exceed the one-megabyte persisted limit.",
            )
        ids: list[str] = []
        rows: list[Mapping[str, Any]] = []
        for fixture in fixtures:
            if not isinstance(fixture, dict) or not fixture:
                raise APIError(
                    HTTPStatus.BAD_REQUEST,
                    "detection_fixtures_invalid",
                    "Each fixture must be a non-empty JSON object.",
                )
            fixture_id = fixture.get("fixture_id")
            if not isinstance(fixture_id, str) or not _FIXTURE_ID.fullmatch(fixture_id):
                raise APIError(
                    HTTPStatus.BAD_REQUEST,
                    "detection_fixtures_invalid",
                    "Each fixture requires a stable fixture_id of at most 200 characters.",
                )
            ids.append(fixture_id)
            rows.append(fixture)
        if len(set(ids)) != len(ids):
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "detection_fixtures_invalid",
                "Fixture identifiers must be unique.",
            )
        return tuple(rows)

    @staticmethod
    def _yara_fixture_shape(fixtures: Sequence[Mapping[str, Any]]) -> None:
        for fixture in fixtures:
            if set(fixture) != {"fixture_id", "data"} or not isinstance(fixture.get("data"), str):
                raise DetectionError(
                    "YARA fixtures must contain only fixture_id and bounded text data"
                )

    def _immutable_evidence(
        self, run_id: str, selected_ids: tuple[str, ...] | None
    ) -> tuple[EvidenceRecord, ...]:
        try:
            run = self.run_store.get_run(run_id)
        except RunStoreError as exc:
            if "integrity" in str(exc).casefold():
                raise APIError(
                    HTTPStatus.UNPROCESSABLE_ENTITY,
                    "detection_evidence_integrity_invalid",
                    "The finalized evidence bundle failed integrity validation.",
                ) from exc
            raise APIError(
                HTTPStatus.NOT_FOUND,
                "detection_run_not_found",
                "Observed-evidence run was not found.",
            ) from exc
        if not isinstance(run.get("manifest"), Mapping):
            raise APIError(
                HTTPStatus.CONFLICT,
                "detection_run_not_immutable",
                "Observed exercise requires a finalized immutable run bundle.",
            )
        evidence = run.get("evidence")
        rows = evidence.get("records") if isinstance(evidence, Mapping) else None
        if not isinstance(rows, list) or len(rows) > 10_000:
            raise APIError(
                HTTPStatus.UNPROCESSABLE_ENTITY,
                "detection_evidence_invalid",
                "The immutable run has an invalid evidence collection.",
            )
        records: list[EvidenceRecord] = []
        try:
            for row in rows:
                if not isinstance(row, Mapping):
                    raise EvidenceError("evidence row is not an object")
                record = EvidenceRecord.from_mapping(row)
                if record.run_id != run_id:
                    raise EvidenceError("evidence run identity does not match its bundle")
                records.append(record)
        except EvidenceError as exc:
            raise APIError(
                HTTPStatus.UNPROCESSABLE_ENTITY,
                "detection_evidence_invalid",
                "The immutable run contains invalid evidence.",
                [str(exc)],
            ) from exc
        by_id = {record.evidence_id: record for record in records}
        if selected_ids is not None:
            missing = sorted(set(selected_ids) - set(by_id))
            if missing:
                raise APIError(
                    HTTPStatus.UNPROCESSABLE_ENTITY,
                    "detection_evidence_missing",
                    "Requested evidence is not present in the immutable run.",
                    missing,
                )
            selected = [by_id[evidence_id] for evidence_id in selected_ids]
        else:
            selected = [
                record for record in records if record.provenance is EvidenceProvenance.OBSERVED
            ]
        if not selected or len(selected) > _MAX_EVIDENCE:
            raise APIError(
                HTTPStatus.UNPROCESSABLE_ENTITY,
                "detection_observed_evidence_unavailable",
                "Select between 1 and 256 observed evidence records.",
            )
        if any(record.provenance is not EvidenceProvenance.OBSERVED for record in selected):
            raise APIError(
                HTTPStatus.UNPROCESSABLE_ENTITY,
                "detection_observed_evidence_required",
                "Only independently observed evidence may advance this lifecycle action.",
            )
        return tuple(selected)

    @classmethod
    def _observed_fields(cls, records: Sequence[EvidenceRecord]) -> set[str]:
        result: set[str] = set()

        def visit(value: Any, prefix: str) -> None:
            if isinstance(value, Mapping):
                for key, child in value.items():
                    if isinstance(key, str) and key:
                        visit(child, f"{prefix}.{key}" if prefix else key)
            elif prefix:
                result.add(prefix)

        for record in records:
            visit(record.content, "")
        return result

    def _resource(self, candidate_id: str) -> Mapping[str, Any]:
        if not isinstance(candidate_id, str) or not _DETECTION_ID.fullmatch(candidate_id):
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "detection_id_invalid",
                "Detection candidate identifier is invalid.",
            )
        try:
            resource = self.product_store.get_resource("detection", candidate_id)
        except ProductStoreError as exc:
            raise APIError(
                HTTPStatus.NOT_FOUND,
                "detection_not_found",
                "Detection candidate was not found.",
            ) from exc
        return self._validated_resource(resource)

    def _validated_resource(self, resource: Mapping[str, Any]) -> Mapping[str, Any]:
        try:
            candidate = self._candidate_from_resource(resource)
        except DetectionError as exc:
            raise APIError(
                HTTPStatus.UNPROCESSABLE_ENTITY,
                "detection_resource_invalid",
                "Persisted detection candidate failed strict validation.",
                [str(exc)],
            ) from exc
        document = resource.get("document")
        if not isinstance(document, Mapping) or resource.get("digest") != content_hash(document):
            raise APIError(
                HTTPStatus.UNPROCESSABLE_ENTITY,
                "detection_resource_invalid",
                "Persisted detection candidate digest is invalid.",
            )
        self._validated_public_baselines(list(candidate.public_baselines))
        self._validate_revision_lineage(candidate)
        return resource

    def _validate_revision_lineage(self, candidate: DetectionCandidate) -> None:
        if candidate.revision_kind == "origin":
            return
        parent_id = candidate.parent_candidate_id
        if parent_id is None:
            raise APIError(
                HTTPStatus.UNPROCESSABLE_ENTITY,
                "detection_revision_lineage_invalid",
                "Persisted detection revision has no parent candidate.",
            )
        try:
            parent_resource = self.product_store.get_resource("detection", parent_id)
        except ProductStoreError as exc:
            raise APIError(
                HTTPStatus.UNPROCESSABLE_ENTITY,
                "detection_revision_parent_missing",
                "Persisted detection revision parent is unavailable.",
                [parent_id],
            ) from exc
        parent = self._candidate_from_resource(self._validated_resource(parent_resource))
        invalid = (
            parent.revision_root_id != candidate.revision_root_id
            or parent.revision >= candidate.revision
            or parent.behavior_id != candidate.behavior_id
            or parent.target_language != candidate.target_language
        )
        if candidate.revision_kind == "clone":
            invalid = invalid or (
                parent.selection != candidate.selection or parent.logsource != candidate.logsource
            )
        elif candidate.revision_kind == "tune":
            invalid = invalid or (
                parent.selection == candidate.selection and parent.logsource == candidate.logsource
            )
        if invalid:
            raise APIError(
                HTTPStatus.UNPROCESSABLE_ENTITY,
                "detection_revision_lineage_invalid",
                "Persisted detection revision does not match its immutable parent lineage.",
            )

    @staticmethod
    def _candidate_from_resource(resource: Mapping[str, Any]) -> DetectionCandidate:
        document = resource.get("document")
        if not isinstance(document, Mapping):
            raise DetectionError("persisted detection document is not an object")
        candidate = DetectionCandidate.from_mapping(document)
        if resource.get("id") != candidate.candidate_id:
            raise DetectionError("persisted resource ID does not match candidate identity")
        if resource.get("status") != candidate.state.value:
            raise DetectionError("persisted resource status does not match candidate state")
        return candidate

    def _save(self, candidate: DetectionCandidate) -> Mapping[str, Any]:
        try:
            validated = DetectionCandidate.from_mapping(candidate.to_dict())
            return self.product_store.save_resource(
                "detection",
                validated.candidate_id,
                validated.to_dict(),
                status=validated.state.value,
            )
        except DetectionError as exc:
            raise APIError(
                HTTPStatus.UNPROCESSABLE_ENTITY,
                "detection_transition_invalid",
                "Detection transition produced an invalid candidate.",
                [str(exc)],
            ) from exc
        except ProductStoreError as exc:
            raise APIError(
                HTTPStatus.UNPROCESSABLE_ENTITY,
                "detection_persistence_rejected",
                "Detection source, fixtures, or notes were rejected by secret-safe persistence.",
                [str(exc)],
            ) from exc

    @staticmethod
    def _envelope(resource: Mapping[str, Any]) -> Mapping[str, Any]:
        return {
            "schema_version": "bluefire.detection-resource.v1",
            "candidate": resource,
        }

    def _record_transition(
        self,
        before: DetectionCandidate,
        after: DetectionCandidate,
        action: str,
        request: Mapping[str, Any],
        *,
        run_id: str | None = None,
    ) -> DetectionCandidate:
        if after.state is DetectionState.REJECTED:
            outcome = "rejected"
        elif after.state is before.state:
            outcome = "no_state_change"
        else:
            outcome = "transitioned"
        return self._record(
            before,
            after,
            action=action,
            outcome=outcome,
            request=request,
            run_id=run_id,
        )

    @staticmethod
    def _record(
        before: DetectionCandidate | None,
        after: DetectionCandidate,
        *,
        action: str,
        outcome: str,
        request: Mapping[str, Any],
        run_id: str | None = None,
    ) -> DetectionCandidate:
        history = before.lifecycle_history if before is not None else after.lifecycle_history
        if len(history) >= _MAX_HISTORY:
            raise APIError(
                HTTPStatus.CONFLICT,
                "detection_history_full",
                "Detection lifecycle history reached its bounded limit.",
            )
        row: dict[str, Any] = {
            "sequence": len(history) + 1,
            "action": action,
            "from_state": before.state.value if before is not None else None,
            "to_state": after.state.value,
            "outcome": outcome,
            "input_digest": content_hash(request),
            "recorded_at": _utc_now(),
        }
        if run_id is not None:
            row["run_id"] = run_id
        return replace(after, lifecycle_history=(*history, row))

    @staticmethod
    def _raise_detection_error(error: DetectionError, *, action: str) -> NoReturn:
        message = str(error)
        if "unavailable" in message.casefold():
            raise APIError(
                HTTPStatus.SERVICE_UNAVAILABLE,
                "detection_backend_unavailable",
                "The authoritative detection backend is unavailable; candidate state was unchanged.",
            ) from error
        if any(
            marker in message.casefold()
            for marker in (
                "invalid detection transition",
                "must be parsed",
                "must be exercised",
                "only a hypothesis",
                "cannot advance",
            )
        ):
            raise APIError(
                HTTPStatus.CONFLICT,
                "detection_transition_conflict",
                f"Detection cannot {action} from its current state.",
            ) from error
        raise APIError(
            HTTPStatus.UNPROCESSABLE_ENTITY,
            "detection_validation_failed",
            f"Detection could not {action}.",
            [message],
        ) from error


__all__ = ["DetectionLabService"]
