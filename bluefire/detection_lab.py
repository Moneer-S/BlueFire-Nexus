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
)
from .evidence import EvidenceError, EvidenceProvenance, EvidenceRecord
from .product_store import ProductStore, ProductStoreError
from .registry import BehaviorRegistry, RegistryError
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
        public_baselines = request.get("public_baselines", [])
        predicted_fields = request.get("predicted_fields", [])
        if (
            not isinstance(known_misses, list)
            or not isinstance(public_baselines, list)
            or not all(isinstance(row, Mapping) for row in public_baselines)
            or not isinstance(predicted_fields, list)
        ):
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "detection_hypothesis_invalid",
                "Hypothesis misses, baselines, and predicted fields must be bounded JSON lists.",
            )
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
            )
            proposed = replace(proposed, predicted_fields=tuple(predicted_fields))
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
                outcome = "created"
            else:
                before = self._candidate_from_resource(self._validated_resource(existing_resource))
                if before.state is not DetectionState.HYPOTHESIS:
                    raise APIError(
                        HTTPStatus.CONFLICT,
                        "detection_hypothesis_locked",
                        "A progressed or rejected candidate cannot be overwritten as a hypothesis.",
                    )
                candidate = replace(
                    before,
                    title=proposed.title,
                    public_baselines=proposed.public_baselines,
                    known_misses=proposed.known_misses,
                    provenance=proposed.provenance,
                    predicted_fields=proposed.predicted_fields,
                )
                outcome = "updated"
            recorded = self._record(
                before,
                candidate,
                action="hypothesis_upsert",
                outcome=outcome,
                request=request,
            )
            return self._envelope(self._save(recorded))

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
            self._candidate_from_resource(resource)
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
        return resource

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
