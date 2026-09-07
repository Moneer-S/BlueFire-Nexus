"""Detection assistance using the existing durable callback job controller."""

from __future__ import annotations

import re
import uuid
from http import HTTPStatus
from typing import Any, Callable, Mapping

from .ai_detection_revision import PROPOSAL_SCHEMA, observed_context, suggest_source
from .ai_provider_access import AIProviderAccess
from .ai_wire import AIProviderCancelled, AIProviderError
from .application_errors import APIError
from .config import AIConfig, AIProviderConfig, AIProviderKind, ConfigError
from .detection_evaluations import _source, _source_binding, build_run_evaluation
from .detection_lab import DetectionLabService
from .detections import DetectionCandidate, DetectionError, DetectionState
from .job_runtime import (
    JobCancelled,
    JobContext,
    JobQueueFull,
    JobResult,
    JobRuntimeError,
    RunJobController,
)
from .product_store_detection_ai import (
    APPLY_KIND,
    PROPOSE_KIND,
    apply_revision,
    decide,
    proposal_from_job,
)
from .product_store_errors import ProductStoreError
from .util import content_hash

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
REQUEST_SCHEMA = "bluefire.detection-ai-request.v1"


def _fail(
    message: str, *, code: str = "detection_ai_conflict", status: HTTPStatus = HTTPStatus.CONFLICT
) -> APIError:
    return APIError(status, code, message)


def _text(value: Any, limit: int, name: str) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value.strip()) <= limit
        or any(ord(char) < 32 for char in value)
    ):
        raise _fail(
            f"{name} must contain 1–{limit} printable characters.", status=HTTPStatus.BAD_REQUEST
        )
    return value.strip()


class DetectionAIJobs:
    def __init__(
        self,
        *,
        lab: DetectionLabService,
        controller: RunJobController,
        ai_config: Callable[[], AIConfig],
        access: AIProviderAccess,
    ) -> None:
        self.lab, self.controller, self.ai_config, self.access = lab, controller, ai_config, access
        self.store = lab.product_store
        self.on_application: Callable[[Mapping[str, Any]], None] | None = None

    def _provider(self, provider_id: str) -> AIProviderConfig:
        config = self.ai_config()
        try:
            provider = config.provider(provider_id)
        except ConfigError as exc:
            raise _fail("Selected provider is unavailable.") from exc
        if provider.kind is AIProviderKind.DETERMINISTIC:
            raise _fail(
                "Select a configured model provider; offline planning cannot generate detection source.",
                code="detection_ai_provider_required",
            )
        return provider

    def submit(
        self,
        candidate_id: str,
        request: Mapping[str, Any],
        *,
        _assistance_turn: Mapping[str, Any] | None = None,
    ) -> Mapping[str, Any]:
        self.lab._fields(
            request,
            required={
                "submission_id",
                "run_id",
                "parent_resource_digest",
                "question",
                "case_role",
                "provider_id",
            },
            optional={"autonomy"},
            context="detection AI revision",
        )
        provider_id = _text(request["provider_id"], 200, "Provider")
        question = _text(request["question"], 1000, "Question")
        if request["case_role"] not in ("attack", "benign", "replay", "heldout"):
            raise _fail(
                "Declare attack, benign, replay, or heldout as case context.",
                status=HTTPStatus.BAD_REQUEST,
            )
        digest = request["parent_resource_digest"]
        if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
            raise _fail(
                "A valid parent resource digest is required.", status=HTTPStatus.BAD_REQUEST
            )
        intent = content_hash({"candidate_id": candidate_id, **dict(request)})
        try:
            existing = self.store.get_job_submission(
                PROPOSE_KIND, submission_id=request["submission_id"], intent_digest=intent
            )
        except ProductStoreError as exc:
            raise _fail(str(exc), status=HTTPStatus.BAD_REQUEST) from exc
        if existing is not None:
            return {"job": existing}
        document: dict[str, Any] = {
            "schema_version": REQUEST_SCHEMA,
            "candidate_id": candidate_id,
            "submitted_request": dict(request),
        }
        if _assistance_turn is not None:
            document["assistance_turn"] = dict(_assistance_turn)
        try:
            autonomy = request.get("autonomy", self.ai_config().autonomy.value)
            if autonomy == "off":
                raise _fail(
                    "AI is Off. Select Assist before requesting a detection revision.",
                    code="detection_ai_off",
                )
            if autonomy != "assist":
                raise _fail(
                    "This detection operation supports Assist review. Auto orchestration is not yet available.",
                    code="detection_ai_autonomy_unsupported",
                )
            provider = self._provider(provider_id)
            with self.lab._lock:
                resource = self.lab._resource(candidate_id)
                parent = self.lab._candidate_from_resource(resource)
                if resource["digest"] != digest:
                    raise _fail("The selected parent changed; review its current source.")
                if parent.target_language not in {"sqlite", "sigma"} or not parent.rule_source:
                    raise _fail("Select an existing SQLite or Sigma source candidate.")
                run, records, observed = _source(self.lab, request["run_id"])
                observed_context(observed, provider)
                document.update(
                    {
                        "parent": {
                            "candidate_id": candidate_id,
                            "resource_digest": digest,
                            "definition_digest": parent.definition_digest,
                            "target_language": parent.target_language,
                            "source": parent.rule_source,
                        },
                        "source_run": _source_binding(run, records, observed),
                        "observed_ids": [row.evidence_id for row in observed],
                        "question": question,
                        "case_role": request["case_role"],
                        "provider_id": provider_id,
                        "provider_binding_digest": content_hash(provider.to_dict()),
                        "autonomy": "assist",
                        "application_submission_id": str(uuid.uuid4()),
                    }
                )
        except APIError as exc:
            document["admission_error"] = {"code": exc.code, "message": exc.message}
        except AIProviderError:
            document["admission_error"] = {
                "code": "detection_ai_context_unsupported",
                "message": "Detection assistance requires 1–128 valid observed records with bounded field metadata.",
            }
        try:
            job = self.controller.submit(
                PROPOSE_KIND,
                document,
                callback=self._propose,
                submission_id=request["submission_id"],
                intent_digest=intent,
            )
        except ProductStoreError as exc:
            raise _fail(str(exc)) from exc
        except (JobQueueFull, JobRuntimeError) as exc:
            raise _fail(
                "Detection job capacity is unavailable; retry this same submission.",
                status=HTTPStatus.SERVICE_UNAVAILABLE,
            ) from exc
        return {"job": job}

    def _fresh(self, request: Mapping[str, Any]) -> tuple[Mapping[str, Any], list[Any]]:
        resource = self.lab._resource(request["parent"]["candidate_id"])
        self.lab._candidate_from_resource(resource)
        if resource["digest"] != request["parent"]["resource_digest"]:
            raise _fail("The parent changed after this operation was prepared.")
        run, records, observed = _source(self.lab, request["source_run"]["run_id"])
        if _source_binding(run, records, observed) != request["source_run"]:
            raise _fail("The immutable source no longer matches the selected run.")
        return resource, observed

    def _propose(self, context: JobContext, request: Mapping[str, Any]) -> JobResult:
        return self._with_diagnostic(context, request, self._propose_work)

    def _with_diagnostic(
        self,
        context: JobContext,
        request: Mapping[str, Any],
        callback: Callable[[JobContext, Mapping[str, Any]], JobResult],
    ) -> JobResult:
        try:
            return callback(context, request)
        except (APIError, AIProviderError, ProductStoreError) as exc:
            if context.cancellation_event.is_set():
                raise JobCancelled("Detection operation cancelled.") from exc
            error = (
                {"code": exc.code, "message": exc.message}
                if isinstance(exc, APIError)
                else {
                    "code": "detection_ai_operation_refused",
                    "message": "The provider response or retained detection binding failed validation. Inspect the durable application receipt for any committed result.",
                }
            )
            context.checkpoint({"operation_error": error})
            raise

    def _propose_work(self, context: JobContext, request: Mapping[str, Any]) -> JobResult:
        if "admission_error" in request:
            error = request["admission_error"]
            raise _fail(error["message"], code=error["code"])
        if request.get("autonomy") != "assist":
            raise _fail("The retained detection request does not authorize Assist.")
        context.checkpoint({"operation_phase": "requesting_detection_revision"})
        provider = self._provider(request["provider_id"])
        if content_hash(provider.to_dict()) != request["provider_binding_digest"]:
            raise _fail("Provider configuration changed; make a new reviewed request.")
        resource, observed = self._fresh(request)
        model_context = {
            "parent": request["parent"],
            "question": request["question"],
            "source_run": request["source_run"],
            "observations": observed_context(observed, provider),
            "development_case": True,
        }
        try:
            suggestion = suggest_source(
                config=provider,
                access=self.access,
                context=model_context,
                cancel_event=context.cancellation_event,
            )
        except AIProviderCancelled as exc:
            raise JobCancelled("Detection provider cancellation confirmed.") from exc
        context.checkpoint()
        parent = self.lab._candidate_from_resource(resource)
        hypothesis = DetectionCandidate.hypothesis(
            behavior_id=parent.behavior_id,
            title=parent.title,
            target_language=parent.target_language,
            logsource=parent.logsource,
            selection=parent.selection,
            provenance=parent.provenance,
        )
        parse = (
            self.lab.validator.parse_sqlite
            if parent.target_language == "sqlite"
            else self.lab.validator.parse_sigma
        )
        try:
            validated = parse(hypothesis, suggestion["source"])
        except DetectionError as exc:
            raise _fail(
                "The selected detection parser is unavailable or refused the proposed source.",
                code="detection_ai_source_invalid",
            ) from exc
        if validated.state is not DetectionState.PARSED:
            raise _fail(
                "The proposed source failed the existing bounded detection parser; no proposal is available to apply.",
                code="detection_ai_source_invalid",
            )
        self._fresh(request)
        proposal = {
            "schema_version": PROPOSAL_SCHEMA,
            **suggestion,
            "parent": request["parent"],
            "source_run": request["source_run"],
            "provider_binding_digest": request["provider_binding_digest"],
        }
        proposal["proposal_digest"] = content_hash(proposal)
        return JobResult(progress={"operation_phase": "proposal_available", "proposal": proposal})

    def decision(self, job_id: str, request: Mapping[str, Any]) -> Mapping[str, Any]:
        self.lab._fields(
            request,
            required={"proposal_digest", "parent_resource_digest", "decision", "reviewed_by"},
            optional=set(),
            context="detection revision decision",
        )
        if request["decision"] not in ("accept", "reject"):
            raise _fail("Decision must be accept or reject.", status=HTTPStatus.BAD_REQUEST)
        reviewed = {**request, "reviewed_by": _text(request["reviewed_by"], 200, "Reviewer")}
        try:
            job = decide(self.store, job_id, reviewed)
            application = None
            if reviewed["decision"] == "accept":
                application_request = {
                    "schema_version": "bluefire.detection-ai-apply-request.v1",
                    "proposal_job_id": job_id,
                    "proposal_digest": reviewed["proposal_digest"],
                }
                if "assistance_turn" in job["request"]:
                    application_request["assistance_turn"] = job["request"]["assistance_turn"]
                application = self.controller.submit(
                    APPLY_KIND,
                    application_request,
                    callback=self._apply,
                    submission_id=job["request"]["application_submission_id"],
                    intent_digest=content_hash(application_request),
                )
                application = self._latest_application(application)
            return {
                "proposal_job": job,
                "application_job": application,
                "decision": job["progress"]["decision"],
            }
        except ProductStoreError as exc:
            raise _fail(str(exc)) from exc
        except (JobQueueFull, JobRuntimeError) as exc:
            raise _fail(
                "Decision retained. Retry the same decision to recover its application job.",
                status=HTTPStatus.SERVICE_UNAVAILABLE,
            ) from exc

    @staticmethod
    def _retry_intent(job: Mapping[str, Any]) -> tuple[dict[str, Any], str]:
        request = {key: value for key, value in job["request"].items() if key != "_submission"}
        request["retry_of_job_id"] = job["job_id"]
        submission_id = str(
            uuid.uuid5(uuid.NAMESPACE_URL, "bluefire.detection.retry:" + str(job["job_id"]))
        )
        return request, submission_id

    def _latest_application(self, job: Mapping[str, Any]) -> Mapping[str, Any]:
        for _ in range(32):
            if job["state"] != "interrupted":
                return job
            request, submission_id = self._retry_intent(job)
            successor = self.store.get_job_submission(
                APPLY_KIND, submission_id=submission_id, intent_digest=content_hash(request)
            )
            if successor is None:
                return job
            if {
                key: value for key, value in successor["request"].items() if key != "_submission"
            } != request:
                raise ProductStoreError("Detection application retry lineage is invalid.")
            job = successor
        raise ProductStoreError("Detection application retry lineage exceeds its recovery bound.")

    def _apply(self, context: JobContext, request: Mapping[str, Any]) -> JobResult:
        return self._with_diagnostic(context, request, self._apply_work)

    def _apply_work(self, context: JobContext, request: Mapping[str, Any]) -> JobResult:
        context.checkpoint({"operation_phase": "applying_detection_revision"})
        proposal_job = self.store.get_job(request["proposal_job_id"])
        proposal = proposal_from_job(proposal_job)
        if request["proposal_digest"] != proposal["proposal_digest"]:
            raise _fail("Application proposal digest does not match.")
        stored = proposal_job["request"]
        # Existing committed receipts are resolved in the transaction even if the
        # parent lifecycle has since advanced. New effects require freshness.
        if proposal_job["progress"].get("application") is None:
            self._fresh(stored)
        committed: dict[str, Any] = {}

        def cancelled() -> None:
            if context.cancellation_event.is_set():
                raise JobCancelled("Detection application cancelled before commit.")

        def report(resource: Mapping[str, Any]) -> Mapping[str, Any]:
            candidate = self.lab._candidate_from_resource(resource)
            return build_run_evaluation(
                self.lab,
                candidate,
                resource,
                {
                    "run_id": stored["source_run"]["run_id"],
                    "question": stored["question"],
                    "case_role": stored["case_role"],
                },
                development_case=True,
            )

        def commit(
            revision_root_id: str,
            build_document: Callable[[int], Mapping[str, Any]],
            *,
            max_revisions: int,
        ) -> Mapping[str, Any]:
            resource, evaluation, receipt = apply_revision(
                self.store,
                proposal_job_id=str(proposal_job["job_id"]),
                application_job_id=context.job_id,
                revision_root_id=revision_root_id,
                build_document=build_document,
                max_revisions=max_revisions,
                build_report=report,
                check_cancelled=cancelled,
            )
            committed.update({"resource": resource, "evaluation": evaluation, "receipt": receipt})
            return resource

        self.lab._create_revision(
            str(proposal["parent"]["candidate_id"]),
            {
                "source": proposal["source"],
                "reason": proposal["reason"],
                "ai_revision_proposal": {
                    "job_id": proposal_job["job_id"],
                    "proposal_digest": proposal["proposal_digest"],
                },
            },
            revision_kind="source",
            application_commit=commit,
        )
        if self.on_application is not None and "assistance_turn" in stored:
            self.on_application(self.store.get_job(str(proposal_job["job_id"])))
        return JobResult(
            result_ref=committed["resource"]["id"],
            progress={"operation_phase": "revision_applied", "application": committed["receipt"]},
            completion_confirmed=True,
        )

    def retry(self, job_id: str) -> Mapping[str, Any]:
        try:
            job = self.store.get_job(job_id)
            if job["kind"] not in {PROPOSE_KIND, APPLY_KIND} or job["state"] != "interrupted":
                raise ProductStoreError("Only interrupted detection jobs can be retried.")
            request, submission_id = self._retry_intent(job)
            replacement = self.controller.submit(
                job["kind"],
                request,
                callback=self._apply if job["kind"] == APPLY_KIND else self._propose,
                submission_id=submission_id,
                intent_digest=content_hash(request),
            )
            job = self.store.transition_job(
                job_id,
                "interrupted",
                progress={**job["progress"], "retry_job_id": replacement["job_id"]},
            )
        except ProductStoreError as exc:
            raise _fail(str(exc)) from exc
        except (JobQueueFull, JobRuntimeError) as exc:
            raise _fail(
                "Detection retry capacity is unavailable; retry the same interrupted job.",
                status=HTTPStatus.SERVICE_UNAVAILABLE,
            ) from exc
        return {
            "schema_version": "bluefire.job-retry.v1",
            "retry_of_job_id": job_id,
            "source_job": job,
            "job": replacement,
        }
