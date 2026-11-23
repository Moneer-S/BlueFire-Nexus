"""Initial source proposals and reviewed applications on the existing job controller."""

from __future__ import annotations

import uuid
from contextlib import AbstractContextManager
from http import HTTPStatus
from typing import Any, Callable, Mapping

from . import product_store_detection_create as records
from .action_catalog import ActionCatalogSnapshot
from .ai_assistance import message_text
from .ai_detection_create import APPLY_KIND, KIND, PROPOSAL_SCHEMA, suggest_source
from .ai_detection_revision import observed_context
from .ai_provider_access import AIProviderAccess
from .ai_wire import AIProviderCancelled
from .application_errors import APIError
from .config import AIConfig, AIProviderConfig, AIProviderKind
from .detection_ai_jobs import DetectionAIJobs, _text
from .detection_create_candidate import parsed, reviewed_digest
from .detection_create_context import context, selection, source
from .detection_evaluations import _source, build_run_evaluation
from .detection_lab import DetectionLabService
from .job_runtime import JobCancelled, JobContext, JobResult, RunJobController
from .product_store_assistance import job_at, patch, require_active
from .product_store_errors import ProductStoreError
from .registry import RegistryError
from .util import content_hash

TERMINAL = {"completed", "failed", "cancelled", "interrupted"}


def fail(message: str) -> APIError:
    return APIError(HTTPStatus.CONFLICT, "detection_creation_refused", message)


class DetectionCreateJobs:
    def __init__(
        self,
        *,
        lab: DetectionLabService,
        controller: RunJobController,
        ai_config: Callable[[], AIConfig],
        access: AIProviderAccess,
        configuration_lock: AbstractContextManager[Any],
        catalog: Callable[[], ActionCatalogSnapshot],
    ) -> None:
        self.lab, self.store, self.controller = lab, lab.product_store, controller
        self.ai_config, self.access, self.configuration_lock = ai_config, access, configuration_lock
        self.catalog = catalog
        self.on_application: Callable[[Mapping[str, Any]], None] | None = None

    def source(self, run_id: str) -> Mapping[str, Any]:
        try:
            return source(self.lab, run_id, self.catalog().registry)
        except (ProductStoreError, RegistryError) as exc:
            raise fail(
                "The verified source or its registered behavior is unavailable. Review the selected run."
            ) from exc

    def context(self, selected: Mapping[str, Any]) -> Mapping[str, Any]:
        try:
            snapshot = self.catalog()
            return context(
                self.lab,
                selected,
                snapshot.registry,
                {
                    "generation": snapshot.generation,
                    "catalog_digest": snapshot.catalog_digest,
                    "authority_digest": snapshot.authority.get("authority_digest"),
                },
            )
        except (ProductStoreError, RegistryError) as exc:
            raise fail(
                "The verified source, selected behavior or parser context changed. Select its current source binding."
            ) from exc

    def _job(self, job_id: str) -> Mapping[str, Any]:
        try:
            job = self.store.get_job(job_id)
        except ProductStoreError as exc:
            raise APIError(
                HTTPStatus.NOT_FOUND,
                "detection_creation_not_found",
                "The initial source proposal was not found.",
            ) from exc
        if job["kind"] != KIND:
            raise fail("The selected job is not an initial source proposal.")
        return job

    def _fresh(self, job: Mapping[str, Any]) -> AIProviderConfig:
        request = job["request"]
        if self.context(request["submitted_request"]["selection"]) != request["context"]:
            raise fail(
                "The selected source, behavior or parser changed. Review a new source context."
            )
        provider = self.ai_config().provider(request["submitted_request"]["provider_id"])
        if (
            provider.kind is AIProviderKind.DETERMINISTIC
            or content_hash(provider.to_dict()) != request["provider_binding_digest"]
        ):
            raise fail("The explicitly selected provider changed or is unavailable.")
        return provider

    def submit(
        self, request: Mapping[str, Any], *, _assistance_turn: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        self.lab._fields(
            request,
            required={
                "submission_id",
                "selection",
                "context_digest",
                "message",
                "autonomy",
                "provider_id",
            },
            optional=set(),
            context="initial detection proposal",
        )
        selection(request["selection"])
        message_text(request["message"])
        _text(request["provider_id"], 200, "Provider")
        if request["autonomy"] not in {"assist", "auto"}:
            raise fail("Off cannot create an initial source proposal.")
        intent = content_hash(dict(request))
        existing = self.store.get_job_submission(
            KIND, submission_id=request["submission_id"], intent_digest=intent
        )
        if existing is not None:
            return self.read(existing["job_id"])
        with self.configuration_lock:
            current = self.context(request["selection"])
            if (
                current["context_digest"] != request["context_digest"]
                or not current["capabilities"][0]["available"]
            ):
                raise fail("The selected source changed or initial source creation is unavailable.")
            provider = self.ai_config().provider(request["provider_id"])
            if provider.kind is AIProviderKind.DETERMINISTIC:
                raise fail("Select an explicit model provider.")
            _, _, observed = _source(self.lab, request["selection"]["run_id"])
            document = {
                "submitted_request": dict(request),
                "context_digest": request["context_digest"],
                "context": current,
                "provider_binding_digest": content_hash(provider.to_dict()),
                "observed_ids": [row.evidence_id for row in observed],
                "assistance_turn": dict(_assistance_turn),
            }
            job = self.controller.submit(
                KIND,
                document,
                callback=self._propose,
                submission_id=request["submission_id"],
                intent_digest=intent,
            )
        return self.read(job["job_id"])

    def _propose(self, ctx: JobContext, request: Mapping[str, Any]) -> JobResult:
        ctx.checkpoint({"operation_phase": "proposing_initial_source"})
        job = self._job(ctx.job_id)
        with self.configuration_lock:
            provider = self._fresh(job)
            with self.store._connection() as connection:
                require_active(self.store, connection, job)
        _, _, observed = _source(self.lab, request["context"]["selected"]["run_id"])
        try:
            suggestion = suggest_source(
                config=provider,
                access=self.access,
                context={
                    "selected": request["context"]["selected"],
                    "message": request["submitted_request"]["message"],
                    "observations": observed_context(observed, provider),
                },
                cancel_event=ctx.cancellation_event,
            )
        except AIProviderCancelled as exc:
            raise JobCancelled() from exc
        value = {
            "schema_version": PROPOSAL_SCHEMA,
            "selected": request["context"]["selected"],
            "source_run": request["context"]["source"]["source_run"],
            "provider_binding_digest": request["provider_binding_digest"],
            **suggestion,
        }
        value["proposal_digest"] = content_hash(value)
        with self.configuration_lock, self.store._connection(write=True) as connection:
            current = job_at(self.store, connection, ctx.job_id)
            require_active(self.store, connection, current)
            self._fresh(current)
            if current["progress"].get("stopped") or ctx.cancellation_event.is_set():
                raise JobCancelled()
            records.safe_patch(connection, current, {"proposal": value})
        return JobResult(progress={"operation_phase": "awaiting_native_source_review"})

    def _application(self, job: Mapping[str, Any]) -> Mapping[str, Any] | None:
        decision = job["progress"].get("decision")
        if not decision or decision["decision"] != "accept":
            return None
        request, identifier = self._application_intent(job)
        current = self.store.get_job_submission(
            APPLY_KIND, submission_id=identifier, intent_digest=content_hash(request)
        )
        for _ in range(32):
            if current is None or current["state"] != "interrupted":
                return current
            request, identifier = DetectionAIJobs._retry_intent(current)
            successor = self.store.get_job_submission(
                APPLY_KIND, submission_id=identifier, intent_digest=content_hash(request)
            )
            if successor is None:
                return current
            current = successor
        raise fail("Initial source application recovery exceeded its bound.")

    @staticmethod
    def _application_intent(job: Mapping[str, Any]) -> tuple[dict[str, Any], str]:
        identifier = str(
            uuid.uuid5(
                uuid.UUID(job["request"]["submitted_request"]["submission_id"]),
                "initial-source-application",
            )
        )
        return {
            "proposal_job_id": job["job_id"],
            "decision": job["progress"]["decision"],
            "assistance_turn": job["request"]["assistance_turn"],
        }, identifier

    def read(self, job_id: str) -> Mapping[str, Any]:
        job = self._job(job_id)
        proposal = records.proposal(job) if "proposal" in job["progress"] else None
        with self.store._connection() as connection:
            committed = records.committed(self.store, connection, job)
            ready = (
                proposal is not None
                and job["state"] in {"completed", "interrupted"}
                and not job["progress"].get("decision")
                and not job["progress"].get("stopped")
            )
            if ready:
                try:
                    require_active(self.store, connection, job)
                except ProductStoreError:
                    ready = False
        return {
            "job": job,
            "proposal": proposal,
            "review_ready": ready,
            "decision": job["progress"].get("decision"),
            "application_job": self._application(job),
            "application": committed[0] if committed else None,
            "evaluation": committed[1] if committed else None,
        }

    def validate(self, job_id: str, request: Mapping[str, Any]) -> Mapping[str, Any]:
        self.lab._fields(
            request,
            required={"proposal_digest", "title", "source"},
            optional=set(),
            context="initial detection validation",
        )
        envelope = self.read(job_id)
        if (
            not envelope["review_ready"]
            or request["proposal_digest"] != envelope["proposal"]["proposal_digest"]
        ):
            raise fail("Only the exact retained and active proposal can be validated for review.")
        with self.configuration_lock:
            self._fresh(envelope["job"])
            candidate = parsed(
                self.lab, envelope["proposal"]["selected"], request["title"], request["source"]
            )
        return {
            **request,
            "reviewed_digest": reviewed_digest(
                request["proposal_digest"], request["title"], request["source"], candidate
            ),
            "validation": {
                "valid": True,
                "target_language": candidate.target_language,
                "backend": dict(candidate.parser_backend or {}),
            },
        }

    def review(self, job_id: str, request: Mapping[str, Any]) -> Mapping[str, Any]:
        accept = request.get("decision") == "accept"
        self.lab._fields(
            request,
            required={"decision", "proposal_digest", "reviewed_by"}
            | ({"reviewed_digest", "title", "source"} if accept else set()),
            optional=set(),
            context="initial detection review",
        )
        if request["decision"] not in {"accept", "reject"}:
            raise fail("Choose accept or reject.")
        _text(request["reviewed_by"], 200, "Reviewer")
        job = self._job(job_id)
        previous = job["progress"].get("decision")
        if previous is not None:
            if content_hash(previous) != content_hash(dict(request)):
                raise fail("This proposal already has a different exact decision.")
        else:
            if accept:
                validated = self.validate(
                    job_id, {key: request[key] for key in ("proposal_digest", "title", "source")}
                )
                if validated["reviewed_digest"] != request["reviewed_digest"]:
                    raise fail(
                        "The edited source changed after validation. Validate the exact current source."
                    )
            with self.configuration_lock, self.store._connection(write=True) as connection:
                job = job_at(self.store, connection, job_id)
                proposal = records.proposal(job)
                require_active(self.store, connection, job)
                if job["progress"].get("decision") is not None:
                    if job["progress"]["decision"] != request:
                        raise fail("A different decision won this proposal review.")
                else:
                    if (
                        job["state"] not in {"completed", "interrupted"}
                        or job["progress"].get("stopped")
                        or request["proposal_digest"] != proposal["proposal_digest"]
                    ):
                        raise fail("The proposal is not available for native review.")
                    if accept:
                        self._fresh(job)
                    try:
                        records.safe_patch(connection, job, {"decision": dict(request)})
                    except records.CreationRefused as exc:
                        raise APIError(HTTPStatus.UNPROCESSABLE_ENTITY, exc.code, str(exc)) from exc
            job = self._job(job_id)
        if accept and not job["progress"].get("application"):
            self._enqueue_application(job)
        if not accept and self.on_application is not None:
            self.on_application(job)
        return self.read(job_id)

    def _enqueue_application(self, job: Mapping[str, Any]) -> None:
        current = self._application(job)
        if current is None:
            request, identifier = self._application_intent(job)
        elif current["state"] == "interrupted":
            request, identifier = DetectionAIJobs._retry_intent(current)
        else:
            return
        self.controller.submit(
            APPLY_KIND,
            request,
            callback=self._apply,
            submission_id=identifier,
            intent_digest=content_hash(request),
        )

    def _apply(self, ctx: JobContext, request: Mapping[str, Any]) -> JobResult:
        try:
            return self._apply_current(ctx, request)
        except (APIError, ProductStoreError) as exc:
            job = self._job(request["proposal_job_id"])
            parent = self.store.get_job(job["request"]["assistance_turn"]["parent_job_id"])
            if (
                ctx.cancellation_event.is_set()
                or job["progress"].get("stopped")
                or parent["progress"].get("stopped")
                or parent["state"] in {"cancelled", "cancelling"}
            ):
                raise JobCancelled() from exc
            if isinstance(exc, APIError):
                ctx.checkpoint({"operation_error": exc.message, "operation_error_code": exc.code})
            elif isinstance(exc, records.CreationRefused):
                ctx.checkpoint({"operation_error": str(exc), "operation_error_code": exc.code})
            raise

    def _apply_current(self, ctx: JobContext, request: Mapping[str, Any]) -> JobResult:
        ctx.checkpoint({"operation_phase": "parsing_reviewed_initial_source"})
        job = self._job(request["proposal_job_id"])
        envelope = self.read(job["job_id"])
        if envelope["application"] is not None:
            return JobResult(result_ref=envelope["application"]["candidate_id"])
        decision = request["decision"]
        if job["progress"].get("decision") != decision:
            raise fail("The application decision differs from the retained native review.")
        with self.configuration_lock:
            self._fresh(job)
        selected = job["request"]["context"]["selected"]
        candidate = parsed(self.lab, selected, decision["title"], decision["source"])
        if (
            reviewed_digest(
                decision["proposal_digest"], decision["title"], decision["source"], candidate
            )
            != decision["reviewed_digest"]
        ):
            raise fail("The exact source validation binding changed before application.")
        resource = {
            "id": candidate.candidate_id,
            "digest": content_hash(candidate.to_dict()),
            "document": candidate.to_dict(),
        }
        ctx.checkpoint({"operation_phase": "evaluating_reviewed_initial_source"})
        report = build_run_evaluation(
            self.lab,
            candidate,
            resource,
            {
                "run_id": selected["run_id"],
                "case_role": selected["case_role"],
                "question": " ".join(job["request"]["submitted_request"]["message"].split()),
            },
            development_case=True,
        )

        def check(current: Mapping[str, Any]) -> None:
            self._fresh(current)
            if current["progress"].get("stopped") or ctx.cancellation_event.is_set():
                raise JobCancelled()

        with self.configuration_lock:
            receipt = records.apply(
                self.store,
                proposal_job_id=job["job_id"],
                application_job_id=ctx.job_id,
                candidate=candidate,
                report=report,
                check=check,
            )
        if self.on_application is not None:
            self.on_application(self._job(job["job_id"]))
        return JobResult(
            result_ref=receipt["candidate_id"],
            progress={"operation_phase": "initial_rule_and_development_evaluation_saved"},
        )

    def cancel(self, job_id: str) -> Mapping[str, Any]:
        with self.store._connection(write=True) as connection:
            job = job_at(self.store, connection, job_id)
            if job["kind"] != KIND:
                raise fail("Select the original initial source proposal to stop this operation.")
            if not job["progress"].get("application"):
                patch(connection, job, {"stopped": True})
        if not job["progress"].get("application"):
            app = self._application(job)
            for child in (job, app):
                if child is not None and child["state"] not in TERMINAL:
                    self.controller.cancel(child["job_id"])
        return self.read(job_id)
