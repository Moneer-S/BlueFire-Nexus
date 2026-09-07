"""Contextual turns composing existing native jobs, reviews and immutable receipts."""

from __future__ import annotations

import re
import uuid
from http import HTTPStatus
from typing import Any, Mapping

from .ai_assistance import REVISE, suggest_plan
from .ai_wire import AIProviderCancelled, AIProviderError
from .application_errors import APIError
from .assistance_context import LIMITATIONS, AssistanceContext
from .assistance_context import context as selected_context
from .assistance_results import TERMINAL, active, child_job, child_path, result
from .config import AIProviderConfig, AIProviderKind, ConfigError
from .detection_ai_jobs import _text
from .job_runtime import JobCancelled, JobContext, JobResult, JobRuntimeError
from .product_store_assistance import KIND, reserve, stop, update
from .product_store_errors import ProductStoreError
from .run_store import RUN_ID_RE
from .util import content_hash


def fail(message: str) -> APIError:
    return APIError(HTTPStatus.CONFLICT, "assistance_turn_refused", message)


class ExperimentAssistance:
    def __init__(self, service: AssistanceContext) -> None:
        self.service = service
        self.store = service.product_store
        self.controller = service.job_controller

    def context(self, run_id: str, candidate_id: str) -> Mapping[str, Any]:
        return selected_context(self.service, run_id, candidate_id)

    def _job(self, job_id: str) -> Mapping[str, Any]:
        try:
            job = self.store.get_job(job_id)
        except ProductStoreError as exc:
            raise APIError(
                HTTPStatus.NOT_FOUND, "assistance_turn_not_found", "Assistance turn was not found."
            ) from exc
        if job["kind"] != KIND:
            raise fail("The selected job is not an assistance turn.")
        return job

    def _fresh(self, job: Mapping[str, Any]) -> Mapping[str, Any]:
        request = job["request"]["submitted_request"]
        current = self.context(request["run_id"], request["candidate_id"])
        if current != job["request"]["context"]:
            raise fail(
                "The selected saved source or detector changed. Review the current objects in a new turn."
            )
        return current

    def _provider(self, job: Mapping[str, Any]) -> AIProviderConfig:
        request = job["request"]
        provider = self.service._runtime_ai().provider(request["submitted_request"]["provider_id"])
        if (
            provider.kind is AIProviderKind.DETERMINISTIC
            or content_hash(provider.to_dict()) != request["provider_binding_digest"]
        ):
            raise fail("The explicitly selected provider changed or is unavailable.")
        return provider

    def submit(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        self.service.detection_lab._fields(
            request,
            required={
                "submission_id",
                "context_digest",
                "run_id",
                "candidate_id",
                "candidate_resource_digest",
                "message",
                "case_role",
                "autonomy",
            },
            optional={"provider_id"},
            context="assistance turn",
        )
        _text(request["message"], 1000, "Message")
        if request["autonomy"] not in ("off", "assist", "auto") or request["case_role"] not in (
            "attack",
            "benign",
            "replay",
            "heldout",
        ):
            raise fail("Select an explicit autonomy level and source case role.")
        if (
            not isinstance(request["run_id"], str)
            or not RUN_ID_RE.fullmatch(request["run_id"])
            or not isinstance(request["candidate_id"], str)
            or not re.fullmatch(r"detection-[0-9a-f]{20}", request["candidate_id"])
        ):
            raise fail("Select canonical saved run and detector identifiers.")
        if any(
            not isinstance(request[key], str)
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", request[key])
            for key in ("context_digest", "candidate_resource_digest")
        ):
            raise fail("Selected context and resource digests are invalid.")
        if "provider_id" in request:
            _text(request["provider_id"], 200, "Provider")
        intent = content_hash(dict(request))
        try:
            existing = self.store.get_job_submission(
                KIND, submission_id=request["submission_id"], intent_digest=intent
            )
            if existing is not None:
                return self.read(existing["job_id"])
            document: dict[str, Any] = {
                "schema_version": "bluefire.assistance-turn-request.v1",
                "submitted_request": dict(request),
                "context": None,
            }
            try:
                context = self.context(request["run_id"], request["candidate_id"])
                if (
                    request["context_digest"] != context["context_digest"]
                    or request["candidate_resource_digest"]
                    != context["selected"]["candidate_resource_digest"]
                ):
                    raise fail("The selected objects changed after the message was prepared.")
                document["context"] = context
                if request["autonomy"] == "assist":
                    provider_id = _text(request.get("provider_id"), 200, "Provider")
                    provider = self.service._runtime_ai().provider(provider_id)
                    if provider.kind is AIProviderKind.DETERMINISTIC:
                        raise fail("Select an explicit model provider for this assistance turn.")
                    document["provider_binding_digest"] = content_hash(provider.to_dict())
                elif request["autonomy"] == "auto":
                    document["admission_error"] = (
                        "The current rule-revision capability requires native Assist review. Select Assist; Auto support remains capability-specific."
                    )
            except (APIError, ConfigError, ProductStoreError) as exc:
                document["admission_error"] = (
                    exc.message
                    if isinstance(exc, APIError)
                    else "The selected saved objects or explicit provider are unavailable. Review them in a new turn."
                )
            job = self.controller.submit(
                KIND,
                document,
                callback=self._plan,
                submission_id=request["submission_id"],
                intent_digest=intent,
            )
            return self.read(job["job_id"])
        except (ProductStoreError, ConfigError, JobRuntimeError) as exc:
            raise fail(str(exc)) from exc

    def _plan(self, ctx: JobContext, request: Mapping[str, Any]) -> JobResult:
        submitted = request["submitted_request"]
        if "admission_error" in request:
            ctx.checkpoint({"operation_error": request["admission_error"]})
            raise fail(request["admission_error"])
        if submitted["autonomy"] == "off":
            return JobResult(
                progress={
                    "message": "AI is Off. No model request or child operation was made. Review the selected run and saved detector in their native views.",
                    "plan": [],
                    "off": True,
                }
            )
        try:
            job = self._job(ctx.job_id)
            context = self._fresh(job)
            proposal = suggest_plan(
                config=self._provider(job),
                access=self.service._provider_access,
                context=context,
                message=submitted["message"],
                cancel=ctx.cancellation_event,
            )
            ctx.checkpoint(proposal)
            self._advance(ctx.job_id)
            return JobResult(progress={"planning_complete": True})
        except AIProviderCancelled as exc:
            raise JobCancelled("Assistance provider cancellation confirmed.") from exc
        except (APIError, AIProviderError, ProductStoreError, ConfigError, JobRuntimeError) as exc:
            if ctx.cancellation_event.is_set():
                raise JobCancelled("Assistance turn cancelled.") from exc
            ctx.checkpoint(
                {
                    "operation_error": (
                        exc.message
                        if isinstance(exc, APIError)
                        else "The provider or retained capability binding failed validation. No unsupported action was taken."
                    )
                }
            )
            raise

    def _advance(self, parent_id: str) -> None:
        parent = self._job(parent_id)
        if parent["progress"].get("stopped") or parent["state"] in {"cancelled", "cancelling"}:
            raise fail("This assistance turn is cancelled.")
        if parent["request"]["submitted_request"]["autonomy"] != "assist":
            return
        self._fresh(parent)
        self._provider(parent)
        submitted = parent["request"]["submitted_request"]
        candidate_id = submitted["candidate_id"]
        for step in parent["progress"].get("plan", []):
            child = child_job(self.service, parent, step)
            if child is not None:
                completed = result(self.service, child, step)
                if completed is None:
                    return
                if completed["kind"] == "detection_revision":
                    candidate_id = completed["candidate_id"]
                continue
            resource = self.service.detection_lab._resource(candidate_id)
            submission = str(
                uuid.uuid5(uuid.UUID(submitted["submission_id"]), "capability:" + step["step_id"])
            )
            common = {
                "submission_id": submission,
                "provider_id": submitted["provider_id"],
                "autonomy": "assist",
            }
            if step["capability_id"] == REVISE:
                child_request = {
                    **common,
                    "run_id": submitted["run_id"],
                    "parent_resource_digest": resource["digest"],
                    "question": submitted["message"],
                    "case_role": submitted["case_role"],
                }
                kind, object_id = "detection.ai.propose", candidate_id
            else:
                prepared = self.service.method_comparison.context(submitted["run_id"])
                options = prepared["options"]
                if not options:
                    raise fail(
                        "No compatible method is ready in the retained source authority. Open the native method review."
                    )
                # The existing method service/model selects a validated option; the
                # assistance layer binds only the authoritative step to investigate.
                step_ids = sorted({option["step_id"] for option in options})
                if len(step_ids) != 1:
                    raise fail(
                        "More than one method step is available. Select the intended step in native Compare before proceeding."
                    )
                child_request = {
                    **common,
                    "source_binding_digest": prepared["source_binding_digest"],
                    "selected_step_id": step_ids[0],
                    "candidate_id": candidate_id,
                    "candidate_resource_digest": resource["digest"],
                    "question": submitted["message"],
                    "source_case_role": submitted["case_role"],
                }
                kind, object_id = "replay.ai.propose", submitted["run_id"]
            reservation = {
                "job_id": "job-" + uuid.UUID(submission).hex,
                "submission_id": submission,
                "kind": kind,
                "object_id": object_id,
                "request": child_request,
            }
            reserve(self.store, parent_id, step["step_id"], reservation)
            binding = {"parent_job_id": parent_id, "step_id": step["step_id"]}
            if kind == "detection.ai.propose":
                self.service.detection_ai.submit(object_id, child_request, _assistance_turn=binding)
            else:
                self.service.method_comparison.submit(
                    object_id, child_request, _assistance_turn=binding
                )
            update(self.store, parent_id, {"handoff_error": None})
            return

    def application_committed(self, child: Mapping[str, Any]) -> None:
        """Existing native commit hook: no timer, polling, scheduler or review bypass."""
        parent_id = child["request"]["assistance_turn"]["parent_job_id"]
        try:
            self._advance(parent_id)
        except (APIError, ProductStoreError, ConfigError, JobRuntimeError) as exc:
            # The native application is already committed. A handoff failure must
            # never turn it into an apparent failed application or repeat it.
            try:
                update(
                    self.store,
                    parent_id,
                    {
                        "handoff_error": (
                            exc.message
                            if isinstance(exc, APIError)
                            else "The next capability could not be admitted. Recover this turn after reviewing readiness."
                        )
                    },
                )
            except ProductStoreError:
                # The immutable application receipt remains authoritative. A later
                # read infers the missing child and offers explicit recovery.
                pass

    def continue_turn(self, parent_id: str, request: Mapping[str, Any]) -> Mapping[str, Any]:
        self.service.detection_lab._fields(
            request,
            required={"submission_id", "context_digest"},
            optional=set(),
            context="assistance continuation",
        )
        if not isinstance(request["context_digest"], str) or not re.fullmatch(
            r"sha256:[0-9a-f]{64}", request["context_digest"]
        ):
            raise fail("Continuation context digest is invalid.")
        try:
            identifier = uuid.UUID(request["submission_id"])
            if str(identifier) != request["submission_id"]:
                raise ValueError
        except (ValueError, TypeError, AttributeError) as exc:
            raise fail("Continuation requires a canonical submission UUID.") from exc
        parent = self._job(parent_id)
        try:
            intent = content_hash({"parent_job_id": parent_id, **dict(request)})
            existing = self.store.get_job_submission(
                "assistance.continue", submission_id=request["submission_id"], intent_digest=intent
            )
            if existing is not None:
                return self.read(parent_id)
            document = {"parent_job_id": parent_id, "context_digest": request["context_digest"]}
            if (
                request["context_digest"]
                != parent["request"]["submitted_request"]["context_digest"]
            ):
                document["admission_error"] = "Continuation refers to a different selected context."
            elif "plan" not in parent["progress"]:
                document["admission_error"] = (
                    "No validated plan was retained. Start a new turn instead of repeating an uncertain model request."
                )
            continuation = self.controller.submit(
                "assistance.continue",
                document,
                callback=self._continue,
                submission_id=request["submission_id"],
                intent_digest=intent,
            )
            update(self.store, parent_id, {"continuation_job_id": continuation["job_id"]})
        except (ProductStoreError, ConfigError, JobRuntimeError) as exc:
            raise fail(str(exc)) from exc
        return self.read(parent_id)

    def _continue(self, ctx: JobContext, request: Mapping[str, Any]) -> JobResult:
        ctx.checkpoint()
        try:
            if "admission_error" in request:
                raise fail(request["admission_error"])
            self._advance(request["parent_job_id"])
        except (APIError, ProductStoreError, ConfigError, JobRuntimeError) as exc:
            if ctx.cancellation_event.is_set():
                raise JobCancelled(
                    "Assistance continuation cancelled; parent turn is stopped."
                ) from exc
            update(
                self.store,
                request["parent_job_id"],
                {
                    "handoff_error": (
                        exc.message
                        if isinstance(exc, APIError)
                        else "The next capability could not be admitted. Review native readiness before recovery."
                    )
                },
            )
            raise
        ctx.checkpoint()
        return JobResult(progress={"parent_job_id": request["parent_job_id"]})

    def _continuations(self, parent: Mapping[str, Any]) -> list[Mapping[str, Any]]:
        """Existing bounded controller inventory plus the durable latest receipt."""
        identifiers = set(self.controller.active_job_ids)
        latest = parent["progress"].get("continuation_job_id")
        if latest:
            identifiers.add(latest)
        return [
            job
            for job in (self.store.get_job(identifier) for identifier in identifiers)
            if job["kind"] == "assistance.continue"
            and job["request"].get("parent_job_id") == parent["job_id"]
        ]

    def cancel_continuation(self, job_id: str) -> Mapping[str, Any]:
        job = self.store.get_job(job_id)
        request = job["request"]
        parent = self._job(request["parent_job_id"])
        submission = request["_submission"]
        if (
            job["kind"] != "assistance.continue"
            or job_id != "job-" + uuid.UUID(submission["submission_id"]).hex
            or submission["intent_digest"]
            != content_hash(
                {
                    "parent_job_id": parent["job_id"],
                    "submission_id": submission["submission_id"],
                    "context_digest": request["context_digest"],
                }
            )
        ):
            raise fail("Continuation cancellation has an invalid retained parent binding.")
        if job["state"] not in TERMINAL:
            # Stop authorizes no further publication before signalling the callback.
            # cancel() uses controller.cancel directly, never this service route.
            self.cancel(parent["job_id"])
        return self.store.get_job(job_id)

    def _settled(self, parent: Mapping[str, Any]) -> bool:
        """Resolve every native lifecycle independently of candidate/result validity."""
        try:
            if parent["state"] not in TERMINAL:
                return False
            if any(job["state"] not in TERMINAL for job in self._continuations(parent)):
                return False
            for step in parent["progress"].get("plan", []):
                child = child_job(self.service, parent, step)
                if child is not None and active(self.service, child, step)["state"] not in TERMINAL:
                    return False
            return True
        except (APIError, ProductStoreError, KeyError, TypeError, ValueError):
            return False

    def cancel(self, parent_id: str) -> Mapping[str, Any]:
        parent = stop(self.store, parent_id)
        for continuation in self._continuations(parent):
            if continuation["state"] not in TERMINAL:
                try:
                    self.controller.cancel(continuation["job_id"])
                except JobRuntimeError:
                    pass
        for step in parent["progress"].get("plan", []):
            child = child_job(self.service, parent, step)
            if child is None:
                continue
            if child["kind"] == "replay.ai.propose":
                self.service.method_comparison.cancel(child["job_id"])
            else:
                current = active(self.service, child, step)
                if current["state"] not in TERMINAL:
                    try:
                        self.controller.cancel(current["job_id"])
                    except JobRuntimeError:
                        pass
        if parent["state"] not in TERMINAL:
            try:
                self.controller.cancel(parent_id)
            except JobRuntimeError:
                pass
        return self.read(parent_id)

    def read(self, parent_id: str) -> Mapping[str, Any]:
        parent = self._job(parent_id)
        progress, request = parent["progress"], parent["request"]
        selected = request["submitted_request"]
        view: dict[str, Any] = {
            "schema_version": "bluefire.assistance-turn.v1",
            "status": "planning",
            "message": progress.get(
                "message", "Selecting supported next steps for the saved objects."
            ),
            "context_digest": selected["context_digest"],
            "selected": {
                key: selected[key]
                for key in ("run_id", "candidate_id", "candidate_resource_digest")
            },
            "plan": progress.get("plan", []),
            "active_child": None,
            "next_action": None,
            "results": [],
            "limitations": list(LIMITATIONS),
        }
        try:
            view["continuation"] = None
            if progress.get("continuation_job_id"):
                continuation = self.store.get_job(progress["continuation_job_id"])
                if (
                    continuation["kind"] != "assistance.continue"
                    or continuation["request"].get("parent_job_id") != parent_id
                ):
                    raise ProductStoreError("Continuation receipt has different selected context.")
                view["continuation"] = {
                    "job_id": continuation["job_id"],
                    "submission_id": continuation["request"]["_submission"]["submission_id"],
                    "state": continuation["state"],
                    "context_digest": continuation["request"]["context_digest"],
                }
            if progress.get("off"):
                view["status"] = "off"
            elif "plan" not in progress:
                if parent["state"] in TERMINAL:
                    view.update(
                        status="blocked",
                        message=progress.get(
                            "operation_error",
                            "Planning did not retain a validated result. Start a new turn; no model request will be repeated automatically.",
                        ),
                        next_action={
                            "kind": "new_turn",
                            "label": "Start a new turn",
                            "native_path": None,
                        },
                    )
            elif not progress["plan"]:
                view.update(
                    status="blocked",
                    next_action={
                        "kind": "new_turn",
                        "label": "Review supported next steps",
                        "native_path": None,
                    },
                )
            else:
                view["status"] = "completed"
                for step in progress["plan"]:
                    child = child_job(self.service, parent, step)
                    if child is None:
                        view.update(
                            status="ready_to_continue",
                            next_action={
                                "kind": "continue",
                                "label": "Recover next step",
                                "native_path": None,
                            },
                        )
                        continuation_id = progress.get("continuation_job_id")
                        if (
                            continuation_id
                            and self.store.get_job(continuation_id)["state"] not in TERMINAL
                        ):
                            view.update(status="working", next_action=None)
                        if progress.get("handoff_error") or progress.get("operation_error"):
                            view["message"] = (
                                progress.get("handoff_error") or progress["operation_error"]
                            )
                        break
                    completed = result(self.service, child, step)
                    if completed is not None:
                        view["results"].append(completed)
                        continue
                    current = active(self.service, child, step)
                    view["active_child"] = current
                    decision = child["progress"].get("decision", {}).get("decision")
                    if current["state"] == "awaiting_approval":
                        view.update(
                            status="awaiting_execute_approval",
                            next_action={
                                "kind": "review_execute",
                                "label": "Review Execute approval",
                                "native_path": current["native_path"],
                            },
                        )
                    elif child["state"] == "completed" and not decision:
                        revision = child["kind"] == "detection.ai.propose"
                        view.update(
                            status="awaiting_review",
                            next_action={
                                "kind": "review_detection" if revision else "review_method",
                                "label": (
                                    "Review rule revision" if revision else "Review method proposal"
                                ),
                                "native_path": child_path(child),
                            },
                        )
                    elif decision == "reject" or current["state"] in {
                        "failed",
                        "interrupted",
                        "cancelled",
                        "completed",
                    }:
                        view.update(
                            status="blocked",
                            message="The native operation needs attention or was declined. Review its retained receipt; no operation will be repeated automatically.",
                            next_action={
                                "kind": (
                                    "review_detection"
                                    if step["capability_id"] == REVISE
                                    else "review_method"
                                ),
                                "label": "Review native operation",
                                "native_path": child_path(child),
                            },
                        )
                    else:
                        view["status"] = "working"
                    break
        except (APIError, ProductStoreError, KeyError, TypeError, ValueError):
            view.update(
                status="blocked",
                message="Retained assistance records no longer match their selected objects. Stop this turn and review native receipts before starting another.",
                active_child=None,
                next_action=None,
                results=[],
            )
        if progress.get("stopped") or parent["state"] in {"cancelled", "cancelling"}:
            settled = self._settled(parent)
            view.update(
                status="cancelled" if settled else "cancelling",
                message=(
                    "This turn is stopped. Only verified committed results remain available."
                    if settled
                    else "Cancellation requested; native settlement is still pending or cannot yet be verified."
                ),
                next_action=None,
            )
        view["can_start_new_turn"] = view["status"] in {"off", "completed", "cancelled"} or (
            view["status"] == "blocked" and not progress.get("plan") and self._settled(parent)
        )
        return {"job": parent, "turn": view}
