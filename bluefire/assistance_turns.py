"""Contextual turns composing existing native jobs, reviews and immutable receipts."""

from __future__ import annotations

import re
import uuid
from http import HTTPStatus
from typing import Any, Mapping
from urllib.parse import urlencode

from .ai_assistance import COMPARE, CREATE, REVISE, message_text, suggest_plan
from .ai_wire import AIProviderCancelled, AIProviderError
from .application_errors import APIError
from .assistance_context import LIMITATIONS, AssistanceContext
from .assistance_context import context as selected_context
from .assistance_receiver_context import KINDS as RECEIVER_KINDS
from .assistance_receiver_context import selection as receiver_selection
from .assistance_results import TERMINAL, active, child_job, child_path, result
from .assistance_run_context import CAPABILITY as RUN
from .assistance_run_context import selection as run_selection
from .assistance_run_context import setup_path as run_setup_path
from .config import AIProviderConfig, AIProviderKind, ConfigError
from .detection_ai_jobs import _text
from .detection_create_context import selection as create_selection
from .graph_ai_context import GRAPH
from .graph_ai_context import selection as graph_selection
from .job_runtime import JobCancelled, JobContext, JobResult, JobRuntimeError
from .product_store_assistance import KIND, attach_continuation, reserve, stop, update
from .product_store_errors import ProductStoreError
from .run_store import RUN_ID_RE
from .util import content_hash


def fail(message: str) -> APIError:
    return APIError(HTTPStatus.CONFLICT, "assistance_turn_refused", message)


def submitted(request: Mapping[str, Any]) -> Mapping[str, Any]:
    """Normalize additive selection syntax without changing the durable wire request."""
    chosen = request.get("selection")
    if chosen is None or chosen.get("kind") in {
        "graph",
        "saved_graph",
        "saved_scenario",
        "run_detection",
        *RECEIVER_KINDS,
    }:
        return request
    return {
        **{key: value for key, value in request.items() if key != "selection"},
        **{key: value for key, value in chosen.items() if key != "kind"},
    }


def is_graph(request: Mapping[str, Any]) -> bool:
    return bool(
        request.get("selection", {}).get("kind")
        in {"graph", "saved_graph", "saved_scenario", "run_detection", *RECEIVER_KINDS}
    )


def is_receiver(request):
    return request.get("selection", {}).get("kind") in RECEIVER_KINDS


def is_creation(request: Mapping[str, Any]) -> bool:
    return bool(request.get("selection", {}).get("kind") == "run_detection")


def is_saved_run(request: Mapping[str, Any]) -> bool:
    return bool(request.get("selection", {}).get("kind") in {"saved_graph", "saved_scenario"})


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
        request = submitted(request)
        if is_receiver(request):
            return dict(self.service.assistance_receiver.fresh(job))
        current = (
            (
                self.service.assistance_runs.context(request["selection"])
                if is_saved_run(request)
                else (
                    self.service.detection_create.context(request["selection"])
                    if is_creation(request)
                    else self.service.graph_ai.context(request["selection"])
                )
            )
            if is_graph(request)
            else self.context(request["run_id"], request["candidate_id"])
        )
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
        original = request
        if "selection" in request:
            self.service.detection_lab._fields(
                request,
                required={"submission_id", "context_digest", "selection", "message", "autonomy"},
                optional={"provider_id"},
                context="assistance turn",
            )
            chosen = request["selection"]
            if not isinstance(chosen, Mapping) or not isinstance(chosen.get("kind"), str):
                raise fail("Select a typed graph or detector context.")
            if chosen.get("kind") in {
                "graph",
                "saved_graph",
                "saved_scenario",
                "run_detection",
                *RECEIVER_KINDS,
            }:
                try:
                    (
                        receiver_selection
                        if chosen["kind"] in RECEIVER_KINDS
                        else (
                            graph_selection
                            if chosen["kind"] == "graph"
                            else (
                                create_selection
                                if chosen["kind"] == "run_detection"
                                else run_selection
                            )
                        )
                    )(chosen)
                except ProductStoreError as exc:
                    raise fail(str(exc)) from exc
            elif chosen.get("kind") == "detection":
                self.service.detection_lab._fields(
                    chosen,
                    required={
                        "kind",
                        "run_id",
                        "candidate_id",
                        "candidate_resource_digest",
                        "case_role",
                    },
                    optional=set(),
                    context="detector selection",
                )
                request = submitted(request)
            else:
                raise fail("Select a typed graph or detector context.")
        else:
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
        try:
            message_text(request["message"])
        except AIProviderError as exc:
            raise fail(str(exc)) from exc
        if request["autonomy"] not in ("off", "assist", "auto") or (
            not is_graph(request)
            and request["case_role"]
            not in (
                "attack",
                "benign",
                "replay",
                "heldout",
            )
        ):
            raise fail("Select an explicit autonomy level and source case role.")
        if not is_graph(request) and (
            not isinstance(request["run_id"], str)
            or not RUN_ID_RE.fullmatch(request["run_id"])
            or not isinstance(request["candidate_id"], str)
            or not re.fullmatch(r"detection-[0-9a-f]{20}", request["candidate_id"])
        ):
            raise fail("Select canonical saved run and detector identifiers.")
        if any(
            not isinstance(request[key], str)
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", request[key])
            for key in (
                ("context_digest",)
                if is_graph(request)
                else ("context_digest", "candidate_resource_digest")
            )
        ):
            raise fail("Selected context and resource digests are invalid.")
        if "provider_id" in request:
            _text(request["provider_id"], 200, "Provider")
        intent = content_hash(dict(original))
        try:
            existing = self.store.get_job_submission(
                KIND, submission_id=request["submission_id"], intent_digest=intent
            )
            if existing is not None:
                return self.read(existing["job_id"])
            document: dict[str, Any] = {
                "schema_version": "bluefire.assistance-turn-request.v1",
                "submitted_request": dict(original),
                "context": None,
            }
            try:
                context = (
                    self.service.assistance_receiver.context(request["selection"])
                    if is_receiver(request)
                    else (
                        (
                            self.service.assistance_runs.context(request["selection"])
                            if is_saved_run(request)
                            else (
                                self.service.detection_create.context(request["selection"])
                                if is_creation(request)
                                else self.service.graph_ai.context(request["selection"])
                            )
                        )
                        if is_graph(request)
                        else self.context(request["run_id"], request["candidate_id"])
                    )
                )
                if request["context_digest"] != context["context_digest"] or (
                    not is_graph(request)
                    and request["candidate_resource_digest"]
                    != context["selected"]["candidate_resource_digest"]
                ):
                    raise fail("The selected objects changed after the message was prepared.")
                document["context"] = context
                if (is_creation(request) or is_receiver(request)) and not context["capabilities"][
                    0
                ]["available"]:
                    raise fail(context["capabilities"][0]["reason"])
                if request["autonomy"] == "assist" or (
                    is_graph(request) and request["autonomy"] == "auto"
                ):
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
                    "message": "AI is Off. No model request or child operation was made. Review the selected objects in their native views.",
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
            if self._job(ctx.job_id)["progress"].get("plan"):
                problem = self._handoff_problem(ctx.job_id, exc)
                ctx.checkpoint({"handoff_error": problem["message"], "handoff_problem": problem})
                raise
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

    def _advance(self, parent_id: str, *, recovery: bool = False) -> None:
        parent = self._job(parent_id)
        if parent["progress"].get("stopped") or parent["state"] in {"cancelled", "cancelling"}:
            raise fail("This assistance turn is cancelled.")
        if parent["request"]["submitted_request"]["autonomy"] not in {"assist", "auto"}:
            return
        self._fresh(parent)
        self._provider(parent)
        selected_request = submitted(parent["request"]["submitted_request"])
        if is_receiver(selected_request):
            self.service.assistance_receiver.advance(parent, recovery=recovery)
            return
        if is_graph(selected_request):
            self._advance_graph(parent, selected_request, recovery=recovery)
            return
        submitted_request = selected_request
        question = " ".join(submitted_request["message"].split())
        candidate_id = submitted_request["candidate_id"]
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
                uuid.uuid5(
                    uuid.UUID(submitted_request["submission_id"]), "capability:" + step["step_id"]
                )
            )
            common = {
                "submission_id": submission,
                "provider_id": submitted_request["provider_id"],
                "autonomy": "assist",
            }
            if step["capability_id"] == REVISE:
                child_request = {
                    **common,
                    "run_id": submitted_request["run_id"],
                    "parent_resource_digest": resource["digest"],
                    "question": question,
                    "case_role": submitted_request["case_role"],
                }
                kind, object_id = "detection.ai.propose", candidate_id
            else:
                prepared = self.service.method_comparison.context(submitted_request["run_id"])
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
                    "question": question,
                    "source_case_role": submitted_request["case_role"],
                }
                kind, object_id = "replay.ai.propose", submitted_request["run_id"]
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
            update(self.store, parent_id, {"handoff_error": None, "handoff_problem": None})
            return

    def _advance_graph(
        self, parent: Mapping[str, Any], request: Mapping[str, Any], *, recovery: bool = False
    ) -> None:
        saved_run = is_saved_run(request)
        creation = is_creation(request)
        kind = (
            "detection.ai.create"
            if creation
            else "run.assistance.prepare" if saved_run else "graph.ai.propose"
        )
        for step in parent["progress"].get("plan", []):
            if step["capability_id"] != (CREATE if creation else RUN if saved_run else GRAPH):
                raise fail("The graph context cannot dispatch detector operations.")
            child = child_job(self.service, parent, step)
            if child is not None:
                if saved_run:
                    self.service.assistance_runs.advance(child["job_id"], retry_inspection=recovery)
                return
            submission = str(
                uuid.uuid5(uuid.UUID(request["submission_id"]), "capability:" + step["step_id"])
            )
            child_request = {
                key: request[key]
                for key in ("selection", "context_digest", "message", "autonomy", "provider_id")
            }
            child_request["submission_id"] = submission
            reserve(
                self.store,
                parent["job_id"],
                step["step_id"],
                {
                    "job_id": "job-" + uuid.UUID(submission).hex,
                    "submission_id": submission,
                    "kind": kind,
                    "object_id": request["context_digest"],
                    "request": child_request,
                },
            )
            (
                self.service.detection_create
                if creation
                else self.service.assistance_runs if saved_run else self.service.graph_ai
            ).submit(
                child_request,
                _assistance_turn={"parent_job_id": parent["job_id"], "step_id": step["step_id"]},
            )
            update(self.store, parent["job_id"], {"handoff_error": None, "handoff_problem": None})
            return

    def _handoff_problem(self, parent_id: str, error: Exception) -> Mapping[str, Any]:
        """Expose fixed remediation, never exception text, paths or arbitrary details."""
        parent = self._job(parent_id)
        chosen = submitted(parent["request"]["submitted_request"])
        if is_creation(chosen):
            return {
                "code": "source_review_required",
                "message": "Review the verified source and native initial rule proposal; a changed source requires a new turn.",
                "profile_id": None,
                "action": {
                    "label": "Review initial rule source",
                    "native_path": "/detection-lab?"
                    + urlencode({"run": chosen["selection"]["run_id"], "create": "1"}),
                },
            }
        if is_saved_run(chosen):
            return {
                "code": "native_review_required",
                "message": "The saved experiment needs native run attention. Check the runner and retained run receipt; recovery only resumes missing preparation or inspection, never repeats a run.",
                "profile_id": chosen["selection"]["run_intent"]["runner_profile_id"],
                "action": {
                    "label": "Review run setup",
                    "native_path": run_setup_path(chosen["selection"]),
                },
            }
        if is_receiver(chosen):
            path = "/compare"
            plan = parent["progress"].get("plan", [])
            if plan:
                owner_id, _ = self.service.assistance_receiver._owner(parent, plan[0])
                if owner_id:
                    path += "?receiver_job=" + owner_id
            return {
                "code": "receiver_review_required",
                "message": "Review the retained receiver test and analysis. Recovery cannot repeat effects or renew a receiver session.",
                "profile_id": None,
                "action": {"label": "Review receiver test", "native_path": path},
            }
        if is_graph(chosen):
            return {
                "code": "source_review_required",
                "message": "The graph proposal needs attention. Review the saved reference and current catalog in Builder; changed context requires a new turn.",
                "profile_id": None,
                "action": {"label": "Review graph context", "native_path": "/builder"},
            }
        run_id = chosen["run_id"]
        candidate_id = chosen["candidate_id"]
        source_path = "/detection-lab?" + urlencode(
            {"run": run_id, "candidate": candidate_id, "candidate_scope": "registry"}
        )
        problem: dict[str, Any] = {
            "code": "source_review_required",
            "message": "The next step could not be prepared. Review the selected source and saved objects before continuing.",
            "profile_id": None,
            "action": {"label": "Review selected source", "native_path": source_path},
        }
        capability = None
        try:
            for step in parent["progress"].get("plan", []):
                child = child_job(self.service, parent, step)
                if child is not None and result(self.service, child, step) is not None:
                    continue
                capability = step["capability_id"]
                detection = capability == REVISE
                problem.update(
                    code="detection_review_required" if detection else "native_review_required",
                    message=(
                        "The rule revision could not be prepared. Review the selected rule and evidence; changed context requires a new turn."
                        if detection
                        else "The next step could not be prepared. Review the source and native method requirements before resuming this saved turn."
                    ),
                    action={
                        "label": (
                            "Review rule and evidence"
                            if detection
                            else "Review method requirements"
                        ),
                        "native_path": (
                            child_path(child)
                            if child is not None
                            else (
                                source_path
                                if detection
                                else "/compare?" + urlencode({"source": run_id})
                            )
                        ),
                    },
                )
                break
        except (APIError, ProductStoreError, KeyError, TypeError, ValueError):
            pass
        if not (
            capability == COMPARE
            and isinstance(error, APIError)
            and error.code == "replay_preparation_refused"
            and isinstance(error.details, Mapping)
            and error.details.get("reason_code") == "runner_readiness_required"
        ):
            return problem
        try:
            source, binding, _ = self.service.method_comparison._source(run_id)
            if binding != parent["request"]["context"]["selected"]["source_binding"]:
                return problem
            profile = source.get("profile")
            profile_id = profile.get("id") if isinstance(profile, Mapping) else None
            if (
                source.get("mode") != "execute"
                or not isinstance(profile_id, str)
                or not re.fullmatch(r"[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*\.v[1-9][0-9]*", profile_id)
            ):
                return problem
            return {
                "code": "runner_readiness_required",
                "message": "Check the recorded runner before preparing the other method. Your saved results remain available; resuming rechecks the original source and authority.",
                "profile_id": profile_id,
                "action": {
                    "label": "Check runner setup",
                    "native_path": (
                        "/runs?setup=execute" if profile_id == "sandbox-execute.v1" else "/runners"
                    ),
                },
            }
        except (APIError, ProductStoreError, KeyError, TypeError, ValueError):
            return problem

    def application_committed(self, child: Mapping[str, Any]) -> None:
        """Existing native commit hook: no timer, polling, scheduler or review bypass."""
        parent_id = child["request"]["assistance_turn"]["parent_job_id"]
        try:
            self._advance(parent_id)
        except (APIError, ProductStoreError, ConfigError, JobRuntimeError) as exc:
            # The native application is already committed. A handoff failure must
            # never turn it into an apparent failed application or repeat it.
            try:
                problem = self._handoff_problem(parent_id, exc)
                update(
                    self.store,
                    parent_id,
                    {"handoff_error": problem["message"], "handoff_problem": problem},
                )
            except (APIError, ProductStoreError):
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
                attach_continuation(self.store, parent_id, existing["job_id"])
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
            attach_continuation(self.store, parent_id, continuation["job_id"])
        except (ProductStoreError, ConfigError, JobRuntimeError) as exc:
            raise fail(str(exc)) from exc
        return self.read(parent_id)

    def _continue(self, ctx: JobContext, request: Mapping[str, Any]) -> JobResult:
        ctx.checkpoint()
        try:
            if "admission_error" in request:
                raise fail(request["admission_error"])
            self._advance(request["parent_job_id"], recovery=True)
        except (APIError, ProductStoreError, ConfigError, JobRuntimeError) as exc:
            if ctx.cancellation_event.is_set():
                raise JobCancelled(
                    "Assistance continuation cancelled; parent turn is stopped."
                ) from exc
            problem = self._handoff_problem(request["parent_job_id"], exc)
            update(
                self.store,
                request["parent_job_id"],
                {"handoff_error": problem["message"], "handoff_problem": problem},
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
            if is_receiver(parent["request"]["submitted_request"]):
                return bool(self.service.assistance_receiver.settled(parent))
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
        receiver = is_receiver(parent["request"]["submitted_request"])
        if receiver:
            self.service.assistance_receiver.cancel(parent)
        for step in ([] if receiver else parent["progress"].get("plan", [])):
            child = child_job(self.service, parent, step)
            if child is None:
                continue
            if child["kind"] == "run.assistance.prepare":
                self.service.assistance_runs.cancel(child["job_id"])
            elif child["kind"] == "detection.ai.create":
                self.service.detection_create.cancel(child["job_id"])
            elif child["kind"] == "graph.ai.propose":
                self.service.graph_ai.cancel(child["job_id"])
            elif child["kind"] == "replay.ai.propose":
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
        selected = submitted(request["submitted_request"])
        view: dict[str, Any] = {
            "schema_version": "bluefire.assistance-turn.v1",
            "status": "planning",
            "message": progress.get(
                "message", "Selecting supported next steps for the saved objects."
            ),
            "context_digest": selected["context_digest"],
            "selected": (
                selected["selection"]
                if is_graph(selected)
                else {
                    key: selected[key]
                    for key in ("run_id", "candidate_id", "candidate_resource_digest")
                }
            ),
            "plan": progress.get("plan", []),
            "active_child": None,
            "next_action": None,
            "results": [],
            "recovery": None,
            "limitations": list((request.get("context") or {}).get("limitations", LIMITATIONS)),
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
                    if is_receiver(
                        request["submitted_request"]
                    ) and self.service.assistance_receiver.apply_view(parent, step, view):
                        break
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
                        if progress.get("handoff_problem"):
                            view["recovery"] = progress["handoff_problem"]
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
                    if child["kind"] == "detection.ai.create":
                        from .detection_create_view import apply_view

                        apply_view(
                            self.service.detection_create.read(child["job_id"]), view, current
                        )
                        break
                    if child["kind"] == "run.assistance.prepare":
                        from .assistance_run_view import apply_view

                        apply_view(
                            self.service.assistance_runs.read(child["job_id"]), view, current
                        )
                        break
                    decision = child["progress"].get("decision", {}).get("decision")
                    if child["progress"].get("stopped"):
                        decision = "reject"
                    if current["state"] == "awaiting_approval":
                        view.update(
                            status="awaiting_execute_approval",
                            next_action={
                                "kind": "review_execute",
                                "label": "Review Execute approval",
                                "native_path": current["native_path"],
                            },
                        )
                    elif (child["state"] == "completed" and not decision) or (
                        child["kind"] == "graph.ai.propose"
                        and self.service.graph_ai.read(child["job_id"])["review_ready"]
                    ):
                        revision = child["kind"] == "detection.ai.propose"
                        view.update(
                            status="awaiting_review",
                            next_action={
                                "kind": (
                                    "review_graph"
                                    if child["kind"] == "graph.ai.propose"
                                    else "review_detection" if revision else "review_method"
                                ),
                                "label": (
                                    "Review graph proposal"
                                    if child["kind"] == "graph.ai.propose"
                                    else (
                                        "Review rule revision"
                                        if revision
                                        else "Review method proposal"
                                    )
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
                                    "review_graph"
                                    if step["capability_id"] == GRAPH
                                    else (
                                        "review_detection"
                                        if step["capability_id"] == REVISE
                                        else "review_method"
                                    )
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
        if view["status"] != "ready_to_continue":
            view["recovery"] = None
        view["can_start_new_turn"] = (
            (view.get("can_start_new_turn") is True and self._settled(parent))
            or view["status"] in {"off", "completed", "cancelled"}
            or (view["status"] == "blocked" and not progress.get("plan") and self._settled(parent))
        )
        return {"job": parent, "turn": view}
