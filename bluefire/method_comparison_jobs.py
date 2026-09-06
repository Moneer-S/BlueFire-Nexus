"""One connected method replay and detector comparison on existing durable jobs."""

from __future__ import annotations

import re
import uuid
from http import HTTPStatus
from typing import Any, Mapping, Protocol

from .ai_detection_revision import observed_context
from .ai_method_comparison import PROPOSAL_SCHEMA, suggest_method
from .ai_provider_access import AIProviderAccess
from .ai_wire import AIProviderCancelled, AIProviderError
from .application_errors import APIError
from .comparison import compare_runs
from .config import AIConfig, AIProviderConfig, AIProviderKind, ConfigError
from .contracts import ExecutionMode, ScenarioDefinition
from .detection_evaluations import _source, _source_binding, build_run_evaluation
from .detection_lab import DetectionLabService
from .job_runtime import (
    JobCancelled,
    JobContext,
    JobNotManaged,
    JobResult,
    JobRuntimeError,
    RunJobController,
)
from .product_store import ProductStore
from .product_store_errors import ProductStoreError
from .product_store_method_comparison import (
    PROPOSE_KIND,
    RECOVER_KIND,
    commit_comparison,
    decide,
    job_at,
    patch,
    proposal_at,
    retain_run,
    stop,
)
from .registry import BehaviorRegistry
from .replay import ReplayError
from .run_store import RunStore
from .util import content_hash

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


def _fail(message: str, *, status: HTTPStatus = HTTPStatus.CONFLICT) -> APIError:
    return APIError(status, "method_comparison_refused", message)


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


class MethodComparisonContext(Protocol):
    store: RunStore
    product_store: ProductStore
    detection_lab: DetectionLabService
    job_controller: RunJobController
    registry: BehaviorRegistry
    _provider_access: AIProviderAccess

    def _runtime_ai(self) -> AIConfig: ...
    def _job_completion_is_durably_settled(self, result: Mapping[str, Any]) -> bool: ...
    def prepare_replay(self, run_id: str, request: Mapping[str, Any]) -> Mapping[str, Any]: ...
    def submit_replay(
        self,
        run_id: str,
        request: Mapping[str, Any],
        *,
        _method_comparison: Mapping[str, Any] | None = None,
    ) -> Mapping[str, Any]: ...


class MethodComparisonJobs:
    def __init__(self, service: MethodComparisonContext) -> None:
        self.service = service
        self.store = service.product_store
        self.lab = service.detection_lab
        self.controller = service.job_controller

    def _provider(self, provider_id: str) -> AIProviderConfig:
        try:
            provider = self.service._runtime_ai().provider(provider_id)
        except ConfigError as exc:
            raise _fail("Selected provider is unavailable.") from exc
        if provider.kind is AIProviderKind.DETERMINISTIC:
            raise _fail("Select a configured model provider for this method operation.")
        return provider

    @staticmethod
    def _job_id(submission_id: str) -> str:
        return "job-" + uuid.UUID(submission_id).hex

    def _source(self, run_id: str) -> tuple[Mapping[str, Any], Mapping[str, Any], list[Any]]:
        run, records, observed = _source(self.lab, run_id)
        if not self.service.store.validate_bundle(run_id).get("valid"):
            raise _fail("Source run integrity validation failed.")
        return run, _source_binding(run, records, observed), observed

    def _options(
        self, run: Mapping[str, Any], selected_step_id: str | None = None
    ) -> list[Mapping[str, Any]]:
        scenario = ScenarioDefinition.from_mapping(run["scenario"])
        mode = ExecutionMode(run["mode"])
        scope: Mapping[str, Any] = {}
        if mode is ExecutionMode.EXECUTE:
            recorded_scope = run.get("authorized_target_scope")
            if not isinstance(recorded_scope, Mapping) or not recorded_scope:
                raise _fail("The source has no reconstructable canonical authorized scope.")
            scope = recorded_scope
        options: list[Mapping[str, Any]] = []
        for step in scenario.steps:
            if selected_step_id is not None and step.id != selected_step_id:
                continue
            alternatives = step.alternates
            collection_pair = {"sandbox.collection.records.v1", "sandbox.collection.archive.v1"}
            if step.behavior_id in collection_pair:
                alternatives = tuple(sorted(collection_pair - {step.behavior_id}))
            recorded_steps = run.get("steps", [])
            if (
                alternatives
                and isinstance(recorded_steps, list)
                and any(
                    isinstance(row, Mapping)
                    and row.get("step_id") == step.id
                    and row.get("execution_disposition") != "counterfactual"
                    and isinstance(row.get("behavior_id"), str)
                    and row["behavior_id"] != step.behavior_id
                    for row in recorded_steps
                )
            ):
                raise _fail(
                    "The recorded runtime method differs from the frozen scenario. Select a run whose recorded method matches its replay snapshot."
                )
            for alternate in alternatives:
                if alternate == step.behavior_id:
                    continue
                if alternate not in self.service.registry.compatible_behaviors(step.behavior_id):
                    continue
                payload: dict[str, Any] = {
                    "exact": False,
                    "swap_step_id": step.id,
                    "swap_behavior_id": alternate,
                    "autonomy": "off",
                }
                if mode is ExecutionMode.EXECUTE:
                    payload["target_scope"] = dict(scope)
                prepared = self.service.prepare_replay(str(run["run_id"]), payload)
                self._same_authority(run, prepared)
                problems = [
                    item
                    for item in prepared["preflight"].get("problems", [])
                    if item != "Explicit operator approval is required."
                ]
                if problems:
                    continue
                behavior = next(
                    value for value in self.service.registry.behaviors if value.id == alternate
                )
                options.append(
                    {
                        "option_id": "method-"
                        + content_hash({"step": step.id, "behavior": alternate})[7:27],
                        "step_id": step.id,
                        "behavior_from": step.behavior_id,
                        "behavior_to": alternate,
                        "title_from": self.service.registry.get_behavior(step.behavior_id).title,
                        "title": behavior.title,
                        "replay_preparation": prepared,
                    }
                )
                if len(options) > 8:
                    raise _fail("Select a step with at most eight compatible method alternatives.")
        return options

    @staticmethod
    def _same_authority(run: Mapping[str, Any], prepared: Mapping[str, Any]) -> None:
        lineage = prepared["lineage"]
        resolution = prepared["binding"]["resolution"]
        policy = run.get("policy")
        context = policy.get("approval_context") if isinstance(policy, Mapping) else None
        binding = context.get("collector_binding") if isinstance(context, Mapping) else None
        if not isinstance(binding, Mapping) or binding != resolution["collector_binding"]:
            raise _fail("The source has no matching explicit recorded collector binding.")
        if any(
            lineage.get(key) is not False
            for key in (
                "profile_changed",
                "catalog_authority_changed",
                "collector_authority_changed",
                "collector_settings_changed",
            )
        ):
            raise _fail("The original profile, catalog or collector authority cannot be preserved.")
        if run.get("mode") == "execute" and (
            resolution["target_scope"] != run.get("authorized_target_scope")
            or resolution["profile"] != run.get("profile")
        ):
            raise _fail("Prepared replay differs from the recorded scope or profile.")

    def context(self, run_id: str) -> Mapping[str, Any]:
        run, binding, _ = self._source(run_id)
        options = self._options(run)
        return {
            "schema_version": "bluefire.method-comparison-context.v1",
            "source_run": binding,
            "source_binding_digest": content_hash(binding),
            "options": [
                {key: value for key, value in option.items() if key != "replay_preparation"}
                for option in options
            ],
            "replay_extent": "full",
            "replay_autonomy": "off",
        }

    def submit(self, run_id: str, request: Mapping[str, Any]) -> Mapping[str, Any]:
        self.lab._fields(
            request,
            required={
                "submission_id",
                "source_binding_digest",
                "selected_step_id",
                "candidate_id",
                "candidate_resource_digest",
                "question",
                "source_case_role",
                "provider_id",
            },
            optional={"autonomy"},
            context="method comparison",
        )
        for name in ("source_binding_digest", "candidate_resource_digest"):
            if not isinstance(request[name], str) or not _DIGEST.fullmatch(request[name]):
                raise _fail(
                    "A valid selected-object digest is required.", status=HTTPStatus.BAD_REQUEST
                )
        for name in ("selected_step_id", "candidate_id", "provider_id"):
            _text(request[name], 200, name)
        if "autonomy" in request and request["autonomy"] not in ("off", "assist", "auto"):
            raise _fail("Autonomy must be off, assist or auto.", status=HTTPStatus.BAD_REQUEST)
        _text(request["question"], 1000, "Question")
        if request["source_case_role"] not in ("attack", "benign", "replay", "heldout"):
            raise _fail("Declare the source case role.", status=HTTPStatus.BAD_REQUEST)
        intent = content_hash({"source_run_id": run_id, "submitted_request": dict(request)})
        try:
            existing = self.store.get_job_submission(
                PROPOSE_KIND, submission_id=request["submission_id"], intent_digest=intent
            )
        except ProductStoreError as exc:
            raise _fail(str(exc), status=HTTPStatus.BAD_REQUEST) from exc
        if existing is not None:
            return {"job": existing}
        document: dict[str, Any] = {
            "schema_version": "bluefire.method-comparison-request.v1",
            "source_run_id": run_id,
            "submitted_request": dict(request),
            "replay_submission_id": str(
                uuid.uuid5(uuid.UUID(request["submission_id"]), "method-replay")
            ),
            "recovery_submission_id": str(
                uuid.uuid5(uuid.UUID(request["submission_id"]), "method-comparison")
            ),
        }
        try:
            autonomy = request.get("autonomy", self.service._runtime_ai().autonomy.value)
            if autonomy not in {"assist", "auto"}:
                raise _fail(
                    "Select Assist or Auto for this AI operation; Off sends no provider request."
                )
            provider = self._provider(request["provider_id"])
            run, binding, observed = self._source(run_id)
            if content_hash(binding) != request["source_binding_digest"]:
                raise _fail("The selected source changed.")
            observed_context(observed, provider)
            resource = self.lab._resource(request["candidate_id"])
            candidate = self.lab._candidate_from_resource(resource)
            if resource["digest"] != request["candidate_resource_digest"]:
                raise _fail("The selected detector changed.")
            # Parse/readiness and evidence bounds use the actual existing evaluator.
            build_run_evaluation(
                self.lab,
                candidate,
                resource,
                {
                    "run_id": run_id,
                    "question": request["question"],
                    "case_role": request["source_case_role"],
                },
            )
            options = self._options(run, request["selected_step_id"])
            if not options:
                raise _fail(
                    "This step has no compatible registered alternative in the same authority."
                )
            document.update(
                source_run=binding,
                detector={
                    "candidate_id": candidate.candidate_id,
                    "resource_digest": resource["digest"],
                    "definition_digest": candidate.definition_digest,
                    "target_language": candidate.target_language,
                },
                options=options,
                provider_id=provider.id,
                provider_binding_digest=content_hash(provider.to_dict()),
                autonomy=autonomy,
            )
        except (APIError, AIProviderError, ReplayError, ValueError) as exc:
            document["admission_error"] = {
                "code": "method_comparison_admission_refused",
                "message": (
                    exc.message
                    if isinstance(exc, APIError)
                    else "The source, provider context or compatible replay could not be validated."
                ),
            }
        try:
            return {
                "job": self.controller.submit(
                    PROPOSE_KIND,
                    document,
                    callback=self._propose,
                    submission_id=request["submission_id"],
                    intent_digest=intent,
                )
            }
        except JobRuntimeError as exc:
            raise _fail(
                "Capacity is unavailable; retry this exact submission.",
                status=HTTPStatus.SERVICE_UNAVAILABLE,
            ) from exc

    def _fresh(self, request: Mapping[str, Any]) -> list[Any]:
        _, binding, observed = self._source(request["source_run"]["run_id"])
        resource = self.lab._resource(request["detector"]["candidate_id"])
        if (
            binding != request["source_run"]
            or resource["digest"] != request["detector"]["resource_digest"]
        ):
            raise _fail("A selected object changed; prepare a new operation.")
        return observed

    def _propose(self, context: JobContext, request: Mapping[str, Any]) -> JobResult:
        try:
            if "admission_error" in request:
                raise _fail(request["admission_error"]["message"])
            provider = self._provider(request["provider_id"])
            if content_hash(provider.to_dict()) != request["provider_binding_digest"]:
                raise _fail("Provider configuration changed.")
            observed = self._fresh(request)
            context.checkpoint({"operation_phase": "choosing_method"})
            suggestion = suggest_method(
                config=provider,
                access=self.service._provider_access,
                context={
                    "source_run": request["source_run"],
                    "question": request["submitted_request"]["question"],
                    "detector": request["detector"],
                    "options": [
                        {key: value for key, value in option.items() if key != "replay_preparation"}
                        for option in request["options"]
                    ],
                    "observations": observed_context(observed, provider),
                },
                cancel_event=context.cancellation_event,
            )
            option = next(
                row for row in request["options"] if row["option_id"] == suggestion["option_id"]
            )
            self._fresh(request)
            proposal = {
                "schema_version": PROPOSAL_SCHEMA,
                **suggestion,
                "source_run": request["source_run"],
                "detector": request["detector"],
                "provider_binding_digest": request["provider_binding_digest"],
                "option": {
                    key: value for key, value in option.items() if key != "replay_preparation"
                },
                "replay_preparation": option["replay_preparation"],
                "sequence": [
                    "full_method_replay",
                    "evaluate_same_detector_on_both_runs",
                    "compare_runs",
                ],
                "replay_autonomy": "off",
            }
            prepared = option["replay_preparation"]
            proposal.update(
                scope=prepared["binding"]["resolution"]["target_scope"],
                profile=prepared["binding"]["resolution"]["profile"],
                replay_extent="full",
                changes={
                    "step_id": option["step_id"],
                    "behavior": {"from": option["behavior_from"], "to": option["behavior_to"]},
                    "runtime_autonomy": {"from": prepared["lineage"]["autonomy_from"], "to": "off"},
                },
                comparison_limitations=[
                    "The selected source informed the method choice; this exploratory comparison is not independent held-out validation.",
                    "Both reports evaluate the same saved detector; query matches do not establish deployed detection or prevention.",
                ],
            )
            proposal["proposal_digest"] = content_hash(proposal)
            context.checkpoint({"proposal": proposal, "operation_phase": "proposal_available"})
            if request["autonomy"] == "auto":
                decision = {
                    "proposal_digest": proposal["proposal_digest"],
                    "decision": "accept",
                    "reviewed_by": "bounded-auto-policy",
                }
                job = decide(self.store, context.job_id, decision, automatic=True)
                context.checkpoint()
                self._publish(job)
            return JobResult(progress={"operation_phase": "proposal_available"})
        except AIProviderCancelled as exc:
            raise JobCancelled("Method provider cancellation confirmed.") from exc
        except (APIError, AIProviderError, ProductStoreError) as exc:
            context.checkpoint(
                {
                    "operation_error": {
                        "code": "method_comparison_refused",
                        "message": (
                            exc.message
                            if isinstance(exc, APIError)
                            else "The method operation could not validate its retained context or provider response."
                        ),
                    }
                }
            )
            raise

    def decision(self, job_id: str, request: Mapping[str, Any]) -> Mapping[str, Any]:
        self.lab._fields(
            request,
            required={"proposal_digest", "decision", "reviewed_by"},
            optional=set(),
            context="method comparison decision",
        )
        if request["decision"] not in ("accept", "reject"):
            raise _fail("Decision must be accept or reject.", status=HTTPStatus.BAD_REQUEST)
        _text(request["reviewed_by"], 200, "Reviewer")
        try:
            job = decide(self.store, job_id, request)
            replay = self._publish(job) if request["decision"] == "accept" else None
            return {
                "proposal_job": self.store.get_job(job_id),
                "replay_job": replay,
                "decision": job["progress"]["decision"],
            }
        except ProductStoreError as exc:
            raise _fail(str(exc)) from exc
        except JobRuntimeError as exc:
            raise _fail(
                "Decision retained. Retry the same decision to publish its reserved replay.",
                status=HTTPStatus.SERVICE_UNAVAILABLE,
            ) from exc

    def _publish(self, job: Mapping[str, Any]) -> Mapping[str, Any]:
        proposal = proposal_at(job)
        prepared = proposal["replay_preparation"]
        body = {
            **prepared["replay_request"],
            "preparation_id": prepared["preparation_id"],
            "preparation_context": prepared["preparation_context"],
            "submission_id": job["request"]["replay_submission_id"],
        }
        binding = {"proposal_job_id": job["job_id"], "proposal_digest": proposal["proposal_digest"]}
        response = self.service.submit_replay(
            proposal["source_run"]["run_id"], body, _method_comparison=binding
        )
        replay = response["job"]
        with self.store._connection(write=True) as connection:
            parent = job_at(self.store, connection, job["job_id"])
            patch(connection, parent, {"replay_job_id": replay["job_id"]})
        if parent["progress"].get("stopped"):
            self._cancel_child(replay)
        return self.store.get_job(replay["job_id"])

    def before_replay(self, request: Mapping[str, Any]) -> None:
        binding = request["method_comparison"]
        parent = self.store.get_job(binding["proposal_job_id"])
        proposal = proposal_at(parent)
        if parent["progress"].get("stopped"):
            raise JobCancelled("Method operation was stopped before replay.")
        if (
            proposal["proposal_digest"] != binding["proposal_digest"]
            or parent["progress"].get("decision", {}).get("decision") != "accept"
        ):
            raise _fail("Method replay has no matching accepted proposal.")
        self._fresh(parent["request"])

    def after_replay(
        self, context: JobContext, request: Mapping[str, Any], run: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        parent_id = request["method_comparison"]["proposal_job_id"]
        _, binding, _ = self._source(str(run["run_id"]))
        retain_run(
            self.store, proposal_job_id=parent_id, replay_job_id=context.job_id, run_binding=binding
        )
        return self._finish_checked(context, parent_id)

    def _finish_checked(self, context: JobContext, parent_id: str) -> Mapping[str, Any]:
        try:
            return self._finish(context, parent_id)
        except (APIError, ProductStoreError) as exc:
            context.checkpoint(
                {
                    "operation_error": {
                        "code": "method_comparison_analysis_refused",
                        "message": (
                            exc.message
                            if isinstance(exc, APIError)
                            else "Comparison could not be retained. The finalized replay remains available; recovery never replays effects."
                        ),
                    }
                }
            )
            raise

    def _finish(self, context: JobContext, parent_id: str) -> Mapping[str, Any]:
        parent = self.store.get_job(parent_id)
        source = parent["request"]["source_run"]
        replay = parent["progress"]["replay_result"]
        _, actual, _ = self._source(replay["source"]["run_id"])
        if actual != replay["source"]:
            raise _fail("Retained replay evidence changed.")
        _, original, _ = self._source(source["run_id"])
        if original != source:
            raise _fail("Retained source evidence changed.")

        def build() -> tuple[list[Mapping[str, Any]], Mapping[str, Any]]:
            resource = self.lab._resource(parent["request"]["detector"]["candidate_id"])
            candidate = self.lab._candidate_from_resource(resource)
            body = parent["request"]["submitted_request"]
            reports = [
                build_run_evaluation(
                    self.lab,
                    candidate,
                    resource,
                    {"run_id": run_id, "question": body["question"], "case_role": role},
                )
                for run_id, role in (
                    (source["run_id"], body["source_case_role"]),
                    (actual["run_id"], "replay"),
                )
            ]
            return reports, compare_runs(self.service.store, [source["run_id"], actual["run_id"]])

        def check() -> None:
            if context.cancellation_event.is_set():
                raise JobCancelled("Comparison cancelled; the finalized replay is retained.")

        context.checkpoint({"operation_phase": "comparing_detections"})
        return commit_comparison(
            self.store,
            proposal_job_id=parent_id,
            application_job_id=context.job_id,
            build=build,
            check_cancelled=check,
        )

    def _recover(self, context: JobContext, request: Mapping[str, Any]) -> JobResult:
        receipt = self._finish_checked(context, request["proposal_job_id"])
        return JobResult(
            result_ref=receipt["child_run_id"],
            progress={"comparison": receipt},
            completion_confirmed=True,
        )

    def retry(self, job_id: str) -> Mapping[str, Any]:
        job = self.store.get_job(job_id)
        if job["state"] not in {"interrupted", "failed", "cancelled"}:
            raise _fail("Only interrupted or failed operation analysis can be recovered.")
        if job["kind"] == PROPOSE_KIND:
            if job["progress"].get("decision", {}).get("decision") == "accept":
                return self._retry_response(job, self._publish(job), "recover_publication")
            raise _fail(
                "This provider attempt has no accepted method. Review it or submit a new explicit request."
            )
        parent_id = job["request"].get("method_comparison", {}).get("proposal_job_id") or job[
            "request"
        ].get("proposal_job_id")
        parent = self.store.get_job(parent_id)
        replay_id = self._job_id(parent["request"]["replay_submission_id"])
        replay = self.store.get_job(replay_id)
        if replay["state"] not in {"completed", "failed", "interrupted", "cancelled"}:
            raise _fail("The replay must settle before comparison recovery.")
        run_id = replay.get("result_ref") or replay["progress"].get("run_id")
        if not isinstance(run_id, str):
            raise _fail(
                "No finalized replay receipt is known. Recover the original run; this operation will not replay effects."
            )
        run, binding, _ = self._source(run_id)
        if (
            run.get("replay", {}).get("source_run_id") != parent["request"]["source_run"]["run_id"]
            or run.get("scenario") != proposal_at(parent)["replay_preparation"]["scenario"]
        ):
            raise _fail("The known run is not the exact reviewed method replay.")
        if not self.service._job_completion_is_durably_settled(run):
            raise _fail("Replay cleanup must settle before comparison recovery.")
        retain_run(
            self.store, proposal_job_id=parent_id, replay_job_id=replay_id, run_binding=binding
        )
        recovery_id = (
            parent["request"]["recovery_submission_id"]
            if job["kind"] != RECOVER_KIND
            else str(
                uuid.uuid5(
                    uuid.UUID(job["request"]["_submission"]["submission_id"]), "comparison-retry"
                )
            )
        )
        request = {
            "proposal_job_id": parent_id,
            "replay_job_id": replay_id,
            "retry_of_job_id": job_id,
            "stop_generation": parent["progress"].get("stop_generation", 0),
        }
        try:
            existing = self.store.get_job(self._job_id(recovery_id))
        except ProductStoreError:
            existing = None
        if existing is not None:
            retained = {
                key: value for key, value in existing["request"].items() if key != "_submission"
            }
            if (
                existing["kind"] != RECOVER_KIND
                or any(
                    retained.get(key) != request[key]
                    for key in ("proposal_job_id", "replay_job_id", "retry_of_job_id")
                )
                or existing["request"].get("_submission", {}).get("intent_digest")
                != content_hash(retained)
            ):
                raise _fail("Comparison recovery identity has a different retained intent.")
            return self._retry_response(job, existing, "comparison_only")
        replacement = self.controller.submit(
            RECOVER_KIND,
            request,
            callback=self._recover,
            submission_id=recovery_id,
            intent_digest=content_hash(request),
        )
        with self.store._connection(write=True) as connection:
            current = job_at(self.store, connection, parent_id)
            patch(connection, current, {"comparison_recovery_job_id": replacement["job_id"]})
        if current["progress"].get("stop_generation", 0) != request["stop_generation"]:
            self._cancel_child(replacement)
        return self._retry_response(
            job, self.store.get_job(replacement["job_id"]), "comparison_only"
        )

    @staticmethod
    def _retry_response(
        source: Mapping[str, Any], job: Mapping[str, Any], operation_kind: str
    ) -> Mapping[str, Any]:
        return {
            "schema_version": "bluefire.job-retry.v1",
            "retry_of_job_id": source["job_id"],
            "source_job": source,
            "job": job,
            "approval_request": None,
            "preflight": None,
            "operation_kind": operation_kind,
        }

    def _cancel_child(self, child: Mapping[str, Any]) -> None:
        if child["state"] in {"completed", "failed", "cancelled", "interrupted"}:
            return
        try:
            self.controller.cancel(child["job_id"])
        except JobNotManaged:
            current = self.store.get_job(child["job_id"])
            if current["state"] == "queued":
                self.store.transition_job(child["job_id"], "cancelled")
            else:
                raise

    def cancel(self, job_id: str) -> Mapping[str, Any]:
        parent = stop(self.store, job_id)
        child_id = self._job_id(parent["request"]["replay_submission_id"])
        try:
            child = self.store.get_job(child_id)
        except ProductStoreError:
            child = None
        if child is not None:
            self._cancel_child(child)
        recovery_id = parent["progress"].get("comparison_recovery_job_id")
        if isinstance(recovery_id, str):
            self._cancel_child(self.store.get_job(recovery_id))
        if parent["state"] not in {"completed", "failed", "cancelled", "interrupted"}:
            try:
                self.controller.cancel(job_id)
            except JobRuntimeError:
                pass
        return self.store.get_job(job_id)
