"""One saved S3 exercise through existing jobs, immutable runs and explicit reviews."""

from __future__ import annotations

import hashlib
import uuid
from datetime import timedelta
from typing import Any, Mapping

from . import product_store_s3_access as records
from . import s3_access_results as results
from .evidence import EvidenceProvenance, EvidenceRecord
from .job_runtime import JobResult, JobRuntimeError, RunJobController
from .product_store import ProductStore
from .product_store_errors import ProductStoreError
from .run_store import RunStore
from .s3_access_contract import S3AccessError, S3AccessScope, digest, exact, timestamp
from .s3_access_executor import S3AccessExecutor, validate_execution
from .s3_access_policy import plan_hardening
from .s3_access_wire import REQUEST_SCHEMA, S3WorkerRequest
from .util import content_hash


class S3AccessJobs:
    def __init__(self, service, executor: S3AccessExecutor, *, clock=results.now):
        self.service = service
        self.store: ProductStore = service.product_store
        self.runs: RunStore = service.store
        self.controller: RunJobController = service.job_controller
        self.executor = executor
        self.clock = clock

    def _readiness(self, scope: S3AccessScope) -> dict[str, Any]:
        value = self.executor.readiness(scope)
        exact(
            value,
            {"available", "problem", "runner_profile_id", "worker_generation", "runtime_digest"},
            "S3 readiness",
        )
        if type(value["available"]) is not bool:
            raise S3AccessError("The runtime readiness response is invalid.")
        if value["available"]:
            if (
                value["problem"] is not None
                or not isinstance(value["runner_profile_id"], str)
                or not 1 <= len(value["runner_profile_id"]) <= 128
            ):
                raise S3AccessError("The runtime readiness binding is incomplete.")
            digest(value["worker_generation"])
            digest(value["runtime_digest"])
        return dict(value)

    def environments(self) -> Mapping[str, Any]:
        entries = self.executor.environments()
        if not isinstance(entries, list) or len(entries) > 32:
            raise S3AccessError("The enrolled environment inventory exceeds its bound.")
        rows: list[dict[str, Any]] = []
        for entry in entries:
            selected = results.environment(entry)
            scope = S3AccessScope.from_mapping(selected["scope"])
            runtime = self._readiness(scope)
            current = True
            try:
                scope.assert_current(clock=self.clock)
            except S3AccessError:
                current = False
            rows.append(
                {
                    "environment": selected,
                    "runtime": runtime,
                    "available": runtime["available"] and current,
                    "problem": (
                        None
                        if runtime["available"] and current
                        else "The exact enrolled scope, protected runtime and temporary access must be ready."
                    ),
                    "context_digest": content_hash({"environment": selected, "runtime": runtime}),
                }
            )
        if len({row["environment"]["environment_id"] for row in rows}) != len(rows):
            raise S3AccessError("The enrolled environment inventory is ambiguous.")
        return {
            "schema_version": "bluefire.s3-environments.v1",
            "environments": rows,
            "problem": (
                None
                if rows
                else "No S3 environment is enrolled. Account, roles, generated objects, protected runtime and finite spending authority are required."
            ),
        }

    def _selected(self, identifier: str) -> Mapping[str, Any]:
        matches: list[Mapping[str, Any]] = [
            row
            for row in self.environments()["environments"]
            if row["environment"]["environment_id"] == identifier
        ]
        if len(matches) != 1:
            raise S3AccessError("Select one available enrolled S3 environment.")
        return matches[0]

    def create(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        exact(request, {"submission_id", "environment_id", "context_digest"}, "S3 exercise request")
        identifier = results.submission(request["submission_id"])
        digest(request["context_digest"])
        intent = content_hash(request)
        old = self.store.get_job_submission(
            results.OWNER_KIND, submission_id=identifier, intent_digest=intent
        )
        if old is not None:
            return self.read(old["job_id"])
        selected = self._selected(request["environment_id"])
        if not selected["available"] or selected["context_digest"] != request["context_digest"]:
            raise S3AccessError("The enrolled environment changed or is not ready.")
        owner = records.create_owner(
            self.store,
            {
                "submitted_request": dict(request),
                "environment": selected["environment"],
                "runtime": selected["runtime"],
            },
            submission_id=identifier,
            intent_digest=intent,
        )
        return self.read(owner["job_id"])

    def _owner(self, identifier: str) -> Mapping[str, Any]:
        owner = self.store.get_job(results.job_id(identifier))
        if owner["kind"] != results.OWNER_KIND:
            raise S3AccessError("Select an exact saved S3 exercise.")
        results.environment(owner["request"]["environment"])
        return owner

    def _fresh(self, owner: Mapping[str, Any], phase: str) -> Mapping[str, Any]:
        selected = self._selected(owner["request"]["environment"]["environment_id"])
        if (
            not selected["available"]
            or selected["environment"] != owner["request"]["environment"]
            or selected["runtime"] != owner["request"]["runtime"]
        ):
            raise S3AccessError("The saved S3 enrollment or protected runtime changed.")
        results.assert_phase_current(
            S3AccessScope.from_mapping(selected["environment"]["scope"]), phase, self.clock()
        )
        if (
            phase in {"apply", "rollback"}
            and selected["environment"]["exclusive_writer_digest"] is None
        ):
            raise S3AccessError("Policy changes require the enrolled exclusive-writer premise.")
        return selected

    def list_exercises(self) -> Mapping[str, Any]:
        owners = records.list_owners(self.store)
        return {
            "schema_version": "bluefire.s3-exercise-list.v1",
            "truncated": len(owners) > 100,
            "exercises": [
                {
                    "workflow_job_id": row["job_id"],
                    "name": row["request"]["environment"]["display_name"],
                    "bucket": row["request"]["environment"]["scope"]["bucket"],
                    "policy_state": row["progress"]["policy_state"],
                    "updated_at": row["updated_at"],
                }
                for row in owners[:100]
            ],
        }

    def read(self, identifier: str) -> Mapping[str, Any]:
        owner = self._owner(identifier)
        history = []
        for row in owner["progress"]["operations"]:
            if row["outcome_digest"] != content_hash(
                {key: value for key, value in row.items() if key != "outcome_digest"}
            ):
                raise S3AccessError("Saved S3 outcome integrity is unavailable.")
            child = self.store.get_job(row["operation_job_id"])
            marker = child["request"]["s3_access"]
            if (
                marker["workflow_job_id"] != identifier
                or marker["phase"] != row["phase"]
                or row["review_digest"] != marker["review"]["review_digest"]
            ):
                raise S3AccessError("Saved S3 result lineage is invalid.")
            requests = records.validate_requests(owner, child["request"])
            if len(row["run_ids"]) != len(row["executions"]) or len(row["executions"]) > len(
                requests
            ):
                raise S3AccessError("Saved S3 result sequence is invalid.")
            for run_id, execution, request in zip(
                row["run_ids"], row["executions"], child["request"]["worker_requests"], strict=False
            ):
                checked = validate_execution(S3WorkerRequest.from_mapping(request), execution)
                run = self.runs.get_run(run_id)
                if (
                    not run.get("manifest")
                    or run.get("s3_execution") != checked
                    or run.get("s3_workflow_job_id") != identifier
                    or run.get("s3_operation_job_id") != child["job_id"]
                    or run.get("s3_request_digest") != S3WorkerRequest.from_mapping(request).digest
                ):
                    raise S3AccessError("An S3 run is unsealed or belongs to different saved work.")
            history.append({key: value for key, value in row.items() if key != "executions"})
        pending = owner["progress"].get("pending_operation")
        active = self.store.get_job(pending) if pending else None
        allowed = results.allowed_phases(owner)
        problem = None
        baseline = results.latest(owner, "baseline")
        if (
            not active
            and not owner["progress"]["stopped"]
            and baseline
            and baseline["outcome"]["state"] == "observed"
            and results.latest(owner, "apply") is None
            and not results.stage_affordable(owner, "apply")
        ):
            problem = "Remaining authority cannot cover the policy change, required fresh access checks and bounded recovery allowance. A new explicitly reviewed scope is required."
        current = []
        for phase in allowed:
            try:
                self._fresh(owner, phase)
            except (S3AccessError, ProductStoreError):
                continue
            current.append(phase)
        if allowed and not current:
            problem = (
                "The saved enrollment or runtime is unavailable. Retained results remain readable."
            )
        allowed = current
        return {
            "schema_version": "bluefire.s3-exercise.v1",
            "workflow_job_id": identifier,
            "context_digest": owner["request"]["submitted_request"]["context_digest"],
            "environment": owner["request"]["environment"],
            "revision": owner["progress"]["revision"],
            "policy_state": owner["progress"]["policy_state"],
            "stopped": owner["progress"]["stopped"],
            "operations": history,
            "active_job": active,
            "allowed_phases": allowed,
            "saved_result_recovery_available": bool(active and active["state"] in results.TERMINAL),
            "remaining": results.remaining(owner),
            "problem": problem,
            "audit": "not_collected",
            "resource_disposition": "retained",
            "independent_observations": 0,
            "live_outcome_verified": False,
        }

    def review(self, identifier: str, request: Mapping[str, Any]) -> Mapping[str, Any]:
        exact(request, {"phase"}, "S3 stage review")
        owner = self._owner(identifier)
        # Verify retained run integrity before using its baseline or change facts.
        self.read(identifier)
        phase = request["phase"]
        if phase not in results.allowed_phases(owner):
            raise S3AccessError("This S3 stage is unavailable or needs reconciliation.")
        self._fresh(owner, phase)
        return results.review_document(owner, phase)

    def submit(self, identifier: str, request: Mapping[str, Any]) -> Mapping[str, Any]:
        exact(
            request,
            {"submission_id", "phase", "review_digest", "reviewed_by"},
            "S3 stage submission",
        )
        submission = results.submission(request["submission_id"])
        reviewed_by = results.reviewer(request["reviewed_by"])
        intent = content_hash({"workflow_job_id": identifier, **request})
        old = self.store.get_job_submission(
            results.OPERATION_KIND, submission_id=submission, intent_digest=intent
        )
        if old is not None:
            return self.read(identifier)
        review = self.review(identifier, {"phase": request["phase"]})
        if review["review_digest"] != request["review_digest"]:
            raise S3AccessError("The exact S3 stage needs a fresh review.")
        owner = self._owner(identifier)
        operation_id = "job-" + uuid.UUID(submission).hex
        worker_requests = self._requests(owner, request["phase"], operation_id)
        marker = {
            "workflow_job_id": identifier,
            "operation_job_id": operation_id,
            "phase": request["phase"],
            "expected_revision": owner["progress"]["revision"],
            "review": review,
        }
        self.controller.submit(
            results.OPERATION_KIND,
            {
                "s3_access": marker,
                "submitted_request": {**request, "reviewed_by": reviewed_by},
                "worker_requests": [item.to_dict() for item in worker_requests],
            },
            submission_id=submission,
            intent_digest=intent,
            callback=self._execute,
        )
        return self.read(identifier)

    def _requests(self, owner, phase: str, operation_id: str) -> list[S3WorkerRequest]:
        selected, runtime = owner["request"]["environment"], owner["request"]["runtime"]
        scope = S3AccessScope.from_mapping(selected["scope"])
        change = plan_hardening(scope, selected["baseline_policy"])
        deadline = min(
            self.clock() + timedelta(seconds=selected["scope"]["limits"]["request_seconds"]),
            timestamp(selected["scope"]["expires_at"]),
        )
        return [
            S3WorkerRequest.from_mapping(
                {
                    "schema_version": REQUEST_SCHEMA,
                    "launch_id": uuid.uuid4().hex + uuid.uuid4().hex,
                    "request_id": hashlib.sha256(f"{operation_id}:{index}".encode()).hexdigest(),
                    "worker_generation": runtime["worker_generation"],
                    "runtime_digest": runtime["runtime_digest"],
                    "scope": scope.to_dict(),
                    "scope_digest": scope.digest,
                    "operation": operation,
                    "policy_change": (
                        change.to_dict()
                        if operation in {"apply_policy", "rollback_policy", "reconcile_policy"}
                        else None
                    ),
                    "exclusive_writer_digest": (
                        selected["exclusive_writer_digest"]
                        if operation in {"apply_policy", "rollback_policy"}
                        else None
                    ),
                    "deadline": deadline.isoformat().replace("+00:00", "Z"),
                    "max_sends": results.SEND_LIMITS[operation],
                }
            )
            for index, operation in enumerate(results.PHASES[phase])
        ]

    def _execute(self, context, document: Mapping[str, Any]) -> JobResult:
        marker = document["s3_access"]
        executions: list[dict[str, Any]] = []
        run_ids: list[str] = []
        try:
            for payload in document["worker_requests"]:
                owner = records.guard_execution(self.store, context.job_id)
                self._fresh(owner, marker["phase"])
                request = S3WorkerRequest.from_mapping(payload)
                request.assert_current(self.clock)
                context.checkpoint({"phase": marker["phase"]})
                handle = self.runs.create_run(
                    scenario={
                        "schema_version": "1.0",
                        "id": "bluefire.s3-access",
                        "title": "S3 access review",
                        "steps": [],
                    },
                    plan={"schema_version": "bluefire.s3-operation-plan.v1", "request": payload},
                    policy={
                        "scope_digest": payload["scope_digest"],
                        "review_digest": marker["review"]["review_digest"],
                    },
                    profile={"id": owner["request"]["runtime"]["runner_profile_id"]},
                )
                context.checkpoint(
                    {
                        "execution_started": True,
                        "current_run_id": handle.run_id,
                        "run_ids": [*run_ids, handle.run_id],
                    }
                )
                authorization = records.workflow_approval(owner, context.job_id, document, request)

                def before_dispatch(value, run_id=handle.run_id, original=request):
                    if context.cancellation_event.is_set():
                        raise S3AccessError("The original S3 task was stopped before dispatch.")
                    records.retain_original_task(
                        self.store, context.job_id, run_id, original, value
                    )

                execution = validate_execution(
                    request,
                    self.executor.execute(
                        request,
                        authorization=authorization,
                        cancellation_event=context.cancellation_event,
                        before_dispatch=before_dispatch,
                    ),
                )
                self._finalize_run(
                    handle.run_id, owner["job_id"], context.job_id, request, execution
                )
                executions.append(execution)
                run_ids.append(handle.run_id)
                if (
                    execution["cleanup"] != "verified"
                    or execution["result"] is None
                    or execution["result"]["outcome"] != "observed"
                ):
                    break
            saved = records.finish(self.store, context.job_id, executions, run_ids)
            return JobResult(
                result_ref=run_ids[-1] if run_ids else None,
                progress={"outcome_digest": saved["outcome_digest"]},
                completion_confirmed=True,
            )
        except BaseException:
            records.finish(self.store, context.job_id, executions, run_ids, failure=True)
            raise

    def _finalize_run(self, run_id, owner_id, operation_id, request, execution) -> None:
        execution = validate_execution(request, execution)
        with records.result_publication(self.store, operation_id, run_id, request, execution) as (
            owner,
            child,
        ):
            if owner["job_id"] != owner_id:
                raise S3AccessError("The original S3 result belongs to another exercise.")
            current = self.runs.get_run(run_id)
            if current.get("manifest"):
                if (
                    current.get("s3_workflow_job_id") != owner_id
                    or current.get("s3_operation_job_id") != operation_id
                    or current.get("s3_request_digest") != request.digest
                    or current.get("s3_execution") != execution
                ):
                    raise S3AccessError("The S3 run already has a different sealed result.")
                return
            self._assert_initial_run(owner, child, run_id, request, current)
            self._publish_run(run_id, owner_id, operation_id, request, execution)

    def _publish_run(self, run_id, owner_id, operation_id, request, execution) -> None:
        if execution["provenance"] == "synthetic":
            provenance = EvidenceProvenance.SYNTHETIC
        elif execution["dispatch"] == "not_started":
            provenance = EvidenceProvenance.CONTROL_BLOCKED
        elif execution["dispatch"] == "permit_issued" and execution["result"] is not None:
            provenance = EvidenceProvenance.EXECUTED
        else:
            provenance = EvidenceProvenance.UNKNOWN
        row = EvidenceRecord.create(
            run_id=run_id,
            step_id="s3-operation",
            behavior_id="cloud.s3.access-review.v1",
            action_id=request.to_dict()["operation"],
            provenance=provenance,
            producer="bluefire.s3-worker",
            content=execution,
            target_scope_ref=request.to_dict()["scope_digest"],
            limitations=(
                "Runner-reported control or attempt only; permits and debits do not prove completed sends or defensive effects.",
                "Admission or cancellation refusal is not defensive effectiveness. No independent observation or runtime-isolation claim.",
            ),
        )
        self.runs.append_event(
            run_id,
            "s3.execution.result",
            {"request_digest": request.digest, "cleanup": execution["cleanup"]},
        )
        self.runs.finalize(
            run_id,
            result={
                "schema_version": "1.0",
                "status": (
                    "completed"
                    if execution["result"] and execution["result"]["outcome"] == "observed"
                    else "failed"
                ),
                "mode": "simulate" if provenance is EvidenceProvenance.SYNTHETIC else "execute",
                "scenario_id": "bluefire.s3-access",
                "scenario_title": "S3 access review",
                "ai_enabled": False,
                "ai_proposals": [],
                "objective_reached": False,
                "objective": "Review scoped S3 access and preserve legitimate reads.",
                "steps": [
                    {
                        "step_id": "s3-operation",
                        "behavior_id": "cloud.s3.access-review.v1",
                        "action_id": request.to_dict()["operation"],
                        "status": (
                            "success"
                            if execution["result"] and execution["result"]["outcome"] == "observed"
                            else "failed"
                        ),
                        "evidence_ids": [row.evidence_id],
                    }
                ],
                "s3_workflow_job_id": owner_id,
                "s3_operation_job_id": operation_id,
                "s3_request_digest": request.digest,
                "s3_execution": execution,
                "cleanup": {
                    "status": execution["cleanup"],
                    "attempted": True,
                    "success": execution["cleanup"] == "verified",
                },
            },
            evidence=[row.to_dict()],
            detections=[],
        )

    def recover(self, identifier: str, request: Mapping[str, Any]) -> Mapping[str, Any]:
        """Adopt only authenticated original results; never dispatch or replay."""
        exact(request, set(), "S3 saved result recovery")
        owner = self._owner(identifier)
        pending = owner["progress"].get("pending_operation")
        if not pending:
            return self.read(identifier)
        child = self.store.get_job(pending)
        if child["state"] not in results.TERMINAL:
            raise S3AccessError(
                "Wait for the original operation to settle before recovering results."
            )
        requests = records.validate_requests(owner, child["request"])
        run_ids = child["progress"].get("run_ids", [])
        if (
            not isinstance(run_ids, list)
            or len(run_ids) > len(requests)
            or any(not isinstance(value, str) for value in run_ids)
            or len(set(run_ids)) != len(run_ids)
        ):
            raise S3AccessError("The original saved run sequence is unavailable.")
        executions = []
        for run_id, original in zip(run_ids, requests, strict=False):
            run = self.runs.get_run(run_id)
            if not run.get("manifest"):
                run = self._recover_original_run(owner, child, run_id, original, run)
            if (
                not run.get("manifest")
                or run.get("s3_workflow_job_id") != identifier
                or run.get("s3_operation_job_id") != pending
                or run.get("s3_request_digest") != original.digest
            ):
                raise S3AccessError(
                    "The original operation lacks a sealed result. Native cleanup remains unresolved."
                )
            executions.append(validate_execution(original, run.get("s3_execution")))
        if child["progress"].get("execution_started") and not executions:
            raise S3AccessError(
                "The original operation lacks its sealed result; no request was repeated."
            )
        records.finish(self.store, pending, executions, run_ids, failure=True)
        return self.read(identifier)

    def _recover_original_run(self, owner, child, run_id, request, run):
        retained = child["progress"].get("original_tasks", {})
        if not isinstance(retained, dict) or run_id not in retained:
            raise S3AccessError(
                "The original operation lacks a sealed result and its retained task identity."
            )
        original = records.original_task_context(owner, child, run_id, request, retained[run_id])
        self._assert_initial_run(owner, child, run_id, request, run)
        recovered = self.executor.recover_original(request, original)
        exact(recovered, {"status", "execution"}, "S3 original result recovery")
        if recovered["status"] != "finalized":
            raise S3AccessError(
                "The original task has no finalized result; cleanup remains unresolved."
            )
        execution = validate_execution(request, recovered["execution"])
        self._finalize_run(run_id, owner["job_id"], child["job_id"], request, execution)
        return self.runs.get_run(run_id)

    @staticmethod
    def _assert_initial_run(owner, child, run_id, request, run) -> None:
        events = run.get("events")
        if (
            not isinstance(events, list)
            or len(events) not in {1, 2}
            or events[0].get("event_type") != "run.created"
        ):
            raise S3AccessError("The unsealed S3 run has partial or unexpected publication.")
        initial = events[0].get("data")
        required = {"schema_version", "run_id", "created_at", "status", "replay"}
        if (
            not isinstance(initial, dict)
            or set(initial) not in (required, required | {"acceptance_binding"})
            or initial["schema_version"] != "1.0"
            or initial["run_id"] != run_id
            or initial["status"] != "created"
            or initial["replay"] is not None
        ):
            raise S3AccessError("The original S3 run creation metadata is invalid.")
        expected = dict(initial)
        if len(events) == 2:
            interruption = events[1]
            interrupted_at = run.get("interrupted_at")
            if (
                interruption.get("event_type") != "run.interrupted"
                or interruption.get("data") != {"reason": "restart_recovery"}
                or not isinstance(interrupted_at, str)
                or not (
                    timestamp(initial["created_at"])
                    <= timestamp(events[0]["timestamp"])
                    <= timestamp(interrupted_at)
                    <= timestamp(interruption["timestamp"])
                )
            ):
                raise S3AccessError("The S3 run lacks its exact startup interruption record.")
            expected.update(
                status="interrupted",
                interrupted_at=interrupted_at,
                recovery="No finalized manifest was present after restart.",
            )
        expected.update(
            scenario={
                "schema_version": "1.0",
                "id": "bluefire.s3-access",
                "title": "S3 access review",
                "steps": [],
            },
            plan={"schema_version": "bluefire.s3-operation-plan.v1", "request": request.to_dict()},
            policy={
                "scope_digest": request.to_dict()["scope_digest"],
                "review_digest": child["request"]["s3_access"]["review"]["review_digest"],
            },
            profile={"id": owner["request"]["runtime"]["runner_profile_id"]},
            evidence={"schema_version": "1.0", "records": []},
            detections={"schema_version": "1.0", "candidates": []},
            events=events,
        )
        if run != expected or timestamp(initial["created_at"]) > timestamp(events[0]["timestamp"]):
            raise S3AccessError("The unsealed S3 run differs from its original request.")

    def stop(self, identifier: str, request: Mapping[str, Any]) -> Mapping[str, Any]:
        exact(request, set(), "S3 stop request")
        pending = records.stop(self.store, results.job_id(identifier))
        if pending:
            try:
                self.controller.cancel(pending)
            except JobRuntimeError:
                pass
        return self.read(identifier)
