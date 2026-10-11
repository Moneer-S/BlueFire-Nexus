"""Saved finite AD workspace on the existing job controller and run bundle store.

Production admission defaults to unavailable without exact installed configuration.
Fixture executors exercise persistence without claiming Windows or domain execution.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any, Mapping

from . import ad_smb_results as results
from . import product_store_ad_smb as records
from .ad_smb_contract import AdSmbError, AdSmbScope, document, exact, timestamp
from .ad_smb_execution import (
    AdSmbExecutor,
    InstalledAdSmbExecutor,
    UnavailableAdSmbExecutor,
    configured_executor,
)
from .evidence import EvidenceProvenance, EvidenceRecord
from .job_runtime import JobResult, JobRuntimeError, RunJobController
from .product_store import ProductStore
from .run_store import RunStore
from .util import content_hash


class AdSmbJobs:
    def __init__(self, service, executor: AdSmbExecutor | None = None, *, clock=results.now):
        self.store: ProductStore = service.product_store
        self.runs: RunStore = service.store
        self.controller: RunJobController = service.job_controller
        self._executor = executor
        self._service = service
        self.clock = clock

    @property
    def executor(self) -> AdSmbExecutor:
        # Missing startup enrollment is not a permanent adapter selection.
        return self._executor if self._executor is not None else configured_executor(self._service)

    def environments(self) -> dict[str, Any]:
        executor = self.executor
        entries = executor.environments()
        if not isinstance(entries, list) or len(entries) > 16:
            raise AdSmbError("AD enrolled environment inventory exceeds its bound.")
        rows: list[dict[str, Any]] = []
        identities = set()
        for value in entries:
            selected = results.environment(value)
            identity = selected["environment_id"]
            if identity in identities:
                raise AdSmbError("AD enrolled environment identity is ambiguous.")
            identities.add(identity)
            scope = AdSmbScope.from_mapping(selected["scope"])
            ready = results.readiness(executor.readiness(scope))
            current = True
            try:
                scope.assert_current(self.clock)
            except AdSmbError:
                current = False
            rows.append(
                {
                    "environment": selected,
                    "readiness": ready,
                    "available": current and ready["available"],
                }
            )
        return {
            "environments": rows,
            "native_execution_available": any(
                row["available"] and row["environment"]["provenance"] != "synthetic_fixture"
                for row in rows
            ),
        }

    def _selected(self, identifier):
        selected = [
            row
            for row in self.environments()["environments"]
            if row["environment"]["environment_id"] == identifier
        ]
        if len(selected) != 1 or not selected[0]["available"]:
            raise AdSmbError(
                "This AD environment lacks current authenticated native prerequisites."
            )
        return selected[0]

    def create(self, request: Mapping[str, Any]) -> dict[str, Any]:
        row = document(request)
        exact(row, {"submission_id", "environment_id"}, "AD workspace request")
        key = results.submission(row.pop("submission_id"))
        intent = content_hash(row)
        old = self.store.get_job_submission(
            results.OWNER_KIND, submission_id=key, intent_digest=intent
        )
        if old is not None:
            return self.read(old["job_id"])
        selected = self._selected(row["environment_id"])
        owner = records.create_owner(
            self.store,
            {
                "environment": selected["environment"],
                "readiness": selected["readiness"],
                "submitted_request": row,
            },
            submission_id=key,
            intent_digest=intent,
        )
        return self.read(owner["job_id"])

    def _owner(self, identifier):
        with self.store._connection() as connection:
            return records.owner_at(self.store, connection, identifier)

    def read(self, identifier) -> dict[str, Any]:
        owner = self._owner(identifier)
        executor = self.executor
        return {
            "workflow": owner,
            "allowed_phases": results.allowed_phases(owner),
            "remaining": results.remaining(owner),
            "effective_access_claim": False,
            "execution_integration": (
                "unavailable"
                if isinstance(executor, UnavailableAdSmbExecutor)
                else (
                    "configured_admission"
                    if isinstance(executor, InstalledAdSmbExecutor)
                    else "injected_adapter"
                )
            ),
        }

    def list(self) -> dict[str, Any]:
        return {"workflows": [self.read(row["job_id"]) for row in records.list_owners(self.store)]}

    def review(self, identifier, phase) -> dict[str, Any]:
        owner = self._owner(identifier)
        self._current(owner, phase)
        return results.review_document(owner, phase)

    def _current(self, owner, phase):
        selected = self._selected(owner["request"]["environment"]["environment_id"])
        if (
            selected["environment"] != owner["request"]["environment"]
            or selected["readiness"] != owner["request"]["readiness"]
        ):
            raise AdSmbError(
                "AD enrollment or native admission changed after saving the workspace."
            )
        results.phase_current(
            AdSmbScope.from_mapping(selected["environment"]["scope"]), phase, self.clock()
        )

    def submit(self, identifier, request: Mapping[str, Any]) -> Mapping[str, Any]:
        row = document(request)
        exact(row, {"submission_id", "phase", "review_digest", "reviewed_by"}, "AD reviewed stage")
        key = results.submission(row.pop("submission_id"))
        submitted = {"workflow_job_id": results.job_id(identifier), **row}
        intent = content_hash(submitted)
        old = self.store.get_job_submission(
            results.OPERATION_KIND, submission_id=key, intent_digest=intent
        )
        if old is not None:
            return old
        owner = self._owner(identifier)
        self._current(owner, row["phase"])
        review = results.review_document(owner, row["phase"])
        if review["review_digest"] != row["review_digest"]:
            raise AdSmbError("Review the changed AD stage before submitting it.")
        operation_id, _binding = self.store._job_submission_binding(key, intent)
        clock = self.clock()
        scope = owner["request"]["environment"]["scope"]
        deadline = min(
            clock + timedelta(seconds=scope["limits"]["operation_seconds"]),
            results.phase_deadline(AdSmbScope.from_mapping(scope), row["phase"]),
        )
        requests = [
            results.request_for(
                owner,
                row["phase"],
                operation_id,
                index,
                clock.isoformat(),
                deadline.isoformat(),
                review,
                row["reviewed_by"],
            )
            for index in range(len(results.PHASES[row["phase"]]))
        ]
        payload = {
            "submitted_request": submitted,
            "requests": requests,
            "ad_smb": {
                "workflow_job_id": identifier,
                "operation_job_id": operation_id,
                "phase": row["phase"],
                "prior_progress": owner["progress"],
                "review": review,
            },
        }
        return self.controller.submit(
            results.OPERATION_KIND,
            payload,
            callback=self._execute,
            submission_id=key,
            intent_digest=intent,
            submission_factory=lambda: records.reserve_operation(
                self.store, payload, submission_id=key, intent_digest=intent
            ),
        )

    def stop(self, identifier: str) -> dict[str, Any]:
        pending = records.stop(self.store, identifier)
        if pending:
            try:
                self.controller.cancel(pending)
            except JobRuntimeError:
                pass
        return self.read(identifier)

    @staticmethod
    def _documents(owner, child):
        return {
            "scenario.json": {
                "schema_version": "1.0",
                "scenario_id": "bluefire.ad-smb-access",
                "title": "AD share access review",
                "ad_workflow_job_id": owner["job_id"],
            },
            "plan.json": {
                "ad_review": child["request"]["ad_smb"]["review"],
                "requests": child["request"]["requests"],
            },
            "policy.json": {"scope": owner["request"]["environment"]["scope"]},
            "profile.json": {
                "environment": owner["request"]["environment"],
                "readiness": owner["request"]["readiness"],
            },
        }

    def _execute(self, context, payload):
        owner, child = records.active(self.store, context.job_id)
        docs = self._documents(owner, child)
        handle = self.runs.create_run(
            scenario=docs["scenario.json"],
            plan=docs["plan.json"],
            policy=docs["policy.json"],
            profile=docs["profile.json"],
        )
        initial = {
            "result": self.runs.read_json(handle.run_id, "result.json"),
            "events": self.runs.read_events(handle.run_id),
        }
        records.retain_run(self.store, context.job_id, handle.run_id, initial)
        for index, request in enumerate(payload["requests"]):
            context.checkpoint()
            owner, _child = records.active(self.store, context.job_id)
            self._current(owner, request["phase"])
            if self.clock() >= timestamp(request["deadline"]):
                raise AdSmbError("The saved AD operation deadline ended before the next step.")
            execution = self.executor.execute(
                request,
                cancellation_event=context.cancellation_event,
                before_dispatch=lambda original, i=index, saved=request: self._before_dispatch(
                    context, i, saved, original
                ),
            )
            records.record_terminal(self.store, context.job_id, index, execution)
            checked = results.validate_execution(request, execution)
            if (
                checked["dispatch"] != "attempted"
                or checked["cleanup"] != "verified"
                or checked["observation"] is None
            ):
                break
        outcome = records.finish(self.store, context.job_id, self._publish)
        return JobResult(
            result_ref=handle.run_id, progress={"ad_outcome": outcome}, completion_confirmed=True
        )

    def _before_dispatch(self, context, index, request, original):
        context.checkpoint()
        owner, _child = records.active(self.store, context.job_id)
        self._current(owner, request["phase"])
        if self.clock() >= timestamp(request["deadline"]):
            raise AdSmbError("The original AD deadline ended before native dispatch.")
        records.retain_original(self.store, context.job_id, index, original)

    def recover(self, identifier) -> dict[str, Any]:
        """Read only saved original contexts, without discovery, credentials or dispatch."""
        owner = self._owner(identifier)
        pending = owner["progress"]["pending_operation"]
        if pending is None:
            return self.read(identifier)
        owner, child = records.active(self.store, pending)
        if child["state"] not in results.TERMINAL:
            raise AdSmbError("Wait for the original local AD operation to settle.")
        if child["progress"]["run_id"] is None:
            raise AdSmbError("Original AD run identity was not retained; no replay is allowed.")
        for index, task in enumerate(child["progress"]["tasks"]):
            if task["execution"] is not None or task["recovery"] is not None:
                continue
            request = child["request"]["requests"][index]
            original = results.original_context(request, task["context"])
            recovered = document(self.executor.recover_original(request, original))
            exact(recovered, {"status", "execution"}, "AD original result recovery")
            if recovered["status"] != "terminal" or recovered["execution"] is None:
                raise AdSmbError(
                    "The original AD terminal remains unavailable; no new work was sent."
                )
            records.record_recovery(self.store, pending, index, original, recovered["execution"])
        records.finish(self.store, pending, self._publish)
        return self.read(identifier)

    def _expected_final(self, owner, child, executions, outcome):
        run_id = child["progress"]["run_id"]
        evidence = []
        for request, execution in zip(child["request"]["requests"], executions, strict=False):
            provenance = (
                EvidenceProvenance.SYNTHETIC
                if execution["provenance"] == "synthetic_fixture"
                else (
                    EvidenceProvenance.CONTROL_BLOCKED
                    if execution["dispatch"] == "not_started"
                    else (
                        EvidenceProvenance.EXECUTED
                        if execution["dispatch"] == "attempted"
                        and execution["observation"] is not None
                        else EvidenceProvenance.UNKNOWN
                    )
                )
            )
            evidence.append(
                EvidenceRecord.create(
                    run_id=run_id,
                    step_id=request["step"],
                    behavior_id="identity.ad.smb_access.v1",
                    action_id=results.ACTION,
                    provenance=provenance,
                    producer="bluefire.ad-smb-adapter",
                    content=execution,
                    target_scope_ref=request["scope_digest"],
                    timestamp=child["created_at"],
                    limitations=(
                        "Saved runner or fixture projection only; no authenticated remote principal, independent audit or effective-access claim.",
                        "Local token and LUID do not identify a fresh server logon; remote session closure remains unknown.",
                        "Record timestamp is the job creation time, not a native observation time.",
                    ),
                ).to_dict()
            )
        initial = child["progress"]["initial_run"]["result"]
        final = {
            "schema_version": "1.0",
            "run_id": run_id,
            "created_at": initial["created_at"],
            "status": "completed" if outcome["state"] == "complete" else "failed",
            "mode": (
                "simulate"
                if owner["request"]["environment"]["provenance"] == "synthetic_fixture"
                else "execute"
            ),
            "scenario_id": "bluefire.ad-smb-access",
            "scenario_title": "AD share access review",
            "ai_enabled": False,
            "ai_proposals": [],
            "objective_reached": False,
            "objective": "Review exact share access and preserve legitimate reads.",
            "ad_workflow_job_id": owner["job_id"],
            "ad_operation_job_id": child["job_id"],
            "ad_outcome": outcome,
            "ad_executions": executions,
            "cleanup": {"status": outcome["cleanup"], "success": outcome["cleanup"] == "verified"},
            "steps": [
                {
                    "step_id": request["step"],
                    "behavior_id": "identity.ad.smb_access.v1",
                    "action_id": results.ACTION,
                    "status": "success" if outcome["state"] == "complete" else "failed",
                    "evidence_ids": [row["evidence_id"]],
                }
                for request, row in zip(child["request"]["requests"], evidence, strict=False)
            ],
        }
        if "acceptance_binding" in initial:
            final["acceptance_binding"] = initial["acceptance_binding"]
        return final, evidence

    def _publish(self, owner, child, executions, outcome):
        run_id = child["progress"]["run_id"]
        path = self.runs._run_path(run_id, must_exist=True)
        docs = self._documents(owner, child)
        required = {*docs, "result.json", "evidence.json", "detections.json", "events.jsonl"}
        sealed = (path / "manifest.json").exists()
        if {item.name for item in path.iterdir()} != required | (
            {"manifest.json"} if sealed else set()
        ):
            raise AdSmbError("AD original run contains unreviewed files or an incomplete snapshot.")
        if any(self.runs.read_json(run_id, key) != value for key, value in docs.items()):
            raise AdSmbError("AD original run snapshots changed before publication.")
        final, evidence = self._expected_final(owner, child, executions, outcome)
        actual = dict(self.runs.read_json(run_id, "result.json"))
        events = self.runs.read_events(run_id)
        initial = child["progress"]["initial_run"]
        prefix = initial["events"]
        if len(prefix) != 1 or events[:1] != prefix:
            raise AdSmbError("AD original run creation evidence changed.")
        tail = events[1:]
        if tail and tail[0]["event_type"] == "run.interrupted":
            if tail[0]["data"] != {"reason": "restart_recovery"}:
                raise AdSmbError("AD restart evidence is not the exact ordinary recovery event.")
            tail = tail[1:]
        if sealed:
            finalized = actual.pop("finalized_at", None)
            timestamp(finalized)
            if (
                not self.runs.validate_bundle(run_id)["valid"]
                or actual != final
                or set(self.runs.read_json(run_id, "manifest.json")["files"]) != required
                or self.runs.read_json(run_id, "evidence.json")
                != {"schema_version": "1.0", "records": evidence}
                or self.runs.read_json(run_id, "detections.json")
                != {"schema_version": "1.0", "candidates": []}
                or len(tail) != 1
                or tail[0]["event_type"] != "run.finalized"
                or tail[0]["data"] != {**final, "finalized_at": finalized}
            ):
                raise AdSmbError("AD sealed run differs from its exact original terminal evidence.")
            return
        expected_initial = dict(initial["result"])
        if len(events) == 2 and events[-1]["event_type"] == "run.interrupted":
            interrupted = actual.get("interrupted_at")
            timestamp(interrupted)
            expected_initial.update(
                status="interrupted",
                interrupted_at=interrupted,
                recovery="No finalized manifest was present after restart.",
            )
        if (
            tail
            or actual != expected_initial
            or self.runs.read_json(run_id, "evidence.json")
            != {"schema_version": "1.0", "records": []}
            or self.runs.read_json(run_id, "detections.json")
            != {"schema_version": "1.0", "candidates": []}
        ):
            raise AdSmbError("AD partial or changed run publication is retained, not overwritten.")
        self.runs.finalize(run_id, result=final, evidence=evidence, detections=[])
        # Validate the resulting sealed bytes before releasing the database reservation.
        self._publish(owner, child, executions, outcome)
