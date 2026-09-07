"""Compose native preparation, one ordinary run, and retained evidence inspection."""

from __future__ import annotations

from http import HTTPStatus
from typing import Any, Mapping

from . import product_store_assistance_run as records
from .ai_run_inspection import inspect
from .ai_wire import AIProviderCancelled
from .application_errors import APIError
from .assistance_run_context import INSPECT_KIND, KIND, context, selection
from .assistance_run_inspection import source, verify_lineage
from .assistance_run_protocol import AssistanceRunService
from .config import AIProviderConfig, AIProviderKind, ConfigError
from .job_runtime import JobCancelled, JobContext, JobResult, JobRuntimeError
from .product_store_assistance import job_at, patch, require_active
from .product_store_errors import ProductStoreError
from .util import content_hash

TERMINAL = {"completed", "failed", "cancelled", "interrupted"}


def fail(message: str) -> APIError:
    return APIError(HTTPStatus.CONFLICT, "assistance_run_refused", message)


class AssistanceRunJobs:
    def __init__(self, service: AssistanceRunService) -> None:
        self.service = service
        self.store = service.product_store
        self.controller = service.job_controller

    def context(self, selected: Mapping[str, Any]) -> Mapping[str, Any]:
        return context(self.service, selected)

    def _job(self, job_id: str) -> Mapping[str, Any]:
        try:
            job = self.store.get_job(job_id)
        except ProductStoreError as exc:
            raise APIError(
                HTTPStatus.NOT_FOUND,
                "assistance_run_not_found",
                "The native run preparation was not found.",
            ) from exc
        if job["kind"] != KIND:
            raise fail("The selected job is not a native run preparation.")
        return job

    def _fresh(self, job: Mapping[str, Any]) -> AIProviderConfig:
        request = job["request"]
        if self.context(request["submitted_request"]["selection"]) != request["context"]:
            raise fail(
                "The accepted graph or native run configuration changed. Review a new context."
            )
        provider = self.service._runtime_ai().provider(request["submitted_request"]["provider_id"])
        if (
            provider.kind is AIProviderKind.DETERMINISTIC
            or content_hash(provider.to_dict()) != request["provider_binding_digest"]
        ):
            raise fail("The explicitly selected analysis provider changed or is unavailable.")
        return provider

    def submit(
        self, request: Mapping[str, Any], *, _assistance_turn: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        if set(request) != {
            "submission_id",
            "selection",
            "context_digest",
            "message",
            "autonomy",
            "provider_id",
        }:
            raise fail("Native run preparation fields are invalid.")
        selection(request["selection"])
        if request["autonomy"] not in {"assist", "auto"}:
            raise fail("Off cannot create a run assistance operation.")
        intent = content_hash(dict(request))
        existing = self.store.get_job_submission(
            KIND, submission_id=request["submission_id"], intent_digest=intent
        )
        if existing is not None:
            return self.read(existing["job_id"])
        current = self.context(request["selection"])
        if current["context_digest"] != request["context_digest"]:
            raise fail("The selected run context changed.")
        provider = self.service._runtime_ai().provider(request["provider_id"])
        if provider.kind is AIProviderKind.DETERMINISTIC:
            raise fail("Select an explicit analysis provider.")
        document = {
            "submitted_request": dict(request),
            "context_digest": request["context_digest"],
            "context": current,
            "provider_binding_digest": content_hash(provider.to_dict()),
            "assistance_turn": dict(_assistance_turn),
        }
        job = self.controller.submit(
            KIND,
            document,
            callback=self._prepare,
            submission_id=request["submission_id"],
            intent_digest=intent,
        )
        return self.read(job["job_id"])

    def _prepare(self, ctx: JobContext, request: Mapping[str, Any]) -> JobResult:
        try:
            return self._prepare_current(ctx, request)
        except (APIError, ConfigError, ProductStoreError) as exc:
            self._retain_preflight_refusal(ctx, request, exc)
            raise

    def _retain_preflight_refusal(
        self,
        ctx: JobContext,
        request: Mapping[str, Any],
        error: Exception,
        *,
        report: Mapping[str, Any] | None = None,
        run_request: Mapping[str, Any] | None = None,
    ) -> None:
        # APIError is the explicit safe HTTP boundary. Never copy arbitrary
        # exception text, nested details, provider payloads or a traceback.
        code = "run_context_refused"
        message = "The selected run context is unavailable or changed. Review its saved graph and native settings."
        if isinstance(error, APIError):
            code, message = error.code, error.message
        elif isinstance(error, ConfigError):
            code = "run_configuration_unavailable"
            message = "The selected runtime configuration is unavailable. Review the provider and runner settings."
        with (
            self.service._runtime_configuration_lock,
            self.store._connection(write=True) as connection,
        ):
            job = job_at(self.store, connection, ctx.job_id)
            if ctx.cancellation_event.is_set():
                raise JobCancelled("Native run preparation stopped.")
            require_active(self.store, connection, job)
            if job["progress"].get("stopped"):
                raise JobCancelled("Native run preparation stopped.")
            if "preflight_refusal" in job["progress"] or "preparation" in job["progress"]:
                return
            patch(
                connection,
                job,
                {
                    "preflight_refusal": {
                        "code": code,
                        "message": message,
                        "native_path": "/runs",
                        "context_digest": request["context_digest"],
                        "run_request_digest": content_hash(run_request)
                        if run_request is not None
                        else None,
                        "preflight": report,
                    }
                },
            )

    def _prepare_current(self, ctx: JobContext, request: Mapping[str, Any]) -> JobResult:
        ctx.checkpoint()
        self._fresh(self._job(ctx.job_id))
        selected = request["submitted_request"]["selection"]
        application = selected["application"]
        scenario = self.service.scenario_version(
            application["scenario_id"], version=application["version"]
        )["scenario"]["document"]
        run_request = {"scenario": scenario, **selected["run_intent"]}
        report = self.service.preflight(run_request)
        problems = [
            item
            for item in report.get("problems", [])
            if not (
                run_request["mode"] == "execute"
                and item == "Explicit operator approval is required."
            )
        ]
        if problems:
            error = APIError(
                HTTPStatus.CONFLICT,
                "run_preflight_refused",
                "Native run preflight is not ready. Check its findings and the selected runner and run settings.",
            )
            self._retain_preflight_refusal(
                ctx, request, error, report=report, run_request=run_request
            )
            raise error
        prepared = {
            "schema_version": "bluefire.assistance-run-preparation.v1",
            "context_digest": request["context_digest"],
            "selection": selected,
            "scenario": scenario,
            "run_request": run_request,
            "preflight": report,
            "approval_created": False,
            "effects_started": False,
        }
        prepared["preparation_digest"] = content_hash(prepared)
        with (
            self.service._runtime_configuration_lock,
            self.store._connection(write=True) as connection,
        ):
            job = job_at(self.store, connection, ctx.job_id)
            self._fresh(job)
            require_active(self.store, connection, job)
            if ctx.cancellation_event.is_set() or job["progress"].get("stopped"):
                raise JobCancelled("Native run preparation stopped.")
            patch(connection, job, {"preparation": prepared})
        ctx.checkpoint()
        if request["submitted_request"]["autonomy"] == "auto":
            records.decide(
                self.store,
                ctx.job_id,
                {"decision": "policy", "preparation_digest": prepared["preparation_digest"]},
            )
            self.advance(ctx.job_id)
        return JobResult()

    def review(self, job_id: str, decision: Mapping[str, Any]) -> Mapping[str, Any]:
        if set(decision) != {"decision", "preparation_digest"} or decision["decision"] not in {
            "accept",
            "reject",
        }:
            raise fail(
                "Native review requires an exact preparation and explicit accept or reject decision."
            )
        job = self._job(job_id)
        previous = job["progress"].get("decision")
        if previous is not None:
            if previous != decision:
                raise fail("This preparation already has another native decision.")
            if self._nested(job, "run_job_id", "scenario.run") is not None:
                return self.read(job_id)
        else:
            with self.service._runtime_configuration_lock:
                self._fresh(job)
                records.decide(self.store, job_id, decision)
        if decision["decision"] == "accept":
            current = self._job(job_id)
            with self.store._connection() as connection:
                try:
                    require_active(self.store, connection, current)
                except ProductStoreError:
                    return self.read(job_id)
            self.advance(job_id)
        return self.read(job_id)

    def _nested(
        self, operation: Mapping[str, Any], key: str, kind: str
    ) -> Mapping[str, Any] | None:
        identifier = operation["progress"].get(key)
        if identifier is None:
            return None
        with self.store._connection() as connection:
            row = connection.execute("SELECT * FROM jobs WHERE job_id=?", (identifier,)).fetchone()
            if row is None:
                return None
            job = self.store._job_from_row(row)
        records.nested_binding(operation, job, kind)
        return job

    def advance(self, job_id: str, *, retry_inspection: bool = False) -> None:
        job = self._job(job_id)
        if job["progress"].get("stopped"):
            return
        with self.store._connection() as connection:
            require_active(self.store, connection, job)
        if self.read(job_id)["result"] is not None:
            return
        prepared = records.preparation(job)
        decision = job["progress"].get("decision")
        if prepared is None or not decision or decision["decision"] == "reject":
            return
        run_job = self._nested(job, "run_job_id", "scenario.run")
        if run_job is None:
            self._fresh(job)
            self.service.submit_run(
                {"submission_id": job["progress"]["run_submission_id"], **prepared["run_request"]},
                _assistance_run={
                    "operation_job_id": job_id,
                    "preparation_digest": prepared["preparation_digest"],
                },
            )
            return
        if not job["progress"].get("run_id"):
            run_id = run_job.get("result_ref")
            if not isinstance(run_id, str) or run_job["state"] not in TERMINAL:
                return
            run = self.service.store.get_run(run_id)
            self.after_run(run_job["job_id"], run_job["request"], run)
            return
        self._start_inspection(job_id, retry=retry_inspection)

    def before_run(self, request: Mapping[str, Any]) -> None:
        binding = request.get("assistance_run")
        if binding is None:
            return
        with self.service._runtime_configuration_lock, self.store._connection() as connection:
            operation = self._job(binding["operation_job_id"])
            self._fresh(operation)
            records.publication_guard(self.store, connection, "scenario.run", request)

    def after_run(
        self, run_job_id: str, request: Mapping[str, Any], result: Mapping[str, Any]
    ) -> None:
        binding = request.get("assistance_run")
        if binding is None:
            return
        operation = self._job(binding["operation_job_id"])
        prepared = records.preparation(operation)
        run = self.service.store.get_run(result["run_id"])
        if prepared is None or operation["progress"].get("run_job_id") != run_job_id:
            raise ProductStoreError("Run result does not match its native preparation.")
        changes = verify_lineage(self.service, operation, run)
        previous_ref = self.store.get_job(run_job_id).get("result_ref")
        allowed_refs = {
            None,
            run["run_id"],
            *(
                self.store.get_ai_proposal_review(identifier)["source_run_id"]
                for identifier in changes
            ),
        }
        if previous_ref not in allowed_refs:
            raise ProductStoreError("Native run previously linked an unrelated result.")
        records.bind_result(
            self.store,
            operation["job_id"],
            run_job_id,
            run["run_id"],
            run["manifest"]["bundle_hash"],
            expected_result_ref=previous_ref,
        )
        try:
            self._start_inspection(operation["job_id"], retry=False)
        except (APIError, ProductStoreError, ConfigError, JobRuntimeError):
            # The actual run remains bound even if analysis admission is unavailable.
            pass

    def _start_inspection(self, job_id: str, *, retry: bool) -> None:
        with self.service._runtime_configuration_lock:
            job = self._job(job_id)
            if job["progress"].get("stopped"):
                return
            provider = self._fresh(job)
            selected = source(self.service, job)
            job = records.reserve_inspection(self.store, job_id, retry=retry)
            prepared = records.preparation(job)
            if prepared is None:
                raise ProductStoreError("Inspection has no accepted native preparation.")
            document = {
                "assistance_run": {
                    "operation_job_id": job_id,
                    "preparation_digest": prepared["preparation_digest"],
                },
                "run_id": job["progress"]["run_id"],
                "run_digest": selected["run_digest"],
                "provider_id": provider.id,
                "provider_binding_digest": job["request"]["provider_binding_digest"],
                "message": job["request"]["submitted_request"]["message"],
            }
            self.controller.submit(
                INSPECT_KIND,
                document,
                callback=self._inspect,
                submission_id=job["progress"]["inspection_submission_id"],
                intent_digest=content_hash(document),
            )

    def _inspect(self, ctx: JobContext, request: Mapping[str, Any]) -> JobResult:
        ctx.checkpoint()
        operation = self._job(request["assistance_run"]["operation_job_id"])
        config = self._fresh(operation)
        selected = source(self.service, operation)
        if selected["run_digest"] != request["run_digest"]:
            raise ProductStoreError("Inspection source changed.")
        try:
            report = inspect(
                selected,
                config=config,
                access=self.service._provider_access,
                cancel=ctx.cancellation_event,
                objective=request["message"],
            )
        except AIProviderCancelled as exc:
            raise JobCancelled("Evidence inspection cancelled.") from exc
        values = {"inspection": report, "inspection_digest": content_hash(report)}
        with (
            self.service._runtime_configuration_lock,
            self.store._connection(write=True) as connection,
        ):
            job = job_at(self.store, connection, ctx.job_id)
            self._fresh(operation)
            records.publication_guard(self.store, connection, INSPECT_KIND, job["request"])
            if ctx.cancellation_event.is_set():
                raise JobCancelled("Evidence inspection stopped before retention.")
            patch(connection, job, values)
        return JobResult(progress=values)

    def read(self, job_id: str) -> Mapping[str, Any]:
        job = self._job(job_id)
        prepared = records.preparation(job)
        decision = job["progress"].get("decision")
        run_job = self._nested(job, "run_job_id", "scenario.run")
        inspection_job = self._nested(job, "inspection_job_id", INSPECT_KIND)
        inspection = inspection_job["progress"].get("inspection") if inspection_job else None
        result = None
        if inspection is not None:
            if inspection_job is None or prepared is None:
                raise ProductStoreError("Retained inspection has no exact preparation.")
            if (
                inspection_job["progress"].get("inspection_digest") != content_hash(inspection)
                or inspection["run_id"] != job["progress"].get("run_id")
                or inspection["run_digest"] != job["progress"].get("run_digest")
            ):
                raise ProductStoreError("Retained inspection differs from its run source.")
            selected = source(self.service, job)
            if inspection["observed_records"] != len(selected["observed"]) or inspection[
                "total_records"
            ] != len(selected["records"]):
                raise ProductStoreError("Retained inspection has different evidence counts.")
            if (
                run_job
                and run_job["state"] in TERMINAL
                and inspection_job["state"] in {"completed", "interrupted"}
            ):
                app = prepared["selection"]["application"]
                result = {
                    "kind": "run_inspected",
                    "run_id": inspection["run_id"],
                    "run_job_id": run_job["job_id"],
                    "inspection_job_id": inspection_job["job_id"],
                    **{key: app[key] for key in ("scenario_id", "version", "digest")},
                    "mode": selected["run"]["mode"],
                    "objective_reached": selected["run"].get("objective_reached", False),
                    "cleanup_state": selected["cleanup_state"],
                    "observed_records": inspection["observed_records"],
                    "total_records": inspection["total_records"],
                    "inspection_status": inspection["status"],
                    "runtime_modified": bool(selected["runtime_changes"]),
                    "runtime_proposal_record_ids": selected["runtime_changes"],
                    "actual_scenario_digest": content_hash(selected["run"]["scenario"]),
                    "native_path": "/runs/" + inspection["run_id"],
                }
        ready = False
        if (
            prepared is not None
            and decision is None
            and job["state"] in {"completed", "interrupted"}
            and not job["progress"].get("stopped")
        ):
            try:
                with self.store._connection() as connection:
                    require_active(self.store, connection, job)
                ready = True
            except ProductStoreError:
                pass
        return {
            "job": job,
            "preparation": prepared,
            "decision": decision,
            "run_job": self.service.job(run_job["job_id"]) if run_job else None,
            "inspection_job": inspection_job,
            "inspection": inspection,
            "result": result,
            "review_ready": ready,
        }

    def cancel(self, job_id: str) -> Mapping[str, Any]:
        job = records.stop(self.store, job_id)
        identifiers = [job_id]
        for key, kind in (("run_job_id", "scenario.run"), ("inspection_job_id", INSPECT_KIND)):
            nested = self._nested(job, key, kind)
            if nested is not None:
                identifiers.append(nested["job_id"])
        for identifier in identifiers:
            if identifier in self.controller.active_job_ids:
                self.controller.cancel(identifier)
        return self._job(job_id)
