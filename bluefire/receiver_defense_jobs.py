"""Explicit receiver preparation composed with ordinary reviewed runs and replays."""

from __future__ import annotations

import uuid
from typing import Mapping

from . import product_store_receiver_defense as records
from .application_errors import APIError
from .job_runtime import JobResult, JobRuntimeError
from .product_store_errors import ProductStoreError
from .receiver_defense_context import OWNER_KIND, PHASES, POLICIES, PREPARE_KIND, context
from .receiver_defense_ownership import ReceiverOwners
from .util import content_hash


def fields(request, expected):
    if not isinstance(request, Mapping) or set(request) != expected:
        raise ProductStoreError("Receiver request contains unsupported or missing fields.")
    identifier = request.get("submission_id")
    if identifier is not None and (
        not isinstance(identifier, str) or str(uuid.UUID(identifier)) != identifier
    ):
        raise ProductStoreError("Receiver submission requires a canonical UUID.")
    reviewer = request.get("reviewed_by")
    if reviewer is not None and (
        not isinstance(reviewer, str)
        or not 1 <= len(reviewer.strip()) <= 200
        or any(ord(char) < 32 for char in reviewer)
    ):
        raise ProductStoreError("A bounded reviewer identity is required.")
    from .product_store import _safe_document

    _safe_document(request, context="receiver request")


class ReceiverDefenseJobs:
    def __init__(self, service, *, factory=None):
        self.service = service
        self.store = service.product_store
        self.controller = service.job_controller
        self.owners = ReceiverOwners(self.store, factory=factory)

    def context(self, request):
        current = context(self.service, request)
        supported = not any(
            reason["code"] in {"linux_required", "execute_required"}
            for reason in current["reasons"]
        )
        ready = False
        if supported and current["eligible"]:
            status = self.service.runner_status(
                profile_id=current["run_intent"]["runner_profile_id"]
            )
            ready = (
                status.get("state") == "ready"
                and status.get("profile_id") == current["run_intent"]["runner_profile_id"]
            )
        return {
            **current,
            "availability": {
                "supported": supported,
                "ready": ready,
                "reason": (
                    None
                    if ready
                    else "Use the supported Linux environment and prepare/start the selected native runner before preparing a receiver."
                ),
                "native_path": "/runs" if supported else None,
            },
        }

    def _job(self, identifier):
        job = self.store.get_job(identifier)
        if job["kind"] != OWNER_KIND:
            raise ProductStoreError("The selected job is not a receiver comparison.")
        return job

    def list(self, *, cursor=None):
        owners, truncated = records.list_owners(self.store, cursor)
        jobs = []
        for owner in owners:
            view = self.read(owner["job_id"])
            jobs.append(
                {
                    "job_id": owner["job_id"],
                    "title": (owner["request"]["context"] or {}).get(
                        "scenario_title", "Unavailable receiver test source"
                    ),
                    "status": view["status"],
                    "phase": view["next_action"]["phase"],
                    "updated_at": owner["updated_at"],
                    "native_path": "/compare?receiver_job=" + owner["job_id"],
                }
            )
        return {
            "schema_version": "bluefire.receiver-defense-list.v1",
            "jobs": jobs,
            "truncated": truncated,
            "next_cursor": owners[-1]["job_id"] if truncated else None,
        }

    def _fresh(self, parent):
        request = parent["request"]["submitted_request"]
        current = self.context({key: request[key] for key in ("selection", "run_intent")})
        if (
            current["context_digest"] != parent["request"]["context_digest"]
            or not current["eligible"]
        ):
            raise ProductStoreError(
                "The saved graph or native receiver settings changed or are unavailable."
            )
        if parent["progress"].get("stopped"):
            raise ProductStoreError("This receiver comparison was stopped.")
        return current

    def submit(self, request):
        fields(request, {"submission_id", "selection", "run_intent", "context_digest"})
        digest = content_hash(request)
        previous = self.store.get_job_submission(
            OWNER_KIND, submission_id=request["submission_id"], intent_digest=digest
        )
        if previous is not None:
            return self.read(previous["job_id"])
        from .receiver_defense_context import intent, selected

        selected(request["selection"])
        intent(request["run_intent"])
        try:
            current = self.context({key: request[key] for key in ("selection", "run_intent")})
        except (APIError, ProductStoreError, ValueError):
            current = None
        document = {
            "submitted_request": dict(request),
            "context": current,
            "context_digest": request["context_digest"],
        }
        if (
            current is None
            or current["context_digest"] != request["context_digest"]
            or not current["eligible"]
        ):
            rejected = records.refuse_admission(
                self.store, document, request["submission_id"], digest
            )
            return self.read(rejected["job_id"])

        def admit(ctx, _request):
            try:
                parent = self._job(ctx.job_id)
                if parent["request"]["context"] is None:
                    raise ProductStoreError("Receiver context is unavailable.")
                self._fresh(parent)
            except (APIError, ProductStoreError, ValueError):
                self.store.transition_job(
                    ctx.job_id,
                    "failed",
                    progress={
                        "admission": {"accepted": False, "problem": records.ADMISSION_PROBLEM},
                        "receiver_settled": True,
                    },
                    error=records.ADMISSION_PROBLEM,
                )
                raise ProductStoreError("Receiver context admission was refused.") from None
            return JobResult(
                progress={
                    "phase": "receiver_not_started",
                    "admission": {"accepted": True, "problem": None},
                }
            )

        job = self.controller.submit(
            OWNER_KIND,
            document,
            callback=admit,
            submission_id=request["submission_id"],
            intent_digest=digest,
        )
        return self.read(job["job_id"])

    def prepare(self, parent_id, request):
        fields(request, {"submission_id", "phase", "reviewed_by"})
        digest = content_hash({"parent_job_id": parent_id, **request})
        previous = self.store.get_job_submission(
            PREPARE_KIND, submission_id=request["submission_id"], intent_digest=digest
        )
        if previous is not None:
            return self.read(parent_id)
        parent = self._job(parent_id)
        self._fresh(parent)
        old = parent["progress"].get("phases", {}).get(request["phase"])
        if old:
            child = self.store.get_job(old["receiver_job_id"])
            if child["state"] not in {"completed", "failed", "cancelled", "interrupted"}:
                raise ProductStoreError(
                    "The current receiver preparation must settle before another explicit attempt."
                )
            if child["progress"].get("execution_started") or child["progress"].get("task_binding"):
                raise ProductStoreError(
                    "An executed or uncertain receiver phase cannot be repeated."
                )
            execution_id = child["progress"].get("execution_job_id")
            if execution_id:
                self.controller.cancel(execution_id)
            if not self.owners.close(child["job_id"]):
                raise ProductStoreError("The previous receiver has no verified cleanup receipt.")
        receiver_id = records.reserve(self.store, parent_id, request)
        marker = {
            "parent_job_id": parent_id,
            "receiver_job_id": receiver_id,
            "phase": request["phase"],
        }
        self.controller.submit(
            PREPARE_KIND,
            {"submitted_request": dict(request), "receiver_defense": marker},
            callback=self._prepare,
            submission_id=request["submission_id"],
            intent_digest=digest,
        )
        return self.read(parent_id)

    def _prepare(self, ctx, request):
        marker = request["receiver_defense"]
        try:
            parent = self._job(marker["parent_job_id"])
            current = self._fresh(parent)
            ctx.checkpoint({"phase": "preparing_receiver"})
            # Ordinary native preflight verifies profile/enrollment/scope before
            # the explicit preparation action can create its fixed listener.
            initial = self.service.preflight(
                {"scenario": current["scenario"], **current["run_intent"]}
            )
            problems = [
                item
                for item in initial["problems"]
                if item != "Explicit operator approval is required."
            ]
            if problems:
                records.update(self.store, ctx.job_id, {"preflight_refusal": initial}, active=True)
                raise ProductStoreError(
                    "Native preflight refused receiver preparation. Review its findings."
                )
            ctx.checkpoint({"prepare_started": True})
            session = self.owners.prepare(
                ctx.job_id, POLICIES[PHASES.index(marker["phase"])], current["handoff"]["port"]
            )
            records.update(self.store, ctx.job_id, {"session": session}, active=True)
            ctx.checkpoint({"phase": "receiver_ready"})
            self._fresh(self._job(marker["parent_job_id"]))
            prepared = self._native_preparation(marker)
            self.owners.current(ctx.job_id, session)
            records.update(self.store, ctx.job_id, {"preparation": prepared}, active=True)
            return JobResult(progress={"phase": "native_review_ready"})
        except BaseException:
            self.owners.close(ctx.job_id)
            raise

    def baseline(self, parent):
        from .receiver_defense_result import verified_result

        baseline = parent["progress"].get("phases", {}).get("baseline")
        if baseline is None:
            raise ProductStoreError("The authenticated baseline is unavailable.")
        job = self.store.get_job(baseline["receiver_job_id"])
        if not records.phase_verified(job, "baseline"):
            raise ProductStoreError(
                "The baseline needs accepted retained public bytes and verified cleanup."
            )
        return verified_result(self, job)

    def _native_preparation(self, marker):
        parent = self._job(marker["parent_job_id"])
        current = self._fresh(parent)
        child = self.store.get_job(marker["receiver_job_id"])
        session = child["progress"]["session"]
        if marker["phase"] == "baseline":
            run_request = {"scenario": current["scenario"], **current["run_intent"]}
            report = self.service.preflight(run_request, _receiver_defense=marker)
            replay, artifact = None, None
        else:
            baseline = self.baseline(parent)
            payload = {
                "exact": False,
                **{key: value for key, value in current["run_intent"].items() if key != "mode"},
                "defense_change": "Owned receiver content policy: "
                + POLICIES[PHASES.index(marker["phase"])],
            }
            replay = self.service.prepare_replay(
                baseline["run_id"], payload, _receiver_defense=marker
            )
            report, artifact, run_request = replay["preflight"], baseline["artifact"], None
        problems = [
            item for item in report["problems"] if item != "Explicit operator approval is required."
        ]
        if problems:
            records.update(self.store, child["job_id"], {"preflight_refusal": report}, active=True)
            raise ProductStoreError(
                "The exact receiver execution is not ready. Review native preflight."
            )
        value = {
            "schema_version": "bluefire.receiver-defense-preparation.v1",
            **marker,
            "context_digest": current["context_digest"],
            "session": session,
            "execution_kind": (
                "scenario.run" if marker["phase"] == "baseline" else "scenario.replay"
            ),
            "run_request": run_request,
            "replay_preparation": replay,
            "preflight": report,
            "baseline_artifact": artifact,
            "approval_created": False,
            "target_effects_started": False,
            "receiver_started": True,
        }
        return {**value, "preparation_digest": content_hash(value)}

    def authority(self, marker):
        child = self.store.get_job(marker["receiver_job_id"])
        if child["request"]["receiver_defense"] != marker:
            raise ProductStoreError("Receiver ownership marker changed.")
        parent = self._job(marker["parent_job_id"])
        self._fresh(parent)
        session = child["progress"]["session"]
        self.owners.current(child["job_id"], session)
        return {
            **marker,
            "session": session,
            "baseline_artifact": (
                None if marker["phase"] == "baseline" else self.baseline(parent)["artifact"]
            ),
        }

    def review(self, parent_id, request):
        fields(request, {"submission_id", "phase", "preparation_digest", "decision", "reviewed_by"})
        if request["decision"] not in {"accept", "reject"}:
            raise ProductStoreError("Choose an explicit native accept or reject decision.")
        parent = self._job(parent_id)
        for old in parent["progress"].get("attempt_history", []):
            old_child = self.store.get_job(old["receiver_job_id"])
            old_preparation = records.preparation(old_child)
            if (
                old_preparation
                and old_preparation["preparation_digest"] == request["preparation_digest"]
            ):
                if old_child["progress"].get("decision") != request:
                    raise ProductStoreError(
                        "The previous receiver attempt has another retained decision."
                    )
                return self.read(parent_id)
        reservation = parent["progress"].get("phases", {}).get(request["phase"])
        if reservation is None:
            raise ProductStoreError("Prepare the named receiver phase before reviewing it.")
        child = self.store.get_job(reservation["receiver_job_id"])
        existing = child["progress"].get("decision")
        with self.service._runtime_configuration_lock:
            if existing is None and request["decision"] == "accept":
                self.authority(child["request"]["receiver_defense"])
            child = records.decide(self.store, child["job_id"], request)
        if request["decision"] == "reject":
            self.owners.close(child["job_id"])
            return self.read(parent_id)
        identifier = child["progress"]["execution_submission_id"]
        prepared = records.preparation(child)
        marker = child["request"]["receiver_defense"]
        if prepared["execution_kind"] == "scenario.run":
            self.service.submit_run(
                {**prepared["run_request"], "submission_id": identifier}, _receiver_defense=marker
            )
        else:
            replay = prepared["replay_preparation"]
            self.service.submit_replay(
                self.baseline(parent)["run_id"],
                {
                    **replay["replay_request"],
                    "preparation_id": replay["preparation_id"],
                    "preparation_context": replay["preparation_context"],
                    "submission_id": identifier,
                },
                _receiver_defense=marker,
            )
        return self.read(parent_id)

    def before_execute(self, request):
        marker = request["receiver_defense"]
        self.authority(marker)
        records.update(
            self.store, marker["receiver_job_id"], {"execution_started": True}, active=True
        )

    def cancel(self, parent_id):
        identifiers = records.stop(self.store, parent_id)
        for identifier in identifiers:
            child = self.store.get_job(identifier)
            for target in (child["progress"].get("execution_job_id"), identifier):
                if target:
                    try:
                        self.controller.cancel(target)
                    except (ProductStoreError, JobRuntimeError):
                        pass
            self.owners.close(identifier)
        records.settle_owner(self.store, parent_id)
        return self.read(parent_id)

    def read(self, parent_id):
        from .receiver_defense_view import read

        return read(self, self._job(parent_id))
