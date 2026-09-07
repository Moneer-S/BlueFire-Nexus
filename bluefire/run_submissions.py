"""Idempotent ordinary run publication; approval remains the existing immutable gate."""

from __future__ import annotations

import uuid
from contextlib import contextmanager
from http import HTTPStatus
from time import monotonic
from typing import Any, Mapping

from .application_errors import APIError
from .approvals import execution_intent_id
from .assistance_run_protocol import AssistanceRunService
from .config import ConfigError
from .contracts import ExecutionMode
from .job_runtime import JobRuntimeError
from .product_store_errors import ProductStoreError
from .product_store_run_submissions import close_refused
from .util import content_hash

_ACTION_CATALOG_AUTHORITY_KEY = "_action_catalog_authority"
_EXECUTE_READINESS_KEY = "_execute_readiness"
PREFLIGHT = "_run_submission_preflight"
ORIGINAL = "_run_submission_request"


@contextmanager
def admission(service):
    with service._runtime_configuration_lock:
        deadline = monotonic() + 5
        if not service._action_catalog_lock.acquire(timeout=max(0, deadline - monotonic())):
            raise APIError(
                HTTPStatus.CONFLICT,
                "run_admission_busy",
                "Run admission is busy. Review a new submission after the current admission settles.",
            )
        try:
            with service.product_store.action_package_catalog_lease(deadline=deadline):
                yield
        finally:
            service._action_catalog_lock.release()


def problem(error, report):
    code = getattr(error, "code", None)
    if code == "run_admission_busy" or isinstance(error, JobRuntimeError):
        return {
            "code": "run_admission_busy",
            "message": "Run admission capacity is busy. Wait for current jobs to settle, then review a new submission.",
            "native_path": "/runs",
        }
    if report is not None:
        return {
            "code": "run_preflight_refused",
            "message": "Native preflight or its reviewed authority refused this submission. Check the selected runner, scope and run settings, then review a new submission.",
            "native_path": "/runs",
        }
    if isinstance(error, ConfigError):
        return {
            "code": "run_configuration_unavailable",
            "message": "The selected runtime configuration is unavailable. Review the provider and runner settings before a new submission.",
            "native_path": "/settings",
        }
    return {
        "code": "run_context_refused",
        "message": "The exact run context is unavailable or changed. Review its immutable graph and current native settings before a new submission.",
        "native_path": "/runs",
    }


def response(service: AssistanceRunService, job: Mapping[str, Any]) -> Mapping[str, Any]:
    visible = service.job(job["job_id"])
    return {
        "schema_version": "bluefire.run-job-submission.v1",
        "job": visible,
        "approval_request": visible.get("approval_request"),
        "preflight": job["request"].get(PREFLIGHT),
    }


def submit(
    service: AssistanceRunService,
    request: Mapping[str, Any],
    *,
    assistance_run: Mapping[str, Any] | None = None,
) -> Mapping[str, Any]:
    supplied = dict(request)
    submission_id = supplied.pop("submission_id", None)
    try:
        if not isinstance(submission_id, str):
            raise ValueError
        parsed = uuid.UUID(submission_id)
        if str(parsed) != submission_id:
            raise ValueError
    except (ValueError, TypeError, AttributeError) as exc:
        raise APIError(
            HTTPStatus.BAD_REQUEST,
            "run_submission_invalid",
            "Run submission requires a canonical UUID.",
        ) from exc
    forbidden = {"approval", "approval_request_id", "assistance_turn", "assistance_run"}
    if any(key.startswith("_") or key in forbidden for key in supplied):
        raise APIError(
            HTTPStatus.BAD_REQUEST,
            "run_submission_invalid",
            "Run submission cannot supply internal authority fields.",
        )
    from .product_store import _safe_document

    try:
        _safe_document(supplied, context="run submission")
    except ProductStoreError as exc:
        raise APIError(
            HTTPStatus.BAD_REQUEST,
            "run_submission_invalid",
            "Run submission contains unsupported metadata.",
        ) from exc
    intent = content_hash({"request": supplied, "assistance_run": assistance_run})
    try:
        existing = service.product_store.get_job_submission(
            "scenario.run", submission_id=submission_id, intent_digest=intent
        )
    except ProductStoreError as exc:
        raise APIError(
            HTTPStatus.CONFLICT,
            "run_submission_conflict",
            "This run UUID is already bound to another request.",
        ) from exc
    if existing is not None:
        return response(service, existing)

    report = None
    try:
        # Preserve the existing action catalog authority lease through publication.
        with admission(service):
            existing = service.product_store.get_job_submission(
                "scenario.run", submission_id=submission_id, intent_digest=intent
            )
            if existing is not None:
                return response(service, existing)
            mode = service._mode(supplied)
            reviewed_request = dict(supplied)
            if assistance_run is not None:
                from .product_store_assistance_run import preparation

                operation = service.assistance_runs._job(assistance_run["operation_job_id"])
                prepared = preparation(operation)
                if (
                    prepared is None
                    or prepared["preparation_digest"] != assistance_run["preparation_digest"]
                ):
                    raise ProductStoreError("Native preparation binding is unavailable.")
                # Existing readiness validation rechecks the live identity and age,
                # while preserving the exact reviewed timestamp/authority digest.
                if mode is ExecutionMode.EXECUTE:
                    reviewed_request[_EXECUTE_READINESS_KEY] = prepared["preflight"][
                        "runner_readiness"
                    ]
                    reviewed_request[_ACTION_CATALOG_AUTHORITY_KEY] = prepared["preflight"][
                        "catalog_authority"
                    ]
            report = service.preflight(reviewed_request)
            problems = [
                item
                for item in report.get("problems", [])
                if not (
                    mode is ExecutionMode.EXECUTE
                    and item == "Explicit operator approval is required."
                )
            ]
            if problems:
                raise APIError(
                    HTTPStatus.CONFLICT,
                    "preflight_refused",
                    "The exact run is not ready for review.",
                )
            stored = {**supplied, ORIGINAL: supplied, PREFLIGHT: report}
            if assistance_run is not None:
                stored["assistance_run"] = dict(assistance_run)
            if mode is ExecutionMode.EXECUTE:
                binding, readiness, authority = (
                    report.get(key)
                    for key in ("approval_binding", "runner_readiness", "catalog_authority")
                )
                if (
                    not isinstance(binding, Mapping)
                    or not isinstance(readiness, Mapping)
                    or not isinstance(authority, Mapping)
                ):
                    raise APIError(
                        HTTPStatus.CONFLICT,
                        "preflight_refused",
                        "The run has no complete immutable approval binding.",
                    )
                stored[_EXECUTE_READINESS_KEY] = dict(readiness)
                stored[_ACTION_CATALOG_AUTHORITY_KEY] = dict(authority)
                stored["_pending_run_approval"] = {
                    "run_id": execution_intent_id(binding),
                    **{
                        key: str(binding[key])
                        for key in (
                            "state_digest",
                            "plan_digest",
                            "profile_id",
                            "target_scope_digest",
                            "maximum_tier",
                        )
                    },
                    "expires_at": service._approval_review_expires_at(),
                }
            if assistance_run is not None:
                service.assistance_runs._fresh(
                    service.assistance_runs._job(assistance_run["operation_job_id"])
                )
            queued = service.job_controller.submit(
                "scenario.run",
                stored,
                requires_approval=mode is ExecutionMode.EXECUTE,
                submission_id=submission_id,
                intent_digest=intent,
            )
            return response(service, queued)
    except (APIError, ProductStoreError, JobRuntimeError, ConfigError) as exc:
        # A publication winner is returned; a definite pre-publication refusal closes
        # this UUID atomically so a stale browser retry cannot later start effects.
        closed = close_refused(
            service.product_store,
            supplied,
            submission_id,
            intent,
            assistance_run=assistance_run,
            refusal=problem(exc, report),
            report=report,
        )
        return response(service, closed)
