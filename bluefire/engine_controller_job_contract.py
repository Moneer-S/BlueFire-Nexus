"""Pure request contracts shared by engine controllers and durable storage."""

from __future__ import annotations

import re
import uuid
from enum import Enum
from typing import Any, Mapping

from .engine_experiment import DefenseState, EngineDefenseChange
from .util import content_hash, parse_iso8601_datetime

_EXPERIMENT_ID = re.compile(r"^experiment-[0-9a-f]{32}$")

_CHECK_ID = re.compile(r"^controller-check-[0-9a-f]{32}$")

_CHANGE_ID = re.compile(r"^defense-change-[0-9a-f]{32}$")

_RUN_ID = re.compile(r"^run-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}$")

_JOB_ID = re.compile(r"^job-[0-9a-f]{32}$")

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class EngineControllerJobError(RuntimeError):
    """A controller job lost its exact saved intent or lifecycle binding."""


class DefenseOperation(str, Enum):
    APPLY = "apply"
    RECONCILE_APPLICATION = "reconcile_application"
    ROLLBACK = "rollback"
    RECONCILE_ROLLBACK = "reconcile_rollback"


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise EngineControllerJobError(f"{label} is invalid")
    return value


def _timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise EngineControllerJobError(f"{label} is invalid")
    try:
        parsed = parse_iso8601_datetime(value)
    except ValueError as exc:
        raise EngineControllerJobError(f"{label} is invalid") from exc
    if parsed.isoformat().replace("+00:00", "Z") != value:
        raise EngineControllerJobError(f"{label} is not canonical")
    return value


def _submission(value: Any) -> str:
    if not isinstance(value, str):
        raise EngineControllerJobError("submission identity is invalid")
    try:
        parsed = uuid.UUID(value)
    except ValueError as exc:
        raise EngineControllerJobError("submission identity must be a canonical UUID") from exc
    if str(parsed) != value:
        raise EngineControllerJobError("submission identity must be a canonical UUID")
    return value


def _product_store_request(request: Mapping[str, Any], label: str) -> dict[str, Any]:
    """Strip and verify ProductStore's immutable idempotent-submission binding."""

    if not isinstance(request, Mapping):
        raise EngineControllerJobError(f"{label} request fields changed")
    parsed = dict(request)
    submission = parsed.pop("_submission", None)
    if submission is None:
        return parsed
    if (
        not isinstance(submission, Mapping)
        or set(submission) != {"schema_version", "submission_id", "intent_digest"}
        or submission.get("schema_version") != "bluefire.job-submission.v1"
        or submission.get("intent_digest") != content_hash(parsed)
    ):
        raise EngineControllerJobError(f"{label} submission binding changed")
    _submission(submission.get("submission_id"))
    return parsed


def exact_defense_request(
    request: Mapping[str, Any],
) -> tuple[dict[str, Any], DefenseOperation]:
    fields = {
        "schema_version",
        "experiment_id",
        "experiment_revision",
        "experiment_digest",
        "change_id",
        "change_digest",
        "operation",
        "originating_job_id",
        "originating_operation_receipt_digest",
    }
    parsed = _product_store_request(request, "defense operation")
    if set(parsed) != fields:
        raise EngineControllerJobError("defense operation request fields changed")
    if parsed["schema_version"] != "bluefire.engine-defense-operation-job.v1":
        raise EngineControllerJobError("defense operation request version changed")
    try:
        operation = DefenseOperation(parsed["operation"])
    except (TypeError, ValueError) as exc:
        raise EngineControllerJobError("defense operation is invalid") from exc
    if (
        not isinstance(parsed["experiment_id"], str)
        or _EXPERIMENT_ID.fullmatch(parsed["experiment_id"]) is None
        or not isinstance(parsed["change_id"], str)
        or _CHANGE_ID.fullmatch(parsed["change_id"]) is None
        or isinstance(parsed["experiment_revision"], bool)
        or not isinstance(parsed["experiment_revision"], int)
    ):
        raise EngineControllerJobError("defense operation identity is invalid")
    _digest(parsed["experiment_digest"], "defense experiment digest")
    _digest(parsed["change_digest"], "defense change digest")
    if parsed["originating_job_id"] is not None and (
        not isinstance(parsed["originating_job_id"], str)
        or _JOB_ID.fullmatch(parsed["originating_job_id"]) is None
    ):
        raise EngineControllerJobError("originating defense job is invalid")
    if parsed["originating_operation_receipt_digest"] is not None:
        _digest(
            parsed["originating_operation_receipt_digest"],
            "originating defense receipt",
        )
    return parsed, operation


def exact_check_request(request: Mapping[str, Any]) -> dict[str, Any]:
    fields = {
        "schema_version",
        "experiment_id",
        "experiment_revision",
        "experiment_digest",
        "check_id",
        "run_id",
        "role",
        "performer",
        "mechanism_ref",
        "target_snapshot_ref",
        "input_digest",
        "reserved_at",
    }
    parsed = _product_store_request(request, "controller check")
    if set(parsed) != fields:
        raise EngineControllerJobError("controller check request fields changed")
    if parsed["schema_version"] != "bluefire.engine-controller-check-job.v1":
        raise EngineControllerJobError("controller check request version changed")
    if (
        not isinstance(parsed["experiment_id"], str)
        or _EXPERIMENT_ID.fullmatch(parsed["experiment_id"]) is None
        or not isinstance(parsed["check_id"], str)
        or _CHECK_ID.fullmatch(parsed["check_id"]) is None
        or not isinstance(parsed["run_id"], str)
        or _RUN_ID.fullmatch(parsed["run_id"]) is None
        or isinstance(parsed["experiment_revision"], bool)
        or not isinstance(parsed["experiment_revision"], int)
    ):
        raise EngineControllerJobError("controller check request identity is invalid")
    for field in (
        "experiment_digest",
        "mechanism_ref",
        "target_snapshot_ref",
        "input_digest",
    ):
        _digest(parsed[field], f"controller check {field}")
    _timestamp(parsed["reserved_at"], "controller check reservation time")
    return parsed


def require_defense_operation(change: EngineDefenseChange, operation: DefenseOperation) -> None:
    if operation is DefenseOperation.APPLY and change.state is not DefenseState.REVIEWED:
        raise EngineControllerJobError("defense application is not ready")
    if operation is DefenseOperation.RECONCILE_APPLICATION and not (
        change.state is DefenseState.UNKNOWN and change.rollback_operation_digest is None
    ):
        raise EngineControllerJobError("defense application does not require reconciliation")
    if operation is DefenseOperation.ROLLBACK and change.state not in {
        DefenseState.APPLIED,
        DefenseState.RETAINED,
    }:
        raise EngineControllerJobError("defense rollback is not ready")
    if operation is DefenseOperation.RECONCILE_ROLLBACK and not (
        change.state is DefenseState.UNKNOWN and change.rollback_operation_digest is not None
    ):
        raise EngineControllerJobError("defense rollback does not require reconciliation")
