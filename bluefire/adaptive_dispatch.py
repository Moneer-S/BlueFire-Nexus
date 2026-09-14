"""Bridge a reviewed logical experiment to the finite native dispatch envelope."""

from __future__ import annotations

from typing import Any, Mapping

from .adaptive_execution import AdaptiveAuthorizationError, validate_selected_method
from .adaptive_runtime import reviewed_methods
from .config import RunnerProfile
from .planner import ExecutionPlan, PlanStep
from .registry import BehaviorRegistry
from .util import content_hash


def execution_steps(
    plan: ExecutionPlan, authorization: Mapping[str, Any] | None
) -> tuple[PlanStep, ...]:
    rows = list(plan.steps)
    if authorization is not None:
        for group in authorization["steps"]:
            rows.extend(reviewed_methods(authorization, group["step_id"]))
    return tuple({content_hash(step.to_dict()): step for step in rows}.values())


def operation_identity(step: PlanStep) -> dict[str, Any]:
    return {
        "step_id": step.step_id,
        "behavior_id": step.behavior_id,
        "action_id": step.action_id,
        "execution_binding_digest": (
            content_hash(step.execution_binding) if step.execution_binding is not None else None
        ),
    }


def runner_authorization(
    plan: ExecutionPlan, authorization: Mapping[str, Any] | None
) -> dict[str, Any] | None:
    if authorization is None:
        return None
    operations = {
        content_hash(operation_identity(step)): operation_identity(step)
        for step in execution_steps(plan, authorization)
    }
    return {
        "schema_version": "bluefire.reviewed-execution.v1",
        "authorization_digest": authorization["authorization_digest"],
        "operations": list(operations.values()),
    }


def reviewed_operation(step: PlanStep, runner_profile: Mapping[str, Any]) -> dict[str, Any] | None:
    reviewed = runner_profile.get("reviewed_execution")
    if reviewed is None:
        return None
    operation = operation_identity(step)
    if operation not in reviewed["operations"]:
        raise AdaptiveAuthorizationError("operation is outside the finite native profile")
    return {**operation, "authorization_digest": reviewed["authorization_digest"]}


def validate_dispatch(
    *,
    step: PlanStep,
    plan: ExecutionPlan,
    authorization: Mapping[str, Any],
    expected_digest: str,
    registry: BehaviorRegistry,
    profile: RunnerProfile,
    target_scope: Mapping[str, Any],
    platform: str,
    catalog_authority: Mapping[str, Any] | None,
    remaining_steps: int,
    remaining_seconds: float,
    retries_used: int,
    approval_expires_at: str,
) -> None:
    if any(group["step_id"] == step.step_id for group in authorization["steps"]):
        validate_selected_method(
            authorization=authorization,
            expected_authorization_digest=expected_digest,
            step=step,
            profile=profile,
            target_scope=target_scope,
            platform=platform,
            registry=registry,
            catalog_authority=catalog_authority,
            remaining_steps=remaining_steps,
            remaining_seconds=remaining_seconds,
            retries_used=retries_used,
            approval_expires_at=approval_expires_at,
        )
    elif step.to_dict() not in [baseline.to_dict() for baseline in plan.steps]:
        raise AdaptiveAuthorizationError("non-adaptive step differs from the reviewed exact plan")
