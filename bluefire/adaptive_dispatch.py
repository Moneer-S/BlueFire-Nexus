"""Bridge a reviewed logical experiment to the finite native dispatch envelope."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping

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
    step_retries_used: int | None = None,
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
            step_retries_used=step_retries_used,
            approval_expires_at=approval_expires_at,
        )
    elif step.to_dict() not in [baseline.to_dict() for baseline in plan.steps]:
        raise AdaptiveAuthorizationError("non-adaptive step differs from the reviewed exact plan")


@dataclass(frozen=True)
class ReviewedStepChecks:
    """Bind immutable authority once; recheck the live deadline before each effect.

    A returned callback captures the counters at reservation time. Later loop
    iterations cannot change which reservation that callback is checking.
    """

    plan: ExecutionPlan
    authorization: Mapping[str, Any] | None
    expected_digest: str | None
    registry: BehaviorRegistry
    profile: RunnerProfile | None
    target_scope: Mapping[str, Any]
    platform: str
    catalog_authority: Mapping[str, Any] | None
    approval: Mapping[str, Any] | None
    deadline: float | None
    cleanup_reserve: float

    def bind(
        self,
        *,
        remaining_steps: int,
        retries_used: int,
        budget: Mapping[str, Any] | None,
        step: PlanStep | None = None,
        is_retry: bool = False,
    ) -> Callable[..., None]:
        counts = (
            {key: row["used"] for key, row in budget["per_step"].items()}
            if budget is not None
            else {}
        )

        def check(selected: PlanStep | None = step) -> None:
            if self.authorization is None:
                if is_retry:
                    raise AdaptiveAuthorizationError(
                        "adaptive method selection has no reviewed authority"
                    )
                return
            assert self.profile is not None and self.approval is not None and selected is not None
            args: dict[str, Any] = {
                "step": selected,
                "authorization": self.authorization,
                "registry": self.registry,
                "profile": self.profile,
                "target_scope": self.target_scope,
                "platform": self.platform,
                "catalog_authority": self.catalog_authority,
                "remaining_steps": remaining_steps,
                "remaining_seconds": max(
                    (self.deadline or time.monotonic()) - time.monotonic() - self.cleanup_reserve,
                    0.0,
                ),
                "retries_used": retries_used,
                "step_retries_used": counts.get(selected.step_id),
                "approval_expires_at": str(self.approval["expires_at"]),
            }
            assert self.expected_digest is not None
            digest = self.expected_digest
            if is_retry:
                validate_selected_method(
                    **args, expected_authorization_digest=digest, is_retry=True
                )
            else:
                validate_dispatch(**args, plan=self.plan, expected_digest=digest)

        return check
