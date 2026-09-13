"""Compile optional finite authority at every ordinary Execute approval boundary."""

from __future__ import annotations

from typing import Any, Mapping

from .adaptive_execution import compile_adaptive_authorization
from .approvals import execution_approval_binding
from .config import AutonomyLevel, RunnerProfile
from .contracts import ScenarioDefinition
from .planner import DeterministicPlanner
from .registry import BehaviorRegistry
from .runner_contracts import current_platform


def reviewed_execution_approval_binding(
    *,
    planner: DeterministicPlanner,
    registry: BehaviorRegistry,
    scenario: ScenarioDefinition,
    plan: Mapping[str, Any],
    profile: RunnerProfile,
    target_scope: Mapping[str, Any],
    autonomy: AutonomyLevel,
    ai_provider: Mapping[str, Any],
    context: Mapping[str, Any] | None = None,
    runner_readiness: Mapping[str, Any] | None = None,
    catalog_authority: Mapping[str, Any] | None = None,
) -> Mapping[str, str]:
    authorization = compile_adaptive_authorization(
        registry=registry,
        scenario=scenario,
        plan=plan,
        profile=profile,
        target_scope=target_scope,
        platform=current_platform(),
        planner=planner,
        catalog_authority=catalog_authority,
    )
    return execution_approval_binding(
        registry=registry,
        scenario=scenario,
        plan=plan,
        profile=profile,
        target_scope=target_scope,
        autonomy=autonomy,
        ai_provider=ai_provider,
        context=context,
        runner_readiness=runner_readiness,
        catalog_authority=catalog_authority,
        adaptive_authorization=authorization,
    )
