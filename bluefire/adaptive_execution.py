"""Finite reviewed method authority, independent of model proposals and dispatch.

Authorization documents are review material, not bearer capabilities. A caller
must bind their digest into a consumed approval and supply that trusted digest
when rechecking a selected operation. No helper here executes an action.
"""

from __future__ import annotations

import math
from dataclasses import replace
from datetime import datetime, timezone
from typing import Any, Mapping

from .adaptive_execution_contract import AdaptiveExecution
from .config import AutonomyLevel, CleanupPolicy, RunnerProfile
from .contracts import ExecutionMode, ScenarioDefinition
from .planner import DeterministicPlanner, ExecutionPlan, PlanStep
from .registry import BehaviorRegistry
from .util import content_hash, json_clone

_SCHEMA = "bluefire.adaptive-authorization.v1"
_FIELDS = frozenset(
    {
        "schema_version",
        "scenario_digest",
        "plan_digest",
        "objective",
        "profile_digest",
        "target_scope",
        "platform",
        "catalog_authority_digest",
        "policy",
        "parameter_policy",
        "limits",
        "cleanup_policy",
        "steps",
        "authorization_digest",
    }
)
_CHOICE_FIELDS = frozenset(
    {
        "plan_step",
        "plan_step_digest",
        "behavior_contract_digest",
        "action_contract_digest",
        "execution_binding_digest",
        "capabilities",
        "mutates",
        "cleanup_action_id",
        "cleanup_contract_digest",
    }
)


class AdaptiveAuthorizationError(ValueError):
    """A selected operation is outside the reviewed finite authorization."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise AdaptiveAuthorizationError(message)


def _document(value: ExecutionPlan | PlanStep | Mapping[str, Any]) -> dict[str, Any]:
    return dict(
        json_clone(value.to_dict() if isinstance(value, (ExecutionPlan, PlanStep)) else value)
    )


def _choice(
    step: Mapping[str, Any], *, registry: BehaviorRegistry, profile: RunnerProfile, platform: str
) -> dict[str, Any]:
    behavior = registry.get_behavior(str(step.get("behavior_id")))
    action = registry.get_action(str(step.get("action_id")))
    _require(action.id in behavior.action_ids, "adaptive action is not owned by its behavior")
    _require(
        action.id in profile.enabled_actions and action.id not in profile.blocked_actions,
        "adaptive action is disabled or blocked by the reviewed profile",
    )
    _require(
        platform in profile.platforms
        and platform in action.platforms
        and platform in behavior.platforms,
        "adaptive method is incompatible with the reviewed platform",
    )
    capabilities = sorted(set(behavior.capabilities) | set(action.capabilities))
    _require(
        set(capabilities).issubset(profile.capabilities), "adaptive method expands capabilities"
    )
    _require(
        behavior.safety_tier in profile.safety_tiers and action.safety_tier in profile.safety_tiers,
        "adaptive method expands the reviewed safety tier",
    )
    _require(action.id != "sandbox.cleanup.v1", "cleanup cannot be an adaptive operation")
    cleanup = None
    if action.cleanup_action_id is not None:
        cleanup = registry.get_action(action.cleanup_action_id)
        _require(
            cleanup.id in profile.enabled_actions and cleanup.id not in profile.blocked_actions,
            "adaptive method cleanup is not enabled",
        )
        _require(
            platform in cleanup.platforms
            and set(cleanup.capabilities).issubset(profile.capabilities)
            and cleanup.safety_tier in profile.safety_tiers,
            "adaptive cleanup exceeds the profile",
        )
    if action.mutates:
        _require(
            cleanup is not None and profile.cleanup_policy is CleanupPolicy.ALWAYS,
            "mutating adaptive methods require enabled cleanup with an always policy",
        )
    return {
        "plan_step": dict(json_clone(step)),
        "plan_step_digest": content_hash(step),
        "behavior_contract_digest": content_hash(behavior.to_dict()),
        "action_contract_digest": content_hash(action.to_dict()),
        "execution_binding_digest": content_hash(step.get("execution_binding")),
        "capabilities": capabilities,
        "mutates": action.mutates,
        "cleanup_action_id": action.cleanup_action_id,
        "cleanup_contract_digest": content_hash(cleanup.to_dict()) if cleanup is not None else None,
    }


def compile_adaptive_authorization(
    *,
    registry: BehaviorRegistry,
    scenario: ScenarioDefinition,
    plan: ExecutionPlan | Mapping[str, Any],
    profile: RunnerProfile,
    target_scope: Mapping[str, Any],
    platform: str,
    planner: DeterministicPlanner | None = None,
    catalog_authority: Mapping[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Resolve only explicitly authored pairs to exact reviewed PlanStep values.

    ``steps[*].methods[*].plan_step`` is the complete operation consumed by the
    orchestrator. It contains exact logical parameters and artifact bindings.
    ``authorization_digest`` must be bound to the one-time Execute approval.
    Package-backed alternatives require the current catalog's planner bindings.
    """
    if scenario.adaptive_execution is None:
        return None
    # Reparse even programmatically constructed dataclasses at this boundary.
    scenario = ScenarioDefinition.from_mapping(scenario.to_dict())
    registry.validate_scenario(scenario)
    registry.validate_runner_profile(profile)
    policy = scenario.adaptive_execution
    assert policy is not None
    document = _document(plan)
    _require(
        profile.mode is ExecutionMode.EXECUTE and document.get("mode") == "execute",
        "adaptive authorization requires an Execute plan and profile",
    )
    _require(profile.approval_required, "adaptive execution requires operator approval")
    _require(platform in profile.platforms, "adaptive execution platform is not reviewed")
    scope = dict(json_clone(target_scope))
    refs = scope.get("scope_refs")
    _require(
        isinstance(refs, list)
        and all(isinstance(ref, str) for ref in refs)
        and len(set(refs)) == len(refs)
        and set(refs).issubset(profile.scope),
        "adaptive target scope exceeds the reviewed profile",
    )
    raw_steps = document.get("steps")
    _require(
        isinstance(raw_steps, list) and all(isinstance(row, Mapping) for row in raw_steps),
        "adaptive execution plan steps are invalid",
    )
    assert isinstance(raw_steps, list)
    if planner is None:
        _require(
            not any(row.get("execution_binding") is not None for row in raw_steps),
            "package-backed adaptive methods require the current catalog planner",
        )
        planner = DeterministicPlanner(registry)
    _require(planner.registry is registry, "adaptive planner must use the reviewed registry")
    implementations = {str(row["step_id"]): str(row["action_id"]) for row in raw_steps}
    compiled = planner.compile(
        scenario,
        mode=ExecutionMode.EXECUTE,
        profile=profile,
        autonomy=AutonomyLevel(str(document.get("autonomy"))),
        ai_provider=document.get("ai_provider", {}),
        action_implementations=implementations,
    )
    _require(
        content_hash(compiled.to_dict()) == content_hash(document),
        "adaptive authorization is not bound to the current compiled plan",
    )
    baseline = {step.step_id: step for step in compiled.steps}
    reviewed_steps = []
    for selected in policy.steps:
        source = scenario.step(selected.step_id)
        pairs = {(method.behavior_id, method.action_id) for method in selected.methods}
        base = baseline[selected.step_id]
        _require(
            (base.behavior_id, base.action_id) in pairs,
            "adaptive methods must explicitly include the saved primary method",
        )
        methods = []
        for method in selected.methods:
            variant_steps = tuple(
                replace(step, behavior_id=method.behavior_id) if step.id == source.id else step
                for step in scenario.steps
            )
            variant = replace(scenario, steps=variant_steps, adaptive_execution=None)
            resolved = planner.compile(
                variant,
                mode=ExecutionMode.EXECUTE,
                profile=profile,
                autonomy=compiled.autonomy,
                ai_provider=compiled.ai_provider,
                action_implementations={**implementations, source.id: method.action_id},
            )
            step = next(item for item in resolved.steps if item.step_id == source.id)
            methods.append(
                _choice(step.to_dict(), registry=registry, profile=profile, platform=platform)
            )
        reviewed_steps.append({"step_id": source.id, "methods": methods})
    body = {
        "schema_version": _SCHEMA,
        "scenario_digest": content_hash(scenario.to_dict()),
        "plan_digest": content_hash(document),
        "objective": compiled.objective,
        "profile_digest": content_hash(profile.to_dict()),
        "target_scope": scope,
        "platform": platform,
        "catalog_authority_digest": content_hash(catalog_authority),
        "policy": policy.to_dict(),
        "parameter_policy": "exact_reviewed_values_and_inputs",
        "limits": profile.budgets.to_dict(),
        "cleanup_policy": profile.cleanup_policy.value,
        "steps": reviewed_steps,
    }
    return {**body, "authorization_digest": content_hash(body)}


def validate_adaptive_authorization(
    authorization: Mapping[str, Any],
    *,
    expected_digest: str,
    registry: BehaviorRegistry,
    profile: RunnerProfile,
    target_scope: Mapping[str, Any],
    platform: str,
    catalog_authority: Mapping[str, Any] | None = None,
) -> Mapping[str, Any]:
    """Recheck reviewed bytes and current registry/environment before selection.

    ``expected_digest`` must come from the approval-bound authorization, never
    from the model or the candidate document being checked.
    """
    _require(
        isinstance(authorization, Mapping) and set(authorization) == _FIELDS,
        "adaptive authorization fields are invalid",
    )
    body = {key: value for key, value in authorization.items() if key != "authorization_digest"}
    _require(
        authorization.get("schema_version") == _SCHEMA
        and authorization.get("authorization_digest") == expected_digest
        and content_hash(body) == expected_digest,
        "adaptive authorization digest changed",
    )
    _require(
        authorization.get("profile_digest") == content_hash(profile.to_dict()),
        "adaptive authorization profile changed",
    )
    _require(
        authorization.get("target_scope") == dict(target_scope),
        "adaptive authorization target changed",
    )
    _require(
        authorization.get("platform") == platform and platform in profile.platforms,
        "adaptive authorization platform changed",
    )
    _require(
        authorization.get("catalog_authority_digest") == content_hash(catalog_authority),
        "adaptive authorization catalog changed",
    )
    _require(
        authorization.get("limits") == profile.budgets.to_dict()
        and authorization.get("cleanup_policy") == profile.cleanup_policy.value
        and authorization.get("parameter_policy") == "exact_reviewed_values_and_inputs",
        "adaptive authorization limits or cleanup changed",
    )
    policy = AdaptiveExecution.from_mapping(authorization.get("policy"))
    steps = authorization.get("steps")
    _require(
        isinstance(steps, list) and len(steps) == len(policy.steps),
        "adaptive authorization steps changed",
    )
    assert isinstance(steps, list)
    for authored, row in zip(policy.steps, steps, strict=True):
        _require(
            isinstance(row, Mapping)
            and set(row) == {"step_id", "methods"}
            and row.get("step_id") == authored.step_id,
            "adaptive authorization step changed",
        )
        methods = row.get("methods")
        _require(
            isinstance(methods, list) and len(methods) == len(authored.methods),
            "adaptive authorization methods changed",
        )
        for method, choice in zip(authored.methods, methods, strict=True):
            _require(
                isinstance(choice, Mapping) and set(choice) == _CHOICE_FIELDS,
                "adaptive authorization choice fields changed",
            )
            step = choice.get("plan_step")
            _require(
                isinstance(step, Mapping)
                and step.get("step_id") == authored.step_id
                and step.get("behavior_id") == method.behavior_id
                and step.get("action_id") == method.action_id,
                "adaptive authorization choice identity changed",
            )
            _require(
                dict(choice)
                == _choice(step, registry=registry, profile=profile, platform=platform),
                "adaptive method contracts, effects, or execution binding changed",
            )
    return dict(json_clone(authorization))


def validate_selected_method(
    *,
    authorization: Mapping[str, Any],
    expected_authorization_digest: str,
    step: PlanStep | Mapping[str, Any],
    profile: RunnerProfile,
    target_scope: Mapping[str, Any],
    platform: str,
    registry: BehaviorRegistry,
    remaining_steps: int,
    remaining_seconds: float,
    retries_used: int,
    approval_expires_at: str,
    is_retry: bool = False,
    catalog_authority: Mapping[str, Any] | None = None,
    now: datetime | None = None,
) -> Mapping[str, Any]:
    """Return the exact reviewed choice after authority, expiry, and budget checks.

    Set ``is_retry`` when admitting a new retry, using the count before its
    reservation. Rechecks of an already reserved operation use False. Callers
    reserve that retry before effects and retain it in the durable attempt record.
    """
    validated = validate_adaptive_authorization(
        authorization,
        expected_digest=expected_authorization_digest,
        registry=registry,
        profile=profile,
        target_scope=target_scope,
        platform=platform,
        catalog_authority=catalog_authority,
    )
    _require(
        type(remaining_steps) is int and 0 < remaining_steps <= profile.budgets.max_steps,
        "adaptive step budget exhausted or invalid",
    )
    _require(
        not isinstance(remaining_seconds, bool)
        and isinstance(remaining_seconds, (int, float))
        and math.isfinite(remaining_seconds)
        and 0 < remaining_seconds <= profile.budgets.max_seconds,
        "adaptive time budget exhausted or invalid",
    )
    _require(
        type(is_retry) is bool
        and type(retries_used) is int
        and 0 <= retries_used
        and retries_used + int(is_retry) <= validated["policy"]["max_retries"],
        "adaptive retry budget exhausted or invalid",
    )
    try:
        expires = datetime.fromisoformat(approval_expires_at.replace("Z", "+00:00"))
        current = now or datetime.now(timezone.utc)
    except (ValueError, TypeError, AttributeError) as exc:
        raise AdaptiveAuthorizationError("adaptive execution approval expiry is invalid") from exc
    _require(
        expires.tzinfo is not None and current.tzinfo is not None and expires > current,
        "adaptive execution approval expired or lacks a timezone",
    )
    candidate = _document(step)
    for row in validated["steps"]:
        for choice in row["methods"]:
            if (
                candidate == choice["plan_step"]
                and content_hash(candidate) == choice["plan_step_digest"]
            ):
                return dict(json_clone(choice))
    raise AdaptiveAuthorizationError(
        "selected method, parameters, or input bindings were not reviewed"
    )


def validate_authorization_binding(
    *,
    authorization: Mapping[str, Any],
    registry: BehaviorRegistry,
    scenario: ScenarioDefinition,
    plan: Mapping[str, Any],
    profile: RunnerProfile,
    target_scope: Mapping[str, Any],
    catalog_authority: Mapping[str, Any] | None = None,
) -> None:
    """Validate the resolved review document against inputs to an approval binding."""
    _require(
        scenario.adaptive_execution is not None, "legacy plans cannot acquire adaptive authority"
    )
    validate_adaptive_authorization(
        authorization,
        expected_digest=str(authorization.get("authorization_digest")),
        registry=registry,
        profile=profile,
        target_scope=target_scope,
        platform=str(authorization.get("platform")),
        catalog_authority=catalog_authority,
    )
    assert scenario.adaptive_execution is not None
    _require(
        authorization.get("scenario_digest") == content_hash(scenario.to_dict())
        and authorization.get("plan_digest") == content_hash(plan)
        and authorization.get("objective") == scenario.purpose
        and authorization.get("policy") == scenario.adaptive_execution.to_dict(),
        "adaptive authorization is not bound to the reviewed scenario and plan",
    )
    for row in authorization["steps"]:
        source = scenario.step(row["step_id"])
        for choice in row["methods"]:
            actual = choice["plan_step"]
            behavior = registry.get_behavior(actual["behavior_id"])
            parameters = {
                spec.name: spec.default for spec in behavior.parameters if spec.default is not None
            }
            parameters.update(source.parameters)
            expected = PlanStep(
                step_id=source.id,
                behavior_id=behavior.id,
                action_id=actual["action_id"],
                simulation_id=behavior.simulation_id,
                parameters=parameters,
                inputs={name: binding.to_dict() for name, binding in source.inputs.items()},
                expected_outputs=tuple(spec.name for spec in behavior.outputs),
                required_capabilities=behavior.capabilities,
                safety_tier=behavior.safety_tier,
                alternates=source.alternates,
                execution_binding=actual.get("execution_binding"),
            )
            _require(
                actual == expected.to_dict(),
                "adaptive authorization parameters, inputs, or operation contract were not reviewed",
            )


__all__ = [
    "AdaptiveAuthorizationError",
    "compile_adaptive_authorization",
    "validate_adaptive_authorization",
    "validate_selected_method",
    "validate_authorization_binding",
]
