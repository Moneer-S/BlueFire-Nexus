"""Orchestrator helpers for reviewed owned-service authority."""

from __future__ import annotations

import inspect
from typing import Any, Mapping

from .contracts import ContractError
from .owned_service_authority import (
    OwnedServiceGrant,
    OwnedServiceScope,
    compile_owned_service_scope,
    mint_owned_service_grant,
    profile_policy_digest,
)
from .tool_adapters.service_journal import ServiceIntentJournal
from .tool_adapters.service_lifecycle import OwnedUserService
from .tool_adapters.service_operation_binding import ServiceOperationBinding
from .util import content_hash


def compile_run_scope(
    value: Mapping[str, Any] | OwnedServiceScope,
    *,
    profile: Any,
    scenario_id: str,
    plan_steps: list[Any] | tuple[Any, ...],
    target_scope: Mapping[str, Any],
    service_journal: ServiceIntentJournal | None,
) -> tuple[OwnedServiceScope, ServiceOperationBinding]:
    scope = compile_owned_service_scope(
        value.to_dict() if isinstance(value, OwnedServiceScope) else value,
        profile=profile,
    )
    document = scope.to_dict()
    matching_steps = [
        step
        for step in plan_steps
        if step.step_id == document["step_id"] and step.action_id == document["action_id"]
    ]
    if (
        document["scenario_id"] != scenario_id
        or len(matching_steps) != 1
        or document["target_scope_digest"] != content_hash(target_scope)
        or document["profile_policy_digest"] != profile_policy_digest(profile)
    ):
        raise ContractError(
            "owned-service scope does not match the exact reviewed plan and profile"
        )
    return scope, pending_service_operation_binding(service_journal, scope)


def compile_run_scope_orchestrator(
    value: Mapping[str, Any] | OwnedServiceScope | None,
    *,
    profile: Any,
    scenario_id: str,
    plan_steps: list[Any] | tuple[Any, ...],
    target_scope: Mapping[str, Any],
    service_journal: ServiceIntentJournal | None,
) -> tuple[OwnedServiceScope | None, ServiceOperationBinding | None]:
    if value is None:
        return None, None
    return compile_run_scope(
        value,
        profile=profile,
        scenario_id=scenario_id,
        plan_steps=plan_steps,
        target_scope=target_scope,
        service_journal=service_journal,
    )


def pending_service_operation_binding(
    journal: ServiceIntentJournal | None,
    scope: OwnedServiceScope,
    *,
    expected_revision: int | None = None,
) -> ServiceOperationBinding:
    """Read one current pending journal record bound to the reviewed scope."""

    if not isinstance(journal, ServiceIntentJournal):
        raise ContractError("owned-service execution requires a configured service intent journal")
    identity = OwnedUserService.from_mapping(scope.identity_mapping())
    record = journal.get(identity.digest)
    revision = record.get("revision")
    if type(revision) is not int or (
        expected_revision is not None and revision != expected_revision
    ):
        raise ContractError("owned-service pending journal record changed before dispatch")
    document = scope.to_dict()
    binding = journal.pending_binding(
        identity.digest,
        revision,
        reviewed_scope_digest=scope.digest,
        manager_installation_digest=document["installations"]["manager"]["digest"],
        payload_installation_digest=document["installations"]["payload"]["digest"],
    )
    if not isinstance(binding, ServiceOperationBinding):
        raise ContractError("service journal returned an invalid pending operation binding")
    return binding


def recheck_pending_service_operation_binding(
    journal: ServiceIntentJournal | None,
    scope: OwnedServiceScope | None,
    expected: ServiceOperationBinding | None,
) -> ServiceOperationBinding:
    """Re-read the captured journal revision and refuse any changed intent."""

    if not isinstance(scope, OwnedServiceScope) or not isinstance(
        expected, ServiceOperationBinding
    ):
        raise ContractError("owned-service dispatch has no captured pending journal binding")
    revision = expected.to_dict()["journal_revision"]
    current = pending_service_operation_binding(journal, scope, expected_revision=revision)
    if current != expected:
        raise ContractError("owned-service pending journal record changed before dispatch")
    return current


def validate_approval_scope_binding(
    approval_binding: Mapping[str, Any], scope: OwnedServiceScope | None
) -> None:
    if scope is not None and approval_binding.get("owned_service_scope_digest") != scope.digest:
        raise ContractError("Execute approval does not bind the exact owned-service scope")


def validate_run_options(
    scope: Mapping[str, Any] | OwnedServiceScope | None,
    service_journal_configured: bool,
    *,
    mode: Any,
    execute_mode: Any,
    replay: Any,
    replay_checkpoint: Any,
    resume_from_step_id: Any,
) -> None:
    if scope is not None and mode is not execute_mode:
        raise ContractError("owned-service scope requires Execute mode")
    if scope is not None and (
        replay is not None or replay_checkpoint is not None or resume_from_step_id is not None
    ):
        raise ContractError("owned-service Execute cannot replay or resume a previous run")
    if scope is not None and not service_journal_configured:
        raise ContractError("owned-service execution requires a configured service intent journal")


def mint_step_grant(
    scope: OwnedServiceScope | None,
    *,
    approval_record: Mapping[str, Any] | None,
    approval_binding: Mapping[str, Any] | None,
    operation_binding: ServiceOperationBinding | None,
    run_id: str,
    step: Any,
    manifest: Mapping[str, Any],
    sealed_profile: Mapping[str, Any],
    task_id: str,
) -> OwnedServiceGrant | None:
    if scope is None:
        return None
    document = scope.to_dict()
    if document["step_id"] != step.step_id or document["action_id"] != step.action_id:
        return None
    if approval_record is None or approval_binding is None:
        raise ContractError("owned-service dispatch requires its consumed approval binding")
    if not isinstance(operation_binding, ServiceOperationBinding):
        raise ContractError("owned-service dispatch requires a committed pending journal binding")
    return mint_owned_service_grant(
        scope=scope,
        claimed_approval=approval_record,
        approval_binding=approval_binding,
        operation_binding=operation_binding,
        run_id=run_id,
        manifest=manifest,
        sealed_profile=sealed_profile,
        task_id=task_id,
    )


def service_grant_kwargs(
    runner: Any,
    execute_task: Any,
    grant: OwnedServiceGrant | None,
) -> dict[str, Any]:
    if grant is None:
        return {}
    try:
        parameters: Mapping[str, inspect.Parameter] = inspect.signature(execute_task).parameters
    except (TypeError, ValueError):
        parameters = {}
    parameter = parameters.get("owned_service_grant")
    if (
        getattr(runner, "owned_service_grant_protocol", None) != grant.to_dict()["schema_version"]
        or parameter is None
        or parameter.kind
        not in {inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.KEYWORD_ONLY}
    ):
        raise ContractError(
            "runner has no authenticated owned-service grant admission for the reviewed version"
        )
    return {"owned_service_grant": grant.to_dict()}


def owned_service_digest(scope: OwnedServiceScope | None) -> str | None:
    return None if scope is None else scope.digest


def owned_service_policy(scope: OwnedServiceScope | None) -> dict[str, Any]:
    return {} if scope is None else {"owned_service_scope": scope.to_dict()}


def plan_has_owned_service(plan_steps: list[Any] | tuple[Any, ...]) -> bool:
    return any(step.action_id == "owned.user_service.fixed_wait.v1" for step in plan_steps)
