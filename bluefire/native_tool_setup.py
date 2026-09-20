"""Operator-requested, read-only tool setup against one saved runner profile."""

from __future__ import annotations

from http import HTTPStatus
from typing import Any, Mapping

from .application_errors import APIError
from .contracts import ContractError, ExecutionMode
from .native_tool_candidate import validate_candidate_inspection
from .native_tool_installations import canonical_native_tool_candidate
from .native_tool_setup_transport import managed_setup_transport
from .registry import RegistryError
from .runner_client import canonical_runner_inventory, runner_transport_identity
from .runner_lifecycle import RunnerLifecycleError
from .runner_transport_errors import RunnerTransportError
from .tool_adapters.chmod import ADAPTER_ID


def inspect_profile_tool(
    service: Any, profile_id: str, request: Mapping[str, Any]
) -> Mapping[str, Any]:
    resource = service._runtime_resource("runner_profile", profile_id)
    try:
        candidate = canonical_native_tool_candidate(request)
        profile = service._validated_runner_profile(resource["document"], profile_id)
        if (
            candidate["action_id"] != ADAPTER_ID
            or profile.mode is not ExecutionMode.EXECUTE
            or tuple(profile.platforms) != ("linux",)
            or ADAPTER_ID not in profile.enabled_actions
            or ADAPTER_ID in profile.blocked_actions
        ):
            raise ContractError("selected profile cannot set up this method")
    except (ContractError, RegistryError, KeyError, TypeError, ValueError):
        raise APIError(
            HTTPStatus.UNPROCESSABLE_ENTITY,
            "native_tool_setup_invalid",
            "Choose an enabled Linux method in a saved Execute profile and a valid tool location and version.",
        ) from None

    try:
        factory = service._native_tool_setup_runner_factory
        runner = (
            factory(profile)[0]
            if factory is not None
            else managed_setup_transport(service.runner_lifecycle)
        )
        before = runner.inventory()
        canonical = canonical_runner_inventory(before)
        identity = runner_transport_identity(runner, before)
        # Admission is independent of the model, UI and eventual tool record.
        from .native_tool_execution_readiness import reviewed_native_tool_descriptor

        reviewed_native_tool_descriptor(
            before, canonical["actions"], action_id=candidate["action_id"]
        )
        inspector = getattr(runner, "inspect_native_tool_candidate", None)
        if not callable(inspector):
            raise ContractError("candidate inspection is unavailable")
        result = validate_candidate_inspection(candidate, inspector(candidate))
        after = runner.inventory()
        if (
            canonical_runner_inventory(after) != canonical
            or runner_transport_identity(runner, after) != identity
        ):
            raise ContractError("runner changed during inspection")
        current = service._runtime_resource("runner_profile", profile_id)
        if current.get("digest") != resource.get("digest") or current.get("status") != resource.get(
            "status"
        ):
            raise ContractError("profile changed during inspection")
        return result
    except RunnerLifecycleError:
        raise APIError(
            HTTPStatus.CONFLICT,
            "native_tool_runner_unavailable",
            "Start the local runner in Runners, then inspect this installation. The draft does not need activation.",
        ) from None
    except (ContractError, RunnerTransportError, OSError, TypeError, ValueError):
        raise APIError(
            HTTPStatus.CONFLICT,
            "native_tool_inspection_unavailable",
            "The selected runner could not inspect this tool consistently. Check its connection and installed methods, then inspect again.",
        ) from None
