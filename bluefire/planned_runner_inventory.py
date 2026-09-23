"""Execution-layer validation for the exact runner contracts used by a plan."""

from __future__ import annotations

from collections.abc import Collection, Mapping, Sequence
from typing import Any

from .provider_runner_contracts import (
    ProviderRunnerContractError,
    canonical_provider_bindings,
)
from .runner_client import RunnerReadinessError, canonical_runner_inventory
from .runner_inventory import (
    RunnerInventoryAuthorityError,
    validate_builtin_action_inventory,
)


class PlannedRunnerInventoryError(ValueError):
    """The runner inventory cannot satisfy one planned execution contract."""


def validate_planned_runner_inventory(
    inventory: Mapping[str, Any],
    *,
    required_action_ids: Collection[str],
    provider_bindings: Sequence[Mapping[str, Any]],
    structural_tool_action_ids: Collection[str] = (),
) -> None:
    """Validate planned native and provider contracts at the execution boundary."""

    try:
        if required_action_ids:
            validate_builtin_action_inventory(
                inventory,
                required_action_ids=required_action_ids,
                structural_tool_action_ids=structural_tool_action_ids,
            )
        providers = canonical_provider_bindings(
            tuple(provider_bindings),
            context="planned provider bindings",
        )
        if providers:
            canonical_inventory = canonical_runner_inventory(inventory)
            raw_runtimes = canonical_inventory.get("provider_runtimes")
            if not isinstance(raw_runtimes, list):
                raise RunnerReadinessError("Runner provider runtime is unavailable.")
            runtimes = {
                (str(runtime["kind"]), str(runtime["abi_version"])): runtime
                for runtime in raw_runtimes
            }
            for binding in providers:
                runtime = runtimes.get(("wasm", str(binding["abi_version"])))
                if (
                    runtime is None
                    or runtime.get("readiness") != "ready"
                    or runtime.get("no_host_imports") is not True
                    or runtime.get("contract_digest") != binding["provider_runtime_contract_digest"]
                ):
                    raise RunnerReadinessError(
                        "Runner provider runtime does not match the planned contract."
                    )
                hard_limits = runtime.get("hard_limits")
                if not isinstance(hard_limits, Mapping) or any(
                    binding["limits"][field] > hard_limits.get(field, 0)
                    for field in binding["limits"]
                ):
                    raise RunnerReadinessError(
                        "Runner provider runtime cannot satisfy the planned limits."
                    )
    except (
        ProviderRunnerContractError,
        RunnerInventoryAuthorityError,
        RunnerReadinessError,
    ) as exc:
        raise PlannedRunnerInventoryError(
            "Rust runner inventory does not satisfy the planned action contracts"
        ) from exc
