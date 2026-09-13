from __future__ import annotations

import copy

import pytest

from bluefire.runner_client import RunnerReadinessError, canonical_runner_inventory
from bluefire.runner_inventory import validate_builtin_action_inventory
from bluefire.util import content_hash


def _provider_runtime() -> dict[str, object]:
    contract: dict[str, object] = {
        "kind": "wasm",
        "abi_version": "bluefire.provider-abi.v1",
        "runtime_version": "wasmi-1.1.0",
        "readiness": "ready",
        "no_host_imports": True,
        "hard_limits": {
            "max_module_bytes": 2 * 1024 * 1024,
            "max_memory_bytes": 16 * 1024 * 1024,
            "max_input_bytes": 1024 * 1024,
            "max_output_bytes": 1024 * 1024,
            "fuel": 100_000_000,
        },
    }
    return {**contract, "contract_digest": content_hash(contract)}


def _raw_inventory() -> dict[str, object]:
    return {
        "schema_version": "bluefire.runner-inventory.v1",
        "runner_id": "bluefire-rust-runner.v1",
        "runner_version": "0.1.0",
        "action_sdk_version": "bluefire.runner-action-sdk.v1",
        "receipt_protocol": "bluefire.cleanup-receipt.v1",
        "platform": "windows",
        "actions": [
            {
                "schema_version": "bluefire.runner-action-sdk.v1",
                "action_id": "sandbox.cleanup.v1",
                "action_version": "1.1.0",
                "readiness": "ready",
            }
        ],
        "provider_runtimes": [_provider_runtime()],
    }


def test_provider_runtime_inventory_is_canonical_and_core_independent() -> None:
    raw = _raw_inventory()
    canonical = canonical_runner_inventory(raw)

    assert canonical["provider_runtimes"] == [_provider_runtime()]
    assert [row["action_id"] for row in canonical["actions"]] == ["sandbox.cleanup.v1"]
    validate_builtin_action_inventory(
        canonical,
        required_action_ids={"sandbox.cleanup.v1"},
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "digest",
        "imports",
        "limit",
        "duplicate",
        "unknown",
    ],
)
def test_provider_runtime_inventory_refuses_malformed_contracts(mutation: str) -> None:
    inventory = _raw_inventory()
    runtimes = inventory["provider_runtimes"]
    assert isinstance(runtimes, list)
    runtime = runtimes[0]
    assert isinstance(runtime, dict)
    if mutation == "digest":
        runtime["contract_digest"] = "sha256:" + "0" * 64
    elif mutation == "imports":
        runtime["no_host_imports"] = False
    elif mutation == "limit":
        limits = runtime["hard_limits"]
        assert isinstance(limits, dict)
        limits["fuel"] = 0
    elif mutation == "duplicate":
        runtimes.append(copy.deepcopy(runtime))
    else:
        runtime["executable"] = "provider.exe"

    with pytest.raises(RunnerReadinessError):
        canonical_runner_inventory(inventory)


def test_legacy_inventory_keeps_its_historical_canonical_shape() -> None:
    raw = _raw_inventory()
    raw.pop("provider_runtimes")

    assert "provider_runtimes" not in canonical_runner_inventory(raw)
