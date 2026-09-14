from __future__ import annotations

import copy
import json
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path
from typing import Any, Mapping, cast

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from bluefire.action_packages import canonical_public_key_b64u
from bluefire.api import APIError
from bluefire.config import RunnerProfile
from bluefire.contracts import ExecutionMode
from bluefire.runner_client import RunnerReadinessError
from bluefire.service import BlueFireService
from bluefire.util import content_hash
from tests_platform.test_action_provider_packages import (
    ACTION_ID,
    ARTIFACT,
    KEY_ID,
    PUBLISHER_ID,
    _manifest,
    _runner_inventory,
    _signed,
)
from tests_platform.test_service import EXECUTE_PROFILE_ACTIONS, _ready_inventory

ROOT = Path(__file__).resolve().parents[1]
PACKAGE_ID = str(_manifest()["package_id"])
PRIVATE_PACKAGE_FIELDS = {
    "artifact_hex",
    "canonical_envelope_bytes",
    "canonical_content_bytes",
}


class ProviderInventoryRunner:
    def __init__(self) -> None:
        inventory = dict(_ready_inventory(actions=EXECUTE_PROFILE_ACTIONS))
        inventory["platform"] = "windows"
        inventory["provider_runtimes"] = copy.deepcopy(_runner_inventory()["provider_runtimes"])
        self.document = inventory

    def inventory(self) -> Mapping[str, Any]:
        return copy.deepcopy(self.document)

    def execute(
        self,
        _manifest: Mapping[str, Any],
        _profile: Mapping[str, Any],
    ) -> Mapping[str, Any]:  # pragma: no cover - service readiness tests do not dispatch
        raise AssertionError("provider service test runner must not dispatch")


@pytest.fixture
def provider_service(
    tmp_path: Path,
) -> Iterator[tuple[BlueFireService, ProviderInventoryRunner]]:
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    runner = ProviderInventoryRunner()
    service = BlueFireService(
        project_root=ROOT,
        runs_dir=tmp_path / "runs",
        product_db_path=tmp_path / "product.sqlite3",
        runner_factory=lambda _profile: (runner, sandbox),
    )
    try:
        yield service, runner
    finally:
        service.close()


def _execute_profile(service: BlueFireService) -> RunnerProfile:
    return next(
        profile for profile in service._runner_profiles() if profile.mode is ExecutionMode.EXECUTE
    )


def _trust_and_install(
    service: BlueFireService,
    private_key: Ed25519PrivateKey,
) -> None:
    service.trust_action_package_publisher(
        {
            "publisher_id": PUBLISHER_ID,
            "key_id": KEY_ID,
            "public_key": canonical_public_key_b64u(private_key.public_key()),
            "provenance": {
                "source": "local provider service test",
                "purpose": "provider lifecycle acceptance",
            },
            "trusted_by": "provider-reviewer",
        }
    )
    service.install_action_package(
        {
            "envelope": json.loads(_signed(private_key)),
            "installed_by": "provider-installer",
        }
    )


def _activate(service: BlueFireService) -> Mapping[str, Any]:
    return cast(
        Mapping[str, Any],
        service.activate_action_package(
            PACKAGE_ID,
            "1.2.3",
            {
                "runner_profile_id": _execute_profile(service).id,
                "activated_by": "provider-operator",
                "reason": "reviewed isolated provider service acceptance",
            },
        ),
    )


def _assert_public(value: Any) -> None:
    assert not isinstance(value, bytes)
    if isinstance(value, Mapping):
        assert PRIVATE_PACKAGE_FIELDS.isdisjoint(value)
        for child in value.values():
            _assert_public(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _assert_public(child)


def test_provider_activation_readiness_deactivation_and_private_history(
    provider_service: tuple[BlueFireService, ProviderInventoryRunner],
) -> None:
    service, _runner = provider_service
    private_key = Ed25519PrivateKey.generate()
    base_profile = _execute_profile(service)
    assert ACTION_ID not in base_profile.enabled_actions

    _trust_and_install(service, private_key)
    activated = _activate(service)
    effective_profile = service._profile(base_profile.id, ExecutionMode.EXECUTE)
    assert effective_profile is not None
    assert ACTION_ID in effective_profile.enabled_actions

    _transport, _sandbox, readiness = service._execute_readiness_boundary(effective_profile)
    row = next(item for item in readiness["enabled_actions"] if item["action_id"] == ACTION_ID)
    assert len(row["provider_bindings"]) == 1
    readiness_binding = row["provider_bindings"][0]
    binding = service._catalog_snapshot.execution_binding(
        str(readiness_binding["logical_behavior_id"]),
        ACTION_ID,
    )
    assert binding is not None
    assert row == {
        "action_id": ACTION_ID,
        "action_version": binding["package_version"],
        "readiness": "ready",
        "contract_digest": binding["runtime_contract_digest"],
        "execution_model": "wasm_provider_v1",
        "package_id": binding["package_id"],
        "package_version": binding["package_version"],
        "package_digest": binding["package_digest"],
        "content_digest": binding["content_digest"],
        "program_digest": binding["program_digest"],
        "action_contract_digest": binding["action_contract_digest"],
        "runtime_contract_digest": binding["runtime_contract_digest"],
        "provider_runtime_contract_digest": binding["provider_runtime_contract_digest"],
        "provider": activated["catalog"]["packages"][0]["provider"],
        "provider_bindings": [binding],
    }
    assert "native_action_id" not in row
    assert service._catalog_snapshot.profile_native_action_requirements(effective_profile) == ()

    inventory = service.action_packages()
    assert inventory["execution_boundary"] == "signed-reviewed-opcodes-and-isolated-wasm-providers"
    _assert_public(inventory)
    _assert_public(service.action_package(PACKAGE_ID, version="1.2.3"))
    _assert_public(activated)
    _assert_public(readiness)

    # A managed profile can have persisted the then-valid logical action. The
    # catalog boundary must remove that stale overlay after lifecycle changes.
    managed_overlay = replace(
        base_profile,
        enabled_actions=(*base_profile.enabled_actions, ACTION_ID),
    )
    service._runtime_runner_profiles = tuple(
        managed_overlay if item.id == base_profile.id else item
        for item in service._runner_profiles()
    )
    active_catalog = activated["catalog"]
    deactivated = service.deactivate_action_package(
        PACKAGE_ID,
        "1.2.3",
        {
            "package_digest": activated["package"]["package_digest"],
            "expected_catalog_generation": active_catalog["generation"],
            "expected_catalog_digest": active_catalog["catalog_digest"],
            "deactivated_by": "provider-operator",
            "reason": "verify provider visibility removal",
        },
    )
    assert ACTION_ID not in service.registry.action_ids
    assert service._catalog_snapshot.provider_artifacts == {}
    after_profile = service._profile(base_profile.id, ExecutionMode.EXECUTE)
    assert after_profile is not None
    assert ACTION_ID not in after_profile.enabled_actions
    catalog_profile = next(
        item for item in service.catalog()["runner_profiles"] if item["id"] == base_profile.id
    )
    assert ACTION_ID not in catalog_profile["enabled_actions"]
    _transport, _sandbox, after_readiness = service._execute_readiness_boundary(after_profile)
    assert ACTION_ID not in {item["action_id"] for item in after_readiness["enabled_actions"]}

    removed = service.remove_action_package(
        PACKAGE_ID,
        "1.2.3",
        {
            "package_digest": activated["package"]["package_digest"],
            "expected_catalog_generation": deactivated["catalog"]["generation"],
            "expected_catalog_digest": deactivated["catalog"]["catalog_digest"],
            "removed_by": "provider-operator",
            "reason": "verify stale managed profile reconciliation",
        },
    )
    removed_profile = service._profile(base_profile.id, ExecutionMode.EXECUTE)
    assert removed_profile is not None
    assert ACTION_ID not in removed_profile.enabled_actions

    historical = service._load_action_catalog_snapshot(active_catalog["generation"])
    historical_profile = historical.profile(base_profile)
    assert historical.profile_provider_artifacts(historical_profile) == (
        {
            "artifact_sha256": binding["artifact_sha256"],
            "artifact_size": len(ARTIFACT),
            "artifact_hex": ARTIFACT.hex(),
        },
    )
    _assert_public(deactivated)
    _assert_public(removed)
    _assert_public(historical.to_dict())


@pytest.mark.parametrize("drift", ["runtime_digest", "hard_limits"])
def test_provider_readiness_refuses_runtime_contract_or_limit_drift(
    provider_service: tuple[BlueFireService, ProviderInventoryRunner],
    drift: str,
) -> None:
    service, runner = provider_service
    private_key = Ed25519PrivateKey.generate()
    _trust_and_install(service, private_key)
    _activate(service)
    profile = service._profile(_execute_profile(service).id, ExecutionMode.EXECUTE)
    assert profile is not None

    runtime = runner.document["provider_runtimes"][0]
    if drift == "runtime_digest":
        runtime["runtime_version"] = "wasmi-drifted"
    else:
        runtime["hard_limits"]["fuel"] += 1
    runtime_contract = {key: value for key, value in runtime.items() if key != "contract_digest"}
    runtime["contract_digest"] = content_hash(runtime_contract)

    with pytest.raises(RunnerReadinessError, match="changed after package activation"):
        service._execute_readiness_boundary(profile)


@pytest.mark.parametrize("incompatibility", ["capability", "safe_tier", "platform"])
def test_provider_activation_refuses_incompatible_base_profile(
    provider_service: tuple[BlueFireService, ProviderInventoryRunner],
    incompatibility: str,
) -> None:
    service, _runner = provider_service
    profile = _execute_profile(service)
    if incompatibility == "capability":
        changed = replace(
            profile,
            capabilities=tuple(item for item in profile.capabilities if item != "native.execution"),
        )
    elif incompatibility == "safe_tier":
        changed = replace(
            profile,
            safety_tiers=tuple(item for item in profile.safety_tiers if item.value != "safe"),
        )
    else:
        changed = replace(profile, platforms=("linux",))
    service._runtime_runner_profiles = tuple(
        changed if item.id == profile.id else item for item in service._runner_profiles()
    )
    _trust_and_install(service, Ed25519PrivateKey.generate())

    with pytest.raises(APIError) as refused:
        _activate(service)

    assert refused.value.code == "action_package_activation_refused"
    assert service._catalog_snapshot.generation == 0
    assert ACTION_ID not in service.registry.action_ids
