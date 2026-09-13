from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from bluefire.action_catalog import (
    ActionCatalogError,
    ActionCatalogSnapshot,
    ActivatedActionPackage,
)
from bluefire.action_packages import VerifiedActionPackageActivation
from bluefire.config import RunnerProfile, load_config
from bluefire.provider_runner_contracts import (
    PROVIDER_BINDING_SCHEMA,
    canonical_provider_binding,
)
from bluefire.registry import load_builtin_registry
from bluefire.util import content_hash
from tests_platform.test_action_provider_packages import (
    ACTION_ID,
    ARTIFACT,
    BEHAVIOR_ID,
    PROVIDER_ID,
    _activation,
    _runner_inventory,
)

ROOT = Path(__file__).resolve().parents[1]


def _catalog_digest(activation: VerifiedActionPackageActivation) -> str:
    package = activation.package
    return content_hash(
        {
            "schema_version": "bluefire.active-action-package-catalog.v1",
            "packages": [
                {
                    "package_id": package.manifest.package_id,
                    "version": package.manifest.version,
                    "package_digest": package.package_digest,
                    "content_digest": package.content_digest,
                }
            ],
        }
    )


def _snapshot() -> ActionCatalogSnapshot:
    activation = _activation(Ed25519PrivateKey.generate(), _runner_inventory())
    return ActionCatalogSnapshot.compose(
        load_builtin_registry(),
        generation=1,
        catalog_digest=_catalog_digest(activation),
        active_packages=(ActivatedActionPackage(generation=1, activation=activation),),
    )


def _execute_profile() -> RunnerProfile:
    config = load_config(ROOT / "config" / "bluefire.example.yaml")
    return next(profile for profile in config.runner_profiles if profile.mode.value == "execute")


def test_provider_catalog_seals_runtime_binding_without_core_opcode_alias() -> None:
    snapshot = _snapshot()

    binding = snapshot.execution_binding(BEHAVIOR_ID, ACTION_ID)
    assert binding is not None
    assert binding == canonical_provider_binding(binding, context="test provider binding")
    assert binding["schema_version"] == PROVIDER_BINDING_SCHEMA
    assert binding["provider_id"] == PROVIDER_ID
    assert binding["logical_action_id"] == ACTION_ID
    assert binding["capabilities"] == ["native_execution"]
    assert binding["inputs"] == []
    assert binding["mutates"] is False
    assert binding["cleanup_action_id"] is None
    assert "runner_opcode" not in binding
    assert (BEHAVIOR_ID, ACTION_ID) not in snapshot.native_action_requirements
    assert ACTION_ID not in load_builtin_registry().action_ids


def test_provider_artifact_is_private_but_exactly_available_to_compatible_profile() -> None:
    snapshot = _snapshot()
    profile = snapshot.profile(_execute_profile())

    assert ACTION_ID in profile.enabled_actions
    bindings = snapshot.profile_provider_bindings(profile)
    assert len(bindings) == 1
    assert bindings[0]["logical_action_id"] == ACTION_ID
    artifacts = snapshot.profile_provider_artifacts(profile)
    assert artifacts == (
        {
            "artifact_sha256": bindings[0]["artifact_sha256"],
            "artifact_size": len(ARTIFACT),
            "artifact_hex": ARTIFACT.hex(),
        },
    )
    assert snapshot.profile_action_bindings(profile) == ()

    public_document = snapshot.to_dict()
    serialized = json.dumps(public_document, sort_keys=True)
    assert "artifact_hex" not in serialized
    assert ARTIFACT.hex() not in serialized
    assert public_document["packages"][0]["execution_model"] == "wasm_provider_v1"
    assert public_document["packages"][0]["provider"]["provider_id"] == PROVIDER_ID


def test_provider_profile_requires_capability_tier_and_platform_compatibility() -> None:
    snapshot = _snapshot()
    base = _execute_profile()

    no_capability = replace(
        base,
        capabilities=tuple(item for item in base.capabilities if item != "native.execution"),
    )
    no_safe_tier = replace(
        base,
        safety_tiers=tuple(item for item in base.safety_tiers if item.value != "safe"),
    )
    no_platform = replace(base, platforms=("linux", "macos"))

    assert ACTION_ID not in snapshot.profile(no_capability).enabled_actions
    assert ACTION_ID not in snapshot.profile(no_safe_tier).enabled_actions
    assert ACTION_ID not in snapshot.profile(no_platform).enabled_actions


def test_catalog_refuses_provider_artifact_changed_after_package_verification() -> None:
    activation = _activation(Ed25519PrivateKey.generate(), _runner_inventory())
    changed_package = replace(activation.package, _provider_artifact_bytes=b"changed!")
    changed_activation = replace(activation, package=changed_package)

    with pytest.raises(ActionCatalogError, match="artifact changed"):
        ActionCatalogSnapshot.compose(
            load_builtin_registry(),
            generation=1,
            catalog_digest=_catalog_digest(activation),
            active_packages=(ActivatedActionPackage(generation=1, activation=changed_activation),),
        )


def test_catalog_refuses_provider_activation_descriptor_substitution() -> None:
    activation = _activation(Ed25519PrivateKey.generate(), _runner_inventory())
    changed_runtime = replace(
        activation.provider_bindings[0],
        artifact_sha256="sha256:" + "0" * 64,
    )
    changed_activation = replace(activation, provider_bindings=(changed_runtime,))

    with pytest.raises(ActionCatalogError, match="changed its signed package descriptor"):
        ActionCatalogSnapshot.compose(
            load_builtin_registry(),
            generation=1,
            catalog_digest=_catalog_digest(activation),
            active_packages=(ActivatedActionPackage(generation=1, activation=changed_activation),),
        )
