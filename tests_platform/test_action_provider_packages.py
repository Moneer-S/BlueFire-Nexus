from __future__ import annotations

import copy
import hashlib
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from bluefire.action_packages import (
    ACTION_PACKAGE_PAYLOAD_V2_SCHEMA,
    ACTION_PACKAGE_V2_SCHEMA,
    WASM_PROVIDER_ABI_V1,
    WASM_PROVIDER_PROGRAM_SCHEMA,
    ActionPackageError,
    WasmProviderProgram,
    audit_action_package,
    build_signed_action_package,
    provider_action_contract_digest,
    verify_action_package,
    verify_action_package_for_activation,
)
from bluefire.contracts import ActionDefinition
from bluefire.util import canonical_json_bytes, content_hash

PUBLISHER_ID = "acme.security"
KEY_ID = "release-2026"
BEHAVIOR_ID = "acme.native.echo-behavior.v1"
ACTION_ID = "acme.native.echo-action.v1"
PROVIDER_ID = "acme.native.echo-provider.v1"
ARTIFACT = b"\0asm\x01\0\0\0"


def _source_provenance() -> dict[str, Any]:
    return {
        "source": "ACME reviewed portable provider",
        "reference": "urn:acme:bluefire-provider:echo:sha256:" + "b" * 64,
        "license": "MIT",
        "derived": False,
        "notes": "Source-built deterministic WebAssembly provider.",
    }


def _output() -> dict[str, Any]:
    return {
        "name": "result",
        "type": "artifact.native.provider-result.v1",
        "description": "Bounded provider result.",
    }


def _parameter() -> dict[str, Any]:
    return {
        "name": "repeat_count",
        "type": "integer",
        "required": False,
        "default": 1,
        "enum": [1, 2, 3],
        "minimum": 1,
        "maximum": 3,
        "description": "Bounded repeat count.",
    }


def _action() -> dict[str, Any]:
    return {
        "schema_version": "bluefire.action.v1",
        "id": ACTION_ID,
        "title": "Run portable echo provider",
        "purpose": "Exercise a signed, bounded provider contract.",
        "safety_tier": "safe",
        "capabilities": ["native.execution"],
        "platforms": ["windows"],
        "inputs": [],
        "outputs": [_output()],
        "parameters": [_parameter()],
        "mutates": False,
        "cleanup_action_id": None,
        "provenance": _source_provenance(),
    }


def _behavior() -> dict[str, Any]:
    return {
        "schema_version": "bluefire.behavior.v1",
        "id": BEHAVIOR_ID,
        "title": "Portable provider behavior",
        "purpose": "Expose one independently executable portable provider action.",
        "execution_state": "action",
        "safety_tier": "safe",
        "platforms": ["windows"],
        "techniques": ["T1204"],
        "capabilities": ["native.execution"],
        "inputs": [],
        "outputs": [_output()],
        "parameters": [_parameter()],
        "action_ids": [ACTION_ID],
        "telemetry": ["native.provider.completed"],
        "detection_hints": ["Correlate provider invocation with its signed package digest."],
        "provenance": _source_provenance(),
        "limitations": ["No host imports, artifact inputs, persistence, or network access."],
    }


def _limits() -> dict[str, int]:
    return {
        "max_module_bytes": 64 * 1024,
        "max_memory_bytes": 1024 * 1024,
        "max_input_bytes": 4096,
        "max_output_bytes": 4096,
        "fuel": 10_000,
    }


def _manifest() -> dict[str, Any]:
    return {
        "package_id": "acme.native-provider-pack",
        "version": "1.2.3",
        "compatibility": {
            "minimum_bluefire_version": "0.1.0",
            "maximum_bluefire_version_exclusive": "1.0.0",
        },
        "license": {
            "spdx_id": "MIT",
            "notice": "Copyright 2026 ACME Security; redistributed under MIT.",
        },
        "provenance": {
            "publisher_id": PUBLISHER_ID,
            "source": "ACME reviewed provider package",
            "reference": "urn:acme:bluefire-provider-package:1.2.3",
            "revision": "a" * 40,
        },
        "platforms": ["windows"],
        "capabilities": ["native.execution"],
        "safety_tiers": ["safe"],
        "behavior_ids": [BEHAVIOR_ID],
        "action_ids": [ACTION_ID],
        "provider": {
            "kind": "wasm",
            "provider_id": PROVIDER_ID,
            "abi_version": WASM_PROVIDER_ABI_V1,
            "artifact_sha256": "sha256:" + hashlib.sha256(ARTIFACT).hexdigest(),
            "artifact_size": len(ARTIFACT),
            "limits": _limits(),
        },
    }


def _payload() -> dict[str, Any]:
    action = _action()
    definition = ActionDefinition.from_mapping(action)
    return {
        "schema_version": ACTION_PACKAGE_PAYLOAD_V2_SCHEMA,
        "behaviors": [_behavior()],
        "actions": [
            {
                "definition": action,
                "program": {
                    "schema_version": WASM_PROVIDER_PROGRAM_SCHEMA,
                    "provider_id": PROVIDER_ID,
                    "action_contract_digest": provider_action_contract_digest(definition),
                },
            }
        ],
        "artifact_hex": ARTIFACT.hex(),
    }


def _signed(
    private_key: Ed25519PrivateKey,
    *,
    manifest: dict[str, Any] | None = None,
    payload: dict[str, Any] | None = None,
) -> bytes:
    return build_signed_action_package(
        manifest=_manifest() if manifest is None else manifest,
        payload=_payload() if payload is None else payload,
        key_id=KEY_ID,
        private_key=private_key,
    )


def _trust(private_key: Ed25519PrivateKey) -> dict[tuple[str, str], Any]:
    return {(PUBLISHER_ID, KEY_ID): private_key.public_key()}


def _runner_inventory(
    *,
    readiness: str = "ready",
    hard_limits: dict[str, int] | None = None,
    include_runtime: bool = True,
) -> dict[str, Any]:
    inventory: dict[str, Any] = {
        "schema_version": "bluefire.runner-inventory.v1",
        "runner_id": "bluefire-runner",
        "runner_version": "0.1.0",
        "action_sdk_version": "1.0.0",
        "receipt_protocol": "bluefire.runner-receipt.v1",
        "platform": "windows",
        "actions": [],
    }
    if include_runtime:
        runtime_contract = {
            "kind": "wasm",
            "abi_version": WASM_PROVIDER_ABI_V1,
            "runtime_version": "wasmi-1.1.0",
            "readiness": readiness,
            "no_host_imports": True,
            "hard_limits": hard_limits
            or {
                "max_module_bytes": 128 * 1024,
                "max_memory_bytes": 2 * 1024 * 1024,
                "max_input_bytes": 8192,
                "max_output_bytes": 8192,
                "fuel": 20_000,
            },
        }
        inventory["provider_runtimes"] = [
            {**runtime_contract, "contract_digest": content_hash(runtime_contract)}
        ]
    return inventory


def _activation(private_key: Ed25519PrivateKey, inventory: dict[str, Any]) -> Any:
    return verify_action_package_for_activation(
        _signed(private_key),
        trusted_signers=_trust(private_key),
        bluefire_version="0.1.0",
        runner_inventory=inventory,
        runner_identity_digest="sha256:" + "1" * 64,
        expected_catalog_generation=0,
        expected_catalog_digest=content_hash(
            {"schema_version": "bluefire.active-action-package-catalog.v1", "packages": []}
        ),
    )


def test_v2_package_verifies_provider_descriptor_artifact_and_action_contract() -> None:
    private_key = Ed25519PrivateKey.generate()
    envelope = _signed(private_key)

    verified = verify_action_package(
        envelope,
        trusted_signers=_trust(private_key),
        bluefire_version="0.1.0",
        platform="windows",
    )

    assert verified.canonical_content_bytes == canonical_json_bytes(
        {
            "schema_version": ACTION_PACKAGE_V2_SCHEMA,
            "manifest": _manifest(),
            "payload": _payload(),
        }
    )
    assert verified.provider == verified.manifest.provider
    assert verified.provider is not None
    assert verified.provider.provider_id == PROVIDER_ID
    assert verified.provider_artifact_bytes == ARTIFACT
    assert isinstance(verified.actions[0].program, WasmProviderProgram)
    assert (
        verified.actions[0].program.action_contract_digest
        == _payload()["actions"][0]["program"]["action_contract_digest"]
    )
    assert audit_action_package(envelope, trusted_signers=_trust(private_key)) == verified


def test_provider_activation_uses_runtime_binding_without_static_opcode() -> None:
    private_key = Ed25519PrivateKey.generate()

    activation = _activation(private_key, _runner_inventory())

    assert activation.opcode_bindings == ()
    assert len(activation.provider_bindings) == 1
    binding = activation.provider_bindings[0]
    assert binding.provider_id == PROVIDER_ID
    assert binding.abi_version == WASM_PROVIDER_ABI_V1
    assert binding.artifact_size == len(ARTIFACT)
    assert binding.limits.to_dict() == _limits()
    assert (
        binding.runtime_inventory_contract_digest
        == activation.runner_inventory()["provider_runtimes"][0]["contract_digest"]
    )
    activation_document = activation.to_dict()
    assert activation_document["schema_version"] == (
        "bluefire.action-package-activation-binding.v2"
    )
    assert activation_document["opcode_bindings"] == []
    assert activation_document["provider_bindings"] == [binding.to_dict()]

    replayed = verify_action_package_for_activation(
        activation.package.canonical_envelope_bytes,
        trusted_signers=_trust(private_key),
        bluefire_version="0.1.0",
        runner_inventory=activation.runner_inventory(),
        runner_identity_digest=activation.runner_identity_digest,
        expected_catalog_generation=activation.expected_catalog_generation,
        expected_catalog_digest=activation.expected_catalog_digest,
    )
    assert replayed == activation


def _set_path(root: dict[str, Any], path: tuple[str | int, ...], value: Any) -> None:
    current: Any = root
    for component in path[:-1]:
        current = current[component]
    current[path[-1]] = value


@pytest.mark.parametrize(
    ("path", "value", "message"),
    [
        (("payload", "artifact_hex"), ARTIFACT.hex().upper(), "canonical lowercase"),
        (("payload", "artifact_hex"), "00", "WebAssembly module"),
        (("manifest", "provider", "artifact_size"), len(ARTIFACT) + 1, "size does not match"),
        (
            ("manifest", "provider", "artifact_sha256"),
            "sha256:" + "0" * 64,
            "digest does not match",
        ),
        (
            ("payload", "actions", 0, "program", "provider_id"),
            "acme.native.other-provider.v1",
            "different provider",
        ),
        (
            ("payload", "actions", 0, "program", "action_contract_digest"),
            "sha256:" + "0" * 64,
            "does not match its action",
        ),
        (
            ("manifest", "provider", "abi_version"),
            "bluefire.provider-abi.v2",
            "unsupported",
        ),
        (("manifest", "provider", "artifact_size"), 64 * 1024 + 1, "1..=65536"),
        (("manifest", "provider", "limits", "max_module_bytes"), 4, "artifact_size exceeds"),
        (
            ("payload", "actions", 0, "definition", "capabilities"),
            ["native.execution", "network.client"],
            "exactly native.execution",
        ),
        (
            ("payload", "actions", 0, "definition", "safety_tier"),
            "controlled",
            "safe tier",
        ),
        (
            ("payload", "actions", 0, "definition", "inputs"),
            [{"name": "source", "type": "artifact.native.provider-result.v1"}],
            "cannot accept artifact inputs",
        ),
        (
            ("payload", "actions", 0, "definition", "mutates"),
            True,
            "effect-free",
        ),
        (
            ("payload", "actions", 0, "definition", "command"),
            "whoami",
            "forbidden executable field",
        ),
    ],
)
def test_provider_package_rejects_cross_contract_mutations(
    path: tuple[str | int, ...], value: Any, message: str
) -> None:
    private_key = Ed25519PrivateKey.generate()
    document = {"manifest": _manifest(), "payload": _payload()}
    _set_path(document, path, value)

    with pytest.raises(ActionPackageError, match=message):
        _signed(
            private_key,
            manifest=document["manifest"],
            payload=document["payload"],
        )


def test_provider_package_rejects_ambiguous_parameter_contracts() -> None:
    private_key = Ed25519PrivateKey.generate()

    def resignable_document() -> dict[str, Any]:
        document = {"manifest": _manifest(), "payload": _payload()}
        definition = document["payload"]["actions"][0]["definition"]
        document["payload"]["actions"][0]["program"]["action_contract_digest"] = (
            provider_action_contract_digest(
                ActionDefinition.from_mapping(definition, "provider action")
            )
        )
        return document

    nonnumeric = {"manifest": _manifest(), "payload": _payload()}
    nonnumeric_parameter = nonnumeric["payload"]["actions"][0]["definition"]["parameters"][0]
    nonnumeric_parameter.update(
        {
            "type": "string",
            "default": "one",
            "enum": ["one"],
            "minimum": 1,
            "maximum": 3,
        }
    )
    definition = nonnumeric["payload"]["actions"][0]["definition"]
    nonnumeric["payload"]["actions"][0]["program"]["action_contract_digest"] = (
        provider_action_contract_digest(
            ActionDefinition.from_mapping(definition, "provider action")
        )
    )
    with pytest.raises(ActionPackageError, match="nonnumeric bounds"):
        _signed(
            private_key,
            manifest=nonnumeric["manifest"],
            payload=nonnumeric["payload"],
        )

    duplicate = resignable_document()
    duplicate["payload"]["actions"][0]["definition"]["parameters"][0]["enum"] = [1, 1]
    duplicate_definition = duplicate["payload"]["actions"][0]["definition"]
    duplicate["payload"]["actions"][0]["program"]["action_contract_digest"] = (
        provider_action_contract_digest(
            ActionDefinition.from_mapping(duplicate_definition, "provider action")
        )
    )
    with pytest.raises(ActionPackageError, match="enum contains duplicates"):
        _signed(
            private_key,
            manifest=duplicate["manifest"],
            payload=duplicate["payload"],
        )

    unsafe = resignable_document()
    unsafe["payload"]["actions"][0]["definition"]["parameters"][0]["maximum"] = 1 << 53
    unsafe_definition = unsafe["payload"]["actions"][0]["definition"]
    unsafe["payload"]["actions"][0]["program"]["action_contract_digest"] = (
        provider_action_contract_digest(
            ActionDefinition.from_mapping(unsafe_definition, "provider action")
        )
    )
    with pytest.raises(ActionPackageError, match="unsafe numeric bound"):
        _signed(
            private_key,
            manifest=unsafe["manifest"],
            payload=unsafe["payload"],
        )


@pytest.mark.parametrize(
    ("inventory", "message"),
    [
        (_runner_inventory(include_runtime=False), "no provider runtime support"),
        (_runner_inventory(readiness="unavailable"), "runtime is unavailable"),
        (
            _runner_inventory(
                hard_limits={
                    "max_module_bytes": 32 * 1024,
                    "max_memory_bytes": 1024 * 1024,
                    "max_input_bytes": 4096,
                    "max_output_bytes": 4096,
                    "fuel": 10_000,
                }
            ),
            "limits exceed",
        ),
    ],
)
def test_provider_activation_rejects_missing_unready_or_smaller_runtime(
    inventory: dict[str, Any], message: str
) -> None:
    with pytest.raises(ActionPackageError, match=message):
        _activation(Ed25519PrivateKey.generate(), inventory)


def test_provider_activation_replay_rejects_runtime_contract_digest_tampering() -> None:
    private_key = Ed25519PrivateKey.generate()
    activation = _activation(private_key, _runner_inventory())
    replay_inventory = copy.deepcopy(dict(activation.runner_inventory()))
    replay_inventory["provider_runtimes"][0]["contract_digest"] = "sha256:" + "0" * 64

    with pytest.raises(ActionPackageError, match="contract_digest does not match"):
        _activation(private_key, replay_inventory)
