from __future__ import annotations

import base64
import copy
import hashlib
import json
from dataclasses import FrozenInstanceError
from typing import Any, Mapping

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import bluefire.action_packages as action_packages_module
from bluefire.action_packages import (
    ACTION_PACKAGE_PAYLOAD_SCHEMA,
    ACTION_PACKAGE_SCHEMA,
    ACTION_PROGRAM_ADAPTER,
    ACTION_PROGRAM_SCHEMA,
    MAX_ACTIONS,
    MAX_CONSTANTS,
    MAX_ENVELOPE_BYTES,
    MAX_JSON_DEPTH,
    MAX_STRING_CHARS,
    SUPPORTED_RUNNER_ACTION_VERSIONS,
    ActionPackageError,
    SemVer,
    audit_action_package,
    build_signed_action_package,
    canonical_public_key_b64u,
    ed25519_public_key_fingerprint,
    normalize_ed25519_public_key,
    parse_canonical_action_package,
    verify_action_package,
    verify_action_package_for_activation,
)
from bluefire.util import canonical_json_bytes, content_hash

PUBLISHER_ID = "acme.security"
KEY_ID = "release-2026"
BEHAVIOR_ID = "acme.endpoint.profile.v1"
ACTION_ID = "acme.endpoint.profile-action.v1"


def _source_provenance() -> dict[str, Any]:
    return {
        "source": "ACME reviewed neutral endpoint package",
        "reference": "urn:acme:bluefire-package:endpoint-profile:sha256:" + "b" * 64,
        "license": "MIT",
        "derived": False,
        "notes": "Declarative mapping to one compiled BlueFire runner operation.",
    }


def _behavior() -> dict[str, Any]:
    return {
        "schema_version": "bluefire.behavior.v1",
        "id": BEHAVIOR_ID,
        "title": "Observe bounded endpoint identity",
        "purpose": "Return non-sensitive operating-system and architecture facts.",
        "execution_state": "action",
        "safety_tier": "safe",
        "platforms": ["linux", "macos", "windows"],
        "techniques": ["T1082"],
        "capabilities": ["endpoint.discovery", "system.discovery"],
        "inputs": [],
        "outputs": [
            {
                "name": "system",
                "type": "artifact.endpoint.system-profile.v1",
                "description": "Bounded system profile.",
            }
        ],
        "parameters": [],
        "action_ids": [ACTION_ID],
        "telemetry": ["endpoint.discovery.system_observed"],
        "detection_hints": ["Compare the returned identity with independent host inventory."],
        "provenance": _source_provenance(),
        "limitations": ["Does not inspect accounts, network configuration, or file content."],
    }


def _action() -> dict[str, Any]:
    return {
        "schema_version": "bluefire.action.v1",
        "id": ACTION_ID,
        "title": "Observe bounded endpoint identity",
        "purpose": "Use the reviewed compiled system-profile operation.",
        "safety_tier": "safe",
        "capabilities": ["endpoint.discovery", "system.discovery"],
        "platforms": ["linux", "macos", "windows"],
        "inputs": [],
        "outputs": [
            {
                "name": "system",
                "type": "artifact.endpoint.system-profile.v1",
                "description": "Bounded system profile.",
            }
        ],
        "parameters": [],
        "mutates": False,
        "cleanup_action_id": None,
        "provenance": _source_provenance(),
    }


def _manifest() -> dict[str, Any]:
    return {
        "package_id": "acme.endpoint-pack",
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
            "source": "ACME reviewed action package",
            "reference": "urn:acme:bluefire-package:1.2.3",
            "revision": "a" * 40,
        },
        "platforms": ["linux", "macos", "windows"],
        "capabilities": ["endpoint.discovery", "system.discovery"],
        "safety_tiers": ["safe"],
        "behavior_ids": [BEHAVIOR_ID],
        "action_ids": [ACTION_ID],
    }


def _payload() -> dict[str, Any]:
    return {
        "schema_version": ACTION_PACKAGE_PAYLOAD_SCHEMA,
        "behaviors": [_behavior()],
        "actions": [
            {
                "definition": _action(),
                "program": {
                    "schema_version": ACTION_PROGRAM_SCHEMA,
                    "steps": [
                        {
                            "opcode": "endpoint.discovery.system.v1",
                            "adapter": ACTION_PROGRAM_ADAPTER,
                            "constants": {},
                        }
                    ],
                },
            }
        ],
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


def _verify(envelope: bytes, private_key: Ed25519PrivateKey, **kwargs: Any) -> Any:
    return verify_action_package(
        envelope,
        trusted_signers=_trust(private_key),
        bluefire_version="0.1.0",
        platform="windows",
        **kwargs,
    )


def _b64u(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _runner_inventory(
    *, action_version: str = "1.0.0", readiness: str = "ready", include_opcode: bool = True
) -> dict[str, Any]:
    actions: list[dict[str, str]] = [
        {
            "action_id": "sandbox.archive.tar.v1",
            "action_version": "1.0.0",
            "readiness": "ready",
        }
    ]
    if include_opcode:
        actions.insert(
            0,
            {
                "action_id": "endpoint.discovery.system.v1",
                "action_version": action_version,
                "readiness": readiness,
            },
        )
    return {
        "schema_version": "bluefire.runner-inventory.v1",
        "runner_id": "bluefire-runner",
        "runner_version": "0.1.0",
        "action_sdk_version": "1.0.0",
        "receipt_protocol": "bluefire.runner-receipt.v1",
        "platform": "windows",
        "actions": actions,
    }


def test_valid_signed_envelope_returns_store_safe_verified_result() -> None:
    private_key = Ed25519PrivateKey.generate()
    envelope = _signed(private_key)

    verified = _verify(envelope, private_key)

    assert verified.canonical_envelope_bytes == envelope
    assert verified.canonical_content_bytes == canonical_json_bytes(
        {
            "schema_version": ACTION_PACKAGE_SCHEMA,
            "manifest": _manifest(),
            "payload": _payload(),
        }
    )
    assert verified.content_digest == (
        "sha256:" + hashlib.sha256(verified.canonical_content_bytes).hexdigest()
    )
    assert verified.package_digest == "sha256:" + hashlib.sha256(envelope).hexdigest()
    assert verified.publisher_id == PUBLISHER_ID
    assert verified.key_id == KEY_ID
    assert verified.public_key_fingerprint == ed25519_public_key_fingerprint(
        private_key.public_key()
    )
    assert verified.manifest_bytes == canonical_json_bytes(_manifest())
    assert verified.manifest.package_id == "acme.endpoint-pack"
    assert verified.behaviors[0].id == BEHAVIOR_ID
    assert verified.actions[0].definition.id == ACTION_ID
    assert verified.actions[0].program.steps[0].opcode == "endpoint.discovery.system.v1"
    with pytest.raises(FrozenInstanceError):
        verified.manifest.version = "2.0.0"  # type: ignore[misc]


def test_activation_verifier_binds_exact_catalog_and_canonical_runner_inventory() -> None:
    private_key = Ed25519PrivateKey.generate()
    envelope = _signed(private_key)
    empty_digest = content_hash(
        {"schema_version": "bluefire.active-action-package-catalog.v1", "packages": []}
    )

    activation = verify_action_package_for_activation(
        envelope,
        trusted_signers=_trust(private_key),
        bluefire_version="0.1.0",
        runner_inventory=_runner_inventory(),
        runner_identity_digest="sha256:" + "1" * 64,
        expected_catalog_generation=0,
        expected_catalog_digest=empty_digest,
        occupied_behavior_ids=("endpoint.discovery.system.v1",),
        occupied_action_ids=("endpoint.discovery.system.v1",),
    )

    assert activation.expected_catalog_generation == 0
    assert activation.expected_catalog_digest == empty_digest
    assert activation.runner_platform == "windows"
    assert [item["action_id"] for item in activation.runner_inventory()["actions"]] == [
        "endpoint.discovery.system.v1",
        "sandbox.archive.tar.v1",
    ]
    assert activation.opcode_bindings[0].package_action_id == ACTION_ID
    assert activation.opcode_bindings[0].opcode == "endpoint.discovery.system.v1"
    assert activation.to_dict()["runner"]["identity_digest"] == "sha256:" + "1" * 64
    with pytest.raises(FrozenInstanceError):
        activation.runner_platform = "linux"  # type: ignore[misc]

    # A persisted canonical snapshot is accepted byte-for-byte for independent
    # activation replay; source/contract digests must not be hashed a second time.
    replayed = verify_action_package_for_activation(
        envelope,
        trusted_signers=_trust(private_key),
        bluefire_version="0.1.0",
        runner_inventory=activation.runner_inventory(),
        runner_identity_digest=activation.runner_identity_digest,
        expected_catalog_generation=0,
        expected_catalog_digest=empty_digest,
        occupied_behavior_ids=activation.occupied_behavior_ids,
        occupied_action_ids=activation.occupied_action_ids,
    )
    assert replayed == activation


@pytest.mark.parametrize(
    ("inventory", "message"),
    [
        (_runner_inventory(include_opcode=False), "missing packaged reviewed opcode"),
        (_runner_inventory(action_version="2.0.0"), "version is incompatible"),
        (_runner_inventory(readiness="unavailable"), "is not ready"),
    ],
)
def test_activation_verifier_rejects_runner_inventory_mismatch(
    inventory: Mapping[str, Any], message: str
) -> None:
    private_key = Ed25519PrivateKey.generate()
    with pytest.raises(ActionPackageError, match=message):
        verify_action_package_for_activation(
            _signed(private_key),
            trusted_signers=_trust(private_key),
            bluefire_version="0.1.0",
            runner_inventory=inventory,
            runner_identity_digest="sha256:" + "2" * 64,
            expected_catalog_generation=0,
            expected_catalog_digest=content_hash(
                {
                    "schema_version": "bluefire.active-action-package-catalog.v1",
                    "packages": [],
                }
            ),
        )


def test_key_encodings_are_canonical_and_strict() -> None:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    raw = normalize_ed25519_public_key(public_key)

    assert len(raw) == 32
    assert normalize_ed25519_public_key(raw) == raw
    assert canonical_public_key_b64u(public_key) == _b64u(raw)
    assert "=" not in canonical_public_key_b64u(public_key)
    with pytest.raises(ActionPackageError, match="exactly 32"):
        normalize_ed25519_public_key(b"short")


def test_signing_and_canonicalization_are_deterministic() -> None:
    private_key = Ed25519PrivateKey.generate()
    manifest = dict(reversed(list(_manifest().items())))
    payload = dict(reversed(list(_payload().items())))

    first = _signed(private_key, manifest=manifest, payload=payload)
    second = _signed(private_key)

    assert first == second
    assert canonical_json_bytes(json.loads(first)) == first
    noncanonical = json.dumps(json.loads(first), ensure_ascii=False).encode("utf-8")
    with pytest.raises(ActionPackageError, match="not canonical JSON"):
        parse_canonical_action_package(noncanonical)


def test_content_tampering_and_signature_substitution_are_rejected() -> None:
    private_key = Ed25519PrivateKey.generate()
    envelope = _signed(private_key)
    document = json.loads(envelope)
    document["payload"]["behaviors"][0]["purpose"] = "Changed after signing."
    tampered_content = canonical_json_bytes(document)

    with pytest.raises(ActionPackageError, match="integrity check failed"):
        _verify(tampered_content, private_key)

    document = json.loads(envelope)
    signature = base64.urlsafe_b64decode(document["signature"]["value"] + "==")
    document["signature"]["value"] = _b64u(bytes([signature[0] ^ 1]) + signature[1:])
    tampered_signature = canonical_json_bytes(document)
    with pytest.raises(ActionPackageError, match="signature verification failed"):
        _verify(tampered_signature, private_key)


def test_unknown_identity_and_wrong_trusted_key_are_rejected() -> None:
    private_key = Ed25519PrivateKey.generate()
    envelope = _signed(private_key)

    with pytest.raises(ActionPackageError, match="not locally trusted"):
        verify_action_package(
            envelope,
            trusted_signers={},
            bluefire_version="0.1.0",
            platform="windows",
        )
    with pytest.raises(ActionPackageError, match="signature verification failed"):
        verify_action_package(
            envelope,
            trusted_signers={(PUBLISHER_ID, KEY_ID): Ed25519PrivateKey.generate().public_key()},
            bluefire_version="0.1.0",
            platform="windows",
        )


def test_duplicate_json_keys_are_rejected_before_canonicalization() -> None:
    private_key = Ed25519PrivateKey.generate()
    envelope = _signed(private_key)
    duplicate = b'{"schema_version":"bluefire.action-package.v1",' + envelope.removeprefix(b"{")

    with pytest.raises(ActionPackageError, match="duplicate JSON object key: schema_version"):
        parse_canonical_action_package(duplicate)


@pytest.mark.parametrize("number", ["1.5", "1e2", "NaN", "Infinity", "-Infinity"])
def test_floats_and_non_finite_numbers_are_rejected(number: str) -> None:
    with pytest.raises(ActionPackageError, match="JSON numbers|point JSON"):
        parse_canonical_action_package(f'{{"value":{number}}}'.encode())


def test_extreme_integer_and_lone_surrogate_raise_contract_errors() -> None:
    with pytest.raises(ActionPackageError, match="signed 64-bit"):
        parse_canonical_action_package(b'{"value":' + b"9" * 5000 + b"}")

    with pytest.raises(ActionPackageError, match="control characters|Unicode scalar"):
        parse_canonical_action_package(b'{"value":"\\ud800"}')


def test_envelope_string_depth_and_collection_bounds_are_enforced() -> None:
    with pytest.raises(ActionPackageError, match="exceeds .* bytes"):
        parse_canonical_action_package(b"x" * (MAX_ENVELOPE_BYTES + 1))

    oversized_string = canonical_json_bytes({"value": "x" * (MAX_STRING_CHARS + 1)})
    with pytest.raises(ActionPackageError, match="exceeds .* characters"):
        parse_canonical_action_package(oversized_string)

    nested: Any = 0
    for _ in range(MAX_JSON_DEPTH + 1):
        nested = {"value": nested}
    with pytest.raises(ActionPackageError, match="maximum JSON depth"):
        parse_canonical_action_package(canonical_json_bytes(nested))

    private_key = Ed25519PrivateKey.generate()
    payload = _payload()
    payload["actions"] = [copy.deepcopy(payload["actions"][0]) for _ in range(MAX_ACTIONS + 1)]
    with pytest.raises(ActionPackageError, match=r"payload.actions must contain 1\.\.=64"):
        _signed(private_key, payload=payload)

    payload = _payload()
    payload["actions"][0]["program"]["steps"][0]["constants"] = {
        f"constant_{index}": index for index in range(MAX_CONSTANTS + 1)
    }
    with pytest.raises(ActionPackageError, match="constants exceeds"):
        _signed(private_key, payload=payload)


@pytest.mark.parametrize("field", ["args", "executable", "native", "script", "url"])
def test_arbitrary_execution_fields_are_rejected_recursively(field: str) -> None:
    private_key = Ed25519PrivateKey.generate()
    payload = _payload()
    payload["actions"][0]["program"]["steps"][0][field] = "caller-authored"

    with pytest.raises(ActionPackageError, match="forbidden executable field"):
        _signed(private_key, payload=payload)


def test_forbidden_action_parameter_and_unreviewed_opcode_are_rejected() -> None:
    private_key = Ed25519PrivateKey.generate()
    payload = _payload()
    parameter = {"name": "args", "type": "string", "required": False}
    payload["behaviors"][0]["parameters"] = [copy.deepcopy(parameter)]
    payload["actions"][0]["definition"]["parameters"] = [copy.deepcopy(parameter)]
    with pytest.raises(ActionPackageError, match="forbidden executable parameter args"):
        _signed(private_key, payload=payload)

    payload = _payload()
    payload["actions"][0]["program"]["steps"][0]["opcode"] = "acme.shell.execute.v1"
    with pytest.raises(ActionPackageError, match="opcode is not allowlisted"):
        _signed(private_key, payload=payload)


def test_program_cannot_understate_compiled_opcode_effects() -> None:
    private_key = Ed25519PrivateKey.generate()
    payload = _payload()
    payload["actions"][0]["program"]["steps"][0][
        "opcode"
    ] = "sandbox.restricted.persistence-marker.v1"
    payload["actions"][0]["program"]["steps"][0]["constants"] = {"marker_kind": "detection-canary"}

    with pytest.raises(ActionPackageError, match="reviewed opcode safety tier"):
        _signed(private_key, payload=payload)


def test_manifest_payload_id_closure_and_catalog_collisions_are_rejected() -> None:
    private_key = Ed25519PrivateKey.generate()
    manifest = _manifest()
    manifest["action_ids"] = ["acme.different.v1"]
    with pytest.raises(ActionPackageError, match="manifest action IDs do not exactly match"):
        _signed(private_key, manifest=manifest)

    payload = _payload()
    payload["behaviors"][0]["action_ids"] = ["acme.external-action.v1"]
    with pytest.raises(ActionPackageError, match="references action .* outside the package"):
        _signed(private_key, payload=payload)

    payload = _payload()
    payload["actions"][0]["definition"]["cleanup_action_id"] = "acme.external-cleanup.v1"
    with pytest.raises(ActionPackageError, match="cleanup reference outside the package"):
        _signed(private_key, payload=payload)

    envelope = _signed(private_key)
    with pytest.raises(ActionPackageError, match="action IDs collide"):
        _verify(envelope, private_key, occupied_action_ids={ACTION_ID})


def test_exact_claims_compatibility_platform_and_semver_are_enforced() -> None:
    private_key = Ed25519PrivateKey.generate()
    manifest = _manifest()
    manifest["capabilities"] = ["endpoint.discovery"]
    with pytest.raises(ActionPackageError, match="capabilities do not exactly match"):
        _signed(private_key, manifest=manifest)

    manifest = _manifest()
    manifest["version"] = "01.2.3"
    with pytest.raises(ActionPackageError, match="strict semantic versioning"):
        _signed(private_key, manifest=manifest)

    assert SemVer.parse("18446744073709551615.0.0").major == (1 << 64) - 1
    with pytest.raises(ActionPackageError, match="unsigned 64-bit"):
        SemVer.parse("18446744073709551616.0.0")

    envelope = _signed(private_key)
    with pytest.raises(ActionPackageError, match="incompatible"):
        verify_action_package(
            envelope,
            trusted_signers=_trust(private_key),
            bluefire_version="1.0.0",
            platform="windows",
        )
    with pytest.raises(ActionPackageError, match="does not support platform"):
        verify_action_package(
            envelope,
            trusted_signers=_trust(private_key),
            bluefire_version="0.1.0",
            platform="freebsd",
        )


def test_signature_block_cannot_self_assert_publisher_or_trust() -> None:
    private_key = Ed25519PrivateKey.generate()
    document = json.loads(_signed(private_key))
    document["signature"]["publisher_id"] = PUBLISHER_ID

    with pytest.raises(ActionPackageError, match="signature has unknown fields: publisher_id"):
        verify_action_package(
            canonical_json_bytes(document),
            trusted_signers=_trust(private_key),
            bluefire_version="0.1.0",
            platform="windows",
        )


def test_target_independent_verification_defers_compatibility() -> None:
    private_key = Ed25519PrivateKey.generate()
    envelope = _signed(private_key)

    staged = verify_action_package(
        envelope,
        trusted_signers=_trust(private_key),
        bluefire_version=None,
        platform=None,
    )

    assert staged.manifest.package_id == _manifest()["package_id"]
    with pytest.raises(ActionPackageError, match="both be supplied or both be omitted"):
        verify_action_package(
            envelope,
            trusted_signers=_trust(private_key),
            bluefire_version=None,
            platform="windows",
        )


def test_historical_audit_does_not_depend_on_current_registry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    envelope = _signed(private_key)

    def retired_contract(_actions: Any) -> None:
        raise ActionPackageError("reviewed opcode retired from the current registry")

    monkeypatch.setattr(action_packages_module, "_validate_program_bindings", retired_contract)
    with pytest.raises(ActionPackageError, match="retired from the current registry"):
        verify_action_package(
            envelope,
            trusted_signers=_trust(private_key),
            bluefire_version=None,
            platform=None,
        )

    audited = audit_action_package(envelope, trusted_signers=_trust(private_key))
    assert audited.package_digest == "sha256:" + hashlib.sha256(envelope).hexdigest()


def test_low_order_ed25519_key_and_universal_forgery_are_rejected() -> None:
    low_order_key = b"\x01" + b"\x00" * 31
    forged_signature = b"\x01" + b"\x00" * 63
    with pytest.raises(ActionPackageError, match="prime-order"):
        normalize_ed25519_public_key(low_order_key)

    private_key = Ed25519PrivateKey.generate()
    document = json.loads(_signed(private_key))
    document["signature"]["value"] = _b64u(forged_signature)
    with pytest.raises(ActionPackageError, match="prime-order"):
        verify_action_package(
            canonical_json_bytes(document),
            trusted_signers={(PUBLISHER_ID, KEY_ID): low_order_key},
            bluefire_version=None,
            platform=None,
        )


@pytest.mark.parametrize("definition_kind", ["behavior", "action"])
def test_payload_license_must_match_single_manifest_license(definition_kind: str) -> None:
    private_key = Ed25519PrivateKey.generate()
    payload = _payload()
    if definition_kind == "behavior":
        payload["behaviors"][0]["provenance"]["license"] = "GPL-3.0-only"
    else:
        payload["actions"][0]["definition"]["provenance"]["license"] = "LicenseRef-Proprietary"

    with pytest.raises(ActionPackageError, match="provenance license conflicts"):
        _signed(private_key, payload=payload)


@pytest.mark.parametrize(
    "reference",
    [
        "javascript:alert(1)",
        "https://operator:password@example.test/source",  # pragma: allowlist secret
        "https://example.test/source?ref=main",
        "https://example.test/source#latest",
    ],
)
def test_package_provenance_references_are_safe_and_immutable(reference: str) -> None:
    private_key = Ed25519PrivateKey.generate()
    manifest = _manifest()
    manifest["provenance"]["reference"] = reference
    with pytest.raises(ActionPackageError, match="credential-free HTTPS URL"):
        _signed(private_key, manifest=manifest)

    payload = _payload()
    payload["behaviors"][0]["provenance"]["reference"] = reference
    with pytest.raises(ActionPackageError, match="credential-free HTTPS URL"):
        _signed(private_key, payload=payload)


@pytest.mark.parametrize(
    "reference",
    [
        "https://example.test/source/main",
        "https://example.test/source/latest",
        "urn:acme:source:latest",
    ],
)
def test_payload_provenance_reference_must_be_content_addressed(reference: str) -> None:
    private_key = Ed25519PrivateKey.generate()
    payload = _payload()
    payload["actions"][0]["definition"]["provenance"]["reference"] = reference

    with pytest.raises(ActionPackageError, match="sha256"):
        _signed(private_key, payload=payload)


@pytest.mark.parametrize("revision", ["latest", "main", "release-1.2.3", "A" * 40])
def test_package_revision_requires_immutable_full_identity(revision: str) -> None:
    private_key = Ed25519PrivateKey.generate()
    manifest = _manifest()
    manifest["provenance"]["revision"] = revision

    with pytest.raises(ActionPackageError, match="full lowercase VCS commit"):
        _signed(private_key, manifest=manifest)


@pytest.mark.parametrize(
    "opcode",
    [
        "sandbox.archive.tar.v1",
        "sandbox.fixture.create.v1",
        "sandbox.network.loopback.v1",
        "sandbox.peer.handoff.v1",
        "sandbox.restricted.persistence-marker.v1",
    ],
)
def test_program_constants_cannot_fall_back_to_unsigned_defaults(opcode: str) -> None:
    private_key = Ed25519PrivateKey.generate()
    payload = _payload()
    payload["actions"][0]["program"]["steps"][0]["opcode"] = opcode

    with pytest.raises(ActionPackageError, match="must explicitly bind reviewed fields"):
        _signed(private_key, payload=payload)


def test_runner_contract_versions_fail_closed_across_breaking_semantic_schemas() -> None:
    assert SUPPORTED_RUNNER_ACTION_VERSIONS == {
        "endpoint.discovery.processes.v1": "1.0.0",
        "endpoint.discovery.system.v1": "1.0.0",
        "sandbox.archive.tar.v1": "1.0.0",
        "sandbox.cleanup.v1": "1.1.0",
        "sandbox.collection.stage.v1": "2.0.0",
        "sandbox.discovery.list.v1": "2.0.0",
        "sandbox.discovery.metadata.v1": "2.0.0",
        "sandbox.discovery.recursive.v1": "1.0.0",
        "sandbox.execution.native-canary.v1": "1.0.0",
        "sandbox.export.local.v1": "2.0.0",
        "sandbox.fixture.create.v1": "2.0.0",
        "sandbox.fixture.transform.v1": "2.0.0",
        "sandbox.identity-material.inspect.v1": "1.0.0",
        "sandbox.identity-material.seed.v1": "1.0.0",
        "sandbox.network.loopback.v1": "1.0.0",
        "sandbox.observability.variant.v1": "1.0.0",
        "sandbox.peer.handoff.v1": "1.0.0",
        "sandbox.restricted.persistence-marker.v1": "1.0.0",
    }
