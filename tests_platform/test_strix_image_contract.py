"""Synthetic assertions exercise the gate; none are live qualification proof."""

from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import FrozenInstanceError
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from bluefire import strix_image_contract as image
from bluefire.util import canonical_json_bytes, content_hash

# Deliberately public synthetic test signer; never a production trust root.
_TEST_SIGNER = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
_TEST_PUBLIC_KEY = _TEST_SIGNER.public_key().public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw
)
_TEST_AUTHORITY = "sha256:" + hashlib.sha256(_TEST_PUBLIC_KEY).hexdigest()


def _digest(label: str) -> str:
    return content_hash({"synthetic-test-fixture": label})


def _contract_document() -> dict[str, Any]:
    digest = _digest("image")
    return {
        "schema_version": "bluefire.strix-derived-image.v1",
        "source_revision": image.STRIX_SOURCE_REVISION,
        "source_tree_digest": _digest("source-tree"),
        "image_reference": "registry.example/bluefire/strix@" + digest,
        "image_digest": digest,
        "base_image_digest": _digest("base-image"),
        "dockerfile_digest": _digest("proposed-build-recipe"),
        "dependency_lock_digest": _digest("dependency-lock"),
        "sbom_digest": _digest("sbom"),
        "provenance_digest": _digest("provenance"),
        "attestation_digest": _digest("attestation"),
        "components": image.pinned_image_components(),
        "platform": image.TESTED_PLATFORM,
        "runtime_profile": image.proposed_image_runtime_profile(
            network_id="a" * 64,
            network_name="bluefire-engine-" + "b" * 32,
            network_policy_digest=_digest("network-policy"),
        ),
        "redistribution_review": image.blocked_image_redistribution_review(),
    }


def _receipt_document(contract: image.StrixImageContract, check: str) -> dict[str, Any]:
    return {
        "schema_version": "bluefire.strix-image-qualification.v1",
        "stage": "local-build" if check in image.LOCAL_BUILD_CHECKS else "hosted-qualification",
        "check": check,
        "contract_digest": contract.contract_digest,
        "runtime_profile_digest": contract.runtime_profile_digest,
        "image_digest": contract.to_dict()["image_digest"],
        "source_revision": image.STRIX_SOURCE_REVISION,
        "platform": image.TESTED_PLATFORM,
        "runner_digest": _digest("synthetic-runner"),
        "verifier_digest": _TEST_AUTHORITY,
        "evidence_digest": _digest(check),
        "checked_at": "2026-11-04T16:00:00Z",
        "passed": True,
    }


def _receipts(contract: image.StrixImageContract) -> list[image.StrixImageQualificationReceipt]:
    return [
        image.StrixImageQualificationReceipt.from_mapping(_receipt_document(contract, check))
        for check in image.LOCAL_BUILD_CHECKS + image.HOSTED_QUALIFICATION_CHECKS
    ]


def _evaluate(
    contract: image.StrixImageContract,
    receipts: list[image.StrixImageQualificationReceipt],
) -> image.StrixImageAdmissionDecision:
    # Only test harness authority configuration can admit synthetic signatures.
    # The shipped production module has no configured authority and cannot do so.
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(image, "_CONTROLLER_RECEIPT_PUBLIC_KEYS", (_TEST_PUBLIC_KEY,))
        registry = _registry(receipts)
        return image.evaluate_image_admission(contract, receipts, receipt_registry=registry)


def _signed(
    receipt: image.StrixImageQualificationReceipt,
    signer: Ed25519PrivateKey = _TEST_SIGNER,
) -> image.SignedImageQualificationReceipt:
    message = (
        b"bluefire.strix-image-controller-receipt.v1\x00"
        + _TEST_AUTHORITY.encode("ascii")
        + b"\x00"
        + receipt.canonical_bytes
    )
    return image.SignedImageQualificationReceipt(receipt.canonical_bytes, signer.sign(message))


def _registry(
    receipts: list[image.StrixImageQualificationReceipt],
) -> image.ControllerVerifiedImageReceiptRegistry:
    retained = {receipt.receipt_digest: _signed(receipt) for receipt in receipts}
    return image.ControllerVerifiedImageReceiptRegistry(
        authority_key_id=_TEST_AUTHORITY,
        open_signed_receipt=lambda contract_digest, receipt_digest: retained[receipt_digest],
    )


def test_declaration_and_local_build_do_not_promote_hosted_or_live_admission() -> None:
    contract = image.StrixImageContract.from_mapping(_contract_document())
    missing = _evaluate(contract, [])
    assert not missing.local_build_qualified
    assert not missing.hosted_qualification_complete
    assert not missing.image_admitted_for_runtime
    assert len(missing.missing_checks) == 12
    local = _evaluate(contract, _receipts(contract)[:2])
    assert local.local_build_qualified
    assert not local.hosted_qualification_complete
    assert not local.image_admitted_for_runtime
    assert not local.redistribution_authorized
    assert not local.production_runtime_admitted
    assert not local.live_execution_proven


def test_complete_synthetic_receipts_satisfy_only_the_necessary_image_gate() -> None:
    contract = image.StrixImageContract.from_mapping(_contract_document())
    decision = _evaluate(contract, _receipts(contract))
    assert decision.local_build_qualified
    assert decision.hosted_qualification_complete
    assert decision.image_admitted_for_runtime
    assert decision.missing_checks == ()
    assert not decision.redistribution_authorized
    assert not decision.production_runtime_admitted
    assert not decision.live_execution_proven


def test_runtime_tmpdir_is_the_private_container_tmpfs() -> None:
    profile = image.proposed_image_runtime_profile(
        network_id="a" * 64,
        network_name="bluefire-engine-" + "b" * 32,
        network_policy_digest=_digest("network-policy"),
    )

    assert profile["environment"]["TMPDIR"] == "/tmp"
    assert profile["tmpfs"]["/tmp"] == (
        "rw,nosuid,nodev,noexec,size=134217728,uid=1000,gid=1000,mode=0700"
    )


@pytest.mark.parametrize("omitted", range(12))
def test_every_exact_check_is_required(omitted: int) -> None:
    contract = image.StrixImageContract.from_mapping(_contract_document())
    receipts = _receipts(contract)
    missing = receipts.pop(omitted).to_dict()["check"]
    decision = _evaluate(contract, receipts)
    assert not decision.image_admitted_for_runtime
    assert decision.missing_checks == (missing,)


@pytest.mark.parametrize("field", tuple(_contract_document()))
def test_missing_contract_fields_refuse(field: str) -> None:
    document = _contract_document()
    del document[field]
    with pytest.raises(image.StrixImageContractError):
        image.StrixImageContract.from_mapping(document)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("source_revision", "a" * 40),
        ("platform", "linux/arm64"),
        ("image_reference", "registry.example/strix:latest"),
        ("image_digest", _digest("different-image")),
        ("sbom_digest", None),
        ("provenance_digest", "sha256:" + "A" * 64),
        ("attestation_digest", "sha256:abc"),
        ("components", {**image.pinned_image_components(), "docker": "7.1.1"}),
    ],
)
def test_unpinned_or_different_artifacts_refuse(field: str, value: Any) -> None:
    document = _contract_document()
    document[field] = value
    with pytest.raises(image.StrixImageContractError):
        image.StrixImageContract.from_mapping(document)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("user", "0:0"),
        ("user", "root"),
        ("read_only_root", False),
        ("read_only_root", 1),
        ("working_directory", "/host"),
        ("entrypoint", ["/bin/sh", "-c", "pip install strix-agent"]),
        ("command", ["sh"]),
        ("environment", {"HOME": "/root"}),
        ("mounts", [{"source": "/var/run/docker.sock", "destination": "/docker.sock"}]),
        ("volumes", ["host-data"]),
        ("published_ports", ["48080:48080"]),
        ("extra_hosts", ["host.docker.internal:host-gateway"]),
        ("devices", ["/dev/net/tun"]),
        ("privileged", True),
        ("cap_add", ["NET_ADMIN", "NET_RAW"]),
        ("cap_drop", []),
        ("security_options", []),
        ("pid_mode", "host"),
        ("ipc_mode", "host"),
        ("uts_mode", "host"),
        ("memory_bytes", 0),
        ("memory_bytes", 2147483648.0),
        ("memory_swap_bytes", -1),
        ("nano_cpus", 0),
        ("pids_limit", -1),
        ("runtime_installs", True),
        ("runtime_image_pulls", True),
        ("preloaded_image_required", False),
        ("restart_policy", "always"),
        ("tmpfs", {"/workspace": "rw"}),
    ],
)
def test_unsafe_or_different_runtime_profiles_refuse(field: str, value: Any) -> None:
    document = _contract_document()
    document["runtime_profile"][field] = value
    with pytest.raises(image.StrixImageContractError):
        image.StrixImageContract.from_mapping(document)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("id", "host"),
        ("name", "bridge"),
        ("policy_digest", None),
        ("internal", False),
        ("attach_additional_networks", True),
    ],
)
def test_network_has_no_host_or_dynamic_fallback(field: str, value: Any) -> None:
    document = _contract_document()
    document["runtime_profile"]["network"][field] = value
    with pytest.raises(image.StrixImageContractError):
        image.StrixImageContract.from_mapping(document)


def test_nested_mutation_is_detached_and_direct_bytes_are_validated() -> None:
    document = _contract_document()
    contract = image.StrixImageContract.from_mapping(document)
    original_digest = contract.contract_digest
    document["runtime_profile"]["tmpfs"].clear()
    detached = contract.to_dict()
    detached["runtime_profile"]["user"] = "root"
    assert contract.contract_digest == original_digest
    assert contract.to_dict()["runtime_profile"]["user"] == "1000:1000"
    with pytest.raises(FrozenInstanceError):
        contract.canonical_bytes = b"{}"  # type: ignore[misc]
    for raw in (b"{}", b"not json", b"\xff", json.dumps(contract.to_dict()).encode()):
        with pytest.raises(image.StrixImageContractError):
            image.StrixImageContract(raw)


@pytest.mark.parametrize("field", ["redistribution_authorized", "license_review_complete"])
def test_success_cannot_clear_component_rights(field: str) -> None:
    document = _contract_document()
    document["redistribution_review"][field] = True
    with pytest.raises(image.StrixImageContractError):
        image.StrixImageContract.from_mapping(document)


def test_receipt_authenticity_is_separate_from_a_well_formed_declaration() -> None:
    contract = image.StrixImageContract.from_mapping(_contract_document())
    with pytest.raises(image.StrixImageContractError, match="registry is unavailable"):
        image.evaluate_image_admission(contract, _receipts(contract))


@pytest.mark.parametrize("field", ["contract_digest", "runtime_profile_digest", "image_digest"])
def test_authenticated_but_wrong_image_receipt_refuses(field: str) -> None:
    contract = image.StrixImageContract.from_mapping(_contract_document())
    row = _receipt_document(contract, image.LOCAL_BUILD_CHECKS[0])
    row[field] = _digest("other-identity")
    receipt = image.StrixImageQualificationReceipt.from_mapping(row)
    with pytest.raises(image.StrixImageContractError):
        _evaluate(contract, [receipt])


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("stage", "local-build"),
        ("check", "live-proof"),
        ("passed", 1),
        ("passed", False),
        ("platform", "linux/arm64"),
        ("source_revision", "b" * 40),
        ("checked_at", "yesterday"),
        ("evidence_digest", None),
        ("runner_digest", ""),
        ("verifier_digest", "unknown"),
    ],
)
def test_forged_or_incomplete_hosted_receipt_refuses(field: str, value: Any) -> None:
    contract = image.StrixImageContract.from_mapping(_contract_document())
    row = _receipt_document(contract, image.HOSTED_QUALIFICATION_CHECKS[0])
    row[field] = value
    with pytest.raises(image.StrixImageContractError):
        image.StrixImageQualificationReceipt.from_mapping(row)


def test_duplicate_checks_and_unknown_fields_refuse() -> None:
    contract = image.StrixImageContract.from_mapping(_contract_document())
    receipts = _receipts(contract)
    with pytest.raises(image.StrixImageContractError, match="duplicate"):
        _evaluate(contract, [receipts[0], receipts[0]])
    document = _contract_document()
    document["production_runtime_admitted"] = True
    with pytest.raises(image.StrixImageContractError):
        image.StrixImageContract.from_mapping(document)
    row = _receipt_document(contract, image.LOCAL_BUILD_CHECKS[0])
    row["redistribution_authorized"] = True
    with pytest.raises(image.StrixImageContractError):
        image.StrixImageQualificationReceipt.from_mapping(row)


def test_changed_network_or_supply_chain_material_invalidates_all_old_receipts() -> None:
    original = image.StrixImageContract.from_mapping(_contract_document())
    receipts = _receipts(original)
    for field in ("sbom_digest", "provenance_digest", "attestation_digest", "source_tree_digest"):
        document = copy.deepcopy(original.to_dict())
        document[field] = _digest("new-" + field)
        with pytest.raises(image.StrixImageContractError):
            _evaluate(image.StrixImageContract.from_mapping(document), receipts)
    document = original.to_dict()
    document["runtime_profile"]["network"]["id"] = "f" * 64
    with pytest.raises(image.StrixImageContractError):
        _evaluate(image.StrixImageContract.from_mapping(document), receipts)


def test_duplicate_json_key_and_noncanonical_receipt_bytes_refuse() -> None:
    contract = image.StrixImageContract.from_mapping(_contract_document())
    raw = canonical_json_bytes(contract.to_dict())
    duplicated = b'{"platform":"linux/arm64",' + raw[1:]
    with pytest.raises(image.StrixImageContractError):
        image.StrixImageContract(duplicated)
    row = _receipt_document(contract, image.LOCAL_BUILD_CHECKS[0])
    with pytest.raises(image.StrixImageContractError):
        image.StrixImageQualificationReceipt(json.dumps(row, indent=2).encode())


def test_unconfigured_production_authority_refuses_self_registration() -> None:
    assert image._CONTROLLER_RECEIPT_PUBLIC_KEYS == ()
    contract = image.StrixImageContract.from_mapping(_contract_document())
    receipts = _receipts(contract)
    with pytest.raises(image.StrixImageContractError, match="authority is not configured"):
        _registry(receipts)
    blocked = image.evaluate_image_admission(contract, [])
    assert not blocked.image_admitted_for_runtime


@pytest.mark.parametrize("forged_kind", ["hash-set", "duck-registry", "subclass-registry"])
def test_forged_registry_capabilities_refuse(
    forged_kind: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(image, "_CONTROLLER_RECEIPT_PUBLIC_KEYS", (_TEST_PUBLIC_KEY,))
    contract = image.StrixImageContract.from_mapping(_contract_document())
    receipts = _receipts(contract)

    class ForgedRegistry:
        def reopen_verified(self, **kwargs: Any) -> image.StrixImageQualificationReceipt:
            pytest.fail("untrusted registry callback must not run")

    class ForgedSubclass(image.ControllerVerifiedImageReceiptRegistry):
        def reopen_verified(self, **kwargs: Any) -> image.StrixImageQualificationReceipt:
            pytest.fail("registry subclass override must not run")

    forgeries: dict[str, Any] = {
        "hash-set": frozenset(receipt.receipt_digest for receipt in receipts),
        "duck-registry": ForgedRegistry(),
        "subclass-registry": ForgedSubclass(_TEST_AUTHORITY, lambda *args: _signed(receipts[0])),
    }
    with pytest.raises(image.StrixImageContractError, match="not a controller capability"):
        image.evaluate_image_admission(contract, receipts, receipt_registry=forgeries[forged_kind])


def test_caller_signed_receipts_fail_even_with_real_registry_type(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(image, "_CONTROLLER_RECEIPT_PUBLIC_KEYS", (_TEST_PUBLIC_KEY,))
    contract = image.StrixImageContract.from_mapping(_contract_document())
    receipt = _receipts(contract)[0]
    attacker_signer = Ed25519PrivateKey.from_private_bytes(bytes(reversed(range(32))))
    registry = image.ControllerVerifiedImageReceiptRegistry(
        _TEST_AUTHORITY, lambda *args: _signed(receipt, attacker_signer)
    )
    with pytest.raises(image.StrixImageContractError, match="signature is invalid"):
        image.evaluate_image_admission(contract, [receipt], receipt_registry=registry)


@pytest.mark.parametrize("replacement", ["different-check", "different-evidence", "cross-contract"])
def test_registry_receipt_replacement_refuses(
    replacement: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(image, "_CONTROLLER_RECEIPT_PUBLIC_KEYS", (_TEST_PUBLIC_KEY,))
    contract = image.StrixImageContract.from_mapping(_contract_document())
    receipt = _receipts(contract)[0]
    row = receipt.to_dict()
    if replacement == "different-check":
        row["check"] = image.LOCAL_BUILD_CHECKS[1]
    elif replacement == "different-evidence":
        row["evidence_digest"] = _digest("replaced-evidence")
    else:
        row["contract_digest"] = _digest("different-contract")
    replaced = image.StrixImageQualificationReceipt.from_mapping(row)
    registry = image.ControllerVerifiedImageReceiptRegistry(
        _TEST_AUTHORITY, lambda *args: _signed(replaced)
    )
    with pytest.raises(image.StrixImageContractError, match="receipt was replaced"):
        image.evaluate_image_admission(contract, [receipt], receipt_registry=registry)


def test_even_authentic_receipts_cannot_be_replayed_for_another_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(image, "_CONTROLLER_RECEIPT_PUBLIC_KEYS", (_TEST_PUBLIC_KEY,))
    original = image.StrixImageContract.from_mapping(_contract_document())
    receipts = _receipts(original)
    changed = original.to_dict()
    changed["sbom_digest"] = _digest("other-sbom")
    contract = image.StrixImageContract.from_mapping(changed)
    with pytest.raises(image.StrixImageContractError, match="registry receipt contract"):
        image.evaluate_image_admission(contract, receipts, receipt_registry=_registry(receipts))


def test_registry_reopens_each_exact_receipt_and_does_not_cache_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(image, "_CONTROLLER_RECEIPT_PUBLIC_KEYS", (_TEST_PUBLIC_KEY,))
    contract = image.StrixImageContract.from_mapping(_contract_document())
    receipts = _receipts(contract)
    retained = {receipt.receipt_digest: _signed(receipt) for receipt in receipts}
    calls: list[tuple[str, str]] = []

    def reopen(contract_digest: str, receipt_digest: str) -> image.SignedImageQualificationReceipt:
        calls.append((contract_digest, receipt_digest))
        return retained[receipt_digest]

    registry = image.ControllerVerifiedImageReceiptRegistry(_TEST_AUTHORITY, reopen)
    assert image.evaluate_image_admission(
        contract, receipts, receipt_registry=registry
    ).image_admitted_for_runtime
    assert calls == [(contract.contract_digest, receipt.receipt_digest) for receipt in receipts]
    del retained[receipts[-1].receipt_digest]
    with pytest.raises(image.StrixImageContractError, match="could not be reopened"):
        image.evaluate_image_admission(contract, receipts, receipt_registry=registry)
    monkeypatch.setattr(image, "_CONTROLLER_RECEIPT_PUBLIC_KEYS", ())
    with pytest.raises(image.StrixImageContractError, match="authority is not configured"):
        image.evaluate_image_admission(contract, receipts, receipt_registry=registry)


@pytest.mark.parametrize("kind", ["unsigned", "wrong-domain", "wrong-verifier", "bool-envelope"])
def test_registry_does_not_treat_response_assertions_as_authentication(
    kind: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(image, "_CONTROLLER_RECEIPT_PUBLIC_KEYS", (_TEST_PUBLIC_KEY,))
    contract = image.StrixImageContract.from_mapping(_contract_document())
    receipt = _receipts(contract)[0]
    if kind == "wrong-verifier":
        row = receipt.to_dict()
        row["verifier_digest"] = _digest("attacker-verifier")
        receipt = image.StrixImageQualificationReceipt.from_mapping(row)
    envelopes: dict[str, Any] = {
        "unsigned": image.SignedImageQualificationReceipt(receipt.canonical_bytes, b""),
        "wrong-domain": image.SignedImageQualificationReceipt(
            receipt.canonical_bytes, _TEST_SIGNER.sign(receipt.canonical_bytes)
        ),
        "wrong-verifier": _signed(receipt),
        "bool-envelope": {"verified": True, "receipt": receipt},
    }
    registry = image.ControllerVerifiedImageReceiptRegistry(
        _TEST_AUTHORITY, lambda *args: envelopes[kind]
    )
    with pytest.raises(image.StrixImageContractError):
        image.evaluate_image_admission(contract, [receipt], receipt_registry=registry)
