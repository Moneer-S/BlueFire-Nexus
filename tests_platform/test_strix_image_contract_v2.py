"""Synthetic V2 image assertions never establish real qualification."""

from __future__ import annotations

import copy
import hashlib
import json
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from bluefire import strix_image_contract as image
from bluefire import strix_policy_overlay, strix_startup_overlay
from bluefire.util import canonical_json_bytes, content_hash

_TEST_SIGNER = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
_TEST_PUBLIC_KEY = _TEST_SIGNER.public_key().public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw
)
_TEST_AUTHORITY = "sha256:" + hashlib.sha256(_TEST_PUBLIC_KEY).hexdigest()
_INDEX = "application/vnd.oci.image.index.v1+json"
_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
_CONFIG = "application/vnd.oci.image.config.v1+json"


def _digest(label: str) -> str:
    return content_hash({"synthetic-v2-image-test": label})


def _contract_document() -> dict[str, Any]:
    upstream_index_digest = image.REVIEWED_UPSTREAM_INDEX_REFERENCE.rsplit("@", 1)[-1]
    derived_index_digest = _digest("derived-index")
    upstream_inventory_digest = _digest("upstream-oci-inventory")
    sbom_digest = _digest("derived-sbom")
    return {
        "schema_version": "bluefire.strix-derived-image.v2",
        "source_revision": image.STRIX_SOURCE_REVISION,
        "source_tree_digest": _digest("source-tree"),
        "upstream_image": {
            "index_reference": image.REVIEWED_UPSTREAM_INDEX_REFERENCE,
            "index": {"digest": upstream_index_digest, "media_type": _INDEX},
            "platform_child": {
                "digest": _digest("upstream-child"),
                "media_type": _MANIFEST,
                "platform": image.TESTED_PLATFORM,
            },
            "config": {
                "digest": _digest("upstream-config"),
                "media_type": _CONFIG,
                "platform": image.TESTED_PLATFORM,
            },
            "inventory_digest": upstream_inventory_digest,
            "qualification_receipt_digest": _digest("upstream-qualification"),
        },
        "dockerfile_from": {
            "reference": image.REVIEWED_UPSTREAM_INDEX_REFERENCE,
            "platform_child_manifest_digest": _digest("upstream-child"),
            "config_digest": _digest("upstream-config"),
        },
        "derived_image": {
            "index_reference": "registry.example/bluefire/strix@" + derived_index_digest,
            "index": {"digest": derived_index_digest, "media_type": _INDEX},
            "platform_child": {
                "digest": _digest("derived-child"),
                "media_type": _MANIFEST,
                "platform": image.TESTED_PLATFORM,
            },
            "config": {
                "digest": _digest("derived-config"),
                "media_type": _CONFIG,
                "platform": image.TESTED_PLATFORM,
            },
        },
        "dockerfile_digest": _digest("actual-dockerfile"),
        "dependency_lock_digest": _digest("complete-dependency-lock"),
        "sbom_digest": sbom_digest,
        "provenance_digest": _digest("provenance"),
        "attestation_digest": _digest("attestation"),
        "components": image.pinned_image_components(),
        "platform": image.TESTED_PLATFORM,
        "runtime_profile": image.proposed_image_runtime_profile(
            network_id="a" * 64,
            network_name="bluefire-engine-" + "b" * 32,
            network_policy_digest=_digest("network-policy"),
        ),
        "prompt_overlay_receipt": {
            "schema_version": "bluefire.strix-prompt-overlay.v1",
            "source_revision": image.STRIX_SOURCE_REVISION,
            "upstream_sha256": strix_policy_overlay.REVIEWED_PROMPT_SHA256,
            "overlay_sha256": strix_policy_overlay.OVERLAY_SHA256,
            "patched_sha256": strix_policy_overlay.PATCHED_PROMPT_SHA256,
        },
        "startup_overlay_receipt": {
            "schema_version": "bluefire.strix-startup-overlay.v1",
            "source_revision": image.STRIX_SOURCE_REVISION,
            "upstream_sha256": strix_startup_overlay.REVIEWED_STARTUP_SHA256,
            "overlay_sha256": strix_startup_overlay.STARTUP_OVERLAY_SHA256,
            "patched_sha256": strix_startup_overlay.PATCHED_STARTUP_SHA256,
        },
        "upstream_notice_review": {
            "notice_report_digest": _digest("upstream-notice-report"),
            "notices_complete": False,
            "license_review_complete": False,
            "redistribution_rights_confirmed": None,
        },
        "derived_notice_review": {
            "notice_report_digest": _digest("derived-notice-report"),
            "notices_complete": False,
            "license_review_complete": False,
            "redistribution_rights_confirmed": None,
        },
        "redistribution_review": image.blocked_image_redistribution_review(),
    }


def _receipt_document(contract: image.StrixImageContractV2, check: str) -> dict[str, Any]:
    row = contract.to_dict()
    upstream = row["upstream_image"]
    derived = row["derived_image"]
    return {
        "schema_version": "bluefire.strix-image-qualification.v2",
        "stage": "local-build" if check in image.LOCAL_BUILD_CHECKS else "hosted-qualification",
        "check": check,
        "contract_digest": contract.contract_digest,
        "image_identity_digest": contract.image_identity_digest,
        "runtime_profile_digest": contract.runtime_profile_digest,
        "upstream_index_digest": upstream["index"]["digest"],
        "upstream_child_manifest_digest": upstream["platform_child"]["digest"],
        "upstream_config_digest": upstream["config"]["digest"],
        "derived_index_digest": derived["index"]["digest"],
        "derived_child_manifest_digest": derived["platform_child"]["digest"],
        "derived_config_digest": derived["config"]["digest"],
        "source_revision": image.STRIX_SOURCE_REVISION,
        "platform": image.TESTED_PLATFORM,
        "runner_digest": _digest("synthetic-runner"),
        "verifier_digest": _TEST_AUTHORITY,
        "evidence_digest": _digest(check),
        "checked_at": "2026-11-04T16:00:00Z",
        "passed": True,
    }


def _receipts(contract: image.StrixImageContractV2) -> list[image.StrixImageQualificationReceiptV2]:
    return [
        image.StrixImageQualificationReceiptV2.from_mapping(_receipt_document(contract, check))
        for check in image.LOCAL_BUILD_CHECKS + image.HOSTED_QUALIFICATION_CHECKS
    ]


def _signed(
    receipt: image.StrixImageQualificationReceiptV2,
    *,
    domain: bytes = image._RECEIPT_SIGNATURE_DOMAIN_V2,
) -> image.SignedImageQualificationReceiptV2:
    message = domain + _TEST_AUTHORITY.encode("ascii") + b"\x00" + receipt.canonical_bytes
    return image.SignedImageQualificationReceiptV2(
        receipt.canonical_bytes, _TEST_SIGNER.sign(message)
    )


def _registry(
    receipts: list[image.StrixImageQualificationReceiptV2],
) -> image.ControllerVerifiedImageReceiptRegistryV2:
    retained = {receipt.receipt_digest: _signed(receipt) for receipt in receipts}
    return image.ControllerVerifiedImageReceiptRegistryV2(
        _TEST_AUTHORITY, lambda _contract_digest, receipt_digest: retained[receipt_digest]
    )


def _evaluate(
    contract: image.StrixImageContractV2,
    receipts: list[image.StrixImageQualificationReceiptV2],
) -> image.StrixImageAdmissionDecisionV2:
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(image, "_CONTROLLER_RECEIPT_PUBLIC_KEYS_V2", (_TEST_PUBLIC_KEY,))
        return image.evaluate_image_admission_v2(
            contract, receipts, receipt_registry=_registry(receipts)
        )


def test_v2_requires_all_twelve_authenticated_checks_and_keeps_other_gates_closed() -> None:
    contract = image.StrixImageContractV2.from_mapping(_contract_document())
    receipts = _receipts(contract)
    assert len(receipts) == 12
    decision = _evaluate(contract, receipts)
    assert decision.local_build_qualified
    assert decision.hosted_qualification_complete
    assert decision.image_admitted_for_runtime
    assert decision.missing_checks == ()
    assert not decision.notices_complete
    assert not decision.license_review_complete
    assert decision.redistribution_rights_confirmed is None
    assert not decision.redistribution_authorized
    assert not decision.production_runtime_admitted
    assert not decision.live_execution_proven


@pytest.mark.parametrize("omitted", range(12))
def test_v2_every_exact_check_is_required(omitted: int) -> None:
    contract = image.StrixImageContractV2.from_mapping(_contract_document())
    receipts = _receipts(contract)
    missing = receipts.pop(omitted).to_dict()["check"]
    decision = _evaluate(contract, receipts)
    assert not decision.image_admitted_for_runtime
    assert decision.missing_checks == (missing,)


@pytest.mark.parametrize("field", tuple(_contract_document()))
def test_v2_missing_contract_fields_refuse(field: str) -> None:
    row = _contract_document()
    del row[field]
    with pytest.raises(image.StrixImageContractError):
        image.StrixImageContractV2.from_mapping(row)


@pytest.mark.parametrize(
    ("path", "replacement"),
    [
        (
            ("upstream_image", "index_reference"),
            "ghcr.io/usestrix/strix-sandbox@" + _digest("elsewhere"),
        ),
        (("upstream_image", "index", "digest"), _digest("elsewhere")),
        (
            ("upstream_image", "platform_child", "digest"),
            image.REVIEWED_UPSTREAM_INDEX_REFERENCE.rsplit("@", 1)[-1],
        ),
        (("upstream_image", "platform_child", "media_type"), _INDEX),
        (("upstream_image", "config", "digest"), _digest("upstream-child")),
        (("upstream_image", "config", "media_type"), _MANIFEST),
        (("upstream_image", "config", "platform"), "linux/arm64"),
        (("dockerfile_from", "reference"), "registry.example/other/base@" + _digest("other-base")),
        (("dockerfile_from", "platform_child_manifest_digest"), _digest("other-child")),
        (("dockerfile_from", "config_digest"), _digest("other-config")),
        (("derived_image", "index_reference"), image.REVIEWED_UPSTREAM_INDEX_REFERENCE),
        (("derived_image", "index", "digest"), _digest("upstream-child")),
        (("derived_image", "platform_child", "digest"), _digest("derived-index")),
        (("derived_image", "config", "digest"), _digest("derived-child")),
        (("derived_image", "config", "media_type"), _MANIFEST),
        (("derived_image", "platform_child", "platform"), "linux/arm64"),
        (("upstream_image", "inventory_digest"), None),
        (("upstream_image", "qualification_receipt_digest"), None),
        (("prompt_overlay_receipt", "upstream_sha256"), "0" * 64),
        (("prompt_overlay_receipt", "patched_sha256"), "0" * 64),
        (("startup_overlay_receipt", "overlay_sha256"), "0" * 64),
        (("derived_notice_review", "notices_complete"), True),
        (("upstream_notice_review", "redistribution_rights_confirmed"), True),
        (("upstream_notice_review", "notice_report_digest"), _digest("upstream-oci-inventory")),
        (("derived_notice_review", "notice_report_digest"), _digest("derived-sbom")),
    ],
)
def test_v2_rejects_substituted_lineage_and_review_claims(
    path: tuple[str, ...], replacement: Any
) -> None:
    row = _contract_document()
    target = row
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = replacement
    with pytest.raises(image.StrixImageContractError):
        image.StrixImageContractV2.from_mapping(row)


@pytest.mark.parametrize(
    "reference",
    [
        "registry.example//bluefire/strix@" + _digest("derived-index"),
        "REGISTRY.example/bluefire/strix@" + _digest("derived-index"),
        "https://registry.example/bluefire/strix@" + _digest("derived-index"),
        "registry.example/bluefire/../strix@" + _digest("derived-index"),
        "registry.example/bluefire/strix:latest@" + _digest("derived-index"),
        "registry.example:080/bluefire/strix@" + _digest("derived-index"),
        "registry.example:443/bluefire/strix@" + _digest("derived-index"),
        "registry.example:5000/bluefire/strix@" + _digest("derived-index"),
        "strix@" + _digest("derived-index"),
    ],
)
def test_v2_rejects_noncanonical_derived_references(reference: str) -> None:
    row = _contract_document()
    row["derived_image"]["index_reference"] = reference
    with pytest.raises(image.StrixImageContractError):
        image.StrixImageContractV2.from_mapping(row)


def test_v2_public_reference_validator_matches_contract_grammar() -> None:
    reference = _contract_document()["derived_image"]["index_reference"]
    assert image.validate_v2_image_reference(reference) == reference
    assert image.validate_v2_image_reference("localhost/bluefire/strix@" + _digest("local"))
    for bad in (
        "registry.example:5000/bluefire/strix@" + _digest("derived-index"),
        "registry.example/bluefire/strix:latest@" + _digest("derived-index"),
        "bluefire/strix@" + _digest("derived-index"),
        "https://registry.example/bluefire/strix@" + _digest("derived-index"),
        "registry.example/bluefire/strix@sha256:" + "A" * 64,
    ):
        with pytest.raises(image.StrixImageContractError):
            image.validate_v2_image_reference(bad)


def test_v2_derived_image_cannot_reuse_the_upstream_repository() -> None:
    row = _contract_document()
    row["derived_image"]["index_reference"] = "ghcr.io/usestrix/strix-sandbox@" + _digest(
        "derived-index"
    )
    with pytest.raises(image.StrixImageContractError, match="separate controlled repository"):
        image.StrixImageContractV2.from_mapping(row)


def test_v2_accepts_qualified_docker_media_roles_without_aliasing_them() -> None:
    row = _contract_document()
    for image_row in (row["upstream_image"], row["derived_image"]):
        image_row["index"][
            "media_type"
        ] = "application/vnd.docker.distribution.manifest.list.v2+json"
        image_row["platform_child"][
            "media_type"
        ] = "application/vnd.docker.distribution.manifest.v2+json"
        image_row["config"]["media_type"] = "application/vnd.docker.container.image.v1+json"
    contract = image.StrixImageContractV2.from_mapping(row)
    assert contract.to_dict()["upstream_image"]["config"]["media_type"] == (
        "application/vnd.docker.container.image.v1+json"
    )


def test_v2_rejects_extra_fields_noncanonical_bytes_and_rights_promotion() -> None:
    row = _contract_document()
    row["upstream_image"]["unreviewed"] = True
    with pytest.raises(image.StrixImageContractError):
        image.StrixImageContractV2.from_mapping(row)
    row = _contract_document()
    row["redistribution_review"]["redistribution_authorized"] = True
    with pytest.raises(image.StrixImageContractError):
        image.StrixImageContractV2.from_mapping(row)
    contract = image.StrixImageContractV2.from_mapping(_contract_document())
    with pytest.raises(image.StrixImageContractError):
        image.StrixImageContractV2(json.dumps(contract.to_dict(), indent=2).encode())
    with pytest.raises(image.StrixImageContractError):
        image.StrixImageContractV2(b'{"platform":"linux/arm64",' + contract.canonical_bytes[1:])


@pytest.mark.parametrize(
    "field",
    [
        "contract_digest",
        "image_identity_digest",
        "runtime_profile_digest",
        "upstream_index_digest",
        "upstream_child_manifest_digest",
        "upstream_config_digest",
        "derived_index_digest",
        "derived_child_manifest_digest",
        "derived_config_digest",
    ],
)
def test_v2_authenticated_receipts_bind_every_identity(field: str) -> None:
    contract = image.StrixImageContractV2.from_mapping(_contract_document())
    row = _receipt_document(contract, image.LOCAL_BUILD_CHECKS[0])
    row[field] = _digest("substituted-" + field)
    receipt = image.StrixImageQualificationReceiptV2.from_mapping(row)
    with pytest.raises(image.StrixImageContractError):
        _evaluate(contract, [receipt])


def test_v2_mixed_receipts_duplicates_and_extra_fields_refuse() -> None:
    contract = image.StrixImageContractV2.from_mapping(_contract_document())
    receipts = _receipts(contract)
    with pytest.raises(image.StrixImageContractError, match="duplicate"):
        _evaluate(contract, [receipts[0], receipts[0]])
    v1_row = {
        name: value
        for name, value in receipts[0].to_dict().items()
        if name
        in {
            "schema_version",
            "stage",
            "check",
            "contract_digest",
            "runtime_profile_digest",
            "source_revision",
            "platform",
            "runner_digest",
            "verifier_digest",
            "evidence_digest",
            "checked_at",
            "passed",
        }
    }
    v1_row["schema_version"] = "bluefire.strix-image-qualification.v1"
    v1_row["image_digest"] = contract.to_dict()["derived_image"]["index"]["digest"]
    v1_receipt = image.StrixImageQualificationReceipt.from_mapping(v1_row)
    with pytest.raises(image.StrixImageContractError, match="not been parsed"):
        image.evaluate_image_admission_v2(contract, [v1_receipt])  # type: ignore[list-item]
    row = _receipt_document(contract, image.LOCAL_BUILD_CHECKS[0])
    row["redistribution_authorized"] = True
    with pytest.raises(image.StrixImageContractError):
        image.StrixImageQualificationReceiptV2.from_mapping(row)
    row = _receipt_document(contract, image.LOCAL_BUILD_CHECKS[0])
    with pytest.raises(image.StrixImageContractError):
        image.StrixImageQualificationReceiptV2(json.dumps(row, indent=2).encode())


def test_v2_replay_across_changed_contract_and_replacement_refuse() -> None:
    original = image.StrixImageContractV2.from_mapping(_contract_document())
    receipts = _receipts(original)
    changed = copy.deepcopy(original.to_dict())
    changed["dockerfile_digest"] = _digest("other-dockerfile")
    contract = image.StrixImageContractV2.from_mapping(changed)
    with pytest.raises(image.StrixImageContractError, match="registry V2 receipt contract"):
        _evaluate(contract, receipts)
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(image, "_CONTROLLER_RECEIPT_PUBLIC_KEYS_V2", (_TEST_PUBLIC_KEY,))
        replacement_row = receipts[0].to_dict()
        replacement_row["evidence_digest"] = _digest("other-evidence")
        replacement = image.StrixImageQualificationReceiptV2.from_mapping(replacement_row)
        registry = image.ControllerVerifiedImageReceiptRegistryV2(
            _TEST_AUTHORITY, lambda *_args: _signed(replacement)
        )
        with pytest.raises(image.StrixImageContractError, match="was replaced"):
            image.evaluate_image_admission_v2(original, receipts[:1], receipt_registry=registry)


def test_v2_wrong_signature_domain_and_v1_registry_refuse() -> None:
    contract = image.StrixImageContractV2.from_mapping(_contract_document())
    receipt = _receipts(contract)[0]
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(image, "_CONTROLLER_RECEIPT_PUBLIC_KEYS_V2", (_TEST_PUBLIC_KEY,))
        registry = image.ControllerVerifiedImageReceiptRegistryV2(
            _TEST_AUTHORITY,
            lambda *_args: _signed(receipt, domain=image._RECEIPT_SIGNATURE_DOMAIN),
        )
        with pytest.raises(image.StrixImageContractError, match="signature is invalid"):
            image.evaluate_image_admission_v2(contract, [receipt], receipt_registry=registry)
    with pytest.raises(image.StrixImageContractError, match="not a controller capability"):
        image.evaluate_image_admission_v2(
            contract,
            [receipt],
            receipt_registry=object(),  # type: ignore[arg-type]
        )


def test_v2_untrusted_signer_missing_retention_and_key_revocation_refuse() -> None:
    contract = image.StrixImageContractV2.from_mapping(_contract_document())
    receipt = _receipts(contract)[0]
    attacker = Ed25519PrivateKey.from_private_bytes(bytes(reversed(range(32))))
    message = (
        image._RECEIPT_SIGNATURE_DOMAIN_V2
        + _TEST_AUTHORITY.encode("ascii")
        + b"\x00"
        + receipt.canonical_bytes
    )
    forged = image.SignedImageQualificationReceiptV2(
        receipt.canonical_bytes, attacker.sign(message)
    )
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(image, "_CONTROLLER_RECEIPT_PUBLIC_KEYS_V2", (_TEST_PUBLIC_KEY,))
        registry = image.ControllerVerifiedImageReceiptRegistryV2(
            _TEST_AUTHORITY, lambda *_args: forged
        )
        with pytest.raises(image.StrixImageContractError, match="signature is invalid"):
            image.evaluate_image_admission_v2(contract, [receipt], receipt_registry=registry)
        retained = {receipt.receipt_digest: _signed(receipt)}
        registry = image.ControllerVerifiedImageReceiptRegistryV2(
            _TEST_AUTHORITY, lambda _contract_digest, digest: retained[digest]
        )
        assert not image.evaluate_image_admission_v2(
            contract, [receipt], receipt_registry=registry
        ).image_admitted_for_runtime
        retained.clear()
        with pytest.raises(image.StrixImageContractError, match="could not be reopened"):
            image.evaluate_image_admission_v2(contract, [receipt], receipt_registry=registry)
        patch.setattr(image, "_CONTROLLER_RECEIPT_PUBLIC_KEYS_V2", ())
        with pytest.raises(image.StrixImageContractError, match="authority is not configured"):
            image.evaluate_image_admission_v2(contract, [receipt], receipt_registry=registry)


def test_v2_registry_subclass_cannot_override_verification() -> None:
    contract = image.StrixImageContractV2.from_mapping(_contract_document())
    receipt = _receipts(contract)[0]

    class ForgedRegistry(image.ControllerVerifiedImageReceiptRegistryV2):
        def reopen_verified(
            self, *, contract_digest: str, receipt_digest: str
        ) -> image.StrixImageQualificationReceiptV2:
            pytest.fail("subclass callback must not run")

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(image, "_CONTROLLER_RECEIPT_PUBLIC_KEYS_V2", (_TEST_PUBLIC_KEY,))
        registry = ForgedRegistry(_TEST_AUTHORITY, lambda *_args: _signed(receipt))
        with pytest.raises(image.StrixImageContractError, match="not a controller capability"):
            image.evaluate_image_admission_v2(contract, [receipt], receipt_registry=registry)


def test_v2_production_authority_is_unconfigured_and_declaration_stays_closed() -> None:
    assert image._CONTROLLER_RECEIPT_PUBLIC_KEYS_V2 == ()
    contract = image.StrixImageContractV2.from_mapping(_contract_document())
    receipts = _receipts(contract)
    with pytest.raises(image.StrixImageContractError, match="registry is unavailable"):
        image.evaluate_image_admission_v2(contract, receipts)
    with pytest.raises(image.StrixImageContractError, match="authority is not configured"):
        _registry(receipts)
    blocked = image.evaluate_image_admission_v2(contract, [])
    assert not blocked.image_admitted_for_runtime
    assert len(blocked.missing_checks) == 12


def test_v2_canonical_contract_and_receipt_digests_match_their_bytes() -> None:
    contract = image.StrixImageContractV2.from_mapping(_contract_document())
    receipt = _receipts(contract)[0]
    assert contract.canonical_bytes == canonical_json_bytes(contract.to_dict())
    assert receipt.canonical_bytes == canonical_json_bytes(receipt.to_dict())
    assert (
        contract.contract_digest == "sha256:" + hashlib.sha256(contract.canonical_bytes).hexdigest()
    )
    assert receipt.receipt_digest == "sha256:" + hashlib.sha256(receipt.canonical_bytes).hexdigest()
