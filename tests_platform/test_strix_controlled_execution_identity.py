from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import asdict
from typing import Any

import pytest

from bluefire import strix_image_contract as image
from bluefire.strix_adapter import StrixBuildIdentity
from bluefire.strix_controlled_backend import ControlledRuntimeProfile
from bluefire.strix_controlled_execution_identity import (
    DERIVED_IMAGE_SCHEMA_VERSION,
    RECEIPT_SET_SCHEMA_VERSION,
    SCHEMA_VERSION,
    StrixControlledExecutionIdentityError,
    StrixControlledExecutionIdentityV2,
)
from bluefire.strix_image_contract import (
    HOSTED_QUALIFICATION_CHECKS,
    LOCAL_BUILD_CHECKS,
    REVIEWED_UPSTREAM_INDEX_REFERENCE,
)
from bluefire.strix_policy_overlay import (
    OVERLAY_SHA256,
    PATCHED_PROMPT_SHA256,
    REVIEWED_PROMPT_SHA256,
)
from bluefire.strix_startup_overlay import (
    PATCHED_STARTUP_SHA256,
    REVIEWED_STARTUP_SHA256,
    STARTUP_OVERLAY_SHA256,
)
from bluefire.util import canonical_json_bytes, content_hash


def _digest(character: str) -> str:
    return "sha256:" + character * 64


def _profile(*, build_ref: str, image_reference: str) -> ControlledRuntimeProfile:
    return ControlledRuntimeProfile.create(
        attempt_id="engine-attempt-" + "a" * 32,
        build_digest=build_ref,
        policy_digest=_digest("2"),
        relay_digest=_digest("3"),
        relay_upstream_digest=_digest("4"),
        relay_channel_digest=_digest("5"),
        relay_retry_digest=_digest("6"),
        boundary_digest=_digest("7"),
        admission_digest=_digest("8"),
        image_reference=image_reference,
        image_digest=image_reference.rsplit("@", 1)[1],
        manifest_digest=_digest("9"),  # Controlled workspace manifest, not OCI.
        sdk_digest=_digest("a"),
        bootstrap_digest=_digest("b"),
        tmpfs_contract_digest=_digest("c"),
        sandbox_uid=1000,
        sandbox_gid=1000,
    )


def _identity() -> dict[str, Any]:
    upstream = REVIEWED_UPSTREAM_INDEX_REFERENCE
    derived = "registry.example/strix-controlled@" + _digest("e")
    build = StrixBuildIdentity(
        source_revision="6b7ae2ebe4d47037a927aade23265ff4e4f27e84",
        source_tree_sha256=_digest("f"),
        package_sha256=_digest("1"),
        executable_sha256=_digest("2"),
        image_reference=upstream,
        image_inventory_sha256=_digest("3"),
        prompt_upstream_sha256="sha256:" + REVIEWED_PROMPT_SHA256,
        prompt_overlay_sha256="sha256:" + OVERLAY_SHA256,
        prompt_patched_sha256="sha256:" + PATCHED_PROMPT_SHA256,
    )
    build_row = build.to_dict()
    build_ref = content_hash(build_row)
    profile = _profile(build_ref=build_ref, image_reference=derived)
    receipts = {
        check: content_hash(check) for check in LOCAL_BUILD_CHECKS + HOSTED_QUALIFICATION_CHECKS
    }
    authority = _digest("4")
    contract_digest = _digest("5")
    return {
        "schema_version": SCHEMA_VERSION,
        "attempt_id": profile.attempt_id,
        "startup_build_identity": build_row,
        "startup_build_ref": build_ref,
        "runtime_qualification_ref": _digest("6"),
        "upstream_oci_index_reference": upstream,
        "upstream_oci_index_digest": upstream.rsplit("@", 1)[1],
        "upstream_oci_platform": "linux/amd64",
        "upstream_oci_child_manifest_digest": _digest("7"),
        "upstream_oci_config_digest": _digest("8"),
        "upstream_oci_inventory_ref": build.image_inventory_sha256,
        "prompt_upstream_sha256": build.prompt_upstream_sha256,
        "prompt_overlay_sha256": build.prompt_overlay_sha256,
        "prompt_patched_sha256": build.prompt_patched_sha256,
        "startup_upstream_sha256": "sha256:" + REVIEWED_STARTUP_SHA256,
        "startup_overlay_sha256": "sha256:" + STARTUP_OVERLAY_SHA256,
        "startup_patched_sha256": "sha256:" + PATCHED_STARTUP_SHA256,
        "private_transfer_bundle_ref": _digest("9"),
        "private_transport_provenance_ref": _digest("a"),
        "derived_image_contract_schema": DERIVED_IMAGE_SCHEMA_VERSION,
        "derived_image_contract_ref": contract_digest,
        "derived_image_contract_digest": contract_digest,
        "derived_image_decision_ref": _digest("c"),
        "derived_image_reference": derived,
        "derived_image_digest": _digest("e"),
        "platform_child_manifest_digest": _digest("f"),
        "image_config_digest": _digest("0"),
        "image_relation_receipt_ref": _digest("1"),
        "receipt_authority_ref": authority,
        "authenticated_receipts": receipts,
        "authenticated_receipt_set_ref": content_hash(
            {
                "schema_version": RECEIPT_SET_SCHEMA_VERSION,
                "contract_digest": contract_digest,
                "authority_ref": authority,
                "receipts": receipts,
            }
        ),
        "controlled_runtime_profile": asdict(profile),
        "controlled_runtime_profile_ref": profile.profile_digest,
        "worker_transport_ref": _digest("2"),
        "worker_channel_ref": _digest("3"),
        "package_artifact_digest": build.package_sha256,
    }


def _with_profile(row: dict[str, Any], profile: ControlledRuntimeProfile) -> None:
    row["controlled_runtime_profile"] = asdict(profile)
    row["controlled_runtime_profile_ref"] = profile.profile_digest


def _public_image_contract(row: dict[str, Any]) -> image.StrixImageContractV2:
    """Build one synthetic, canonical V2 contract through its public parser."""

    upstream = row["upstream_oci_index_reference"]
    derived = row["derived_image_reference"]
    sbom = content_hash("synthetic-derived-sbom")
    index_media = "application/vnd.oci.image.index.v1+json"
    manifest_media = "application/vnd.oci.image.manifest.v1+json"
    config_media = "application/vnd.oci.image.config.v1+json"
    source_revision = row["startup_build_identity"]["source_revision"]
    document = {
        "schema_version": DERIVED_IMAGE_SCHEMA_VERSION,
        "source_revision": source_revision,
        "source_tree_digest": row["startup_build_identity"]["source_tree_sha256"],
        "upstream_image": {
            "index_reference": upstream,
            "index": {"digest": row["upstream_oci_index_digest"], "media_type": index_media},
            "platform_child": {
                "digest": row["upstream_oci_child_manifest_digest"],
                "media_type": manifest_media,
                "platform": "linux/amd64",
            },
            "config": {
                "digest": row["upstream_oci_config_digest"],
                "media_type": config_media,
                "platform": "linux/amd64",
            },
            "inventory_digest": row["upstream_oci_inventory_ref"],
            "qualification_receipt_digest": content_hash("synthetic-upstream-OCI-qualification"),
        },
        "dockerfile_from": {
            "reference": upstream,
            "platform_child_manifest_digest": row["upstream_oci_child_manifest_digest"],
            "config_digest": row["upstream_oci_config_digest"],
        },
        "derived_image": {
            "index_reference": derived,
            "index": {"digest": row["derived_image_digest"], "media_type": index_media},
            "platform_child": {
                "digest": row["platform_child_manifest_digest"],
                "media_type": manifest_media,
                "platform": "linux/amd64",
            },
            "config": {
                "digest": row["image_config_digest"],
                "media_type": config_media,
                "platform": "linux/amd64",
            },
        },
        "dockerfile_digest": content_hash("synthetic-dockerfile"),
        "dependency_lock_digest": content_hash("synthetic-lock"),
        "sbom_digest": sbom,
        "provenance_digest": content_hash("synthetic-provenance"),
        "attestation_digest": content_hash("synthetic-attestation"),
        "components": image.pinned_image_components(),
        "platform": "linux/amd64",
        "runtime_profile": image.proposed_image_runtime_profile(
            network_id="a" * 64,
            network_name="bluefire-engine-" + "b" * 32,
            network_policy_digest=content_hash("synthetic-network-policy"),
        ),
        "prompt_overlay_receipt": {
            "schema_version": "bluefire.strix-prompt-overlay.v1",
            "source_revision": source_revision,
            "upstream_sha256": REVIEWED_PROMPT_SHA256,
            "overlay_sha256": OVERLAY_SHA256,
            "patched_sha256": PATCHED_PROMPT_SHA256,
        },
        "startup_overlay_receipt": {
            "schema_version": "bluefire.strix-startup-overlay.v1",
            "source_revision": source_revision,
            "upstream_sha256": REVIEWED_STARTUP_SHA256,
            "overlay_sha256": STARTUP_OVERLAY_SHA256,
            "patched_sha256": PATCHED_STARTUP_SHA256,
        },
        "upstream_notice_review": {
            "notice_report_digest": content_hash("synthetic-upstream-notice-report"),
            "notices_complete": False,
            "license_review_complete": False,
            "redistribution_rights_confirmed": None,
        },
        "derived_notice_review": {
            "notice_report_digest": content_hash("synthetic-derived-notice-report"),
            "notices_complete": False,
            "license_review_complete": False,
            "redistribution_rights_confirmed": None,
        },
        "redistribution_review": image.blocked_image_redistribution_review(),
    }
    return image.StrixImageContractV2.from_mapping(document)


def _bind_contract(row: dict[str, Any], contract: image.StrixImageContractV2) -> None:
    row["derived_image_contract_ref"] = contract.contract_digest
    row["derived_image_contract_digest"] = contract.contract_digest
    row["authenticated_receipt_set_ref"] = content_hash(
        {
            "schema_version": RECEIPT_SET_SCHEMA_VERSION,
            "contract_digest": contract.contract_digest,
            "authority_ref": row["receipt_authority_ref"],
            "receipts": row["authenticated_receipts"],
        }
    )


def test_canonical_round_trip_digest_and_repr_are_stable() -> None:
    source = _identity()
    identity = StrixControlledExecutionIdentityV2.from_mapping(source)
    assert identity.to_dict() == source
    assert identity.canonical_bytes == canonical_json_bytes(source)
    assert (
        identity.identity_digest == "sha256:" + hashlib.sha256(identity.canonical_bytes).hexdigest()
    )
    assert StrixControlledExecutionIdentityV2(identity.canonical_bytes) == identity
    assert (
        StrixControlledExecutionIdentityV2.from_mapping(dict(reversed(list(source.items()))))
        == identity
    )
    source["authenticated_receipts"].clear()
    assert len(identity.to_dict()["authenticated_receipts"]) == 12
    assert "registry.example" not in repr(identity)
    assert "private" not in repr(identity)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("schema_version", "bluefire.strix-controlled-identity.v1"),
        ("attempt_id", "engine-attempt-/secrets"),
        ("startup_build_ref", _digest("0")),
        ("upstream_oci_index_reference", "registry.example/substitute@" + _digest("d")),
        ("upstream_oci_index_digest", _digest("e")),
        ("upstream_oci_platform", "linux/arm64"),
        ("upstream_oci_inventory_ref", _digest("0")),
        ("prompt_overlay_sha256", _digest("0")),
        ("startup_overlay_sha256", "sha256:" + OVERLAY_SHA256),
        ("derived_image_contract_schema", "bluefire.strix-derived-image.v1"),
        ("derived_image_contract_ref", _digest("b")),
        ("derived_image_digest", _digest("d")),
        ("upstream_oci_child_manifest_digest", _digest("e")),
        ("image_config_digest", _digest("f")),
        ("package_artifact_digest", _digest("e")),
        ("private_transport_provenance_ref", "C:/secret/private-transfer.json"),
        ("worker_channel_ref", "unix:///tmp/controller.sock"),
    ],
)
def test_rejects_cross_contract_substitution(field: str, replacement: str) -> None:
    row = _identity()
    row[field] = replacement
    with pytest.raises(StrixControlledExecutionIdentityError):
        StrixControlledExecutionIdentityV2.from_mapping(row)


def test_rejects_v1_build_mutation_and_extra_fields() -> None:
    row = _identity()
    row["startup_build_identity"]["package_sha256"] = _digest("0")
    with pytest.raises(StrixControlledExecutionIdentityError):
        StrixControlledExecutionIdentityV2.from_mapping(row)

    row = _identity()
    row["startup_build_identity"]["secret_path"] = "C:/secret"
    with pytest.raises(StrixControlledExecutionIdentityError):
        StrixControlledExecutionIdentityV2.from_mapping(row)


@pytest.mark.parametrize("port", ("80", "443", "65536"))
def test_rejects_noncanonical_or_invalid_registry_ports(port: str) -> None:
    row = _identity()
    row["derived_image_reference"] = f"registry.example:{port}/controlled@{_digest('e')}"
    with pytest.raises(StrixControlledExecutionIdentityError):
        StrixControlledExecutionIdentityV2.from_mapping(row)


def test_rejects_swapped_controlled_profile_even_with_recomputed_profile_digest() -> None:
    row = _identity()
    _with_profile(
        row, _profile(build_ref=_digest("0"), image_reference=row["derived_image_reference"])
    )
    with pytest.raises(StrixControlledExecutionIdentityError):
        StrixControlledExecutionIdentityV2.from_mapping(row)

    row = _identity()
    _with_profile(
        row,
        _profile(
            build_ref=row["startup_build_ref"],
            image_reference="other.example/derived@" + _digest("0"),
        ),
    )
    with pytest.raises(StrixControlledExecutionIdentityError):
        StrixControlledExecutionIdentityV2.from_mapping(row)


def test_rejects_missing_extra_duplicate_and_swapped_receipts() -> None:
    row = _identity()
    row.pop("worker_transport_ref")
    with pytest.raises(StrixControlledExecutionIdentityError):
        StrixControlledExecutionIdentityV2.from_mapping(row)

    row = _identity()
    row["path"] = "/host/private"
    with pytest.raises(StrixControlledExecutionIdentityError):
        StrixControlledExecutionIdentityV2.from_mapping(row)

    row = _identity()
    row["authenticated_receipts"].pop(LOCAL_BUILD_CHECKS[0])
    with pytest.raises(StrixControlledExecutionIdentityError):
        StrixControlledExecutionIdentityV2.from_mapping(row)

    row = _identity()
    row["authenticated_receipts"]["extra-check"] = _digest("0")
    with pytest.raises(StrixControlledExecutionIdentityError):
        StrixControlledExecutionIdentityV2.from_mapping(row)

    row = _identity()
    checks = list(row["authenticated_receipts"])
    row["authenticated_receipts"][checks[0]] = row["authenticated_receipts"][checks[1]]
    with pytest.raises(StrixControlledExecutionIdentityError):
        StrixControlledExecutionIdentityV2.from_mapping(row)

    row = _identity()
    checks = list(row["authenticated_receipts"])
    row["authenticated_receipts"][checks[0]], row["authenticated_receipts"][checks[1]] = (
        row["authenticated_receipts"][checks[1]],
        row["authenticated_receipts"][checks[0]],
    )
    with pytest.raises(StrixControlledExecutionIdentityError):
        StrixControlledExecutionIdentityV2.from_mapping(row)


def test_rejects_noncanonical_and_ambiguous_bytes() -> None:
    row = _identity()
    canonical = canonical_json_bytes(row)
    with pytest.raises(StrixControlledExecutionIdentityError):
        StrixControlledExecutionIdentityV2(b" " + canonical)
    with pytest.raises(StrixControlledExecutionIdentityError):
        StrixControlledExecutionIdentityV2(
            canonical.replace(b'"attempt_id":', b'"attempt_id":"duplicate","attempt_id":', 1)
        )
    with pytest.raises(StrixControlledExecutionIdentityError):
        StrixControlledExecutionIdentityV2(json.dumps(row, indent=2).encode())


def test_rejects_profile_type_confusion_and_v1_only_input() -> None:
    row = _identity()
    row["controlled_runtime_profile"]["sandbox_uid"] = True
    with pytest.raises(StrixControlledExecutionIdentityError):
        StrixControlledExecutionIdentityV2.from_mapping(row)

    with pytest.raises(StrixControlledExecutionIdentityError):
        StrixControlledExecutionIdentityV2.from_mapping(_identity()["startup_build_identity"])


@pytest.mark.parametrize(
    "field",
    (
        "runtime_qualification_ref",
        "upstream_oci_child_manifest_digest",
        "upstream_oci_config_digest",
        "private_transfer_bundle_ref",
        "private_transport_provenance_ref",
        "derived_image_decision_ref",
        "platform_child_manifest_digest",
        "image_config_digest",
        "image_relation_receipt_ref",
        "worker_transport_ref",
        "worker_channel_ref",
    ),
)
def test_external_ref_substitution_changes_identity_digest(field: str) -> None:
    original = _identity()
    changed = _identity()
    changed[field] = content_hash({"substitute": field})
    before = StrixControlledExecutionIdentityV2.from_mapping(original)
    after = StrixControlledExecutionIdentityV2.from_mapping(changed)
    assert before.identity_digest != after.identity_digest


@pytest.mark.parametrize(
    "substitution",
    (
        "upstream-index",
        "upstream-child",
        "upstream-config",
        "derived-reference",
        "contract-digest",
        "relation-ref",
    ),
)
def test_v2_contract_projection_and_protected_identity_pin_refuse_substitution(
    substitution: str,
) -> None:
    row = _identity()
    contract = _public_image_contract(row)
    _bind_contract(row, contract)
    identity = StrixControlledExecutionIdentityV2.from_mapping(row)
    identity.verify_image_contract(contract)
    identity.require_expected_digest(identity.identity_digest)

    changed = copy.deepcopy(row)
    if substitution == "upstream-index":
        changed["upstream_oci_index_reference"] = "other.example/strix@" + _digest("a")
    elif substitution == "upstream-child":
        changed["upstream_oci_child_manifest_digest"] = _digest("a")
    elif substitution == "upstream-config":
        changed["upstream_oci_config_digest"] = _digest("a")
    elif substitution == "derived-reference":
        other = "other.example/derived@" + _digest("a")
        changed["derived_image_reference"] = other
        changed["derived_image_digest"] = _digest("a")
        _with_profile(
            changed, _profile(build_ref=changed["startup_build_ref"], image_reference=other)
        )
    elif substitution == "contract-digest":
        changed["derived_image_contract_ref"] = _digest("a")
        changed["derived_image_contract_digest"] = _digest("a")
        changed["authenticated_receipt_set_ref"] = content_hash(
            {
                "schema_version": RECEIPT_SET_SCHEMA_VERSION,
                "contract_digest": _digest("a"),
                "authority_ref": changed["receipt_authority_ref"],
                "receipts": changed["authenticated_receipts"],
            }
        )
    else:
        changed["image_relation_receipt_ref"] = _digest("a")

    try:
        substituted = StrixControlledExecutionIdentityV2.from_mapping(changed)
    except StrixControlledExecutionIdentityError:
        return
    assert substituted.identity_digest != identity.identity_digest
    if substitution == "relation-ref":
        substituted.verify_image_contract(contract)
        with pytest.raises(StrixControlledExecutionIdentityError):
            substituted.require_expected_digest(identity.identity_digest)
    else:
        with pytest.raises(StrixControlledExecutionIdentityError):
            substituted.verify_image_contract(contract)
