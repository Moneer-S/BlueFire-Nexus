"""Canonical, effect-free identity for a proposed controlled Strix execution.

This v2 identity binds references supplied by independently reviewed owners.
Parsing it does not authenticate receipts, inspect images, qualify a runtime, or
grant per-attempt authority. No v1 build or admission object is promoted to v2.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, fields
from typing import Any, Mapping, cast

from .strix_adapter import StrixBuildIdentity
from .strix_controlled_backend import ControlledRuntimeProfile
from .strix_image_contract import (
    HOSTED_QUALIFICATION_CHECKS,
    LOCAL_BUILD_CHECKS,
    REVIEWED_UPSTREAM_INDEX_REFERENCE,
    StrixImageContractError,
    StrixImageContractV2,
)
from .strix_startup_overlay import (
    PATCHED_STARTUP_SHA256,
    REVIEWED_STARTUP_SHA256,
    STARTUP_OVERLAY_SHA256,
)
from .util import canonical_json_bytes, content_hash

SCHEMA_VERSION = "bluefire.strix-controlled-execution-identity.v2"
DERIVED_IMAGE_SCHEMA_VERSION = "bluefire.strix-derived-image.v2"
RECEIPT_SET_SCHEMA_VERSION = "bluefire.strix-authenticated-image-receipt-set.v2"
TESTED_PLATFORM = "linux/amd64"
MAX_IDENTITY_BYTES = 32 * 1024

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_IMAGE = re.compile(
    r"(?P<registry>[a-z0-9]+(?:[.-][a-z0-9]+)*(?::[1-9][0-9]{0,4})?)/"
    r"(?P<repository>[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*)"
    r"@(?P<digest>sha256:[0-9a-f]{64})\Z"
)
_ATTEMPT = re.compile(r"engine-attempt-[0-9a-f]{32}\Z")
_BUILD_FIELDS = frozenset(
    {
        "engine",
        "package_version",
        "source_revision",
        "source_tree_sha256",
        "package_sha256",
        "executable_sha256",
        "image_reference",
        "image_inventory_sha256",
        "prompt_upstream_sha256",
        "prompt_overlay_sha256",
        "prompt_patched_sha256",
    }
)
_PROFILE_FIELDS = frozenset(
    {
        "schema_version",
        "attempt_id",
        "source_revision",
        "build_digest",
        "policy_digest",
        "relay_digest",
        "relay_upstream_digest",
        "relay_channel_digest",
        "relay_retry_digest",
        "boundary_digest",
        "admission_digest",
        "image_reference",
        "image_digest",
        "manifest_digest",
        "sdk_digest",
        "bootstrap_digest",
        "tmpfs_contract_digest",
        "sandbox_uid",
        "sandbox_gid",
        "profile_digest",
        "exec_timeout_seconds",
        "exec_output_limit_bytes",
        "workspace_object_limit_bytes",
        "write_chunk_bytes",
    }
)
_FIELDS = frozenset(
    {
        "schema_version",
        "attempt_id",
        "startup_build_identity",
        "startup_build_ref",
        "runtime_qualification_ref",
        "upstream_oci_index_reference",
        "upstream_oci_index_digest",
        "upstream_oci_platform",
        "upstream_oci_child_manifest_digest",
        "upstream_oci_config_digest",
        "upstream_oci_inventory_ref",
        "prompt_upstream_sha256",
        "prompt_overlay_sha256",
        "prompt_patched_sha256",
        "startup_upstream_sha256",
        "startup_overlay_sha256",
        "startup_patched_sha256",
        "private_transfer_bundle_ref",
        "private_transport_provenance_ref",
        "derived_image_contract_schema",
        "derived_image_contract_ref",
        "derived_image_contract_digest",
        "derived_image_decision_ref",
        "derived_image_reference",
        "derived_image_digest",
        "platform_child_manifest_digest",
        "image_config_digest",
        "image_relation_receipt_ref",
        "receipt_authority_ref",
        "authenticated_receipts",
        "authenticated_receipt_set_ref",
        "controlled_runtime_profile",
        "controlled_runtime_profile_ref",
        "worker_transport_ref",
        "worker_channel_ref",
        "package_artifact_digest",
    }
)
_RECEIPT_CHECKS = frozenset(LOCAL_BUILD_CHECKS + HOSTED_QUALIFICATION_CHECKS)


class StrixControlledExecutionIdentityError(ValueError):
    """The proposed v2 identity is incomplete, inconsistent, or noncanonical."""


def _refuse(label: str) -> StrixControlledExecutionIdentityError:
    return StrixControlledExecutionIdentityError(f"controlled execution {label} is invalid")


def _exact(value: Any, expected: frozenset[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != expected:
        raise _refuse(label)
    return cast(dict[str, Any], value)


def _digest(value: Any, label: str) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise _refuse(label)
    return value


def _image(value: Any, label: str) -> str:
    if type(value) is not str or len(value) > 256:
        raise _refuse(label)
    match = _IMAGE.fullmatch(value)
    if match is None:
        raise _refuse(label)
    host, separator, port = match.group("registry").partition(":")
    if ("." not in host and host != "localhost") or (
        separator and (int(port) > 65535 or int(port) in {80, 443})
    ):
        raise _refuse(label)
    return value


def _same(value: Any, expected: Any, label: str) -> None:
    if type(value) is not type(expected) or value != expected:
        raise _refuse(label)


def _pairs_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise ValueError("non-JSON constant")


def _decode(payload: bytes) -> dict[str, Any]:
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_pairs_without_duplicates,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, ValueError, TypeError, RecursionError, OverflowError):
        raise _refuse("encoding") from None
    if type(value) is not dict:
        raise _refuse("document")
    return cast(dict[str, Any], value)


def _validate(value: Any) -> dict[str, Any]:
    row = _exact(value, _FIELDS, "fields")
    _same(row["schema_version"], SCHEMA_VERSION, "schema")
    attempt_id = row["attempt_id"]
    if type(attempt_id) is not str or _ATTEMPT.fullmatch(attempt_id) is None:
        raise _refuse("attempt")

    build_row = _exact(row["startup_build_identity"], _BUILD_FIELDS, "startup build")
    if any(type(item) is not str for item in build_row.values()):
        raise _refuse("startup build")
    _same(build_row["engine"], "strix", "startup engine")
    try:
        build = StrixBuildIdentity(
            **{key: value for key, value in build_row.items() if key != "engine"}
        )
    except (TypeError, ValueError):
        raise _refuse("startup build") from None
    _same(build_row, build.to_dict(), "startup build")
    _same(row["startup_build_ref"], content_hash(build_row), "startup build ref")
    _digest(row["runtime_qualification_ref"], "runtime qualification ref")

    upstream = _image(row["upstream_oci_index_reference"], "upstream index reference")
    _same(upstream, build.image_reference, "upstream index reference")
    _same(upstream, REVIEWED_UPSTREAM_INDEX_REFERENCE, "reviewed upstream index")
    _same(row["upstream_oci_index_digest"], upstream.rsplit("@", 1)[1], "upstream index digest")
    _same(row["upstream_oci_platform"], TESTED_PLATFORM, "upstream platform")
    for name in (
        "upstream_oci_child_manifest_digest",
        "upstream_oci_config_digest",
    ):
        _digest(row[name], name)
    _same(row["upstream_oci_inventory_ref"], build.image_inventory_sha256, "upstream inventory")

    for name in ("prompt_upstream_sha256", "prompt_overlay_sha256", "prompt_patched_sha256"):
        _same(row[name], getattr(build, name), name)
    for name, expected in (
        ("startup_upstream_sha256", REVIEWED_STARTUP_SHA256),
        ("startup_overlay_sha256", STARTUP_OVERLAY_SHA256),
        ("startup_patched_sha256", PATCHED_STARTUP_SHA256),
    ):
        _same(row[name], f"sha256:{expected}", name)

    for name in (
        "private_transfer_bundle_ref",
        "private_transport_provenance_ref",
        "derived_image_contract_ref",
        "derived_image_contract_digest",
        "derived_image_decision_ref",
        "platform_child_manifest_digest",
        "image_config_digest",
        "image_relation_receipt_ref",
        "receipt_authority_ref",
        "controlled_runtime_profile_ref",
        "worker_transport_ref",
        "worker_channel_ref",
    ):
        _digest(row[name], name)
    _same(row["derived_image_contract_schema"], DERIVED_IMAGE_SCHEMA_VERSION, "derived contract")
    _same(
        row["derived_image_contract_ref"],
        row["derived_image_contract_digest"],
        "derived contract content ref",
    )
    derived = _image(row["derived_image_reference"], "derived image reference")
    _same(row["derived_image_digest"], derived.rsplit("@", 1)[1], "derived image digest")
    oci_objects = (
        row["upstream_oci_index_digest"],
        row["upstream_oci_child_manifest_digest"],
        row["upstream_oci_config_digest"],
        row["derived_image_digest"],
        row["platform_child_manifest_digest"],
        row["image_config_digest"],
    )
    if len(set(oci_objects)) != len(oci_objects):
        raise _refuse("OCI role separation")

    receipts = _exact(row["authenticated_receipts"], _RECEIPT_CHECKS, "receipt set")
    if len({_digest(ref, "receipt ref") for ref in receipts.values()}) != len(_RECEIPT_CHECKS):
        raise _refuse("receipt set")
    receipt_set = {
        "schema_version": RECEIPT_SET_SCHEMA_VERSION,
        "contract_digest": row["derived_image_contract_digest"],
        "authority_ref": row["receipt_authority_ref"],
        "receipts": receipts,
    }
    _same(row["authenticated_receipt_set_ref"], content_hash(receipt_set), "receipt set ref")

    profile_row = _exact(row["controlled_runtime_profile"], _PROFILE_FIELDS, "runtime profile")
    if any(
        type(profile_row[key]) is not int
        for key in (
            "sandbox_uid",
            "sandbox_gid",
            "exec_timeout_seconds",
            "exec_output_limit_bytes",
            "workspace_object_limit_bytes",
            "write_chunk_bytes",
        )
    ):
        raise _refuse("runtime profile")
    if any(
        type(value) is not str
        for key, value in profile_row.items()
        if key
        not in (
            "sandbox_uid",
            "sandbox_gid",
            "exec_timeout_seconds",
            "exec_output_limit_bytes",
            "workspace_object_limit_bytes",
            "write_chunk_bytes",
        )
    ):
        raise _refuse("runtime profile")
    if _PROFILE_FIELDS != frozenset(field.name for field in fields(ControlledRuntimeProfile)):
        raise _refuse("runtime profile contract")
    try:
        profile = ControlledRuntimeProfile(**profile_row)
    except (TypeError, ValueError, RuntimeError):
        raise _refuse("runtime profile") from None
    _same(row["controlled_runtime_profile_ref"], profile.profile_digest, "runtime profile ref")
    _same(profile.attempt_id, attempt_id, "profile attempt")
    _same(profile.source_revision, build.source_revision, "profile source revision")
    _same(profile.build_digest, row["startup_build_ref"], "profile build")
    _same(profile.image_reference, derived, "profile image")
    _same(profile.image_digest, row["derived_image_digest"], "profile image digest")
    # profile.manifest_digest is the controlled workspace manifest, not an OCI manifest.

    _same(row["package_artifact_digest"], build.package_sha256, "package artifact")
    return row


@dataclass(frozen=True, slots=True, repr=False)
class StrixControlledExecutionIdentityV2:
    """One canonical identity declaration; references are not authority proofs."""

    canonical_bytes: bytes

    def __post_init__(self) -> None:
        if (
            type(self.canonical_bytes) is not bytes
            or not 0 < len(self.canonical_bytes) <= MAX_IDENTITY_BYTES
        ):
            raise _refuse("bytes")
        row = _validate(_decode(self.canonical_bytes))
        if canonical_json_bytes(row) != self.canonical_bytes:
            raise _refuse("canonical encoding")

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> StrixControlledExecutionIdentityV2:
        row = _validate(value)
        try:
            return cls(canonical_json_bytes(row))
        except (TypeError, ValueError, UnicodeError, RecursionError, OverflowError):
            raise _refuse("encoding") from None

    def to_dict(self) -> dict[str, Any]:
        return _decode(self.canonical_bytes)

    @property
    def identity_digest(self) -> str:
        return "sha256:" + hashlib.sha256(self.canonical_bytes).hexdigest()

    def require_expected_digest(self, expected_ref: str) -> None:
        """Compare with a protected, independently held identity content ref."""

        _same(self.identity_digest, _digest(expected_ref, "expected identity ref"), "identity ref")

    def verify_image_contract(self, contract: StrixImageContractV2) -> None:
        """Compare the projection with reopened canonical V2 contract bytes.

        The caller must independently obtain the contract. This check neither
        authenticates its receipts nor resolves the decision or relation refs.
        """

        if type(contract) is not StrixImageContractV2:
            raise _refuse("derived contract")
        try:
            checked = StrixImageContractV2(contract.canonical_bytes)
        except StrixImageContractError:
            raise _refuse("derived contract") from None
        image_row = checked.to_dict()
        upstream = image_row["upstream_image"]
        derived = image_row["derived_image"]
        identity = self.to_dict()
        build = identity["startup_build_identity"]
        expected = {
            "derived_image_contract_schema": image_row["schema_version"],
            "derived_image_contract_ref": checked.contract_digest,
            "derived_image_contract_digest": checked.contract_digest,
            "upstream_oci_index_reference": upstream["index_reference"],
            "upstream_oci_index_digest": upstream["index"]["digest"],
            "upstream_oci_platform": image_row["platform"],
            "upstream_oci_child_manifest_digest": upstream["platform_child"]["digest"],
            "upstream_oci_config_digest": upstream["config"]["digest"],
            "upstream_oci_inventory_ref": upstream["inventory_digest"],
            "derived_image_reference": derived["index_reference"],
            "derived_image_digest": derived["index"]["digest"],
            "platform_child_manifest_digest": derived["platform_child"]["digest"],
            "image_config_digest": derived["config"]["digest"],
        }
        for name, value in expected.items():
            _same(identity[name], value, name)
        _same(build["source_revision"], image_row["source_revision"], "contract source revision")
        _same(build["source_tree_sha256"], image_row["source_tree_digest"], "contract source tree")
        for name, overlay in (
            ("prompt", image_row["prompt_overlay_receipt"]),
            ("startup", image_row["startup_overlay_receipt"]),
        ):
            for phase in ("upstream", "overlay", "patched"):
                field = f"{name}_{phase}_sha256"
                _same(identity[field], f"sha256:{overlay[f'{phase}_sha256']}", field)

    def __repr__(self) -> str:
        return f"StrixControlledExecutionIdentityV2(identity_digest={self.identity_digest!r})"


__all__ = [
    "DERIVED_IMAGE_SCHEMA_VERSION",
    "RECEIPT_SET_SCHEMA_VERSION",
    "SCHEMA_VERSION",
    "StrixControlledExecutionIdentityError",
    "StrixControlledExecutionIdentityV2",
]
