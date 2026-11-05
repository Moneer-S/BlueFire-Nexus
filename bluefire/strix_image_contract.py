"""Effect-free admission contract for a proposed, exact derived Strix image.

Parsing declarations proves no build, container, network, or hosted execution.
Receipts must be reopened by a controller registry and independently signature
verified against a reviewed authority, never an engine-supplied hash set. No
production signing authority is configured, so production admission is blocked.
Installing a trust root requires a separately reviewed controller change. Image admission
is only a necessary input to per-attempt runtime authority. It cannot clear
redistribution or assert that a production runtime has been admitted.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Sequence, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .strix_redistribution_review import (
    is_blocked_strix_redistribution_review,
    strix_redistribution_review,
)
from .util import canonical_json_bytes, content_hash, parse_iso8601_datetime

STRIX_SOURCE_REVISION = "6b7ae2ebe4d47037a927aade23265ff4e4f27e84"  # pragma: allowlist secret
TESTED_PLATFORM = "linux/amd64"
CONTROLLED_ENTRYPOINT = "/opt/bluefire/bin/strix-controlled-entrypoint"
# This is the image's fixed service-account home, independent of the build host.
_CONTAINER_HOME = "/".join(("", "home", "strix"))
LOCAL_BUILD_CHECKS = ("artifact-integrity", "offline-dependency-closure")
HOSTED_QUALIFICATION_CHECKS = (
    "native-architecture",
    "image-config-and-provenance",
    "nonroot-readonly-tmpfs-startup",
    "no-runtime-install-or-pull",
    "fixed-network-and-host-isolation",
    "capability-and-resource-enforcement",
    "workspace-and-entrypoint",
    "bounded-command-and-caido-startup",
    "cancellation-and-descendant-stop",
    "cleanup-and-residue-absence",
)
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_IMAGE = re.compile(r"[a-z0-9][a-z0-9._/:-]{0,255}@sha256:[0-9a-f]{64}")
_NETWORK_ID = re.compile(r"[0-9a-f]{64}")
_NETWORK_NAME = re.compile(r"bluefire-engine-[0-9a-f]{32}")
# Reviewed controller authority public keys only. No public registration API or
# caller-selected verification key is accepted. Empty until real qualification
# authority and protected registry custody have been reviewed and configured.
_CONTROLLER_RECEIPT_PUBLIC_KEYS: tuple[bytes, ...] = ()
_RECEIPT_SIGNATURE_DOMAIN = b"bluefire.strix-image-controller-receipt.v1\x00"


class StrixImageContractError(ValueError):
    """An image declaration or qualification receipt is incomplete or changed."""


def _exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise StrixImageContractError(f"{label} fields do not match the contract")
    return dict(value)


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise StrixImageContractError(f"{label} digest is invalid")
    return value


def _same(value: Any, expected: Any, label: str) -> None:
    # Canonical bytes distinguish bool/int, list/str, and reject NaN.
    try:
        matches = canonical_json_bytes(value) == canonical_json_bytes(expected)
    except (TypeError, ValueError, OverflowError) as exc:
        raise StrixImageContractError(f"{label} is not canonical JSON") from exc
    if not matches:
        raise StrixImageContractError(f"{label} does not match the reviewed profile")


def pinned_image_components() -> dict[str, str]:
    """Pins are requirements, not a claim that any artifact contains them."""
    return {
        "strix-agent": "1.7.0",
        "openai-agents": "0.19.0",
        "docker": "7.1.0",
        "caido": "0.56.0",
        "caido-sdk-client": "0.2.0",
    }


def proposed_image_runtime_profile(
    *, network_id: str, network_name: str, network_policy_digest: str
) -> dict[str, Any]:
    """Describe one planned profile; do not allocate or verify its network."""
    if not isinstance(network_id, str) or _NETWORK_ID.fullmatch(network_id) is None:
        raise StrixImageContractError("fixed network ID is invalid")
    if not isinstance(network_name, str) or _NETWORK_NAME.fullmatch(network_name) is None:
        raise StrixImageContractError("fixed network name is invalid")
    _digest(network_policy_digest, "network policy")
    return {
        "user": "1000:1000",
        "read_only_root": True,
        "working_directory": "/workspace",
        "entrypoint": [CONTROLLED_ENTRYPOINT],
        "command": [],
        "environment": {
            "HOME": _CONTAINER_HOME,
            "TMPDIR": "/tmp",
            "XDG_CACHE_HOME": f"{_CONTAINER_HOME}/.cache",
            "PYTHONDONTWRITEBYTECODE": "1",
        },
        "tmpfs": {
            destination: f"rw,nosuid,nodev,noexec,size={size},uid=1000,gid=1000,mode=0700"
            for destination, size in (
                (_CONTAINER_HOME, 128 * 1024**2),
                ("/run", 16 * 1024**2),
                ("/tmp", 128 * 1024**2),
                ("/workspace", 512 * 1024**2),
            )
        },
        "mounts": [],
        "volumes": [],
        "published_ports": [],
        "extra_hosts": [],
        "devices": [],
        "privileged": False,
        "cap_add": [],
        "cap_drop": ["ALL"],
        "security_options": ["no-new-privileges:true"],
        "pid_mode": "private",
        "ipc_mode": "private",
        "uts_mode": "private",
        "network": {
            "id": network_id,
            "name": network_name,
            "policy_digest": network_policy_digest,
            "internal": True,
            "attach_additional_networks": False,
        },
        "memory_bytes": 2 * 1024**3,
        "memory_swap_bytes": 2 * 1024**3,
        "nano_cpus": 2_000_000_000,
        "pids_limit": 256,
        "runtime_installs": False,
        "runtime_image_pulls": False,
        "preloaded_image_required": True,
        "restart_policy": "no",
    }


def _validate_contract(value: Any) -> dict[str, Any]:
    row = _exact(
        value,
        {
            "schema_version",
            "source_revision",
            "source_tree_digest",
            "image_reference",
            "image_digest",
            "base_image_digest",
            "dockerfile_digest",
            "dependency_lock_digest",
            "sbom_digest",
            "provenance_digest",
            "attestation_digest",
            "components",
            "platform",
            "runtime_profile",
            "redistribution_review",
        },
        "derived image",
    )
    _same(row["schema_version"], "bluefire.strix-derived-image.v1", "image schema")
    _same(row["source_revision"], STRIX_SOURCE_REVISION, "Strix source revision")
    _same(row["platform"], TESTED_PLATFORM, "tested platform")
    _same(row["components"], pinned_image_components(), "component versions")
    for name in (
        "source_tree_digest",
        "image_digest",
        "base_image_digest",
        "dockerfile_digest",
        "dependency_lock_digest",
        "sbom_digest",
        "provenance_digest",
        "attestation_digest",
    ):
        _digest(row[name], name)
    image = row["image_reference"]
    if not isinstance(image, str) or _IMAGE.fullmatch(image) is None:
        raise StrixImageContractError("derived image reference is not digest pinned")
    if image.rsplit("@", 1)[-1] != row["image_digest"]:
        raise StrixImageContractError("image reference and image digest differ")
    profile = row["runtime_profile"]
    if not isinstance(profile, Mapping):
        raise StrixImageContractError("image runtime profile is invalid")
    network = _exact(
        profile.get("network"),
        {"id", "name", "policy_digest", "internal", "attach_additional_networks"},
        "image network",
    )
    expected = proposed_image_runtime_profile(
        network_id=network["id"],
        network_name=network["name"],
        network_policy_digest=network["policy_digest"],
    )
    _same(profile, expected, "image runtime profile")
    if not is_blocked_strix_redistribution_review(row["redistribution_review"]):
        raise StrixImageContractError("image redistribution review must remain blocked")
    return row


@dataclass(frozen=True, slots=True)
class StrixImageContract:
    """Immutable canonical declaration; its existence is not qualification."""

    canonical_bytes: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.canonical_bytes, bytes) or len(self.canonical_bytes) > 65536:
            raise StrixImageContractError("derived image contract bytes are invalid")
        try:
            row = _validate_contract(json.loads(self.canonical_bytes))
            _same(
                self.canonical_bytes.decode("utf-8"),
                canonical_json_bytes(row).decode("utf-8"),
                "canonical image encoding",
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise StrixImageContractError("derived image contract is not JSON") from exc

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> StrixImageContract:
        return cls(canonical_json_bytes(_validate_contract(value)))

    def to_dict(self) -> dict[str, Any]:
        return dict(json.loads(self.canonical_bytes))

    @property
    def contract_digest(self) -> str:
        return "sha256:" + hashlib.sha256(self.canonical_bytes).hexdigest()

    @property
    def runtime_profile_digest(self) -> str:
        return cast(str, content_hash(self.to_dict()["runtime_profile"]))


@dataclass(frozen=True, slots=True)
class StrixImageQualificationReceipt:
    """One external assertion; authenticity is supplied separately at admission."""

    canonical_bytes: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.canonical_bytes, bytes) or len(self.canonical_bytes) > 8192:
            raise StrixImageContractError("image qualification receipt bytes are invalid")
        try:
            row = _exact(
                json.loads(self.canonical_bytes),
                {
                    "schema_version",
                    "stage",
                    "check",
                    "contract_digest",
                    "runtime_profile_digest",
                    "image_digest",
                    "source_revision",
                    "platform",
                    "runner_digest",
                    "verifier_digest",
                    "evidence_digest",
                    "checked_at",
                    "passed",
                },
                "image qualification receipt",
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise StrixImageContractError("image qualification receipt is not JSON") from exc
        _same(row["schema_version"], "bluefire.strix-image-qualification.v1", "receipt schema")
        _same(row["source_revision"], STRIX_SOURCE_REVISION, "receipt source revision")
        _same(row["platform"], TESTED_PLATFORM, "receipt platform")
        _same(row["passed"], True, "receipt success")
        checks: tuple[str, ...]
        if row["stage"] == "local-build":
            checks = LOCAL_BUILD_CHECKS
        elif row["stage"] == "hosted-qualification":
            checks = HOSTED_QUALIFICATION_CHECKS
        else:
            raise StrixImageContractError("image qualification stage is unsupported")
        if row["check"] not in checks:
            raise StrixImageContractError("image qualification check is unsupported for stage")
        for name in (
            "contract_digest",
            "runtime_profile_digest",
            "image_digest",
            "runner_digest",
            "verifier_digest",
            "evidence_digest",
        ):
            _digest(row[name], name)
        try:
            if not isinstance(row["checked_at"], str):
                raise ValueError("not text")
            parse_iso8601_datetime(row["checked_at"])
        except ValueError as exc:
            raise StrixImageContractError("image qualification timestamp is invalid") from exc
        if self.canonical_bytes != canonical_json_bytes(row):
            raise StrixImageContractError("image qualification encoding is not canonical")

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> StrixImageQualificationReceipt:
        try:
            return cls(canonical_json_bytes(dict(value)))
        except (TypeError, ValueError) as exc:
            raise StrixImageContractError("image qualification receipt is invalid") from exc

    def to_dict(self) -> dict[str, Any]:
        return dict(json.loads(self.canonical_bytes))

    @property
    def receipt_digest(self) -> str:
        return "sha256:" + hashlib.sha256(self.canonical_bytes).hexdigest()


@dataclass(frozen=True, slots=True)
class SignedImageQualificationReceipt:
    """Untrusted registry response; construction confers no authority."""

    canonical_receipt: bytes
    signature: bytes


def _controller_public_key(authority_key_id: str) -> bytes:
    _digest(authority_key_id, "controller image receipt authority")
    for key in _CONTROLLER_RECEIPT_PUBLIC_KEYS:
        if type(key) is bytes and len(key) == 32:
            if "sha256:" + hashlib.sha256(key).hexdigest() == authority_key_id:
                return key
    raise StrixImageContractError("controller image receipt authority is not configured")


@dataclass(frozen=True, slots=True)
class ControllerVerifiedImageReceiptRegistry:
    """Controller capability that reopens and authenticates every exact receipt.

    The opener receives only contract and receipt digests. It returns a signed
    retained receipt; its own flags, types, or digest assertions cannot attest
    qualification. Candidate-selected public keys and signer registrations are
    deliberately unsupported. The module's reviewed authority list is empty.
    """

    authority_key_id: str
    open_signed_receipt: Callable[[str, str], SignedImageQualificationReceipt]

    def __post_init__(self) -> None:
        _controller_public_key(self.authority_key_id)
        if not callable(self.open_signed_receipt):
            raise StrixImageContractError("controller image receipt opener is invalid")

    def reopen_verified(
        self, *, contract_digest: str, receipt_digest: str
    ) -> StrixImageQualificationReceipt:
        _digest(contract_digest, "registry image contract")
        _digest(receipt_digest, "registry image receipt")
        public_key = _controller_public_key(self.authority_key_id)
        try:
            signed = self.open_signed_receipt(contract_digest, receipt_digest)
        except Exception:
            raise StrixImageContractError(
                "controller image receipt could not be reopened"
            ) from None
        if (
            type(signed) is not SignedImageQualificationReceipt
            or type(signed.canonical_receipt) is not bytes
            or type(signed.signature) is not bytes
            or len(signed.signature) != 64
        ):
            raise StrixImageContractError("controller image receipt envelope is invalid")
        receipt = StrixImageQualificationReceipt(signed.canonical_receipt)
        if receipt.receipt_digest != receipt_digest:
            raise StrixImageContractError("controller image receipt was replaced")
        row = receipt.to_dict()
        _same(row["contract_digest"], contract_digest, "registry receipt contract")
        _same(row["verifier_digest"], self.authority_key_id, "registry receipt verifier")
        message = (
            _RECEIPT_SIGNATURE_DOMAIN
            + self.authority_key_id.encode("ascii")
            + b"\x00"
            + signed.canonical_receipt
        )
        try:
            Ed25519PublicKey.from_public_bytes(public_key).verify(signed.signature, message)
        except (InvalidSignature, ValueError):
            raise StrixImageContractError("controller image receipt signature is invalid") from None
        return receipt


@dataclass(frozen=True, slots=True)
class StrixImageAdmissionDecision:
    contract_digest: str
    local_build_qualified: bool
    hosted_qualification_complete: bool
    image_admitted_for_runtime: bool
    missing_checks: tuple[str, ...]
    # These cannot be promoted by build or image qualification receipts.
    redistribution_authorized: bool = False
    production_runtime_admitted: bool = False
    live_execution_proven: bool = False


def evaluate_image_admission(
    contract: StrixImageContract,
    receipts: Sequence[StrixImageQualificationReceipt],
    *,
    receipt_registry: ControllerVerifiedImageReceiptRegistry | None = None,
) -> StrixImageAdmissionDecision:
    """Evaluate a necessary image gate against controller-authenticated receipts.

    Each supplied receipt is merely a candidate reference. The controller registry
    must independently reopen its signed canonical bytes, and the reviewed
    authority signature must authenticate the exact receipt and contract. A true
    image gate grants no per-attempt launch permission. No Docker, network, build,
    clock, or live runtime operation is performed here.
    """
    if not isinstance(contract, StrixImageContract):
        raise StrixImageContractError("image contract has not been parsed")
    # Revalidate even directly constructed or externally deserialized objects.
    contract = StrixImageContract(contract.canonical_bytes)
    if (
        receipt_registry is not None
        and type(receipt_registry) is not ControllerVerifiedImageReceiptRegistry
    ):
        raise StrixImageContractError("image receipt registry is not a controller capability")
    if receipt_registry is not None:
        _controller_public_key(receipt_registry.authority_key_id)
    if not isinstance(receipts, (list, tuple)) or len(receipts) > 12:
        raise StrixImageContractError("image qualification receipt collection is invalid")
    found: set[str] = set()
    image_digest = contract.to_dict()["image_digest"]
    for receipt in receipts:
        if not isinstance(receipt, StrixImageQualificationReceipt):
            raise StrixImageContractError("image qualification receipt has not been parsed")
        receipt = StrixImageQualificationReceipt(receipt.canonical_bytes)
        if receipt_registry is None:
            raise StrixImageContractError("controller image receipt registry is unavailable")
        reopened = ControllerVerifiedImageReceiptRegistry.reopen_verified(
            receipt_registry,
            contract_digest=contract.contract_digest,
            receipt_digest=receipt.receipt_digest,
        )
        if reopened.canonical_bytes != receipt.canonical_bytes:
            raise StrixImageContractError("candidate and controller image receipts differ")
        row = receipt.to_dict()
        for name, expected in (
            ("contract_digest", contract.contract_digest),
            ("runtime_profile_digest", contract.runtime_profile_digest),
            ("image_digest", image_digest),
        ):
            _same(row[name], expected, f"receipt {name}")
        check = row["check"]
        if check in found:
            raise StrixImageContractError("duplicate image qualification check")
        found.add(check)
    local = all(check in found for check in LOCAL_BUILD_CHECKS)
    hosted = all(check in found for check in HOSTED_QUALIFICATION_CHECKS)
    return StrixImageAdmissionDecision(
        contract_digest=contract.contract_digest,
        local_build_qualified=local,
        hosted_qualification_complete=hosted,
        image_admitted_for_runtime=local and hosted,
        missing_checks=tuple(
            check
            for check in LOCAL_BUILD_CHECKS + HOSTED_QUALIFICATION_CHECKS
            if check not in found
        ),
    )


def blocked_image_redistribution_review() -> dict[str, Any]:
    """A fresh unresolved rights review, independent of qualification success."""
    return dict(strix_redistribution_review())


# V2 is deliberately separate from the historical declaration, receipt parser,
# signature domain, and admission decision above. A V1 receipt cannot qualify V2.
REVIEWED_UPSTREAM_INDEX_REFERENCE = (
    "ghcr.io/usestrix/strix-sandbox@"
    "sha256:78df914f3029464c9d00580f531ec51025c251c422ec3b09c3f19c5fa6d80c30"
)
_V2_INDEX_MEDIA_TYPES = frozenset(
    {
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
    }
)
_V2_MANIFEST_MEDIA_TYPES = frozenset(
    {
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    }
)
_V2_CONFIG_MEDIA_TYPES = frozenset(
    {
        "application/vnd.oci.image.config.v1+json",
        "application/vnd.docker.container.image.v1+json",
    }
)
_V2_REFERENCE = re.compile(
    r"(?P<registry>[a-z0-9]+(?:[.-][a-z0-9]+)*(?::[1-9][0-9]{0,4})?)/"
    r"(?P<repository>[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*)"
    r"@(?P<digest>sha256:[0-9a-f]{64})"
)
_CONTROLLER_RECEIPT_PUBLIC_KEYS_V2: tuple[bytes, ...] = ()
_RECEIPT_SIGNATURE_DOMAIN_V2 = b"bluefire.strix-image-controller-receipt.v2\x00"


def validate_v2_image_reference(value: Any, label: str = "image reference") -> str:
    """Return one canonical, fully qualified V2 digest-pinned image reference.

    The same validator is used by the V2 image contract and downstream Docker
    policy. Registry ports, tags, implicit registries, and URL forms are not
    canonical here. This is syntax validation, not image admission.
    """

    if not isinstance(value, str) or len(value) > 256:
        raise StrixImageContractError(f"{label} is not a canonical digest reference")
    match = _V2_REFERENCE.fullmatch(value)
    if match is None:
        raise StrixImageContractError(f"{label} is not a canonical digest reference")
    registry = match.group("registry")
    host, separator, _port = registry.partition(":")
    if "." not in host and host != "localhost":
        raise StrixImageContractError(f"{label} registry is not fully qualified")
    if separator:
        raise StrixImageContractError(f"{label} registry port is invalid")
    return value


def _v2_reference(value: Any, label: str) -> str:
    return validate_v2_image_reference(value, label).rsplit("@", 1)[-1]


def _v2_oci_descriptor(value: Any, *, role: str, platform: bool) -> dict[str, Any]:
    fields = {"digest", "media_type", "platform"} if platform else {"digest", "media_type"}
    row = _exact(value, fields, role)
    _digest(row["digest"], role)
    allowed_media_types = {
        "index": _V2_INDEX_MEDIA_TYPES,
        "manifest": _V2_MANIFEST_MEDIA_TYPES,
        "config": _V2_CONFIG_MEDIA_TYPES,
    }[role.rsplit(" ", 1)[-1]]
    if type(row["media_type"]) is not str or row["media_type"] not in allowed_media_types:
        raise StrixImageContractError(f"{role} media type is invalid")
    if platform:
        _same(row["platform"], TESTED_PLATFORM, f"{role} platform")
    return row


def _v2_overlay_receipts(row: Mapping[str, Any]) -> None:
    from . import strix_policy_overlay, strix_startup_overlay

    expected = (
        (
            "prompt_overlay_receipt",
            {
                "schema_version": "bluefire.strix-prompt-overlay.v1",
                "source_revision": STRIX_SOURCE_REVISION,
                "upstream_sha256": strix_policy_overlay.REVIEWED_PROMPT_SHA256,
                "overlay_sha256": strix_policy_overlay.OVERLAY_SHA256,
                "patched_sha256": strix_policy_overlay.PATCHED_PROMPT_SHA256,
            },
        ),
        (
            "startup_overlay_receipt",
            {
                "schema_version": "bluefire.strix-startup-overlay.v1",
                "source_revision": STRIX_SOURCE_REVISION,
                "upstream_sha256": strix_startup_overlay.REVIEWED_STARTUP_SHA256,
                "overlay_sha256": strix_startup_overlay.STARTUP_OVERLAY_SHA256,
                "patched_sha256": strix_startup_overlay.PATCHED_STARTUP_SHA256,
            },
        ),
    )
    for field, receipt in expected:
        _exact(row[field], set(receipt), field)
        _same(row[field], receipt, field)


def _v2_notice_review(value: Any, label: str) -> str:
    row = _exact(
        value,
        {
            "notice_report_digest",
            "notices_complete",
            "license_review_complete",
            "redistribution_rights_confirmed",
        },
        label,
    )
    notice_digest = _digest(row["notice_report_digest"], label)
    _same(
        {
            "notices_complete": row["notices_complete"],
            "license_review_complete": row["license_review_complete"],
            "redistribution_rights_confirmed": row["redistribution_rights_confirmed"],
        },
        {
            "notices_complete": False,
            "license_review_complete": False,
            "redistribution_rights_confirmed": None,
        },
        label,
    )
    return notice_digest


def _validate_contract_v2(value: Any) -> dict[str, Any]:
    row = _exact(
        value,
        {
            "schema_version",
            "source_revision",
            "source_tree_digest",
            "upstream_image",
            "dockerfile_from",
            "derived_image",
            "dockerfile_digest",
            "dependency_lock_digest",
            "sbom_digest",
            "provenance_digest",
            "attestation_digest",
            "components",
            "platform",
            "runtime_profile",
            "prompt_overlay_receipt",
            "startup_overlay_receipt",
            "upstream_notice_review",
            "derived_notice_review",
            "redistribution_review",
        },
        "derived image V2",
    )
    _same(row["schema_version"], "bluefire.strix-derived-image.v2", "image V2 schema")
    _same(row["source_revision"], STRIX_SOURCE_REVISION, "Strix source revision")
    _same(row["platform"], TESTED_PLATFORM, "tested platform")
    _same(row["components"], pinned_image_components(), "component versions")
    for name in (
        "source_tree_digest",
        "dockerfile_digest",
        "dependency_lock_digest",
        "sbom_digest",
        "provenance_digest",
        "attestation_digest",
    ):
        _digest(row[name], name)

    upstream = _exact(
        row["upstream_image"],
        {
            "index_reference",
            "index",
            "platform_child",
            "config",
            "inventory_digest",
            "qualification_receipt_digest",
        },
        "upstream image",
    )
    upstream_index = _v2_oci_descriptor(upstream["index"], role="upstream index", platform=False)
    upstream_child = _v2_oci_descriptor(
        upstream["platform_child"], role="upstream manifest", platform=True
    )
    upstream_config = _v2_oci_descriptor(upstream["config"], role="upstream config", platform=True)
    _same(
        upstream["index_reference"],
        REVIEWED_UPSTREAM_INDEX_REFERENCE,
        "reviewed upstream index reference",
    )
    _same(
        _v2_reference(upstream["index_reference"], "upstream index reference"),
        upstream_index["digest"],
        "upstream index reference digest",
    )
    _digest(upstream["inventory_digest"], "upstream inventory")
    _digest(upstream["qualification_receipt_digest"], "upstream qualification receipt")

    dockerfile_from = _exact(
        row["dockerfile_from"],
        {"reference", "platform_child_manifest_digest", "config_digest"},
        "actual Dockerfile FROM",
    )
    _same(
        _v2_reference(dockerfile_from["reference"], "Dockerfile FROM reference"),
        upstream_index["digest"],
        "Dockerfile FROM index digest",
    )
    _same(dockerfile_from["reference"], upstream["index_reference"], "Dockerfile FROM reference")
    _same(
        dockerfile_from["platform_child_manifest_digest"],
        upstream_child["digest"],
        "Dockerfile FROM child manifest",
    )
    _same(dockerfile_from["config_digest"], upstream_config["digest"], "Dockerfile FROM config")

    derived = _exact(
        row["derived_image"],
        {"index_reference", "index", "platform_child", "config"},
        "derived image",
    )
    derived_index = _v2_oci_descriptor(derived["index"], role="derived index", platform=False)
    derived_child = _v2_oci_descriptor(
        derived["platform_child"], role="derived manifest", platform=True
    )
    derived_config = _v2_oci_descriptor(derived["config"], role="derived config", platform=True)
    _same(
        _v2_reference(derived["index_reference"], "derived image reference"),
        derived_index["digest"],
        "derived image reference digest",
    )
    # The six OCI objects serve distinct roles. In particular an upstream index
    # is not an executable child, and the base cannot masquerade as the result.
    oci_digests = (
        upstream_index["digest"],
        upstream_child["digest"],
        upstream_config["digest"],
        derived_index["digest"],
        derived_child["digest"],
        derived_config["digest"],
    )
    if len(set(oci_digests)) != len(oci_digests):
        raise StrixImageContractError("OCI index, child, config, and derived roles overlap")
    if derived["index_reference"] == upstream["index_reference"]:
        raise StrixImageContractError("upstream base cannot be the derived image")
    if derived["index_reference"].split("@", 1)[0] == upstream["index_reference"].split("@", 1)[0]:
        raise StrixImageContractError("derived image must use a separate controlled repository")

    profile = row["runtime_profile"]
    if not isinstance(profile, Mapping):
        raise StrixImageContractError("image runtime profile is invalid")
    network = _exact(
        profile.get("network"),
        {"id", "name", "policy_digest", "internal", "attach_additional_networks"},
        "image network",
    )
    _same(
        profile,
        proposed_image_runtime_profile(
            network_id=network["id"],
            network_name=network["name"],
            network_policy_digest=network["policy_digest"],
        ),
        "image runtime profile",
    )
    _v2_overlay_receipts(row)
    upstream_notice = _v2_notice_review(row["upstream_notice_review"], "upstream notice review")
    derived_notice = _v2_notice_review(row["derived_notice_review"], "derived notice review")
    if (
        len({upstream_notice, derived_notice, upstream["inventory_digest"], row["sbom_digest"]})
        != 4
    ):
        raise StrixImageContractError("notice reports must have separate artifact identities")
    if not is_blocked_strix_redistribution_review(row["redistribution_review"]):
        raise StrixImageContractError("image redistribution review must remain blocked")
    return row


@dataclass(frozen=True, slots=True)
class StrixImageContractV2:
    """Canonical proposed identity, including claims about FROM and upstream proof.

    Only authenticated qualification receipts can establish that the actual
    Dockerfile, resolved registry objects, and retained upstream receipt match.
    Parsing this declaration does not inspect those external artifacts.
    """

    canonical_bytes: bytes

    def __post_init__(self) -> None:
        if type(self.canonical_bytes) is not bytes or len(self.canonical_bytes) > 65536:
            raise StrixImageContractError("derived image V2 contract bytes are invalid")
        try:
            row = _validate_contract_v2(json.loads(self.canonical_bytes))
            if self.canonical_bytes != canonical_json_bytes(row):
                raise StrixImageContractError("derived image V2 encoding is not canonical")
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise StrixImageContractError("derived image V2 contract is not JSON") from exc

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> StrixImageContractV2:
        try:
            return cls(canonical_json_bytes(_validate_contract_v2(value)))
        except (TypeError, ValueError, OverflowError) as exc:
            if isinstance(exc, StrixImageContractError):
                raise
            raise StrixImageContractError("derived image V2 contract is invalid") from exc

    def to_dict(self) -> dict[str, Any]:
        return dict(json.loads(self.canonical_bytes))

    @property
    def contract_digest(self) -> str:
        return "sha256:" + hashlib.sha256(self.canonical_bytes).hexdigest()

    @property
    def runtime_profile_digest(self) -> str:
        return cast(str, content_hash(self.to_dict()["runtime_profile"]))

    @property
    def image_identity_digest(self) -> str:
        row = self.to_dict()
        identity_fields = (
            "source_revision",
            "source_tree_digest",
            "upstream_image",
            "dockerfile_from",
            "derived_image",
            "dockerfile_digest",
            "dependency_lock_digest",
            "sbom_digest",
            "provenance_digest",
            "attestation_digest",
            "components",
            "platform",
            "runtime_profile",
            "prompt_overlay_receipt",
            "startup_overlay_receipt",
        )
        return cast(str, content_hash({name: row[name] for name in identity_fields}))


@dataclass(frozen=True, slots=True)
class StrixImageQualificationReceiptV2:
    """One V2 assertion; only the controller can authenticate retained bytes."""

    canonical_bytes: bytes

    def __post_init__(self) -> None:
        if type(self.canonical_bytes) is not bytes or len(self.canonical_bytes) > 8192:
            raise StrixImageContractError("image V2 qualification receipt bytes are invalid")
        try:
            row = _exact(
                json.loads(self.canonical_bytes),
                {
                    "schema_version",
                    "stage",
                    "check",
                    "contract_digest",
                    "image_identity_digest",
                    "runtime_profile_digest",
                    "upstream_index_digest",
                    "upstream_child_manifest_digest",
                    "upstream_config_digest",
                    "derived_index_digest",
                    "derived_child_manifest_digest",
                    "derived_config_digest",
                    "source_revision",
                    "platform",
                    "runner_digest",
                    "verifier_digest",
                    "evidence_digest",
                    "checked_at",
                    "passed",
                },
                "image V2 qualification receipt",
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise StrixImageContractError("image V2 qualification receipt is not JSON") from exc
        _same(row["schema_version"], "bluefire.strix-image-qualification.v2", "receipt V2 schema")
        _same(row["source_revision"], STRIX_SOURCE_REVISION, "receipt source revision")
        _same(row["platform"], TESTED_PLATFORM, "receipt platform")
        _same(row["passed"], True, "receipt success")
        checks: tuple[str, ...]
        if row["stage"] == "local-build":
            checks = LOCAL_BUILD_CHECKS
        elif row["stage"] == "hosted-qualification":
            checks = HOSTED_QUALIFICATION_CHECKS
        else:
            raise StrixImageContractError("image V2 qualification stage is unsupported")
        if row["check"] not in checks:
            raise StrixImageContractError("image V2 qualification check is unsupported for stage")
        for name in (
            "contract_digest",
            "image_identity_digest",
            "runtime_profile_digest",
            "upstream_index_digest",
            "upstream_child_manifest_digest",
            "upstream_config_digest",
            "derived_index_digest",
            "derived_child_manifest_digest",
            "derived_config_digest",
            "runner_digest",
            "verifier_digest",
            "evidence_digest",
        ):
            _digest(row[name], name)
        try:
            if not isinstance(row["checked_at"], str):
                raise ValueError("not text")
            parse_iso8601_datetime(row["checked_at"])
        except ValueError as exc:
            raise StrixImageContractError("image V2 qualification timestamp is invalid") from exc
        if self.canonical_bytes != canonical_json_bytes(row):
            raise StrixImageContractError("image V2 qualification encoding is not canonical")

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> StrixImageQualificationReceiptV2:
        try:
            return cls(canonical_json_bytes(dict(value)))
        except (TypeError, ValueError, OverflowError) as exc:
            if isinstance(exc, StrixImageContractError):
                raise
            raise StrixImageContractError("image V2 qualification receipt is invalid") from exc

    def to_dict(self) -> dict[str, Any]:
        return dict(json.loads(self.canonical_bytes))

    @property
    def receipt_digest(self) -> str:
        return "sha256:" + hashlib.sha256(self.canonical_bytes).hexdigest()


@dataclass(frozen=True, slots=True)
class SignedImageQualificationReceiptV2:
    """Untrusted registry response; construction confers no authority."""

    canonical_receipt: bytes
    signature: bytes


def _controller_public_key_v2(authority_key_id: str) -> bytes:
    _digest(authority_key_id, "controller V2 image receipt authority")
    for key in _CONTROLLER_RECEIPT_PUBLIC_KEYS_V2:
        if type(key) is bytes and len(key) == 32:
            if "sha256:" + hashlib.sha256(key).hexdigest() == authority_key_id:
                return key
    raise StrixImageContractError("controller V2 image receipt authority is not configured")


@dataclass(frozen=True, slots=True)
class ControllerVerifiedImageReceiptRegistryV2:
    """Reopen and verify every V2 receipt under a separately reviewed authority."""

    authority_key_id: str
    open_signed_receipt: Callable[[str, str], SignedImageQualificationReceiptV2]

    def __post_init__(self) -> None:
        _controller_public_key_v2(self.authority_key_id)
        if not callable(self.open_signed_receipt):
            raise StrixImageContractError("controller V2 image receipt opener is invalid")

    def reopen_verified(
        self, *, contract_digest: str, receipt_digest: str
    ) -> StrixImageQualificationReceiptV2:
        _digest(contract_digest, "registry V2 image contract")
        _digest(receipt_digest, "registry V2 image receipt")
        public_key = _controller_public_key_v2(self.authority_key_id)
        try:
            signed = self.open_signed_receipt(contract_digest, receipt_digest)
        except Exception:
            raise StrixImageContractError(
                "controller V2 image receipt could not be reopened"
            ) from None
        if (
            type(signed) is not SignedImageQualificationReceiptV2
            or type(signed.canonical_receipt) is not bytes
            or type(signed.signature) is not bytes
            or len(signed.signature) != 64
        ):
            raise StrixImageContractError("controller V2 image receipt envelope is invalid")
        receipt = StrixImageQualificationReceiptV2(signed.canonical_receipt)
        if receipt.receipt_digest != receipt_digest:
            raise StrixImageContractError("controller V2 image receipt was replaced")
        row = receipt.to_dict()
        _same(row["contract_digest"], contract_digest, "registry V2 receipt contract")
        _same(row["verifier_digest"], self.authority_key_id, "registry V2 receipt verifier")
        message = (
            _RECEIPT_SIGNATURE_DOMAIN_V2
            + self.authority_key_id.encode("ascii")
            + b"\x00"
            + signed.canonical_receipt
        )
        try:
            Ed25519PublicKey.from_public_bytes(public_key).verify(signed.signature, message)
        except (InvalidSignature, ValueError):
            raise StrixImageContractError(
                "controller V2 image receipt signature is invalid"
            ) from None
        return receipt


@dataclass(frozen=True, slots=True)
class StrixImageAdmissionDecisionV2:
    contract_digest: str
    local_build_qualified: bool
    hosted_qualification_complete: bool
    image_admitted_for_runtime: bool
    missing_checks: tuple[str, ...]
    # These are separate decisions. Image receipts cannot clear them.
    notices_complete: bool = False
    license_review_complete: bool = False
    redistribution_rights_confirmed: None = None
    redistribution_authorized: bool = False
    production_runtime_admitted: bool = False
    live_execution_proven: bool = False


def evaluate_image_admission_v2(
    contract: StrixImageContractV2,
    receipts: Sequence[StrixImageQualificationReceiptV2],
    *,
    receipt_registry: ControllerVerifiedImageReceiptRegistryV2 | None = None,
) -> StrixImageAdmissionDecisionV2:
    """Evaluate only the necessary V2 image gate, without effects or launch authority.

    The reviewed signer must have inspected the actual Dockerfile and upstream
    qualification evidence. This pure decision only authenticates its receipts.
    """
    if type(contract) is not StrixImageContractV2:
        raise StrixImageContractError("image V2 contract has not been parsed")
    contract = StrixImageContractV2(contract.canonical_bytes)
    if (
        receipt_registry is not None
        and type(receipt_registry) is not ControllerVerifiedImageReceiptRegistryV2
    ):
        raise StrixImageContractError("image V2 receipt registry is not a controller capability")
    if receipt_registry is not None:
        _controller_public_key_v2(receipt_registry.authority_key_id)
    if not isinstance(receipts, (list, tuple)) or len(receipts) > 12:
        raise StrixImageContractError("image V2 qualification receipt collection is invalid")
    row = contract.to_dict()
    upstream = row["upstream_image"]
    derived = row["derived_image"]
    expected = {
        "contract_digest": contract.contract_digest,
        "image_identity_digest": contract.image_identity_digest,
        "runtime_profile_digest": contract.runtime_profile_digest,
        "upstream_index_digest": upstream["index"]["digest"],
        "upstream_child_manifest_digest": upstream["platform_child"]["digest"],
        "upstream_config_digest": upstream["config"]["digest"],
        "derived_index_digest": derived["index"]["digest"],
        "derived_child_manifest_digest": derived["platform_child"]["digest"],
        "derived_config_digest": derived["config"]["digest"],
    }
    found: set[str] = set()
    for candidate in receipts:
        if type(candidate) is not StrixImageQualificationReceiptV2:
            raise StrixImageContractError("image V2 qualification receipt has not been parsed")
        receipt = StrixImageQualificationReceiptV2(candidate.canonical_bytes)
        if receipt_registry is None:
            raise StrixImageContractError("controller V2 image receipt registry is unavailable")
        reopened = ControllerVerifiedImageReceiptRegistryV2.reopen_verified(
            receipt_registry,
            contract_digest=contract.contract_digest,
            receipt_digest=receipt.receipt_digest,
        )
        if reopened.canonical_bytes != receipt.canonical_bytes:
            raise StrixImageContractError("candidate and controller V2 image receipts differ")
        receipt_row = receipt.to_dict()
        for name, value in expected.items():
            _same(receipt_row[name], value, f"V2 receipt {name}")
        check = receipt_row["check"]
        if check in found:
            raise StrixImageContractError("duplicate V2 image qualification check")
        found.add(check)
    local = all(check in found for check in LOCAL_BUILD_CHECKS)
    hosted = all(check in found for check in HOSTED_QUALIFICATION_CHECKS)
    return StrixImageAdmissionDecisionV2(
        contract_digest=contract.contract_digest,
        local_build_qualified=local,
        hosted_qualification_complete=hosted,
        image_admitted_for_runtime=local and hosted,
        missing_checks=tuple(
            check
            for check in LOCAL_BUILD_CHECKS + HOSTED_QUALIFICATION_CHECKS
            if check not in found
        ),
    )
