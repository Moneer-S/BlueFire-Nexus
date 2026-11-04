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

STRIX_SOURCE_REVISION = "6b7ae2ebe4d47037a927aade23265ff4e4f27e84"
TESTED_PLATFORM = "linux/amd64"
CONTROLLED_ENTRYPOINT = "/opt/bluefire/bin/strix-controlled-entrypoint"
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
            "HOME": "/home/strix",
            "TMPDIR": "/tmp",
            "XDG_CACHE_HOME": "/home/strix/.cache",
            "PYTHONDONTWRITEBYTECODE": "1",
        },
        "tmpfs": {
            destination: f"rw,nosuid,nodev,noexec,size={size},uid=1000,gid=1000,mode=0700"
            for destination, size in (
                ("/home/strix", 128 * 1024**2),
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
