"""Signed, bounded action-package contracts.

Action packages extend the logical catalog without loading Python modules,
native libraries, scripts, or caller-authored command lines.  Their executable
portion is a tiny declarative program that selects one reviewed runner opcode
through one reviewed adapter.  Package trust is always supplied by local
policy; no field in an envelope can make its own signing key trusted.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import unicodedata
from collections.abc import Collection, Mapping
from dataclasses import dataclass
from functools import lru_cache, total_ordering
from types import MappingProxyType
from typing import Any, TypeAlias
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .contracts import ActionDefinition, BehaviorDefinition, ContractError, ExecutionState
from .util import canonical_json_bytes


class ActionPackageError(ValueError):
    """Raised when an action package is malformed, untrusted, or incompatible."""


ACTION_PACKAGE_SCHEMA = "bluefire.action-package.v1"
ACTION_PACKAGE_PAYLOAD_SCHEMA = "bluefire.action-package-payload.v1"
ACTION_PROGRAM_SCHEMA = "bluefire.action-program.v1"
ACTION_PROGRAM_ADAPTER = "bluefire.builtin-runner-adapter.v1"
SIGNATURE_DOMAIN = b"BlueFire Nexus action-package signature v1\x00"

MAX_ENVELOPE_BYTES = 256 * 1024
MAX_JSON_DEPTH = 16
MAX_STRING_CHARS = 4096
MAX_COLLECTION_ITEMS = 128
MAX_BEHAVIORS = 64
MAX_ACTIONS = 64
MAX_PROGRAM_STEPS = 32
MAX_CONSTANTS = 32
MAX_INTEGER = (1 << 63) - 1

_PACKAGE_ID = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
_STABLE_ID = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*\.v[1-9][0-9]*$")
_NAMESPACE = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
_KEY_ID = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
_SPDX_SHAPED_ID = re.compile(
    r"^(?:[A-Za-z0-9][A-Za-z0-9.+-]{0,63}|LicenseRef-[A-Za-z0-9.-]{1,52})$"
)
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_IMMUTABLE_REVISION = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64}|sha256:[0-9a-f]{64})$")
_URN_REFERENCE = re.compile(
    r"^urn:[a-z0-9][a-z0-9-]{0,31}:[A-Za-z0-9]" r"[A-Za-z0-9._~:/@!$&'()*+,;=%-]{0,959}$"
)
_CONTENT_ADDRESSED_URN = re.compile(r":sha256:[0-9a-f]{64}$")
_CONTENT_ADDRESSED_HTTPS_PATH = re.compile(r"/sha256/[0-9a-f]{64}$")
_B64U = re.compile(r"^[A-Za-z0-9_-]+$")
_SEMVER = re.compile(
    r"^(0|[1-9][0-9]*)\."
    r"(0|[1-9][0-9]*)\."
    r"(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)
_URL_VALUE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")

_FORBIDDEN_EXECUTION_FIELDS = frozenset(
    {
        "args",
        "arguments",
        "argv",
        "binary",
        "binaries",
        "cmd",
        "command",
        "commands",
        "dll",
        "dynamic_library",
        "entry_point",
        "executable",
        "executable_path",
        "hostname",
        "interpreter",
        "library",
        "module",
        "native",
        "native_code",
        "python_entry_point",
        "script",
        "script_body",
        "shell",
        "shellcode",
        "uri",
        "uris",
        "url",
        "urls",
        "webhook",
    }
)

# These are the immutable v1 identifiers for already reviewed, compiled runner
# operations. A later product may stop activating one, but removing it from
# this v1 parser would make historical signed inventory unauditable.
ALLOWED_PROGRAM_OPCODES = frozenset(
    {
        "endpoint.discovery.processes.v1",
        "endpoint.discovery.system.v1",
        "sandbox.archive.tar.v1",
        "sandbox.cleanup.v1",
        "sandbox.collection.stage.v1",
        "sandbox.discovery.list.v1",
        "sandbox.discovery.metadata.v1",
        "sandbox.discovery.recursive.v1",
        "sandbox.export.local.v1",
        "sandbox.fixture.create.v1",
        "sandbox.fixture.transform.v1",
        "sandbox.network.loopback.v1",
        "sandbox.restricted.persistence-marker.v1",
    }
)
ALLOWED_PROGRAM_ADAPTERS: Mapping[str, frozenset[str]] = MappingProxyType(
    {ACTION_PROGRAM_ADAPTER: ALLOWED_PROGRAM_OPCODES}
)
SUPPORTED_PLATFORMS = frozenset({"linux", "macos", "windows"})

_ALLOWED_PROGRAM_CONSTANTS: Mapping[str, Mapping[str, frozenset[str] | type[int] | type[bool]]] = (
    MappingProxyType(
        {
            "endpoint.discovery.processes.v1": MappingProxyType({}),
            "endpoint.discovery.system.v1": MappingProxyType({}),
            "sandbox.archive.tar.v1": MappingProxyType({"archive_format": frozenset({"ustar"})}),
            "sandbox.cleanup.v1": MappingProxyType({}),
            "sandbox.collection.stage.v1": MappingProxyType({}),
            "sandbox.discovery.list.v1": MappingProxyType({}),
            "sandbox.discovery.metadata.v1": MappingProxyType({}),
            "sandbox.discovery.recursive.v1": MappingProxyType({}),
            "sandbox.export.local.v1": MappingProxyType({}),
            "sandbox.fixture.create.v1": MappingProxyType(
                {"content_template": frozenset({"telemetry-seed"})}
            ),
            "sandbox.fixture.transform.v1": MappingProxyType(
                {"transform": frozenset({"uppercase-ascii"})}
            ),
            "sandbox.network.loopback.v1": MappingProxyType({"method": frozenset({"POST"})}),
            "sandbox.restricted.persistence-marker.v1": MappingProxyType(
                {"marker_kind": frozenset({"detection-canary"})}
            ),
        }
    )
)

JsonScalar: TypeAlias = str | int | bool | None
PublicKeyValue: TypeAlias = bytes | Ed25519PublicKey

_ED25519_FIELD = (1 << 255) - 19
_ED25519_D = (-121665 * pow(121666, _ED25519_FIELD - 2, _ED25519_FIELD)) % _ED25519_FIELD
_ED25519_SQRT_M1 = pow(2, (_ED25519_FIELD - 1) // 4, _ED25519_FIELD)
_ED25519_SUBGROUP_ORDER = (1 << 252) + 27742317777372353535851937790883648493
_ED25519_IDENTITY = (0, 1, 1, 0)


def _ed25519_extended_add(
    left: tuple[int, int, int, int],
    right: tuple[int, int, int, int],
) -> tuple[int, int, int, int]:
    """Add two extended Edwards points without data-dependent field inversion."""

    x1, y1, z1, t1 = left
    x2, y2, z2, t2 = right
    field = _ED25519_FIELD
    a = ((y1 - x1) * (y2 - x2)) % field
    b = ((y1 + x1) * (y2 + x2)) % field
    c = (2 * _ED25519_D * t1 * t2) % field
    d = (2 * z1 * z2) % field
    e = (b - a) % field
    f = (d - c) % field
    g = (d + c) % field
    h = (b + a) % field
    return (e * f % field, g * h % field, f * g % field, e * h % field)


def _ed25519_scalar_multiply(
    point: tuple[int, int, int, int], scalar: int
) -> tuple[int, int, int, int]:
    result = _ED25519_IDENTITY
    addend = point
    value = scalar
    while value:
        if value & 1:
            result = _ed25519_extended_add(result, addend)
        addend = _ed25519_extended_add(addend, addend)
        value >>= 1
    return result


def _validate_prime_order_ed25519_public_key(raw: bytes) -> None:
    """Reject non-canonical, low-order, and mixed-order Ed25519 encodings."""

    encoded = int.from_bytes(raw, "little")
    sign = encoded >> 255
    y = encoded & ((1 << 255) - 1)
    field = _ED25519_FIELD
    if y >= field:
        raise ActionPackageError("trusted signer key uses a non-canonical Ed25519 encoding")
    y_squared = y * y % field
    numerator = (y_squared - 1) % field
    denominator = (_ED25519_D * y_squared + 1) % field
    if denominator == 0:
        raise ActionPackageError("trusted signer key is not an Ed25519 curve point")
    x_squared = numerator * pow(denominator, field - 2, field) % field
    x = pow(x_squared, (field + 3) // 8, field)
    if x * x % field != x_squared:
        x = x * _ED25519_SQRT_M1 % field
    if x * x % field != x_squared or (x == 0 and sign == 1):
        raise ActionPackageError("trusted signer key is not an Ed25519 curve point")
    if x & 1 != sign:
        x = field - x
    point = (x, y, 1, x * y % field)
    subgroup_check = _ed25519_scalar_multiply(point, _ED25519_SUBGROUP_ORDER)
    if (
        point == _ED25519_IDENTITY
        or subgroup_check[0] != 0
        or subgroup_check[1] != subgroup_check[2]
    ):
        raise ActionPackageError(
            "trusted signer key must be a non-identity prime-order Ed25519 point"
        )


def _digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _canonical_b64u(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def normalize_ed25519_public_key(value: PublicKeyValue) -> bytes:
    """Return the canonical raw 32-byte encoding of an Ed25519 public key."""

    if isinstance(value, Ed25519PublicKey):
        raw = value.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    elif isinstance(value, bytes):
        raw = value
    else:
        raise ActionPackageError("trusted signer key must be an Ed25519 public key")
    if len(raw) != 32:
        raise ActionPackageError("trusted signer key must contain exactly 32 raw bytes")
    _validate_prime_order_ed25519_public_key(raw)
    try:
        Ed25519PublicKey.from_public_bytes(raw)
    except ValueError as exc:
        raise ActionPackageError("trusted signer key is not a valid Ed25519 public key") from exc
    return raw


def canonical_public_key_b64u(value: PublicKeyValue) -> str:
    """Return the canonical unpadded base64url public-key encoding."""

    return _canonical_b64u(normalize_ed25519_public_key(value))


def ed25519_public_key_fingerprint(value: PublicKeyValue) -> str:
    """Return the stable SHA-256 fingerprint of a raw Ed25519 public key."""

    return _digest(normalize_ed25519_public_key(value))


def _bounded_string(value: Any, context: str, *, maximum: int = MAX_STRING_CHARS) -> str:
    if not isinstance(value, str) or not value:
        raise ActionPackageError(f"{context} must be a non-empty string")
    if len(value) > maximum:
        raise ActionPackageError(f"{context} exceeds {maximum} characters")
    if unicodedata.normalize("NFC", value) != value:
        raise ActionPackageError(f"{context} must use NFC-normalized Unicode")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ActionPackageError(f"{context} contains control characters")
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise ActionPackageError(f"{context} contains an invalid Unicode scalar value")
    return value


def _immutable_source_reference(value: Any, context: str) -> str:
    reference = _bounded_string(value, context, maximum=1024)
    if _URN_REFERENCE.fullmatch(reference) is not None:
        return reference
    try:
        parsed = urlsplit(reference)
        port = parsed.port
    except ValueError as exc:
        raise ActionPackageError(f"{context} must be a canonical HTTPS URL or bounded URN") from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or not parsed.netloc.isascii()
        or parsed.netloc != parsed.netloc.casefold()
        or "\\" in reference
        or (port == 443)
    ):
        raise ActionPackageError(
            f"{context} must be a canonical credential-free HTTPS URL without query or fragment, "
            "or a bounded URN"
        )
    return reference


def _content_addressed_source_reference(value: Any, context: str) -> str:
    """Require an embedded definition source to carry its own content identity."""

    reference = _immutable_source_reference(value, context)
    if reference.startswith("urn:"):
        content_addressed = _CONTENT_ADDRESSED_URN.search(reference) is not None
    else:
        content_addressed = (
            _CONTENT_ADDRESSED_HTTPS_PATH.search(urlsplit(reference).path) is not None
        )
    if not content_addressed:
        raise ActionPackageError(
            f"{context} must end in :sha256:<64 lowercase hex> for a URN or "
            "/sha256/<64 lowercase hex> for an HTTPS URL"
        )
    return reference


def _immutable_revision(value: Any, context: str) -> str:
    revision = _bounded_string(value, context, maximum=71)
    if _IMMUTABLE_REVISION.fullmatch(revision) is None:
        raise ActionPackageError(f"{context} must be a full lowercase VCS commit or sha256 digest")
    return revision


def _identifier(value: Any, context: str, pattern: re.Pattern[str], maximum: int = 128) -> str:
    result = _bounded_string(value, context, maximum=maximum)
    if pattern.fullmatch(result) is None:
        raise ActionPackageError(f"{context} has an invalid identifier")
    return result


def _strict_mapping(
    value: Any,
    *,
    context: str,
    required: Collection[str],
    allowed: Collection[str] | None = None,
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ActionPackageError(f"{context} must be an object")
    expected = set(required)
    permitted = expected if allowed is None else set(allowed)
    missing = expected - set(value)
    unknown = set(value) - permitted
    if missing:
        raise ActionPackageError(f"{context} is missing fields: {', '.join(sorted(missing))}")
    if unknown:
        raise ActionPackageError(f"{context} has unknown fields: {', '.join(sorted(unknown))}")
    return value


def _strict_sorted_strings(
    value: Any,
    context: str,
    *,
    pattern: re.Pattern[str],
    maximum_items: int = MAX_COLLECTION_ITEMS,
) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ActionPackageError(f"{context} must be an array")
    if not 1 <= len(value) <= maximum_items:
        raise ActionPackageError(f"{context} must contain 1..={maximum_items} items")
    result = tuple(
        _identifier(item, f"{context}[{index}]", pattern) for index, item in enumerate(value)
    )
    if tuple(sorted(result)) != result:
        raise ActionPackageError(f"{context} must be sorted and contain no duplicates")
    if len(result) != len(set(result)):
        raise ActionPackageError(f"{context} must be sorted and contain no duplicates")
    return result


@total_ordering
@dataclass(frozen=True, slots=True)
class SemVer:
    """Strict SemVer 2.0 value with precedence comparison."""

    text: str
    major: int
    minor: int
    patch: int
    prerelease: tuple[str, ...] = ()
    build: tuple[str, ...] = ()

    @classmethod
    def parse(cls, value: Any, context: str = "version") -> SemVer:
        text = _bounded_string(value, context, maximum=128)
        match = _SEMVER.fullmatch(text)
        if match is None:
            raise ActionPackageError(f"{context} must be strict semantic versioning")
        prerelease = tuple(match.group(4).split(".")) if match.group(4) else ()
        build = tuple(match.group(5).split(".")) if match.group(5) else ()
        if any(part.isdigit() and len(part) > 1 and part.startswith("0") for part in prerelease):
            raise ActionPackageError(
                f"{context} numeric prerelease identifiers cannot contain leading zeroes"
            )
        return cls(
            text=text,
            major=int(match.group(1)),
            minor=int(match.group(2)),
            patch=int(match.group(3)),
            prerelease=prerelease,
            build=build,
        )

    def _compare(self, other: SemVer) -> int:
        left_core = (self.major, self.minor, self.patch)
        right_core = (other.major, other.minor, other.patch)
        if left_core != right_core:
            return -1 if left_core < right_core else 1
        if self.prerelease == other.prerelease:
            return 0
        if not self.prerelease:
            return 1
        if not other.prerelease:
            return -1
        for left, right in zip(self.prerelease, other.prerelease, strict=False):
            if left == right:
                continue
            left_numeric = left.isdigit()
            right_numeric = right.isdigit()
            if left_numeric and right_numeric:
                return -1 if int(left) < int(right) else 1
            if left_numeric != right_numeric:
                return -1 if left_numeric else 1
            return -1 if left < right else 1
        return -1 if len(self.prerelease) < len(other.prerelease) else 1

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, SemVer):
            return NotImplemented
        return self._compare(other) < 0

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SemVer):
            return False
        return self._compare(other) == 0

    def __hash__(self) -> int:
        # Build metadata is intentionally absent because SemVer precedence
        # ignores it and ``__eq__`` follows precedence for range checks.
        return hash((self.major, self.minor, self.patch, self.prerelease))


@dataclass(frozen=True, slots=True)
class PackageCompatibility:
    minimum_bluefire_version: str
    maximum_bluefire_version_exclusive: str

    @classmethod
    def from_mapping(
        cls, value: Any, context: str = "manifest.compatibility"
    ) -> PackageCompatibility:
        data = _strict_mapping(
            value,
            context=context,
            required={"minimum_bluefire_version", "maximum_bluefire_version_exclusive"},
        )
        minimum = SemVer.parse(
            data["minimum_bluefire_version"], f"{context}.minimum_bluefire_version"
        )
        maximum = SemVer.parse(
            data["maximum_bluefire_version_exclusive"],
            f"{context}.maximum_bluefire_version_exclusive",
        )
        if minimum >= maximum:
            raise ActionPackageError(f"{context} minimum must precede its exclusive maximum")
        return cls(minimum.text, maximum.text)

    def supports(self, version: SemVer) -> bool:
        return (
            SemVer.parse(self.minimum_bluefire_version)
            <= version
            < SemVer.parse(self.maximum_bluefire_version_exclusive)
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "minimum_bluefire_version": self.minimum_bluefire_version,
            "maximum_bluefire_version_exclusive": self.maximum_bluefire_version_exclusive,
        }


@dataclass(frozen=True, slots=True)
class PackageLicense:
    spdx_id: str
    notice: str

    @classmethod
    def from_mapping(cls, value: Any, context: str = "manifest.license") -> PackageLicense:
        data = _strict_mapping(value, context=context, required={"spdx_id", "notice"})
        spdx_id = _bounded_string(data["spdx_id"], f"{context}.spdx_id", maximum=64)
        if _SPDX_SHAPED_ID.fullmatch(spdx_id) is None:
            raise ActionPackageError(
                f"{context}.spdx_id must use SPDX-shaped identifier or LicenseRef syntax"
            )
        return cls(
            spdx_id=spdx_id,
            notice=_bounded_string(data["notice"], f"{context}.notice", maximum=1024),
        )

    def to_dict(self) -> dict[str, str]:
        return {"spdx_id": self.spdx_id, "notice": self.notice}


@dataclass(frozen=True, slots=True)
class PackageProvenance:
    publisher_id: str
    source: str
    reference: str
    revision: str

    @classmethod
    def from_mapping(cls, value: Any, context: str = "manifest.provenance") -> PackageProvenance:
        data = _strict_mapping(
            value,
            context=context,
            required={"publisher_id", "source", "reference", "revision"},
        )
        return cls(
            publisher_id=_identifier(data["publisher_id"], f"{context}.publisher_id", _PACKAGE_ID),
            source=_bounded_string(data["source"], f"{context}.source", maximum=512),
            reference=_immutable_source_reference(data["reference"], f"{context}.reference"),
            revision=_immutable_revision(data["revision"], f"{context}.revision"),
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "publisher_id": self.publisher_id,
            "source": self.source,
            "reference": self.reference,
            "revision": self.revision,
        }


@dataclass(frozen=True, slots=True)
class ActionPackageManifest:
    package_id: str
    version: str
    compatibility: PackageCompatibility
    license: PackageLicense
    provenance: PackageProvenance
    platforms: tuple[str, ...]
    capabilities: tuple[str, ...]
    safety_tiers: tuple[str, ...]
    behavior_ids: tuple[str, ...]
    action_ids: tuple[str, ...]

    @classmethod
    def from_mapping(cls, value: Any, context: str = "manifest") -> ActionPackageManifest:
        data = _strict_mapping(
            value,
            context=context,
            required={
                "package_id",
                "version",
                "compatibility",
                "license",
                "provenance",
                "platforms",
                "capabilities",
                "safety_tiers",
                "behavior_ids",
                "action_ids",
            },
        )
        tiers = _strict_sorted_strings(
            data["safety_tiers"], f"{context}.safety_tiers", pattern=_NAMESPACE, maximum_items=3
        )
        if not set(tiers).issubset({"safe", "controlled", "restricted"}):
            raise ActionPackageError(
                f"{context}.safety_tiers may contain only safe, controlled, and restricted"
            )
        platforms = _strict_sorted_strings(
            data["platforms"], f"{context}.platforms", pattern=_NAMESPACE
        )
        if not set(platforms).issubset(SUPPORTED_PLATFORMS):
            raise ActionPackageError(f"{context}.platforms contains an unsupported runner platform")
        return cls(
            package_id=_identifier(data["package_id"], f"{context}.package_id", _PACKAGE_ID),
            version=SemVer.parse(data["version"], f"{context}.version").text,
            compatibility=PackageCompatibility.from_mapping(data["compatibility"]),
            license=PackageLicense.from_mapping(data["license"]),
            provenance=PackageProvenance.from_mapping(data["provenance"]),
            platforms=platforms,
            capabilities=_strict_sorted_strings(
                data["capabilities"], f"{context}.capabilities", pattern=_NAMESPACE
            ),
            safety_tiers=tiers,
            behavior_ids=_strict_sorted_strings(
                data["behavior_ids"],
                f"{context}.behavior_ids",
                pattern=_STABLE_ID,
                maximum_items=MAX_BEHAVIORS,
            ),
            action_ids=_strict_sorted_strings(
                data["action_ids"],
                f"{context}.action_ids",
                pattern=_STABLE_ID,
                maximum_items=MAX_ACTIONS,
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "package_id": self.package_id,
            "version": self.version,
            "compatibility": self.compatibility.to_dict(),
            "license": self.license.to_dict(),
            "provenance": self.provenance.to_dict(),
            "platforms": list(self.platforms),
            "capabilities": list(self.capabilities),
            "safety_tiers": list(self.safety_tiers),
            "behavior_ids": list(self.behavior_ids),
            "action_ids": list(self.action_ids),
        }


@dataclass(frozen=True, slots=True)
class ActionProgramStep:
    opcode: str
    adapter: str
    constants: tuple[tuple[str, JsonScalar], ...]

    @classmethod
    def from_mapping(cls, value: Any, context: str) -> ActionProgramStep:
        data = _strict_mapping(value, context=context, required={"opcode", "adapter", "constants"})
        opcode = _identifier(data["opcode"], f"{context}.opcode", _STABLE_ID)
        adapter = _identifier(data["adapter"], f"{context}.adapter", _STABLE_ID)
        allowed_opcodes = ALLOWED_PROGRAM_ADAPTERS.get(adapter)
        if allowed_opcodes is None:
            raise ActionPackageError(f"{context}.adapter is not allowlisted")
        if opcode not in allowed_opcodes:
            raise ActionPackageError(f"{context}.opcode is not allowlisted for its adapter")
        constants_data = data["constants"]
        if not isinstance(constants_data, Mapping):
            raise ActionPackageError(f"{context}.constants must be an object")
        if len(constants_data) > MAX_CONSTANTS:
            raise ActionPackageError(f"{context}.constants exceeds {MAX_CONSTANTS} fields")
        allowed_constants = _ALLOWED_PROGRAM_CONSTANTS[opcode]
        unknown = set(constants_data) - set(allowed_constants)
        if unknown:
            raise ActionPackageError(
                f"{context}.constants has unreviewed fields: {', '.join(sorted(unknown))}"
            )
        missing = set(allowed_constants) - set(constants_data)
        if missing:
            raise ActionPackageError(
                f"{context}.constants must explicitly bind reviewed fields: "
                f"{', '.join(sorted(missing))}"
            )
        constants: list[tuple[str, JsonScalar]] = []
        for name, raw in constants_data.items():
            _reject_forbidden_field_name(name, f"{context}.constants.{name}")
            spec = allowed_constants[name]
            if isinstance(spec, frozenset):
                if not isinstance(raw, str) or raw not in spec:
                    raise ActionPackageError(
                        f"{context}.constants.{name} is not a reviewed constant"
                    )
                if _URL_VALUE.match(raw):
                    raise ActionPackageError(f"{context}.constants.{name} cannot contain a URL")
                parsed: JsonScalar = raw
            elif spec is int:
                if isinstance(raw, bool) or not isinstance(raw, int):
                    raise ActionPackageError(f"{context}.constants.{name} must be an integer")
                parsed = raw
            elif spec is bool:
                if not isinstance(raw, bool):
                    raise ActionPackageError(f"{context}.constants.{name} must be a boolean")
                parsed = raw
            else:  # pragma: no cover - immutable module-owned table
                raise AssertionError("unsupported action-program constant specification")
            constants.append((name, parsed))
        return cls(opcode=opcode, adapter=adapter, constants=tuple(constants))

    def to_dict(self) -> dict[str, Any]:
        return {
            "opcode": self.opcode,
            "adapter": self.adapter,
            "constants": dict(self.constants),
        }


@dataclass(frozen=True, slots=True)
class ActionProgram:
    schema_version: str
    steps: tuple[ActionProgramStep, ...]

    @classmethod
    def from_mapping(cls, value: Any, context: str) -> ActionProgram:
        data = _strict_mapping(value, context=context, required={"schema_version", "steps"})
        if data["schema_version"] != ACTION_PROGRAM_SCHEMA:
            raise ActionPackageError(f"{context}.schema_version must be {ACTION_PROGRAM_SCHEMA}")
        raw_steps = data["steps"]
        if not isinstance(raw_steps, list):
            raise ActionPackageError(f"{context}.steps must be an array")
        if not 1 <= len(raw_steps) <= MAX_PROGRAM_STEPS:
            raise ActionPackageError(f"{context}.steps must contain 1..={MAX_PROGRAM_STEPS} items")
        # A package action is one reviewed operation.  Multi-step orchestration
        # belongs in scenario graphs where every edge and artifact is explicit.
        if len(raw_steps) != 1:
            raise ActionPackageError(f"{context}.steps must select exactly one reviewed operation")
        return cls(
            schema_version=ACTION_PROGRAM_SCHEMA,
            steps=tuple(
                ActionProgramStep.from_mapping(item, f"{context}.steps[{index}]")
                for index, item in enumerate(raw_steps)
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "steps": [step.to_dict() for step in self.steps],
        }


@dataclass(frozen=True, slots=True)
class PackagedAction:
    definition: ActionDefinition
    program: ActionProgram


@dataclass(frozen=True, slots=True)
class VerifiedActionPackage:
    """An immutable verification result safe to hand to persistent stores."""

    canonical_envelope_bytes: bytes
    canonical_content_bytes: bytes
    content_digest: str
    package_digest: str
    publisher_id: str
    key_id: str
    public_key_fingerprint: str
    signature_b64u: str
    manifest: ActionPackageManifest
    behaviors: tuple[BehaviorDefinition, ...]
    actions: tuple[PackagedAction, ...]

    @property
    def manifest_bytes(self) -> bytes:
        return canonical_json_bytes(self.manifest.to_dict())


def _reject_forbidden_field_name(value: Any, context: str) -> None:
    if not isinstance(value, str):
        raise ActionPackageError(f"{context} field name must be a string")
    normalized = value.strip().casefold().replace("-", "_")
    if normalized in _FORBIDDEN_EXECUTION_FIELDS:
        raise ActionPackageError(f"forbidden executable field at {context}")


def _reject_forbidden_fields(value: Any, *, path: str = "$") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            # The envelope's required payload member is data, not an execution
            # field.  A nested field with that name remains prohibited.
            if not (path == "$" and key == "payload"):
                _reject_forbidden_field_name(key, f"{path}.{key}")
            _reject_forbidden_fields(child, path=f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_forbidden_fields(child, path=f"{path}[{index}]")


def _parse_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        # CPython applies a configurable digit limit before constructing a
        # giant integer. Keep that implementation detail behind our contract.
        raise ActionPackageError("JSON integers must fit in signed 64-bit range") from exc
    if not -MAX_INTEGER <= parsed <= MAX_INTEGER:
        raise ActionPackageError("JSON integers must fit in signed 64-bit range")
    return parsed


def _reject_float(value: str) -> Any:
    raise ActionPackageError(f"floating-point JSON numbers are prohibited: {value}")


def _reject_constant(value: str) -> Any:
    raise ActionPackageError(f"non-finite JSON numbers are prohibited: {value}")


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ActionPackageError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _validate_json_tree(value: Any, *, context: str = "$", depth: int = 1) -> None:
    if depth > MAX_JSON_DEPTH:
        raise ActionPackageError(f"{context} exceeds maximum JSON depth {MAX_JSON_DEPTH}")
    if isinstance(value, Mapping):
        if len(value) > MAX_COLLECTION_ITEMS:
            raise ActionPackageError(f"{context} object exceeds {MAX_COLLECTION_ITEMS} fields")
        for key, child in value.items():
            _bounded_string(key, f"{context} key", maximum=128)
            _validate_json_tree(child, context=f"{context}.{key}", depth=depth + 1)
        return
    if isinstance(value, list):
        if len(value) > MAX_COLLECTION_ITEMS:
            raise ActionPackageError(f"{context} array exceeds {MAX_COLLECTION_ITEMS} items")
        for index, child in enumerate(value):
            _validate_json_tree(child, context=f"{context}[{index}]", depth=depth + 1)
        return
    if isinstance(value, str):
        if len(value) > MAX_STRING_CHARS:
            raise ActionPackageError(f"{context} exceeds {MAX_STRING_CHARS} characters")
        if value != value.strip():
            raise ActionPackageError(f"{context} contains surrounding whitespace")
        if unicodedata.normalize("NFC", value) != value:
            raise ActionPackageError(f"{context} must use NFC-normalized Unicode")
        if any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise ActionPackageError(f"{context} contains control characters")
        if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
            raise ActionPackageError(f"{context} contains an invalid Unicode scalar value")
        return
    if isinstance(value, bool) or value is None:
        return
    if isinstance(value, int):
        if not -MAX_INTEGER <= value <= MAX_INTEGER:
            raise ActionPackageError(f"{context} integer must fit in signed 64-bit range")
        return
    if isinstance(value, float):
        raise ActionPackageError(f"{context} floating-point values are prohibited")
    raise ActionPackageError(f"{context} contains a non-JSON value")


def parse_canonical_action_package(envelope_bytes: bytes) -> Mapping[str, Any]:
    """Parse one canonical JSON envelope with duplicate and resource limits."""

    if not isinstance(envelope_bytes, bytes):
        raise ActionPackageError("action package envelope must be bytes")
    if not envelope_bytes:
        raise ActionPackageError("action package envelope cannot be empty")
    if len(envelope_bytes) > MAX_ENVELOPE_BYTES:
        raise ActionPackageError(f"action package envelope exceeds {MAX_ENVELOPE_BYTES} bytes")
    try:
        text = envelope_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ActionPackageError("action package envelope must be valid UTF-8") from exc
    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_int=_parse_int,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except ActionPackageError:
        raise
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ActionPackageError(
            "action package envelope must contain exactly one JSON value"
        ) from exc
    if not isinstance(parsed, Mapping):
        raise ActionPackageError("action package envelope must be a JSON object")
    _validate_json_tree(parsed)
    try:
        canonical_bytes = canonical_json_bytes(parsed)
    except UnicodeEncodeError as exc:  # defensive if validation ever changes
        raise ActionPackageError(
            "action package envelope contains an invalid Unicode scalar value"
        ) from exc
    if canonical_bytes != envelope_bytes:
        raise ActionPackageError("action package envelope is not canonical JSON")
    _reject_forbidden_fields(parsed)
    return parsed


def _definition_parameter_names(definition: ActionDefinition, context: str) -> None:
    for parameter in definition.parameters:
        normalized = parameter.name.casefold().replace("-", "_")
        if normalized in _FORBIDDEN_EXECUTION_FIELDS:
            raise ActionPackageError(
                f"{context} exposes forbidden executable parameter {parameter.name}"
            )


def _parse_payload(
    value: Any,
) -> tuple[tuple[BehaviorDefinition, ...], tuple[PackagedAction, ...]]:
    data = _strict_mapping(
        value,
        context="payload",
        required={"schema_version", "behaviors", "actions"},
    )
    if data["schema_version"] != ACTION_PACKAGE_PAYLOAD_SCHEMA:
        raise ActionPackageError(f"payload.schema_version must be {ACTION_PACKAGE_PAYLOAD_SCHEMA}")
    raw_behaviors = data["behaviors"]
    raw_actions = data["actions"]
    if not isinstance(raw_behaviors, list) or not 1 <= len(raw_behaviors) <= MAX_BEHAVIORS:
        raise ActionPackageError(f"payload.behaviors must contain 1..={MAX_BEHAVIORS} items")
    if not isinstance(raw_actions, list) or not 1 <= len(raw_actions) <= MAX_ACTIONS:
        raise ActionPackageError(f"payload.actions must contain 1..={MAX_ACTIONS} items")
    behaviors: list[BehaviorDefinition] = []
    for index, raw in enumerate(raw_behaviors):
        try:
            behavior_definition = BehaviorDefinition.from_mapping(
                raw, f"payload.behaviors[{index}]"
            )
        except ContractError as exc:
            raise ActionPackageError(str(exc)) from exc
        behaviors.append(behavior_definition)
    actions: list[PackagedAction] = []
    for index, raw in enumerate(raw_actions):
        item = _strict_mapping(
            raw,
            context=f"payload.actions[{index}]",
            required={"definition", "program"},
        )
        try:
            action_definition = ActionDefinition.from_mapping(
                item["definition"], f"payload.actions[{index}].definition"
            )
        except ContractError as exc:
            raise ActionPackageError(str(exc)) from exc
        _definition_parameter_names(action_definition, f"payload.actions[{index}].definition")
        actions.append(
            PackagedAction(
                definition=action_definition,
                program=ActionProgram.from_mapping(
                    item["program"], f"payload.actions[{index}].program"
                ),
            )
        )
    return tuple(behaviors), tuple(actions)


def _validate_id_closure(
    manifest: ActionPackageManifest,
    behaviors: tuple[BehaviorDefinition, ...],
    actions: tuple[PackagedAction, ...],
    *,
    occupied_behavior_ids: Collection[str],
    occupied_action_ids: Collection[str],
) -> None:
    behavior_ids = tuple(item.id for item in behaviors)
    action_ids = tuple(item.definition.id for item in actions)
    if len(behavior_ids) != len(set(behavior_ids)):
        raise ActionPackageError("payload contains duplicate behavior IDs")
    if len(action_ids) != len(set(action_ids)):
        raise ActionPackageError("payload contains duplicate action IDs")
    if tuple(sorted(behavior_ids)) != manifest.behavior_ids:
        raise ActionPackageError("manifest behavior IDs do not exactly match the payload")
    if tuple(sorted(action_ids)) != manifest.action_ids:
        raise ActionPackageError("manifest action IDs do not exactly match the payload")
    behavior_collisions = set(behavior_ids).intersection(occupied_behavior_ids)
    if behavior_collisions:
        raise ActionPackageError(
            "package behavior IDs collide with the active catalog: "
            + ", ".join(sorted(behavior_collisions))
        )
    action_collisions = set(action_ids).intersection(occupied_action_ids)
    if action_collisions:
        raise ActionPackageError(
            "package action IDs collide with the active catalog: "
            + ", ".join(sorted(action_collisions))
        )
    action_index = {item.definition.id: item.definition for item in actions}
    for action in action_index.values():
        if action.cleanup_action_id is not None and action.cleanup_action_id not in action_index:
            raise ActionPackageError(
                f"action {action.id} has a cleanup reference outside the package"
            )
        if action.cleanup_action_id == action.id:
            raise ActionPackageError(f"action {action.id} cannot clean itself up")
    referenced_ids: set[str] = set()
    for behavior in behaviors:
        if behavior.execution_state is not ExecutionState.ACTION:
            raise ActionPackageError(
                f"behavior {behavior.id} must be action-backed in an action package"
            )
        if behavior.simulation_id is not None:
            raise ActionPackageError(
                f"behavior {behavior.id} cannot reference simulation code outside the package"
            )
        behavior_actions: list[ActionDefinition] = []
        for action_id in behavior.action_ids:
            referenced_action = action_index.get(action_id)
            if referenced_action is None:
                raise ActionPackageError(
                    f"behavior {behavior.id} references action {action_id} outside the package"
                )
            referenced_ids.add(action_id)
            behavior_actions.append(referenced_action)
            missing_capabilities = set(referenced_action.capabilities) - set(behavior.capabilities)
            if missing_capabilities:
                raise ActionPackageError(
                    f"behavior {behavior.id} omits action capabilities: "
                    + ", ".join(sorted(missing_capabilities))
                )
            if referenced_action.safety_tier is not behavior.safety_tier:
                raise ActionPackageError(
                    f"behavior {behavior.id} and action {referenced_action.id} "
                    "have different safety tiers"
                )
            if not set(referenced_action.platforms).issubset(behavior.platforms):
                raise ActionPackageError(
                    f"behavior {behavior.id} does not cover action "
                    f"{referenced_action.id} platforms"
                )
            if tuple(spec.signature() for spec in referenced_action.inputs) != tuple(
                spec.signature() for spec in behavior.inputs
            ):
                raise ActionPackageError(
                    f"behavior {behavior.id} and action {referenced_action.id} "
                    "input schemas differ"
                )
            if tuple(spec.signature() for spec in referenced_action.outputs) != tuple(
                spec.signature() for spec in behavior.outputs
            ):
                raise ActionPackageError(
                    f"behavior {behavior.id} and action {referenced_action.id} "
                    "output schemas differ"
                )
            if tuple(spec.signature() for spec in referenced_action.parameters) != tuple(
                spec.signature() for spec in behavior.parameters
            ):
                raise ActionPackageError(
                    f"behavior {behavior.id} and action {referenced_action.id} "
                    "parameter schemas differ"
                )
        exact_capabilities = {
            capability for item in behavior_actions for capability in item.capabilities
        }
        if set(behavior.capabilities) != exact_capabilities:
            raise ActionPackageError(
                f"behavior {behavior.id} capabilities do not exactly match its actions"
            )
        exact_platforms = {platform for item in behavior_actions for platform in item.platforms}
        if set(behavior.platforms) != exact_platforms:
            raise ActionPackageError(
                f"behavior {behavior.id} platforms do not exactly match its actions"
            )
    orphaned_actions = set(action_index) - referenced_ids
    if orphaned_actions:
        raise ActionPackageError(
            "payload contains actions unreachable from every behavior: "
            + ", ".join(sorted(orphaned_actions))
        )


def _validate_manifest_claims(
    manifest: ActionPackageManifest,
    behaviors: tuple[BehaviorDefinition, ...],
    actions: tuple[PackagedAction, ...],
) -> None:
    definitions: tuple[BehaviorDefinition | ActionDefinition, ...] = behaviors + tuple(
        item.definition for item in actions
    )
    capabilities = tuple(sorted({value for item in definitions for value in item.capabilities}))
    platforms = tuple(sorted({value for item in definitions for value in item.platforms}))
    tiers = tuple(sorted({item.safety_tier.value for item in definitions}))
    if manifest.capabilities != capabilities:
        raise ActionPackageError("manifest capabilities do not exactly match the payload")
    if manifest.platforms != platforms:
        raise ActionPackageError("manifest platforms do not exactly match the payload")
    if manifest.safety_tiers != tiers:
        raise ActionPackageError("manifest safety tiers do not exactly match the payload")
    for definition in definitions:
        if definition.provenance.license != manifest.license.spdx_id:
            raise ActionPackageError(
                f"payload definition {definition.id} provenance license conflicts with manifest"
            )
        _content_addressed_source_reference(
            definition.provenance.reference,
            f"payload definition {definition.id} provenance.reference",
        )


@lru_cache(maxsize=1)
def _reviewed_action_registry() -> Any:
    """Load the immutable-by-convention built-in registry once per process."""

    from .registry import load_builtin_registry

    return load_builtin_registry()


def _validate_program_bindings(actions: tuple[PackagedAction, ...]) -> None:
    """Bind every alias to the complete reviewed logical runner contract."""

    # Loaded lazily so this execution-free contract does not add a module
    # initialization dependency on catalog I/O. Caching also bounds repeated
    # rejection work for invalid packages on this local administrative surface.
    reviewed_registry = _reviewed_action_registry()
    packaged_by_id = {item.definition.id: item for item in actions}
    for packaged in actions:
        definition = packaged.definition
        opcode = packaged.program.steps[0].opcode
        try:
            reviewed = reviewed_registry.get_action(opcode)
        except ContractError as exc:  # pragma: no cover - guarded by the static allowlist
            raise ActionPackageError(f"reviewed opcode is unavailable: {opcode}") from exc
        if definition.safety_tier is not reviewed.safety_tier:
            raise ActionPackageError(
                f"action {definition.id} understates or changes reviewed opcode safety tier"
            )
        if set(definition.capabilities) != set(reviewed.capabilities):
            raise ActionPackageError(
                f"action {definition.id} capabilities differ from its reviewed opcode"
            )
        if not set(definition.platforms).issubset(reviewed.platforms):
            raise ActionPackageError(
                f"action {definition.id} expands its reviewed opcode platforms"
            )
        if definition.mutates is not reviewed.mutates:
            raise ActionPackageError(
                f"action {definition.id} mutation claim differs from its reviewed opcode"
            )
        if tuple(spec.signature() for spec in definition.inputs) != tuple(
            spec.signature() for spec in reviewed.inputs
        ):
            raise ActionPackageError(
                f"action {definition.id} input schema differs from its reviewed opcode"
            )
        if tuple(spec.signature() for spec in definition.outputs) != tuple(
            spec.signature() for spec in reviewed.outputs
        ):
            raise ActionPackageError(
                f"action {definition.id} output schema differs from its reviewed opcode"
            )
        if tuple(spec.signature() for spec in definition.parameters) != tuple(
            spec.signature() for spec in reviewed.parameters
        ):
            raise ActionPackageError(
                f"action {definition.id} parameter schema differs from its reviewed opcode"
            )
        if reviewed.cleanup_action_id is None:
            if definition.cleanup_action_id is not None:
                raise ActionPackageError(
                    f"action {definition.id} invents cleanup for an effect-free reviewed opcode"
                )
            continue
        if definition.cleanup_action_id is None:
            raise ActionPackageError(
                f"action {definition.id} omits its reviewed opcode cleanup operation"
            )
        packaged_cleanup = packaged_by_id[definition.cleanup_action_id]
        cleanup_opcode = packaged_cleanup.program.steps[0].opcode
        if cleanup_opcode != reviewed.cleanup_action_id:
            raise ActionPackageError(
                f"action {definition.id} cleanup does not select the reviewed cleanup opcode"
            )


def _parse_content(
    envelope: Mapping[str, Any],
    *,
    bluefire_version: str | None,
    platform: str | None,
    occupied_behavior_ids: Collection[str],
    occupied_action_ids: Collection[str],
    enforce_current_action_contract: bool,
) -> tuple[
    ActionPackageManifest,
    tuple[BehaviorDefinition, ...],
    tuple[PackagedAction, ...],
    bytes,
]:
    data = _strict_mapping(
        envelope,
        context="envelope",
        required={"schema_version", "manifest", "payload", "integrity", "signature"},
    )
    if data["schema_version"] != ACTION_PACKAGE_SCHEMA:
        raise ActionPackageError(f"envelope.schema_version must be {ACTION_PACKAGE_SCHEMA}")
    manifest = ActionPackageManifest.from_mapping(data["manifest"])
    behaviors, actions = _parse_payload(data["payload"])
    _validate_id_closure(
        manifest,
        behaviors,
        actions,
        occupied_behavior_ids=occupied_behavior_ids,
        occupied_action_ids=occupied_action_ids,
    )
    if enforce_current_action_contract:
        _validate_program_bindings(actions)
    _validate_manifest_claims(manifest, behaviors, actions)
    if bluefire_version is not None:
        current = SemVer.parse(bluefire_version, "bluefire_version")
        if not manifest.compatibility.supports(current):
            raise ActionPackageError(
                f"package is incompatible with BlueFire Nexus {bluefire_version}"
            )
    if platform is not None:
        selected = _identifier(platform, "platform", _NAMESPACE, maximum=32)
        if selected not in manifest.platforms:
            raise ActionPackageError(f"package does not support platform {selected}")
    content = {
        "schema_version": ACTION_PACKAGE_SCHEMA,
        "manifest": data["manifest"],
        "payload": data["payload"],
    }
    return manifest, behaviors, actions, canonical_json_bytes(content)


def _signature_input(content_digest: str) -> bytes:
    if _SHA256.fullmatch(content_digest) is None:
        raise ActionPackageError("content digest must be a lowercase SHA-256 digest")
    return SIGNATURE_DOMAIN + bytes.fromhex(content_digest.removeprefix("sha256:"))


def _decode_signature(value: Any) -> tuple[str, bytes]:
    encoded = _bounded_string(value, "signature.value", maximum=128)
    if _B64U.fullmatch(encoded) is None or "=" in encoded:
        raise ActionPackageError("signature.value must be canonical unpadded base64url")
    try:
        raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    except (ValueError, binascii.Error) as exc:
        raise ActionPackageError("signature.value is not valid base64url") from exc
    if len(raw) != 64 or _canonical_b64u(raw) != encoded:
        raise ActionPackageError("signature.value must encode exactly 64 signature bytes")
    return encoded, raw


def build_signed_action_package(
    *,
    manifest: Mapping[str, Any],
    payload: Mapping[str, Any],
    key_id: str,
    private_key: Ed25519PrivateKey,
) -> bytes:
    """Build canonical signed bytes after validating all package content.

    This helper proves well-formedness, not trust.  Installation must still call
    :func:`verify_action_package` with a local trusted-signer mapping.
    """

    if not isinstance(private_key, Ed25519PrivateKey):
        raise ActionPackageError("private_key must be an Ed25519 private key")
    clean_key_id = _identifier(key_id, "signature.key_id", _KEY_ID)
    provisional = {
        "schema_version": ACTION_PACKAGE_SCHEMA,
        "manifest": dict(manifest),
        "payload": dict(payload),
        "integrity": {"algorithm": "sha256", "content_digest": "sha256:" + "0" * 64},
        "signature": {"algorithm": "ed25519", "key_id": clean_key_id, "value": "A" * 86},
    }
    _validate_json_tree(provisional)
    _reject_forbidden_fields(provisional)
    provisional_bytes = canonical_json_bytes(provisional)
    parsed = parse_canonical_action_package(provisional_bytes)
    _, _, _, content_bytes = _parse_content(
        parsed,
        bluefire_version=None,
        platform=None,
        occupied_behavior_ids=(),
        occupied_action_ids=(),
        enforce_current_action_contract=True,
    )
    content_digest = _digest(content_bytes)
    signature = private_key.sign(_signature_input(content_digest))
    envelope = {
        "schema_version": ACTION_PACKAGE_SCHEMA,
        "manifest": parsed["manifest"],
        "payload": parsed["payload"],
        "integrity": {"algorithm": "sha256", "content_digest": content_digest},
        "signature": {
            "algorithm": "ed25519",
            "key_id": clean_key_id,
            "value": _canonical_b64u(signature),
        },
    }
    result = canonical_json_bytes(envelope)
    if len(result) > MAX_ENVELOPE_BYTES:
        raise ActionPackageError(f"action package envelope exceeds {MAX_ENVELOPE_BYTES} bytes")
    return result


def _verify_action_package(
    envelope_bytes: bytes,
    *,
    trusted_signers: Mapping[tuple[str, str], PublicKeyValue],
    bluefire_version: str | None,
    platform: str | None,
    occupied_behavior_ids: Collection[str] = (),
    occupied_action_ids: Collection[str] = (),
    enforce_current_action_contract: bool,
) -> VerifiedActionPackage:
    if (bluefire_version is None) != (platform is None):
        raise ActionPackageError(
            "bluefire_version and platform must both be supplied or both be omitted"
        )
    envelope = parse_canonical_action_package(envelope_bytes)
    manifest, behaviors, actions, content_bytes = _parse_content(
        envelope,
        bluefire_version=bluefire_version,
        platform=platform,
        occupied_behavior_ids=occupied_behavior_ids,
        occupied_action_ids=occupied_action_ids,
        enforce_current_action_contract=enforce_current_action_contract,
    )
    integrity = _strict_mapping(
        envelope["integrity"],
        context="integrity",
        required={"algorithm", "content_digest"},
    )
    if integrity["algorithm"] != "sha256":
        raise ActionPackageError("integrity.algorithm must be sha256")
    claimed_digest = _bounded_string(
        integrity["content_digest"], "integrity.content_digest", maximum=71
    )
    if _SHA256.fullmatch(claimed_digest) is None:
        raise ActionPackageError("integrity.content_digest must be a lowercase SHA-256 digest")
    actual_digest = _digest(content_bytes)
    if claimed_digest != actual_digest:
        raise ActionPackageError("action package content integrity check failed")
    signature = _strict_mapping(
        envelope["signature"],
        context="signature",
        required={"algorithm", "key_id", "value"},
    )
    if signature["algorithm"] != "ed25519":
        raise ActionPackageError("signature.algorithm must be ed25519")
    key_id = _identifier(signature["key_id"], "signature.key_id", _KEY_ID)
    signature_b64u, signature_bytes = _decode_signature(signature["value"])
    trust_identity = (manifest.provenance.publisher_id, key_id)
    trusted_value = trusted_signers.get(trust_identity)
    if trusted_value is None:
        raise ActionPackageError(
            f"package signer is not locally trusted: {trust_identity[0]}/{trust_identity[1]}"
        )
    raw_public_key = normalize_ed25519_public_key(trusted_value)
    public_key = Ed25519PublicKey.from_public_bytes(raw_public_key)
    try:
        public_key.verify(signature_bytes, _signature_input(actual_digest))
    except InvalidSignature as exc:
        raise ActionPackageError("action package signature verification failed") from exc
    return VerifiedActionPackage(
        canonical_envelope_bytes=envelope_bytes,
        canonical_content_bytes=content_bytes,
        content_digest=actual_digest,
        package_digest=_digest(envelope_bytes),
        publisher_id=manifest.provenance.publisher_id,
        key_id=key_id,
        public_key_fingerprint=_digest(raw_public_key),
        signature_b64u=signature_b64u,
        manifest=manifest,
        behaviors=behaviors,
        actions=actions,
    )


def verify_action_package(
    envelope_bytes: bytes,
    *,
    trusted_signers: Mapping[tuple[str, str], PublicKeyValue],
    bluefire_version: str | None,
    platform: str | None,
    occupied_behavior_ids: Collection[str] = (),
    occupied_action_ids: Collection[str] = (),
) -> VerifiedActionPackage:
    """Verify a package against the current reviewed action contract.

    Supplying a product version and platform additionally proves target
    compatibility. Passing ``None`` for both stages against the current action
    contract without choosing a target; activation must recheck a concrete
    product version and authenticated runner platform.
    """

    return _verify_action_package(
        envelope_bytes,
        trusted_signers=trusted_signers,
        bluefire_version=bluefire_version,
        platform=platform,
        occupied_behavior_ids=occupied_behavior_ids,
        occupied_action_ids=occupied_action_ids,
        enforce_current_action_contract=True,
    )


def audit_action_package(
    envelope_bytes: bytes,
    *,
    trusted_signers: Mapping[tuple[str, str], PublicKeyValue],
) -> VerifiedActionPackage:
    """Reverify immutable v1 structure/signature for historical inventory.

    This intentionally omits the mutable current registry and target
    compatibility. It cannot authorize activation or execution.
    """

    return _verify_action_package(
        envelope_bytes,
        trusted_signers=trusted_signers,
        bluefire_version=None,
        platform=None,
        occupied_behavior_ids=(),
        occupied_action_ids=(),
        enforce_current_action_contract=False,
    )


__all__ = [
    "ACTION_PACKAGE_PAYLOAD_SCHEMA",
    "ACTION_PACKAGE_SCHEMA",
    "ACTION_PROGRAM_ADAPTER",
    "ACTION_PROGRAM_SCHEMA",
    "ALLOWED_PROGRAM_ADAPTERS",
    "ALLOWED_PROGRAM_OPCODES",
    "ActionPackageError",
    "ActionPackageManifest",
    "ActionProgram",
    "ActionProgramStep",
    "audit_action_package",
    "MAX_ACTIONS",
    "MAX_BEHAVIORS",
    "MAX_COLLECTION_ITEMS",
    "MAX_CONSTANTS",
    "MAX_ENVELOPE_BYTES",
    "MAX_JSON_DEPTH",
    "MAX_PROGRAM_STEPS",
    "MAX_STRING_CHARS",
    "PackageCompatibility",
    "PackageLicense",
    "PackageProvenance",
    "PackagedAction",
    "SemVer",
    "VerifiedActionPackage",
    "build_signed_action_package",
    "canonical_public_key_b64u",
    "ed25519_public_key_fingerprint",
    "normalize_ed25519_public_key",
    "parse_canonical_action_package",
    "verify_action_package",
]
