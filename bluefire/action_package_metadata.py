"""Version, compatibility, licensing, and provenance package metadata."""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from functools import total_ordering
from typing import Any, Mapping
from urllib.parse import urlsplit

from .action_package_errors import ActionPackageError

_PACKAGE_ID = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
_SPDX_SHAPED_ID = re.compile(
    r"^(?:[A-Za-z0-9][A-Za-z0-9.+-]{0,63}|LicenseRef-[A-Za-z0-9.-]{1,52})$"
)
_IMMUTABLE_REVISION = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64}|sha256:[0-9a-f]{64})$")
_URN_REFERENCE = re.compile(
    r"^urn:[a-z0-9][a-z0-9-]{0,31}:[A-Za-z0-9]" r"[A-Za-z0-9._~:/@!$&'()*+,;=%-]{0,959}$"
)
_SEMVER = re.compile(
    r"^(0|[1-9][0-9]*)\."
    r"(0|[1-9][0-9]*)\."
    r"(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)
_SEMVER_CORE_MAX = (1 << 64) - 1


def _bounded_string(value: Any, context: str, *, maximum: int) -> str:
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


def _strict_mapping(value: Any, *, context: str, required: set[str]) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ActionPackageError(f"{context} must be an object")
    missing = required - set(value)
    unknown = set(value) - required
    if missing:
        raise ActionPackageError(f"{context} is missing fields: {', '.join(sorted(missing))}")
    if unknown:
        raise ActionPackageError(f"{context} has unknown fields: {', '.join(sorted(unknown))}")
    return value


def _identifier(value: Any, context: str, pattern: re.Pattern[str]) -> str:
    result = _bounded_string(value, context, maximum=128)
    if pattern.fullmatch(result) is None:
        raise ActionPackageError(f"{context} has an invalid identifier")
    return result


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
        or port == 443
    ):
        raise ActionPackageError(
            f"{context} must be a canonical credential-free HTTPS URL without query or fragment, "
            "or a bounded URN"
        )
    return reference


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
        core = tuple(int(match.group(index)) for index in (1, 2, 3))
        if any(part > _SEMVER_CORE_MAX for part in core):
            raise ActionPackageError(
                f"{context} semantic version core must fit unsigned 64-bit integers"
            )
        prerelease = tuple(match.group(4).split(".")) if match.group(4) else ()
        build = tuple(match.group(5).split(".")) if match.group(5) else ()
        if any(part.isdigit() and len(part) > 1 and part.startswith("0") for part in prerelease):
            raise ActionPackageError(
                f"{context} numeric prerelease identifiers cannot contain leading zeroes"
            )
        return cls(text, core[0], core[1], core[2], prerelease, build)

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
        return isinstance(other, SemVer) and self._compare(other) == 0

    def __hash__(self) -> int:
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
        revision = _bounded_string(data["revision"], f"{context}.revision", maximum=71)
        if _IMMUTABLE_REVISION.fullmatch(revision) is None:
            raise ActionPackageError(
                f"{context}.revision must be a full lowercase VCS commit or sha256 digest"
            )
        return cls(
            publisher_id=_identifier(data["publisher_id"], f"{context}.publisher_id", _PACKAGE_ID),
            source=_bounded_string(data["source"], f"{context}.source", maximum=512),
            reference=_immutable_source_reference(data["reference"], f"{context}.reference"),
            revision=revision,
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "publisher_id": self.publisher_id,
            "source": self.source,
            "reference": self.reference,
            "revision": self.revision,
        }


__all__ = ["PackageCompatibility", "PackageLicense", "PackageProvenance", "SemVer"]
