"""Strict request contract for offline declarative source intake."""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from datetime import date
from pathlib import PurePosixPath
from typing import Any, Mapping
from urllib.parse import urlsplit

MAX_SOURCE_BYTES = 1024 * 1024
GATE_CHECK_NAMES = frozenset(
    {
        "classification_model",
        "pinned_metadata_import",
        "executable_adapter",
        "source_license_review",
        "attribution_integrity_transform",
        "ui_provenance",
        "third_party_notices",
        "safe_intake",
    }
)

_INTAKE_ID = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*\.v[1-9][0-9]*$")
_TRANSFORMER_NAME = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
_TRANSFORMER_VERSION = re.compile(r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_IMMUTABLE_REF = re.compile(
    r"^(?:[0-9a-f]{40}|[0-9a-f]{64}|sha256:[0-9a-f]{64}|"
    r"v?[0-9]+(?:\.[0-9]+){1,3}(?:-[0-9A-Za-z.-]+)?)$"
)
_SPDX_ID = re.compile(r"^(?:[A-Za-z0-9][A-Za-z0-9.+-]{0,63}|LicenseRef-[A-Za-z0-9.-]{1,52})$")
_SAFE_PATH_COMPONENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class SourceIntakeError(ValueError):
    """Raised when an intake request, source, transform, or publication is unsafe."""


def _error(message: str) -> SourceIntakeError:
    return SourceIntakeError(message)


def _strict_object(value: Any, *, context: str, required: set[str]) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise _error(f"{context} must be an object with string keys")
    missing = required - set(value)
    unknown = set(value) - required
    if missing:
        raise _error(f"{context} is missing fields: {', '.join(sorted(missing))}")
    if unknown:
        raise _error(f"{context} has unknown fields: {', '.join(sorted(unknown))}")
    return value


def _bounded_text(value: Any, context: str, *, maximum: int = 1024) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise _error(f"{context} must be a non-empty canonical string")
    if len(value) > maximum:
        raise _error(f"{context} exceeds {maximum} characters")
    if unicodedata.normalize("NFC", value) != value:
        raise _error(f"{context} must use NFC-normalized Unicode")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise _error(f"{context} contains control characters")
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise _error(f"{context} contains an invalid Unicode scalar value")
    return value


def _identifier(value: Any, context: str) -> str:
    result = _bounded_text(value, context, maximum=128)
    if _INTAKE_ID.fullmatch(result) is None:
        raise _error(f"{context} must be a lowercase versioned stable ID")
    return result


def _digest(value: Any, context: str) -> str:
    result = _bounded_text(value, context, maximum=71)
    if _SHA256.fullmatch(result) is None:
        raise _error(f"{context} must be a canonical sha256 digest")
    return result


def _positive_size(value: Any, context: str, *, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 < value <= maximum:
        raise _error(f"{context} must be between 1 and {maximum} bytes")
    return value


def _iso_date(value: Any, context: str) -> str:
    result = _bounded_text(value, context, maximum=10)
    try:
        parsed = date.fromisoformat(result)
    except ValueError as exc:
        raise _error(f"{context} must be an ISO calendar date") from exc
    if parsed.isoformat() != result:
        raise _error(f"{context} must be a canonical ISO calendar date")
    return result


def _https_url(value: Any, context: str, *, exact_ref: str | None = None) -> str:
    result = _bounded_text(value, context, maximum=1024)
    try:
        parsed = urlsplit(result)
        port = parsed.port
    except ValueError as exc:
        raise _error(f"{context} must be a canonical public HTTPS URL") from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or port is not None
        or "\\" in result
        or not parsed.netloc.isascii()
        or parsed.netloc != parsed.netloc.casefold()
    ):
        raise _error(f"{context} must be a canonical credential-free HTTPS URL")
    if exact_ref is not None and exact_ref not in parsed.path:
        raise _error(f"{context} must contain the exact immutable source ref")
    return result


def _relative_source_path(value: Any, context: str) -> str:
    result = _bounded_text(value, context, maximum=512)
    if "\\" in result or ":" in result or result.startswith("/") or "\x00" in result:
        raise _error(f"{context} must be a canonical relative POSIX path")
    path = PurePosixPath(result)
    parts = path.parts
    if (
        not parts
        or str(path) != result
        or any(part in {"", ".", ".."} for part in parts)
        or any(_SAFE_PATH_COMPONENT.fullmatch(part) is None for part in parts)
    ):
        raise _error(f"{context} contains an unsafe path component")
    return result


@dataclass(frozen=True, slots=True)
class IntakeSource:
    path: str
    sha256: str
    size_bytes: int
    media_type: str

    @classmethod
    def from_mapping(cls, value: Any, context: str = "request.source") -> "IntakeSource":
        data = _strict_object(
            value, context=context, required={"path", "sha256", "size_bytes", "media_type"}
        )
        media_type = _bounded_text(data["media_type"], f"{context}.media_type", maximum=64)
        if media_type != "application/json":
            raise _error(f"{context}.media_type must be application/json")
        return cls(
            path=_relative_source_path(data["path"], f"{context}.path"),
            sha256=_digest(data["sha256"], f"{context}.sha256"),
            size_bytes=_positive_size(
                data["size_bytes"], f"{context}.size_bytes", maximum=MAX_SOURCE_BYTES
            ),
            media_type=media_type,
        )


@dataclass(frozen=True, slots=True)
class IntakeProvenance:
    research_source_id: str
    project: str
    exact_ref: str
    version: str
    retrieved_at: str
    reference_url: str

    @classmethod
    def from_mapping(cls, value: Any, context: str = "request.provenance") -> "IntakeProvenance":
        data = _strict_object(
            value,
            context=context,
            required={
                "research_source_id",
                "project",
                "exact_ref",
                "version",
                "retrieved_at",
                "reference_url",
            },
        )
        exact_ref = _bounded_text(data["exact_ref"], f"{context}.exact_ref", maximum=128)
        if _IMMUTABLE_REF.fullmatch(exact_ref) is None:
            raise _error(f"{context}.exact_ref must be an immutable commit, digest, or version")
        version = _bounded_text(data["version"], f"{context}.version", maximum=128)
        if version.casefold() in {"head", "latest", "main", "master", "trunk"}:
            raise _error(f"{context}.version must not be a mutable label")
        return cls(
            research_source_id=_identifier(
                data["research_source_id"], f"{context}.research_source_id"
            ),
            project=_bounded_text(data["project"], f"{context}.project", maximum=256),
            exact_ref=exact_ref,
            version=version,
            retrieved_at=_iso_date(data["retrieved_at"], f"{context}.retrieved_at"),
            reference_url=_https_url(
                data["reference_url"], f"{context}.reference_url", exact_ref=exact_ref
            ),
        )


@dataclass(frozen=True, slots=True)
class IntakeReview:
    license: str
    license_url: str
    license_review: str
    file_review: str
    file_disposition: str
    use_classification: str
    attribution: str

    @classmethod
    def from_mapping(cls, value: Any, context: str = "request.review") -> "IntakeReview":
        required = {
            "license",
            "license_url",
            "license_review",
            "file_review",
            "file_disposition",
            "use_classification",
            "attribution",
        }
        data = _strict_object(value, context=context, required=required)
        license_name = _bounded_text(data["license"], f"{context}.license", maximum=64)
        if _SPDX_ID.fullmatch(license_name) is None:
            raise _error(f"{context}.license must be an SPDX-shaped identifier")
        review = _bounded_text(data["license_review"], f"{context}.license_review", maximum=32)
        disposition = _bounded_text(
            data["file_disposition"], f"{context}.file_disposition", maximum=64
        )
        classification = _bounded_text(
            data["use_classification"], f"{context}.use_classification", maximum=64
        )
        if review != "reviewed":
            raise _error(f"{context}.license_review must be reviewed")
        if disposition != "declarative_metadata":
            raise _error(f"{context}.file_disposition must be declarative_metadata")
        if classification != "metadata_import":
            raise _error(f"{context}.use_classification must be metadata_import")
        file_review = _bounded_text(data["file_review"], f"{context}.file_review", maximum=2048)
        attribution = _bounded_text(data["attribution"], f"{context}.attribution", maximum=2048)
        if len(file_review) < 12 or len(attribution) < 8:
            raise _error(f"{context} must include substantive file review and attribution")
        return cls(
            license_name,
            _https_url(data["license_url"], f"{context}.license_url"),
            review,
            file_review,
            disposition,
            classification,
            attribution,
        )


@dataclass(frozen=True, slots=True)
class TransformerSelection:
    name: str
    version: str

    @classmethod
    def from_mapping(
        cls, value: Any, context: str = "request.transformer"
    ) -> "TransformerSelection":
        data = _strict_object(value, context=context, required={"name", "version"})
        name = _bounded_text(data["name"], f"{context}.name", maximum=128)
        version = _bounded_text(data["version"], f"{context}.version", maximum=32)
        if _TRANSFORMER_NAME.fullmatch(name) is None:
            raise _error(f"{context}.name is invalid")
        if _TRANSFORMER_VERSION.fullmatch(version) is None:
            raise _error(f"{context}.version must be strict major.minor.patch")
        return cls(name, version)


@dataclass(frozen=True, slots=True)
class SourceIntakeRequest:
    schema_version: str
    intake_id: str
    source: IntakeSource
    provenance: IntakeProvenance
    review: IntakeReview
    transformer: TransformerSelection

    @classmethod
    def from_mapping(
        cls, value: Any, context: str = "source intake request"
    ) -> "SourceIntakeRequest":
        required = {
            "schema_version",
            "intake_id",
            "source",
            "provenance",
            "review",
            "transformer",
        }
        data = _strict_object(value, context=context, required=required)
        if data["schema_version"] != "bluefire.source-intake-request.v1":
            raise _error(f"{context}.schema_version must be bluefire.source-intake-request.v1")
        return cls(
            "bluefire.source-intake-request.v1",
            _identifier(data["intake_id"], f"{context}.intake_id"),
            IntakeSource.from_mapping(data["source"], f"{context}.source"),
            IntakeProvenance.from_mapping(data["provenance"], f"{context}.provenance"),
            IntakeReview.from_mapping(data["review"], f"{context}.review"),
            TransformerSelection.from_mapping(data["transformer"], f"{context}.transformer"),
        )
