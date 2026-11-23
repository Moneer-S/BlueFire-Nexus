"""Explicit paired-v2 provenance; shared geometry never negotiates a protocol."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from . import windows_file_access_admission as common
from .file_access_contract import FileAccessContractError
from .util import canonical_json_bytes, content_hash

_PROTOCOL = common._PAIR_SETUP
SCHEMA = _PROTOCOL.schema("access-enrollment")
IMPORT_SCHEMA = _PROTOCOL.schema("setup-import")
CONTEXT_SCHEMA = _PROTOCOL.schema("access-baseline-context")
PREPARATION_SCHEMA = _PROTOCOL.schema("access-baseline-preparation")


def _document(value: Any) -> dict[str, Any]:
    return common._document_for(value, _PROTOCOL)


def _purpose(row: dict[str, Any]) -> str:
    return common._purpose_for(row, _PROTOCOL)


@dataclass(frozen=True, slots=True)
class WindowsPairEnrollmentCandidate:
    _raw: bytes = field(repr=False)

    def __post_init__(self) -> None:
        try:
            common.wire._require(type(self._raw) is bytes)
            _document(self._raw)
        except common._FAILURES:
            raise FileAccessContractError(
                "Windows paired enrollment candidate is invalid."
            ) from None

    @property
    def consistency_digest(self) -> str:
        return content_hash(_document(self._raw))

    @property
    def generation(self) -> str:
        return str(_document(self._raw)["generation"])

    @property
    def resource_path(self) -> str:
        return "C:\\BlueFire\\EndpointAccess\\" + self.generation + "\\records.jsonl"

    @property
    def reader_account(self) -> str:
        return "bf_" + self.generation[:16]


def parse_windows_pair_enrollment_candidate(
    value: Any, *, now_ms: int
) -> WindowsPairEnrollmentCandidate:
    try:
        row = _document(value)
        common.wire._int(now_ms, 1, 2**63 - 1)
        common.wire._require(row["issued_at_ms"] <= now_ms < row["expires_at_ms"])
        return WindowsPairEnrollmentCandidate(canonical_json_bytes(row))
    except common._FAILURES:
        raise FileAccessContractError(
            "Windows paired enrollment candidate is invalid or stale."
        ) from None


@dataclass(frozen=True, slots=True, init=False)
class VerifiedWindowsPairSetup:
    _raw: bytes = field(repr=False)
    _receipt: bytes = field(repr=False)

    def __init__(self) -> None:
        raise TypeError("Windows setup snapshots require the concrete protected observer")

    def summary(self) -> dict[str, Any]:
        row = _document(self._raw)
        return {
            "enrollment_id": row["enrollment_id"],
            "enrollment_digest": content_hash(row),
            "expires_at_ms": row["expires_at_ms"],
            "verification": "protected_setup_only",
        }


def checked_provenance(checked: VerifiedWindowsPairSetup) -> tuple[dict, dict]:
    common.wire._require(type(checked) is VerifiedWindowsPairSetup)
    return common._provenance_for(
        checked._raw, common.wire._document(checked._receipt, 16384), _PROTOCOL
    )


def import_document(checked: VerifiedWindowsPairSetup, *, now_ms: int) -> dict:
    row, receipt = checked_provenance(checked)
    return common._import_document_for(row, receipt, now_ms, _PROTOCOL)


def validate_import(value: Any) -> dict:
    return common._validate_import_for(value, _PROTOCOL)


def projection(value: Any) -> dict:
    return common._projection_for(value, _PROTOCOL)


def baseline_context(imported: Any) -> dict:
    return common._baseline_context_for(imported, _PROTOCOL)


def build_preparation(job_id: str, original: dict, imported: dict, *, issued_at_ms: int) -> dict:
    return common._build_preparation_for(job_id, original, imported, issued_at_ms, _PROTOCOL)


def validate_retained_preparation(value: Any, original: dict, imported: dict) -> dict:
    """Historical consistency only; never current dispatch or renewed authority."""
    return common._retained_preparation_for(value, original, imported, _PROTOCOL)


def validate_preparation(value: Any, original: dict, imported: dict, *, now_ms: int) -> dict:
    row = validate_retained_preparation(value, original, imported)
    common.wire._int(now_ms, 1, 2**63 - 1)
    if not row["issued_at_ms"] <= now_ms < row["expires_at_ms"]:
        raise common.ProductStoreError(
            "The original Windows baseline preparation changed or expired."
        )
    return row
