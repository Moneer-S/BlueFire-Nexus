"""Opaque correction evidence and pure retained-document consistency checks."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from . import _windows_file_access_native_contract as contract
from . import windows_file_access_pair_admission as pair
from .util import canonical_json_bytes, content_hash

RECEIPT_SCHEMA = "bluefire.windows-file-correction-control-receipt.v1"
RESULT_SCHEMA = "bluefire.windows-file-correction-child-result.v1"
OUTPUT_MAX = 4096


@dataclass(frozen=True, slots=True)
class CorrectionObservationInput:
    checked_setup: pair.VerifiedWindowsPairSetup = field(repr=False)
    binding_bytes: bytes = field(repr=False)
    target_descriptor_sha256: str = field(repr=False)


@dataclass(frozen=True, slots=True, init=False)
class VerifiedWindowsCorrectionPostimage:
    _raw: bytes = field(repr=False)
    _receipt: bytes = field(repr=False)
    _binding: bytes = field(repr=False)
    _descriptor_sha256: str = field(repr=False)
    _setup: pair.VerifiedWindowsPairSetup = field(repr=False)

    def __init__(self) -> None:
        raise TypeError("Windows correction facts require the concrete protected observer")


def _validated(value: CorrectionObservationInput) -> tuple[dict, dict, dict]:
    from .windows_file_access_correction_admission import validate_correction_binding

    contract._require(
        type(value) is CorrectionObservationInput and type(value.binding_bytes) is bytes
    )
    record, receipt = pair.checked_provenance(value.checked_setup)
    binding = validate_correction_binding(value.binding_bytes, value.checked_setup)
    contract._require(value.binding_bytes == canonical_json_bytes(binding))
    contract._require(
        binding["target_resource"] == {**record["resource"], "state": "metadata_only"}
    )
    contract._digest(value.target_descriptor_sha256)
    return record, receipt, binding


def checked_provenance(checked: VerifiedWindowsCorrectionPostimage) -> tuple[dict, dict, dict]:
    """Historical consistency only; dispatch still needs the exact durable claim."""
    contract._require(type(checked) is VerifiedWindowsCorrectionPostimage)
    value = CorrectionObservationInput(checked._setup, checked._binding, checked._descriptor_sha256)
    record, receipt, binding = _validated(value)
    contract._require(
        checked._raw == checked._setup._raw and checked._receipt == checked._setup._receipt
    )
    return record, receipt, binding


def observation_input(checked: VerifiedWindowsCorrectionPostimage) -> CorrectionObservationInput:
    checked_provenance(checked)
    return CorrectionObservationInput(checked._setup, checked._binding, checked._descriptor_sha256)


def validate_terminal(value: Any, binding: dict, returncode: int) -> dict:
    row = contract._exact(
        contract._document(value, OUTPUT_MAX), "schema_version binding_digest result"
    )
    contract._require(
        row["schema_version"] == RESULT_SCHEMA and row["binding_digest"] == content_hash(binding)
    )
    if row["result"] is None:
        contract._require(returncode == 4)
    else:
        result = contract._exact(
            row["result"],
            "before_descriptor_sha256 after_descriptor_sha256 target file_identity preserved_sha256 fresh_owner_read read_handles_closed",
        )
        contract._digest(result["before_descriptor_sha256"])
        contract._digest(result["after_descriptor_sha256"])
        contract._require(
            returncode == 0
            and result["before_descriptor_sha256"] == binding["previous_descriptor_sha256"]
            and result["after_descriptor_sha256"] != result["before_descriptor_sha256"]
            and result["target"] == "metadata_only"
            and result["file_identity"] == binding["target_resource"]["file_identity"]
            and result["preserved_sha256"] == binding["target_resource"]["sha256"]
            and result["fresh_owner_read"] is True
            and result["read_handles_closed"] is True
        )
    return row


def validate_retained_control_receipt(payload: Any, binding: dict) -> dict:
    """Historical consistency only; never restore an owner or dispatch allowance."""
    row = contract._exact(
        contract._document(payload),
        "schema_version binding_digest dispatch process_cleanup terminal settled",
    )
    contract._require(
        row["schema_version"] == RECEIPT_SCHEMA
        and row["binding_digest"] == content_hash(binding)
        and row["dispatch"] in ("not_started", "unknown", "attempted")
        and row["process_cleanup"] == "verified"
        and row["settled"] is False
    )
    if row["terminal"] is not None:
        contract._require(type(row["terminal"]) is dict)
        terminal = row["terminal"]
        validate_terminal(terminal, binding, 4 if terminal.get("result") is None else 0)
        contract._require(
            (row["dispatch"] == "unknown" and terminal["result"] is None)
            or (row["dispatch"] == "attempted" and terminal["result"] is not None)
        )
    else:
        contract._require(row["dispatch"] in ("not_started", "unknown"))
    return row


@dataclass(frozen=True, slots=True, init=False)
class OwnedCorrectionControlReceipt:
    """Trusted supervisor-produced physical closure, never proof against Python code."""

    _raw: bytes = field(repr=False)
    _binding: bytes = field(repr=False)

    def __init__(self) -> None:
        raise TypeError("Correction closure receipts require the trusted process supervisor")

    def document(self) -> dict:
        contract._require(type(self) is OwnedCorrectionControlReceipt)
        row = validate_retained_control_receipt(self._raw, contract._document(self._binding))
        contract._require(self._raw == canonical_json_bytes(row))
        return row
