"""Exact validation for durable reviewed-source intake operation receipts."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Mapping

from .source_intake_package import INTAKE_ID, PACKAGE_ID, PACKAGE_VERSION
from .util import canonical_json_bytes, content_hash

OPERATION_RECEIPT_SCHEMA = "bluefire.reviewed-source-intake-operation-receipt.v1"
OPERATION_RECEIPT_MEDIA_TYPE = (
    "application/vnd.bluefire.reviewed-source-intake-operation-receipt+json"
)
MAX_OPERATION_RECEIPT_BYTES = 32 * 1024


class SourceIntakeReceiptValidationError(ValueError):
    """Raised when an operation receipt is not exact or independently bound."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise SourceIntakeReceiptValidationError(message)


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise SourceIntakeReceiptValidationError(
                "the source-intake operation receipt contains duplicate keys"
            )
        value[key] = item
    return value


def _utc_timestamp(value: Any) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise SourceIntakeReceiptValidationError(
            "the source-intake operation receipt time is invalid"
        )
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise SourceIntakeReceiptValidationError(
            "the source-intake operation receipt time is invalid"
        ) from exc
    if parsed.tzinfo != timezone.utc:
        raise SourceIntakeReceiptValidationError(
            "the source-intake operation receipt time is invalid"
        )
    return parsed


def validate_source_intake_operation_receipt(
    payload: bytes,
    *,
    destination_id: str,
    operator_id: str,
    profile_id: str,
    intake: Mapping[str, Any],
    package: Mapping[str, Any],
    activation_operation: str,
    catalog_generation: int,
    catalog_digest: str,
    not_before: datetime | None = None,
    not_after: datetime | None = None,
) -> tuple[Mapping[str, Any], str, datetime]:
    """Validate canonical bytes against intake, package, catalog, actor, and time."""

    _require(
        0 < len(payload) <= MAX_OPERATION_RECEIPT_BYTES,
        "the source-intake operation receipt has an invalid size",
    )
    try:
        record = json.loads(payload, object_pairs_hook=_object_without_duplicate_keys)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise SourceIntakeReceiptValidationError(
            "the source-intake operation receipt is invalid JSON"
        ) from exc
    _require(
        isinstance(record, Mapping) and payload == canonical_json_bytes(record),
        "the source-intake operation receipt is not canonical JSON",
    )
    intake_record = intake.get("record")
    if not isinstance(intake_record, Mapping):
        raise SourceIntakeReceiptValidationError(
            "the operation receipt intake binding is unavailable"
        )
    expected_artifact_ref = f"source-intakes/{destination_id}/{INTAKE_ID}.json"
    completed_at = _utc_timestamp(record.get("completed_at"))
    _require(
        (not_before is None) == (not_after is None),
        "the operation receipt validation interval is incomplete",
    )
    if not_before is not None and not_after is not None:
        _require(
            not_before <= completed_at <= not_after,
            "the source-intake operation receipt time is outside the gate interval",
        )
    _require(
        type(catalog_generation) is int
        and set(record)
        == {
            "schema_version",
            "destination_id",
            "operator_id",
            "runner_profile_id",
            "intake",
            "artifact",
            "package",
            "activation",
            "completed_at",
        }
        and record.get("schema_version") == OPERATION_RECEIPT_SCHEMA
        and record.get("destination_id") == destination_id
        and record.get("operator_id") == operator_id
        and record.get("runner_profile_id") == profile_id
        and record.get("intake")
        == {
            "intake_id": INTAKE_ID,
            "record_sha256": intake.get("record_sha256"),
            "output_sha256": content_hash(intake_record.get("output")),
        }
        and record.get("artifact")
        == {
            "state_ref": expected_artifact_ref,
            "sha256": content_hash(intake),
            "size_bytes": len(canonical_json_bytes(intake)),
        }
        and record.get("package")
        == {
            "package_id": PACKAGE_ID,
            "version": PACKAGE_VERSION,
            "package_digest": package.get("package_digest"),
            "content_digest": package.get("content_digest"),
        }
        and record.get("activation")
        == {
            "operation": activation_operation,
            "catalog_generation": catalog_generation,
            "catalog_digest": catalog_digest,
        },
        "the source-intake operation receipt is detached from product state",
    )
    return record, content_hash(record), completed_at


def validate_source_intake_operation_receipt_binding(
    payload: bytes,
    binding: Any,
    *,
    artifact_path: str,
    destination_id: str,
    operator_id: str,
    profile_id: str,
    intake: Mapping[str, Any],
    package: Mapping[str, Any],
    activation_operation: str,
    catalog_generation: int,
    catalog_digest: str,
    not_before: datetime | None = None,
    not_after: datetime | None = None,
) -> Mapping[str, Any]:
    """Validate a receipt and its exact persisted-evidence descriptor."""

    record, receipt_sha256, _completed_at = validate_source_intake_operation_receipt(
        payload,
        destination_id=destination_id,
        operator_id=operator_id,
        profile_id=profile_id,
        intake=intake,
        package=package,
        activation_operation=activation_operation,
        catalog_generation=catalog_generation,
        catalog_digest=catalog_digest,
        not_before=not_before,
        not_after=not_after,
    )
    _require(
        binding
        == {
            "path": artifact_path,
            "media_type": OPERATION_RECEIPT_MEDIA_TYPE,
            "sha256": receipt_sha256,
            "size_bytes": len(payload),
            "state_ref": f"source-intakes/{destination_id}/{INTAKE_ID}.operation-receipt.json",
        },
        "the source-intake operation receipt descriptor is invalid",
    )
    return record


__all__ = [
    "MAX_OPERATION_RECEIPT_BYTES",
    "OPERATION_RECEIPT_MEDIA_TYPE",
    "OPERATION_RECEIPT_SCHEMA",
    "SourceIntakeReceiptValidationError",
    "validate_source_intake_operation_receipt",
    "validate_source_intake_operation_receipt_binding",
]
