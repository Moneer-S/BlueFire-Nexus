"""Semantic validation for the Gate 09 production-browser source-intake proof."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Mapping
from urllib.parse import urlsplit

from .source_intake_journey import (
    BROWSER_INTAKE_DESTINATION_ID,
    BROWSER_OPERATION_SEQUENCE,
    BROWSER_SCHEMA,
)
from .source_intake_package import (
    ACTION_ID,
    BEHAVIOR_ID,
    INTAKE_ID,
    LICENSE_ASSET,
    LICENSE_ID,
    SOURCE_ASSET,
    SOURCE_COMMIT,
    SOURCE_ID,
)
from .source_intake_receipt_validation import (
    SourceIntakeReceiptValidationError,
    validate_source_intake_operation_receipt,
)
from .util import canonical_json_bytes


class SourceIntakeBrowserValidationError(ValueError):
    """Raised when browser evidence is detached from the real intake operation."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise SourceIntakeBrowserValidationError(message)


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise SourceIntakeBrowserValidationError(
                "the browser-created intake contains duplicate keys"
            )
        value[key] = item
    return value


def _utc_timestamp(value: Any) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise SourceIntakeBrowserValidationError("the browser observation time is invalid")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise SourceIntakeBrowserValidationError("the browser observation time is invalid") from exc
    if parsed.tzinfo != timezone.utc:
        raise SourceIntakeBrowserValidationError("the browser observation time is invalid")
    return parsed


def validate_source_intake_browser_evidence(
    report: Mapping[str, Any],
    *,
    intake: Mapping[str, Any],
    browser_artifact_payload: bytes,
    browser_receipt_payload: bytes,
    profile_id: str,
    package: Mapping[str, Any],
    catalog_generation: int,
    catalog_digest: str,
    not_before: datetime | None = None,
    not_after: datetime | None = None,
) -> None:
    """Bind visible UI claims to the second intake created through the public API."""

    expected_keys = {
        "action_id",
        "activation_operation",
        "attribution_visible",
        "behavior_id",
        "behavior_provenance_reference",
        "behavior_provenance_visible",
        "demo_mode",
        "execution_state",
        "imported_paths",
        "intake_destination_id",
        "intake_record_sha256",
        "intake_state_ref",
        "observed_at",
        "operation_receipt_sha256",
        "operation_receipt_state_ref",
        "operation_receipt_visible",
        "operation_sequence",
        "origin",
        "production_browser_interaction",
        "runner_profile_id",
        "schema_version",
        "source_classification",
        "source_content_handling",
        "source_id",
        "source_license",
        "source_pin",
        "source_project",
        "source_version",
        "technique_id",
        "transformation_visible",
    }
    origin = report.get("origin")
    try:
        parsed = urlsplit(origin) if isinstance(origin, str) else None
        valid_origin = bool(
            parsed
            and parsed.scheme == "http"
            and parsed.hostname == "127.0.0.1"
            and parsed.port
            and parsed.path == ""
            and not parsed.query
            and not parsed.fragment
        )
    except ValueError:
        valid_origin = False
    observed_at = _utc_timestamp(report.get("observed_at"))
    _require(
        (not_before is None) == (not_after is None),
        "the browser observation interval is incomplete",
    )
    if not_before is not None and not_after is not None:
        _require(
            not_before <= observed_at <= not_after,
            "the browser observation falls outside the gate execution interval",
        )
    try:
        browser_envelope = json.loads(
            browser_artifact_payload,
            object_pairs_hook=_object_without_duplicate_keys,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise SourceIntakeBrowserValidationError(
            "the browser-created source-intake artifact is invalid"
        ) from exc
    _require(
        isinstance(browser_envelope, Mapping)
        and browser_artifact_payload == canonical_json_bytes(browser_envelope)
        and browser_envelope == intake,
        "the browser-created intake is detached from the reviewed transformation",
    )
    provenance_reference = (
        f"urn:bluefire:source-intake:{INTAKE_ID}:"
        f"sha256:{str(intake['record_sha256']).removeprefix('sha256:')}"
    )
    try:
        receipt, receipt_sha256, receipt_completed_at = validate_source_intake_operation_receipt(
            browser_receipt_payload,
            destination_id=BROWSER_INTAKE_DESTINATION_ID,
            operator_id="gate-09-browser-reviewer",
            profile_id=profile_id,
            intake=intake,
            package=package,
            activation_operation="already_active_revalidated",
            catalog_generation=catalog_generation,
            catalog_digest=catalog_digest,
            not_before=not_before,
            not_after=not_after,
        )
    except SourceIntakeReceiptValidationError as exc:
        raise SourceIntakeBrowserValidationError(str(exc)) from exc
    _require(
        receipt_completed_at <= observed_at,
        "the browser report predates its durable operation receipt",
    )
    _require(
        set(report) == expected_keys
        and report.get("schema_version") == BROWSER_SCHEMA
        and report.get("production_browser_interaction") is True
        and report.get("demo_mode") is False
        and valid_origin
        and report.get("source_id") == SOURCE_ID
        and report.get("source_project") == "mitre/cti"
        and report.get("source_version") == "19.2"
        and report.get("source_pin") == SOURCE_COMMIT
        and report.get("source_license") == LICENSE_ID
        and report.get("source_classification") == "metadata_import"
        and report.get("source_content_handling") == "vendored_declarative"
        and report.get("imported_paths")
        == [f"bluefire/data/{SOURCE_ASSET}", f"bluefire/data/{LICENSE_ASSET}"]
        and report.get("attribution_visible") is True
        and report.get("transformation_visible") is True
        and report.get("behavior_id") == BEHAVIOR_ID
        and report.get("technique_id") == "T1082"
        and report.get("action_id") == ACTION_ID
        and report.get("activation_operation") == "already_active_revalidated"
        and report.get("behavior_provenance_visible") is True
        and report.get("behavior_provenance_reference") == provenance_reference
        and report.get("execution_state") == "action"
        and report.get("intake_destination_id") == BROWSER_INTAKE_DESTINATION_ID
        and report.get("intake_record_sha256") == intake["record_sha256"]
        and report.get("intake_state_ref")
        == f"source-intakes/{BROWSER_INTAKE_DESTINATION_ID}/{INTAKE_ID}.json"
        and report.get("runner_profile_id") == profile_id
        and report.get("operation_sequence") == list(BROWSER_OPERATION_SEQUENCE)
        and report.get("operation_receipt_visible") is True
        and report.get("operation_receipt_sha256") == receipt_sha256
        and report.get("operation_receipt_state_ref")
        == (f"source-intakes/{BROWSER_INTAKE_DESTINATION_ID}/{INTAKE_ID}.operation-receipt.json")
        and receipt.get("operator_id") == "gate-09-browser-reviewer",
        "the production browser provenance report is invalid",
    )


__all__ = [
    "SourceIntakeBrowserValidationError",
    "validate_source_intake_browser_evidence",
]
