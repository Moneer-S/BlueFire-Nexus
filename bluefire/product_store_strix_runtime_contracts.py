"""Strict document contracts for private v20 Strix runtime persistence.

The tables in this module are controller-only.  They are deliberately absent
from generic resources, HTTP routes, exports, and presentation projections.
They retain authority and custody provenance; they never allocate a runtime,
resolve an opaque location, acquire credentials, or launch work.
"""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Mapping
from contextlib import AbstractContextManager
from typing import Any, Protocol, cast

from .product_store_contracts import safe_document
from .product_store_errors import ProductStoreError
from .product_store_serialization import canonical_json
from .strix_adapter import StrixAdapterError, StrixBudgets, StrixBuildIdentity, StrixRuntimeLimits
from .util import content_hash, parse_iso8601_datetime

AUTHORITY_EVENT_SCHEMA = "bluefire.strix-runtime-authority-event.v1"
ADMISSION_RESERVATION_SCHEMA = "bluefire.strix-runtime-admission-reservation.v1"
ADMISSION_EVENT_SCHEMA = "bluefire.strix-runtime-admission-event.v1"
ADMISSION_RECORD_SCHEMA = "bluefire.strix-runtime-admission-record.v1"
MAX_AUTHORITY_EVENTS = 4096
MAX_ADMISSION_EVENTS = 4096
MAX_DOCUMENT_BYTES = 256 * 1024

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_ATTEMPT = re.compile(r"^engine-attempt-[0-9a-f]{32}$")
_EXPERIMENT = re.compile(r"^experiment-[0-9a-f]{32}$")
_REVISION = re.compile(r"^[0-9a-f]{40}$")
_ARTIFACT_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{31,127}$")
_AUTHORITY_STATES = {"active", "revoked"}
_ADMISSION_STATES = {"reserved", "preparing", "verified", "unknown", "revoked", "cleaned"}
_ADMISSION_TRANSITIONS = {
    "reserved": {"preparing", "revoked", "cleaned"},
    "preparing": {"verified", "unknown", "revoked"},
    "verified": {"unknown", "revoked", "cleaned"},
    "unknown": {"verified", "revoked", "cleaned"},
    "revoked": {"cleaned"},
    "cleaned": set(),
}
_AUTHORITY_FIELDS = {
    "schema_version",
    "generation",
    "state",
    "qualification_manifest_ref",
    "protected_artifact_key",
    "installed_bluefire_revision",
    "strix_build_digest",
    "threat_review_ref",
    "recorded_at",
    "revocation_reason",
}
_RESERVATION_FIELDS = {
    "schema_version",
    "attempt_id",
    "experiment_id",
    "experiment_revision",
    "experiment_digest",
    "binding_digest",
    "delegation_digest",
    "objective_ref",
    "environment_ref",
    "authority_ref",
    "authority_generation",
    "authority_record_digest",
    "qualification_ref",
    "target_snapshot_digest",
    "request_digest",
    "created_at",
    "expires_at",
}
_ADMISSION_FIELDS = {
    "schema_version",
    "attempt_id",
    "experiment_id",
    "experiment_revision",
    "experiment_digest",
    "binding_digest",
    "delegation_digest",
    "objective_ref",
    "environment_ref",
    "authority_ref",
    "authority_generation",
    "authority_record_digest",
    "qualification_ref",
    "target_snapshot_digest",
    "build",
    "build_digest",
    "model_id",
    "scope_record_ref",
    "scope_record_digest",
    "gateway_record_ref",
    "gateway_record_digest",
    "budgets",
    "limits",
    "network_plan_ref",
    "network_plan_digest",
    "network_snapshot_ref",
    "network_snapshot_digest",
    "network_verification_ref",
    "network_verification_digest",
    "custody_plan_ref",
    "custody_plan_digest",
    "protected_roots_ref",
    "protected_roots_digest",
    "containment_ref",
    "containment_digest",
    "runtime_install_ref",
    "runtime_install_digest",
    "workspace_ref",
    "workspace_digest",
    "executable_ref",
    "executable_digest",
    "path_environment_ref",
    "path_environment_digest",
    "control_root_ref",
    "control_root_digest",
    "artifact_root_ref",
    "artifact_root_digest",
    "custody_source_ref",
    "custody_record_ref",
    "custody_record_digest",
    "admission_proof_bundle_digest",
    "created_at",
    "expires_at",
}
_ADMISSION_DIGEST_FIELDS = {
    name
    for name in _ADMISSION_FIELDS
    if name.endswith(("_ref", "_digest"))
    and name
    not in {
        "authority_ref",
        "runtime_install_ref",
        "workspace_ref",
        "executable_ref",
        "path_environment_ref",
        "control_root_ref",
        "artifact_root_ref",
        "custody_source_ref",
        "custody_record_ref",
    }
}
_OPAQUE_DIGEST_FIELDS = {
    "authority_ref",
    "runtime_install_ref",
    "workspace_ref",
    "executable_ref",
    "path_environment_ref",
    "control_root_ref",
    "artifact_root_ref",
    "custody_source_ref",
    "custody_record_ref",
}


class StrixRuntimeStore(Protocol):
    def _connection(self, *, write: bool = False) -> AbstractContextManager[sqlite3.Connection]: ...


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ProductStoreError(f"{label} must be an exact lowercase sha256 digest")
    return value


def _positive_int(value: Any, label: str, *, maximum: int = 2**63 - 1) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        raise ProductStoreError(f"{label} is invalid")
    return value


def _timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise ProductStoreError(f"{label} is invalid")
    try:
        parsed = parse_iso8601_datetime(value)
    except (TypeError, ValueError, RecursionError) as exc:
        raise ProductStoreError(f"{label} is invalid") from exc
    if parsed.isoformat().replace("+00:00", "Z") != value:
        raise ProductStoreError(f"{label} must use canonical UTC text")
    return value


def _bounded_document(value: Mapping[str, Any], *, context: str) -> dict[str, Any]:
    try:
        cloned = safe_document(value, context=context)
    except ProductStoreError:
        raise
    except (TypeError, ValueError, RecursionError) as exc:
        raise ProductStoreError(f"{context} is invalid") from exc
    if not isinstance(cloned, dict):
        raise ProductStoreError(f"{context} must be an object")
    try:
        encoded = canonical_json(cloned)
    except (TypeError, ValueError, RecursionError) as exc:
        raise ProductStoreError(f"{context} is invalid") from exc
    if not 1 <= len(encoded.encode("utf-8")) <= MAX_DOCUMENT_BYTES:
        raise ProductStoreError(f"{context} exceeds its byte bound")
    return cloned


def _authority(value: Mapping[str, Any]) -> dict[str, Any]:
    row = _bounded_document(value, context="Strix runtime authority")
    if set(row) != _AUTHORITY_FIELDS:
        raise ProductStoreError("Strix runtime authority fields are invalid")
    generation = _positive_int(
        row["generation"], "Strix authority generation", maximum=MAX_AUTHORITY_EVENTS
    )
    state = row["state"]
    if (
        row["schema_version"] != "bluefire.strix-runtime-authority.v1"
        or state not in _AUTHORITY_STATES
    ):
        raise ProductStoreError("Strix runtime authority contract is invalid")
    for name in ("qualification_manifest_ref", "strix_build_digest", "threat_review_ref"):
        _digest(row[name], f"Strix authority {name}")
    if (
        not isinstance(row["protected_artifact_key"], str)
        or _ARTIFACT_KEY.fullmatch(row["protected_artifact_key"]) is None
    ):
        raise ProductStoreError("Strix authority artifact key is invalid")
    if (
        not isinstance(row["installed_bluefire_revision"], str)
        or _REVISION.fullmatch(row["installed_bluefire_revision"]) is None
    ):
        raise ProductStoreError("Strix authority BlueFire revision is invalid")
    _timestamp(row["recorded_at"], "Strix authority timestamp")
    reason = row["revocation_reason"]
    if state == "active":
        if reason is not None:
            raise ProductStoreError("active Strix authority cannot have a revocation reason")
    elif (
        not isinstance(reason, str)
        or not reason
        or len(reason) > 200
        or any(ord(char) < 32 or ord(char) == 127 for char in reason)
    ):
        raise ProductStoreError("revoked Strix authority reason is invalid")
    row["generation"] = generation
    return row


def _authority_event_document(
    *,
    authority_ref: str,
    authority: Mapping[str, Any],
    authority_basis_ref: str,
    previous_event_digest: str | None,
) -> dict[str, Any]:
    checked = _authority(authority)
    return {
        "schema_version": AUTHORITY_EVENT_SCHEMA,
        "authority_ref": _digest(authority_ref, "Strix authority ref"),
        "authority": checked,
        "authority_record_digest": content_hash(checked),
        "authority_basis_ref": _digest(authority_basis_ref, "Strix authority basis"),
        "previous_event_digest": (
            None
            if previous_event_digest is None
            else _digest(previous_event_digest, "previous Strix authority event")
        ),
    }


def _reservation(value: Mapping[str, Any]) -> dict[str, Any]:
    row = _bounded_document(value, context="Strix admission reservation")
    if set(row) != _RESERVATION_FIELDS or row["schema_version"] != ADMISSION_RESERVATION_SCHEMA:
        raise ProductStoreError("Strix admission reservation fields are invalid")
    if not isinstance(row["attempt_id"], str) or _ATTEMPT.fullmatch(row["attempt_id"]) is None:
        raise ProductStoreError("Strix admission attempt is invalid")
    if (
        not isinstance(row["experiment_id"], str)
        or _EXPERIMENT.fullmatch(row["experiment_id"]) is None
    ):
        raise ProductStoreError("Strix admission experiment is invalid")
    _positive_int(row["experiment_revision"], "Strix experiment revision", maximum=10000)
    for name in (
        "experiment_digest",
        "binding_digest",
        "delegation_digest",
        "authority_ref",
        "authority_record_digest",
        "qualification_ref",
        "target_snapshot_digest",
        "request_digest",
    ):
        _digest(row[name], f"Strix reservation {name}")
    _positive_int(
        row["authority_generation"],
        "Strix admitted authority generation",
        maximum=MAX_AUTHORITY_EVENTS,
    )
    for name in ("objective_ref", "environment_ref"):
        if (
            not isinstance(row[name], str)
            or not row[name]
            or len(row[name]) > 256
            or any(ord(char) < 32 or ord(char) == 127 for char in row[name])
        ):
            raise ProductStoreError(f"Strix reservation {name} is invalid")
    created = _timestamp(row["created_at"], "Strix reservation creation time")
    expires = _timestamp(row["expires_at"], "Strix reservation expiry")
    if parse_iso8601_datetime(expires) <= parse_iso8601_datetime(created):
        raise ProductStoreError("Strix admission reservation expiry is not after creation")
    return row


def _admission(value: Mapping[str, Any]) -> dict[str, Any]:
    row = _bounded_document(value, context="Strix verified admission")
    if set(row) != _ADMISSION_FIELDS or row["schema_version"] != ADMISSION_RECORD_SCHEMA:
        raise ProductStoreError("Strix verified admission fields are invalid")
    if not isinstance(row["attempt_id"], str) or _ATTEMPT.fullmatch(row["attempt_id"]) is None:
        raise ProductStoreError("Strix admission attempt is invalid")
    if (
        not isinstance(row["experiment_id"], str)
        or _EXPERIMENT.fullmatch(row["experiment_id"]) is None
    ):
        raise ProductStoreError("Strix admission experiment is invalid")
    _positive_int(row["experiment_revision"], "Strix experiment revision", maximum=10000)
    _positive_int(
        row["authority_generation"],
        "Strix admitted authority generation",
        maximum=MAX_AUTHORITY_EVENTS,
    )
    for name in (
        _ADMISSION_DIGEST_FIELDS
        | _OPAQUE_DIGEST_FIELDS
        | {
            "experiment_digest",
            "binding_digest",
            "delegation_digest",
        }
    ):
        _digest(row[name], f"Strix admission {name}")
    for name in ("objective_ref", "environment_ref", "model_id"):
        if (
            not isinstance(row[name], str)
            or not row[name]
            or len(row[name]) > 256
            or any(ord(char) < 32 or ord(char) == 127 for char in row[name])
        ):
            raise ProductStoreError(f"Strix admission {name} is invalid")
    build = row["build"]
    if not isinstance(build, dict) or build.get("engine") != "strix":
        raise ProductStoreError("Strix admission build identity is invalid")
    try:
        checked_build = StrixBuildIdentity(
            **{name: item for name, item in build.items() if name != "engine"}
        )
        checked_budgets = StrixBudgets(**cast(dict[str, Any], row["budgets"]))
        checked_limits = StrixRuntimeLimits(**cast(dict[str, Any], row["limits"]))
    except (StrixAdapterError, TypeError, ValueError) as exc:
        raise ProductStoreError("Strix admission runtime bounds are invalid") from exc
    if checked_build.to_dict() != build or content_hash(build) != row["build_digest"]:
        raise ProductStoreError("Strix admission build digest changed")
    if {
        name: getattr(checked_budgets, name) for name in checked_budgets.__dataclass_fields__
    } != row["budgets"]:
        raise ProductStoreError("Strix admission budgets are not canonical")
    if {name: getattr(checked_limits, name) for name in checked_limits.__dataclass_fields__} != row[
        "limits"
    ]:
        raise ProductStoreError("Strix admission limits are not canonical")
    created = _timestamp(row["created_at"], "Strix admission creation time")
    expires = _timestamp(row["expires_at"], "Strix admission expiry")
    if parse_iso8601_datetime(expires) <= parse_iso8601_datetime(created):
        raise ProductStoreError("Strix admission expiry is not after creation")
    return row


def _event_document(
    *,
    attempt_id: str,
    sequence: int,
    state: str,
    lifecycle_basis_ref: str,
    recorded_at: str,
    previous_event_digest: str | None,
    admission_record_ref: str | None,
) -> dict[str, Any]:
    if not isinstance(attempt_id, str) or _ATTEMPT.fullmatch(attempt_id) is None:
        raise ProductStoreError("Strix admission event attempt is invalid")
    _positive_int(sequence, "Strix admission event sequence", maximum=MAX_ADMISSION_EVENTS)
    if state not in _ADMISSION_STATES:
        raise ProductStoreError("Strix admission lifecycle state is invalid")
    _digest(lifecycle_basis_ref, "Strix admission lifecycle basis")
    _timestamp(recorded_at, "Strix admission lifecycle time")
    if previous_event_digest is not None:
        _digest(previous_event_digest, "previous Strix admission event")
    if admission_record_ref is not None:
        _digest(admission_record_ref, "Strix admission record ref")
    return {
        "schema_version": ADMISSION_EVENT_SCHEMA,
        "attempt_id": attempt_id,
        "sequence": sequence,
        "state": state,
        "lifecycle_basis_ref": lifecycle_basis_ref,
        "recorded_at": recorded_at,
        "previous_event_digest": previous_event_digest,
        "admission_record_ref": admission_record_ref,
    }
