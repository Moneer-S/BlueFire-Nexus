"""Explicit owner-local S3 extension review/publication; no registration or AWS calls."""

from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

from .runner_trust import RunnerEnrollment
from .s3_access_contract import S3AccessError, S3AccessScope, digest, document, exact, timestamp
from .s3_access_extension_contract import MAX_REVISIONS, purpose, reference
from .s3_access_extension_store import S3ExtensionStore
from .s3_access_wire import S3Credentials, aware_now
from .util import canonical_json_bytes, content_hash, json_clone

REVIEW_SCHEMA = "bluefire.s3-extension-review.v1"


def _now():
    return datetime.now(timezone.utc)


def _configuration(store: S3ExtensionStore, value: Any, clock) -> dict:
    from .s3_access_configuration import validate_configuration
    from .s3_access_runtime import validate_runtime

    row = validate_configuration(
        value,
        runner_id=store.enrollment.runner_id,
        profile_ids=store.enrollment.allowed_profile_ids,
    )
    for entry in row["environments"]:
        S3AccessScope.from_mapping(entry["scope"]).assert_current(clock=clock)
        descriptor = entry.get("fixture_lifecycle")
        if descriptor and descriptor["generation_digest"] != store.binding["enrollment_generation"]:
            raise S3AccessError("S3 fixture belongs to another enrollment generation")
        runtime = validate_runtime(Path(entry["runtime_root"]), entry["runtime_digest"])
        if runtime.worker_generation != entry["worker_generation"]:
            raise S3AccessError("S3 protected worker generation changed")
    return row


def review_configuration(enrollment: RunnerEnrollment, value: Any, *, clock=_now) -> dict:
    store = S3ExtensionStore(enrollment)
    row = _configuration(store, value, clock)
    previous = store.read()
    if previous is not None and previous["configuration"] != row:
        raise S3AccessError("Changing retained S3 authority requires a separate history review")
    now = aware_now(clock)
    expires = min(
        now + timedelta(seconds=120),
        *(timestamp(entry["scope"]["expires_at"]) for entry in row["environments"]),
    )
    review = {
        "schema_version": REVIEW_SCHEMA,
        "binding": store.binding,
        "configuration_digest": content_hash(row),
        "expected_revision": content_hash(previous) if previous else None,
        "expires_at": expires.isoformat(),
    }
    return {**review, "review_digest": content_hash(review)}


def apply_configuration(
    enrollment: RunnerEnrollment, value: Any, reviewed: Any, *, clock=_now
) -> dict:
    store = S3ExtensionStore(enrollment)
    row = _configuration(store, value, clock)
    review = document(reviewed, limit=16 * 1024)
    exact(
        review,
        {
            "schema_version",
            "binding",
            "configuration_digest",
            "expected_revision",
            "expires_at",
            "review_digest",
        },
        "S3 extension review",
    )
    unsigned = {key: value for key, value in review.items() if key != "review_digest"}
    remaining = (timestamp(review["expires_at"]) - aware_now(clock)).total_seconds()
    if (
        review["schema_version"] != REVIEW_SCHEMA
        or review["binding"] != store.binding
        or review["configuration_digest"] != content_hash(row)
        or review["review_digest"] != content_hash(unsigned)
        or not 0 < remaining <= 120
    ):
        raise S3AccessError("S3 extension review changed or expired")
    if review["expected_revision"] is not None:
        digest(review["expected_revision"])
    previous = store.read()
    if previous is not None:
        if previous["configuration"] != row:
            raise S3AccessError("Changing retained S3 authority requires a separate history review")
        # Repeating a configuration apply does not create a new revision or any credential.
        return {"status": "already_configured", "revision_digest": content_hash(previous)}
    committed = store.append(
        row, {}, operation="configure", expected_revision=review["expected_revision"]
    )
    return {"status": "configured", "revision_digest": content_hash(committed)}


def import_temporary_material(
    enrollment: RunnerEnrollment,
    environment_id: str,
    payload: bytes,
    *,
    expected_revision: str,
    clock=_now,
) -> dict:
    """Receive already acquired material from the owner, never argv/env or a browser."""
    digest(expected_revision)
    if not isinstance(payload, bytes) or not 0 < len(payload) <= 16 * 1024:
        raise S3AccessError("S3 temporary material input is invalid")
    store = S3ExtensionStore(enrollment)
    previous = store.read()
    if previous is None or content_hash(previous) != expected_revision:
        raise S3AccessError("S3 setup revision changed; review again")
    if previous["sequence"] >= MAX_REVISIONS:
        raise S3AccessError("S3 setup revision allowance is exhausted")
    matches = [
        entry
        for entry in previous["configuration"]["environments"]
        if entry["environment_id"] == environment_id
    ]
    if len(matches) != 1:
        raise S3AccessError("S3 temporary material has no exact environment")
    entry = matches[0]
    scope = S3AccessScope.from_mapping(entry["scope"])
    now = aware_now(clock)
    scope.assert_current(clock=lambda: now)
    raw = document(payload, limit=16 * 1024)
    credentials = S3Credentials.from_mapping(
        raw, clock=lambda: now, deadline=now + timedelta(microseconds=1)
    )
    if credentials.expires_at > timestamp(entry["scope"]["expires_at"]):
        raise S3AccessError("S3 temporary material outlives its scope")
    bound_purpose = purpose(store.binding, entry)
    opaque = store.enrollment.secret_provider.protect(bound_purpose, canonical_json_bytes(raw))
    protected = reference(
        {
            "purpose": bound_purpose,
            "scope_digest": content_hash(entry["scope"]),
            "created_at": now.isoformat(),
            "expires_at": credentials.expires_at.isoformat(),
            "protected_sha256": "sha256:" + hashlib.sha256(opaque).hexdigest(),
            "opaque": base64.b64encode(opaque).decode("ascii"),
        },
        store.binding,
        entry,
    )
    references = {**previous["credentials"], environment_id: protected}
    committed = store.append(
        previous["configuration"],
        references,
        operation="credentials",
        expected_revision=expected_revision,
    )
    return {
        "status": "reference_imported",
        "revision_digest": content_hash(committed),
        "expires_at": protected["expires_at"],
    }


def read_configuration(enrollment: RunnerEnrollment) -> dict | None:
    current = S3ExtensionStore(enrollment).read()
    return json_clone(current["configuration"]) if current else None


def read_temporary_material(
    enrollment: RunnerEnrollment, entry: Mapping[str, Any], request, clock
) -> bytes:
    store = S3ExtensionStore(enrollment)
    current = store.read()
    if current is None:
        raise S3AccessError("S3 temporary material reference is unavailable")
    matches = [item for item in current["configuration"]["environments"] if item == dict(entry)]
    if len(matches) != 1 or request.to_dict()["scope"] != entry["scope"]:
        raise S3AccessError("S3 temporary material authority changed")
    protected = current["credentials"].get(entry["environment_id"])
    if protected is None:
        raise S3AccessError("S3 temporary material reference is unavailable")
    bound = reference(protected, store.binding, entry)
    value = store.enrollment.secret_provider.unprotect(
        bound["purpose"], base64.b64decode(bound["opaque"], validate=True)
    )
    raw = document(value, limit=16 * 1024)
    credentials = S3Credentials.from_mapping(
        raw, clock=clock, deadline=timestamp(request.to_dict()["deadline"])
    )
    if credentials.expires_at != timestamp(bound["expires_at"]):
        raise S3AccessError("S3 temporary material expiry binding changed")
    return canonical_json_bytes(raw)


def inspect_extension(enrollment: RunnerEnrollment, *, clock=_now) -> dict:
    """Local status reads only protected-reference metadata, never AWS material."""
    store = S3ExtensionStore(enrollment)
    current = store.read()
    if current is None:
        return {"status": "not_configured", "revision_digest": None, "references": []}
    now = aware_now(clock)
    rows = []
    for entry in current["configuration"]["environments"]:
        protected = current["credentials"].get(entry["environment_id"])
        rows.append(
            {
                "environment_id": entry["environment_id"],
                "state": (
                    "absent"
                    if protected is None
                    else "current" if timestamp(protected["expires_at"]) > now else "expired"
                ),
                "expires_at": protected["expires_at"] if protected else None,
            }
        )
    return {
        "status": (
            "revision_allowance_exhausted" if current["sequence"] == MAX_REVISIONS else "configured"
        ),
        "revision_digest": content_hash(current),
        "references": rows,
    }
