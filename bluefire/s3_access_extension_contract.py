"""Finite records for the separately stored, enrollment-bound S3 extension."""

from __future__ import annotations

import base64
import hashlib
from typing import Any, Mapping

from .s3_access_contract import S3AccessError, S3AccessScope, digest, document, exact, timestamp
from .util import content_hash

SCHEMA = "bluefire.s3-extension-revision.v1"
MAX_REVISIONS = 32
MAX_BYTES = 1024 * 1024


def purpose(binding: Mapping[str, Any], environment: Mapping[str, Any]) -> str:
    return ":".join(
        (
            "bluefire.s3-temporary.v1",
            binding["enrollment_generation"],
            environment["environment_id"],
            content_hash(environment["scope"]),
        )
    )


def reference(value: Any, binding: Mapping[str, Any], environment: Mapping[str, Any]) -> dict:
    row = document(value, limit=32 * 1024)
    exact(
        row,
        {"purpose", "scope_digest", "created_at", "expires_at", "protected_sha256", "opaque"},
        "S3 protected reference",
    )
    if (
        row["purpose"] != purpose(binding, environment)
        or row["scope_digest"] != content_hash(environment["scope"])
        or not isinstance(row["opaque"], str)
        or len(row["opaque"]) > 24 * 1024
    ):
        raise S3AccessError("S3 protected reference binding is invalid")
    try:
        opaque = base64.b64decode(row["opaque"], validate=True)
    except (ValueError, TypeError):
        raise S3AccessError("S3 protected reference is invalid") from None
    if (
        not 1 <= len(opaque) <= 16 * 1024
        or base64.b64encode(opaque).decode("ascii") != row["opaque"]
        or row["protected_sha256"] != "sha256:" + hashlib.sha256(opaque).hexdigest()
    ):
        raise S3AccessError("S3 protected reference identity is invalid")
    created, expires = timestamp(row["created_at"]), timestamp(row["expires_at"])
    if not 0 < (expires - created).total_seconds() <= 900 or expires > timestamp(
        environment["scope"]["expires_at"]
    ):
        raise S3AccessError("S3 protected reference lifetime is invalid")
    return row


def revision(
    value: Any,
    *,
    binding: Mapping[str, Any],
    sequence: int,
    previous: Mapping[str, Any] | None,
) -> dict:
    row = document(value, limit=MAX_BYTES)
    exact(
        row,
        {
            "schema_version",
            "sequence",
            "operation",
            "previous_digest",
            "binding",
            "configuration",
            "credentials",
            "authentication",
        },
        "S3 extension revision",
    )
    if (
        row["schema_version"] != SCHEMA
        or type(row["sequence"]) is not int
        or row["sequence"] != sequence
        or not 1 <= sequence <= MAX_REVISIONS
        or row["binding"] != dict(binding)
        or row["previous_digest"] != (content_hash(previous) if previous else None)
    ):
        raise S3AccessError("S3 extension revision binding changed")
    digest(row["authentication"])
    credentials = row["credentials"]
    configuration = row["configuration"]
    if not isinstance(credentials, dict) or not isinstance(configuration, dict):
        raise S3AccessError("S3 extension document is invalid")
    environments = configuration.get("environments")
    if not isinstance(environments, list) or not 1 <= len(environments) <= 8:
        raise S3AccessError("S3 extension environments are invalid")
    known = {}
    for environment in environments:
        if not isinstance(environment, dict):
            raise S3AccessError("S3 extension environment is invalid")
        identifier = environment.get("environment_id")
        if not isinstance(identifier, str) or identifier in known:
            raise S3AccessError("S3 extension environment is ambiguous")
        S3AccessScope.from_mapping(environment.get("scope"))
        known[identifier] = environment
    if set(credentials) - set(known):
        raise S3AccessError("S3 protected reference has no enrolled environment")
    for identifier, value in credentials.items():
        reference(value, binding, known[identifier])
    if previous is None:
        if row["operation"] != "configure" or credentials:
            raise S3AccessError("S3 extension must begin with configuration only")
    elif (
        row["operation"] != "credentials"
        or configuration != previous["configuration"]
        or set(previous["credentials"]) - set(credentials)
        or sum(previous["credentials"].get(key) != value for key, value in credentials.items()) != 1
    ):
        raise S3AccessError("S3 extension revision changes authority or multiple references")
    return row
