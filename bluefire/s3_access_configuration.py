"""Pure S3 configuration validation shared by setup and authenticated reads."""

from __future__ import annotations

from typing import Any

from . import s3_audit_collection_contract as audit
from . import s3_fixture_contract as fixtures
from .s3_access_contract import S3AccessError, S3AccessScope, digest, document, exact
from .s3_access_policy import plan_hardening

SCHEMA = "bluefire.s3-host-environments.v1"
BOUND_SCHEMA = "bluefire.s3-host-environments.v3"
AUDIT_SCHEMA = "bluefire.s3-host-environments.v4"
_FIELDS = {
    "environment_id",
    "display_name",
    "profile",
    "scope",
    "baseline_policy",
    "exclusive_writer_digest",
    "runtime_root",
    "runtime_digest",
    "worker_generation",
    "ledger_root",
    "credential_reference",
}


def _identifier(value: Any) -> str:
    import re

    if (
        not isinstance(value, str)
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", value) is None
    ):
        raise S3AccessError("configured S3 identity is invalid")
    return value


def _path(value: Any) -> str:
    if (
        not isinstance(value, str)
        or len(value) > 4096
        or not value.startswith("/")
        or "\\" in value
        or "\0" in value
        or any(part in {"", ".", ".."} for part in value.split("/")[1:])
    ):
        raise S3AccessError("configured S3 location is invalid")
    return value


def validate_configuration(
    value: Any, *, runner_id: str, profile_ids: tuple[str, ...]
) -> dict[str, Any]:
    from .runner_contracts import seal_profile

    row = document(value, limit=512 * 1024)
    exact(row, {"schema_version", "runner_id", "environments"}, "S3 host configuration")
    if (
        row["schema_version"]
        not in (SCHEMA, "bluefire.s3-host-environments.v2", BOUND_SCHEMA, AUDIT_SCHEMA)
        or row["runner_id"] != runner_id
    ):
        raise S3AccessError("S3 configuration belongs to another enrolled host")
    entries = row["environments"]
    if not isinstance(entries, list) or not 1 <= len(entries) <= 8:
        raise S3AccessError("S3 environment configuration exceeds its finite scope")
    identifiers: set[str] = set()
    ledgers: set[str] = set()
    buckets: set[tuple[str, str, str]] = set()
    bound = row["schema_version"] in (BOUND_SCHEMA, AUDIT_SCHEMA)
    audit_enabled = row["schema_version"] == AUDIT_SCHEMA
    for entry in entries:
        fixture_keys = (
            {"fixture_lifecycle"}
            if row["schema_version"] == "bluefire.s3-host-environments.v2"
            or (bound and isinstance(entry, dict) and "fixture_lifecycle" in entry)
            else set()
        )
        binding_keys = {"managed_profile_digest"} if bound else set()
        audit_keys = {"audit_source"} if audit_enabled else set()
        exact(
            entry,
            _FIELDS | fixture_keys | binding_keys | audit_keys,
            "configured S3 environment",
        )
        if bound:
            digest(entry["managed_profile_digest"])
        identifier = _identifier(entry["environment_id"])
        if identifier in identifiers:
            raise S3AccessError("S3 configured environments are ambiguous")
        identifiers.add(identifier)
        label = entry["display_name"]
        if not isinstance(label, str) or not 1 <= len(label) <= 100 or not label.isprintable():
            raise S3AccessError("configured S3 display name is invalid")
        scope = S3AccessScope.from_mapping(entry["scope"])
        source = scope.to_dict()
        bucket = (source["account_id"], source["region"], source["bucket"])
        if bucket in buckets:
            raise S3AccessError("One S3 bucket must have one configured journal authority")
        buckets.add(bucket)
        plan_hardening(scope, entry["baseline_policy"])
        digest(entry["exclusive_writer_digest"])
        if fixture_keys:
            descriptor = fixtures.enrollment(scope, entry["fixture_lifecycle"])
            if descriptor["exclusive_writer_digest"] != entry["exclusive_writer_digest"]:
                raise S3AccessError("Fixture enrollment has a different exclusive writer")
        digest(entry["runtime_digest"])
        digest(entry["worker_generation"])
        if audit_enabled:
            descriptor = audit.source(scope, entry["audit_source"])
            if (
                descriptor["managed_profile_digest"] != entry["managed_profile_digest"]
                or descriptor["protected_runtime_digest"] != entry["runtime_digest"]
                or descriptor["worker_generation"] != entry["worker_generation"]
            ):
                raise S3AccessError("Audit source differs from its enrolled profile or runtime")
        _path(entry["runtime_root"])
        ledger = _path(entry["ledger_root"])
        if ledger in ledgers:
            raise S3AccessError("S3 environments must not share a reservation store")
        ledgers.add(ledger)
        if entry["credential_reference"] != f"s3-{identifier}.secret":
            raise S3AccessError("S3 temporary material must use its exact enrollment reference")
        profile = entry["profile"]
        if (
            not isinstance(profile, dict)
            or profile.get("profile_id") not in profile_ids
            or profile.get("runner_id") != runner_id
            or profile.get("platform") != "linux"
            or profile.get("schema_version") != "bluefire.runner-profile.v1"
            or profile.get("policy_digest") != seal_profile(profile).get("policy_digest")
            or not isinstance(profile.get("capabilities"), list)
            or not isinstance(profile.get("allowed_actions"), list)
            or not isinstance(profile.get("control_blocked_actions", []), list)
            or "cloud_aws_s3_access" not in profile["capabilities"]
            or "owned.aws.s3_access.v1" not in profile["allowed_actions"]
            or "owned.aws.s3_access.v1" in profile.get("control_blocked_actions", [])
        ):
            raise S3AccessError("S3 environment lacks its enrolled cloud-capable profile")
    return row
