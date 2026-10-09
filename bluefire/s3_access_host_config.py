"""Read-only S3 environments explicitly bound to an existing host enrollment.

No API route writes this configuration or discovers ambient AWS credentials.
Temporary material is an OS-protected enrollment reference and is never part of
the public environment projection, request, durable job, or runner manifest.
One bucket has one local journal authority. Exclusive ownership across other
hosts/controllers remains an enrollment premise, not a distributed lock.
"""

from __future__ import annotations

import os
import stat
import sys
from typing import Any, Mapping, cast

from .s3_access_contract import S3AccessError, S3AccessScope, digest, document, exact
from .s3_access_policy import plan_hardening
from .s3_access_wire import S3Credentials, S3WorkerRequest, timestamp
from .util import canonical_json_bytes, content_hash, json_clone

SCHEMA = "bluefire.s3-host-environments.v1"
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
    if row["schema_version"] != SCHEMA or row["runner_id"] != runner_id:
        raise S3AccessError("S3 configuration belongs to another enrolled host")
    entries = row["environments"]
    if not isinstance(entries, list) or not 1 <= len(entries) <= 8:
        raise S3AccessError("S3 environment configuration exceeds its finite scope")
    identifiers: set[str] = set()
    ledgers: set[str] = set()
    buckets: set[tuple[str, str, str]] = set()
    for entry in entries:
        exact(entry, _FIELDS, "configured S3 environment")
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
        digest(entry["runtime_digest"])
        digest(entry["worker_generation"])
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


def read_configuration(enrollment: Any) -> dict[str, Any] | None:
    getuid, geteuid = (getattr(os, name, None) for name in ("getuid", "geteuid"))
    nofollow, nonblock = (getattr(os, name, None) for name in ("O_NOFOLLOW", "O_NONBLOCK"))
    if (
        not sys.platform.startswith("linux")
        or not callable(getuid)
        or not callable(geteuid)
        or getuid() <= 0
        or getuid() != geteuid()
        or type(nofollow) is not int
        or type(nonblock) is not int
    ):
        raise S3AccessError("S3 configuration requires its owned Linux host")
    path = enrollment.root / "s3-access.json"
    try:
        descriptor = os.open(path, os.O_RDONLY | nofollow | nonblock)
    except FileNotFoundError:
        return None
    try:
        details = os.fstat(descriptor)
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_uid != getuid()
            or stat.S_IMODE(details.st_mode) != 0o600
            or details.st_nlink != 1
            or not 0 < details.st_size <= 512 * 1024
        ):
            raise S3AccessError("S3 configured environment identity is unavailable")
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            payload = source.read(512 * 1024 + 1)
        after = os.fstat(descriptor)
        named = path.lstat()

        def identity(item):
            return (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)

        if identity(details) != identity(after) or identity(details) != identity(named):
            raise S3AccessError("S3 configured environment changed during inspection")
        return validate_configuration(
            payload,
            runner_id=enrollment.runner_id,
            profile_ids=tuple(enrollment.allowed_profile_ids),
        )
    finally:
        os.close(descriptor)


def public_environments(configuration: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    if configuration is None:
        return []
    return cast(
        list[dict[str, Any]],
        json_clone(
            [
                {
                    name: entry[name]
                    for name in (
                        "environment_id",
                        "display_name",
                        "scope",
                        "baseline_policy",
                        "exclusive_writer_digest",
                    )
                }
                for entry in configuration["environments"]
            ]
        ),
    )


def selected_environment(
    configuration: Mapping[str, Any],
    request: S3WorkerRequest,
    approval: Mapping[str, Any],
    profile: Mapping[str, Any],
) -> dict[str, Any]:
    source = request.to_dict()
    matches = [
        entry
        for entry in configuration["environments"]
        if entry["environment_id"] == approval.get("environment_id")
    ]
    if len(matches) != 1:
        raise S3AccessError("S3 request has no exact enrolled environment")
    entry = matches[0]
    if (
        source["scope"] != entry["scope"]
        or dict(profile) != entry["profile"]
        or source["runtime_digest"] != entry["runtime_digest"]
        or source["worker_generation"] != entry["worker_generation"]
        or (
            source["operation"] in {"apply_policy", "rollback_policy"}
            and source["exclusive_writer_digest"] != entry["exclusive_writer_digest"]
        )
    ):
        raise S3AccessError("S3 request differs from its exact enrolled authority")
    return dict(entry)


def temporary_material(
    enrollment: Any, entry: Mapping[str, Any], request: S3WorkerRequest, clock
) -> bytes:
    reference = entry["credential_reference"]
    expected = f"s3-{_identifier(entry['environment_id'])}.secret"
    if reference != expected:
        raise S3AccessError("S3 temporary material reference is invalid")
    # Existing purpose-bound OS protection; no ambient AWS provider or plaintext file.
    value = document(
        enrollment._secret(reference, f"s3-temporary:{entry['environment_id']}"), limit=16 * 1024
    )
    S3Credentials.from_mapping(
        value, clock=clock, deadline=timestamp(request.to_dict()["deadline"])
    )
    return canonical_json_bytes(value)


def configuration_identity(configuration: Mapping[str, Any]) -> str:
    return content_hash(configuration)
