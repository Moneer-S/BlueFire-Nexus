"""Read-only S3 environments explicitly bound to an existing host enrollment.

No API route writes this configuration or discovers ambient AWS credentials.
Temporary material is an OS-protected enrollment reference and is never part of
the public environment projection, request, durable job, or runner manifest.
One bucket has one local journal authority. Exclusive ownership across other
hosts/controllers remains an enrollment premise, not a distributed lock.
"""

from __future__ import annotations

import os
import sys
from typing import Any, Mapping, cast

from . import s3_audit_collection_contract as audit
from . import s3_fixture_contract as fixtures
from .s3_access_configuration import AUDIT_SCHEMA, BOUND_SCHEMA, _identifier
from .s3_access_configuration import SCHEMA as SCHEMA
from .s3_access_configuration import validate_configuration as validate_configuration
from .s3_access_contract import S3AccessError, S3AccessScope
from .s3_access_wire import S3WorkerRequest
from .util import content_hash, json_clone


def require_owned_host() -> None:
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


def read_configuration(enrollment: Any) -> dict[str, Any] | None:
    require_owned_host()
    from .s3_access_setup import read_configuration as read_extension

    return read_extension(enrollment)


def public_environments(configuration: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    if configuration is None:
        return []
    return cast(
        list[dict[str, Any]],
        json_clone(
            [
                {
                    **{
                        name: entry[name]
                        for name in (
                            "environment_id",
                            "display_name",
                            "scope",
                            "baseline_policy",
                            "exclusive_writer_digest",
                        )
                    },
                    **(
                        {"fixture_lifecycle": entry["fixture_lifecycle"]}
                        if "fixture_lifecycle" in entry
                        else {}
                    ),
                    **({"audit_source": entry["audit_source"]} if "audit_source" in entry else {}),
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
    if source["schema_version"] == fixtures.REQUEST_SCHEMA:
        if (
            configuration["schema_version"]
            not in ("bluefire.s3-host-environments.v2", BOUND_SCHEMA, AUDIT_SCHEMA)
            or "fixture_lifecycle" not in entry
            or source["fixture_authority_digest"]
            != fixtures.authority_digest(
                S3AccessScope.from_mapping(source["scope"]), entry["fixture_lifecycle"]
            )
        ):
            raise S3AccessError("Fixture operations require their exact new enrolled generation")
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
    audited = configuration["schema_version"] == AUDIT_SCHEMA
    if audited != (approval.get("schema_version") == audit.APPROVAL_SCHEMA):
        raise S3AccessError("Audit approval requires its exact new enrolled configuration")
    if source["operation"] == "collect_audit" and not audited:
        raise S3AccessError("Audit collection requires its exact new enrolled configuration")
    if audited:
        scope = S3AccessScope.from_mapping(source["scope"])
        descriptor = audit.source(scope, entry.get("audit_source"))
        if (
            descriptor["managed_profile_digest"] != entry.get("managed_profile_digest")
            or descriptor["protected_runtime_digest"] != entry["runtime_digest"]
            or descriptor["worker_generation"] != entry["worker_generation"]
        ):
            raise S3AccessError("Audit source differs from its enrolled profile or runtime")
        commitment = audit.build_workflow(
            scope,
            descriptor,
            workflow_job_id=approval["workflow_job_id"],
            environment_id=entry["environment_id"],
        )
        if approval.get("audit_workflow_digest") != content_hash(commitment):
            raise S3AccessError("Audit approval differs from its exact enrolled commitment")
        if source["operation"] == "collect_audit" and (
            source["audit"]["source"] != descriptor
            or source["audit"]["workflow_job_id"] != commitment["workflow_job_id"]
        ):
            raise S3AccessError("Audit collection differs from its exact enrolled commitment")
    return dict(entry)


def temporary_material(
    enrollment: Any, entry: Mapping[str, Any], request: S3WorkerRequest, clock
) -> bytes:
    reference = entry["credential_reference"]
    expected = f"s3-{_identifier(entry['environment_id'])}.secret"
    if reference != expected:
        raise S3AccessError("S3 temporary material reference is invalid")
    from .s3_access_setup import read_temporary_material

    return read_temporary_material(enrollment, entry, request, clock)


def configuration_identity(configuration: Mapping[str, Any]) -> str:
    return content_hash(configuration)
