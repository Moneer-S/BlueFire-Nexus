"""Closed Darwin retained-file objective with metadata-only attempt artifacts."""

from __future__ import annotations

from typing import Any, Mapping

from . import capability_file_access
from .capability_packs import MACOS_FILE_ACCESS_METHODS, MACOS_FILE_ACCESS_PACK
from .capability_resources import CapabilityContractError, digest, exact, integer
from .contracts import StepOutcome
from .util import content_hash, json_clone

ENV_FIELDS = capability_file_access.ENV_FIELDS | {"workspace_custody_digest", "binding_digest"}
FACT_SCHEMA = "bluefire.macos-file-access-composition-facts.v1"
DEPENDENCY_FIELDS = (
    "control_owner_id",
    "control_digest",
    "resource_id",
    "resource_generation",
    "resource_digest",
    "probe_enrollment_digest",
    "baseline_digest",
    "control_revision",
    "workspace_custody_digest",
    "binding_digest",
)


def validate_objective(value: Any) -> dict[str, Any]:
    row = capability_file_access.validate_objective(value)
    if row["predicate"]["record_count"] != 8:
        raise CapabilityContractError("the installed macOS method requires its original records")
    return row


def validate_environment(value: Any) -> dict[str, Any]:
    row = exact(value, ENV_FIELDS, "macOS file-access environment")
    # The descriptive retained-file fields share their bounds, not Linux authority.
    common = capability_file_access.validate_environment(
        {key: row[key] for key in capability_file_access.ENV_FIELDS}
    )
    return {
        **common,
        "workspace_custody_digest": digest(row["workspace_custody_digest"], "original workspace"),
        "binding_digest": digest(row["binding_digest"], "original file binding"),
    }


def graph_details(steps, successors, routes, grant):
    if len(steps) != 3 or sorted(row["behavior_id"] for row in steps.values()) != sorted(
        MACOS_FILE_ACCESS_METHODS
    ):
        raise CapabilityContractError(
            "macOS graph requires one probe, owner read and attempt closure"
        )
    by_method = {row["behavior_id"]: identity for identity, row in steps.items()}
    probe, owner, closure = (by_method[method] for method in MACOS_FILE_ACCESS_METHODS)
    if (
        successors[closure]
        or any(routes.get((probe, outcome.value)) != owner for outcome in StepOutcome)
        or any(routes.get((owner, outcome.value)) != closure for outcome in StepOutcome)
        or steps[probe]["inputs"]
        or steps[owner]["inputs"] != {"probe": {"from_step": probe, "artifact": "probe"}}
        or steps[closure]["inputs"] != {"workspace": {"from_step": probe, "artifact": "workspace"}}
    ):
        raise CapabilityContractError("macOS reads require exact probe lineage and attempt closure")
    return {
        "macos_file_access": {
            "schema_version": "bluefire.macos-file-access-composition-dependency.v1",
            "probe_step_id": probe,
            "owner_step_id": owner,
            "cleanup_step_id": closure,
            **{key: grant["environment"][key] for key in DEPENDENCY_FIELDS},
        }
    }


def initial_proposal():
    probe, owner, closure = "probe", "verify_owner", "close_attempt"
    return {
        "schema_version": "bluefire.composition-proposal.v1",
        "title": "Verify effective access in the original macOS workspace",
        "start": probe,
        "steps": [
            {"id": identity, "behavior_id": method, "parameters": {}}
            for identity, method in zip(
                (probe, owner, closure), MACOS_FILE_ACCESS_METHODS, strict=True
            )
        ],
        "edges": [
            {"from_step": source, "outcome": outcome.value, "to_step": target}
            for source, target in ((probe, owner), (owner, closure))
            for outcome in StepOutcome
        ],
        "evidence_refs": ["control"],
        "rationale": "Compare fresh non-owner and owner reads of the same retained resource without undoing its defense.",
    }


def seal_facts(grant: Mapping[str, Any]) -> dict[str, Any]:
    environment = validate_environment(grant["environment"])
    body = {
        "schema_version": FACT_SCHEMA,
        "pack": MACOS_FILE_ACCESS_PACK,
        "grant_id": grant["grant_id"],
        "environment_digest": content_hash(environment),
        "control_digest": environment["control_digest"],
        "prior_attempt_id": None,
        "prior_graph_digest": None,
        "facts": [
            {
                "fact_id": "control",
                "kind": "retained_macos_file_control",
                "provenance": "observed",
                "source": {
                    "kind": "control_record",
                    "id": environment["control_owner_id"],
                    "digest": environment["control_digest"],
                },
                "observed_at_ms": grant["created_at_ms"],
                "valid_until_ms": grant["expires_at_ms"],
                "environment_digest": content_hash(environment),
                "control_digest": environment["control_digest"],
                "attempt_id": None,
                "value": {key: environment[key] for key in DEPENDENCY_FIELDS},
            }
        ],
    }
    return {**body, "facts_digest": content_hash(body)}


def validate_facts(
    value: Any,
    *,
    expected_digest: str,
    grant: Mapping[str, Any],
    now_ms: int,
    require_prior_result: bool,
) -> dict[str, Any]:
    digest(expected_digest, "trusted macOS facts digest")
    integer(now_ms, grant["created_at_ms"], grant["expires_at_ms"] - 1, "fact observation time")
    if type(require_prior_result) is not bool or require_prior_result:
        raise CapabilityContractError("the fixed macOS pack has no different permitted route")
    expected = seal_facts(grant)
    if value != expected or expected["facts_digest"] != expected_digest:
        raise CapabilityContractError("macOS facts changed from the current retained control")
    return dict(json_clone(expected))


def objective_result(grant: Mapping[str, Any], result: Any) -> dict[str, Any]:
    objective = validate_objective(grant["objective"])
    environment = validate_environment(grant["environment"])
    row = exact(
        result,
        {
            "probe_verified",
            "non_owner_decision",
            "owner_verified",
            "owner_decision",
            "resource_digest",
            "resource_generation",
            "control_revision",
            "binding_digest",
            "sha256",
            "record_count",
            "request_closure",
            "attempt_artifacts",
            "workers_retained",
            "whole_enrollment_cleanup",
        },
        "macOS file-access objective result",
    )
    for key in ("probe_verified", "owner_verified", "workers_retained", "whole_enrollment_cleanup"):
        if type(row[key]) is not bool:
            raise CapabilityContractError("macOS observation flag is invalid")
    if row["non_owner_decision"] not in ("allowed", "denied", "unknown") or row[
        "owner_decision"
    ] not in ("allowed", "denied", "unknown"):
        raise CapabilityContractError("macOS read decision is invalid")
    integer(row["record_count"], 0, 8, "observed record count")
    checks = {
        "probe_authenticated": row["probe_verified"],
        "non_owner_denied": row["non_owner_decision"] == "denied",
        "owner_read_verified": row["owner_verified"] and row["owner_decision"] == "allowed",
        "same_resource": row["resource_digest"] == environment["resource_digest"]
        and row["resource_generation"] == environment["resource_generation"],
        "same_control_revision": row["control_revision"] == environment["control_revision"],
        "same_original_binding": row["binding_digest"] == environment["binding_digest"],
        "content_preserved": row["sha256"] == objective["predicate"]["sha256"]
        and row["record_count"] == objective["predicate"]["record_count"],
        "requests_closed": row["request_closure"] == "verified_closed",
        "no_attempt_artifacts": row["attempt_artifacts"] == "not_created",
        "enrollment_retained": row["workers_retained"] and not row["whole_enrollment_cleanup"],
    }
    return {"established": all(checks.values()), "checks": checks}
