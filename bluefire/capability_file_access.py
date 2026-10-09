"""The fixed Linux retained-file objective, facts and graph boundary."""

from __future__ import annotations

from typing import Any, Mapping

from .capability_packs import FILE_ACCESS_METHODS, FILE_ACCESS_PACK
from .capability_resources import CapabilityContractError, digest, exact, identifier, integer, text
from .contracts import StepOutcome
from .util import content_hash, json_clone

ENV_FIELDS = {
    "environment_id",
    "environment_generation",
    "runner_id",
    "enrollment_digest",
    "profile_digest",
    "target_scope_digest",
    "collector_digest",
    "control_owner_id",
    "control_digest",
    "resource_id",
    "resource_generation",
    "resource_digest",
    "probe_enrollment_digest",
    "baseline_digest",
    "control_revision",
    "mode",
}
PREDICATE = "non_owner_denied_owner_preserves_records"
FACT_SCHEMA = "bluefire.file-access-composition-facts.v1"


def validate_objective(value: Any) -> dict[str, Any]:
    row = exact(value, {"question", "predicate"}, "file-access objective")
    predicate = exact(
        row["predicate"], {"kind", "record_count", "data_class", "sha256"}, "file-access predicate"
    )
    if predicate["kind"] != PREDICATE or predicate["data_class"] != "generated_public_jsonl":
        raise CapabilityContractError("file-access objective predicate is unsupported")
    integer(predicate["record_count"], 1, 100, "original record count")
    digest(predicate["sha256"], "original content digest")
    text(row["question"], "objective question", 4000)
    return dict(json_clone(row))


def validate_environment(value: Any) -> dict[str, Any]:
    row = exact(value, ENV_FIELDS, "file-access environment")
    for key in ENV_FIELDS - {"control_revision", "mode"}:
        (digest if key.endswith("_digest") else identifier)(row[key], key)
    integer(row["control_revision"], 1, 2**31 - 1, "retained control revision")
    if row["mode"] != "0600":
        raise CapabilityContractError("file-access delegation requires the retained hardened mode")
    return dict(json_clone(row))


def graph_details(steps, successors, routes, grant):
    if len(steps) != 3 or sorted(row["behavior_id"] for row in steps.values()) != sorted(
        FILE_ACCESS_METHODS
    ):
        raise CapabilityContractError(
            "file-access graph requires exactly one probe, owner verification and cleanup"
        )
    by_method = {row["behavior_id"]: key for key, row in steps.items()}
    probe, owner, cleanup = (by_method[key] for key in FILE_ACCESS_METHODS)
    if (
        successors[cleanup]
        or any(routes.get((probe, outcome.value)) != owner for outcome in StepOutcome)
        or any(routes.get((owner, outcome.value)) != cleanup for outcome in StepOutcome)
        or steps[owner]["inputs"].get("probe") != {"from_step": probe, "artifact": "probe"}
        or steps[cleanup]["inputs"].get("workspace")
        != {"from_step": probe, "artifact": "workspace"}
    ):
        raise CapabilityContractError(
            "every file-access outcome must verify the owner then clean attempt artifacts"
        )
    return {
        "file_access": {
            "schema_version": "bluefire.file-access-composition-dependency.v1",
            "probe_step_id": probe,
            "owner_step_id": owner,
            **{
                key: grant["environment"][key]
                for key in (
                    "control_owner_id",
                    "control_digest",
                    "resource_id",
                    "resource_generation",
                    "resource_digest",
                    "probe_enrollment_digest",
                    "baseline_digest",
                    "control_revision",
                )
            },
        }
    }


def initial_proposal():
    probe, owner, cleanup = "probe", "verify_owner", "cleanup"
    return {
        "schema_version": "bluefire.composition-proposal.v1",
        "title": "Verify effective access to the retained generated file",
        "start": probe,
        "steps": [
            {"id": identity, "behavior_id": method, "parameters": parameters}
            for identity, method, parameters in (
                (probe, FILE_ACCESS_METHODS[0], {}),
                (owner, FILE_ACCESS_METHODS[1], {}),
                (cleanup, FILE_ACCESS_METHODS[2], {"verify_removal": True}),
            )
        ],
        "edges": [
            {"from_step": source, "outcome": outcome.value, "to_step": target}
            for source, target in ((probe, owner), (owner, cleanup))
            for outcome in StepOutcome
        ],
        "evidence_refs": ["control"],
        "rationale": "Freshly test the enrolled non-owner and owner against the same retained resource generation.",
    }


def seal_facts(grant: Mapping[str, Any]) -> dict[str, Any]:
    environment = grant["environment"]
    body = {
        "schema_version": FACT_SCHEMA,
        "pack": FILE_ACCESS_PACK,
        "grant_id": grant["grant_id"],
        "environment_digest": content_hash(environment),
        "control_digest": environment["control_digest"],
        "prior_attempt_id": None,
        "prior_graph_digest": None,
        "facts": [
            {
                "fact_id": "control",
                "kind": "retained_file_control",
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
                "value": {
                    key: environment[key]
                    for key in (
                        "resource_id",
                        "resource_generation",
                        "resource_digest",
                        "probe_enrollment_digest",
                        "baseline_digest",
                        "control_revision",
                        "mode",
                    )
                },
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
    digest(expected_digest, "trusted file-access facts digest")
    integer(now_ms, grant["created_at_ms"], grant["expires_at_ms"] - 1, "fact observation time")
    if type(require_prior_result) is not bool:
        raise CapabilityContractError("fact admission kind is invalid")
    if require_prior_result:
        raise CapabilityContractError(
            "The fixed file-access pack has no different permitted route; review the retained control explicitly."
        )
    expected = seal_facts(grant)
    if value != expected or expected["facts_digest"] != expected_digest:
        raise CapabilityContractError(
            "file-access facts are not the exact current retained control"
        )
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
            "probe_enrollment_digest",
            "mode",
            "sha256",
            "record_count",
            "identity_unchanged",
            "parents_unchanged",
            "acl_unchanged",
            "run_cleanup",
            "request_cleanup",
        },
        "file-access objective result",
    )
    for key in (
        "probe_verified",
        "owner_verified",
        "identity_unchanged",
        "parents_unchanged",
        "acl_unchanged",
    ):
        if type(row[key]) is not bool:
            raise CapabilityContractError("file-access observation flag is invalid")
    if row["non_owner_decision"] not in ("allowed", "permission_denied", "unknown") or row[
        "owner_decision"
    ] not in ("allowed", "unknown"):
        raise CapabilityContractError("file-access observation decision is invalid")
    integer(row["record_count"], 0, 100, "observed record count")
    checks = {
        "probe_authenticated": row["probe_verified"],
        "non_owner_denied": row["non_owner_decision"] == "permission_denied",
        "owner_read_verified": row["owner_verified"] and row["owner_decision"] == "allowed",
        "same_resource": row["resource_digest"] == environment["resource_digest"]
        and row["resource_generation"] == environment["resource_generation"],
        "same_control_revision": row["control_revision"] == environment["control_revision"]
        and row["mode"] == environment["mode"],
        "same_probe_enrollment": row["probe_enrollment_digest"]
        == environment["probe_enrollment_digest"],
        "content_preserved": row["sha256"] == objective["predicate"]["sha256"]
        and row["record_count"] == objective["predicate"]["record_count"],
        "identity_unchanged": row["identity_unchanged"],
        "parents_unchanged": row["parents_unchanged"],
        "acl_unchanged": row["acl_unchanged"],
        "run_cleaned": row["run_cleanup"] == "complete",
        "request_closed": row["request_cleanup"] == "verified_closed",
    }
    return {"established": all(checks.values()), "checks": checks}
