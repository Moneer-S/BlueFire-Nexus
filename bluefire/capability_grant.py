"""Pure immutable capability review documents, never execution bearer authority."""

from __future__ import annotations

import re
from typing import Any, Mapping

from .capability_resources import (
    METHODS,
    PACK,
    CapabilityContractError,
    exact,
    integer,
    method_cost,
    semantic_ports,
    validate_limits,
)
from .contracts import ExecutionState
from .receiver_policy import REDACTED_ONLY_POLICY, ReceiverContentPolicy
from .registry import BehaviorRegistry
from .util import canonical_json_bytes, content_hash, json_clone

SCHEMA = "bluefire.capability-grant.v1"
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
_ENV_FIELDS = {
    "environment_id",
    "environment_generation",
    "runner_id",
    "enrollment_digest",
    "profile_digest",
    "target_scope_digest",
    "collector_digest",
    "control_owner_id",
    "control_digest",
    "policy_id",
    "policy_digest",
    "port",
}
_GRANT_FIELDS = {
    "schema_version",
    "grant_id",
    "approved_by",
    "created_at_ms",
    "expires_at_ms",
    "objective",
    "environment",
    "limits",
    "snapshot",
    "grant_digest",
}


def digest(value: Any, context: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise CapabilityContractError(f"{context} must be a SHA-256 digest")
    return value


def identifier(value: Any, context: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise CapabilityContractError(f"{context} is invalid")
    return value


def authority_id(value: Any, kind: str) -> str:
    if (
        kind not in ("grant", "attempt")
        or not isinstance(value, str)
        or re.fullmatch(kind + r"-[0-9a-f]{32}", value) is None
    ):
        raise CapabilityContractError(f"{kind} ID is invalid")
    return value


def text(value: Any, context: str, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= maximum
        or not value.strip()
        or any(ord(char) < 32 and char not in "\n\t" for char in value)
    ):
        raise CapabilityContractError(f"{context} is invalid")
    return value


def validate_objective(value: Any) -> dict[str, Any]:
    row = exact(value, {"question", "predicate"}, "objective")
    predicate = exact(
        row["predicate"], {"kind", "record_count", "data_class"}, "objective predicate"
    )
    if (
        predicate["kind"] != "redacted_delivery_preserves_records"
        or predicate["data_class"] != "generated_public_jsonl"
    ):
        raise CapabilityContractError("objective predicate is unsupported")
    integer(predicate["record_count"], 1, 100, "objective record count")
    text(row["question"], "objective question", 4000)
    return dict(json_clone(row))


def validate_environment(value: Any) -> dict[str, Any]:
    row = exact(value, _ENV_FIELDS, "composition environment")
    for key in _ENV_FIELDS - {"port"}:
        (digest if key.endswith("_digest") else identifier)(row[key], key)
    integer(row["port"], 1024, 65535, "receiver port")
    if (
        row["policy_id"] != REDACTED_ONLY_POLICY
        or row["policy_digest"] != ReceiverContentPolicy(REDACTED_ONLY_POLICY).digest
    ):
        raise CapabilityContractError("composition requires the retained redacted-only policy")
    return dict(json_clone(row))


def build_snapshot(
    registry: BehaviorRegistry,
    implementation_digests: Mapping[str, str],
    objective: Mapping[str, Any],
    environment: Mapping[str, Any],
) -> dict[str, Any]:
    objective, environment = validate_objective(objective), validate_environment(environment)
    exact(implementation_digests, set(METHODS), "installed implementation snapshot")
    domains = {
        METHODS[0]: {"record_count": [objective["predicate"]["record_count"]]},
        METHODS[1]: {"redact_values": [False, True]},
        METHODS[2]: {},
        METHODS[3]: {},
        METHODS[4]: {"bundle_format": ["jsonl"]},
        METHODS[5]: {"port": [environment["port"]]},
        METHODS[6]: {"verify_removal": [True]},
    }
    methods = []
    for method_id in METHODS:
        behavior, action = registry.get_behavior(method_id), registry.get_action(method_id)
        if (
            behavior.execution_state is not ExecutionState.ACTION
            or method_id not in behavior.action_ids
            or "linux" not in behavior.platforms
            or "linux" not in action.platforms
        ):
            raise CapabilityContractError("installed method does not support the reviewed pack")
        actual_ports = (
            tuple((port.name, port.type, port.multiple, port.required) for port in behavior.inputs),
            tuple((port.name, port.type, port.multiple) for port in behavior.outputs),
        )
        if actual_ports != semantic_ports(method_id):
            raise CapabilityContractError("installed method semantic contract changed")
        # Domains are resolved here, never inferred from model text or arbitrary inputs.
        if {spec.name for spec in behavior.parameters} != set(domains[method_id]):
            raise CapabilityContractError("installed method parameters changed")
        for name, values in domains[method_id].items():
            for value in values:
                behavior.validate_parameters({name: value})
        methods.append(
            {
                "behavior_id": method_id,
                "action_id": method_id,
                "behavior": behavior.to_dict(),
                "action": action.to_dict(),
                "implementation_digest": digest(
                    implementation_digests[method_id], "implementation"
                ),
                "parameter_domains": domains[method_id],
                "cost": method_cost(method_id),
            }
        )
    body = {
        "schema_version": "bluefire.capability-snapshot.v1",
        "pack": PACK,
        "platform": "linux",
        "methods": methods,
        "artifact_context": {
            "environment_digest": content_hash(environment),
            "materialization": "fresh_attempt",
            "data_class": objective["predicate"]["data_class"],
        },
    }
    return {**body, "snapshot_digest": content_hash(body)}


def create_grant(
    *,
    registry: BehaviorRegistry,
    implementation_digests: Mapping[str, str],
    objective: Mapping[str, Any],
    environment: Mapping[str, Any],
    limits: Mapping[str, Any],
    grant_id: str,
    approved_by: str,
    created_at_ms: int,
    expires_at_ms: int,
) -> dict[str, Any]:
    authority_id(grant_id, "grant")
    text(approved_by, "grant actor", 128)
    integer(created_at_ms, 1, 2**63 - 1, "grant creation")
    integer(expires_at_ms, created_at_ms + 1, created_at_ms + 900_000, "grant expiry")
    objective, environment = validate_objective(objective), validate_environment(environment)
    body = {
        "schema_version": SCHEMA,
        "grant_id": grant_id,
        "approved_by": approved_by,
        "created_at_ms": created_at_ms,
        "expires_at_ms": expires_at_ms,
        "objective": objective,
        "environment": environment,
        "limits": validate_limits(limits),
        "snapshot": build_snapshot(registry, implementation_digests, objective, environment),
    }
    return {**body, "grant_digest": content_hash(body)}


def validate_grant(
    value: Any,
    *,
    expected_digest: str,
    registry: BehaviorRegistry,
    implementation_digests: Mapping[str, str],
    current_environment: Mapping[str, Any],
    now_ms: int,
) -> dict[str, Any]:
    """The expected digest must come from the trusted durable grant record."""
    row = exact(value, _GRANT_FIELDS, "capability grant")
    digest(expected_digest, "trusted grant digest")
    integer(now_ms, 1, 2**63 - 1, "current time")
    if row["schema_version"] != SCHEMA:
        raise CapabilityContractError("capability grant version is unsupported")
    expected = create_grant(
        registry=registry,
        implementation_digests=implementation_digests,
        **{
            key: row[key]
            for key in (
                "objective",
                "environment",
                "limits",
                "grant_id",
                "approved_by",
                "created_at_ms",
                "expires_at_ms",
            )
        },
    )
    if (
        expected["grant_digest"] != expected_digest
        or canonical_json_bytes(row) != canonical_json_bytes(expected)
        or validate_environment(current_environment) != expected["environment"]
    ):
        raise CapabilityContractError("grant, installed capability or environment changed")
    if not row["created_at_ms"] <= now_ms < row["expires_at_ms"]:
        raise CapabilityContractError("capability grant is not current")
    return dict(json_clone(expected))


def objective_result(grant: Mapping[str, Any], result: Any) -> dict[str, Any]:
    """Evaluate only independently verified terminal facts supplied by the caller."""
    objective = validate_objective(grant["objective"])
    row = exact(
        result,
        {
            "receiver_verified",
            "policy_digest",
            "data_class",
            "record_count",
            "redacted_record_count",
            "retained_record_count",
            "empty_record_count",
            "decision",
            "run_cleanup",
            "receiver_cleanup",
        },
        "composition objective result",
    )
    for key in (
        "record_count",
        "redacted_record_count",
        "retained_record_count",
        "empty_record_count",
    ):
        integer(row[key], 0, 100, key)
    if type(row["receiver_verified"]) is not bool:
        raise CapabilityContractError("receiver verification flag is invalid")
    count = objective["predicate"]["record_count"]
    checks = {
        "receiver_verified": row["receiver_verified"],
        "policy_unchanged": row["policy_digest"] == grant["environment"]["policy_digest"],
        "data_class_preserved": row["data_class"] == objective["predicate"]["data_class"],
        "record_count_preserved": row["record_count"] == count,
        "all_records_redacted": row["redacted_record_count"] == count
        and row["retained_record_count"] == row["empty_record_count"] == 0,
        "accepted": row["decision"] == "accepted",
        "run_cleaned": row["run_cleanup"] == "complete",
        "receiver_closed": row["receiver_cleanup"] == "verified_closed",
    }
    return {"established": all(checks.values()), "checks": checks}
