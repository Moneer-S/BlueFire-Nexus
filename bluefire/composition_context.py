"""Server-owned receiver objective context; clients never supply effect authority."""

from __future__ import annotations

from typing import Any

from .capability_grant import build_snapshot, validate_objective
from .capability_resources import METHODS, MIB, validate_limits
from .contracts import ExecutionMode
from .product_store_errors import ProductStoreError
from .receiver_defense_workflow import retained
from .util import content_hash

DEFAULT_LIMITS = {
    "max_attempts": 3,
    "max_nodes_per_attempt": 16,
    "max_edges_per_attempt": 64,
    "max_business_steps": 24,
    "max_generated_bytes": 10 * MIB,
    "max_network_bytes": 3 * MIB,
    "max_peak_workspace_bytes": 4 * MIB,
    "max_workspace_files": 8,
    "max_retained_metadata_bytes": 8 * MIB,
    "max_reserved_attempt_ms": 270_000,
    "per_attempt_wall_ms": 90_000,
    "cleanup_reserve_ms": 10_000,
}


def resolve(service, owner_id: str) -> dict[str, Any]:
    """Read live authority through existing catalog, receiver and runner boundaries."""
    owner = service.receiver_defense._job(owner_id)
    current = service.receiver_defense._fresh(owner)
    if (
        not retained(current)
        or current.get("source_control")
        or owner["progress"].get("receiver_completed") is not True
        or owner["progress"].get("control_rollback")
    ):
        raise ProductStoreError("Composition needs the original completed retained control.")
    baseline = service.receiver_defense.baseline(owner)
    if baseline is None:
        raise ProductStoreError("The independently verified original baseline is unavailable.")
    run_intent = current["run_intent"]
    profile = service._profile(run_intent["runner_profile_id"], ExecutionMode.EXECUTE)
    if profile is None:
        raise ProductStoreError("Composition requires its enrolled Execute profile.")
    runner, sandbox, readiness = service._execute_readiness_boundary(profile, for_dispatch=True)
    raw_runner = getattr(runner, "runner", runner)
    identity_probe = getattr(raw_runner, "transport_identity", None)
    if not callable(getattr(raw_runner, "execute_task", None)) or not callable(identity_probe):
        raise ProductStoreError("Composition requires authenticated single-task transport.")
    transport = identity_probe()
    if (
        transport.get("schema_version") != "bluefire.runner-transport-identity.v1"
        or transport.get("transport") != "mutual-tls-loopback"
        or transport.get("tls") != "TLSv1.3"
        or not isinstance(transport.get("enrollment_generation"), str)
        or readiness["platform"] != "linux"
    ):
        raise ProductStoreError("The authenticated Linux runner enrollment is unavailable.")
    catalog = service._catalog_snapshot
    native = {row["action_id"]: row for row in readiness["enabled_actions"]}
    implementation_digests = {}
    for method in METHODS:
        if method not in native or native[method].get("readiness") != "ready":
            raise ProductStoreError("The enrolled profile lacks a required composition method.")
        implementation_digests[method] = content_hash(
            {
                "native": native[method],
                "binding": catalog.action_bindings.get((method, method)),
                "catalog": catalog.to_dict(),
                "runner_binary_digest": transport.get("runner_binary_digest"),
            }
        )
    collector_ids, collector_runtime = service._collector_configuration(
        run_intent, mode=ExecutionMode.EXECUTE
    )
    control = current["control"]
    environment = {
        "environment_id": "environment-" + readiness["sandbox"]["root_digest"][7:],
        "environment_generation": "generation-"
        + content_hash(
            {
                "sandbox": readiness["sandbox"],
                "enrollment_generation": transport["enrollment_generation"],
                "runner_identity": readiness["runner_identity_digest"],
            }
        )[7:],
        "runner_id": transport["runner_id"],
        "enrollment_digest": content_hash(transport),
        "profile_digest": content_hash(profile.to_dict()),
        "target_scope_digest": content_hash(run_intent["target_scope"]),
        "collector_digest": content_hash(
            service._collector_binding(collector_ids, collector_runtime)
        ),
        "control_owner_id": owner_id,
        "control_digest": control["control_digest"],
        "policy_id": control["policy_id"],
        "policy_digest": control["policy_digest"],
        "port": current["handoff"]["port"],
    }
    count = baseline["receiver_observation"]["terminal"]["decision"]["semantics"]["record_count"]
    return {
        "owner": owner,
        "source_context": current,
        "baseline": baseline,
        "record_count": count,
        "registry": catalog.registry,
        "implementation_digests": implementation_digests,
        "current_environment": environment,
        "run_intent": run_intent,
        "profile": profile,
        "runner": runner,
        "sandbox": sandbox,
        "runner_readiness": readiness,
        "collector_ids": collector_ids,
        "collector_runtime": collector_runtime,
    }


def review(service, owner_id, *, question, limits=None):
    current = resolve(service, owner_id)
    objective = validate_objective(
        {
            "question": question,
            "predicate": {
                "kind": "redacted_delivery_preserves_records",
                "record_count": current["record_count"],
                "data_class": "generated_public_jsonl",
            },
        }
    )
    environment = current["current_environment"]
    body = {
        "schema_version": "bluefire.composition-review.v1",
        "objective": objective,
        "environment": environment,
        "limits": validate_limits(DEFAULT_LIMITS if limits is None else limits),
        "snapshot": build_snapshot(
            current["registry"], current["implementation_digests"], objective, environment
        ),
        "baseline_source": current["baseline"]["source_binding"],
        "limitations": [
            "Delegates fresh graphs within these installed capabilities, not an exact human-approved itinerary.",
            "Each attempt regenerates public synthetic records and retains the reviewed receiver policy.",
            "Generated material and network allowances are conservative complete-attempt reservations.",
            "Workspace byte and file allowances count generated data artifacts, not native receipt or control metadata.",
            "Retained metadata bytes are an admission estimate, not an enforced total-storage quota.",
            "Runtime AI requests require a separate provider/data/usage authorization.",
        ],
    }
    return {**body, "review_digest": content_hash(body)}
