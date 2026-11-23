"""Server-owned receiver objective context; clients never supply effect authority."""

from __future__ import annotations

from typing import Any, Mapping

from .capability_grant import build_snapshot, validate_objective
from .capability_packs import (
    FILE_ACCESS_PACK,
    MACOS_FILE_ACCESS_PACK,
    RECEIVER_PACK,
    RECEIVER_RETAINED_PACK,
)
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


def resolve(service, owner_id: str, *, pack: str = RECEIVER_PACK) -> dict[str, Any]:
    """Read live authority through existing catalog, receiver and runner boundaries."""
    if pack == MACOS_FILE_ACCESS_PACK:
        from . import macos_file_access_context

        return macos_file_access_context.composition(service, owner_id, service.file_access.clock())
    if pack == FILE_ACCESS_PACK:
        context: dict[str, Any] = service.file_access.composition_context(owner_id)
        return context
    if pack not in (RECEIVER_PACK, RECEIVER_RETAINED_PACK):
        raise ProductStoreError("The composition pack is unavailable.")
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
    from .retained_artifact_contract import METHOD

    methods = (*METHODS, METHOD) if pack == RECEIVER_RETAINED_PACK else METHODS
    for method in methods:
        if method not in native or native[method].get("readiness") != "ready":
            if pack == RECEIVER_RETAINED_PACK and method == METHOD:
                raise ProductStoreError(
                    "The enrolled profile lacks the ready retained-result materialization method."
                )
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


def review(service, owner_id, *, question, limits=None, pack=RECEIVER_PACK):
    current = resolve(service, owner_id, pack=pack)
    file_access = pack in {FILE_ACCESS_PACK, MACOS_FILE_ACCESS_PACK}
    objective = validate_objective(
        {
            "question": question,
            "predicate": {
                "kind": (
                    "non_owner_denied_owner_preserves_records"
                    if file_access
                    else "redacted_delivery_preserves_records"
                ),
                "record_count": current["record_count"],
                "data_class": "generated_public_jsonl",
                **({"sha256": current["resource_sha256"]} if file_access else {}),
            },
        },
        pack=pack,
    )
    environment = current["current_environment"]
    body = {
        "schema_version": (
            "bluefire.composition-review.v2"
            if file_access or pack == RECEIVER_RETAINED_PACK
            else "bluefire.composition-review.v1"
        ),
        **({"pack": pack} if file_access or pack == RECEIVER_RETAINED_PACK else {}),
        "objective": objective,
        "environment": environment,
        "limits": validate_limits(DEFAULT_LIMITS if limits is None else limits),
        "snapshot": build_snapshot(
            current["registry"],
            current["implementation_digests"],
            objective,
            environment,
            pack=pack,
        ),
        "baseline_source": (
            {
                "kind": "original_creator_control",
                "control_owner_id": owner_id,
                "control_digest": environment["control_digest"],
                "baseline_digest": environment["baseline_digest"],
            }
            if pack == MACOS_FILE_ACCESS_PACK
            else current["baseline"]["source_binding"]
        ),
        "limitations": (
            [
                "Delegates only the original non-owner read, owner verification and attempt-request closure.",
                "Read evidence is original-producer metadata, not independent telemetry.",
                "The empty attempt workspace is verified separately; no native filesystem cleanup receipts are created.",
                "The original resource, workers and namespace remain retained. Attempt closure is not whole-enrollment cleanup.",
                "No creation, hardening, rollback, reset, arbitrary identity, path or network operation is delegated.",
                "The fixed pack has one permitted graph; changed control requires a new review. Unknown requests cannot be replayed.",
                "Retained metadata bytes are an admission estimate, not an enforced total-storage quota.",
                "Runtime AI requests require a separate provider/data/usage authorization.",
            ]
            if pack == MACOS_FILE_ACCESS_PACK
            else (
                [
                    "Delegates only the enrolled non-owner fresh read, owner verification and attempt-artifact cleanup.",
                    "The exact generated resource remains under its separately reviewed retained control.",
                    "No retained creation, hardening, rollback, reset, arbitrary identity, path or network operation is delegated.",
                    "The fixed pack has one useful permitted graph; a changed control requires a new review.",
                    "Retained metadata bytes are an admission estimate, not an enforced total-storage quota.",
                    "Runtime AI requests require a separate provider/data/usage authorization.",
                ]
                if file_access
                else [
                    "Delegates fresh graphs within these installed capabilities, not an exact human-approved itinerary.",
                    "Each attempt regenerates public synthetic records and retains the reviewed receiver policy.",
                    "Generated material and network allowances are conservative complete-attempt reservations.",
                    "Workspace byte and file allowances count generated data artifacts, not native receipt or control metadata.",
                    "Retained metadata bytes are an admission estimate, not an enforced total-storage quota.",
                    "Runtime AI requests require a separate provider/data/usage authorization.",
                ]
            )
        ),
    }
    if pack == RECEIVER_RETAINED_PACK:
        from .retained_artifact_contract import METHOD, POLICY
        from .util import json_clone

        body["retention"] = json_clone(POLICY)
        body["native_materialization"] = {
            "method": METHOD,
            "readiness": "ready",
            "implementation_digest": current["implementation_digests"][METHOD],
        }
        body["limitations"] = [
            "Delegates fresh graphs within the reviewed same-objective and exact-environment lineage.",
            "At most one generated public JSONL staging output of at most 256 KiB is sealed per attempt until its run bundle is deleted.",
            "Workspace cleanup removes owned workspace artifacts; it does not delete the sealed run-bundle output.",
            "Materialization also retains payload copies in the existing task and transport stores until those stores are deleted; two copies are included in the reservation.",
            "Later-produced sources are validated when selected and again before dispatch; source summaries contain no payload bytes.",
            "Materialization writes exact retained JSONL to the fixed reviewed fixture input with a fresh workspace receipt; existing transform, discovery and staging must produce the handoff bundle.",
            "Historical findings remain reasoning context and do not authorize source reuse or establish current receiver acceptance.",
            "No source availability or successful receiver delivery is promised by this review.",
            "The retained-storage allowance is an admission reservation, not an enforced total-storage quota.",
            "Runtime AI requests require a separate provider/data/usage authorization for retained-result proposals.",
        ]
    return {**body, "review_digest": content_hash(body)}


RETAINED_CONTEXT_SCHEMA = "bluefire.retained-composition-proposal-context.v1"


def retained_proposal_context(
    jobs, grant: Mapping[str, Any], body: dict[str, Any], *, owner_id: str
) -> dict[str, Any]:
    """Expose validated sealed custody metadata separately from current execution facts."""
    from .retained_artifact_contract import POLICY
    from .retained_artifacts import available_sources
    from .util import json_clone

    if grant.get("pack") != RECEIVER_RETAINED_PACK:
        return body
    sources = available_sources(jobs, grant, owner_id=owner_id)
    return {
        **body,
        "schema_version": RETAINED_CONTEXT_SCHEMA,
        "retained_artifacts": {
            "policy": json_clone(POLICY),
            "available_sources": sources,
            "availability": "available" if sources else "none_available",
        },
    }


def receiver_facts(jobs, grant, prior_attempt_id=None, *, owner_id=None) -> dict[str, Any]:
    """Project current policy and verified prior receiver history without dispatch."""
    from datetime import datetime

    from . import retained_artifacts
    from .capability_facts import seal_facts
    from .capability_packs import grant_pack

    environment = grant["environment"]

    def fact(identity, kind, source, value, observed=None):
        return {
            "fact_id": identity,
            "kind": kind,
            "provenance": "observed",
            "source": source,
            "observed_at_ms": grant["created_at_ms"] if observed is None else observed,
            "valid_until_ms": grant["expires_at_ms"],
            "environment_digest": content_hash(environment),
            "control_digest": environment["control_digest"],
            "attempt_id": None if kind == "retained_policy" else prior_attempt_id,
            "value": value,
        }

    rows = [
        fact(
            "policy",
            "retained_policy",
            {
                "kind": "control_record",
                "id": environment["control_owner_id"],
                "digest": environment["control_digest"],
            },
            {"status": "retained", "policy_digest": environment["policy_digest"]},
        )
    ]
    prior_graph = None
    if prior_attempt_id is not None:
        attempt = jobs.store.get_capability_attempt(prior_attempt_id)
        prior_job = jobs.store.get_job(attempt["lease"]["job_id"])
        marker = prior_job["request"].get("composition_attempt", {})
        prior_owner = jobs._owner(marker.get("parent_job_id"))
        if (
            attempt["lease"]["grant_id"] != grant["grant_id"]
            or attempt["lease"]["grant_digest"] != grant["grant_digest"]
            or prior_job["kind"] != "composition.attempt"
            or marker.get("attempt_id") != prior_attempt_id
            or prior_owner["request"]["grant_id"] != grant["grant_id"]
            or prior_owner["request"]["grant_digest"] != grant["grant_digest"]
            or (
                grant_pack(grant) == retained_artifacts.PACK
                and marker.get("parent_job_id") != owner_id
            )
        ):
            raise ProductStoreError("Prior evidence belongs to another delegated objective.")
        if attempt["state"] != "settled":
            raise ProductStoreError("Prior owned effects must settle before a revision.")
        if grant_pack(grant) == retained_artifacts.PACK:
            retained_artifacts.historical_sources(jobs, grant, owner_id=owner_id)
            # Preserve a verified receiver decision whenever one exists.
            # An absent terminal is not evidence of a policy refusal.
            if retained_artifacts.receiver_terminal_absent(prior_job):
                result = retained_artifacts.prior_failure(
                    jobs, grant, attempt, prior_job, owner_id=owner_id
                )
            else:
                result = jobs._verified_result(attempt)
        else:
            result = jobs._verified_result(attempt)
        source = {
            "kind": "run_evidence",
            "id": result["run_id"],
            "digest": content_hash(result["source_binding"]),
        }
        finalized = result["source_binding"]["finalized_at"]
        observed = int(datetime.fromisoformat(finalized.replace("Z", "+00:00")).timestamp() * 1000)
        result_kind = (
            "retained_artifact_result"
            if "retained_artifact_result" in result
            else "receiver_result"
        )
        rows += [
            fact("result", result_kind, source, result[result_kind], observed),
            fact("cleanup", "cleanup", source, result["cleanup"], observed),
        ]
        prior_graph = attempt["compiled"]["semantic_digest"]
    return seal_facts(
        {
            "schema_version": "bluefire.composition-facts.v1",
            "environment_digest": content_hash(environment),
            "control_digest": environment["control_digest"],
            "prior_attempt_id": prior_attempt_id,
            "prior_graph_digest": prior_graph,
            "facts": rows,
        }
    )
