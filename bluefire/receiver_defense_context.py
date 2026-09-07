"""Saved-graph eligibility for the fixed, real receiver policy comparison."""

from __future__ import annotations

import sys
from typing import Any, Mapping

from .contracts import ScenarioDefinition
from .product_store_errors import ProductStoreError
from .receiver_defense_contract import (
    OWNER_KIND as OWNER_KIND,
)
from .receiver_defense_contract import (
    PHASES as PHASES,
)
from .receiver_defense_contract import (
    PREPARE_KIND as PREPARE_KIND,
)
from .receiver_policy import REDACTED_ONLY_POLICY, REVIEWED_RECORDS_POLICY, ReceiverContentPolicy
from .util import content_hash

POLICIES = (REVIEWED_RECORDS_POLICY, REDACTED_ONLY_POLICY, REVIEWED_RECORDS_POLICY)
LIMITATIONS = [
    "Tests a fixed destination policy on reviewed public synthetic JSONL over literal loopback.",
    "Each phase starts a new single-use receiver and needs a separate fresh Execute approval.",
    "Restored means a fresh reviewed-records receiver accepts the same bytes; it is not a VM or host reset.",
    "A receiver refusal is an independent observation, not a successful transport action or a general defense guarantee.",
    "Missing authenticated terminal evidence or unverified cleanup remains unknown; uncertain effects are never retried.",
    "Runtime AI is Off for this controlled comparison; no model request is made.",
]


def selected(value: Any) -> Mapping[str, Any]:
    if (
        not isinstance(value, Mapping)
        or set(value) != {"kind", "scenario_id", "version", "digest"}
        or value.get("kind") != "saved_scenario"
    ):
        raise ProductStoreError("Select an exact saved scenario version.")
    if (
        not isinstance(value["scenario_id"], str)
        or not 1 <= len(value["scenario_id"]) <= 200
        or type(value["version"]) is not int
        or not 1 <= value["version"] <= 2**31 - 1
        or not isinstance(value["digest"], str)
    ):
        raise ProductStoreError("The saved scenario identity is invalid.")
    return dict(value)


def intent(value: Any) -> Mapping[str, Any]:
    required = {"mode", "autonomy", "ai_provider_id", "runner_profile_id", "target_scope"}
    if (
        not isinstance(value, Mapping)
        or not required <= set(value)
        or set(value) - required - {"collectors", "action_implementations"}
        or value["mode"] not in {"simulate", "execute"}
        or value["autonomy"] != "off"
        or value["ai_provider_id"] is not None
        or (
            value["mode"] == "execute"
            and (
                not isinstance(value["runner_profile_id"], str)
                or not 1 <= len(value["runner_profile_id"]) <= 200
            )
        )
    ):
        raise ProductStoreError(
            "Select native Execute settings with runtime AI Off and no provider."
        )
    return dict(value)


def context(service: Any, request: Mapping[str, Any]) -> Mapping[str, Any]:
    if set(request) != {"selection", "run_intent"}:
        raise ProductStoreError(
            "Receiver context requires only saved selection and native settings."
        )
    selection, run_intent = selected(request["selection"]), intent(request["run_intent"])
    saved = service.scenario_version(selection["scenario_id"], version=selection["version"])[
        "scenario"
    ]
    if saved["digest"] != selection["digest"] or content_hash(saved["document"]) != saved["digest"]:
        raise ProductStoreError("The immutable saved graph digest changed.")
    scenario = ScenarioDefinition.from_mapping(saved["document"])
    catalog = service._action_catalog_boundary()
    catalog.registry.validate_scenario(scenario)
    mode = service._mode(run_intent)
    profile = (
        service._profile(run_intent["runner_profile_id"], mode)
        if run_intent["mode"] == "execute"
        else None
    )
    service._action_implementations(run_intent, mode=mode)
    collectors, runtime = service._collector_configuration(run_intent, mode=mode)
    reasons = []
    if run_intent["mode"] != "execute":
        reasons.append(
            {
                "code": "execute_required",
                "message": "This real receiver comparison requires native Execute. Simulate cannot start a receiver.",
            }
        )
    if not sys.platform.startswith("linux"):
        reasons.append(
            {
                "code": "linux_required",
                "message": "The owned receiver requires the supported isolated Linux environment; it cannot start on this host.",
            }
        )
    for message in service._scope_problems(run_intent, profile, mode):
        reasons.append({"code": "scope_required", "message": str(message)})
    steps = saved["document"]["steps"]
    handoffs = [
        step
        for step in steps
        if step["behavior_id"]
        in {"sandbox.peer.handoff.v1", "sandbox.credential.peer-challenge.v1"}
    ]
    alternate_handoffs = any(
        set(step.get("alternates", []))
        & {"sandbox.peer.handoff.v1", "sandbox.credential.peer-challenge.v1"}
        for step in steps
    )
    handoff = None
    if len(handoffs) == 1 and not alternate_handoffs:
        peer = handoffs[0]
        source = peer.get("inputs", {}).get("bundle", {})
        stage = next((step for step in steps if step["id"] == source.get("from_step")), None)
        if (
            stage is not None
            and stage["behavior_id"] == "sandbox.collection.stage.v1"
            and stage.get("parameters", {}).get("bundle_format", "jsonl") == "jsonl"
            and source.get("artifact") == "bundle"
            and not peer.get("alternates")
            and not stage.get("alternates")
        ):
            handoff = {
                "stage_step_id": stage["id"],
                "handoff_step_id": peer["id"],
                "port": peer.get("parameters", {}).get("port", 4317),
                "artifact_type": "artifact.sandbox.bundle.v1",
                "container": "jsonl",
            }
    if handoff is None:
        reasons.append(
            {
                "code": "receiver_graph_ineligible",
                "message": "Save a graph with exactly one JSONL collection.stage bundle feeding the registered peer handoff.",
            }
        )
    cleanup_ids = {step["id"] for step in steps if step["behavior_id"] == "sandbox.cleanup.v1"}
    if not cleanup_ids:
        reasons.append(
            {
                "code": "cleanup_required",
                "message": "The saved experiment needs its registered workspace cleanup.",
            }
        )
    elif handoff is not None:
        cleanup_outcomes = {
            edge["outcome"]
            for edge in saved["document"]["edges"]
            if edge["from_step"] == handoff["handoff_step_id"] and edge["to_step"] in cleanup_ids
        }
        if not {"success", "partial", "blocked", "failed"} <= cleanup_outcomes:
            reasons.append(
                {
                    "code": "handoff_cleanup_required",
                    "message": "The registered handoff needs explicit cleanup paths for success, partial, blocked and failed outcomes.",
                }
            )
    policies = []
    for policy_id, title, description in (
        (
            REVIEWED_RECORDS_POLICY,
            "Reviewed records",
            "Accept valid reviewed public synthetic records.",
        ),
        (
            REDACTED_ONLY_POLICY,
            "Redacted records only",
            "Refuse valid records unless every record is explicitly redacted.",
        ),
    ):
        policies.append(
            {
                "policy_id": policy_id,
                "title": title,
                "description": description,
                "digest": ReceiverContentPolicy(policy_id).digest,
            }
        )
    document = {
        "schema_version": "bluefire.receiver-defense-context.v1",
        "selection": selection,
        "run_intent": run_intent,
        "scenario": saved["document"],
        "scenario_title": scenario.title,
        "eligible": not reasons,
        "reasons": reasons,
        "handoff": handoff,
        "policies": policies,
        "limitations": LIMITATIONS,
        "catalog_binding": catalog.to_dict(),
        "profile_digest": content_hash(profile.to_dict()) if profile is not None else None,
        "collector_binding": service._collector_binding(collectors, runtime),
    }
    return {**document, "context_digest": content_hash(document)}
