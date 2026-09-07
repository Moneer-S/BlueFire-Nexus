"""Authoritative immutable saved-graph and operator-selected run policy context."""

from __future__ import annotations

import re
from typing import Any, Mapping

from .assistance_run_protocol import AssistanceRunService
from .contracts import ScenarioDefinition
from .product_store_errors import ProductStoreError
from .util import content_hash

CAPABILITY = "run.saved_graph_and_inspect"
KIND = "run.assistance.prepare"
INSPECT_KIND = "run.evidence.inspect"
LIMITATIONS = [
    "Runs only the exact accepted saved graph with the operator-selected run settings.",
    "Assist requires native preparation review. Auto may submit that frozen policy; Execute always requires a separate fresh native approval.",
    "Inspection describes retained evidence and cleanup. Simulated, missing or unobserved results do not establish real execution or deployed defense effectiveness.",
    "Recovery may retry evidence inspection against the same run, never repeat an uncertain execution.",
]


def selection(value: Any) -> Mapping[str, Any]:
    if (
        not isinstance(value, Mapping)
        or set(value) != {"kind", "proposal_job_id", "application", "run_intent"}
        or value["kind"] != "saved_graph"
    ):
        raise ProductStoreError("Select an exact accepted graph and explicit native run settings.")
    if not isinstance(value["proposal_job_id"], str) or not re.fullmatch(
        r"job-[0-9a-f]{32}", value["proposal_job_id"]
    ):
        raise ProductStoreError("The selected graph proposal identity is invalid.")
    if not isinstance(value["application"], Mapping):
        raise ProductStoreError("The selected graph has no exact application receipt.")
    intent = value["run_intent"]
    required = {"mode", "autonomy", "ai_provider_id", "runner_profile_id", "target_scope"}
    if (
        not isinstance(intent, Mapping)
        or not required <= set(intent)
        or set(intent) - required - {"collectors", "action_implementations"}
    ):
        raise ProductStoreError("Native run settings contain unsupported or missing fields.")
    if intent["mode"] not in {"simulate", "execute"} or intent["autonomy"] not in {
        "off",
        "assist",
        "auto",
    }:
        raise ProductStoreError("Select an explicit run mode and runtime autonomy.")
    for key in ("ai_provider_id", "runner_profile_id"):
        if intent[key] is not None and (
            not isinstance(intent[key], str) or not 1 <= len(intent[key]) <= 200
        ):
            raise ProductStoreError("Select canonical runtime provider and profile identities.")
    scope = intent["target_scope"]
    if (
        not isinstance(scope, Mapping)
        or set(scope) != {"scope_refs"}
        or not isinstance(scope["scope_refs"], list)
        or not 1 <= len(scope["scope_refs"]) <= 32
        or any(
            not isinstance(item, str) or not 1 <= len(item) <= 200 for item in scope["scope_refs"]
        )
    ):
        raise ProductStoreError("Select bounded explicit run scope references.")
    if intent["autonomy"] != "off" and not intent["ai_provider_id"]:
        raise ProductStoreError("Runtime AI requires its own explicitly selected provider.")
    if intent["mode"] == "execute" and not intent["runner_profile_id"]:
        raise ProductStoreError("Execute requires its explicitly selected runner profile.")
    if "collectors" in intent and (
        not isinstance(intent["collectors"], list)
        or len(intent["collectors"]) > 16
        or any(
            not isinstance(item, str) or not 1 <= len(item) <= 200 for item in intent["collectors"]
        )
    ):
        raise ProductStoreError("Collector selections are invalid.")
    if "action_implementations" in intent and (
        not isinstance(intent["action_implementations"], Mapping)
        or len(intent["action_implementations"]) > 8
        or any(
            not isinstance(key, str)
            or not isinstance(item, str)
            or not 1 <= len(key) <= 200
            or not 1 <= len(item) <= 200
            for key, item in intent["action_implementations"].items()
        )
    ):
        raise ProductStoreError("Registered action selections are invalid.")
    return dict(value)


def context(service: AssistanceRunService, value: Any) -> Mapping[str, Any]:
    selected = selection(value)
    native = service.graph_ai_job(selected["proposal_job_id"])
    if native["application"] is None or native["application"] != selected["application"]:
        raise ProductStoreError(
            "The graph application differs from the selected immutable receipt."
        )
    application = native["application"]
    saved = service.scenario_version(application["scenario_id"], version=application["version"])[
        "scenario"
    ]
    scenario = ScenarioDefinition.from_mapping(saved["document"])
    catalog = service._action_catalog_boundary()
    catalog.registry.validate_scenario(scenario)
    intent = selected["run_intent"]
    mode = service._mode(intent)
    profile = service._profile(intent["runner_profile_id"], mode)
    # Static definitions, not volatile runner probes, participate in context identity.
    provider_binding = (
        None
        if intent["autonomy"] == "off"
        else service._runtime_ai().provider(intent["ai_provider_id"]).to_dict()
    )
    if provider_binding is not None and provider_binding.get("kind") == "deterministic":
        raise ProductStoreError("Runtime AI requires an explicit model provider.")
    document = {
        "schema_version": "bluefire.assistance-context.v1",
        "selected": selected,
        "reference_summary": {
            "title": scenario.title,
            "purpose": scenario.purpose[:500],
            "behavior_ids": sorted({step.behavior_id for step in scenario.steps}),
            "run_mode": intent["mode"],
        },
        "catalog_binding": {
            "generation": catalog.generation,
            "catalog_digest": catalog.catalog_digest,
            "authority_digest": catalog.authority.get("authority_digest"),
        },
        "scenario_digest": content_hash(saved["document"]),
        "runtime_profile_digest": content_hash(profile.to_dict()) if profile is not None else None,
        "runtime_provider_digest": content_hash(provider_binding)
        if provider_binding is not None
        else None,
        "bounds": {"inspection_attempts": 3, "observations": 128},
        "capabilities": [
            {
                "id": CAPABILITY,
                "title": "Run the accepted graph and inspect retained evidence",
                "available": True,
                "supported_autonomy": ["assist", "auto"],
                "reason": "Uses only the explicit native run settings and ordinary execution approval.",
                "native_path": "/runs",
            }
        ],
        "limitations": LIMITATIONS,
    }
    return {**document, "context_digest": content_hash(document)}
