"""Authoritative immutable saved experiment and operator-selected run policy context."""

from __future__ import annotations

import re
from typing import Any, Mapping
from urllib.parse import urlencode

from .assistance_run_protocol import AssistanceRunService
from .contracts import ScenarioDefinition
from .product_store_errors import ProductStoreError
from .util import content_hash

CAPABILITY = "run.saved_graph_and_inspect"
KIND = "run.assistance.prepare"
INSPECT_KIND = "run.evidence.inspect"
LIMITATIONS = [
    "Runs only the exact saved experiment version with the operator-selected run settings.",
    "Assist requires native preparation review. Auto may submit that frozen policy; Execute always requires a separate fresh native approval.",
    "Inspection describes retained evidence and cleanup. Simulated, missing or unobserved results do not establish real execution or deployed defense effectiveness.",
    "Recovery may retry evidence inspection against the same run, never repeat an uncertain execution.",
]


def selection(value: Any) -> Mapping[str, Any]:
    if (
        not isinstance(value, Mapping)
        or not isinstance(value.get("kind"), str)
        or value["kind"] not in {"saved_graph", "saved_scenario"}
    ):
        raise ProductStoreError(
            "Select an exact saved experiment and explicit native run settings."
        )
    if value["kind"] == "saved_graph":
        if set(value) != {"kind", "proposal_job_id", "application", "run_intent"}:
            raise ProductStoreError("The saved graph selection fields are invalid.")
        if not isinstance(value["proposal_job_id"], str) or not re.fullmatch(
            r"job-[0-9a-f]{32}", value["proposal_job_id"]
        ):
            raise ProductStoreError("The selected graph proposal identity is invalid.")
        if not isinstance(value["application"], Mapping):
            raise ProductStoreError("The selected graph has no exact application receipt.")
    else:
        if set(value) != {"kind", "scenario", "run_intent"}:
            raise ProductStoreError("The saved experiment selection fields are invalid.")
        source = value["scenario"]
        if (
            not isinstance(source, Mapping)
            or set(source) != {"scenario_id", "version", "digest"}
            or not isinstance(source["scenario_id"], str)
            or len(source["scenario_id"]) > 200
            or re.fullmatch(r"[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*", source["scenario_id"]) is None
            or type(source["version"]) is not int
            or not 1 <= source["version"] <= 2**31 - 1
            or not isinstance(source["digest"], str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", source["digest"]) is None
        ):
            raise ProductStoreError("Select an exact saved experiment version and digest.")
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


def source_ref(selected: Mapping[str, Any]) -> Mapping[str, Any]:
    return dict(
        selected["application"] if selected["kind"] == "saved_graph" else selected["scenario"]
    )


def setup_path(selected: Mapping[str, Any]) -> str:
    if selected["kind"] == "saved_graph":
        return "/runs?" + urlencode({"graph_job": selected["proposal_job_id"]})
    source = source_ref(selected)
    return "/runs?" + urlencode(
        {
            "saved_scenario": source["scenario_id"],
            "version": source["version"],
            "digest": source["digest"],
        }
    )


def saved_source(service: AssistanceRunService, selected: Mapping[str, Any]) -> Mapping[str, Any]:
    if selected["kind"] == "saved_graph":
        native = service.graph_ai_job(selected["proposal_job_id"])
        if native["application"] is None or native["application"] != selected["application"]:
            raise ProductStoreError(
                "The graph application differs from the selected immutable receipt."
            )
    application = source_ref(selected)
    saved = service.scenario_version(application["scenario_id"], version=application["version"])[
        "scenario"
    ]
    if (
        any(saved[key] != application[key] for key in ("scenario_id", "version", "digest"))
        or saved["document"]["id"] != application["scenario_id"]
        or content_hash(saved["document"]) != application["digest"]
    ):
        raise ProductStoreError(
            "The saved experiment differs from the selected version and digest."
        )
    return dict(saved)


def context(service: AssistanceRunService, value: Any) -> Mapping[str, Any]:
    selected = selection(value)
    saved = saved_source(service, selected)
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
        "runtime_provider_digest": (
            content_hash(provider_binding) if provider_binding is not None else None
        ),
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
