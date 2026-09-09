"""Immutable graph-selection context; never probes runners or grants execution."""

from __future__ import annotations

import re
from typing import Any, Mapping

from .ai_assistance import GRAPH
from .ai_drafts import draftable_behavior_catalog
from .contracts import ContractError, ScenarioDefinition
from .product_store import ProductStore
from .product_store_errors import ProductStoreError
from .registry import BehaviorRegistry
from .util import canonical_json_bytes, content_hash

LIMITATIONS = [
    "Creates a separate proposed graph, not an exact edit of the reference graph.",
    "Auto is limited to proposal generation, registered validation and durable retention. Saving requires explicit native review.",
    "A saved graph has not run. Runner setup, preflight and fresh Execute approval remain separate.",
]


def selection(value: Any) -> Mapping[str, Any]:
    if (
        not isinstance(value, Mapping)
        or set(value) not in ({"kind", "base_scenario"}, {"kind", "base_scenario", "edit_step"})
        or value["kind"] != "graph"
    ):
        raise ProductStoreError("Select a graph context and an optional exact saved reference.")
    base = value["base_scenario"]
    if base is not None and (
        not isinstance(base, Mapping)
        or set(base) != {"scenario_id", "version", "digest"}
        or not isinstance(base["scenario_id"], str)
        or not re.fullmatch(r"[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*\.v[1-9][0-9]*", base["scenario_id"])
        or type(base["version"]) is not int
        or not 1 <= base["version"] <= 2**31 - 1
        or not isinstance(base["digest"], str)
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", base["digest"])
    ):
        raise ProductStoreError("The saved graph reference is invalid.")
    result = {"kind": "graph", "base_scenario": dict(base) if base is not None else None}
    if "edit_step" in value:
        edit = value["edit_step"]
        if (
            not isinstance(edit, Mapping)
            or set(edit) != {"scenario", "step_id", "dirty"}
            or not isinstance(edit["step_id"], str)
            or type(edit["dirty"]) is not bool
            or not isinstance(edit["scenario"], Mapping)
        ):
            raise ProductStoreError("Select one step in a bounded current graph.")
        try:
            if len(canonical_json_bytes(edit["scenario"])) > 65536:
                raise ValueError("graph byte bound")
            scenario = ScenarioDefinition.from_mapping(edit["scenario"])
            if canonical_json_bytes(scenario.to_dict()) != canonical_json_bytes(edit["scenario"]):
                raise ValueError("source must use the complete canonical graph contract")
        except (ContractError, TypeError, ValueError) as exc:
            raise ProductStoreError(
                "Validate the current graph before requesting a step edit."
            ) from exc
        if (
            len(scenario.steps) > 128
            or len(scenario.edges) > 256
            or edit["step_id"] not in {step.id for step in scenario.steps}
            or (edit["dirty"] and base is not None)
        ):
            raise ProductStoreError("The current step or graph identity is invalid.")
        result["edit_step"] = dict(edit)
    return result


def context(
    store: ProductStore,
    registry: BehaviorRegistry,
    selected: Mapping[str, Any],
    catalog_binding: Mapping[str, Any],
) -> Mapping[str, Any]:
    selected = selection(selected)
    base = selected["base_scenario"]
    reference = None
    if base is not None:
        saved = store.get_scenario(base["scenario_id"])
        if (
            any(saved[key] != base[key] for key in base)
            or content_hash(saved["document"]) != base["digest"]
        ):
            raise ProductStoreError("The selected saved graph changed. Select its current version.")
        behaviors = sorted({step["behavior_id"] for step in saved["document"]["steps"]})
        reference = {
            "title": saved["title"][:200],
            "purpose": saved["document"]["purpose"][:500],
            "behavior_ids": behaviors[:8],
            "truncated": len(behaviors) > 8,
        }
    descriptors = draftable_behavior_catalog(registry)
    edit = selected.get("edit_step")
    editable = None
    if edit is not None:
        scenario = ScenarioDefinition.from_mapping(edit["scenario"])
        if base is not None and (
            scenario.id != base["scenario_id"] or content_hash(edit["scenario"]) != base["digest"]
        ):
            raise ProductStoreError("The current graph differs from the selected saved version.")
        registry.validate_scenario(scenario)
        step = next(row for row in edit["scenario"]["steps"] if row["id"] == edit["step_id"])
        editable = next((row for row in descriptors if row["id"] == step["behavior_id"]), None)
    document = {
        "schema_version": "bluefire.assistance-context.v1",
        "selected": selected,
        "reference_summary": None if edit else reference,
        "catalog_binding": dict(catalog_binding),
        "catalog_digest": content_hash(
            {
                "draftable": list(descriptors),
                "definitions": [registry.get_behavior(row["id"]).to_dict() for row in descriptors],
            }
        ),
        "bounds": (
            {"max_nodes": 128, "max_edges": 256, "max_graph_bytes": 65536}
            if edit
            else {"max_nodes": 8, "max_edges": 16}
        ),
        "capabilities": [
            {
                "id": GRAPH,
                "title": (
                    "Propose changes to the selected step"
                    if edit
                    else "Propose and validate a separate graph"
                ),
                "available": (
                    bool(editable and editable["parameters"]) if edit else bool(descriptors)
                ),
                "supported_autonomy": ["assist", "auto"],
                "reason": (
                    "The selected step has no supported primitive parameters. Edit it manually or choose New experiment."
                    if edit and not (editable and editable["parameters"])
                    else "Only registered parameters; explicit Builder review before saving. No experiment is run."
                ),
                "native_path": "/builder",
            }
        ],
        "limitations": (
            [
                "Only primitive parameters of the selected step may change. All routes, inputs, other steps and the objective remain fixed.",
                "The model receives the objective, selected step and parameter schema; the full source graph stays in this product.",
                *LIMITATIONS[1:],
            ]
            if edit
            else LIMITATIONS
        ),
    }
    if edit is not None:
        document["edit_source_digest"] = content_hash(edit["scenario"])
        document["edit_model_context"] = {
            "purpose": edit["scenario"]["purpose"][:2000],
            "step_id": edit["step_id"],
            "behavior": editable,
            "parameters": step["parameters"],
        }
    return {**document, "context_digest": content_hash(document)}
