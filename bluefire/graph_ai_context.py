"""Immutable graph-selection context; never probes runners or grants execution."""

from __future__ import annotations

import re
from typing import Any, Mapping

from .ai_assistance import GRAPH
from .ai_drafts import draftable_behavior_catalog
from .product_store import ProductStore
from .product_store_errors import ProductStoreError
from .registry import BehaviorRegistry
from .util import content_hash

LIMITATIONS = [
    "Creates a separate proposed graph, not an exact edit of the reference graph.",
    "Auto is limited to proposal generation, registered validation and durable retention. Saving requires explicit native review.",
    "A saved graph has not run. Runner setup, preflight and fresh Execute approval remain separate.",
]


def selection(value: Any) -> Mapping[str, Any]:
    if (
        not isinstance(value, Mapping)
        or set(value) != {"kind", "base_scenario"}
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
    return {"kind": "graph", "base_scenario": dict(base) if base is not None else None}


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
    document = {
        "schema_version": "bluefire.assistance-context.v1",
        "selected": selected,
        "reference_summary": reference,
        "catalog_binding": dict(catalog_binding),
        "catalog_digest": content_hash(
            {
                "draftable": list(descriptors),
                "definitions": [registry.get_behavior(row["id"]).to_dict() for row in descriptors],
            }
        ),
        "bounds": {"max_nodes": 8, "max_edges": 16},
        "capabilities": [
            {
                "id": GRAPH,
                "title": "Propose and validate a separate graph",
                "available": bool(descriptors),
                "supported_autonomy": ["assist", "auto"],
                "reason": "Only registered behaviors; explicit Builder review before saving. No experiment is run.",
                "native_path": "/builder",
            }
        ],
        "limitations": LIMITATIONS,
    }
    return {**document, "context_digest": content_hash(document)}
