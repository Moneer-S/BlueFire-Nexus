"""Verified run observations and explicit initial-rule selection; no model calls."""

from __future__ import annotations

import re
import sqlite3
from typing import Any, Mapping
from urllib.parse import urlencode

from .detection_evaluations import _source, _source_binding
from .detection_lab import DetectionLabService
from .product_store_errors import ProductStoreError
from .registry import BehaviorRegistry
from .run_store import RUN_ID_RE
from .util import content_hash

CAPABILITY = "detection.create_and_evaluate"
LIMITATIONS = [
    "Creates an initial rule from BlueFire normalized observations, not target-native telemetry.",
    "Assist and Auto retain a proposal only. Explicit native source review is required before saving and evaluating.",
    "The selected run is development input, never independent held-out validation or deployment evidence.",
]


def selection(value: Any) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {
        "kind",
        "run_id",
        "source_binding_digest",
        "behavior_id",
        "target_language",
        "case_role",
    }:
        raise ProductStoreError(
            "Select a verified run, behavior, language and development case role."
        )
    if (
        value["kind"] != "run_detection"
        or not isinstance(value["run_id"], str)
        or not RUN_ID_RE.fullmatch(value["run_id"])
    ):
        raise ProductStoreError("The detection source run identifier is invalid.")
    if not isinstance(value["source_binding_digest"], str) or not re.fullmatch(
        r"sha256:[0-9a-f]{64}", value["source_binding_digest"]
    ):
        raise ProductStoreError("The detection source binding is invalid.")
    if not isinstance(value["behavior_id"], str) or not re.fullmatch(
        r"[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*", value["behavior_id"]
    ):
        raise ProductStoreError("Choose a named behavior from this run.")
    if value["target_language"] not in {"sqlite", "sigma"} or value["case_role"] not in {
        "attack",
        "benign",
        "replay",
    }:
        raise ProductStoreError("Choose SQLite or Sigma and an explicit development case role.")
    return dict(value)


def source(lab: DetectionLabService, run_id: str, registry: BehaviorRegistry) -> Mapping[str, Any]:
    run, records, observed = _source(lab, run_id)
    binding = _source_binding(run, records, observed)
    behaviors = []
    for behavior_id in sorted({record.behavior_id for record in observed}):
        definition = registry.get_behavior(behavior_id)
        rows = [row for row in observed if row.behavior_id == behavior_id]
        behaviors.append(
            {
                "behavior_id": behavior_id,
                "title": definition.title,
                "step_ids": sorted({row.step_id for row in rows}),
                "observed_count": len(rows),
            }
        )
    sigma = lab.validator.health()["pySigma"]
    languages = [
        {
            "id": "sqlite",
            "available": True,
            "reason": None,
            "backend": {"name": "SQLite bounded executor", "version": sqlite3.sqlite_version},
        },
        {
            "id": "sigma",
            "available": bool(sigma.get("ready")),
            "reason": (
                None if sigma.get("ready") else "The local Sigma-to-SQLite parser is unavailable."
            ),
            "backend": {
                "name": "pySigma",
                "version": sigma.get("version"),
                "conversion_backend": sigma.get("conversion_backend"),
                "conversion_backend_version": sigma.get("conversion_backend_version"),
            },
        },
    ]
    available = run.get("status") == "completed" and 1 <= len(observed) <= 128 and bool(behaviors)
    return {
        "schema_version": "bluefire.detection-creation-source.v1",
        "run_id": run_id,
        "run_title": str(run.get("scenario", {}).get("title", run_id)),
        "mode": binding["mode"],
        "source_run": binding,
        "source_binding_digest": content_hash(binding),
        "observed_count": len(observed),
        "evidence_count": len(records),
        "available": available,
        "reason": (
            None
            if available
            else "Initial source creation requires a completed run, 1–128 observed records and a registered behavior; none are silently truncated."
        ),
        "behaviors": behaviors,
        "languages": languages,
        "limitations": LIMITATIONS,
    }


def context(
    lab: DetectionLabService,
    selected: Mapping[str, Any],
    registry: BehaviorRegistry,
    catalog_binding: Mapping[str, Any],
) -> Mapping[str, Any]:
    selected = selection(selected)
    discovered = source(lab, selected["run_id"], registry)
    if discovered["source_binding_digest"] != selected["source_binding_digest"]:
        raise ProductStoreError(
            "The selected run source changed. Select its current verified binding."
        )
    chosen = next(
        (row for row in discovered["behaviors"] if row["behavior_id"] == selected["behavior_id"]),
        None,
    )
    if chosen is None:
        raise ProductStoreError("The selected behavior has no verified observations in this run.")
    language = next(
        row for row in discovered["languages"] if row["id"] == selected["target_language"]
    )
    definition = registry.get_behavior(selected["behavior_id"]).to_dict()
    document = {
        "schema_version": "bluefire.assistance-context.v1",
        "selected": selected,
        "source": discovered,
        "behavior_digest": content_hash(definition),
        "capabilities": [
            {
                "id": CAPABILITY,
                "title": "Create and evaluate an initial rule",
                "available": discovered["available"] and language["available"],
                "supported_autonomy": ["assist", "auto"],
                "reason": discovered["reason"]
                or language["reason"]
                or "Review concrete source before saving a new rule and development evaluation.",
                "native_path": "/detection-lab?"
                + urlencode({"run": selected["run_id"], "create": "1"}),
            }
        ],
        "limitations": LIMITATIONS,
    }
    document["catalog_binding"] = dict(catalog_binding)
    return {**document, "context_digest": content_hash(document)}
