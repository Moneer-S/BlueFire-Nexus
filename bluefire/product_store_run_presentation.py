"""Editable run labels, separate from canonical run documents and their hashes."""

from __future__ import annotations

import hashlib
from typing import Any, Mapping

from .product_store_errors import ProductStoreError

KIND = "run_presentation"
SCHEMA = "bluefire.run-presentation.v1"


def resource_id(run_id: str) -> str:
    return "run-name-" + hashlib.sha256(run_id.encode("utf-8")).hexdigest()


def display_name(request: Mapping[str, Any]) -> str | None:
    if set(request) != {"display_name"}:
        raise ProductStoreError("Rename accepts only display_name.")
    value = request["display_name"]
    if value is None:
        return None
    if not isinstance(value, str) or not value.isprintable() or not 1 <= len(value.strip()) <= 120:
        raise ProductStoreError("Run name must contain 1–120 printable characters.")
    return value.strip()


def presentation(
    run: Mapping[str, Any], resource: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    scenario = run.get("scenario")
    title = scenario.get("title") if isinstance(scenario, Mapping) else None
    default = next(
        (
            value.strip()
            for value in (title, run.get("scenario_title"))
            if isinstance(value, str) and value.strip()
        ),
        "Run",
    )
    name = None
    updated_at = None
    if resource is not None:
        document = resource["document"]
        if document.get("schema_version") != SCHEMA or document.get("run_id") != run["run_id"]:
            raise ProductStoreError("Run presentation identity is invalid.")
        name = display_name({"display_name": document.get("display_name")})
        updated_at = resource["updated_at"]
    return {
        "schema_version": SCHEMA,
        "run_id": run["run_id"],
        "display_name": name,
        "default_name": default,
        "updated_at": updated_at,
    }
