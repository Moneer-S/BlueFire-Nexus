"""Canonical Vitest inventories, including observed failed and skipped tests."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from .product_acceptance_process import _redact_runtime_paths


def vitest_inventory(value: Any, frontend: Path) -> dict[str, list[str]]:
    if not isinstance(value, Mapping) or not isinstance(value.get("testResults"), list):
        raise ValueError("Vitest JSON report is invalid")
    inventory: dict[str, list[str]] = {"passed": [], "failed": [], "skipped": []}
    observed: set[str] = set()
    for result in value["testResults"]:
        if not isinstance(result, Mapping) or not isinstance(result.get("assertionResults"), list):
            raise ValueError("Vitest file result is invalid")
        raw_name = result.get("name")
        if not isinstance(raw_name, str):
            raise ValueError("Vitest file identity is invalid")
        path = Path(raw_name).resolve(strict=True)
        try:
            relative = path.relative_to(frontend.resolve(strict=True)).as_posix()
        except ValueError as exc:
            raise ValueError("Vitest result escaped the frontend root") from exc
        for assertion in result["assertionResults"]:
            if (
                not isinstance(assertion, Mapping)
                or not isinstance(assertion.get("status"), str)
                or assertion.get("status") not in {"passed", "failed", "pending", "todo", "skipped"}
                or not isinstance(assertion.get("title"), str)
                or not isinstance(assertion.get("ancestorTitles"), list)
                or not all(isinstance(item, str) for item in assertion["ancestorTitles"])
            ):
                raise ValueError("Vitest assertion is invalid")
            identifier = "::".join([relative, *assertion["ancestorTitles"], assertion["title"]])
            if (
                len(identifier) > 1024
                or identifier in observed
                or _redact_runtime_paths(identifier, repository=frontend, run_dir=frontend)
                != identifier
            ):
                raise ValueError("Vitest assertion identity is unsafe or duplicated")
            observed.add(identifier)
            status = assertion["status"]
            inventory[status if status in {"passed", "failed"} else "skipped"].append(identifier)
    return {status: sorted(identifiers) for status, identifiers in inventory.items()}
