"""Canonical Vitest inventories, including observed failed and skipped tests."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from .gate_private_diagnostics import (
    PRIVATE_OUTPUT_LIMIT,
    private_capture_root,
    retain_private_output,
)
from .product_acceptance_process import _redact_runtime_paths
from .runner_transport_errors import RunnerTransportError


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


def retain_vitest_failures(
    value: Mapping[str, Any],
    *,
    frontend: Path,
    evidence_dir: Path,
    source: Mapping[str, Any],
) -> Mapping[str, Any]:
    """Keep bounded failure details privately, separate from the exact gate inventory."""
    captures: list[Mapping[str, Any]] = []
    try:
        if private_capture_root(frontend.parent, evidence_dir) is None:
            return {"status": "not_configured"}
        inventory = vitest_inventory(value, frontend)
        wanted = set(inventory["failed"])
        failures = []
        for result in value["testResults"]:
            relative = (
                Path(result["name"])
                .resolve(strict=True)
                .relative_to(frontend.resolve(strict=True))
                .as_posix()
            )
            assertions = result["assertionResults"]
            for assertion in assertions:
                identifier = "::".join([relative, *assertion["ancestorTitles"], assertion["title"]])
                if identifier in wanted:
                    failures.append(
                        {
                            "test_id": identifier,
                            "duration_ms": assertion.get("duration"),
                            "failure_messages": assertion.get("failureMessages", []),
                        }
                    )
            if result.get("status") == "failed" and not any(
                row["status"] == "failed" for row in assertions
            ):
                failures.append(
                    {"suite": relative, "failure_messages": [result.get("message", "")]}
                )
        payload = json.dumps({"failures": failures}, ensure_ascii=False, allow_nan=False).encode(
            "utf-8"
        )
        # The producer already bounds the complete source JSON to four MiB.
        # Keep that bound and the existing eight-KiB private capture bound.
        if len(payload) > 4 * 1024 * 1024:
            return {"status": "projection_bound_exceeded", "failure_count": len(failures)}
        digest = "sha256:" + hashlib.sha256(payload).hexdigest()
        parts = (len(payload) + PRIVATE_OUTPUT_LIMIT - 1) // PRIVATE_OUTPUT_LIMIT
        for index in range(parts):
            capture = retain_private_output(
                repository=frontend.parent,
                evidence_dir=evidence_dir,
                stdout=payload[index * PRIVATE_OUTPUT_LIMIT : (index + 1) * PRIVATE_OUTPUT_LIMIT],
                stderr=b"",
                source={
                    **source,
                    "kind": "frontend_failure_projection",
                    "part": index,
                    "parts": parts,
                    "projection_sha256": digest,
                    "projection_bytes": len(payload),
                },
            )
            captures.append(capture)
            if capture.get("status") != "retained":
                return {
                    "status": "retention_incomplete",
                    "failure_count": len(failures),
                    "size_bytes": len(payload),
                    "sha256": digest,
                    "captures": captures,
                }
        return {
            "status": "retained",
            "failure_count": len(failures),
            "size_bytes": len(payload),
            "sha256": digest,
            "captures": captures,
        }
    except (OSError, ValueError, TypeError, KeyError, RunnerTransportError) as error:
        # A diagnostic write refusal must not replace the observed test failures.
        return {
            "status": "retention_failed",
            "error_type": type(error).__name__,
            "captures": captures,
        }
