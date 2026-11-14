"""Admission checks for the dedicated BlueFire Strix worker artifact."""

from __future__ import annotations

import re
from typing import Any, Sequence

from tools import build_strix_worker_runtime_artifact as worker_artifact
from tools.strix_runtime_closure_common import (
    StrixRuntimeClosurePreparationError,
    _digest_bytes,
    _document_bytes,
    _strict_json,
)
from tools.strix_runtime_closure_wheel import (
    WheelPlan,
    _read_plan_member,
)

WORKER_ARTIFACT_SCHEMA = "bluefire.strix-worker-runtime-artifact.v1"
INSTALLED_DISTRIBUTIONS_SCHEMA = "bluefire.strix-installed-distributions.v1"
_REVISION = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


def _worker_manifest(plan: WheelPlan) -> tuple[dict[str, Any], str]:
    if plan.normalized_name == "bluefire-nexus":
        raise StrixRuntimeClosurePreparationError(
            "full BlueFire wheel is incompatible with the pinned Strix runtime"
        )
    if plan.normalized_name != worker_artifact.DISTRIBUTION:
        raise StrixRuntimeClosurePreparationError(
            "worker artifact distribution identity is invalid"
        )
    payload = _read_plan_member(plan, ".dist-info/bluefire_worker_runtime.json")
    document = _strict_json(payload, "worker artifact manifest")
    fields = {
        "schema_version",
        "distribution",
        "version",
        "worker_source_revision",
        "entry_module",
        "entrypoint_digest",
        "requires_python",
        "python_abi",
        "platform_tag",
        "wheel_tag",
        "module_inventory",
        "resource_inventory",
        "requires_dist",
        "required_installed_distributions",
        "forbidden_distributions",
        "allowed_dynamic_imports",
        "import_graph_digest",
    }
    if not isinstance(document, dict) or set(document) != fields:
        raise StrixRuntimeClosurePreparationError(
            "worker artifact manifest fields do not match"
        )
    expected_required = [
        {"name": name, "version": version}
        for name, version in worker_artifact.REQUIRED_INSTALLED_DISTRIBUTIONS
    ]
    if (
        document["schema_version"] != WORKER_ARTIFACT_SCHEMA
        or document["distribution"] != worker_artifact.DISTRIBUTION
        or document["version"] != plan.version
        or document["entry_module"] != worker_artifact.ENTRY_MODULE
        or not isinstance(document["worker_source_revision"], str)
        or _REVISION.fullmatch(document["worker_source_revision"]) is None
        or document["requires_python"] != worker_artifact.PYTHON_REQUIRES
        or plan.requires_python != worker_artifact.PYTHON_REQUIRES
        or document["python_abi"] != worker_artifact.PYTHON_ABI
        or document["platform_tag"] != worker_artifact.PLATFORM_TAG
        or document["wheel_tag"] != worker_artifact.WHEEL_TAG
        or plan.wheel_tags != (worker_artifact.WHEEL_TAG,)
        or plan.root_is_purelib is not True
        or document["requires_dist"] != list(worker_artifact.REQUIRES_DIST)
        or tuple(plan.requires_dist) != worker_artifact.REQUIRES_DIST
        or document["required_installed_distributions"] != expected_required
        or document["forbidden_distributions"]
        != list(worker_artifact.FORBIDDEN_DISTRIBUTIONS)
        or document["allowed_dynamic_imports"]
        != list(worker_artifact.ALLOWED_DYNAMIC_IMPORTS)
        or not isinstance(document["import_graph_digest"], str)
        or _DIGEST.fullmatch(document["import_graph_digest"]) is None
    ):
        raise StrixRuntimeClosurePreparationError(
            "worker artifact manifest identity is invalid"
        )

    entries = {entry.destination: entry for entry in plan.entries}
    expected_inventories = {
        "module_inventory": tuple(worker_artifact.MODULE_PATHS),
        "resource_inventory": tuple(worker_artifact.RESOURCE_PATHS),
    }
    owned_rows: list[dict[str, Any]] = []
    for field, expected_paths in expected_inventories.items():
        rows = document[field]
        if not isinstance(rows, list) or any(
            not isinstance(row, dict)
            or set(row) != {"path", "content_digest", "size"}
            or not isinstance(row.get("path"), str)
            for row in rows
        ):
            raise StrixRuntimeClosurePreparationError(
                "worker artifact inventory row is invalid"
            )
        if rows != sorted(rows, key=lambda row: row["path"]):
            raise StrixRuntimeClosurePreparationError(
                "worker artifact inventory is not sorted"
            )
        if tuple(row["path"] for row in rows) != expected_paths:
            raise StrixRuntimeClosurePreparationError(
                "worker artifact inventory is not the reviewed module closure"
            )
        for row in rows:
            entry = entries.get(row["path"])
            if (
                entry is None
                or row["content_digest"] != entry.digest
                or row["size"] != entry.size
            ):
                raise StrixRuntimeClosurePreparationError(
                    "worker artifact inventory does not bind wheel bytes"
                )
            owned_rows.append(row)

    owned = {
        entry.destination
        for entry in plan.entries
        if entry.destination.startswith("bluefire/")
    }
    expected_owned = set(worker_artifact.MODULE_PATHS) | set(
        worker_artifact.RESOURCE_PATHS
    )
    if owned != expected_owned or "bluefire/__init__.py" in owned:
        raise StrixRuntimeClosurePreparationError(
            "worker artifact module ownership is incomplete"
        )
    entrypoint = entries.get("bluefire/strix_controlled_installed_worker.py")
    if (
        entrypoint is None
        or document["entrypoint_digest"] != entrypoint.digest
        or not any(
            row["path"] == entrypoint.destination
            and row["content_digest"] == entrypoint.digest
            and row["size"] == entrypoint.size
            for row in document["module_inventory"]
        )
    ):
        raise StrixRuntimeClosurePreparationError(
            "worker artifact entrypoint identity is invalid"
        )
    return document, _digest_bytes(payload)


def _require_exact_worker_dependencies(
    plans: Sequence[WheelPlan], strix_plan: WheelPlan
) -> None:
    versions = {plan.normalized_name: plan.version for plan in plans}
    versions[strix_plan.normalized_name] = strix_plan.version
    expected = dict(worker_artifact.REQUIRED_INSTALLED_DISTRIBUTIONS)
    if any(versions.get(name) != version for name, version in expected.items()):
        raise StrixRuntimeClosurePreparationError(
            "worker artifact dependencies do not match the pinned runtime"
        )


def _installed_distributions_ref(plans: Sequence[WheelPlan]) -> str:
    rows = [
        {
            "name": plan.normalized_name,
            "version": plan.version,
            "metadata_digest": plan.metadata_digest,
            "record_digest": plan.record_digest,
        }
        for plan in plans
    ]
    if (
        len({row["name"] for row in rows}) != len(rows)
        or any(
            row["name"] in worker_artifact.FORBIDDEN_DISTRIBUTIONS
            for row in rows
        )
    ):
        raise StrixRuntimeClosurePreparationError(
            "installed distribution identity is ambiguous or forbidden"
        )
    document = {
        "schema_version": INSTALLED_DISTRIBUTIONS_SCHEMA,
        "distributions": sorted(rows, key=lambda row: row["name"]),
    }
    return _digest_bytes(_document_bytes(document))


__all__ = [
    "INSTALLED_DISTRIBUTIONS_SCHEMA",
    "WORKER_ARTIFACT_SCHEMA",
    "_installed_distributions_ref",
    "_require_exact_worker_dependencies",
    "_worker_manifest",
]
