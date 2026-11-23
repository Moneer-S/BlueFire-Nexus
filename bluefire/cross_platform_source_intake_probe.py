"""Exact report contract for Gate 11 native POSIX source-intake probes."""

from __future__ import annotations

import hashlib
import importlib
import json
import sys
from pathlib import Path
from typing import Any, Callable, Mapping, cast

SOURCE_INTAKE_POSIX_PROBE_SCHEMA = "bluefire.source-intake-posix-probes.v1"
SOURCE_INTAKE_POSIX_PROBE_IDS = (
    "source_intake.posix.publication_preserves_rebound_temporary",
    "source_intake.posix.publication_refuses_target_collision",
    "source_intake.posix.quarantine_retained_namespace_no_replace",
)
SOURCE_INTAKE_POSIX_PROBE_COUNT = 3
SOURCE_INTAKE_POSIX_PROBE_IDS_SHA256 = (
    "sha256:bbdd4c7db581e50913736c64c466e9ba783679435b353adba5ea27f2c9cbe6c1"
)
_STAGED_PROBE_MODULE = "bluefire._gate11_source_intake_probe"


class SourceIntakeProbeValidationError(ValueError):
    """Raised when the fixed native POSIX probe report is not exact."""


def run_bound_staged_probe(
    product_root: Path,
    workspace: Path,
    expected_identity: Mapping[str, Any],
    identity_reader: Callable[[Path, int], tuple[int, str]],
    error_type: type[ValueError] = SourceIntakeProbeValidationError,
) -> Mapping[str, Any]:
    """Verify the staged probe's exact identity before importing and executing it."""

    probe_path = product_root / "bluefire" / "_gate11_source_intake_probe.py"
    if _STAGED_PROBE_MODULE in sys.modules:
        raise error_type("source-intake POSIX probe module was already loaded")
    observed_identity = identity_reader(probe_path, 64 * 1024)
    if _STAGED_PROBE_MODULE in sys.modules:
        raise error_type("source-intake POSIX probe module loaded during identity verification")
    if observed_identity != (expected_identity["size"], expected_identity["sha256"]):
        raise error_type("source-intake POSIX probe identity changed")

    probe_module = importlib.import_module(_STAGED_PROBE_MODULE)
    run_probes = cast(Any, probe_module).run_probes

    return cast(Mapping[str, Any], run_probes(workspace))


def _ids_sha256(probe_ids: list[str]) -> str:
    payload = json.dumps(
        probe_ids, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def validate_probe(
    value: Any,
    error_type: type[ValueError] = SourceIntakeProbeValidationError,
) -> Mapping[str, Any]:
    """Return the exact three-case report or raise the requested validation error."""

    if not isinstance(value, Mapping) or set(value) != {
        "schema_version",
        "platform",
        "passed",
        "probe_count",
        "passed_probe_ids",
        "passed_probe_ids_sha256",
    }:
        raise error_type("source-intake POSIX publication probe inventory is invalid")
    probe_ids = value.get("passed_probe_ids")
    if (
        value.get("schema_version") != SOURCE_INTAKE_POSIX_PROBE_SCHEMA
        or value.get("platform") != "linux"
        or value.get("passed") is not True
        or type(value.get("probe_count")) is not int
        or value.get("probe_count") != SOURCE_INTAKE_POSIX_PROBE_COUNT
        or not isinstance(probe_ids, list)
        or tuple(probe_ids) != SOURCE_INTAKE_POSIX_PROBE_IDS
        or probe_ids != sorted(probe_ids)
        or len(set(probe_ids)) != SOURCE_INTAKE_POSIX_PROBE_COUNT
        or value.get("passed_probe_ids_sha256") != SOURCE_INTAKE_POSIX_PROBE_IDS_SHA256
        or _ids_sha256(probe_ids) != SOURCE_INTAKE_POSIX_PROBE_IDS_SHA256
    ):
        raise error_type("source-intake POSIX publication probe inventory is invalid")
    return dict(value)


__all__ = [
    "SOURCE_INTAKE_POSIX_PROBE_COUNT",
    "SOURCE_INTAKE_POSIX_PROBE_IDS",
    "SOURCE_INTAKE_POSIX_PROBE_IDS_SHA256",
    "SOURCE_INTAKE_POSIX_PROBE_SCHEMA",
    "SourceIntakeProbeValidationError",
    "run_bound_staged_probe",
    "validate_probe",
]
