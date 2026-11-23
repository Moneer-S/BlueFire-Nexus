"""Reviewed dependency and runtime-entrypoint health for detection backends."""

from __future__ import annotations

from importlib import import_module, metadata
from typing import Any, Mapping

SQLITE_BACKEND_DISTRIBUTION = "pysigma-backend-sqlite"
PYSIGMA_PIN = "1.5.0"
SQLITE_BACKEND_PIN = "1.2.2"
YARA_PIN = "4.5.4"


def _reviewed_version(distribution: str, pin: str) -> str | None:
    try:
        version = metadata.version(distribution)
    except metadata.PackageNotFoundError:
        return None
    return version if version == pin else None


def _entrypoint_ready(module_name: str, attribute: str) -> bool:
    try:
        module = import_module(module_name)
    except (ImportError, OSError):
        return False
    return callable(getattr(module, attribute, None))


def detection_backend_health() -> Mapping[str, Mapping[str, Any]]:
    """Probe exact pins before importing their required runtime entrypoints."""

    pysigma = _reviewed_version("pysigma", PYSIGMA_PIN)
    sqlite_backend = _reviewed_version(
        SQLITE_BACKEND_DISTRIBUTION,
        SQLITE_BACKEND_PIN,
    )
    yara = _reviewed_version("yara-python", YARA_PIN)
    sigma_ready = bool(
        pysigma
        and sqlite_backend
        and _entrypoint_ready("sigma.collection", "SigmaCollection")
        and _entrypoint_ready("sigma.backends.sqlite", "sqliteBackend")
    )
    yara_ready = bool(yara and _entrypoint_ready("yara", "compile"))
    return {
        "pySigma": {
            "ready": sigma_ready,
            "version": pysigma,
            "conversion_backend": "pySigma SQLite",
            "conversion_backend_version": sqlite_backend,
        },
        "YARA-Python": {"ready": yara_ready, "version": yara},
        "SPL structural checker": {"ready": True, "version": "1"},
    }
