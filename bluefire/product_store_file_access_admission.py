"""Fixed protocol admission inside the original file-access store transaction."""

from __future__ import annotations

from typing import Any

from . import product_store_windows_correction as journal
from . import product_store_windows_file_access as windows
from . import windows_file_access_correction_admission as correction
from .product_store_errors import ProductStoreError


def allowed_operations(status: str) -> list[str]:
    return {
        "created": ["baseline", "reset"],
        "baseline_verified": ["harden", "reset"],
        "hardened": ["rollback", "reset"],
        "rolled_back": ["harden", "baseline", "reset"],
        "reset": [],
        "uncertain": [],
        "recovery_required": ["reset"],
    }.get(status, [])


def permitted_operations(
    store: Any, connection: Any, control: dict, review_context: dict, *, now_ms: int
) -> list[str]:
    from . import product_store_macos_file_access as macos

    if macos.is_control(control):
        macos.validate_review(control, review_context, now_ms)
        return macos.permitted(control)
    if review_context.get("schema_version") == macos.CONTEXT_SCHEMA:
        raise ProductStoreError("Darwin provenance requires its original Darwin control.")
    if not windows.is_windows_control(control):
        return allowed_operations(control["status"])
    if control.get("schema_version") == "bluefire.windows-file-access-control-record.v3":
        return []
    if control.get("schema_version") == windows.CONTROL_RECORD_SCHEMA:
        journal.validate_review(store, connection, control, review_context, now_ms=now_ms)
        return ["harden"]
    return windows.permitted_operations(store, connection, control, review_context, now_ms=now_ms)


def validate_preparation(
    store: Any,
    connection: Any,
    operation: Any,
    original: dict,
    document: dict,
    enrollment: dict,
    prior: dict | None,
    *,
    now_ms: int,
) -> None:
    from . import product_store_macos_file_access as macos

    if document.get("schema_version") == macos.PREPARATION_SCHEMA:
        macos.validate_preparation(operation, original, document, enrollment, prior, now_ms)
    elif prior is not None and macos.is_control(prior):
        raise ProductStoreError("Darwin provenance cannot authorize another platform preparation.")
    elif document.get("schema_version") == correction.PREPARATION_SCHEMA:
        if operation["operation"] != "harden" or prior is None:
            raise ProductStoreError("Correction preparation requires its original review.")
        journal.validate_preparation_at(
            store, connection, operation["job_id"], document, original, prior, now_ms=now_ms
        )
    elif windows.is_preparation(document):
        if operation["operation"] != "baseline" or prior is None:
            raise ProductStoreError("Windows preparation requires an original baseline operation.")
        windows.validate_preparation(document, original, prior, now_ms=now_ms)
    else:
        from .file_access_preparation import validate_preparation as validate_linux_preparation

        if prior is not None and windows.is_windows_control(prior):
            raise ProductStoreError("Windows provenance cannot authorize a Linux preparation.")
        validate_linux_preparation(document, original, enrollment, prior)
