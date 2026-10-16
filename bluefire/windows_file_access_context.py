"""Protected Windows setup selection and the fixed paired baseline context."""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any, NoReturn

from . import windows_file_access_admission as admission
from . import windows_file_access_pair_admission as pair
from .file_access_contract import FileAccessContractError
from .product_store_errors import ProductStoreError
from .util import content_hash
from .windows_file_access_enrollment import (
    VerifiedWindowsSetup,
    WindowsEnrollmentUnavailable,
    read_windows_file_access_enrollment,
    read_windows_file_setup_status,
)
from .windows_file_access_pair_admission import VerifiedWindowsPairSetup


def enrollment(service: Any, now_ms: int) -> VerifiedWindowsSetup:
    return read_windows_file_access_enrollment(now_ms=now_ms)


def execution(service: Any, enrolled: Any) -> NoReturn:
    raise WindowsEnrollmentUnavailable("windows_native_admission_unavailable")


def binding(enrolled: Any, *, revision: int, now_ms: int) -> NoReturn:
    raise WindowsEnrollmentUnavailable("windows_protected_setup_unavailable")


def import_setup(service: Any, request: Any, now_ms: int) -> dict[str, Any]:
    from .product_store_windows_file_access import at, document

    selected = admission.selected(request)
    store = service.product_store
    with store._connection() as connection:
        row = at(connection, enrollment_id=selected["enrollment_id"])
        previous = None if row is None else document(row)
    if previous is not None:
        if content_hash(previous["enrollment"]) != selected["enrollment_digest"]:
            raise ProductStoreError("The selected protected setup differs from saved provenance.")
        return projection(service, previous, now_ms)
    checked = read_windows_file_setup_status(now_ms=now_ms)
    if type(checked) is VerifiedWindowsPairSetup:
        saved = store.import_windows_file_access_pair_setup(
            checked, selection=selected, now_ms=now_ms
        )
    elif type(checked) is VerifiedWindowsSetup:
        saved = store.import_windows_file_access_setup(checked, selection=selected, now_ms=now_ms)
    else:
        raise ProductStoreError("The original protected setup is unavailable.")
    return projection(service, saved, now_ms)


def is_control(document: Any) -> bool:
    return document.get("schema_version") in (
        admission.IMPORT_SCHEMA,
        pair.IMPORT_SCHEMA,
        "bluefire.windows-file-access-control-record.v2",
        "bluefire.windows-file-access-control-record.v3",
    )


def _clock() -> datetime:
    return datetime.now(timezone.utc)


def projection(service: Any, document: Any, now_ms: int) -> dict[str, Any]:
    owner = document["control_owner_id"]
    if document["schema_version"] == admission.IMPORT_SCHEMA:
        return dict(service.product_store.windows_file_access_setup_projection(owner))
    if document["schema_version"] in (
        "bluefire.windows-file-access-control-record.v2",
        "bluefire.windows-file-access-control-record.v3",
    ):
        from .windows_file_access_correction_projection import projection as correction_projection

        return correction_projection(service.product_store, owner, clock=_clock())
    result = dict(
        service.product_store.windows_file_access_pair_control_projection(owner, clock=_clock())
    )
    result["schema_version"] = "bluefire.windows-file-access-control.v2"
    result["operations"] = [
        job
        for job in service.product_store.list_jobs()
        if job["kind"] == "file_access.operation"
        and job["request"].get("control_owner_id") == owner
    ]
    if result["task_usage_state"] == "unresolved":
        result["status"] = "uncertain"
    elif (
        result["task_usage_state"] == "none"
        and not result["operations"]
        and now_ms < result["expires_at_ms"]
    ):
        result["allowed_operations"] = ["baseline"]
    return result


def baseline_context(service: Any, now_ms: int, owner_id: str) -> dict[str, Any]:
    checked = read_windows_file_setup_status(now_ms=now_ms)
    if type(checked) is not VerifiedWindowsPairSetup:
        raise WindowsEnrollmentUnavailable("windows_native_admission_unavailable")
    control = service.product_store.get_file_access_control(owner_id)
    if control["document"].get("schema_version") != pair.IMPORT_SCHEMA:
        raise ProductStoreError("Only an original paired Windows setup can review a baseline.")
    record, _ = pair.checked_provenance(checked)
    selected = {"enrollment_id": record["enrollment_id"], "enrollment_digest": content_hash(record)}
    imported = service.product_store.get_windows_file_access_pair_import(selected)
    if imported is None or imported["control_owner_id"] != owner_id:
        raise ProductStoreError(
            "Import this exact protected paired setup before reviewing a baseline."
        )
    if imported != pair.import_document(checked, now_ms=imported["imported_at_ms"]):
        raise ProductStoreError("The original protected paired setup changed.")
    if control["document"] != imported:
        raise ProductStoreError("This paired baseline has already advanced or is unresolved.")
    context = pair.baseline_context(imported)
    return {
        "_checked": checked,
        "control": control,
        "enrollment": {"document": record, "document_digest": content_hash(record)},
        "context_digest": content_hash(context),
        "review_context": context,
        "expires_at_ms": record["expires_at_ms"],
        "allowed_operations": ["baseline"],
    }


def correction_context(
    service: Any, now_ms: int, owner_id: str, *, _original_job_id: str | None = None
) -> dict[str, Any]:
    """Fresh readable preimage plus the exact retained successful paired baseline."""
    from . import product_store_windows_correction as journal
    from . import windows_file_access_correction_admission as correction
    from . import windows_file_access_correction_observation as observation

    checked = read_windows_file_setup_status(now_ms=now_ms)
    if type(checked) is not VerifiedWindowsPairSetup:
        raise WindowsEnrollmentUnavailable("windows_native_admission_unavailable")
    record, _ = pair.checked_provenance(checked)
    control = service.product_store.get_file_access_control(owner_id)
    selected = {"enrollment_id": record["enrollment_id"], "enrollment_digest": content_hash(record)}
    imported = service.product_store.get_windows_file_access_pair_import(selected)
    if (
        imported is None
        or imported["control_owner_id"] != owner_id
        or imported != pair.import_document(checked, now_ms=imported["imported_at_ms"])
    ):
        raise ProductStoreError("The original protected paired setup changed.")
    descriptor = observation.observe_correction_preimage(
        checked,
        now_ms=now_ms,
        deadline=time.monotonic() + min(5000, record["expires_at_ms"] - now_ms) / 1000,
        cancelled=lambda: False,
    )
    context = correction.correction_context(imported, control["document"], descriptor)
    with service.product_store._connection() as connection:
        journal.validate_review(
            service.product_store,
            connection,
            control["document"],
            context,
            now_ms=now_ms,
            original_job_id=_original_job_id,
        )
    return {
        "_checked": checked,
        "_imported": imported,
        "control": control,
        "enrollment": {"document": record, "document_digest": content_hash(record)},
        "context_digest": content_hash(context),
        "review_context": context,
        "expires_at_ms": record["expires_at_ms"],
        "allowed_operations": ["harden"],
    }


def status(service: Any, now_ms: int) -> dict[str, Any]:
    try:
        checked = read_windows_file_setup_status(now_ms=now_ms)
    except FileAccessContractError:
        return {
            "schema_version": "bluefire.file-access-status.v1",
            "available": False,
            "problem": {
                "code": "windows_file_access_enrollment_unavailable",
                "message": "Verified Windows protected setup and native admission are required.",
            },
            "enrollment": None,
            "allowed_operations": [],
        }
    if type(checked) not in (VerifiedWindowsSetup, VerifiedWindowsPairSetup):
        raise FileAccessContractError("Windows protected setup observation is unavailable.")
    if type(checked) is VerifiedWindowsPairSetup:
        pair.checked_provenance(checked)
        return {
            "schema_version": "bluefire.file-access-status.v1",
            "available": True,
            "problem": None,
            "enrollment": None,
            "setup": checked.summary(),
            "allowed_operations": [],
        }
    return {
        "schema_version": "bluefire.file-access-status.v1",
        "available": False,
        "problem": {
            "code": "windows_native_admission_unavailable",
            "message": "Protected Windows setup is verified. Native task admission is not yet available.",
        },
        # The existing v1 enrollment UI is Linux-UID-specific. Never synthesize
        # UIDs or expose the resource/account/credential documents to that view.
        "enrollment": None,
        "setup": checked.summary(),
        "allowed_operations": [],
    }
