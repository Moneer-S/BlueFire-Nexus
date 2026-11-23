"""Integrity-checked readers for persisted file-access records."""

import json

from .product_store_errors import ProductStoreError
from .product_store_macos_setup import (
    imported_control,
    is_control,
    require,
    setup_document,
)
from .util import content_hash


def _document(row):
    if row is None:
        raise ProductStoreError("The retained file-access record is unavailable.")
    try:
        value = json.loads(row["document_json"])
        if not isinstance(value, dict) or content_hash(value) != row["document_digest"]:
            raise ValueError("digest")
        return value
    except (ValueError, TypeError, KeyError) as exc:
        raise ProductStoreError(
            "The retained file-access record failed integrity verification."
        ) from exc


def imported_at(connection, owner_id):
    row = connection.execute(
        "SELECT * FROM file_access_setup_imports WHERE control_owner_id=?", (owner_id,)
    ).fetchone()
    if row is None:
        return None
    value = _document(row)
    if not is_control(value):
        return None
    require(
        value["control_owner_id"] == row["control_owner_id"]
        and value["enrollment_id"] == row["enrollment_id"]
        and value["generation"] == row["generation"]
        and value["revision"] == 1
    )
    enrolled = _document(
        connection.execute(
            "SELECT * FROM file_access_enrollments WHERE enrollment_id=?", (row["enrollment_id"],)
        ).fetchone()
    )
    require(value == imported_control(setup_document(enrolled["setup"])))
    return {"document": value, "document_digest": row["document_digest"]}


def _control_at(connection, owner_id):
    row = connection.execute(
        "SELECT * FROM file_access_revisions WHERE control_owner_id=? ORDER BY revision DESC LIMIT 1",
        (owner_id,),
    ).fetchone()
    if row is None:
        darwin = imported_at(connection, owner_id)
        if darwin is not None:
            return darwin
        from . import product_store_windows_file_access as windows

        imported = windows.at(connection, owner_id=owner_id)
        document = windows.document(imported)
        return {"document": document, "document_digest": imported["document_digest"]}
    document = _document(row)
    if document["control_owner_id"] != owner_id or document["revision"] != row["revision"]:
        raise ProductStoreError("The retained file control lineage changed.")
    return {"document": document, "document_digest": row["document_digest"]}


def _pending(connection, owner_id):
    rows = connection.execute(
        "SELECT o.job_id,r.document_json,r.document_digest FROM file_access_operations o "
        "LEFT JOIN file_access_outcomes r ON r.sequence=(SELECT MAX(sequence) FROM file_access_outcomes WHERE job_id=o.job_id) WHERE o.control_owner_id=?",
        (owner_id,),
    ).fetchall()
    return any(
        row["document_json"] is None
        or _document(row)["state"] not in ("complete", "settled_partial", "refused_no_effect")
        for row in rows
    )


def _outcome_at(connection, job_id):
    return connection.execute(
        "SELECT * FROM file_access_outcomes WHERE job_id=? ORDER BY sequence DESC LIMIT 1",
        (job_id,),
    ).fetchone()


def guard_control(store, connection, grant):
    environment = grant["environment"]
    view = _control_at(connection, environment["control_owner_id"])
    control = view["document"]
    if (
        view["document_digest"] != environment["control_digest"]
        or control["status"] != "hardened"
        or control["revision"] != environment["control_revision"]
        or content_hash(control["binding"]["resource"]) != environment["resource_digest"]
        or control["binding"]["resource_generation"] != environment["resource_generation"]
        or control["binding"]["resource_id"] != environment["resource_id"]
        or control["binding"]["enrollment_digest"] != environment["probe_enrollment_digest"]
        or control["baseline"]["baseline_digest"] != environment["baseline_digest"]
        or _pending(connection, environment["control_owner_id"])
    ):
        raise ProductStoreError("The exact hardened retained file control is unavailable.")
