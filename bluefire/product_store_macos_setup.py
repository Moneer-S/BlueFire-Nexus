"""Canonical persisted Darwin setup and initial control documents."""

from typing import Any

from .capability_resources import exact
from .macos_file_access_contract import validate_binding
from .product_store_errors import ProductStoreError
from .util import content_hash

SETUP_SCHEMA = "bluefire.macos-file-access-setup.v1"
CONTROL_SCHEMA = "bluefire.macos-file-access-control.v1"


def require(value: bool) -> None:
    if not value:
        raise ProductStoreError("The original committed Darwin operation is unavailable.")


def is_control(value: Any) -> bool:
    return isinstance(value, dict) and value.get("schema_version") == CONTROL_SCHEMA


def setup_document(value: Any) -> dict:
    exact(value, {"schema_version", "binding"}, "Darwin setup")
    require(value["schema_version"] == SETUP_SCHEMA)
    binding = validate_binding(value["binding"])
    require(binding["control_revision"] == 1 and binding["mode"] == "0640")
    return {"schema_version": SETUP_SCHEMA, "binding": binding}


def enrollment_document(setup: dict) -> dict:
    binding = setup["binding"]
    return {
        "schema_version": "bluefire.macos-file-access-enrollment.v1",
        "enrollment_id": binding["enrollment_id"],
        "expires_at_ms": binding["expires_at_ms"],
        "setup": setup,
    }


def imported_control(setup: dict) -> dict:
    binding = setup["binding"]
    return {
        "schema_version": CONTROL_SCHEMA,
        "control_owner_id": "file-control-" + content_hash(setup)[7:],
        "enrollment_id": binding["enrollment_id"],
        "generation": binding["generation"],
        "revision": 1,
        "status": "created",
        "binding": binding,
        "binding_digest": content_hash(binding),
        "setup_digest": content_hash(setup),
        "baseline": None,
    }
