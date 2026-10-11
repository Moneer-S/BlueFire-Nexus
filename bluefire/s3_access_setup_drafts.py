"""Saved nonsecret setup inputs, never installation, readiness or authority."""

from http import HTTPStatus
from typing import Any, Mapping

from .application_errors import APIError
from .product_store_contracts import safe_document, stable_identifier
from .product_store_errors import ProductStoreError, ResourceConflictError
from .s3_access_configuration import _identifier, validate_configuration
from .s3_access_contract import S3AccessError, digest, document, exact, timestamp
from .s3_access_onboarding import MAX_DRAFT_BYTES, review_draft
from .util import content_hash, json_clone

KIND = "s3_setup_draft"
SCHEMA = "bluefire.s3-saved-setup-draft.v1"


def _key(value: Any) -> str:
    return stable_identifier(_identifier(value), "S3 profile")


def _source(profile_id: str, text: Any) -> str:
    if not isinstance(text, str) or len(text) > MAX_DRAFT_BYTES:
        raise S3AccessError("Saved setup source must be bounded JSON text")
    row = document(text, limit=MAX_DRAFT_BYTES)
    checked = validate_configuration(row, runner_id=row["runner_id"], profile_ids=(profile_id,))
    retained = json_clone(checked)
    # The validator derives this exact nonsecret filename. All other fields still
    # receive the product store's recursive plaintext-credential checks.
    for entry in retained["environments"]:
        del entry["credential_reference"]
    safe_document(retained, context="S3 setup draft")
    return text


def _saved(resource: Mapping[str, Any], profile_id: str) -> Mapping[str, Any]:
    row = exact(
        resource["document"],
        {"schema_version", "profile_id", "profile_digest", "configuration_json"},
        "saved setup draft",
    )
    if (
        resource["kind"] != KIND
        or resource["id"] != profile_id
        or resource["status"] != "draft"
        or row["schema_version"] != SCHEMA
        or row["profile_id"] != profile_id
        or resource["digest"] != content_hash(row)
    ):
        raise S3AccessError("Saved setup draft identity changed")
    digest(row["profile_digest"])
    _source(profile_id, row["configuration_json"])
    timestamp(resource["updated_at"])
    return {
        "profile_id": profile_id,
        "profile_digest": row["profile_digest"],
        "configuration_json": row["configuration_json"],
        "digest": resource["digest"],
        "updated_at": resource["updated_at"],
    }


def _unavailable() -> APIError:
    return APIError(
        HTTPStatus.CONFLICT,
        "s3_setup_draft_unavailable",
        "The saved configuration could not be read safely. Its stored data is unchanged.",
    )


def read_saved_draft(service: Any, profile_id: str) -> Mapping[str, Any]:
    """Read stale bindings as editable data without inspecting the current host."""
    try:
        key = _key(profile_id)
        resource = service.product_store.find_resource(KIND, key)
        saved = _saved(resource, key) if resource is not None else None
    except (ProductStoreError, S3AccessError, KeyError, TypeError, ValueError):
        raise _unavailable() from None
    return {"schema_version": SCHEMA, "draft": saved}


def save_draft(service: Any, request: Mapping[str, Any]) -> Mapping[str, Any]:
    try:
        exact(
            request,
            {"profile_id", "profile_digest", "configuration_json", "expected_digest"},
            "save setup draft",
        )
        key = _key(request["profile_id"])
        expected = request["expected_digest"]
        if expected is not None:
            digest(expected)
        selected = {
            name: request[name] for name in ("profile_id", "profile_digest", "configuration_json")
        }
        review_draft(service, selected)
        _source(key, selected["configuration_json"])
        payload = {"schema_version": SCHEMA, **selected}
        saved = service.product_store.save_resource(
            KIND,
            key,
            payload,
            status="draft",
            replace_existing=expected is not None,
            expected_digest=expected,
        )
        if saved["document"] != payload:
            raise ResourceConflictError("A different draft already exists")
        return {"schema_version": SCHEMA, "draft": _saved(saved, key)}
    except ResourceConflictError:
        raise APIError(
            HTTPStatus.CONFLICT,
            "s3_setup_draft_changed",
            "The saved draft changed in another window. Your current inputs are unchanged; reload the saved version before replacing it.",
        ) from None
    except (ProductStoreError, S3AccessError, KeyError, TypeError, ValueError):
        raise APIError(
            HTTPStatus.BAD_REQUEST,
            "s3_setup_draft_invalid",
            "Only a structurally valid nonsecret configuration for the selected current profile can be saved.",
        ) from None
