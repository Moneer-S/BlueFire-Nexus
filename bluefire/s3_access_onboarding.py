"""Profile-bound S3 setup inspection using the existing managed runner lifecycle."""

import hashlib
from http import HTTPStatus
from typing import Any, Mapping

from .application_errors import APIError
from .contracts import ExecutionMode
from .runner_client import canonical_runner_inventory, runner_transport_identity
from .runner_lifecycle import RunnerLifecycleError
from .runner_transport import AuthenticatedRunnerClient
from .runner_transport_errors import RunnerTransportError
from .s3_access_admission import ACTION
from .s3_access_configuration import _identifier, _path, validate_configuration
from .s3_access_contract import S3AccessError, digest, document, exact
from .s3_access_profile import validate_s3_host_binding, validate_s3_profile_binding
from .s3_access_setup_status import _result, validate_status
from .util import content_hash

SCHEMA = "bluefire.s3-onboarding.v1"
CHECK_SCHEMA = "bluefire.s3-onboarding-check.v1"
DRAFT_SCHEMA = "bluefire.s3-onboarding-draft-review.v1"
MAX_DRAFT_BYTES = 128 * 1024


def _eligible(profile):
    return (
        profile.mode is ExecutionMode.EXECUTE
        and tuple(profile.platforms) == ("linux",)
        and "cloud.aws.s3.access" in profile.capabilities
        and ACTION in profile.enabled_actions
        and ACTION not in profile.blocked_actions
    )


def setup_profiles(service: Any) -> Mapping[str, Any]:
    """List active saved profiles only; do not connect, enroll, or inspect secrets."""
    profiles = sorted(
        (profile for profile in service._runner_profiles() if _eligible(profile)),
        key=lambda profile: profile.id,
    )
    return {
        "schema_version": SCHEMA,
        "profiles": [
            {"profile_id": profile.id, "profile_digest": content_hash(profile.to_dict())}
            for profile in profiles[:64]
        ],
        "truncated": len(profiles) > 64,
    }


def _selected(service, profile_id, expected):
    matches = [
        profile
        for profile in service._runner_profiles()
        if profile.id == profile_id and _eligible(profile)
    ]
    if len(matches) != 1 or content_hash(matches[0].to_dict()) != expected:
        raise APIError(
            HTTPStatus.CONFLICT,
            "s3_setup_profile_changed",
            "The selected S3 profile changed or is no longer active. Refresh setup and choose its current version.",
        )
    return matches[0]


def check_setup(service: Any, request: Mapping[str, Any]) -> Mapping[str, Any]:
    try:
        exact(request, {"profile_id", "profile_digest"}, "S3 setup check")
        profile_id = _identifier(request["profile_id"])
        expected = digest(request["profile_digest"])
    except (S3AccessError, KeyError, TypeError):
        raise APIError(
            HTTPStatus.BAD_REQUEST,
            "s3_setup_check_invalid",
            "Choose an unchanged saved Linux S3 profile.",
        ) from None
    profile = _selected(service, profile_id, expected)
    identity = None
    result = None
    try:
        client, sandbox = service.runner_lifecycle.client_for_profile(
            profile_id, profile_budget_seconds=profile.budgets.max_seconds
        )
        if not isinstance(client, AuthenticatedRunnerClient):
            raise S3AccessError("S3 setup requires authenticated transport")
        client.socket_timeout_seconds = 15.0
        before = client.inventory()
        canonical = canonical_runner_inventory(before)
        identity = runner_transport_identity(client, before)
        inspected = validate_status(client.s3_access_setup_status(), profile_id=profile_id)
        if inspected["configuration_state"] == "configured":
            environments = client.s3_access_environments()
            if {row["environment"]["environment_id"] for row in environments} != {
                row["environment_id"] for row in inspected["environments"]
            }:
                raise S3AccessError("S3 configuration changed during setup inspection")
            stale = False
            for row in environments:
                try:
                    validate_s3_host_binding(
                        row["profile"],
                        profile,
                        runner_id=identity["runner_id"],
                        sandbox=sandbox,
                    )
                except (ValueError, TypeError, KeyError):
                    stale = True
            if validate_status(client.s3_access_setup_status(), profile_id=profile_id) != inspected:
                raise S3AccessError("S3 configuration changed during setup inspection")
            if stale:
                inspected = _result(profile_id, "profile_changed", inspected["revision_digest"])
        after = client.inventory()
        if (
            canonical_runner_inventory(after) != canonical
            or runner_transport_identity(client, after) != identity
        ):
            raise S3AccessError("S3 runner changed during setup inspection")
        result = inspected
    except (
        RunnerLifecycleError,
        RunnerTransportError,
        OSError,
        TypeError,
        ValueError,
        RuntimeError,
    ):
        identity = None
    _selected(service, profile_id, expected)
    response = {
        "schema_version": CHECK_SCHEMA,
        "profile_id": profile_id,
        "profile_digest": expected,
        "host_state": "authenticated" if result is not None else "unavailable",
        "setup": result,
    }
    return {
        **response,
        "context_digest": content_hash({"response": response, "transport_identity": identity}),
    }


def _draft_profile(value, selected):
    # Browser draft intake is deliberately narrower than the native profile contract.
    validate_s3_profile_binding(value, selected)
    _identifier(value["runner_id"])
    _path(value["sandbox_root"])


def review_draft(service: Any, request: Mapping[str, Any]) -> Mapping[str, Any]:
    """Validate supplied nonsecret data only, without inspecting any host or path."""
    try:
        exact(request, {"profile_id", "profile_digest", "configuration_json"}, "S3 draft review")
        profile_id = _identifier(request["profile_id"])
        expected = digest(request["profile_digest"])
        text = request["configuration_json"]
        if not isinstance(text, str) or len(text) > MAX_DRAFT_BYTES:
            raise S3AccessError("S3 draft must be bounded JSON text")
        source = text.encode("utf-8")
        row = document(source, limit=MAX_DRAFT_BYTES)
    except (S3AccessError, KeyError, TypeError, UnicodeError):
        raise APIError(
            HTTPStatus.BAD_REQUEST,
            "s3_setup_draft_invalid",
            "Select a current profile and a bounded nonsecret S3 configuration document.",
        ) from None
    selected = _selected(service, profile_id, expected)
    try:
        row = validate_configuration(row, runner_id=row["runner_id"], profile_ids=(profile_id,))
        for entry in row["environments"]:
            _draft_profile(entry["profile"], selected)
    except (S3AccessError, KeyError, TypeError, ValueError):
        raise APIError(
            HTTPStatus.BAD_REQUEST,
            "s3_setup_draft_invalid",
            "The configuration must contain only the supported S3 scope, policy, dedicated profile and local runtime references. Credentials and extra fields are not accepted.",
        ) from None
    _selected(service, profile_id, expected)
    return {
        "schema_version": DRAFT_SCHEMA,
        "profile_id": profile_id,
        "profile_digest": expected,
        "validation_scope": "structural_only",
        "source_sha256": "sha256:" + hashlib.sha256(source).hexdigest(),
        "configuration_digest": content_hash(row),
        "environments": [
            {
                "environment_id": entry["environment_id"],
                "display_name": entry["display_name"],
                "account_id": entry["scope"]["account_id"],
                "region": entry["scope"]["region"],
                "bucket": entry["scope"]["bucket"],
                "expires_at": entry["scope"]["expires_at"],
                "fixture_generation": 2 if "fixture_lifecycle" in entry else 1,
            }
            for entry in row["environments"]
        ],
    }
