"""Closed RunnerTransport helpers for owned-service request envelopes."""

from __future__ import annotations

import inspect
from typing import Any, Callable, Mapping, cast

from .owned_service_authority import (
    ADMISSION_SCHEMA,
    ADMISSION_SCHEMA_V2,
    GRANT_SCHEMA,
    GRANT_SCHEMA_V2,
    SERVICE_ACTION_ID,
    OwnedServiceAdmission,
    OwnedServiceAuthorityError,
    OwnedServiceGrant,
    validate_owned_service_grant_for_request,
)
from .runner_transport_errors import RunnerAuthenticationError, RunnerTransportError
from .util import content_hash


def service_grant_from_payload(
    payload: Mapping[str, Any],
    *,
    manifest: Mapping[str, Any],
    profile: Mapping[str, Any],
    task_id: str,
    check_expiry: bool = True,
) -> OwnedServiceGrant:
    if set(payload) != {"manifest", "profile", "owned_service_grant"}:
        raise OwnedServiceAuthorityError("service payload has an unsupported shape")
    grant = OwnedServiceGrant.from_mapping(payload["owned_service_grant"])
    validate_owned_service_grant_for_request(
        grant,
        manifest=manifest,
        profile=profile,
        task_id=task_id,
        check_expiry=check_expiry,
    )
    return grant


def prepare_client_service_payload(
    manifest: Mapping[str, Any],
    profile: Mapping[str, Any],
    grant_value: Any,
    *,
    task_id: str,
) -> tuple[dict[str, Any], str]:
    grant = (
        grant_value
        if isinstance(grant_value, OwnedServiceGrant)
        else OwnedServiceGrant.from_mapping(grant_value)
    )
    validate_owned_service_grant_for_request(
        grant, manifest=manifest, profile=profile, task_id=task_id
    )
    payload = {
        "manifest": dict(manifest),
        "profile": dict(profile),
        "owned_service_grant": grant.to_dict(),
    }
    return payload, content_hash(payload)


def stored_execute_payload(
    row: Mapping[str, Any],
    *,
    decode_object: Callable[[bytes], dict[str, Any]],
    execution_identity: Callable[[Mapping[str, Any], Mapping[str, Any]], tuple[str, str]],
    legacy_task_id: Callable[[str], str],
) -> tuple[dict[str, Any], dict[str, Any], OwnedServiceGrant | None]:
    raw = row.get("execute_payload_json")
    if not isinstance(raw, bytes):
        raise RunnerTransportError("runner execution manifest is unavailable")
    decoded = decode_object(raw)
    service_request = "owned_service_grant" in decoded
    if set(decoded) != (
        {"manifest", "profile", "owned_service_grant"}
        if service_request
        else {"manifest", "profile"}
    ):
        raise RunnerTransportError("runner execution manifest is invalid")
    manifest = decoded.get("manifest")
    profile = decoded.get("profile")
    if not isinstance(manifest, dict) or not isinstance(profile, dict):
        raise RunnerTransportError("runner execution manifest is invalid")
    if (
        content_hash(decoded) != row.get("request_hash")
        or profile.get("profile_id") != row.get("profile_id")
        or profile.get("runner_id") != row.get("runner_id")
        or manifest.get("runner_id") != row.get("runner_id")
        or manifest.get("runner_profile_id") != row.get("profile_id")
        or manifest.get("platform") != profile.get("platform")
        or manifest.get("policy_digest") != profile.get("policy_digest")
    ):
        raise RunnerTransportError("runner execution manifest identity is invalid")
    grant: OwnedServiceGrant | None = None
    if not service_request and manifest.get("action_id") == SERVICE_ACTION_ID:
        raise RunnerTransportError("runner service grant is missing from its execute payload")
    if service_request:
        try:
            grant = service_grant_from_payload(
                decoded,
                manifest=manifest,
                profile=profile,
                task_id=str(row.get("task_id")),
                check_expiry=False,
            )
            expected_task_id, _base_hash = execution_identity(manifest, profile)
        except (OwnedServiceAuthorityError, RunnerAuthenticationError):
            raise RunnerTransportError("runner service grant identity is invalid") from None
        if str(row.get("task_id")) != expected_task_id:
            raise RunnerTransportError("runner service task identity is invalid")
    elif row.get("task_id") != legacy_task_id(str(row.get("request_hash"))):
        raise RunnerTransportError("runner execution task identity is invalid")
    return manifest, profile, grant


def validate_execute_task_identity(
    payload: Mapping[str, Any],
    *,
    task_id: str,
    request_hash: str,
    execution_identity: Callable[[Mapping[str, Any], Mapping[str, Any]], tuple[str, str]],
    legacy_task_id: Callable[[str], str],
) -> None:
    if "owned_service_grant" not in payload:
        manifest = payload.get("manifest")
        if isinstance(manifest, dict) and manifest.get("action_id") == SERVICE_ACTION_ID:
            raise ValueError("request_invalid")
        if task_id != legacy_task_id(request_hash):
            raise ValueError("request_invalid")
        return
    if set(payload) != {"manifest", "profile", "owned_service_grant"}:
        raise ValueError("request_invalid")
    manifest, profile = payload.get("manifest"), payload.get("profile")
    if not isinstance(manifest, dict) or not isinstance(profile, dict):
        raise ValueError("request_invalid")
    expected_task_id, _base_hash = execution_identity(manifest, profile)
    if task_id != expected_task_id:
        raise ValueError("request_invalid")


def make_authenticated_admission(
    runner: Any,
    grant: OwnedServiceGrant,
    *,
    execute_task: Any,
    issuer: Mapping[str, Any],
) -> OwnedServiceAdmission:
    if not callable(execute_task):
        raise OwnedServiceAuthorityError("runner does not expose task execution")
    try:
        parameters: Mapping[str, inspect.Parameter] = inspect.signature(execute_task).parameters
    except (TypeError, ValueError):
        parameters = {}
    parameter = parameters.get("owned_service_admission")
    expected_protocol = {
        GRANT_SCHEMA: ADMISSION_SCHEMA,
        GRANT_SCHEMA_V2: ADMISSION_SCHEMA_V2,
    }[grant.to_dict()["schema_version"]]
    if (
        getattr(runner, "owned_service_admission_protocol", None) != expected_protocol
        or parameter is None
        or parameter.kind
        not in {inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.KEYWORD_ONLY}
    ):
        raise OwnedServiceAuthorityError(
            "runner has no authenticated service admission for the reviewed version"
        )
    return OwnedServiceAdmission.create(grant, issuer=issuer)


def authenticated_service_issuer(
    enrollment_identity: Mapping[str, str], server_instance_id: str
) -> dict[str, str]:
    return {
        key: enrollment_identity[key]
        for key in ("runner_id", "client_id", "enrollment_generation", "peer_fingerprint")
    } | {"server_instance_id": server_instance_id}


def execute_owned_service_request(
    client: Any,
    payload: Mapping[str, Any],
    *,
    task_id: str,
    request_hash: str,
    remote_error: type[BaseException],
    connection_error: type[BaseException],
    cancelled_error: type[BaseException],
    timed_out_error: type[BaseException],
) -> Mapping[str, Any]:
    client._last_execution = (task_id, request_hash)
    try:
        response = client._call("execute", payload, task_id=task_id, request_hash=request_hash)
        return cast(Mapping[str, Any], client._execution_result(response))
    except remote_error as exc:
        code = getattr(exc, "code", None)
        if code == "task_cancelled":
            raise cancelled_error(
                "Runner task was cancelled after its process tree stopped."
            ) from exc
        if code == "task_timed_out":
            raise timed_out_error("Runner task timed out after its process tree stopped.") from exc
        if code != "duplicate_request":
            raise
        return cast(Mapping[str, Any], client._recovered_execution(task_id, request_hash))
    except connection_error:
        return cast(
            Mapping[str, Any],
            client._recover_after_connection_loss(payload, task_id, request_hash),
        )
