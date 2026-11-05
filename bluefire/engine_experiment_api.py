"""Strict local HTTP routing for external-engine experiments.

The authenticated loopback HTTP shell owns browser-session, origin, host, body,
and JSON parsing checks.  This module only recognizes canonical experiment
paths and forwards exact request envelopes to the injected controller service.
It deliberately exposes no endpoint for minting independent observations,
publishing engine artifacts, or selecting executable content.
"""

from __future__ import annotations

import re
from http import HTTPStatus
from typing import Any, Mapping
from urllib.parse import parse_qsl, urlsplit

from .api_context import API_PREFIX, EngineExperimentAPIService
from .application_errors import APIError
from .engine_action_preparation import EngineWorkspaceAction
from .engine_experiment_service import EngineExperimentServiceError

_EXPERIMENT_ID = re.compile(r"^experiment-[0-9a-f]{32}$")
_ATTEMPT_ID = re.compile(r"^engine-attempt-[0-9a-f]{32}$")
_CHECK_ID = re.compile(r"^controller-check-[0-9a-f]{32}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_APPROVAL_ID = re.compile(r"^approval-[0-9a-f]{32}$")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")

_CREATE_FIELDS = frozenset(
    {
        "schema_version",
        "experiment_id",
        "objective_ref",
        "environment_ref",
        "scope_ref",
        "scope_version",
        "target_snapshot_ref",
    }
)
_ATTEMPT_FIELDS = frozenset(
    {
        "schema_version",
        "experiment_id",
        "binding",
        "delegation",
        "approval_binding",
        "approval_id",
        "approval_nonce",
        "approved_by",
        "submission_id",
        "intent_digest",
        "expected_revision",
        "expected_digest",
    }
)
_TRANSITION_FIELDS = frozenset(
    {"schema_version", "expected_revision", "expected_digest", "action", "request_ref"}
)
_CONTROLLER_JOB_FIELDS = frozenset(
    {
        "schema_version",
        "expected_revision",
        "expected_digest",
        "action",
        "request_ref",
        "submission_id",
        "intent_digest",
    }
)
_ASSISTANCE_SELECTION_FIELDS = frozenset(
    {"kind", "experiment_id", "workspace_digest", "attempt_id", "check_id"}
)
_ACTION_PREPARE_FIELDS = frozenset(
    {"schema_version", "expected_revision", "expected_digest", "workspace_digest"}
)
_ACTION_PREPARE_V2_FIELDS = frozenset((*_ACTION_PREPARE_FIELDS, "action_kind"))
_ACTION_SUBMIT_FIELDS = frozenset({"schema_version", "preparation_id", "protected_request_ref"})

_DEFENSE_ROUTES = {
    "review": ("transition", "review_defense"),
    "retain": ("transition", "retain_defense"),
    "apply": ("controller-job", "apply_defense"),
    "reconcile": ("controller-job", "reconcile_defense"),
    "rollback": ("controller-job", "rollback_defense"),
    "rollback-reconcile": ("controller-job", "reconcile_rollback"),
}
_CHECK_ROLES = frozenset({"retained-reproducer", "legitimate-use"})
_CHECK_ACTIONS = {
    "run": "run",
    "recover": "reconcile",
}
_SERVICE_STATUS = {
    "engine_request_invalid": HTTPStatus.BAD_REQUEST,
    "engine_selection_not_found": HTTPStatus.NOT_FOUND,
    "engine_experiment_conflict": HTTPStatus.CONFLICT,
    "engine_execution_refused": HTTPStatus.CONFLICT,
    "engine_controller_refused": HTTPStatus.CONFLICT,
    "engine_authority_refused": HTTPStatus.CONFLICT,
    "engine_experiment_refused": HTTPStatus.CONFLICT,
    "engine_workspace_unavailable": HTTPStatus.CONFLICT,
    "engine_evidence_unavailable": HTTPStatus.CONFLICT,
    "engine_job_unavailable": HTTPStatus.CONFLICT,
    "engine_experiment_unavailable": HTTPStatus.CONFLICT,
    "engine_assistance_context_unavailable": HTTPStatus.CONFLICT,
    "engine_action_unavailable": HTTPStatus.CONFLICT,
    "engine_action_preparation_refused": HTTPStatus.CONFLICT,
    "engine_action_submission_refused": HTTPStatus.CONFLICT,
    "engine_action_stale": HTTPStatus.CONFLICT,
}


def _request_error(handler: Any, message: str) -> None:
    handler._error(HTTPStatus.BAD_REQUEST, "engine_experiment_invalid", message)


def _service_call(callback: Any) -> Mapping[str, Any]:
    try:
        result = callback()
    except EngineExperimentServiceError as exc:
        status = _SERVICE_STATUS.get(exc.code)
        if status is None:
            raise APIError(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                "engine_service_error",
                "The engine experiment service could not complete the request.",
            ) from exc
        raise APIError(status, exc.code, str(exc)) from exc
    if not isinstance(result, Mapping):
        raise APIError(
            HTTPStatus.INTERNAL_SERVER_ERROR,
            "invalid_service_response",
            "The engine experiment service returned an invalid response.",
        )
    return result


def _workspace_selection(
    handler: Any,
) -> tuple[bool, str | None, str | None]:
    parsed = urlsplit(handler.path)
    if parsed.fragment or len(parsed.query) > 96:
        _request_error(handler, "Workspace selection is invalid.")
        return False, None, None
    if not parsed.query:
        return True, None, None
    try:
        pairs = parse_qsl(
            parsed.query,
            keep_blank_values=True,
            strict_parsing=True,
            max_num_fields=1,
        )
    except ValueError:
        _request_error(handler, "Select one canonical workspace item.")
        return False, None, None
    if len(pairs) != 1:
        _request_error(handler, "Select one canonical workspace item.")
        return False, None, None
    key, value = pairs[0]
    valid = (
        key == "attempt"
        and _ATTEMPT_ID.fullmatch(value) is not None
        or key == "check"
        and _CHECK_ID.fullmatch(value) is not None
    )
    if not valid or parsed.query != f"{key}={value}":
        _request_error(handler, "Workspace selection is invalid.")
        return False, None, None
    return True, value if key == "attempt" else None, value if key == "check" else None


def _text(value: Any, *, maximum: int) -> bool:
    return (
        isinstance(value, str)
        and value == value.strip()
        and 1 <= len(value) <= maximum
        and all(ord(character) >= 32 and ord(character) != 127 for character in value)
    )


def _revision(value: Any) -> bool:
    return not isinstance(value, bool) and isinstance(value, int) and 1 <= value <= 10_000


def _valid_create_request(value: Mapping[str, Any]) -> bool:
    return (
        set(value) == _CREATE_FIELDS
        and value.get("schema_version") == "bluefire.engine-experiment-create.v1"
        and isinstance(value.get("experiment_id"), str)
        and _EXPERIMENT_ID.fullmatch(value["experiment_id"]) is not None
        and all(
            isinstance(value.get(field), str) and _DIGEST.fullmatch(value[field]) is not None
            for field in (
                "objective_ref",
                "environment_ref",
                "scope_ref",
                "target_snapshot_ref",
            )
        )
        and value.get("scope_version") == "bluefire.engine-capability-delegation.v1"
    )


def _valid_attempt_request(value: Mapping[str, Any]) -> bool:
    return (
        set(value) == _ATTEMPT_FIELDS
        and value.get("schema_version") == "bluefire.engine-attempt-submit.v1"
        and isinstance(value.get("experiment_id"), str)
        and _EXPERIMENT_ID.fullmatch(value["experiment_id"]) is not None
        and all(
            isinstance(value.get(field), Mapping)
            for field in ("binding", "delegation", "approval_binding")
        )
        and isinstance(value.get("approval_id"), str)
        and _APPROVAL_ID.fullmatch(value["approval_id"]) is not None
        and _text(value.get("approval_nonce"), maximum=200)
        and _text(value.get("approved_by"), maximum=128)
        and isinstance(value.get("submission_id"), str)
        and _UUID.fullmatch(value["submission_id"]) is not None
        and all(
            isinstance(value.get(field), str) and _DIGEST.fullmatch(value[field]) is not None
            for field in ("intent_digest", "expected_digest")
        )
        and _revision(value.get("expected_revision"))
    )


def _valid_transition_request(value: Mapping[str, Any]) -> bool:
    return (
        set(value) == _TRANSITION_FIELDS
        and value.get("schema_version") == "bluefire.engine-controller-transition.v1"
        and _text(value.get("action"), maximum=80)
        and _revision(value.get("expected_revision"))
        and all(
            isinstance(value.get(field), str) and _DIGEST.fullmatch(value[field]) is not None
            for field in ("expected_digest", "request_ref")
        )
    )


def _valid_controller_job_request(value: Mapping[str, Any]) -> bool:
    return (
        set(value) == _CONTROLLER_JOB_FIELDS
        and value.get("schema_version") == "bluefire.engine-controller-job-submit.v1"
        and _text(value.get("action"), maximum=80)
        and _revision(value.get("expected_revision"))
        and isinstance(value.get("submission_id"), str)
        and _UUID.fullmatch(value["submission_id"]) is not None
        and all(
            isinstance(value.get(field), str) and _DIGEST.fullmatch(value[field]) is not None
            for field in ("expected_digest", "request_ref", "intent_digest")
        )
    )


def _valid_assistance_selection(value: Mapping[str, Any]) -> bool:
    attempt_id = value.get("attempt_id")
    check_id = value.get("check_id")
    return (
        set(value) == _ASSISTANCE_SELECTION_FIELDS
        and value.get("kind") == "engine_experiment"
        and isinstance(value.get("experiment_id"), str)
        and _EXPERIMENT_ID.fullmatch(value["experiment_id"]) is not None
        and isinstance(value.get("workspace_digest"), str)
        and _DIGEST.fullmatch(value["workspace_digest"]) is not None
        and (
            attempt_id is None
            or isinstance(attempt_id, str)
            and _ATTEMPT_ID.fullmatch(attempt_id) is not None
        )
        and (
            check_id is None
            or isinstance(check_id, str)
            and _CHECK_ID.fullmatch(check_id) is not None
        )
        and not (attempt_id is not None and check_id is not None)
    )


def _valid_action_prepare_request(value: Mapping[str, Any]) -> bool:
    schema = value.get("schema_version")
    if schema == "bluefire.engine-action-prepare-request.v1":
        fields_valid = set(value) == _ACTION_PREPARE_FIELDS
    elif schema == "bluefire.engine-action-prepare-request.v2":
        fields_valid = (
            set(value) == _ACTION_PREPARE_V2_FIELDS
            and isinstance(value.get("action_kind"), str)
            and value["action_kind"] in {action.value for action in EngineWorkspaceAction}
        )
    else:
        fields_valid = False
    return (
        fields_valid
        and _revision(value.get("expected_revision"))
        and all(
            isinstance(value.get(field), str) and _DIGEST.fullmatch(value[field]) is not None
            for field in ("expected_digest", "workspace_digest")
        )
    )


def _valid_action_submit_request(value: Mapping[str, Any]) -> bool:
    return (
        set(value) == _ACTION_SUBMIT_FIELDS
        and value.get("schema_version") == "bluefire.engine-action-submit.v1"
        and all(
            isinstance(value.get(field), str) and _DIGEST.fullmatch(value[field]) is not None
            for field in ("preparation_id", "protected_request_ref")
        )
    )


def _parse_suffix(suffix: str) -> tuple[str, tuple[str, ...]] | None:
    if suffix == "":
        return "collection", ()
    parts = suffix.split("/")
    if not parts or _EXPERIMENT_ID.fullmatch(parts[0]) is None:
        return None
    experiment_id = parts[0]
    if len(parts) == 1:
        return "read", (experiment_id,)
    if parts[1:] == ["workspace"]:
        return "workspace", (experiment_id,)
    if parts[1:] == ["assistant-context"]:
        return "assistant-context", (experiment_id,)
    if parts[1:] == ["actions", "prepare"]:
        return "prepare-action", (experiment_id,)
    if parts[1:] == ["actions", "submit"]:
        return "submit-prepared-action", (experiment_id,)
    if parts[1:] == ["attempts"]:
        return "submit-attempt", (experiment_id,)
    if (
        len(parts) == 4
        and parts[1] == "attempts"
        and _ATTEMPT_ID.fullmatch(parts[2]) is not None
        and parts[3] == "recover"
    ):
        return "recover-attempt", (experiment_id, parts[2])
    if len(parts) == 3 and parts[1] == "defense" and parts[2] in _DEFENSE_ROUTES:
        operation, action = _DEFENSE_ROUTES[parts[2]]
        return operation, (experiment_id, action)
    if (
        len(parts) == 4
        and parts[1] == "checks"
        and parts[2] in _CHECK_ROLES
        and parts[3] in _CHECK_ACTIONS
    ):
        role = parts[2].replace("-", "_")
        action = _CHECK_ACTIONS[parts[3]]
        return "controller-job", (experiment_id, f"{action}_{role}")
    return None


def dispatch_engine_experiments(
    handler: Any,
    path: str,
    body: Mapping[str, Any] | None = None,
) -> bool:
    """Dispatch one canonical engine-experiment route.

    ``False`` means the path does not belong to this route family.  A recognized
    but invalid path is consumed with a stable 400 response so it cannot fall
    through to another handler.
    """

    root = f"{API_PREFIX}/engine-experiments"
    if path != root and not path.startswith(root + "/"):
        return False
    if urlsplit(handler.path).path != path:
        _request_error(handler, "Use the exact saved engine experiment path.")
        return True

    if path == root + "/":
        _request_error(handler, "Use the exact engine experiment collection path.")
        return True
    suffix = "" if path == root else path[len(root) + 1 :]
    parsed = _parse_suffix(suffix)
    if parsed is None:
        _request_error(handler, "Select a canonical saved engine experiment.")
        return True

    operation, arguments = parsed
    selected_attempt_id: str | None = None
    selected_check_id: str | None = None
    if operation == "workspace":
        valid, selected_attempt_id, selected_check_id = _workspace_selection(handler)
        if not valid:
            return True
    elif not handler._routes._management_query_free():
        return True
    service: EngineExperimentAPIService = handler.platform_server.service.engine_experiment_service

    if body is None:
        reads = {
            "collection": lambda: service.list(limit=100),
            "read": lambda: service.get(arguments[0]),
            "workspace": lambda: service.workspace(
                arguments[0],
                selected_attempt_id=selected_attempt_id,
                selected_check_id=selected_check_id,
            ),
        }
        callback = reads.get(operation)
        if callback is None:
            handler._method_not_allowed("POST")
        else:
            handler._dispatch(lambda: _service_call(callback))
        return True

    if operation == "collection":
        if not _valid_create_request(body):
            _request_error(handler, "Engine experiment creation request is invalid.")
        else:
            handler._dispatch(lambda: _service_call(lambda: service.create_request(body)))
        return True
    if operation == "assistant-context":
        if not _valid_assistance_selection(body) or body["experiment_id"] != arguments[0]:
            _request_error(handler, "Engine Assistant selection is invalid.")
        else:
            handler._dispatch(
                lambda: _service_call(
                    lambda: service.assistance_context_request(arguments[0], body)
                )
            )
        return True
    if operation == "prepare-action":
        if not _valid_action_prepare_request(body):
            _request_error(handler, "Engine action preparation request is invalid.")
        else:
            handler._dispatch(
                lambda: _service_call(lambda: service.prepare_action_request(arguments[0], body))
            )
        return True
    if operation == "submit-prepared-action":
        if not _valid_action_submit_request(body):
            _request_error(handler, "Engine action submission request is invalid.")
        else:
            handler._dispatch(
                lambda: _service_call(
                    lambda: service.submit_prepared_action_request(arguments[0], body)
                )
            )
        return True
    if operation == "submit-attempt":
        if not _valid_attempt_request(body) or body["experiment_id"] != arguments[0]:
            _request_error(handler, "Engine attempt request is invalid.")
        else:
            handler._dispatch(lambda: _service_call(lambda: service.submit_attempt_request(body)))
        return True
    if operation == "recover-attempt":
        if body:
            _request_error(handler, "Engine attempt recovery requires an empty request.")
        else:
            handler._dispatch(
                lambda: _service_call(
                    lambda: service.recover_attempt(
                        experiment_id=arguments[0], attempt_id=arguments[1]
                    )
                )
            )
        return True
    if operation == "transition":
        if not _valid_transition_request(body) or body["action"] != arguments[1]:
            _request_error(handler, "Engine experiment transition request is invalid.")
        else:
            handler._dispatch(
                lambda: _service_call(
                    lambda: service.perform_controller_transition_request(arguments[0], body)
                )
            )
        return True
    if operation == "controller-job":
        if not _valid_controller_job_request(body) or body["action"] != arguments[1]:
            _request_error(handler, "Engine controller operation request is invalid.")
        else:
            handler._dispatch(
                lambda: _service_call(
                    lambda: service.submit_controller_operation_request(arguments[0], body)
                )
            )
        return True

    handler._method_not_allowed("GET")
    return True


__all__ = ["EngineExperimentAPIService", "dispatch_engine_experiments"]
