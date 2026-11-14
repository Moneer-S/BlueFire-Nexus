from __future__ import annotations

from typing import Mapping

import pytest

from tests_platform.test_api import StubService, json_body, request, running_server


def _digest(character: str) -> str:
    return "sha256:" + character * 64


def _error_code(payload: bytes) -> object:
    error = json_body(payload)["error"]
    assert isinstance(error, Mapping)
    return error["code"]


def _create_request() -> dict[str, object]:
    return {
        "schema_version": "bluefire.engine-experiment-create.v1",
        "experiment_id": "experiment-" + "1" * 32,
        "objective_ref": _digest("1"),
        "environment_ref": _digest("2"),
        "scope_ref": _digest("3"),
        "scope_version": "bluefire.engine-capability-delegation.v1",
        "target_snapshot_ref": _digest("4"),
    }


def _assistance_selection() -> dict[str, object]:
    return {
        "kind": "engine_experiment",
        "experiment_id": "experiment-" + "1" * 32,
        "workspace_digest": _digest("a"),
        "attempt_id": None,
        "check_id": None,
    }


def test_authenticated_engine_collection_get_and_post_reach_product_service() -> None:
    body = _create_request()
    with running_server() as (server, service):
        get_status, _headers, get_payload = request(server, "GET", "/api/v1/engine-experiments")
        post_status, _headers, post_payload = request(
            server,
            "POST",
            "/api/v1/engine-experiments",
            body=body,
        )

    assert get_status == 200
    assert json_body(get_payload)["schema_version"] == "bluefire.engine-experiment-list.v1"
    assert post_status == 200
    assert json_body(post_payload)["experiment_id"] == body["experiment_id"]
    assert service.calls == [
        ("engine_experiments", 100),
        ("create_engine_experiment", body),
    ]


@pytest.mark.parametrize("method", ["GET", "POST"])
def test_engine_collection_requires_browser_session_before_dispatch(method: str) -> None:
    service = StubService()
    with running_server(service, authenticate=False) as (server, _service):
        status, _headers, payload = request(
            server,
            method,
            "/api/v1/engine-experiments",
            body=_create_request() if method == "POST" else None,
            authenticated=False,
        )

    assert status == 401
    assert _error_code(payload) == "browser_session_required"
    assert service.calls == []


def test_engine_create_rejects_cross_origin_and_non_json_before_dispatch() -> None:
    body = _create_request()
    with running_server() as (server, service):
        origin_status, _headers, origin_payload = request(
            server,
            "POST",
            "/api/v1/engine-experiments",
            body=body,
            origin="https://example.invalid",
        )
        media_status, _headers, media_payload = request(
            server,
            "POST",
            "/api/v1/engine-experiments",
            body=body,
            content_type="text/plain",
        )

    assert origin_status == 403
    assert _error_code(origin_payload) == "origin_rejected"
    assert media_status == 415
    assert _error_code(media_payload) == "content_type_required"
    assert service.calls == []


def test_authenticated_engine_assistant_context_reaches_only_read_service() -> None:
    selection = _assistance_selection()
    path = "/api/v1/engine-experiments/" + str(selection["experiment_id"]) + "/assistant-context"
    with running_server() as (server, service):
        status, _headers, payload = request(server, "POST", path, body=selection)

    assert status == 200
    result = json_body(payload)
    assert result["analysis_only"] is True
    assert result["capabilities"] == []
    assert service.calls == [("engine_assistance_context", selection["experiment_id"], selection)]


def test_engine_assistant_context_requires_session_origin_and_json_before_dispatch() -> None:
    selection = _assistance_selection()
    path = "/api/v1/engine-experiments/" + str(selection["experiment_id"]) + "/assistant-context"
    service = StubService()
    with running_server(service, authenticate=False) as (server, _service):
        session_status, _headers, session_payload = request(
            server,
            "POST",
            path,
            body=selection,
            authenticated=False,
        )
    with running_server(service) as (server, _service):
        origin_status, _headers, origin_payload = request(
            server,
            "POST",
            path,
            body=selection,
            origin="https://example.invalid",
        )
        media_status, _headers, media_payload = request(
            server,
            "POST",
            path,
            body=selection,
            content_type="text/plain",
        )

    assert session_status == 401
    assert _error_code(session_payload) == "browser_session_required"
    assert origin_status == 403
    assert _error_code(origin_payload) == "origin_rejected"
    assert media_status == 415
    assert _error_code(media_payload) == "content_type_required"
    assert service.calls == []


def test_engine_assistant_context_rejects_body_identity_drift_before_dispatch() -> None:
    selection = _assistance_selection()
    selection["experiment_id"] = "experiment-" + "2" * 32
    path = "/api/v1/engine-experiments/experiment-" + "1" * 32 + "/assistant-context"
    with running_server() as (server, service):
        status, _headers, payload = request(server, "POST", path, body=selection)

    assert status == 400
    assert _error_code(payload) == "engine_experiment_invalid"
    assert service.calls == []
