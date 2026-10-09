"""Ordinary loopback browser-session routes; no cloud or native execution."""

import pytest

from bluefire.application_errors import APIError
from bluefire.s3_access_contract import S3AccessError
from bluefire.s3_access_service import S3AccessServiceMixin
from tests_platform.test_api import JOB_ID, json_body, request, running_server

ROOT = "/api/v1/s3-access"


@pytest.mark.parametrize(
    ("method", "path", "operation", "has_identifier"),
    [
        ("GET", "/environments", "s3_access_environments", False),
        ("GET", "/exercises", "s3_access_exercises", False),
        ("GET", f"/exercises/{JOB_ID}", "s3_access_exercise", True),
        ("POST", "/exercises", "create_s3_access", False),
        ("POST", f"/exercises/{JOB_ID}/review", "review_s3_access", True),
        ("POST", f"/exercises/{JOB_ID}/operations", "submit_s3_access", True),
        ("POST", f"/exercises/{JOB_ID}/stop", "stop_s3_access", True),
        ("POST", f"/exercises/{JOB_ID}/recover", "recover_s3_access", True),
    ],
)
def test_exact_routes_use_existing_authenticated_shell(method, path, operation, has_identifier):
    body = {"phase": "inspect"} if method == "POST" else None
    with running_server() as (server, service):
        status, _, _ = request(server, method, ROOT + path, body=body)
        assert status == 200
        expected = (
            operation,
            *((JOB_ID,) if has_identifier else ()),
            *((body,) if body is not None else ()),
        )
        assert service.calls == [expected]


@pytest.mark.parametrize("method", ["GET", "POST"])
def test_session_is_required_before_s3_dispatch(method):
    with running_server(authenticate=False) as (server, service):
        status, _, _ = request(
            server, method, ROOT + "/exercises", body={} if method == "POST" else None
        )
        assert status == 401
        assert service.calls == []


def test_cross_origin_s3_command_never_dispatches():
    with running_server() as (server, service):
        status, _, _ = request(
            server,
            "POST",
            ROOT + f"/exercises/{JOB_ID}/stop",
            body={},
            origin="https://example.invalid",
        )
        assert status == 403
        assert service.calls == []


@pytest.mark.parametrize(
    "path",
    [
        "/exercises?phase=apply",
        "/environments?scope=other",
        "/exercises/not-a-job",
        f"/exercises/{JOB_ID}/apply",
        f"/exercises/{JOB_ID}/recover/again",
    ],
)
def test_noncanonical_s3_routes_never_dispatch(path):
    with running_server() as (server, service):
        status, _, _ = request(server, "GET", ROOT + path)
        assert status == 400
        assert service.calls == []


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", f"/exercises/{JOB_ID}/operations"),
        ("GET", f"/exercises/{JOB_ID}/recover"),
        ("POST", "/environments"),
        ("POST", f"/exercises/{JOB_ID}"),
    ],
)
def test_s3_method_refusal_does_not_turn_reads_into_commands(method, path):
    with running_server() as (server, service):
        status, _, _ = request(server, method, ROOT + path, body={} if method == "POST" else None)
        assert status == 405
        assert service.calls == []


def test_s3_service_refusal_does_not_echo_private_adapter_details():
    def refused():
        raise S3AccessError("private adapter diagnostic")

    with pytest.raises(APIError) as caught:
        S3AccessServiceMixin()._s3_call(refused)
    assert caught.value.status == 409
    assert "private adapter diagnostic" not in str(caught.value)


def test_s3_read_refusal_uses_the_ordinary_json_error_shape():
    with running_server() as (server, service):
        service.s3_access_exercise = lambda _identifier: (_ for _ in ()).throw(
            APIError(409, "s3_access_refused", "Saved state is unavailable.")
        )
        status, _, body = request(server, "GET", ROOT + f"/exercises/{JOB_ID}")
        assert status == 409
        assert json_body(body)["error"]["code"] == "s3_access_refused"
