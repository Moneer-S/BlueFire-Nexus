"""Initial creation HTTP verb/session/body/route boundaries."""

import json

import pytest

from tests_platform.test_api import JOB_ID, request, running_server


@pytest.mark.parametrize(
    "method,path,call",
    [
        ("POST", "/assistance/detection-source", ("detection_creation_source", {})),
        ("POST", "/assistance/detection-context", ("detection_creation_context", {})),
        ("GET", f"/ai/detection-create-jobs/{JOB_ID}", ("detection_create_job", JOB_ID)),
        (
            "POST",
            f"/ai/detection-create-jobs/{JOB_ID}/validate",
            ("validate_detection_create", JOB_ID, {}),
        ),
        (
            "POST",
            f"/ai/detection-create-jobs/{JOB_ID}/review",
            ("review_detection_create", JOB_ID, {}),
        ),
    ],
)
def test_dispatch(method, path, call):
    with running_server() as (server, service):
        status, _, body = request(
            server, method, "/api/v1" + path, body={} if method == "POST" else None
        )
        assert status == 200 and isinstance(json.loads(body), dict)
        assert service.calls == [call]


@pytest.mark.parametrize(
    "path",
    [
        "/assistance/detection-source",
        "/assistance/detection-context",
        f"/ai/detection-create-jobs/{JOB_ID}/review",
        f"/ai/detection-create-jobs/{JOB_ID}/validate",
    ],
)
@pytest.mark.parametrize(
    "violation,status",
    [("method", 405), ("query", 400), ("session", 401), ("origin", 403), ("body", 400)],
)
def test_guards(path, violation, status):
    with running_server() as (server, service):
        actual, _, _ = request(
            server,
            "GET" if violation == "method" else "POST",
            "/api/v1" + path + ("?extra=true" if violation == "query" else ""),
            body=None if violation == "method" else [] if violation == "body" else {},
            authenticated=violation != "session",
            origin="https://untrusted.example" if violation == "origin" else "same",
        )
        assert actual == status and not service.calls
