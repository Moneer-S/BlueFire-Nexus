"""Saved-run routes preserve exact verbs, session and query boundaries."""

import json

import pytest

from tests_platform.test_api import JOB_ID, request, running_server


@pytest.mark.parametrize(
    "method,path,expected,status",
    [
        ("POST", "/assistance/run-context", ("assistance_run_context", {}), 200),
        ("GET", f"/assistance/run-jobs/{JOB_ID}", ("assistance_run_job", JOB_ID), 200),
        (
            "POST",
            f"/assistance/run-jobs/{JOB_ID}/review",
            ("review_assistance_run", JOB_ID, {}),
            200,
        ),
    ],
)
def test_dispatch(method, path, expected, status):
    with running_server() as (server, service):
        code, _, body = request(
            server, method, "/api/v1" + path, body={} if method == "POST" else None
        )
        assert code == status and isinstance(json.loads(body), dict) and service.calls == [expected]


@pytest.mark.parametrize(
    "path", ["/assistance/run-context", f"/assistance/run-jobs/{JOB_ID}/review"]
)
@pytest.mark.parametrize(
    "violation,status",
    [("method", 405), ("query", 400), ("session", 401), ("origin", 403), ("body", 400)],
)
def test_mutation_guards(path, violation, status):
    with running_server() as (server, service):
        code, _, _ = request(
            server,
            "GET" if violation == "method" else "POST",
            "/api/v1" + path + ("?bypass=true" if violation == "query" else ""),
            body=None if violation == "method" else [] if violation == "body" else {},
            authenticated=violation != "session",
            origin="https://untrusted.example" if violation == "origin" else "same",
        )
        assert code == status and service.calls == []


@pytest.mark.parametrize(
    "path",
    [
        f"/assistance/run-jobs/{JOB_ID}?autonomy=auto",
        "/assistance/run-jobs/invalid",
        f"/assistance/run-jobs/{JOB_ID}/save",
    ],
)
def test_exact_native_identity(path):
    with running_server() as (server, service):
        code, _, _ = request(server, "GET", "/api/v1" + path)
        assert code == 400 and not service.calls
