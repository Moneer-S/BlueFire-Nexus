"""The connected operation retains the existing local-browser API boundaries."""

import json

import pytest

from tests_platform.test_api import JOB_ID, RUN_ID, request, running_server


@pytest.mark.parametrize(
    "method,path,operation,status",
    [
        ("GET", f"/runs/{RUN_ID}/method-comparison-context", "method_comparison_context", 200),
        ("POST", f"/runs/{RUN_ID}/ai-method-comparison-jobs", "submit_method_comparison", 202),
        ("POST", f"/jobs/{JOB_ID}/method-comparison-decisions", "decide_method_comparison", 202),
    ],
)
def test_exact_dispatch(method, path, operation, status):
    with running_server() as (server, service):
        actual, _, body = request(
            server, method, "/api/v1" + path, body={} if method == "POST" else None
        )
        assert actual == status and isinstance(json.loads(body), dict)
        assert service.calls[0][0] == operation and len(service.calls) == 1


@pytest.mark.parametrize(
    "violation,status",
    [("method", 405), ("query", 400), ("session", 401), ("origin", 403), ("body", 400)],
)
def test_admission_http_guards(violation, status):
    with running_server() as (server, service):
        actual, _, _ = request(
            server,
            "GET" if violation == "method" else "POST",
            f"/api/v1/runs/{RUN_ID}/ai-method-comparison-jobs"
            + ("?autonomy=auto" if violation == "query" else ""),
            body=None if violation == "method" else [] if violation == "body" else {},
            authenticated=violation != "session",
            origin="https://untrusted.example" if violation == "origin" else "same",
        )
        assert actual == status and not service.calls
