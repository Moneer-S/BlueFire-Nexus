"""Contextual assistance preserves ordinary browser/session and verb boundaries."""

import json

import pytest

from tests_platform.test_api import JOB_ID, RUN_ID, request, running_server

CANDIDATE = "detection-" + "a" * 20


@pytest.mark.parametrize(
    "method,path,operation,status",
    [
        (
            "GET",
            f"/assistance/context?run_id={RUN_ID}&candidate_id={CANDIDATE}",
            "assistance_context",
            200,
        ),
        ("POST", "/assistance/turns", "submit_assistance_turn", 202),
        ("GET", "/assistance/graph-context", "assistance_graph_context", 200),
        ("GET", f"/ai/graph-jobs/{JOB_ID}", "graph_ai_job", 200),
        ("POST", f"/ai/graph-jobs/{JOB_ID}/review", "review_graph_ai", 200),
        ("POST", f"/ai/graph-jobs/{JOB_ID}/validate", "validate_graph_ai", 200),
        ("GET", f"/assistance/turns/{JOB_ID}", "assistance_turn", 200),
        ("POST", f"/assistance/turns/{JOB_ID}/continue", "continue_assistance_turn", 202),
    ],
)
def test_dispatch(method, path, operation, status, monkeypatch):
    with running_server() as (server, service):

        def handle(*args):
            service.calls.append((operation, *args))
            return {"job": {"job_id": JOB_ID}}

        monkeypatch.setattr(service, operation, handle, raising=False)
        actual, _, body = request(
            server, method, "/api/v1" + path, body={} if method == "POST" else None
        )
        assert actual == status and isinstance(json.loads(body), dict)
        assert len(service.calls) == 1 and service.calls[0][0] == operation


@pytest.mark.parametrize(
    "violation,status",
    [("method", 405), ("query", 400), ("session", 401), ("origin", 403), ("body", 400)],
)
def test_turn_submission_guards(violation, status):
    with running_server() as (server, service):
        actual, _, _ = request(
            server,
            "GET" if violation == "method" else "POST",
            "/api/v1/assistance/turns" + ("?autonomy=auto" if violation == "query" else ""),
            body=None if violation == "method" else [] if violation == "body" else {},
            authenticated=violation != "session",
            origin="https://untrusted.example" if violation == "origin" else "same",
        )
        assert actual == status and not service.calls


@pytest.mark.parametrize(
    "query",
    [
        f"run_id={RUN_ID}",
        f"run_id={RUN_ID}&run_id={RUN_ID}",
        f"run_id={RUN_ID}&candidate_id={CANDIDATE}&extra=true",
        f"run_id=bad&candidate_id={CANDIDATE}",
    ],
)
def test_context_requires_exact_selected_objects(query):
    with running_server() as (server, service):
        actual, _, _ = request(server, "GET", "/api/v1/assistance/context?" + query)
        assert actual == 400 and not service.calls
