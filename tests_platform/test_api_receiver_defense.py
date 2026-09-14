"""Receiver operations preserve ordinary HTTP session, method and query boundaries."""

import json

import pytest

from tests_platform.test_api import JOB_ID, request, running_server


@pytest.mark.parametrize(
    "method,path,call",
    [
        ("POST", "/receiver-defense/context", ("receiver_defense_context", {})),
        ("POST", "/receiver-defense/jobs", ("submit_receiver_defense", {})),
        ("GET", "/receiver-defense/jobs", ("receiver_defense_jobs", None)),
        ("GET", "/receiver-defense/jobs?", ("receiver_defense_jobs", None)),
        ("GET", f"/receiver-defense/jobs?cursor={JOB_ID}", ("receiver_defense_jobs", JOB_ID)),
        ("GET", f"/receiver-defense/jobs/{JOB_ID}", ("receiver_defense_job", JOB_ID)),
        (
            "POST",
            f"/receiver-defense/jobs/{JOB_ID}/prepare",
            ("prepare_receiver_defense", JOB_ID, {}),
        ),
        (
            "POST",
            f"/receiver-defense/jobs/{JOB_ID}/review",
            ("review_receiver_defense", JOB_ID, {}),
        ),
    ],
)
def test_receiver_routes(method, path, call):
    with running_server() as (server, service):
        status, _, body = request(
            server, method, "/api/v1" + path, body={} if method == "POST" else None
        )
        assert status == 200 and isinstance(json.loads(body), dict)
        assert service.calls == [call]


@pytest.mark.parametrize(
    "query", ["cursor=", "cursor=bad", "cursor", f"cursor={JOB_ID}&cursor={JOB_ID}", "other=1"]
)
def test_receiver_cursor_is_exact_and_read_only(query):
    with running_server() as (server, service):
        status, _, _ = request(server, "GET", "/api/v1/receiver-defense/jobs?" + query)
        assert status == 400 and not service.calls


@pytest.mark.parametrize(
    "violation,status",
    [("method", 405), ("query", 400), ("session", 401), ("origin", 403), ("body", 400)],
)
def test_receiver_prepare_uses_existing_mutation_guards(violation, status):
    with running_server() as (server, service):
        actual, _, _ = request(
            server,
            "GET" if violation == "method" else "POST",
            f"/api/v1/receiver-defense/jobs/{JOB_ID}/prepare"
            + ("?renew=true" if violation == "query" else ""),
            body=None if violation == "method" else [] if violation == "body" else {},
            authenticated=violation != "session",
            origin="https://untrusted.example" if violation == "origin" else "same",
        )
        assert actual == status and not service.calls
