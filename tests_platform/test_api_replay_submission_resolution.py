"""Submission closure retains the existing authenticated same-origin HTTP shell."""

import json

import pytest

from tests_platform.test_api import RUN_ID, request, running_server


def test_resolution_dispatches_exact_json_without_submitting_or_replaying():
    payload = {"submission_id": "b42f4bdd-4f5f-453d-a60a-a985edfb7b4c"}
    with running_server() as (server, service):
        status, _, body = request(
            server, "POST", f"/api/v1/runs/{RUN_ID}/replay-submission-resolution", body=payload
        )
    assert status == 200
    assert json.loads(body)["outcome"] == "closed"
    assert service.calls == [("resolve_replay_submission", RUN_ID, payload)]


@pytest.mark.parametrize(
    "violation,status",
    [
        ("method", 405),
        ("query", 400),
        ("session", 401),
        ("origin", 403),
        ("body", 400),
        ("identifier", 400),
    ],
)
def test_resolution_retains_http_guards(violation, status):
    with running_server() as (server, service):
        run_id = "invalid" if violation == "identifier" else RUN_ID
        actual, _, _ = request(
            server,
            "GET" if violation == "method" else "POST",
            f"/api/v1/runs/{run_id}/replay-submission-resolution"
            + ("?exact=true" if violation == "query" else ""),
            body=None if violation == "method" else [] if violation == "body" else {},
            authenticated=violation != "session",
            origin="https://untrusted.example" if violation == "origin" else "same",
        )
    assert actual == status
    assert service.calls == []
