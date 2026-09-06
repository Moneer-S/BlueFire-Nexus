"""Replay job HTTP dispatch retains existing local browser authority checks."""

import json

import pytest

from tests_platform.test_api import RUN_ID, request, running_server


def test_replay_job_endpoint_returns_accepted_job_without_synchronous_replay():
    payload = {
        "submission_id": "b42f4bdd-4f5f-453d-a60a-a985edfb7b4c",
        "preparation_id": "replay-preparation-" + "a" * 64,
        "preparation_context": {
            "schema_version": "bluefire.replay-preparation-context.v1",
            "runner_readiness": None,
        },
    }
    with running_server() as (server, service):
        status, _, body = request(
            server, "POST", f"/api/v1/runs/{RUN_ID}/replay-jobs", body=payload
        )
    assert status == 202
    assert json.loads(body)["job"]["kind"] == "scenario.replay"
    assert service.calls == [("submit_replay", RUN_ID, payload)]


@pytest.mark.parametrize(
    "violation,status",
    [("method", 405), ("query", 400), ("session", 401), ("origin", 403), ("body", 400)],
)
def test_replay_job_endpoint_retains_http_guards(violation, status):
    with running_server() as (server, service):
        actual, _, _ = request(
            server,
            "GET" if violation == "method" else "POST",
            f"/api/v1/runs/{RUN_ID}/replay-jobs" + ("?exact=true" if violation == "query" else ""),
            body=None if violation == "method" else [] if violation == "body" else {},
            authenticated=violation != "session",
            origin="https://untrusted.example" if violation == "origin" else "same",
        )
    assert actual == status
    assert service.calls == []
