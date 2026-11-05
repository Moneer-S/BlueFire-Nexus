"""Historical knowledge uses the authenticated shell without dispatch authority."""

import json

import pytest

from bluefire.service import BlueFireService
from tests_platform.test_api import JOB_ID, StubService, request, running_server

ATTEMPT_ID = "attempt-0123456789abcdef0123456789abcdef"
QUERY = {
    "schema_version": "bluefire.composition-knowledge-query.v1",
    "attempt_ids": [ATTEMPT_ID],
}
PATH = f"/api/v1/composition/objectives/{JOB_ID}/knowledge"


def test_knowledge_request_preserves_exact_objective_and_query(monkeypatch):
    def read(self, owner_id, query):
        self.calls.append(("composition_knowledge", owner_id, query))
        return {"owner_id": owner_id, "historical": True}

    monkeypatch.setattr(StubService, "composition_knowledge", read, raising=False)
    with running_server() as (server, service):
        status, _, body = request(server, "POST", PATH, body=QUERY)
        assert status == 200
        assert json.loads(body) == {"owner_id": JOB_ID, "historical": True}
        assert service.calls == [("composition_knowledge", JOB_ID, QUERY)]


@pytest.mark.parametrize(
    "violation,expected",
    [("method", 405), ("query", 400), ("session", 401), ("origin", 403), ("body", 400)],
)
def test_knowledge_lookup_keeps_session_origin_and_route_guards(violation, expected):
    with running_server() as (server, service):
        actual, _, _ = request(
            server,
            "GET" if violation == "method" else "POST",
            PATH + ("?scope=all" if violation == "query" else ""),
            body=None if violation == "method" else [] if violation == "body" else QUERY,
            authenticated=violation != "session",
            origin="https://untrusted.example" if violation == "origin" else "same",
        )
        assert actual == expected
        assert service.calls == []


def test_service_routes_knowledge_to_read_only_resolver(monkeypatch):
    from bluefire import composition_knowledge

    calls = []
    jobs = object()

    def build(actual_jobs, owner_id, query):
        calls.append((actual_jobs, owner_id, query))
        return {"historical": True}

    class Service:
        composition = jobs

    monkeypatch.setattr(composition_knowledge, "build_knowledge", build)
    result = BlueFireService.composition_knowledge(Service(), JOB_ID, QUERY)
    assert result == {"historical": True}
    assert calls == [(jobs, JOB_ID, QUERY)]
