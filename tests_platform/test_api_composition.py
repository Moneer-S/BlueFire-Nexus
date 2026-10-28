"""Composition reuses the authenticated HTTP shell without a raw authority endpoint."""

import json

import pytest

from bluefire.application_errors import APIError
from tests_platform.test_api import JOB_ID, StubService, request, running_server

ATTEMPT_ID = "attempt-0123456789abcdef0123456789abcdef"


def test_linux_linkage_route_is_exact_read_only(monkeypatch):
    def read(self, owner, attempt):
        self.calls.append(("file_access_composed_retest_linkage", owner, attempt))
        return {"saved": True}

    monkeypatch.setattr(StubService, "file_access_composed_retest_linkage", read, raising=False)
    path = f"/api/v1/composition/objectives/{JOB_ID}/file-access-linkage/{ATTEMPT_ID}"
    with running_server() as (server, service):
        status, _, body = request(server, "GET", path)
        assert status == 200 and json.loads(body) == {"saved": True}
        assert service.calls == [("file_access_composed_retest_linkage", JOB_ID, ATTEMPT_ID)]
        for method, invalid, expected in (
            ("POST", path, 405),
            ("GET", path + "?scope=expanded", 400),
            ("GET", path.replace(ATTEMPT_ID, "attempt-not-canonical"), 400),
        ):
            status, _, _ = request(server, method, invalid, body={} if method == "POST" else None)
            assert status == expected
        assert service.calls == [("file_access_composed_retest_linkage", JOB_ID, ATTEMPT_ID)]

        def unavailable(self, owner, attempt):
            self.calls.append(("unavailable_linkage", owner, attempt))
            raise APIError(409, "file_access_linkage_unavailable", "Saved lineage unavailable.")

        monkeypatch.setattr(StubService, "file_access_composed_retest_linkage", unavailable)
        status, _, body = request(server, "GET", path)
        assert status == 409
        assert json.loads(body)["error"]["code"] == "file_access_linkage_unavailable"
        assert service.calls[-1] == ("unavailable_linkage", JOB_ID, ATTEMPT_ID)


@pytest.mark.parametrize(
    "method,suffix,call",
    [
        ("POST", "context", ("composition_context", {})),
        ("POST", "objectives", ("authorize_composition", {})),
        ("POST", "objective-list", ("list_composition_objectives", {})),
        ("GET", f"objectives/{JOB_ID}", ("composition_objective", JOB_ID)),
        ("GET", f"proposals/{JOB_ID}", ("composition_proposal", JOB_ID)),
        (
            "POST",
            f"proposals/{JOB_ID}/cancel",
            ("cancel_composition_proposal", JOB_ID, {}),
        ),
        (
            "POST",
            f"objectives/{JOB_ID}/proposals",
            ("submit_composition_proposal", JOB_ID, {}),
        ),
        (
            "POST",
            f"objectives/{JOB_ID}/proposal-context",
            ("composition_proposal_context", JOB_ID, {}),
        ),
        (
            "POST",
            f"objectives/{JOB_ID}/attempts",
            ("submit_composition_attempt", JOB_ID, {}),
        ),
        *[
            (
                "POST",
                f"objectives/{JOB_ID}/{action}",
                ("control_composition", JOB_ID, action, {}),
            )
            for action in ("stop", "revoke", "continue", "recover")
        ],
    ],
)
def test_composition_routes(method, suffix, call):
    with running_server() as (server, service):
        status, _, body = request(
            server,
            method,
            "/api/v1/composition/" + suffix,
            body={} if method == "POST" else None,
        )
        assert status == 200 and json.loads(body) == {"saved": True}
        assert service.calls == [call]


@pytest.mark.parametrize(
    "suffix",
    [
        "context",
        "objectives",
        "objective-list",
        f"proposals/{JOB_ID}/cancel",
        *[
            f"objectives/{JOB_ID}/{action}"
            for action in (
                "proposal-context",
                "proposals",
                "attempts",
                "stop",
                "revoke",
                "continue",
                "recover",
            )
        ],
    ],
)
@pytest.mark.parametrize(
    "violation,status",
    [("method", 405), ("query", 400), ("session", 401), ("origin", 403), ("body", 400)],
)
def test_composition_mutations_keep_shell_guards(suffix, violation, status):
    with running_server() as (server, service):
        actual, _, _ = request(
            server,
            "GET" if violation == "method" else "POST",
            f"/api/v1/composition/{suffix}" + ("?scope=expanded" if violation == "query" else ""),
            body=None if violation == "method" else [] if violation == "body" else {},
            authenticated=violation != "session",
            origin="https://untrusted.example" if violation == "origin" else "same",
        )
        assert actual == status and not service.calls


@pytest.mark.parametrize(
    "suffix",
    ["objectives/bad", f"objectives/{JOB_ID}/compiled", f"objectives/{JOB_ID}/grant", "grants"],
)
def test_composition_has_no_unreviewed_authority_write(suffix):
    with running_server() as (server, service):
        actual, _, _ = request(server, "POST", "/api/v1/composition/" + suffix, body={})
        assert actual == 400 and not service.calls


def test_composition_recovery_forwards_only_explicit_attempt_binding():
    attempt_id = "attempt-" + "a" * 32
    with running_server() as (server, service):
        status, _, body = request(
            server,
            "POST",
            f"/api/v1/composition/objectives/{JOB_ID}/recover",
            body={"attempt_id": attempt_id},
        )
        assert status == 200 and json.loads(body) == {"saved": True}
        assert service.calls == [
            ("control_composition", JOB_ID, "recover", {"attempt_id": attempt_id})
        ]
