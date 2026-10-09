"""Composition reuses the authenticated HTTP shell without a raw authority endpoint."""

import json

import pytest

from tests_platform.test_api import JOB_ID, request, running_server


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
            for action in ("stop", "revoke", "continue")
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
