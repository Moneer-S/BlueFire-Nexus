"""Audit import is authenticated local analysis, not a runner or cloud command."""

import pytest

from tests_platform.test_api import JOB_ID, request, running_server

ROOT = f"/api/v1/s3-access/exercises/{JOB_ID}/audit-reviews"
REVIEW = "job-" + "e" * 32


@pytest.mark.parametrize(
    "method,suffix,operation",
    [
        ("GET", "", "s3_audit_reviews"),
        ("POST", "", "save_s3_audit_review"),
        ("GET", "/" + REVIEW, "s3_audit_review"),
        ("GET", "/" + REVIEW + "/assistant-context", "s3_audit_assistance_context"),
    ],
)
@pytest.mark.parametrize("authenticated", [False, True])
def test_audit_dispatch_requires_session(method, suffix, operation, authenticated):
    body = {"logs": []} if method == "POST" else None
    with running_server(authenticate=authenticated) as (server, service):

        def called(*args):
            service.calls.append((operation, *args))
            return {"ok": True}

        setattr(service, operation, called)
        status, _, _ = request(server, method, ROOT + suffix, body=body)
        assert status == (200 if authenticated else 401)
        expected = (
            operation,
            JOB_ID,
            *((body,) if body is not None else (REVIEW,) if suffix else ()),
        )
        assert service.calls == ([expected] if authenticated else [])


@pytest.mark.parametrize(
    "method,path,expected",
    [
        ("GET", ROOT + "?scope=other", 400),
        ("POST", ROOT + "/" + REVIEW, 405),
        ("POST", ROOT + "/" + REVIEW + "/assistant-context", 405),
        ("GET", ROOT + "/" + REVIEW + "/assistant-context?selection=other", 400),
        ("GET", ROOT + "/assistant-context", 400),
        ("GET", ROOT + "/not-a-review", 400),
        ("GET", ROOT + "/" + REVIEW + "/again", 400),
        ("GET", ROOT.replace("audit-reviews", "stop") + "/" + REVIEW, 400),
    ],
)
def test_noncanonical_import_routes_refuse(method, path, expected):
    with running_server() as (server, service):
        status, _, _ = request(server, method, path, body={} if method == "POST" else None)
        assert status == expected and not service.calls


def test_cross_origin_import_cannot_write():
    with running_server() as (server, service):
        status, _, _ = request(server, "POST", ROOT, body={}, origin="https://example.invalid")
        assert status == 403 and not service.calls
