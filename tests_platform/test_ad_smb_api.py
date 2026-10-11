"""Authenticated saved AD routes, without enrollment or native execution."""

from types import SimpleNamespace

import pytest

from bluefire.ad_smb_contract import AdSmbError
from bluefire.ad_smb_service import AdSmbServiceMixin
from bluefire.application_errors import APIError
from tests_platform.test_api import JOB_ID, json_body, request, running_server

ROOT = "/api/v1/ad-smb"


@pytest.mark.parametrize(
    ("method", "path", "operation", "has_identifier"),
    [
        ("GET", "/environments", "ad_smb_environments", False),
        ("GET", "/workflows", "ad_smb_workflows", False),
        ("GET", f"/workflows/{JOB_ID}", "ad_smb_workflow", True),
        ("POST", "/workflows", "create_ad_smb", False),
        ("POST", f"/workflows/{JOB_ID}/review", "review_ad_smb", True),
        ("POST", f"/workflows/{JOB_ID}/operations", "submit_ad_smb", True),
        ("POST", f"/workflows/{JOB_ID}/stop", "stop_ad_smb", True),
        ("POST", f"/workflows/{JOB_ID}/recover", "recover_ad_smb", True),
    ],
)
def test_exact_ad_routes_use_authenticated_shell(method, path, operation, has_identifier):
    body = {"phase": "inspect"} if method == "POST" else None
    with running_server() as (server, service):
        status, _, _ = request(server, method, ROOT + path, body=body)
        assert status == 200
        assert service.calls == [
            (
                operation,
                *((JOB_ID,) if has_identifier else ()),
                *((body,) if body is not None else ()),
            )
        ]


@pytest.mark.parametrize("method", ["GET", "POST"])
def test_ad_session_required_before_dispatch(method):
    with running_server(authenticate=False) as (server, service):
        status, _, _ = request(
            server, method, ROOT + "/workflows", body={} if method == "POST" else None
        )
        assert status == 401
        assert service.calls == []


@pytest.mark.parametrize("action", ["review", "operations", "stop", "recover"])
def test_cross_origin_ad_commands_never_dispatch(action):
    with running_server() as (server, service):
        status, _, _ = request(
            server,
            "POST",
            ROOT + f"/workflows/{JOB_ID}/{action}",
            body={},
            origin="https://example.invalid",
        )
        assert status == 403
        assert service.calls == []


@pytest.mark.parametrize(
    "path",
    [
        "/workflows?phase=harden",
        "/environments?scope=other",
        "/workflows/not-a-job",
        f"/workflows/{JOB_ID.upper()}",
        f"/workflows/{JOB_ID}/harden",
        f"/workflows/{JOB_ID}/recover/again",
        f"/workflows/{JOB_ID}/recover/",
        f"/workflows/{JOB_ID}%2Frecover",
    ],
)
def test_noncanonical_ad_routes_never_dispatch(path):
    with running_server() as (server, service):
        status, _, _ = request(server, "GET", ROOT + path)
        assert status == 400
        assert service.calls == []


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", f"/workflows/{JOB_ID}/operations"),
        ("GET", f"/workflows/{JOB_ID}/recover"),
        ("GET", f"/workflows/{JOB_ID}/stop"),
        ("POST", "/environments"),
        ("POST", f"/workflows/{JOB_ID}"),
    ],
)
def test_ad_method_refusal_does_not_turn_reads_into_commands(method, path):
    with running_server() as (server, service):
        status, _, _ = request(server, method, ROOT + path, body={} if method == "POST" else None)
        assert status == 405
        assert service.calls == []


@pytest.mark.parametrize("suffix", ["%2Frecover", "%252Fstop", "/%72eview"])
def test_ad_encoded_command_paths_never_dispatch(suffix):
    with running_server() as (server, service):
        status, _, _ = request(server, "POST", ROOT + f"/workflows/{JOB_ID}{suffix}", body={})
        assert status == 400
        assert service.calls == []


def test_ad_service_refusal_does_not_echo_private_adapter_details():
    def refused():
        raise AdSmbError("private member adapter diagnostic")

    with pytest.raises(APIError) as caught:
        AdSmbServiceMixin()._ad_smb_call(refused)
    assert caught.value.status == 409
    assert "private member adapter diagnostic" not in str(caught.value)


def test_ad_read_refusal_uses_existing_json_error_shape():
    with running_server() as (server, service):
        service.ad_smb_workflow = lambda _identifier: (_ for _ in ()).throw(
            APIError(409, "ad_smb_refused", "Saved state is unavailable.")
        )
        status, _, body = request(server, "GET", ROOT + f"/workflows/{JOB_ID}")
        assert status == 409
        assert json_body(body)["error"]["code"] == "ad_smb_refused"


@pytest.mark.parametrize("action", ["stop", "recover"])
def test_ad_lifecycle_service_requires_empty_body(action):
    service = AdSmbServiceMixin()
    calls = []
    service.ad_smb = SimpleNamespace(**{action: lambda identifier: calls.append(identifier) or {}})
    method = getattr(service, f"{action}_ad_smb")
    with pytest.raises(APIError):
        method(JOB_ID, {"scope": "replacement"})
    assert calls == []
    assert method(JOB_ID, {}) == {}
    assert calls == [JOB_ID]


def test_ad_review_service_accepts_only_the_exact_phase_request():
    service = AdSmbServiceMixin()
    calls = []
    service.ad_smb = SimpleNamespace(
        review=lambda identifier, phase: calls.append((identifier, phase)) or {}
    )
    for body in [{}, {"phase": "inspect", "approved": True}]:
        with pytest.raises(APIError):
            service.review_ad_smb(JOB_ID, body)
    assert calls == []
    assert service.review_ad_smb(JOB_ID, {"phase": "inspect"}) == {}
    assert calls == [(JOB_ID, "inspect")]
