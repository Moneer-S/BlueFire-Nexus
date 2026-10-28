"""Authenticated, query-free immutable comparison explanation reads only."""

import pytest

from tests_platform.test_api import StubService, json_body, request, running_server
from tests_platform.test_comparison_assistance import saved
from tests_platform.test_s3_comparison import comparison_service

SNAPSHOT = "run-comparison-" + "a" * 64
PATH = "/api/v1/comparison-snapshots/" + SNAPSHOT + "/assistant-context"


def test_comparison_context_route_forwards_only_exact_canonical_identity():
    service = StubService()
    with running_server(service) as (server, _):
        status, _, payload = request(server, "GET", PATH)
        assert status == 200 and json_body(payload) == {"saved": True}
        assert service.calls == [("comparison_assistance_context", SNAPSHOT)]


@pytest.mark.parametrize(
    "violation", ["session", "query", "fragment", "post", "suffix", "identity"]
)
def test_comparison_context_preserves_http_read_guards(violation):
    service = StubService()
    service.comparison_assistance_context = lambda *_: pytest.fail(
        "Invalid context request reached service"
    )
    path = PATH + (
        "?recompute=true"
        if violation == "query"
        else "#authority" if violation == "fragment" else "/extra" if violation == "suffix" else ""
    )
    if violation == "identity":
        path = path.replace(SNAPSHOT, "comparison-" + "a" * 20)
    method = "POST" if violation == "post" else "GET"
    with running_server(service) as (server, _):
        status, _, _ = request(
            server,
            method,
            path,
            body={} if method == "POST" else None,
            authenticated=violation != "session",
        )
        assert (
            status
            == {
                "session": 401,
                "query": 400,
                "fragment": 400,
                "post": 405,
                "suffix": 404,
                "identity": 404,
            }[violation]
        )
        assert service.calls == []


def test_http_returns_actual_minimized_saved_context_without_recompute(tmp_path, monkeypatch):
    with comparison_service(tmp_path) as (service, _executor):
        metadata = saved(service)
        monkeypatch.setattr(
            service, "compare", lambda *_: pytest.fail("Context recomputed comparison")
        )
        before = service.product_store.path.read_bytes()
        with running_server(service) as (server, _):
            status, _, payload = request(
                server,
                "GET",
                "/api/v1/comparison-snapshots/" + metadata["snapshot_id"] + "/assistant-context",
            )
        result = json_body(payload)
        assert status == 200 and result["analysis_only"] is True and result["capabilities"] == []
        assert result["selected"] == {
            "kind": "comparison_snapshot",
            "snapshot_id": metadata["snapshot_id"],
            "snapshot_digest": metadata["digest"],
        }
        assert result["reference_summary"]["saved_comparison"]["run_count"] == 2
        assert service.product_store.path.read_bytes() == before
