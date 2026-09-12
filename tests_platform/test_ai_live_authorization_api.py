"""Existing authenticated loopback API, deterministic transport, no model requests."""

import json
from pathlib import Path

from bluefire.config import AIProviderKind
from bluefire.service import BlueFireService
from tests_platform.test_ai_live_authorization import FakeAccess, wire
from tests_platform.test_ai_live_authorization import request as decision
from tests_platform.test_ai_wire_runtime import _provider_config
from tests_platform.test_api import request, running_server


def test_authorization_api_requires_existing_browser_boundary_and_preserves_usage(tmp_path):
    access = FakeAccess()
    service = BlueFireService(
        project_root=Path(__file__).resolve().parents[1],
        runs_dir=tmp_path / "runs",
        ai_provider_access=access,
    )
    config = _provider_config(AIProviderKind.OPENAI_RESPONSES, authenticated=True)
    try:
        with running_server(service, max_request_body=16_384) as (server, _):
            path = "/api/v1/ai/authorizations"
            status, _, _ = request(server, "POST", path, body=decision(config), authenticated=False)
            assert status == 401
            status, _, _ = request(
                server, "POST", path, body=decision(config), origin="http://unrelated.invalid"
            )
            assert status == 403
            assert access.calls == [] and service.ai_authorizations()["authorizations"] == []
            status, _, payload = request(server, "POST", path, body=decision(config))
            assert status == 200, payload
            record = json.loads(payload)["authorization"]
            assert record["usage"]["requests"] == 0 and access.calls == []
            service._provider_access.post(config, body=wire(config), timeout_seconds=1)
            status, _, payload = request(server, "GET", path)
            assert (
                status == 200 and json.loads(payload)["authorizations"][0]["usage"]["requests"] == 1
            )
            status, _, payload = request(
                server, "POST", path + "/" + record["authorization_id"] + "/revoke", body={}
            )
            assert status == 200 and json.loads(payload)["authorization"]["status"] == "revoked"
            status, _, _ = request(server, "POST", path + "?expand=true", body=decision(config))
            assert status == 400
    finally:
        service.close()
