"""A saved installation record cannot turn an ordinary action into a tool."""

from __future__ import annotations

from pathlib import Path

import pytest

from bluefire.api import APIError
from bluefire.config import RunnerProfile, load_config
from bluefire.runner_inventory import BUILTIN_NATIVE_TOOL_ACTION_IDS
from bluefire.service import BlueFireService
from tests_platform.test_native_tool_approval_binding import configured_profile
from tests_platform.test_service import ReadyInventoryRunner

ROOT = Path(__file__).resolve().parents[1]


def unsupported_profile() -> RunnerProfile:
    source = next(
        item
        for item in load_config(ROOT / "config/bluefire.example.yaml").runner_profiles
        if item.mode.value == "execute"
    ).to_dict()
    source["id"] = "native-setup-test.v1"
    record = configured_profile().native_tool_installations[0].to_dict()
    record["adapter_id"] = "sandbox.fixture.transform.v1"
    source["native_tool_installations"] = [record]
    return RunnerProfile.from_mapping(source)


def test_legacy_runner_probe_cannot_advertise_native_setup_as_ready() -> None:
    profile = unsupported_profile()
    assert (
        profile.native_tool_installations[0].to_dict()["adapter_id"]
        not in BUILTIN_NATIVE_TOOL_ACTION_IDS
    )
    result = BlueFireService._sanitized_runner_probe(profile, ReadyInventoryRunner().inventory())
    assert result["health"]["state"] == "degraded"
    assert (
        result["health"]["message"]
        == "The installed action catalog does not support this native-tool setup."
    )


def test_native_setup_cannot_issue_approval_or_dispatch_an_ordinary_action(tmp_path: Path) -> None:
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    runner = ReadyInventoryRunner()
    service = BlueFireService(
        project_root=ROOT,
        runs_dir=tmp_path / "runs",
        runner_factory=lambda _profile: (runner, sandbox),
    )
    try:
        profile = unsupported_profile()
        service.save_resource("runner_profile", profile.id, {"document": profile.to_dict()})
        service.activate_resource("runner_profile", profile.id, {})
        request = {
            "scenario_id": "scenario.sandbox.research.chain.v1",
            "mode": "execute",
            "runner_profile_id": profile.id,
            "autonomy": "off",
            "target_scope": {"scope_refs": list(profile.scope)},
        }
        report = service.preflight(request)
        assert report["status"] == "refused"
        assert report["approval_binding"] is None
        assert report["runner_readiness"] is None
        with pytest.raises(APIError) as refused:
            service.submit_run(request)
        assert refused.value.code == "preflight_refused"
        assert any("native-tool setup" in item for item in refused.value.details)
        assert runner.execute_calls == runner.inventory_calls == 0
        assert not (sandbox / ".bluefire-executions").exists()
    finally:
        service.close()
