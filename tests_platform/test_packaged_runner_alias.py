"""Installed-default signed alias smoke without executing a native process."""

from copy import deepcopy
from dataclasses import replace

import pytest

from bluefire.runner_client import RunnerReadinessError
from bluefire.service import BlueFireService
from tests_platform.test_action_package_service import PackageRecordingRunner
from tools.verify_packaged_runner import _smoke_signed_package_alias


class StructuralToolRunner(PackageRecordingRunner):
    def inventory(self):
        inventory = deepcopy(super().inventory())
        for action in inventory["actions"]:
            if action["action_id"] == "sandbox.permission.chmod.v1":
                action["readiness"] = "structural"
        return inventory


def test_signed_alias_smoke_with_installed_default_profile(tmp_path):
    runner = StructuralToolRunner()
    result = _smoke_signed_package_alias(runner, tmp_path)
    assert result["status"] == "success"
    assert result["remaining_file_count"] == 0
    assert runner.execute_calls == 1
    assert (
        runner.manifests[0]["execution_binding"]["runner_opcode"] == "endpoint.discovery.system.v1"
    )
    assert "sandbox.permission.chmod.v1" not in runner.profiles[0]["allowed_actions"]


def test_unconfigured_structural_tool_remains_refused_when_explicitly_enabled(tmp_path):
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    runner = StructuralToolRunner()
    service = BlueFireService(
        project_root=tmp_path,
        runs_dir=tmp_path / "runs",
        product_db_path=tmp_path / "product.db",
        runner_factory=lambda _profile: (runner, sandbox),
    )
    try:
        base = next(row for row in service.config.runner_profiles if row.id == "sandbox-execute.v1")
        profile = replace(
            base, enabled_actions=(*base.enabled_actions, "sandbox.permission.chmod.v1")
        )
        with pytest.raises(RunnerReadinessError, match="not ready: sandbox.permission.chmod.v1"):
            service._execute_readiness_boundary(profile)
        assert runner.execute_calls == 0
    finally:
        service.close()
