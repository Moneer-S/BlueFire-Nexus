from __future__ import annotations

import copy
from dataclasses import replace
from pathlib import Path
from typing import Any, Mapping

import pytest

from bluefire.config import AutonomyLevel
from bluefire.contracts import ExecutionMode, load_scenario
from bluefire.runner_inventory import RUNNER_ACTION_SDK_SCHEMA_VERSION
from bluefire.tool_adapters.chmod import CONTRACT
from tests_platform.test_orchestrator import (
    FULL_TARGET_SCOPE,
    StructuredFakeRunner,
    _approval_kwargs,
    _execute_profile,
    _orchestrator,
)

SCENARIO = """\
schema_version: bluefire.scenario.v1
id: scenario.permission.orchestration-test.v1
title: Permission orchestration test
purpose: Test retained receipt ownership with a fake runner.
start: create_fixture
steps:
  - id: create_fixture
    behavior_id: sandbox.fixture.create.v1
    parameters: {record_count: 6}
  - id: transform_fixture
    behavior_id: sandbox.fixture.transform.v1
    parameters: {redact_values: true}
    inputs:
      workspace: {from_step: create_fixture, artifact: workspace}
  - id: permission
    behavior_id: sandbox.permission.relax.v1
    parameters: {mode: "0660"}
    inputs:
      fixture: {from_step: transform_fixture, artifact: fixture}
  - id: cleanup_workspace
    behavior_id: sandbox.cleanup.v1
    parameters: {verify_removal: true}
    inputs:
      workspace: {from_step: create_fixture, artifact: workspace}
edges:
  - {from_step: create_fixture, outcome: success, to_step: transform_fixture}
  - {from_step: transform_fixture, outcome: success, to_step: permission}
  - {from_step: permission, outcome: success, to_step: cleanup_workspace}
  - {from_step: permission, outcome: partial, to_step: cleanup_workspace}
  - {from_step: permission, outcome: failed, to_step: cleanup_workspace}
provenance: {source: test, reference: test, license: MIT, derived: true, notes: test}
limitations: [fake runner only]
"""


class PermissionFakeRunner(StructuredFakeRunner):
    def __init__(self, *, extra_receipt: bool = False, missing_commit: bool = False) -> None:
        super().__init__()
        self.extra_receipt = extra_receipt
        self.missing_commit = missing_commit

    def inventory(self) -> Mapping[str, Any]:
        value = copy.deepcopy(dict(super().inventory()))
        value["platform"] = "linux"
        actions = value["actions"]
        assert isinstance(actions, list)
        actions.append(
            {
                "schema_version": RUNNER_ACTION_SDK_SCHEMA_VERSION,
                "action_id": "sandbox.permission.chmod.v1",
                "action_version": "1.0.0",
                "readiness": "ready",
            }
        )
        return value

    def execute(self, manifest: Mapping[str, Any], profile: Mapping[str, Any]) -> Mapping[str, Any]:
        if manifest["action_id"] != "sandbox.permission.chmod.v1":
            return super().execute(manifest, profile)
        output = {
            "artifact": "fixtures/transformed.jsonl",
            "sha256": "2" * 64,
            "size": 128,
            "requested_mode": "0660",
            "before_mode": "0644",
            "after_mode": "0660",
            "tool": {
                "installation_digest": "sha256:" + "c" * 64,
                "adapter_contract_digest": CONTRACT.digest,
                "tool_version": "9.4",
            },
            "exit_code": 0,
            "stdout_bytes": 0,
            "stderr_bytes": 0,
        }
        result = {
            "schema_version": "bluefire.runner-result.v1",
            **{
                key: manifest[key]
                for key in (
                    "request_id",
                    "run_id",
                    "step_id",
                    "behavior_id",
                    "action_id",
                    "runner_id",
                    "runner_profile_id",
                    "request_hash",
                )
            },
            "policy_digest": profile["policy_digest"],
            "platform": "linux",
            "status": "success",
            "output": output,
            "stdout": {"bytes": 0, "truncated": False},
            "stderr": {"bytes": 0, "truncated": False},
            "evidence": [{"kind": "fake-permission-runner", "status": "success"}],
            "receipt_ids": [manifest["params"]["source_receipt_id"]]
            + (["f" * 64] if self.extra_receipt else []),
            "cleanup": None,
            "error": None,
            "limitations": ["Fake runner; no chmod invocation occurred."],
        }
        if self.missing_commit:
            source = manifest["params"]["source_receipt_id"]
            commit = (
                Path(str(profile["sandbox_root"]))
                / ".bluefire"
                / "receipt-commits"
                / f"{source}.json"
            )
            commit.unlink(missing_ok=True)
        return result


def _scenario(tmp_path: Path):
    path = tmp_path / "permission.yaml"
    path.write_text(SCENARIO, encoding="utf-8")
    return load_scenario(path)


def _linux_profile():
    profile = _execute_profile()
    return replace(
        profile,
        platforms=("linux",),
        enabled_actions=(*profile.enabled_actions, "sandbox.permission.chmod.v1"),
    )


def test_permission_orchestrator_accepts_committed_source_without_new_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("bluefire.orchestrator.current_platform", lambda: "linux")
    monkeypatch.setattr("bluefire.runner_contracts.current_platform", lambda: "linux")
    runner = PermissionFakeRunner()
    orchestrator = _orchestrator(tmp_path, runner)
    scenario, profile = _scenario(tmp_path), _linux_profile()
    choices = {"permission": "sandbox.permission.chmod.v1"}
    approval = _approval_kwargs(
        orchestrator,
        scenario=scenario,
        profile=profile,
        target_scope=FULL_TARGET_SCOPE,
        action_implementations=choices,
    )
    result = orchestrator.run(
        scenario,
        mode=ExecutionMode.EXECUTE,
        profile=profile,
        sandbox_root=tmp_path,
        target_scope=FULL_TARGET_SCOPE,
        autonomy=AutonomyLevel.OFF,
        action_implementations=choices,
        **approval,
    )
    permission = next(row for row in result["steps"] if row["step_id"] == "permission")
    assert permission["status"] == "success"
    assert len(permission["artifacts"]["fixture"]["receipt_ids"]) == 1
    transformed = next(row for row in result["steps"] if row["step_id"] == "transform_fixture")
    assert permission["receipts"] == transformed["receipts"]
    assert result["cleanup"]["outstanding_receipt_count"] == 0


@pytest.mark.parametrize(
    "runner", [PermissionFakeRunner(missing_commit=True), PermissionFakeRunner(extra_receipt=True)]
)
def test_permission_orchestrator_refuses_lost_or_additional_receipt_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    runner: PermissionFakeRunner,
) -> None:
    monkeypatch.setattr("bluefire.orchestrator.current_platform", lambda: "linux")
    monkeypatch.setattr("bluefire.runner_contracts.current_platform", lambda: "linux")
    orchestrator = _orchestrator(tmp_path, runner)
    scenario, profile = _scenario(tmp_path), _linux_profile()
    choices = {"permission": "sandbox.permission.chmod.v1"}
    approval = _approval_kwargs(
        orchestrator,
        scenario=scenario,
        profile=profile,
        target_scope=FULL_TARGET_SCOPE,
        action_implementations=choices,
    )
    result = orchestrator.run(
        scenario,
        mode=ExecutionMode.EXECUTE,
        profile=profile,
        sandbox_root=tmp_path,
        target_scope=FULL_TARGET_SCOPE,
        autonomy=AutonomyLevel.OFF,
        action_implementations=choices,
        **approval,
    )
    permission = next(row for row in result["steps"] if row["step_id"] == "permission")
    assert permission["status"] == "failed"
    assert permission["error"]["code"] == "runner_transport_failed"
    assert permission["artifacts"] == {}
    assert (
        "ownership" in permission["error"]["message"]
        if runner.missing_commit
        else "authority" in permission["error"]["message"]
    )
