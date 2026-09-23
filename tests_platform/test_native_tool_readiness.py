"""A saved installation record cannot turn an ordinary action into a tool."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any, Mapping

import pytest

from bluefire.api import APIError
from bluefire.config import RunnerProfile, load_config
from bluefire.job_runtime import JobState
from bluefire.native_tool_installations import NativeToolInstallation
from bluefire.runner_inventory import BUILTIN_NATIVE_TOOL_ACTION_IDS
from bluefire.service import BlueFireService
from bluefire.tool_adapters.chmod import ADAPTER_ID, CONTRACT, TOOL_ID, VERSION
from tests_platform.test_native_tool_approval_binding import configured_profile
from tests_platform.test_service import ReadyInventoryRunner, _ready_inventory

ROOT = Path(__file__).resolve().parents[1]


def reviewed_profile() -> RunnerProfile:
    profile = configured_profile()
    record = profile.native_tool_installations[0].to_dict()
    record["adapter_contract_digest"] = CONTRACT.digest
    return replace(
        profile,
        native_tool_installations=(NativeToolInstallation.from_mapping(record),),
    )


class ReviewedChmodRunner(ReadyInventoryRunner):
    def __init__(self, *, failure: str | None = None) -> None:
        super().__init__(actions=set(self_actions()))
        self.failure = failure

    def inventory(self) -> Mapping[str, Any]:
        self.inventory_calls += 1
        inventory = dict(_ready_inventory(actions=self.actions))
        inventory["platform"] = "linux"
        actions = list(inventory["actions"])
        actions.append(
            {
                "schema_version": "bluefire.runner-action-sdk.v1",
                "action_id": ADAPTER_ID,
                "action_version": VERSION,
                "readiness": "structural",
                "native_tool_binding": {
                    "adapter_id": ADAPTER_ID,
                    "adapter_version": VERSION,
                    "adapter_contract_digest": CONTRACT.digest,
                    "tool_id": TOOL_ID,
                },
            }
        )
        inventory["actions"] = actions
        if self.failure == "identity" and self.inventory_calls > 1:
            inventory["runner_version"] = "changed-runner"
        return inventory

    def inspect_native_tool(self, installation: Mapping[str, Any]) -> Mapping[str, Any]:
        if self.failure == "unavailable":
            return {
                "schema_version": "bluefire.native-tool-inspection.v1",
                "installation_digest": NativeToolInstallation.from_mapping(installation).digest,
                "status": "unavailable",
                "code": "inspection_unavailable",
                "content_sha256": None,
                "size_bytes": None,
                "platform": "linux",
                "architecture": "x86_64",
            }
        result = {
            "schema_version": "bluefire.native-tool-inspection.v1",
            "installation_digest": NativeToolInstallation.from_mapping(installation).digest,
            "status": "ready",
            "code": "verified",
            "content_sha256": installation["content_sha256"],
            "size_bytes": installation["size_bytes"],
            "platform": "linux",
            "architecture": "x86_64",
        }
        if self.failure == "digest":
            result["content_sha256"] = "sha256:" + "c" * 64
        return result


def self_actions() -> tuple[str, ...]:
    return tuple(
        item
        for item in next(
            profile
            for profile in load_config(ROOT / "config/bluefire.example.yaml").runner_profiles
            if profile.mode.value == "execute"
        ).enabled_actions
    )


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


def _saved_native_request(profile: RunnerProfile) -> dict[str, Any]:
    return {
        "scenario_id": "scenario.sandbox.research.chain.v1",
        "mode": "execute",
        "runner_profile_id": profile.id,
        "autonomy": "off",
        "target_scope": {"scope_refs": list(profile.scope)},
    }


def _service_with_native_profile(tmp_path: Path, runner: ReviewedChmodRunner):
    profile = reviewed_profile()
    service = BlueFireService(
        project_root=ROOT,
        runs_dir=tmp_path / "runs",
        runner_factory=lambda _profile: (runner, tmp_path / "sandbox"),
    )
    (tmp_path / "sandbox").mkdir()
    service.save_resource("runner_profile", profile.id, {"document": profile.to_dict()})
    service.activate_resource("runner_profile", profile.id, {})
    return service, profile


def test_saved_reviewed_chmod_profile_preflight_binds_verified_inspection(tmp_path: Path) -> None:
    runner = ReviewedChmodRunner()
    service, profile = _service_with_native_profile(tmp_path, runner)
    try:
        report = service.preflight(_saved_native_request(profile))
        assert report["runner_readiness"] is not None
        assert report["approval_binding"] is not None
        assert report["approval_binding"]["state_digest"]
        assert runner.execute_calls == 0
    finally:
        service.close()


@pytest.mark.parametrize("failure", ["unavailable", "digest", "identity"])
def test_saved_native_profile_refuses_unverified_inspection_without_approval_or_execute(
    tmp_path: Path, failure: str
) -> None:
    runner = ReviewedChmodRunner(failure=failure)
    service, profile = _service_with_native_profile(tmp_path, runner)
    try:
        report = service.preflight(_saved_native_request(profile))
        assert report["status"] == "refused"
        assert report["approval_binding"] is None
        assert report["runner_readiness"] is None
        assert runner.execute_calls == 0
    finally:
        service.close()


def test_static_probe_with_saved_record_alone_is_degraded() -> None:
    profile = reviewed_profile()
    inventory = ReviewedChmodRunner().inventory()
    result = BlueFireService._sanitized_runner_probe(profile, inventory)
    assert result["health"]["state"] == "degraded"


@pytest.mark.parametrize("failure", ["unavailable", "digest", "exception"])
def test_dispatch_inspection_refusal_settles_claimed_workspace(
    tmp_path: Path, failure: str
) -> None:
    """Readiness succeeds; only the inspection after claiming approval fails."""
    approval_id: str | None = None
    dispatch_inspections = 0

    class ChangedToolRunner(ReviewedChmodRunner):
        def inspect_native_tool(self, installation: Mapping[str, Any]) -> Mapping[str, Any]:
            nonlocal dispatch_inspections
            if (
                approval_id is not None
                and service.product_store.get_approval_request(approval_id)["status"] == "claimed"
            ):
                dispatch_inspections += 1
                if failure == "exception":
                    raise OSError("unavailable tool at /private/host/tool")
                self.failure = failure
            return super().inspect_native_tool(installation)

    runner = ChangedToolRunner()
    service, profile = _service_with_native_profile(tmp_path, runner)
    try:
        submission = service.submit_run(_saved_native_request(profile))
        assert submission["preflight"]["runner_readiness"] is not None
        approval_id = str(submission["approval_request"]["approval_id"])
        job_id = str(submission["job"]["job_id"])
        service.job_controller.wait_for_state(job_id, {JobState.AWAITING_APPROVAL}, timeout=3)
        service.approve_job(job_id, {"approved_by": "tool-reviewer"})
        failed = service.job_controller.wait(job_id, timeout=3)

        assert dispatch_inspections == 1
        assert failed["state"] == "failed"
        assert failed["error"] == {
            "code": "execution_callback_failed",
            "message": "execution callback failed",
            "exception_type": "APIError",
        }
        assert "/private/host" not in str(failed)
        assert runner.execute_calls == 0
        assert service.store.list_runs() == []
        assert service.product_store.get_approval_request(approval_id)["status"] == "claimed"
        workspace = service.product_store.get_execution_workspace(approval_id)
        assert workspace["state"] == "not_required"
        assert workspace["run_id"] is None
        assert workspace["outcome"] == {
            "schema_version": "bluefire.execution-settlement.v1",
            "status": "pre_dispatch_refused",
            "remaining_receipt_count": 0,
        }
        with pytest.raises(APIError):
            service.approve_job(job_id, {"approved_by": "tool-reviewer"})
        assert dispatch_inspections == 1
        assert runner.execute_calls == 0
    finally:
        service.close()
