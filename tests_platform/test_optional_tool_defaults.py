"""Default readiness and explicit gzip setup, with deterministic inspection only."""

from dataclasses import replace

import pytest

from bluefire.config import RunnerProfile, load_config
from bluefire.runner_inventory import BUILTIN_RUNNER_ACTION_VERSIONS
from bluefire.runner_transport_errors import RunnerReadinessError
from bluefire.service import BlueFireService
from bluefire.tool_adapters import chmod, gzip
from tests_platform.test_gzip_tool_binding import (
    ROOT,
    _descriptor,
    _inspection_result,
    candidate,
    installation,
    result,
)
from tests_platform.test_native_tool_inspection_transport import InspectingRunner


class OptionalToolRunner(InspectingRunner):
    platform = "linux"

    def inventory(self):
        value = dict(super().inventory())
        value["platform"] = self.platform
        value["actions"] = [
            {
                "schema_version": "bluefire.runner-action-sdk.v1",
                "action_id": action_id,
                "action_version": version,
                "readiness": "ready",
            }
            for action_id, version in BUILTIN_RUNNER_ACTION_VERSIONS.items()
            if action_id not in {gzip.ADAPTER_ID, chmod.ADAPTER_ID}
        ] + [
            _descriptor(spec.ADAPTER_ID, spec.VERSION, spec.CONTRACT.digest, spec.TOOL_ID)
            for spec in (chmod, gzip)
        ]
        return value

    def inspect_native_tool_candidate(self, request):
        assert request == candidate()
        self.inspect_calls += 1
        return result()

    def inspect_native_tool(self, record):
        assert record == installation().to_dict()
        self.inspect_calls += 1
        return _inspection_result(installation())


@pytest.mark.parametrize("platform", ["windows", "linux", "macos"])
@pytest.mark.parametrize("packaged", [False, True])
def test_default_execute_readiness_does_not_require_optional_tool(tmp_path, platform, packaged):
    (tmp_path / "workspace").mkdir()
    runner = OptionalToolRunner()
    runner.platform = platform
    # An empty project exercises the same packaged config fallback as wheel smoke.
    root = tmp_path / "installed-project" if packaged else ROOT
    service = BlueFireService(
        project_root=root,
        runs_dir=tmp_path / "runs",
        runner_factory=lambda _profile: (runner, tmp_path / "workspace"),
    )
    try:
        profile = next(p for p in service.config.runner_profiles if p.mode.value == "execute")
        assert gzip.ADAPTER_ID not in profile.enabled_actions
        assert not profile.native_tool_installations
        _, _, readiness = service._execute_readiness_boundary(profile)
        assert all(row["readiness"] == "ready" for row in readiness["enabled_actions"])
        assert runner.inspect_calls == runner.execute_calls == 0
        # Explicit selection is never silently downgraded or granted readiness.
        selected = replace(profile, enabled_actions=(*profile.enabled_actions, gzip.ADAPTER_ID))
        with pytest.raises(RunnerReadinessError, match="not ready"):
            service._execute_readiness_boundary(selected)
    finally:
        service.close()


def test_saved_linux_profile_can_explicitly_enable_inspect_bind_and_activate_gzip(tmp_path):
    (tmp_path / "workspace").mkdir()
    runner = OptionalToolRunner()
    service = BlueFireService(
        project_root=ROOT,
        runs_dir=tmp_path / "runs",
        runner_factory=lambda _profile: (runner, tmp_path / "workspace"),
    )
    try:
        profile = next(
            p
            for p in load_config(ROOT / "config/bluefire.example.yaml").runner_profiles
            if p.mode.value == "execute"
        )
        draft = replace(
            profile,
            id="draft.optional-gzip.v1",
            platforms=("linux",),
            enabled_actions=(*profile.enabled_actions, gzip.ADAPTER_ID),
        ).to_dict()
        service.save_resource("runner_profile", draft["id"], {"document": draft, "status": "draft"})
        with pytest.raises(RunnerReadinessError, match="not ready"):
            service._execute_readiness_boundary(RunnerProfile.from_mapping(draft))
        before = service.product_store.get_resource("runner_profile", draft["id"])
        inspected = service.inspect_runner_profile_tool(draft["id"], candidate())
        assert service.product_store.get_resource("runner_profile", draft["id"]) == before
        draft["native_tool_installations"] = [inspected["installation"]]
        service.save_resource("runner_profile", draft["id"], {"document": draft, "status": "draft"})
        service.activate_resource("runner_profile", draft["id"], {})
        saved = service.product_store.get_resource("runner_profile", draft["id"])
        assert saved["status"] == "active"
        _, _, readiness = service._execute_readiness_boundary(
            RunnerProfile.from_mapping(saved["document"])
        )
        row = next(
            row for row in readiness["enabled_actions"] if row["action_id"] == gzip.ADAPTER_ID
        )
        assert row["readiness"] == "ready"
        assert row["native_tool_installation_digest"] == installation().digest
        assert runner.inspect_calls >= 2 and runner.execute_calls == 0
        assert service.store.list_runs() == []
    finally:
        service.close()
