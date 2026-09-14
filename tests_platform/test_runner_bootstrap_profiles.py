"""Selected-profile bootstrap responses use staged byte fixtures, never a runner."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

import pytest

from bluefire import runner_lifecycle as lifecycle_module
from bluefire.application_errors import APIError
from bluefire.contracts import ExecutionMode
from bluefire.runner_lifecycle import ManagedRunnerLifecycle, RunnerLifecycleError
from bluefire.runner_trust import load_local_enrollment
from bluefire.service import BlueFireService
from tests_platform.runner_lifecycle_host_helper import ProcessTestSecretProvider
from tests_platform.test_runner_history_upgrade import ROOT, _StagedBootstrap

PROFILES = ("endpoint-execute.v1", "sandbox-execute.v1")


def _manager(root: Path) -> tuple[ManagedRunnerLifecycle, _StagedBootstrap]:
    factory = _StagedBootstrap()
    return (
        ManagedRunnerLifecycle(
            root, secret_provider=ProcessTestSecretProvider(), bootstrap_factory=factory
        ),
        factory,
    )


@pytest.mark.parametrize("selected", [None, PROFILES[0], PROFILES[1]])
def test_bootstrap_and_repeat_return_selected_profile_with_unchanged_enrollment(
    tmp_path_factory: pytest.TempPathFactory, selected: str | None
) -> None:
    manager, _ = _manager(tmp_path_factory.mktemp("p") / "m")
    expected = PROFILES[0] if selected is None else selected
    first = manager.bootstrap(allowed_profile_ids=PROFILES, profile_id=selected)
    enrollment = load_local_enrollment(
        manager.enrollment_root, secret_provider=manager.secret_provider
    )
    assert enrollment.allowed_profile_ids == PROFILES
    bootstrap = manager.bootstrap_record_path.read_bytes()
    repeated = manager.bootstrap(allowed_profile_ids=PROFILES, profile_id=selected)
    for result in (first, repeated):
        assert result["profile_id"] == expected
        assert (result["state"], result["enrollment"], result["process"]) == (
            "stopped",
            "active",
            "absent",
        )
    assert manager.bootstrap_record_path.read_bytes() == bootstrap
    assert (
        load_local_enrollment(
            manager.enrollment_root, secret_provider=manager.secret_provider
        ).allowed_profile_ids
        == PROFILES
    )
    assert manager.status(profile_id=None)["profile_id"] == PROFILES[0]
    assert manager.status(profile_id="")["profile_id"] == PROFILES[0]


@pytest.mark.parametrize("selected", ["not-enrolled.v1", "", 7])
def test_unknown_response_profile_refused_before_bootstrap_effects(
    tmp_path: Path, selected: Any
) -> None:
    root = tmp_path / "m"
    manager, factory = _manager(root)
    with pytest.raises(RunnerLifecycleError, match="profile is not enrolled"):
        manager.bootstrap(allowed_profile_ids=PROFILES, profile_id=selected)
    assert not root.exists()
    assert factory.binaries == {}


@pytest.mark.parametrize("interrupted", [False, True])
def test_service_reviewed_upgrade_and_recovery_return_the_requested_nonfirst_profile(
    tmp_path_factory: pytest.TempPathFactory,
    monkeypatch: pytest.MonkeyPatch,
    interrupted: bool,
) -> None:
    root = tmp_path_factory.mktemp("p")
    manager, factory = _manager(root / "m")
    service = BlueFireService(project_root=ROOT, runs_dir=root / "r", runner_lifecycle=manager)
    try:
        profiles = tuple(
            profile.id
            for profile in service._runner_profiles()
            if profile.mode is ExecutionMode.EXECUTE
        )
        assert len(profiles) > 1
        selected = profiles[-1]
        assert selected != profiles[0]
        initial = service.bootstrap_runner(profile_id=selected)
        assert initial["profile_id"] == selected
        old_binary = factory.binaries["1.0.0"]
        old_bytes = old_binary.read_bytes()
        factory.version = "2.0.0"
        review = service.review_runner_upgrade(profile_id=selected)
        assert review["staging"]["execution_started"] is False
        if interrupted:
            original_write = lifecycle_module._write_private_json

            def stop_after_pending(path: Path, value: Mapping[str, Any], **kwargs: Any) -> None:
                original_write(path, value, **kwargs)
                if path.name == "upgrade-pending.json":
                    raise OSError("fixture interruption after approved pending record")

            with monkeypatch.context() as patch:
                patch.setattr(lifecycle_module, "_write_private_json", stop_after_pending)
                with pytest.raises(APIError):
                    service.bootstrap_runner(
                        profile_id=selected,
                        allow_upgrade=True,
                        upgrade_review_digest=review["review_digest"],
                    )
            pending = manager.control_root / "upgrade-pending.json"
            pending_bytes = pending.read_bytes()
            with pytest.raises(RunnerLifecycleError, match="profile is not enrolled"):
                manager.bootstrap(
                    allowed_profile_ids=profiles,
                    profile_id="not-enrolled.v1",
                    allow_upgrade=True,
                    upgrade_review_digest=review["review_digest"],
                )
            assert pending.read_bytes() == pending_bytes
            review = service.review_runner_upgrade(profile_id=selected)
            assert review["recovery_required"] is True
        result = service.bootstrap_runner(
            profile_id=selected, allow_upgrade=True, upgrade_review_digest=review["review_digest"]
        )
        assert result["profile_id"] == selected
        assert (result["state"], result["enrollment"], result["process"]) == (
            "stopped",
            "active",
            "absent",
        )
        assert result["runner"]["runner_version"] == "2.0.0"
        assert old_binary.read_bytes() == old_bytes
        assert not (manager.control_root / "upgrade-pending.json").exists()
        assert (
            load_local_enrollment(
                manager.enrollment_root, secret_provider=manager.secret_provider
            ).allowed_profile_ids
            == profiles
        )
        assert not manager.process_record_path.exists()
    finally:
        service.close()
