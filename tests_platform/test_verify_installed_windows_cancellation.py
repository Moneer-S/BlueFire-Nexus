from __future__ import annotations

import json
import os
import threading
import zipfile
from pathlib import Path

import pytest

from tools import verify_installed_windows_cancellation as verifier


def _passed_driver_report() -> dict[str, object]:
    return {
        "schema_version": "bluefire.installed-windows-cancellation.v1",
        "status": "passed",
        "profile_id": verifier.PROFILE_ID,
        "scenario_id": "scenario.installed-windows-cancel.12345678-1234-4234-8234-123456789abc.v1",
        "scenario_version": 1,
        "scenario_digest": "sha256:" + "a" * 64,
        "job_id": "job-" + "b" * 32,
        "run_id": "run-20261021T120000Z-" + "c" * 16,
        "preflight_status": "approval_required",
        "approval_status_before": "pending",
        "approval_status_after": "consumed",
        "job_state_after_cancel": "cancelled",
        "witness_request_hash": "sha256:" + "d" * 64,
        "runner_stopped": True,
        "execution_interruption": {
            "cooperative_requested": True,
            "cooperative_acknowledged": True,
            "forced_tree_termination": True,
            "control_cleanup_verified": True,
            "process_tree_stopped": True,
        },
        "checks": [
            "shipped_gate11_profile_and_action_verified",
            "fresh_installed_runner_bootstrapped_and_started_through_service",
            "exact_execute_preflight_and_fresh_approval_consumed",
            "cancel_requested_only_after_fresh_witness_processes_were_pinned",
            "retained_interruption_confirmed_cancellation_and_cleanup",
            "both_witness_process_handles_signaled_and_control_tree_removed",
            "managed_runner_stopped_through_service",
        ],
        "request_counts": {
            "session": 1,
            "catalog": 1,
            "runner_status": 2,
            "runner_bootstrap": 1,
            "runner_start": 1,
            "scenario_save": 1,
            "preflight": 1,
            "run_submit": 1,
            "approval": 1,
            "cancel": 1,
            "retained_observations": 1,
            "runner_stop": 1,
            "job_status": 2,
        },
    }


def test_profile_authority_accepts_only_shipped_gate11_bounds() -> None:
    profile = {
        "id": verifier.PROFILE_ID,
        "mode": "execute",
        "platforms": ["windows"],
        "scope": ["sandbox.workspace"],
        "network_allowlist": [],
        "approval_required": True,
        "enabled_actions": [verifier.ACTION_ID, "sandbox.cleanup.v1"],
        "blocked_actions": [],
        "budgets": {"max_steps": 1, "max_seconds": 30, "max_artifacts": 4, "max_bytes": 65536},
    }
    assert verifier._profile_authority_valid(profile)
    for field, value in (
        ("network_allowlist", ["127.0.0.1/32"]),
        ("approval_required", False),
        ("enabled_actions", [verifier.ACTION_ID, "sandbox.network.loopback.v1"]),
        ("budgets", {"max_steps": 2, "max_seconds": 30, "max_artifacts": 4, "max_bytes": 65536}),
    ):
        changed = dict(profile)
        changed[field] = value
        assert not verifier._profile_authority_valid(changed)


def test_ready_record_requires_exact_request_bound_process_identity() -> None:
    digest = "a" * 64
    record = {
        "schema_version": "bluefire.process-tree-cancellation-ready.v1",
        "task_id": f"execute-{digest}",
        "request_hash": f"sha256:{digest}",
        "parent_process_id": 100,
        "descendant_process_id": 200,
    }
    assert verifier._ready_record_valid(record, directory_name=digest)
    for field, value in (
        ("parent_process_id", True),
        ("descendant_process_id", 100),
        ("request_hash", "sha256:" + "A" * 64),
    ):
        changed = dict(record)
        changed[field] = value
        assert not verifier._ready_record_valid(changed, directory_name=digest)
    extra = {**record, "unreviewed": True}
    assert not verifier._ready_record_valid(extra, directory_name=digest)


def test_witness_observer_uses_fresh_approval_workspace_and_pins_before_permit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    digest = "e" * 64
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    task = (
        sandbox
        / ".bluefire-executions"
        / "approval-test"
        / ".bluefire-cancellation-witness-v1"
        / digest
    )
    task.mkdir(parents=True)
    ready = {
        "schema_version": "bluefire.process-tree-cancellation-ready.v1",
        "task_id": f"execute-{digest}",
        "request_hash": f"sha256:{digest}",
        "parent_process_id": 101,
        "descendant_process_id": 202,
    }
    (task / "ready.json").write_text(json.dumps(ready), encoding="utf-8")
    marker = tmp_path / "observed.json"
    permit = tmp_path / "permit.json"
    marker.write_text(
        json.dumps({key: value for key, value in ready.items() if key != "schema_version"}),
        encoding="utf-8",
    )
    pinned: list[dict[str, object]] = []
    monkeypatch.setattr(
        verifier, "_pin_windows_processes", lambda value: pinned.append(value.copy())
    )

    result = verifier._private_ready_record(sandbox, marker, permit, threading.Event())

    assert pinned == [ready]
    assert result["control_path"] == task
    assert json.loads(permit.read_text(encoding="utf-8")) == {
        "witness_request_hash": f"sha256:{digest}"
    }


def test_witness_observer_rejects_ambiguous_approval_workspaces(tmp_path: Path) -> None:
    sandbox = tmp_path / "sandbox"
    executions = sandbox / ".bluefire-executions"
    executions.mkdir(parents=True)
    (executions / "approval-one").mkdir()
    (executions / "approval-two").mkdir()
    digest = "f" * 64
    marker = tmp_path / "observed.json"
    marker.write_text(
        json.dumps(
            {
                "request_hash": f"sha256:{digest}",
                "task_id": f"execute-{digest}",
                "parent_process_id": 11,
                "descendant_process_id": 22,
            }
        ),
        encoding="utf-8",
    )
    permit = tmp_path / "permit.json"

    with pytest.raises(ValueError, match="workspace identity"):
        verifier._private_ready_record(sandbox, marker, permit, threading.Event())
    assert json.loads(permit.read_text(encoding="utf-8")) == {"denied": True}


def test_wheel_identity_requires_installed_package_bytes_to_match(tmp_path: Path) -> None:
    wheel = tmp_path / "bluefire_nexus-1.2.3-py3-none-any.whl"
    package = tmp_path / "site-packages" / "bluefire"
    package.mkdir(parents=True)
    files = {
        "bluefire/__init__.py": b"__version__ = '1.2.3'\n",
        "bluefire/example.py": b"VALUE = 1\n",
        "bluefire/native/bluefire-runner.exe": b"fixture binary\n",
    }
    (package / "__init__.py").write_bytes(files["bluefire/__init__.py"])
    (package / "example.py").write_bytes(files["bluefire/example.py"])
    (package / "native").mkdir()
    (package / "native" / "bluefire-runner.exe").write_bytes(
        files["bluefire/native/bluefire-runner.exe"]
    )
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(
            "bluefire_nexus-1.2.3.dist-info/METADATA", "Name: bluefire-nexus\nVersion: 1.2.3\n\n"
        )
        for name, content in files.items():
            archive.writestr(name, content)

    assert verifier._installed_package_matches_wheel(wheel, package, "1.2.3")
    assert not verifier._installed_package_matches_wheel(wheel, package, "1.2.4")
    (package / "example.py").write_text("VALUE = 2\n", encoding="utf-8")
    assert not verifier._installed_package_matches_wheel(wheel, package, "1.2.3")


@pytest.mark.parametrize("library", ["purelib", "platlib"])
def test_wheel_identity_normalizes_standard_data_package_layouts(
    tmp_path: Path, library: str
) -> None:
    wheel = tmp_path / "bluefire_nexus-1.2.3-py3-none-any.whl"
    package = tmp_path / "site-packages" / "bluefire"
    package.mkdir(parents=True)
    files = {
        "__init__.py": b"__version__ = '1.2.3'\n",
        "native/bluefire-runner.exe": b"fixture binary\n",
    }
    (package / "__init__.py").write_bytes(files["__init__.py"])
    (package / "native").mkdir()
    (package / "native" / "bluefire-runner.exe").write_bytes(files["native/bluefire-runner.exe"])
    data_root = f"bluefire_nexus-1.2.3.data/{library}/bluefire"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(
            "bluefire_nexus-1.2.3.dist-info/METADATA", "Name: bluefire-nexus\nVersion: 1.2.3\n\n"
        )
        for name, content in files.items():
            archive.writestr(f"{data_root}/{name}", content)

    assert verifier._installed_package_matches_wheel(wheel, package, "1.2.3")


def test_wheel_identity_rejects_conflicting_package_layouts(tmp_path: Path) -> None:
    wheel = tmp_path / "bluefire_nexus-1.2.3-py3-none-any.whl"
    package = tmp_path / "site-packages" / "bluefire"
    package.mkdir(parents=True)
    package_file = package / "__init__.py"
    package_file.write_bytes(b"__version__ = '1.2.3'\n")
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(
            "bluefire_nexus-1.2.3.dist-info/METADATA", "Name: bluefire-nexus\nVersion: 1.2.3\n\n"
        )
        archive.writestr("bluefire/__init__.py", package_file.read_bytes())
        archive.writestr(
            "bluefire_nexus-1.2.3.data/purelib/bluefire/__init__.py",
            b"__version__ = '1.2.4'\n",
        )

    assert not verifier._installed_package_matches_wheel(wheel, package, "1.2.3")


def test_wheel_identity_rejects_symlinked_installed_package_directory(tmp_path: Path) -> None:
    wheel = tmp_path / "bluefire_nexus-1.2.3-py3-none-any.whl"
    package = tmp_path / "site-packages" / "bluefire"
    package.mkdir(parents=True)
    (package / "__init__.py").write_bytes(b"__version__ = '1.2.3'\n")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "injected.py").write_text("VALUE = 1\n", encoding="utf-8")
    try:
        os.symlink(outside, package / "linked", target_is_directory=True)
    except OSError as error:
        pytest.skip(f"directory symlinks unavailable: {type(error).__name__}")
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(
            "bluefire_nexus-1.2.3.dist-info/METADATA", "Name: bluefire-nexus\nVersion: 1.2.3\n\n"
        )
        archive.writestr("bluefire/__init__.py", b"__version__ = '1.2.3'\n")

    assert not verifier._installed_package_matches_wheel(wheel, package, "1.2.3")


def test_driver_receipt_contract_and_job_count_are_strict() -> None:
    report = _passed_driver_report()
    assert verifier._driver_passed(report)
    for value in (True, 1, 101):
        changed = {**report, "request_counts": {**report["request_counts"], "job_status": value}}
        assert not verifier._driver_passed(changed)
    changed = {**report, "scenario_version": True}
    assert not verifier._driver_passed(changed)
    changed = {**report, "request_counts": {**report["request_counts"], "cancel": True}}
    assert not verifier._driver_passed(changed)


@pytest.mark.parametrize(
    ("report", "expected"),
    [
        ({"driver_job_created": False}, True),
        (
            {"driver_job_created": True, "driver_job_empty": True, "driver_process_exited": True},
            True,
        ),
        (
            {"driver_job_created": True, "driver_job_empty": False, "driver_process_exited": True},
            False,
        ),
        (
            {"driver_job_created": True, "driver_job_empty": True, "driver_process_exited": False},
            False,
        ),
    ],
)
def test_cleanup_requires_every_created_job_to_drain(report, expected: bool) -> None:
    assert verifier._all_owned_groups_stopped(report) is expected


def _cleanup_ready_report() -> dict[str, object]:
    return {
        "driver_job_created": False,
        "driver_job_empty": True,
        "driver_process_exited": True,
        "managed_runner_stopped": True,
        "service_thread_stopped": True,
        "service_http_server_closed": True,
        "service_closed": True,
        "witness_could_have_started": False,
        "witness_observer_stopped": True,
        "witness_process_handles_stopped": True,
        "witness_control_tree_removed": True,
    }


def test_runtime_removal_requires_all_owned_resources_closed() -> None:
    assert verifier._runtime_removal_allowed(_cleanup_ready_report())
    for field in (
        "managed_runner_stopped",
        "service_thread_stopped",
        "service_http_server_closed",
        "service_closed",
        "witness_observer_stopped",
    ):
        changed = _cleanup_ready_report()
        changed[field] = False
        assert not verifier._runtime_removal_allowed(changed), field


@pytest.mark.parametrize(
    "field",
    ["witness_process_handles_stopped", "witness_control_tree_removed", "witness_observer_stopped"],
)
def test_runtime_removal_requires_witness_cleanup_after_possible_start(field: str) -> None:
    report = _cleanup_ready_report()
    report["witness_could_have_started"] = True
    report[field] = False
    assert not verifier._runtime_removal_allowed(report)


def test_runtime_removal_accepts_complete_witness_cleanup() -> None:
    report = _cleanup_ready_report()
    report["witness_could_have_started"] = True
    assert verifier._runtime_removal_allowed(report)


@pytest.mark.parametrize("state", ["stopped", "unbootstrapped"])
def test_unstarted_runner_is_a_confirmed_clean_state(state: str) -> None:
    class Lifecycle:
        def status(self, **_kwargs):
            return {"state": state}

        def stop(self, **_kwargs):
            pytest.fail("already stopped or unbootstrapped runner should not be mutated")

    assert verifier._stop_managed_runner(Lifecycle())


def test_active_runner_must_stop_and_recheck() -> None:
    class Lifecycle:
        states = iter(("ready", "stopped"))

        def status(self, **_kwargs):
            return {"state": next(self.states)}

        def stop(self, **_kwargs):
            self.stopped = True

    lifecycle = Lifecycle()
    assert verifier._stop_managed_runner(lifecycle)
    assert lifecycle.stopped
