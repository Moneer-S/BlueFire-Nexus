from __future__ import annotations

import shutil
import subprocess
import zipfile
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable

import pytest

import bluefire.install_gate as install_gate
import bluefire.install_gate_validation as validation
import bluefire.product_gates as product_gates
from bluefire.product_acceptance import load_release_contract

REPOSITORY = Path(__file__).resolve().parents[1]
_DIGEST = "sha256:" + "a" * 64
_RUNNER_DIGEST = "sha256:" + "b" * 64
_RUN_IDS = (
    "run-20300101T000000Z-0123456789abcdef",
    "run-20300101T000001Z-fedcba9876543210",
)
_APPROVAL_IDS = (
    "approval-0123456789abcdef0123456789abcdef",
    "approval-fedcba9876543210fedcba9876543210",
)
_JOB_ID = "job-0123456789abcdef0123456789abcdef"


def _inspection() -> dict[str, Any]:
    return {
        "schema_version": "bluefire.package-inspection.v1",
        "wheel": "bluefire_nexus-0.1.0-py3-none-win_amd64.whl",
        "wheel_sha256": "a" * 64,
        "tag": "py3-none-win_amd64",
        "platform": "windows",
        "architecture": "x86_64",
        "runner": {"filename": "bluefire-runner.exe", "size": 1, "sha256": "b" * 64},
        "verified": True,
    }


def _provision() -> dict[str, Any]:
    versions = {
        "PyYAML": "6.0.3",
        "cryptography": "46.0.3",
        "PyNaCl": "1.6.2",
        "cffi": "2.0.0",
        "pycparser": "2.23",
    }
    return {
        "schema_version": "bluefire.gate01-dependency-provision.v1",
        "verified": True,
        "method": "copied-verified-installed-distributions",
        "isolated_environment": True,
        "wheel_sha256": _DIGEST,
        "wheel_requirements_satisfied": True,
        "distributions": {
            name: {"version": version, "file_count": 1, "content_digest": _DIGEST}
            for name, version in versions.items()
        },
    }


def _wheel_dependency_metadata() -> dict[str, Any]:
    requirements = [
        {"name": "cryptography", "specifier": "<47,>=45"},
        {"name": "pynacl", "specifier": "<2,>=1.5"},
        {"name": "pyyaml", "specifier": "<7,>=6.0.1"},
    ]
    return {
        "schema_version": "bluefire.gate01-wheel-dependency-metadata.v1",
        "verified": True,
        "project_name": "bluefire-nexus",
        "project_version": "0.1.0",
        "requires_python": ">=3.10",
        "wheel_sha256": _DIGEST,
        "declared_runtime_dependencies": deepcopy(requirements),
        "wheel_requires_dist": deepcopy(requirements),
    }


def _runtime() -> dict[str, Any]:
    return {
        "schema_version": "bluefire.gate01-installed-package.v1",
        "verified": True,
        "package_version": "0.1.0",
        "fresh_environment": {
            "isolated_mode": True,
            "virtual_environment": True,
            "user_site_enabled": False,
            "package_under_environment_site": True,
            "checkout_on_import_path": False,
            "editable_install": False,
            "console_entrypoint": True,
        },
        "dependencies": {
            "PyYAML": "6.0.3",
            "cryptography": "46.0.3",
            "PyNaCl": "1.6.2",
        },
        "source_overrides_absent": True,
    }


def _ui() -> dict[str, Any]:
    return {
        "schema_version": "bluefire.gate01-ui-health.v1",
        "verified": True,
        "launch": {
            "command": [
                "{python}",
                "-I",
                "-m",
                "bluefire.cli",
                "--runs-dir",
                "{runs-dir}",
                "ui",
                "--host",
                "127.0.0.1",
                "--port",
                "0",
            ],
            "loopback_only": True,
            "ephemeral_port": True,
            "capability_fragment_only": True,
            "capability_single_use": True,
            "strict_session_cookie": True,
        },
        "assets": {
            "/ui/app.js": {"size_bytes": 512, "sha256": _DIGEST},
            "/ui/styles.css": {"size_bytes": 512, "sha256": _DIGEST},
        },
        "api": {
            "session_healthy": True,
            "catalog_behavior_count": 1,
            "scenario_count": 1,
            "seeded_scenario_present": True,
        },
        "runtime_probe": {
            "engine": "edge-headless",
            "browser_sandbox": "disabled-for-ephemeral-probe",
            "network_scope": "loopback-only",
            "javascript_executed": True,
            "authenticated_root_rendered": True,
            "catalog_data_rendered": True,
            "runs_navigation_present": True,
            "runs_route_rendered": True,
            "guided_execute_rendered": True,
        },
    }


def _binding(state: str = "c") -> dict[str, Any]:
    return {
        "state_digest": "sha256:" + state * 64,
        "plan_digest": "sha256:" + "d" * 64,
        "target_scope_digest": "sha256:" + "e" * 64,
        "profile_id": "sandbox-restricted-owned.v1",
        "maximum_tier": "restricted",
    }


def _journey_run(
    run_id: str,
    replay_of: str | None,
    approval_id: str,
    operator: str,
    *,
    state: str = "c",
) -> dict[str, Any]:
    return {
        "run_id": run_id,
        "status": "completed",
        "objective_reached": True,
        "step_count": 2,
        "evidence_provenance": ["executed", "observed"],
        "cleanup": {"attempted": True, "success": True, "outstanding_receipt_count": 0},
        "approval_status": "claimed",
        "replay_source_run_id": replay_of,
        "scenario_id": "scenario.restricted.persistence-canary.v1",
        "runner_profile_id": "sandbox-restricted-owned.v1",
        "scope_refs": ["sandbox.workspace"],
        "approval_id": approval_id,
        "approval_binding": _binding(state),
        "approval_operator": operator,
        "observation": {
            "producer": "collector.filesystem.sandbox.v1",
            "collector_id": "collector.filesystem.sandbox.v1",
            "artifact_path": "restricted/persistence-marker.json",
            "artifact_digest": "sha256:" + "f" * 64,
            "parent_linked": True,
        },
        "residual_canary_absent": True,
    }


def _journey() -> dict[str, Any]:
    return {
        "schema_version": "bluefire.gate01-journey.v1",
        "verified": True,
        "selection": {
            "scenario_id": "scenario.restricted.persistence-canary.v1",
            "runner_profile_id": "sandbox-restricted-owned.v1",
            "collector_id": "collector.filesystem.sandbox.v1",
            "scope_refs": ["sandbox.workspace"],
        },
        "packaged_runner": {
            "source": "packaged",
            "managed_binary": True,
            "managed_sandbox": True,
            "runner_id": "bluefire-rust-runner.v1",
            "bootstrap_state": "stopped",
            "recovery_reused_exact_identity": True,
            "binary_digest": _RUNNER_DIGEST,
        },
        "local_trust": {
            "enrollment": "active",
            "manual_certificate_input": False,
            "manual_hmac_input": False,
            "authenticated_transport": "mutual-tls-loopback",
            "tls": "TLSv1.3",
        },
        "preflight": {
            "status": "approval_required",
            "exact_binding_present": True,
            "exact_envelope_present": True,
            "collector_bound": True,
            "approval_binding": _binding(),
            "envelope_digest": "sha256:" + "9" * 64,
        },
        "approval_job": {
            "job_id": _JOB_ID,
            "request_approval_id": _APPROVAL_IDS[0],
            "progress_approval_ref": _APPROVAL_IDS[0],
            "snapshot_count": 4,
            "initial_state": "awaiting_approval",
            "approval_status": "consumed",
            "terminal_state": "completed",
            "approval_id": _APPROVAL_IDS[0],
            "approval_binding": _binding(),
            "run_approval_status": "claimed",
            "cross_bound": True,
        },
        "source_run": _journey_run(_RUN_IDS[0], None, _APPROVAL_IDS[0], "gate01-release-operator"),
        "replay_run": _journey_run(
            _RUN_IDS[1],
            _RUN_IDS[0],
            _APPROVAL_IDS[1],
            "gate01-replay-operator",
            state="1",
        ),
        "fresh_replay_approval": True,
        "comparison": {
            "comparison_id": "comparison-0123456789abcdef",
            "run_ids": list(_RUN_IDS),
            "delta_count": 1,
        },
        "teardown": {
            "stopped": True,
            "trust_revoked": True,
            "state_removed": True,
            "final_state": "unbootstrapped",
        },
    }


def _structural() -> dict[str, Any]:
    return {
        "schema_version": "bluefire.gate01-structural.v1",
        "verified": True,
        "checks": {
            "console_entrypoint": True,
            "packaged_ui_and_runner": True,
            "platform_wheel_verification": True,
            "explicit_cli_workflow": True,
            "guided_execute_onboarding": True,
            "fresh_approval_boundary": True,
        },
    }


def _verification() -> dict[str, Any]:
    return {
        "schema_version": "bluefire.gate01-verification.v1",
        "passed": True,
        "checks": {
            "fresh_install": True,
            "ui_launch": True,
            "packaged_runner": True,
            "local_trust": True,
            "execute_journey": True,
            "observe_cleanup_replay_compare": True,
            "simple_workflow": True,
        },
        "run_ids": list(_RUN_IDS),
    }


def _summary() -> dict[str, Any]:
    return {
        "schema_version": "bluefire.gate01-helper-summary.v1",
        "status": "passed",
        "checks": [
            "fresh_install",
            "ui_launch",
            "packaged_runner",
            "local_trust",
            "execute_journey",
            "observe_cleanup_replay_compare",
        ],
        "run_count": 2,
    }


def _replace(report: dict[str, Any], path: tuple[str, ...], value: Any) -> dict[str, Any]:
    changed = deepcopy(report)
    target = changed
    for field in path[:-1]:
        target = target[field]
    target[path[-1]] = value
    return changed


def test_persisted_evidence_validators_accept_the_exact_gate_contract() -> None:
    validation.validate_inspection(_inspection())
    validation.validate_wheel_dependency_metadata(_wheel_dependency_metadata())
    validation.validate_wheel_metadata_binding(_inspection(), _wheel_dependency_metadata())
    validation.validate_dependency_provision(_provision())
    validation.validate_dependency_provision_binding(_wheel_dependency_metadata(), _provision())
    validation.validate_package_runtime(_runtime())
    validation.validate_dependency_runtime_binding(
        _wheel_dependency_metadata(), _provision(), _runtime()
    )
    validation.validate_ui(_ui())
    assert validation.validate_journey(_journey()) == _RUN_IDS
    validation.validate_runner_digest_binding(_inspection(), _journey())
    validation.validate_structural(_structural())
    assert validation.validate_verification(_verification()) == _RUN_IDS
    validation.validate_summary(_summary())


def test_persisted_evidence_validators_reject_material_tampering() -> None:
    cases: list[tuple[Callable[[Any], Any], dict[str, Any], tuple[str, ...], Any]] = [
        (validation.validate_inspection, _inspection(), ("verified",), False),
        (
            validation.validate_wheel_dependency_metadata,
            _wheel_dependency_metadata(),
            ("wheel_requires_dist",),
            _wheel_dependency_metadata()["wheel_requires_dist"][:-1],
        ),
        (validation.validate_dependency_provision, _provision(), ("isolated_environment",), False),
        (
            validation.validate_package_runtime,
            _runtime(),
            ("fresh_environment", "checkout_on_import_path"),
            True,
        ),
        (validation.validate_ui, _ui(), ("launch", "capability_single_use"), False),
        (
            validation.validate_journey,
            _journey(),
            ("source_run", "observation", "producer"),
            "runner-self-report.v1",
        ),
        (
            validation.validate_journey,
            _journey(),
            ("replay_run", "cleanup", "outstanding_receipt_count"),
            1,
        ),
        (
            validation.validate_journey,
            _journey(),
            ("approval_job", "approval_binding", "plan_digest"),
            "sha256:" + "0" * 64,
        ),
        (
            validation.validate_journey,
            _journey(),
            ("replay_run", "approval_id"),
            _APPROVAL_IDS[0],
        ),
        (
            validation.validate_journey,
            _journey(),
            ("replay_run", "approval_binding", "state_digest"),
            _binding()["state_digest"],
        ),
        (
            validation.validate_journey,
            _journey(),
            ("approval_job", "request_approval_id"),
            _APPROVAL_IDS[1],
        ),
        (
            validation.validate_journey,
            _journey(),
            ("comparison", "run_ids"),
            list(reversed(_RUN_IDS)),
        ),
        (
            validation.validate_structural,
            _structural(),
            ("checks", "fresh_approval_boundary"),
            False,
        ),
        (
            validation.validate_verification,
            _verification(),
            ("run_ids",),
            [_RUN_IDS[0], _RUN_IDS[0]],
        ),
        (validation.validate_summary, _summary(), ("run_count",), 1),
    ]
    for validator, report, path, value in cases:
        with pytest.raises(ValueError):
            validator(_replace(report, path, value))

    unexpected = _runtime()
    unexpected["sensitive_runtime_detail"] = "must not be accepted"
    with pytest.raises(ValueError):
        validation.validate_package_runtime(unexpected)

    wrong_runner = _journey()
    wrong_runner["packaged_runner"]["binary_digest"] = "sha256:" + "0" * 64
    with pytest.raises(ValueError, match="does not match"):
        validation.validate_runner_digest_binding(_inspection(), wrong_runner)

    wrong_wheel = _wheel_dependency_metadata()
    wrong_wheel["wheel_sha256"] = "sha256:" + "0" * 64
    with pytest.raises(ValueError, match="not bound"):
        validation.validate_wheel_metadata_binding(_inspection(), wrong_wheel)

    incompatible = _provision()
    incompatible["distributions"]["cryptography"]["version"] = "44.0.0"
    with pytest.raises(ValueError, match="does not satisfy"):
        validation.validate_dependency_provision_binding(_wheel_dependency_metadata(), incompatible)

    runtime_mismatch = _runtime()
    runtime_mismatch["dependencies"]["PyNaCl"] = "1.5.0"
    with pytest.raises(ValueError, match="does not match"):
        validation.validate_dependency_runtime_binding(
            _wheel_dependency_metadata(), _provision(), runtime_mismatch
        )

    version_mismatch = _runtime()
    version_mismatch["package_version"] = "0.1.1"
    with pytest.raises(ValueError, match="BlueFire version"):
        validation.validate_dependency_runtime_binding(
            _wheel_dependency_metadata(), _provision(), version_mismatch
        )


def test_gate_failure_messages_never_publish_absolute_paths() -> None:
    assert validation.bounded_failure_message(ValueError("wheel build exited nonzero")) == (
        "wheel build exited nonzero"
    )
    for error in (
        OSError(r"C:\Program Files\private-runtime\missing.dll"),
        RuntimeError("/opt/private/runtime failed"),
    ):
        message = validation.bounded_failure_message(error)
        assert message == "Gate 01 workflow failed without a bounded diagnostic"
        assert "private" not in message.casefold()


def test_gate_contract_registration_and_guided_workflow_are_locked(tmp_path: Path) -> None:
    gate = next(item for item in load_release_contract().gates if item.gate_id == "GATE-01")
    actual = {assertion.assertion_id: assertion.proof for assertion in gate.assertions}
    expected = {
        assertion_id: row[0] for assertion_id, row in install_gate._EXPECTED_ASSERTIONS.items()
    }

    assert actual == expected
    assert product_gates._WORKFLOWS["GATE-01"] is product_gates._gate_01_workflow
    project_document = (REPOSITORY / "pyproject.toml").read_text(encoding="utf-8")
    assert (
        install_gate._project_version(
            REPOSITORY,
            project_document,
            install_gate._project_section(project_document),
        )
        == "0.1.0"
    )
    structural = install_gate._structural_report(REPOSITORY)
    validation.validate_structural(structural)

    mismatch = install_gate.run_gate_01(
        SimpleNamespace(assertions=()), tmp_path, repository_root=REPOSITORY
    )
    assert mismatch.status == "failed"
    assert mismatch.proofs == ()
    assert mismatch.failure_reason == "locked GATE-01 assertion set mismatch"


def _write_metadata_wheel(path: Path, requirements: list[str], *, version: str = "0.1.0") -> None:
    metadata = [
        "Metadata-Version: 2.4",
        "Name: bluefire-nexus",
        f"Version: {version}",
        "Requires-Python: >=3.10",
        *(f"Requires-Dist: {requirement}" for requirement in requirements),
        "",
    ]
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(
            "bluefire_nexus-0.1.0.dist-info/METADATA",
            "\n".join(metadata).encode("utf-8"),
        )


def test_wheel_requires_dist_is_read_from_the_built_artifact(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "pyproject.toml").write_text(
        """[project]
name = "bluefire-nexus"
version = "0.1.0"
requires-python = ">=3.10"
dependencies = ["PyYAML>=6.0.1,<7", "cryptography>=45,<47", "PyNaCl>=1.5,<2"]
""",
        encoding="utf-8",
    )
    wheel = tmp_path / "bluefire_nexus-0.1.0-py3-none-win_amd64.whl"
    requirements = ["PyYAML<7,>=6.0.1", "cryptography<47,>=45", "PyNaCl<2,>=1.5"]
    _write_metadata_wheel(wheel, requirements + ['pytest>=8; extra == "dev"'])

    report = install_gate._wheel_dependency_metadata_report(source, wheel)

    validation.validate_wheel_dependency_metadata(report)
    assert report["project_version"] == "0.1.0"
    assert report["declared_runtime_dependencies"] == report["wheel_requires_dist"]

    _write_metadata_wheel(wheel, requirements[:-1])
    with pytest.raises(ValueError, match="Requires-Dist"):
        install_gate._wheel_dependency_metadata_report(source, wheel)

    _write_metadata_wheel(wheel, requirements, version="0.1.1")
    with pytest.raises(ValueError, match="project metadata"):
        install_gate._wheel_dependency_metadata_report(source, wheel)


def _copy_structural_inputs(destination: Path) -> None:
    for relative in (
        "pyproject.toml",
        "setup.py",
        "bluefire/cli.py",
        "bluefire/ui/app.js",
        "frontend/src/components/ExecuteOnboarding.tsx",
        "frontend/src/pages/Runs.tsx",
    ):
        source = REPOSITORY / relative
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)


def test_structural_proof_rejects_disconnected_or_stale_guided_ui(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    _copy_structural_inputs(repository)
    baseline = install_gate._structural_report(repository)
    validation.validate_structural(baseline)

    runs_path = repository / "frontend/src/pages/Runs.tsx"
    original_runs = runs_path.read_text(encoding="utf-8")
    disconnected = original_runs.replace(
        "import { ExecuteOnboarding,",
        "import { DisconnectedExecuteOnboarding,",
        1,
    )
    assert disconnected != original_runs
    runs_path.write_text(disconnected, encoding="utf-8")
    assert (
        install_gate._structural_report(repository)["checks"]["guided_execute_onboarding"] is False
    )

    unrendered = original_runs.replace("<ExecuteOnboarding", "<DisconnectedOnboarding", 1)
    assert unrendered != original_runs
    runs_path.write_text(unrendered, encoding="utf-8")
    assert (
        install_gate._structural_report(repository)["checks"]["guided_execute_onboarding"] is False
    )

    runs_path.write_text(original_runs, encoding="utf-8")
    app_path = repository / "bluefire/ui/app.js"
    packaged_app = app_path.read_text(encoding="utf-8")
    stale_app = packaged_app.replace("Runner ready to approved run", "Stale guided workflow", 1)
    assert stale_app != packaged_app
    app_path.write_text(stale_app, encoding="utf-8")
    report = install_gate._structural_report(repository)
    assert report["checks"]["guided_execute_onboarding"] is False
    with pytest.raises(ValueError):
        validation.validate_structural(report)


def test_timeout_terminates_the_entire_windows_process_tree(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class TimedOutProcess:
        pid = 4242
        returncode: int | None = None
        wait_count = 0

        def poll(self) -> int | None:
            return self.returncode

        def wait(self, timeout: int) -> int:
            self.wait_count += 1
            if self.wait_count == 1:
                raise subprocess.TimeoutExpired(["helper"], timeout)
            self.returncode = 1
            return self.returncode

        def kill(self) -> None:
            self.returncode = 1

    taskkill_calls: list[tuple[list[str], dict[str, Any]]] = []

    def fake_taskkill(command: list[str], **kwargs: Any) -> SimpleNamespace:
        taskkill_calls.append((command, kwargs))
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(install_gate, "_WINDOWS", True)
    monkeypatch.setattr(install_gate.subprocess, "run", fake_taskkill)
    process = TimedOutProcess()

    with pytest.raises(subprocess.TimeoutExpired):
        install_gate._wait_process(process, ["helper"], 1)  # type: ignore[arg-type]

    assert taskkill_calls[0][0] == ["taskkill", "/PID", "4242", "/T", "/F"]
    assert taskkill_calls[0][1]["timeout"] == 20
    assert process.returncode == 1


def test_release_subprocess_failures_keep_a_bounded_stage_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def cannot_spawn(*_args: Any, **_kwargs: Any) -> None:
        raise OSError("C:\\private\\machine\\path")

    monkeypatch.setattr(install_gate, "_spawn_process", cannot_spawn)
    with pytest.raises(ValueError, match=r"^wheel build could not start$"):
        install_gate._run(
            ["missing"],
            cwd=tmp_path,
            environment={},
            timeout_seconds=1,
            failure_label="wheel build",
        )

    monkeypatch.setattr(install_gate, "_spawn_process", lambda *_args, **_kwargs: object())

    def cannot_terminate(*_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError("C:\\private\\machine\\path")

    monkeypatch.setattr(install_gate, "_wait_process", cannot_terminate)
    with pytest.raises(ValueError, match=r"^installed-wheel journey process control failed$"):
        install_gate._run_json(
            ["helper"],
            cwd=tmp_path,
            environment={},
            timeout_seconds=1,
            failure_label="installed-wheel journey",
        )


def test_ephemeral_cleanup_retries_and_refuses_paths_outside_destination(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "evidence"
    target = destination / "runtime"
    target.mkdir(parents=True)
    (target / "private.db").write_bytes(b"private")
    original_rmtree = install_gate.shutil.rmtree
    attempts = 0

    def intermittently_locked(path: Path) -> None:
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise PermissionError("locked")
        original_rmtree(path)

    monkeypatch.setattr(install_gate.shutil, "rmtree", intermittently_locked)
    monkeypatch.setattr(install_gate.time, "sleep", lambda _seconds: None)

    assert install_gate._bounded_remove(destination, target) is True
    assert attempts == 3
    assert not target.exists()

    outside = tmp_path / "outside"
    outside.mkdir()
    assert install_gate._bounded_remove(destination, outside) is False
    assert outside.is_dir()


def test_successful_journey_bundles_are_removed_if_ephemeral_cleanup_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "evidence"
    destination.mkdir()
    gate = SimpleNamespace(
        assertions=tuple(
            SimpleNamespace(assertion_id=assertion_id, proof=row[0])
            for assertion_id, row in install_gate._EXPECTED_ASSERTIONS.items()
        )
    )
    monkeypatch.setattr(install_gate, "_archive_committed_source", lambda *_args: None)
    monkeypatch.setattr(
        install_gate,
        "_build_and_inspect",
        lambda *_args: destination / "wheel.whl",
    )
    monkeypatch.setattr(
        install_gate,
        "_create_fresh_environment",
        lambda *_args: destination / "python.exe",
    )
    monkeypatch.setattr(install_gate, "_run_installed_helper", lambda *_args: {})
    monkeypatch.setattr(install_gate, "_structural_report", lambda _repository: _structural())
    monkeypatch.setattr(install_gate, "_validate_reports", lambda _evidence: _RUN_IDS)
    removed: list[str] = []

    def remove_with_locked_source(_destination: Path, path: Path) -> bool:
        removed.append(path.name)
        return path.name != "s"

    monkeypatch.setattr(install_gate, "_bounded_remove", remove_with_locked_source)

    outcome = install_gate.run_gate_01(gate, destination, repository_root=REPOSITORY)

    assert outcome.status == "failed"
    assert outcome.failure_reason == "GATE-01 failed: ephemeral Gate 01 cleanup failed: s"
    assert "runs" in removed
