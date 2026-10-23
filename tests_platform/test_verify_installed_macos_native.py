from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import zipfile
from pathlib import Path

import pytest

from tools import verify_installed_macos_native as verifier


def report() -> dict:
    return {
        "schema_version": "bluefire.installed-macos-native-desktop.v1",
        "status": "passed",
        "real_service": True,
        "mocked_responses": False,
        "native_execution": True,
        "live_model_inference": False,
        "effective_access": False,
        "errors": [],
        "blocked_requests": [],
        "cleanup": {"runner_stopped": True, "job_settled": True},
        "observed": {"filesystem_records": 1, "executed_steps": 2, "generated_records": 1},
        "checks": sorted(verifier.REQUIRED_CHECKS),
        "screenshots": [
            {"name": name, "sha256": "a" * 64}
            for name in (
                "macos-native-result",
                "macos-native-evidence",
                "macos-native-cleanup",
                "macos-native-reopened",
            )
        ],
    }


def test_accepts_complete_native_generated_scope() -> None:
    assert verifier.driver_passed(report())


@pytest.mark.parametrize(
    "field,value",
    [
        ("native_execution", False),
        ("effective_access", True),
        ("live_model_inference", True),
        ("mocked_responses", True),
        ("real_service", False),
        ("status", "failed_or_incomplete"),
        ("blocked_requests", ["unexpected"]),
        ("errors", ["TypeError"]),
        ("checks", []),
        ("screenshots", []),
        ("cleanup", {"runner_stopped": False, "job_settled": True}),
        ("observed", {"filesystem_records": True, "executed_steps": 2, "generated_records": 1}),
        ("observed", {"filesystem_records": 0, "executed_steps": 2, "generated_records": 1}),
        ("observed", {"filesystem_records": 1, "executed_steps": 1, "generated_records": 1}),
    ],
)
def test_rejects_incomplete_or_false_scope(field, value) -> None:
    candidate = report()
    candidate[field] = value
    assert not verifier.driver_passed(candidate)


def test_child_environment_does_not_inherit_credentials(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "test-token-not-to-inherit")
    monkeypatch.setenv("OPENAI_API_KEY", "test-provider-not-to-inherit")
    environment = verifier.isolated_environment(
        tmp_path, Path("/usr/local/bin/node"), tmp_path / "cache"
    )
    assert "GITHUB_TOKEN" not in environment and "OPENAI_API_KEY" not in environment
    assert environment["HOME"] == str(tmp_path / "home")
    assert environment["PLAYWRIGHT_BROWSERS_PATH"] == str(tmp_path / "cache")
    assert "BLUEFIRE_RUNNER_BINARY" not in environment


def test_report_reader_refuses_duplicates_and_overlong_files(tmp_path) -> None:
    path = tmp_path / "report.json"
    path.write_text('{"status":"passed","status":"failed"}', encoding="utf-8")
    with pytest.raises(ValueError, match="Duplicate"):
        verifier.read_report(path)
    path.write_bytes(b" " * (verifier.MAX_REPORT_BYTES + 1))
    with pytest.raises(ValueError, match="bounded"):
        verifier.read_report(path)


def wheel(tmp_path: Path, *, extra: tuple[str, bytes] | None = None):
    package = tmp_path / "site" / "bluefire"
    package.mkdir(parents=True)
    (package / "__init__.py").write_bytes(b"__version__ = '3.0.0rc2'\n")
    (package / "ui").mkdir()
    (package / "ui" / "app.js").write_bytes(b"installed real application\n")
    destination = tmp_path / "bluefire_nexus-3.0.0rc2-py3-none-macosx_11_0_x86_64.whl"
    with zipfile.ZipFile(destination, "w") as archive:
        archive.writestr(
            "bluefire_nexus-3.0.0rc2.dist-info/METADATA",
            "Name: bluefire-nexus\nVersion: 3.0.0rc2\n",
        )
        archive.writestr("bluefire/__init__.py", (package / "__init__.py").read_bytes())
        archive.writestr("bluefire/ui/app.js", (package / "ui" / "app.js").read_bytes())
        if extra:
            archive.writestr(*extra)
    return destination, package


def test_exact_installed_package_bytes_include_browser_assets(tmp_path) -> None:
    archive, package = wheel(tmp_path)
    assert verifier.installed_package_matches_wheel(archive, package, "3.0.0rc2")
    (package / "ui" / "app.js").write_bytes(b"changed")
    assert not verifier.installed_package_matches_wheel(archive, package, "3.0.0rc2")


@pytest.mark.parametrize("name", ["bluefire/../escape.py", "bluefire/ui/extra.js"])
def test_package_match_rejects_escape_or_missing_installed_resource(tmp_path, name) -> None:
    archive, package = wheel(tmp_path, extra=(name, b"not installed"))
    assert not verifier.installed_package_matches_wheel(archive, package, "3.0.0rc2")


class Service:
    def __init__(self, jobs):
        self.jobs = copy.deepcopy(jobs)
        self.product_store = self
        self.cancelled = []

    def list_jobs(self):
        return list(self.jobs)

    def cancel_job(self, job_id):
        self.cancelled.append(job_id)
        self.job(job_id)["state"] = "cancelled"

    def job(self, job_id):
        return next(job for job in self.jobs if job["job_id"] == job_id)


def owned_job(state="running"):
    return {
        "job_id": "job-" + "a" * 32,
        "kind": "scenario.run",
        "state": state,
        "request": {
            "scenario": {
                "id": "scenario.installed-macos-native.00000000-0000-4000-8000-000000000000.v1"
            },
            "mode": "execute",
            "runner_profile_id": verifier.PROFILE,
        },
    }


def test_failure_cleanup_cancels_only_private_owned_job() -> None:
    service = Service([owned_job()])
    assert verifier.settle_owned_jobs(service, timeout=0)
    assert service.cancelled == [owned_job()["job_id"]]


def test_unknown_job_refuses_cleanup_before_any_cancellation() -> None:
    foreign = owned_job()
    foreign["request"]["scenario"]["id"] = "scenario.not-owned.v1"
    service = Service([owned_job(), foreign])
    assert not verifier.settle_owned_jobs(service, timeout=0)
    assert service.cancelled == []


def test_completed_job_is_not_replayed_or_cancelled() -> None:
    service = Service([owned_job("completed")])
    assert verifier.settle_owned_jobs(service, timeout=0)
    assert service.cancelled == []


def test_receipt_write_never_overwrites_existing_evidence(tmp_path) -> None:
    path = tmp_path / "receipt.json"
    verifier.write_new(path, {"status": "failed"})
    with pytest.raises(FileExistsError):
        verifier.write_new(path, {"status": "passed"})
    assert json.loads(path.read_text()) == {"status": "failed"}


def test_screenshot_bytes_are_bound_to_each_expected_record(tmp_path) -> None:
    candidate = report()
    raw = b"\x89PNG\r\n\x1a\nowned-generated-pixels"
    for item in candidate["screenshots"]:
        item["sha256"] = hashlib.sha256(raw).hexdigest()
        (tmp_path / (item["name"] + ".png")).write_bytes(raw)
    assert verifier.screenshots_verified(tmp_path, candidate)
    (tmp_path / "macos-native-result.png").write_bytes(b"modified")
    assert not verifier.screenshots_verified(tmp_path, candidate)


class WorkspaceService:
    def __init__(self, workspace, *, run_id="run-owned"):
        self.product_store = self
        self.binding = {
            "state": "completed",
            "profile_id": verifier.PROFILE,
            "run_id": run_id,
            "workspace_path": str(workspace),
        }

    def list_execution_workspaces(self):
        return [self.binding]


def test_inspects_only_bound_owned_workspace_and_requires_empty_generated_files(tmp_path) -> None:
    runtime = tmp_path / "runtime"
    workspace = runtime / "workspace"
    workspace.mkdir(parents=True)
    (workspace / ".bluefire").mkdir()
    (workspace / ".bluefire" / "receipts.json").write_text("{}")
    service = WorkspaceService(workspace)
    assert verifier.workspace_clean(service, runtime, "run-owned")
    (workspace / "fixtures").mkdir()
    (workspace / "fixtures" / "input.jsonl").write_text("owned generated fixture")
    assert not verifier.workspace_clean(service, runtime, "run-owned")


def test_workspace_binding_mismatch_or_outside_path_is_refused(tmp_path) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    foreign = tmp_path / "outside"
    foreign.mkdir()
    assert not verifier.workspace_clean(WorkspaceService(foreign), runtime, "run-owned")
    assert not verifier.workspace_clean(WorkspaceService(runtime), runtime, "another-run")


def test_workspace_traversal_error_cannot_claim_generated_cleanup(tmp_path, monkeypatch) -> None:
    runtime = tmp_path / "runtime"
    workspace = runtime / "workspace"
    workspace.mkdir(parents=True)

    def unreadable(_path, *, followlinks, onerror):
        assert followlinks is False
        onerror(PermissionError("generated subtree unreadable"))
        return iter(())

    monkeypatch.setattr(verifier.os, "walk", unreadable)
    with pytest.raises(PermissionError):
        verifier.workspace_clean(WorkspaceService(workspace), runtime, "run-owned")


def test_waiting_does_not_reap_original_child_or_adopt_another_pid() -> None:
    class Child:
        pid = 6543

        def poll(self):
            raise AssertionError("Do not reap before stopping the original process group")

    observed = []
    verifier.wait_driver_exit(Child(), lambda pid: observed.append(pid) or True, timeout=0)
    assert observed == [6543]
    with pytest.raises(subprocess.TimeoutExpired):
        verifier.wait_driver_exit(Child(), lambda pid: False, timeout=0)
