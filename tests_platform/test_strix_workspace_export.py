from __future__ import annotations

import hashlib
import json
import os
import signal
import stat
import sys
import time
from pathlib import Path

import pytest

from bluefire.strix_workspace_export import (
    StrixWorkspaceExportError,
    StrixWorkspaceExportUnknown,
    export_strix_workspace_run,
    inspect_guest_strix_run_presence,
    inspect_retained_strix_export_state,
    reopen_strix_workspace_export,
)
from bluefire.util import content_hash

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="pinned Linux directory FDs")

ATTEMPT = "engine-attempt-" + "a" * 32
TARGET = "http://bluefire-lab:8080/"
OBJECTIVE = "Assess only the owned lab."
INSTRUCTION = "sha256:" + hashlib.sha256((OBJECTIVE + "\n").encode()).hexdigest()
TERMINAL = "sha256:" + "b" * 64


def _fixture(tmp_path: Path) -> tuple[Path, Path, Path, dict[str, object]]:
    source = tmp_path / "worker-workspace"
    source.mkdir(mode=0o700)
    run = source / "strix_runs" / "upstream-run-1"
    run.mkdir(parents=True)
    (run / "run.json").write_text(
        json.dumps(
            {
                "run_id": "upstream-run-1",
                "run_name": "upstream-run-1",
                "status": "completed",
                "non_interactive": True,
                "scan_mode": "quick",
                "scope_mode": "full",
                "targets_info": [
                    {
                        "type": "web_application",
                        "original": TARGET,
                        "details": {"target_url": TARGET},
                    }
                ],
                "instruction": OBJECTIVE,
            }
        ),
        encoding="utf-8",
    )
    (run / "coverage.json").write_text(
        json.dumps(
            {
                "run_id": "upstream-run-1",
                "run_name": "upstream-run-1",
                "completeness": {
                    "complete": True,
                    "scan_status": "completed",
                    "exit_reason": "completed",
                    "caveats": [],
                },
            }
        ),
        encoding="utf-8",
    )
    host = tmp_path / ATTEMPT
    host.mkdir(mode=0o700)
    source_stat = source.stat()
    workspace = {
        "device": source_stat.st_dev,
        "inode": source_stat.st_ino,
        "mode": stat.S_IMODE(source_stat.st_mode),
        "uid": source_stat.st_uid,
        "gid": source_stat.st_gid,
    }
    observed: dict[str, object] = {
        "schema_version": "bluefire.strix-worker-runtime-observation.v1",
        "attempt_id": ATTEMPT,
        "workspace": workspace,
        "workspace_ref": content_hash(workspace),
    }
    observed["observation_ref"] = content_hash(observed)
    return source, run, host, observed


def _export(source: Path, host: Path, observed: dict[str, object], **kwargs: object):
    descriptor = os.open(source, os.O_RDONLY | os.O_DIRECTORY)
    try:
        return export_strix_workspace_run(
            workspace_fd=descriptor,
            native_observed=observed,
            worker_terminal_ref=TERMINAL,
            attempt_id=ATTEMPT,
            host_attempt_directory=host,
            expected_target=TARGET,
            expected_instruction_sha256=INSTRUCTION,
            process_exit_code=0,
            cessation_verified=True,
            **kwargs,
        )
    finally:
        os.close(descriptor)


def test_export_retains_exact_reviewed_files_and_run_snapshot(tmp_path: Path) -> None:
    source, run, host, observed = _fixture(tmp_path)
    (run / "vulnerabilities.json").write_text("[]", encoding="utf-8")
    (run / "unreviewed.private").write_text("not selected", encoding="utf-8")

    exported = _export(source, host, observed)

    assert exported.attempt_id == ATTEMPT
    assert exported.source_observation_ref == observed["observation_ref"]
    assert exported.worker_terminal_ref == TERMINAL
    assert exported.snapshot.attempt_state == "completed"
    assert exported.snapshot.security_outcome == "not_independently_established"
    assert exported.selected_names == (
        "strix_runs/upstream-run-1/coverage.json",
        "strix_runs/upstream-run-1/run.json",
        "strix_runs/upstream-run-1/vulnerabilities.json",
    )
    assert tuple(row.to_manifest_row() for row in exported.reviewed_files) == tuple(
        json.loads((exported.run_directory / "bluefire-export.json").read_text())["files"]
    )
    assert not (exported.run_directory / "unreviewed.private").exists()
    manifest = json.loads((exported.run_directory / "bluefire-export.json").read_text())
    assert manifest["manifest_ref"] == exported.manifest_ref
    assert (
        content_hash({k: v for k, v in manifest.items() if k != "manifest_ref"})
        == exported.manifest_ref
    )
    assert not (host / ".pending-strix-export").exists()
    assert (
        inspect_retained_strix_export_state(attempt_id=ATTEMPT, host_attempt_directory=host)
        == "published"
    )

    reopened = reopen_strix_workspace_export(
        attempt_id=ATTEMPT,
        host_attempt_directory=host,
        native_observed=observed,
        worker_terminal_ref=TERMINAL,
        expected_target=TARGET,
        expected_instruction_sha256=INSTRUCTION,
        process_exit_code=0,
        cessation_verified=True,
    )
    assert reopened.manifest_ref == exported.manifest_ref
    assert reopened.selected_names == exported.selected_names
    assert reopened.reviewed_files == exported.reviewed_files
    assert reopened.source_run_dir == host
    with pytest.raises(StrixWorkspaceExportError):
        reopen_strix_workspace_export(
            attempt_id=ATTEMPT,
            host_attempt_directory=host,
            native_observed=observed,
            worker_terminal_ref=TERMINAL,
            expected_target=TARGET,
            expected_instruction_sha256=INSTRUCTION,
            process_exit_code=0,
            deadline_monotonic=time.monotonic() - 1,
        )


def test_guest_inventory_distinguishes_empty_from_partial_run(tmp_path: Path) -> None:
    source, run, host, _observed = _fixture(tmp_path)
    descriptor = os.open(source, os.O_RDONLY | os.O_DIRECTORY)
    try:
        assert inspect_guest_strix_run_presence(descriptor) == "run_record_present"
        (run / "run.json").unlink()
        with pytest.raises(StrixWorkspaceExportUnknown):
            inspect_guest_strix_run_presence(descriptor)
        (run / "coverage.json").unlink()
        run.rmdir()
        assert inspect_guest_strix_run_presence(descriptor) == "no_run_record"
    finally:
        os.close(descriptor)
    assert (
        inspect_retained_strix_export_state(attempt_id=ATTEMPT, host_attempt_directory=host)
        == "absent"
    )


def test_reopen_rejects_changed_optional_artifact(tmp_path: Path) -> None:
    source, run, host, observed = _fixture(tmp_path)
    (run / "vulnerabilities.json").write_text("[]", encoding="utf-8")
    _export(source, host, observed)
    retained = host / "strix_runs" / "upstream-run-1" / "vulnerabilities.json"
    retained.write_text("{}", encoding="utf-8")
    with pytest.raises(StrixWorkspaceExportUnknown):
        reopen_strix_workspace_export(
            attempt_id=ATTEMPT,
            host_attempt_directory=host,
            native_observed=observed,
            worker_terminal_ref=TERMINAL,
            expected_target=TARGET,
            expected_instruction_sha256=INSTRUCTION,
            process_exit_code=0,
            cessation_verified=True,
        )


def test_export_refuses_symlink_or_hardlink_source(tmp_path: Path) -> None:
    source, run, host, observed = _fixture(tmp_path)
    original = run / "run.json"
    original.rename(run / "elsewhere.json")
    original.symlink_to(run / "elsewhere.json")
    with pytest.raises(StrixWorkspaceExportError):
        _export(source, host, observed)
    assert not (host / "strix_runs").exists()

    original.unlink()
    os.link(run / "elsewhere.json", original)
    with pytest.raises(StrixWorkspaceExportError):
        _export(source, host, observed)
    assert not (host / "strix_runs").exists()


def test_export_refuses_fifo_without_waiting_for_a_writer(tmp_path: Path) -> None:
    source, run, host, observed = _fixture(tmp_path)
    (run / "run.json").unlink()
    os.mkfifo(run / "run.json")

    def timeout(_signum: int, _frame: object) -> None:
        raise TimeoutError("FIFO open blocked")

    previous = signal.signal(signal.SIGALRM, timeout)
    signal.alarm(5)
    try:
        with pytest.raises(StrixWorkspaceExportError):
            _export(source, host, observed)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)
    assert not (host / "strix_runs").exists()


def test_export_rejects_wrong_native_workspace_identity(tmp_path: Path) -> None:
    source, _run, host, observed = _fixture(tmp_path)
    observed["workspace_ref"] = TERMINAL
    observed["observation_ref"] = content_hash(
        {k: v for k, v in observed.items() if k != "observation_ref"}
    )
    with pytest.raises(StrixWorkspaceExportError):
        _export(source, host, observed)
    assert not (host / "strix_runs").exists()


def test_export_enforces_budget_before_publication(tmp_path: Path) -> None:
    source, _run, host, observed = _fixture(tmp_path)
    with pytest.raises(StrixWorkspaceExportError):
        _export(source, host, observed, max_files=1)
    assert not (host / "strix_runs").exists()

    with pytest.raises(StrixWorkspaceExportError):
        _export(source, host, observed, deadline_monotonic=time.monotonic() - 1)
    assert not (host / "strix_runs").exists()


def test_existing_stage_and_bad_run_remain_unknown(tmp_path: Path) -> None:
    source, run, host, observed = _fixture(tmp_path)
    (host / ".pending-strix-export").mkdir(mode=0o700)
    assert (
        inspect_retained_strix_export_state(attempt_id=ATTEMPT, host_attempt_directory=host)
        == "pending"
    )
    with pytest.raises(StrixWorkspaceExportUnknown):
        _export(source, host, observed)
    assert not (host / "strix_runs").exists()

    (host / ".pending-strix-export").rmdir()
    record = json.loads((run / "run.json").read_text())
    record["targets_info"][0]["original"] = "http://another-target/"
    (run / "run.json").write_text(json.dumps(record), encoding="utf-8")
    with pytest.raises(StrixWorkspaceExportUnknown):
        _export(source, host, observed)
    assert (host / "strix_runs" / "upstream-run-1" / "run.json").is_file()
