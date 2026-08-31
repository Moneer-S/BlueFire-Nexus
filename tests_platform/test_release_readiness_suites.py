from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import bluefire.release_readiness_runtime as runtime_module
import bluefire.release_readiness_suites as suites_module


def test_detect_secrets_scans_a_committed_archive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    baseline = repository / ".secrets.baseline"
    baseline.write_text("original-baseline\n", encoding="utf-8")
    (repository / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    temporary = tmp_path / "temporary" / "security"
    isolated_baselines: list[Path] = []
    detect_commands: list[list[str]] = []
    scan_roots: list[Path] = []

    def archive(_repository: Path, destination: Path, _environment: Any) -> bool:
        source = destination / "source"
        source.mkdir(parents=True)
        (source / ".secrets.baseline").write_bytes(baseline.read_bytes())
        (source / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
        return True

    monkeypatch.setattr(suites_module.shutil, "which", lambda *_args, **_kwargs: "gitleaks")
    monkeypatch.setattr(suites_module, "_archive_source", archive)
    monkeypatch.setattr(
        suites_module,
        "initialize_scan_repository",
        lambda root, _environment: scan_roots.append(root) is None,
    )
    monkeypatch.setattr(
        suites_module.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0,
            stdout=b".secrets.baseline\0module.py\0",
        ),
    )

    def fake_run(command: Any, **_kwargs: Any) -> tuple[int, bytes, bytes]:
        arguments = list(command)
        if "detect_secrets.pre_commit_hook" in arguments:
            detect_commands.append(arguments)
            baseline_path = Path(_kwargs["cwd"]) / arguments[arguments.index("--baseline") + 1]
            isolated_baselines.append(baseline_path)
            baseline_path.write_text("refreshed-baseline\n", encoding="utf-8")
        if "cyclonedx_py" in arguments:
            output = Path(arguments[arguments.index("--output-file") + 1])
            output.write_text(json.dumps({"components": []}), encoding="utf-8")
        return 0, b"", b""

    monkeypatch.setattr(suites_module, "_run", fake_run)

    rows = suites_module._security_suites(repository, evidence, temporary, {})

    detect_secrets = next(row for row in rows if row["suite_id"] == "security.detect-secrets")
    assert baseline.read_text(encoding="utf-8") == "original-baseline\n"
    assert isolated_baselines == [temporary / "archive" / "source" / ".secrets.baseline"]
    assert scan_roots == [temporary / "archive" / "source"]
    assert detect_secrets["passed"] is True
    assert detect_secrets["command"][4:6] == [".secrets.baseline", "--no-verify"]
    assert detect_commands[0].count(".secrets.baseline") == 1
    assert detect_secrets["details"] == {"committed_archive": True, "tracked_files": 1}


def test_full_release_suites_use_the_process_token_temp_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    evidence = tmp_path / "evidence"
    runtime_root = tmp_path / "runtime"
    for directory in (repository, evidence, runtime_root):
        directory.mkdir()
    observed: list[Path] = []

    monkeypatch.setattr(suites_module, "temp_parent", lambda: runtime_root)
    monkeypatch.setattr(suites_module, "_tracked_snapshot", lambda _root: {"file": "hash"})

    def rows(_repository: Path, temporary: Path, *_args: Any) -> list[dict[str, Any]]:
        observed.append(temporary)
        return []

    def rust_rows(
        _repository: Path,
        temporary: Path,
        *_args: Any,
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        observed.append(temporary)
        return [], {}

    def security_rows(
        _repository: Path,
        _evidence: Path,
        temporary: Path,
        *_args: Any,
    ) -> list[dict[str, Any]]:
        observed.append(temporary)
        return []

    monkeypatch.setattr(suites_module, "_python_suites", rows)
    monkeypatch.setattr(suites_module, "_rust_suites", rust_rows)
    monkeypatch.setattr(suites_module, "_frontend_suites", rows)
    monkeypatch.setattr(suites_module, "_security_suites", security_rows)
    monkeypatch.setattr(suites_module, "_production_rows", lambda *_args: [])

    report = suites_module.run_full_release_suites(
        repository,
        evidence,
        upstream={},
        journey={},
    )

    scratch_roots = {path.parent for path in observed}
    assert report["passed"] is True
    assert {path.name for path in observed} == {"python", "rust", "frontend", "security"}
    assert len(scratch_roots) == 1
    scratch = scratch_roots.pop()
    assert scratch.parent == runtime_root
    assert scratch.name.startswith(".gate12-suites-")
    assert not scratch.exists()
    assert list(evidence.iterdir()) == []


def test_scan_repository_uses_fixed_git_and_a_config_free_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "archive"
    root.mkdir()
    executable = tmp_path / "fixed-git"
    observed: list[tuple[list[str], dict[str, Any]]] = []

    monkeypatch.setattr(runtime_module, "trusted_git_executable", lambda: executable)
    monkeypatch.setattr(
        runtime_module,
        "trusted_git_environment",
        lambda _environment: {"GIT_CONFIG_GLOBAL": "disabled"},
    )

    def run(command: Any, **kwargs: Any) -> SimpleNamespace:
        observed.append((list(command), kwargs))
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(runtime_module.subprocess, "run", run)

    assert runtime_module.initialize_scan_repository(root, {"UNTRUSTED": "value"}) is True
    assert [command[1:] for command, _kwargs in observed] == [
        ["init", "--quiet"],
        ["add", "--", ".secrets.baseline"],
    ]
    assert all(command[0] == str(executable) for command, _kwargs in observed)
    assert all(kwargs["cwd"] == root for _command, kwargs in observed)
    assert all(kwargs["env"] == {"GIT_CONFIG_GLOBAL": "disabled"} for _command, kwargs in observed)
