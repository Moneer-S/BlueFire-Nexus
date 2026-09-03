from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import bluefire.release_readiness_gate as gate_module
import bluefire.release_readiness_runtime as runtime_module
import bluefire.release_readiness_suites as suites_module
from bluefire.product_acceptance_artifacts import inspect_regular_file


def _cyclonedx(components: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    entries = (
        [
            {
                "bom-ref": "bluefire==1",
                "name": "bluefire",
                "type": "library",
                "version": "1",
            }
        ]
        if components is None
        else components
    )
    references = [
        str(component["bom-ref"])
        for component in entries
        if isinstance(component.get("bom-ref"), str)
    ]
    return {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "serialNumber": "urn:uuid:12345678-1234-4234-8234-123456789abc",
        "metadata": {},
        "components": entries,
        "dependencies": [{"ref": reference} for reference in references],
    }


def test_suite_rows_project_private_test_ids_without_losing_inventory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    passed = [
        "suite::safe",
        "suite::remote[https://example.test/source]",
        "suite::api[/api/v1/runs]",
        "suite::windows[C:/absolute/outside.txt]",
        "suite::unc[" + r"\\private-server\private-share\artifact.json]",
        "suite::query[https://example.test/view?path=/etc/private]",
    ]
    skipped = ["suite::posix[/tmp/private]"]
    failed = ["suite::file[file:///C:/" + "Users/private/outside.txt]"]
    row = suites_module._row(
        "python.pytest",
        ["{python}", "-m", "pytest"],
        0,
        passed_ids=passed,
        skipped_ids=skipped,
        details={"failed_test_ids": failed},
    )

    assert row["test_count"] == len(passed) + len(skipped)
    assert "suite::safe" in row["passed_test_ids"]
    assert "suite::remote[https://example.test/source]" in row["passed_test_ids"]
    assert len(row["passed_test_ids"]) == len(passed)
    assert len(row["skipped_test_ids"]) == len(skipped)
    assert len(row["details"]["failed_test_ids"]) == len(failed)
    assert row == suites_module._row(
        "python.pytest",
        ["{python}", "-m", "pytest"],
        0,
        passed_ids=passed,
        skipped_ids=skipped,
        details={"failed_test_ids": failed},
    )
    report = tmp_path / "suite.json"
    report.write_text(json.dumps(row), encoding="utf-8")
    assert not inspect_regular_file(
        tmp_path, report.name, label="suite report"
    ).contains_private_path
    monkeypatch.setattr(
        suites_module.hashlib,
        "sha256",
        lambda _value: SimpleNamespace(hexdigest=lambda: "0" * 64),
    )
    with pytest.raises(ValueError, match="projection collided"):
        suites_module._public_test_ids(["suite::same[/tmp/a]", "suite::same[/tmp/b]"])


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
    sbom_sources: list[Path] = []

    def archive(_repository: Path, destination: Path, _environment: Any) -> bool:
        source = destination / "source"
        source.mkdir(parents=True)
        (source / ".secrets.baseline").write_bytes(baseline.read_bytes())
        (source / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
        return True

    monkeypatch.setattr(suites_module.shutil, "which", lambda *_args, **_kwargs: "gitleaks")
    monkeypatch.setattr(suites_module, "_archive_source", archive)
    monkeypatch.setattr(
        runtime_module,
        "initialize_scan_repository",
        lambda root, _environment: scan_roots.append(root) is None,
    )
    monkeypatch.setattr(runtime_module, "tracked_paths", lambda _repository: ["module.py"])

    def fake_run(command: Any, **_kwargs: Any) -> tuple[int, bytes, bytes]:
        arguments = list(command)
        if "detect_secrets.pre_commit_hook" in arguments:
            detect_commands.append(arguments)
            baseline_path = Path(_kwargs["cwd"]) / arguments[arguments.index("--baseline") + 1]
            isolated_baselines.append(baseline_path)
            baseline_path.write_text("refreshed-baseline\n", encoding="utf-8")
        if "cyclonedx_py" in arguments:
            output = Path(arguments[arguments.index("--output-file") + 1])
            sbom_sources.append(output)
            private_url = " \tFiLe:///C:/" + "Users/private/bluefire"
            output.write_text(
                json.dumps(
                    _cyclonedx(
                        [
                            {
                                "bom-ref": "bluefire-nexus==1",
                                "name": "bluefire-nexus",
                                "type": "library",
                                "version": "1",
                                "externalReferences": [
                                    {"type": "distribution", "url": private_url}
                                ],
                            }
                        ]
                    )
                ),
                encoding="utf-8",
            )
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
    persisted_sbom = json.loads((evidence / "gate12-python-sbom.json").read_text("utf-8"))
    assert "externalReferences" not in persisted_sbom["components"][0]
    assert sbom_sources == [temporary / "python-sbom.raw.json"]
    assert not sbom_sources[0].exists()
    unsafe_source = temporary / "unsafe-sbom.json"
    unsafe_destination = evidence / "unsafe-sbom.json"
    unsafe_source.write_text(
        json.dumps(
            _cyclonedx(
                [
                    {
                        "bom-ref": "unsafe==1",
                        "name": "unsafe",
                        "type": "library",
                        "version": "1",
                        "path": "C:/" + "Users/private/package",
                    }
                ]
            )
        ),
        encoding="utf-8",
    )
    assert not runtime_module.sanitize_sbom_file(unsafe_source, unsafe_destination)
    assert not unsafe_destination.exists()


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("$schema", "http://cyclonedx.org/schema/bom-1.5.schema.json"),
        ("bomFormat", "not-cyclonedx"),
        ("specVersion", "1.5"),
        ("version", True),
        ("serialNumber", "not-a-uuid"),
        ("metadata", []),
        ("components", []),
        ("dependencies", {}),
    ],
)
def test_sbom_sanitizer_rejects_invalid_cyclonedx_shape(
    tmp_path: Path,
    field: str,
    replacement: Any,
) -> None:
    source = tmp_path / "source.json"
    destination = tmp_path / "destination.json"
    value = _cyclonedx()
    value[field] = replacement
    source.write_text(json.dumps(value), encoding="utf-8")

    assert not runtime_module.sanitize_sbom_file(source, destination)
    assert not destination.exists()


def test_sbom_sanitizer_rejects_duplicate_components_collisions_and_oversize(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source.json"
    duplicate = {
        "bom-ref": "duplicate",
        "name": "package",
        "type": "library",
        "version": "1",
    }
    destination = tmp_path / "destination.json"
    for component_type in ("unknown", []):
        invalid_type = _cyclonedx()
        invalid_type["components"][0]["type"] = component_type
        source.write_text(json.dumps(invalid_type), encoding="utf-8")
        assert not runtime_module.sanitize_sbom_file(source, destination)

    source.write_text(json.dumps(_cyclonedx([duplicate, dict(duplicate)])), encoding="utf-8")
    assert not runtime_module.sanitize_sbom_file(source, destination)

    source.write_text(json.dumps(_cyclonedx()), encoding="utf-8")
    destination.write_text("sentinel\n", encoding="utf-8")
    assert not runtime_module.sanitize_sbom_file(source, destination)
    assert destination.read_text(encoding="utf-8") == "sentinel\n"

    destination.unlink()
    monkeypatch.setattr(runtime_module, "_MAX_SBOM_BYTES", 64)
    assert not runtime_module.sanitize_sbom_file(source, destination)
    assert not destination.exists()


def test_sbom_sanitizer_refuses_a_racing_or_linked_destination(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source.json"
    source.write_text(json.dumps(_cyclonedx()), encoding="utf-8")
    destination = tmp_path / "destination.json"
    real_link = runtime_module.os.link

    def racing_link(source_path: Any, destination_path: Any, **kwargs: Any) -> None:
        if Path(destination_path) == destination:
            destination.write_text("racer\n", encoding="utf-8")
        real_link(source_path, destination_path, **kwargs)

    monkeypatch.setattr(runtime_module.os, "link", racing_link)
    assert not runtime_module.sanitize_sbom_file(source, destination)
    assert destination.read_text(encoding="utf-8") == "racer\n"

    monkeypatch.setattr(runtime_module.os, "link", real_link)
    destination.unlink()
    outside = tmp_path / "outside.json"
    try:
        destination.symlink_to(outside)
    except (NotImplementedError, OSError):
        pytest.skip("the test host does not permit disposable symlinks")
    assert not runtime_module.sanitize_sbom_file(source, destination)
    assert destination.is_symlink()
    assert not outside.exists()


def test_sbom_sanitizer_contains_deep_json_recursion(tmp_path: Path) -> None:
    source = tmp_path / "source.json"
    destination = tmp_path / "destination.json"
    nested_json = "[" * 2_000 + "0" + "]" * 2_000
    source.write_text(
        json.dumps(_cyclonedx()).replace(
            '"metadata": {}', f'"metadata": {{"nested": {nested_json}}}'
        ),
        encoding="utf-8",
    )
    assert not runtime_module.sanitize_sbom_file(source, destination)
    assert not destination.exists()

    value = _cyclonedx()
    cursor = value["metadata"]
    for _index in range(2_000):
        child: dict[str, Any] = {}
        cursor["nested"] = child
        cursor = child
    assert not runtime_module._publish_bounded_json(destination, value)
    assert not destination.exists()


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

    monkeypatch.setattr(runtime_module, "temp_parent", lambda: runtime_root)
    monkeypatch.setenv("BLUEFIRE_ACCEPTANCE_ID", "must-not-reach-nested-suites")
    monkeypatch.setenv("BLUEFIRE_ACCEPTANCE_GATE_ID", "GATE-12")
    monkeypatch.setenv("bluefire_acceptance_shadow", "case-insensitive-removal")
    monkeypatch.setattr(runtime_module, "tracked_snapshot", lambda _root: {"file": "hash"})
    observed_environments: list[dict[str, str]] = []

    def rows(_repository: Path, temporary: Path, environment: Any) -> list[dict[str, Any]]:
        observed.append(temporary)
        observed_environments.append(dict(environment))
        return []

    def rust_rows(
        _repository: Path,
        temporary: Path,
        environment: Any,
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        observed.append(temporary)
        observed_environments.append(dict(environment))
        return [], {}

    def security_rows(
        _repository: Path,
        _evidence: Path,
        temporary: Path,
        environment: Any,
    ) -> list[dict[str, Any]]:
        observed.append(temporary)
        observed_environments.append(dict(environment))
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
    assert {path.name for path in observed} == {"p", "r", "f", "s"}
    assert len(scratch_roots) == 1
    scratch = scratch_roots.pop()
    assert scratch.parent == runtime_root
    assert scratch.name.startswith(".b")
    assert len((Path(scratch.name) / "t").as_posix()) <= 16
    assert all(
        not any(name.casefold().startswith("bluefire_acceptance_") for name in environment)
        for environment in observed_environments
    )
    assert not scratch.exists()
    assert list(evidence.iterdir()) == []


def test_python_suite_uses_a_short_sibling_basetemp(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    temporary = tmp_path / ".b12345678" / "p"
    commands: list[list[str]] = []
    monkeypatch.setattr(suites_module, "_archive_source", lambda *_args: False)

    def run(command: Any, **_kwargs: Any) -> tuple[int, bytes, bytes]:
        arguments = [str(item) for item in command]
        commands.append(arguments)
        junit = next(
            (
                item.removeprefix("--junitxml=")
                for item in arguments
                if item.startswith("--junitxml=")
            ),
            None,
        )
        if junit is not None:
            Path(junit).write_text("<testsuite />", encoding="utf-8")
        return 0, b"", b""

    monkeypatch.setattr(suites_module, "_run", run)
    suites_module._python_suites(repository, temporary, {})

    pytest_command = next(command for command in commands if "pytest" in command)
    basetemp = next(
        item.removeprefix("--basetemp=")
        for item in pytest_command
        if item.startswith("--basetemp=")
    )
    assert Path(basetemp) == temporary.parent / "t"
    assert len((Path(temporary.parent.name) / "t").as_posix()) <= 16


def test_tracked_release_tree_has_no_private_identity_literals(tmp_path: Path) -> None:
    repository = Path(__file__).resolve().parents[1]
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "gate12-python-sbom.json").write_text(
        json.dumps({"components": [{"name": "safe"}]}), encoding="utf-8"
    )
    suites = {
        "suites": [
            {"suite_id": f"security.{name}", "passed": True}
            for name in ("gitleaks", "detect-secrets", "bandit", "pip-audit")
        ]
    }

    report = gate_module._opsec_report(repository, evidence, suites)

    assert report["private_identity_hits"] == []
    assert report["passed"] is True


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


def test_tracked_git_timeout_becomes_a_closed_suite_input(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(runtime_module, "trusted_git_executable", lambda: tmp_path / "git")
    monkeypatch.setattr(runtime_module, "trusted_git_environment", lambda: {})

    def timeout(*_args: Any, **_kwargs: Any) -> Any:
        raise runtime_module.subprocess.TimeoutExpired(["git", "ls-files"], 30)

    monkeypatch.setattr(runtime_module.subprocess, "run", timeout)

    assert runtime_module.tracked_paths(tmp_path) == []
    assert runtime_module.tracked_snapshot(tmp_path) == {}


def test_tracked_snapshot_rejects_a_linked_file_before_reading(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"outside")
    tracked = repository / "tracked.txt"
    runtime_module.os.link(outside, tracked)
    monkeypatch.setattr(runtime_module, "_tracked_payload", lambda _root: b"tracked.txt\0")

    assert runtime_module.tracked_snapshot(repository) == {}

    tracked.unlink()
    tracked.write_bytes(b"inside")
    assert runtime_module.tracked_snapshot(repository) == {
        "tracked.txt": hashlib.sha256(b"inside").hexdigest()
    }
