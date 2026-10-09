"""Conditional TOML dependency evidence; authored metadata and mocked installation only."""

from __future__ import annotations

import json
import os
import sys
from collections import namedtuple
from copy import deepcopy
from importlib.metadata import PackageNotFoundError
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from bluefire import install_gate
from bluefire import install_gate_package_metadata as metadata
from bluefire import install_gate_validation as validation
from tests_platform.test_install_gate import (
    _provision as legacy_provision,
)
from tests_platform.test_install_gate import (
    _runtime as legacy_runtime,
)
from tests_platform.test_install_gate import (
    _wheel_dependency_metadata as legacy_metadata,
)
from tests_platform.test_install_gate import (
    _write_metadata_wheel,
)
from tools import install_gate_journey_support as support
from tools import run_install_gate_journey as journey

_TOMLI_REQUIREMENT = "tomli==2.4.1; python_version < '3.11'"
_REQUIREMENTS = [
    "PyYAML>=6.0.1,<7",
    "cryptography>=50,<51",
    "PyNaCl>=1.5,<2",
    _TOMLI_REQUIREMENT,
]
_TOMLI_ROW = {"name": "tomli", "specifier": "==2.4.1", "marker": "python_version < '3.11'"}


def _reports(minor: int) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    wheel, provision, runtime = legacy_metadata(), legacy_provision(), legacy_runtime()
    for report in (wheel, provision, runtime):
        report["schema_version"] = report["schema_version"].removesuffix(".v1") + ".v2"
    for field in ("declared_runtime_dependencies", "wheel_requires_dist"):
        wheel[field].append(dict(_TOMLI_ROW))
    provision["python_version"] = [3, minor]
    runtime["python_version"] = [3, minor]
    if minor == 10:
        provision["distributions"]["tomli"] = {
            "version": "2.4.1",
            "file_count": 1,
            "content_digest": wheel["wheel_sha256"],
        }
        runtime["dependencies"]["tomli"] = "2.4.1"
    return wheel, provision, runtime


def _metadata_artifacts(tmp_path: Path, declared: list[str], packaged: list[str]) -> dict[str, Any]:
    source = tmp_path / "source"
    source.mkdir()
    (source / "pyproject.toml").write_text(
        '[project]\nname = "bluefire-nexus"\nversion = "3.0.0"\nrequires-python = ">=3.10"\n'
        + "dependencies = "
        + json.dumps(declared)
        + "\n",
        encoding="utf-8",
    )
    wheel = tmp_path / "bluefire_nexus-3.0.0-py3-none-any.whl"
    _write_metadata_wheel(wheel, packaged)
    report = dict(metadata._wheel_dependency_metadata_report(source, wheel))
    validation.validate_wheel_dependency_metadata(report)
    return report


@pytest.mark.parametrize("marker", ["python_version < '3.11'", ' python_version<"3.11" '])
def test_conditional_metadata_is_read_from_artifact_with_exact_marker(
    tmp_path: Path, marker: str
) -> None:
    report = _metadata_artifacts(
        tmp_path, _REQUIREMENTS, _REQUIREMENTS[:-1] + ["tomli==2.4.1; " + marker]
    )

    assert report["schema_version"] == "bluefire.gate01-wheel-dependency-metadata.v2"
    assert report["declared_runtime_dependencies"] == report["wheel_requires_dist"]
    assert report["wheel_requires_dist"][:-1] == legacy_metadata()["wheel_requires_dist"]
    assert report["wheel_requires_dist"][-1] == _TOMLI_ROW


@pytest.mark.parametrize(
    "requirement",
    [
        "tomli==2.4.1",
        "tomli==2.4.1;",
        "tomli==2.4.1; python_version <= '3.11'",
        "tomli==2.4.1; python_version < '3.12'",
        "tomli==2.4.1; python_full_version < '3.11'",
        "tomli==2.4.1; python_version < '3.11' or os_name == 'nt'",
        "PyYAML>=6.0.1,<7; python_version < '3.11'",
    ],
)
def test_unreviewed_or_missing_dependency_marker_is_refused(requirement: str) -> None:
    with pytest.raises(ValueError, match="marker"):
        metadata._requirement_row(requirement)


@pytest.mark.parametrize(
    "change", ["omit", "duplicate", "extra", "version", "original", "missing-original"]
)
def test_declared_and_packaged_dependency_drift_cannot_make_a_verified_report(
    tmp_path: Path, change: str
) -> None:
    requirements = list(_REQUIREMENTS)
    if change == "omit":
        requirements.pop()
    elif change == "duplicate":
        requirements.append(_TOMLI_REQUIREMENT)
    elif change == "extra":
        requirements.append("unexpected==1")
    elif change == "version":
        requirements[-1] = _TOMLI_REQUIREMENT.replace("2.4.1", "2.4.0")
    elif change == "missing-original":
        requirements.pop(0)
    else:
        requirements[1] = "cryptography>=49,<51"

    with pytest.raises(ValueError):
        _metadata_artifacts(tmp_path, requirements, requirements)


@pytest.mark.parametrize("change", ["omit", "duplicate", "extra", "marker"])
def test_packaged_dependency_drift_is_not_hidden_by_correct_source(
    tmp_path: Path, change: str
) -> None:
    requirements = list(_REQUIREMENTS)
    if change == "omit":
        requirements.pop()
    elif change == "duplicate":
        requirements.append(_TOMLI_REQUIREMENT)
    elif change == "extra":
        requirements.append("unexpected==1")
    else:
        requirements[-1] += " and extra == 'dev'"

    with pytest.raises(ValueError):
        _metadata_artifacts(tmp_path, _REQUIREMENTS, requirements)


def test_historical_v1_dependency_reports_remain_readable() -> None:
    validation.validate_dependency_runtime_binding(
        legacy_metadata(), legacy_provision(), legacy_runtime()
    )


@pytest.mark.parametrize("minor", [10, 11, 12])
def test_v2_dependency_proofs_bind_conditional_tomli_to_python(minor: int) -> None:
    wheel, provision, runtime = _reports(minor)

    validation.validate_dependency_runtime_binding(wheel, provision, runtime)

    assert ("tomli" in provision["distributions"]) == (minor == 10)
    assert ("tomli" in runtime["dependencies"]) == (minor == 10)
    assert runtime["python_version"] == provision["python_version"] == [3, minor]


@pytest.mark.parametrize("report", ["provision", "runtime"])
@pytest.mark.parametrize("change", ["missing", "extra", "tomli-version", "original-version"])
def test_dependency_binding_refuses_missing_extra_or_mismatched_versions(
    report: str, change: str
) -> None:
    wheel, provision, runtime = _reports(10)
    values = provision["distributions"] if report == "provision" else runtime["dependencies"]
    if change == "missing":
        values.pop("tomli")
    elif change == "extra":
        values["unexpected"] = deepcopy(values["tomli"])
    elif report == "provision":
        name = "tomli" if change == "tomli-version" else "cryptography"
        values[name]["version"] = "2.4.0" if name == "tomli" else "49.0.0"
    else:
        name = "tomli" if change == "tomli-version" else "cryptography"
        values[name] = "2.4.0" if name == "tomli" else "50.0.1"

    with pytest.raises(ValueError):
        validation.validate_dependency_runtime_binding(wheel, provision, runtime)


def test_tomli_is_refused_in_the_stdlib_only_proof() -> None:
    wheel, provision, runtime = _reports(11)
    provision["distributions"]["tomli"] = _reports(10)[1]["distributions"]["tomli"]
    runtime["dependencies"]["tomli"] = "2.4.1"

    with pytest.raises(ValueError):
        validation.validate_dependency_provision_binding(wheel, provision)
    with pytest.raises(ValueError):
        validation.validate_package_runtime(runtime)


@pytest.mark.parametrize("version", [[3, 9], [4, 0], [3, True], [3], "3.10", [3, 10, 0]])
def test_v2_proof_requires_a_supported_exact_interpreter_pair(version: Any) -> None:
    wheel, provision, runtime = _reports(10)
    provision["python_version"] = version
    runtime["python_version"] = version

    with pytest.raises(ValueError, match="Python version"):
        validation.validate_dependency_runtime_binding(wheel, provision, runtime)


@pytest.mark.parametrize("family", ["metadata", "provision", "runtime", "interpreter"])
def test_mixed_interpreter_or_schema_proofs_are_refused(family: str) -> None:
    wheel, provision, runtime = _reports(11)
    if family == "metadata":
        wheel = legacy_metadata()
    elif family == "provision":
        provision = legacy_provision()
    elif family == "runtime":
        runtime = legacy_runtime()
    else:
        runtime["python_version"] = [3, 12]

    with pytest.raises(ValueError, match="revisions|Python versions"):
        validation.validate_dependency_runtime_binding(wheel, provision, runtime)


@pytest.mark.parametrize(
    ("minor", "tomli_state"),
    [(10, "correct"), (10, "wrong-version"), (10, "missing"), (11, "correct")],
)
def test_fresh_environment_producer_provisions_before_installing_without_dependencies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, minor: int, tomli_state: str
) -> None:
    wheel, expected, _ = _reports(minor)
    environment_root = tmp_path / "environment"
    python = install_gate._fresh_python(environment_root)
    python.parent.mkdir(parents=True)
    python.touch()
    site_packages = environment_root / (
        "Lib/site-packages" if os.name == "nt" else f"lib/python3.{minor}/site-packages"
    )
    site_packages.mkdir(parents=True)
    version_type = namedtuple("Version", "major minor")
    monkeypatch.setattr(
        install_gate,
        "sys",
        SimpleNamespace(executable="authored-parent-python", version_info=version_type(3, minor)),
    )
    commands: list[list[str]] = []
    copied: list[str] = []
    reports: list[dict[str, Any]] = []

    def run(command: list[str], **kwargs: Any) -> None:
        assert kwargs["timeout_seconds"] == 180
        commands.append(command)

    def provision(name: str, destination: Path) -> dict[str, Any]:
        assert destination == site_packages
        copied.append(name)
        if name == "tomli" and tomli_state == "missing":
            raise PackageNotFoundError(name)
        value = deepcopy(expected["distributions"][name])
        if tomli_state == "wrong-version" and name == "tomli":
            value["version"] = "2.4.0"
        return value

    monkeypatch.setattr(install_gate, "_run", run)
    monkeypatch.setattr(install_gate, "_environment", lambda: {})
    monkeypatch.setattr(install_gate, "_provision_distribution", provision)
    monkeypatch.setattr(install_gate, "_load_json", lambda _path: wheel)
    monkeypatch.setattr(install_gate, "_write_json", lambda _path, report: reports.append(report))
    archive = tmp_path / "authored.whl"

    if tomli_state != "correct":
        error = PackageNotFoundError if tomli_state == "missing" else ValueError
        with pytest.raises(error):
            install_gate._create_fresh_environment(environment_root, archive, tmp_path)
        assert len(commands) == 1
        assert reports == []
    else:
        assert install_gate._create_fresh_environment(environment_root, archive, tmp_path) == python
        assert reports == [expected]
        assert commands[1] == [
            os.fspath(python),
            "-I",
            "-m",
            "pip",
            "install",
            "--isolated",
            "--no-index",
            "--no-deps",
            "--force-reinstall",
            os.fspath(archive),
        ]
    assert commands[0] == [
        "authored-parent-python",
        "-m",
        "venv",
        "--copies",
        os.fspath(environment_root),
    ]
    assert copied == sorted(expected["distributions"])


@pytest.mark.parametrize(("minor", "outside_tomli"), [(10, False), (10, True), (11, False)])
def test_installed_runtime_producer_reports_the_observed_conditional_dependency(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, minor: int, outside_tomli: bool
) -> None:
    prefix = tmp_path / "environment"
    purelib = prefix / "site-packages"
    purelib.mkdir(parents=True)
    forbidden = tmp_path / "checkout"
    forbidden.mkdir()
    console = prefix / ("Scripts/bluefire.exe" if os.name == "nt" else "bin/bluefire")
    console.parent.mkdir()
    console.touch()
    wheel, provision, expected = _reports(minor)
    modules = {
        "bluefire": "3.0.0",
        "yaml": "6.0.3",
        "cryptography": "50.0.0",
        "nacl": "1.6.2",
        "tomli": "2.4.1",
    }
    for name, version in modules.items():
        path = (tmp_path if name == "tomli" and outside_tomli else purelib) / f"{name}.py"
        path.touch()
        monkeypatch.setitem(
            sys.modules, name, SimpleNamespace(__file__=str(path), __version__=version)
        )
    monkeypatch.setattr(
        journey,
        "sys",
        SimpleNamespace(
            prefix=str(prefix),
            base_prefix=str(tmp_path / "base"),
            path=[str(purelib)],
            flags=SimpleNamespace(isolated=1),
            version_info=(3, minor),
        ),
    )
    monkeypatch.setattr(journey, "sysconfig", SimpleNamespace(get_path=lambda _name: str(purelib)))
    monkeypatch.setattr(journey, "site", SimpleNamespace(ENABLE_USER_SITE=False))
    monkeypatch.setattr(journey, "_SUPPORT", support)
    queried: list[str] = []

    def observed_version(name: str) -> str:
        queried.append(name)
        return provision["distributions"][name]["version"]

    monkeypatch.setattr(
        journey,
        "importlib",
        SimpleNamespace(
            metadata=SimpleNamespace(
                distribution=lambda _name: SimpleNamespace(
                    version="3.0.0", read_text=lambda _file: None
                ),
                version=observed_version,
            )
        ),
    )
    monkeypatch.delenv("BLUEFIRE_RUNNER_BINARY", raising=False)
    monkeypatch.delenv("BLUEFIRE_SANDBOX_ROOT", raising=False)

    if outside_tomli:
        with pytest.raises(journey.JourneyError, match="runtime dependency escaped"):
            journey._installed_package_report(forbidden)
        return
    report = journey._installed_package_report(forbidden)

    assert report == expected
    assert set(queried) == set(expected["dependencies"])
    validation.validate_dependency_runtime_binding(wheel, provision, report)
