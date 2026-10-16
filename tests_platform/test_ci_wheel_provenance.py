"""File-only archive/build metadata checks; no native compilation or execution."""

from __future__ import annotations

import hashlib
import json
import os
import re
import runpy
import shlex
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from bluefire.runner_inventory import BUILTIN_RUNNER_ACTION_IDS

REPOSITORY = Path(__file__).resolve().parents[1]


def _package_job():
    workflow = yaml.safe_load(
        (REPOSITORY / ".github/workflows/tests.yml").read_text(encoding="utf-8")
    )
    python_job = workflow["jobs"]["python"]
    assert python_job["name"] == (
        "Python ${{ matrix.python-version }} \u00b7 ${{ matrix.os }}"
        "${{ matrix.partition && format(' \u00b7 {0}', matrix.partition) || '' }}"
    )
    matrix = python_job["strategy"]["matrix"]
    assert set(matrix) == {"os", "python-version", "include"}
    assert matrix["os"] == ["ubuntu-latest", "macos-latest"]
    assert matrix["python-version"] == ["3.10", "3.12"]
    windows = matrix["include"]
    assert len(windows) == 6
    assert all(set(entry) == {"os", "python-version", "partition"} for entry in windows)
    assert {(entry["os"], entry["python-version"], entry["partition"]) for entry in windows} == {
        ("windows-latest", version, partition)
        for version in ("3.10", "3.12")
        for partition in ("a-d", "e-q", "remainder")
    }
    assert python_job["timeout-minutes"] == 120
    assert workflow["jobs"]["rust"]["name"] == "Rust runner \u00b7 ${{ matrix.os }}"
    return workflow["jobs"]["package"]


def _windows_partition_files(names, partition):
    ranges = {"a-d": ("a", "d"), "e-q": ("e", "q")}
    if partition not in {*ranges, "remainder"}:
        raise ValueError(f"unknown Windows test partition: {partition}")

    def belongs(name):
        match = re.fullmatch(r"test_(.).*\.py", name)
        first = match.group(1) if match is not None else ""
        in_middle = "a" <= first <= "q"
        if partition == "remainder":
            return not in_middle
        start, end = ranges[partition]
        return start <= first <= end

    return {name for name in names if belongs(name)}


def test_windows_test_partitions_cover_flat_discovered_suite():
    workflow = yaml.safe_load(
        (REPOSITORY / ".github/workflows/tests.yml").read_text(encoding="utf-8")
    )
    python_job = workflow["jobs"]["python"]
    step = next(item for item in python_job["steps"] if item["name"] == "Test Windows partition")
    command = step["run"]
    assert command.count("Get-ChildItem -LiteralPath tests_platform -File") == 2
    assert command.count("Where-Object { $_.Name -cmatch '^test_[a-d].*\\.py$' }") == 1
    assert command.count("Where-Object { $_.Name -cmatch '^test_[e-q].*\\.py$' }") == 1
    assert "--ignore-glob=tests_platform/test_[a-q]*.py" in command
    assert all(f"'{partition}' {{" in command for partition in ("a-d", "e-q", "remainder"))
    assert 'default { throw "Unknown Windows test partition:' in command

    test_root = REPOSITORY / "tests_platform"
    flat_paths = {path for path in test_root.glob("test_*.py") if path.is_file()}
    nested_paths = {
        path for path in test_root.rglob("test_*.py") if path.is_file() and path.parent != test_root
    }
    assert flat_paths
    assert not nested_paths
    names = {path.name for path in flat_paths}
    # Windows pytest normalizes ignore globs, unlike the explicit case-sensitive groups.
    assert all(name == name.lower() for name in names)

    partitions = {
        partition: _windows_partition_files(names, partition)
        for partition in ("a-d", "e-q", "remainder")
    }
    assert all(partitions.values())
    assert partitions["a-d"].isdisjoint(partitions["e-q"])
    assert partitions["a-d"].isdisjoint(partitions["remainder"])
    assert partitions["e-q"].isdisjoint(partitions["remainder"])
    assert set.union(*partitions.values()) == names

    boundaries = {
        "test_d_boundary.py": "a-d",
        "test_e_boundary.py": "e-q",
        "test_q_boundary.py": "e-q",
        "test_r_boundary.py": "remainder",
        "test_1_nonletter.py": "remainder",
    }
    for name, expected in boundaries.items():
        assert _windows_partition_files({name}, expected) == {name}
        assert all(
            _windows_partition_files({name}, other) == set()
            for other in set(partitions) - {expected}
        )
    with pytest.raises(ValueError, match="unknown Windows test partition"):
        _windows_partition_files(names, "a-c")


def test_native_wheel_build_and_verification_use_the_exact_archive():
    job = _package_job()
    assert job["defaults"]["run"]["working-directory"] == "./wheel-source"
    steps = {step["name"]: step for step in job["steps"]}
    names = list(steps)
    archive = steps["Archive exact committed wheel source"]
    assert archive["working-directory"] == "${{ github.workspace }}"
    assert archive["shell"] == "bash"
    assert 'test "$(git rev-parse HEAD)" = "$GITHUB_SHA"' in archive["run"]
    assert (
        "git -c tar.umask=0022 archive --format=tar "
        '--output="$RUNNER_TEMP/bluefire-wheel-source.tar" "$GITHUB_SHA"' in archive["run"]
    )
    assert "mkdir wheel-source" in archive["run"]
    assert (
        'python -m tarfile -e "$RUNNER_TEMP/bluefire-wheel-source.tar" wheel-source'
        in archive["run"]
    )
    assert "_source_revision.txt" in archive["run"]
    for name in (
        "Install build tooling only",
        "Verify pinned Rust toolchain",
        "Install static Linux runner target",
        "Build static Linux release runner",
        "Build native release runner",
        "Stage verified native runner resources",
        "Build platform wheel",
        "Verify embedded committed source identity",
        "Inspect wheel tag and native resources",
        "Install wheel into a clean environment",
    ):
        assert names.index(name) > names.index("Archive exact committed wheel source")
        assert "working-directory" not in steps[name]
    staged = steps["Stage verified native runner resources"]["run"]
    assert "${{ github.workspace }}/wheel-source/${{ matrix.runner-path }}" in staged
    assert "${{ github.workspace }}/wheel-source/bluefire/native" in staged
    assert steps["Build platform wheel"]["run"] == "python -m build --wheel"
    assert {entry["platform"] for entry in job["strategy"]["matrix"]["include"]} == {
        "windows",
        "linux",
        "macos",
    }
    smoke = steps["Bootstrap and Execute from installed wheel outside checkout"]
    assert smoke["working-directory"] == "${{ runner.temp }}"
    assert "'--forbid-root', os.environ['GITHUB_WORKSPACE']" in smoke["run"]
    upload = steps["Upload wheel and verification reports"]["with"]["path"].splitlines()
    assert upload == [
        "wheel-source/dist/*.whl",
        "wheel-source/dist/package-inspection.json",
        "${{ runner.temp }}/installed-wheel-smoke.json",
    ]


def test_actual_committed_archives_distinguish_backend_changes_with_identical_ui(tmp_path):
    git = shutil.which("git")
    assert git is not None
    source = tmp_path / "source"
    source.mkdir()

    def command(*args):
        return subprocess.run(
            [git, *args], cwd=source, check=True, capture_output=True, text=True, timeout=15
        ).stdout.strip()

    command("init")
    # A permissive inherited archive setting must not override the workflow policy.
    command("config", "tar.umask", "0002")
    (source / ".gitattributes").write_bytes((REPOSITORY / ".gitattributes").read_bytes())
    (source / "setup.py").write_bytes((REPOSITORY / "setup.py").read_bytes())
    package = source / "bluefire"
    (package / "ui").mkdir(parents=True)
    (package / "_source_revision.txt").write_bytes(
        (REPOSITORY / "bluefire/_source_revision.txt").read_bytes()
    )
    for name in ("app.js", "index.html", "styles.css"):
        (package / "ui" / name).write_text(name + "\n", encoding="utf-8")
    backend = package / "backend.py"
    backend.write_text("committed = 1\n", encoding="utf-8")
    executable = source / "fixture-executable.sh"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    command("add", ".")
    command("update-index", "--chmod=+x", "fixture-executable.sh")
    command(
        "-c",
        "user.name=Build fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "commit",
        "-m",
        "first",
    )
    first = command("rev-parse", "HEAD")

    def built_identity(revision, name):
        archive_path = tmp_path / (name + " source.tar")
        step = next(
            step
            for step in _package_job()["steps"]
            if step["name"] == "Archive exact committed wheel source"
        )
        line = next(line for line in step["run"].splitlines() if " --format=tar " in line)
        archive_command = shlex.split(line)
        assert archive_command[0] == "git"
        replacements = {
            "--output=$RUNNER_TEMP/bluefire-wheel-source.tar": "--output=" + str(archive_path),
            "$GITHUB_SHA": revision,
        }
        command(*(replacements.get(arg, arg) for arg in archive_command[1:]))
        with tarfile.open(archive_path) as archive:
            members = archive.getmembers()
            assert members and any(member.isdir() for member in members)
            assert all(member.mode & 0o022 == 0 for member in members)
            assert archive.getmember("bluefire").mode == 0o755
            assert archive.getmember("bluefire/backend.py").mode == 0o644
            assert archive.getmember("fixture-executable.sh").mode == 0o755
        extracted = tmp_path / name
        extracted.mkdir()
        subprocess.run(
            [
                str(Path(sys.executable).absolute()),
                "-m",
                "tarfile",
                "-e",
                str(archive_path),
                str(extracted),
            ],
            check=True,
            capture_output=True,
            timeout=15,
        )
        assert (extracted / "bluefire/_source_revision.txt").read_text().strip() == revision
        assert not (extracted / "untracked.py").exists()
        with patch("setuptools.setup"):
            hook = runpy.run_path(str(extracted / "setup.py"))
        hook["_write_build_identity"](extracted / "bluefire", extracted / "bluefire", "3.0.0")
        raw = (extracted / "bluefire/_build_info.json").read_bytes()
        return json.loads(raw), hashlib.sha256(raw).hexdigest(), extracted

    # Dirty and untracked checkout bytes must never receive the committed identity.
    backend.write_text("dirty = 9\n", encoding="utf-8")
    (source / "untracked.py").write_text("untracked = 9\n", encoding="utf-8")
    first_info, first_digest, extracted = built_identity(first, "first")
    assert (extracted / "bluefire/backend.py").read_text() == "committed = 1\n"
    assert backend.read_text() == "dirty = 9\n"
    backend.write_text("committed = 2\n", encoding="utf-8")
    command("add", "bluefire/backend.py")
    command(
        "-c",
        "user.name=Build fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "commit",
        "-m",
        "backend only",
    )
    second = command("rev-parse", "HEAD")
    second_info, second_digest, _ = built_identity(second, "second")
    assert first_info["source_revision"] == first != second == second_info["source_revision"]
    assert first_info["source_provenance"] == second_info["source_provenance"] == "git_archive"
    assert first_info["ui_digest"] == second_info["ui_digest"]
    assert first_digest != second_digest


@pytest.mark.parametrize("layout", ["root", "purelib", "platlib", "duplicate", "unrelated"])
@pytest.mark.parametrize("recorded", ["exact", "wrong", "missing"])
def test_workflow_checks_actual_wheel_metadata_before_upload(tmp_path, recorded, layout):
    step = next(
        step
        for step in _package_job()["steps"]
        if step["name"] == "Verify embedded committed source identity"
    )
    command = shlex.split(step["run"])
    assert command[:2] == ["python", "-c"]
    command[0] = str(Path(sys.executable).absolute())
    (tmp_path / "dist").mkdir()
    root_member = "bluefire/_build_info.json"
    layouts = {
        "root": [root_member],
        "purelib": ["fixture.data/purelib/" + root_member],
        "platlib": ["fixture.data/platlib/" + root_member],
        "duplicate": [root_member, "fixture.data/purelib/" + root_member],
        "unrelated": ["unrelated/" + root_member],
    }
    with zipfile.ZipFile(tmp_path / "dist/fixture.whl", "w") as archive:
        if recorded != "missing":
            for member in layouts[layout]:
                archive.writestr(
                    member,
                    json.dumps(
                        {
                            "source_revision": "a" * 40 if recorded == "exact" else "b" * 40,
                            "source_provenance": "git_archive",
                        }
                    ),
                )
    result = subprocess.run(
        command,
        cwd=tmp_path,
        env={**os.environ, "GITHUB_SHA": "a" * 40},
        capture_output=True,
        timeout=15,
    )
    assert (result.returncode == 0) is (
        recorded == "exact" and layout not in {"duplicate", "unrelated"}
    )


COMMITTED_NATIVE_RUNNERS = (
    ("bluefire/native/bluefire-runner.exe", "bluefire/native/runner-manifest.json"),
    (
        "bluefire/native/linux-x86_64/bluefire-runner",
        "bluefire/native/linux-x86_64/runner-manifest.json",
    ),
)


@pytest.mark.parametrize(("binary", "manifest"), COMMITTED_NATIVE_RUNNERS)
def test_committed_native_runner_is_not_stale_against_the_builtin_catalog(binary, manifest):
    """Fail when a committed runner predates an action added to the registry.

    The Windows artifact was staged two days before
    ``sandbox.collection.atomic-gzip.v1`` joined ``BUILTIN_RUNNER_ACTION_VERSIONS``
    and was never restaged. ``bootstrap_runner`` validates with
    ``require_exact_catalog=True``, so both Windows CI jobs failed while Linux and
    macOS stayed green, because the gate modules that consume the packaged runner
    skip when ``os.name != "nt"``.

    This reads the committed artifacts instead of executing them, so a host of
    either platform detects a stale artifact for both.
    """

    artifact = REPOSITORY / binary
    recorded = json.loads((REPOSITORY / manifest).read_text(encoding="utf-8"))
    blob = artifact.read_bytes()

    assert recorded["artifact"]["filename"] == artifact.name
    assert len(blob) == recorded["artifact"]["size"]
    assert hashlib.sha256(blob).hexdigest() == recorded["artifact"]["sha256"]

    missing = sorted(
        action_id
        for action_id in BUILTIN_RUNNER_ACTION_IDS
        if action_id.encode("ascii") not in blob
    )
    assert not missing, (
        f"{binary} does not advertise {missing}; rebuild the runner at this revision "
        "and restage it with tools/stage_native_runner.py"
    )
