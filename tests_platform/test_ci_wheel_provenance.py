"""File-only archive/build metadata checks; no native compilation or execution."""

from __future__ import annotations

import hashlib
import json
import os
import runpy
import shlex
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

REPOSITORY = Path(__file__).resolve().parents[1]


def _package_job():
    workflow = yaml.safe_load((REPOSITORY / ".github/workflows/tests.yml").read_text())
    return workflow["jobs"]["package"]


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
        'git archive --format=tar --output="$RUNNER_TEMP/bluefire-wheel-source.tar" "$GITHUB_SHA"'
        in archive["run"]
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
    command("add", ".")
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
        command("archive", "--format=tar", "--output=" + str(archive_path), revision)
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


@pytest.mark.parametrize("recorded", ["exact", "wrong", "missing"])
def test_workflow_checks_actual_wheel_metadata_before_upload(tmp_path, recorded):
    step = next(
        step
        for step in _package_job()["steps"]
        if step["name"] == "Verify embedded committed source identity"
    )
    command = shlex.split(step["run"])
    assert command[:2] == ["python", "-c"]
    command[0] = str(Path(sys.executable).absolute())
    (tmp_path / "dist").mkdir()
    with zipfile.ZipFile(tmp_path / "dist/fixture.whl", "w") as archive:
        if recorded != "missing":
            archive.writestr(
                "fixture.data/purelib/bluefire/_build_info.json",
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
    assert (result.returncode == 0) is (recorded == "exact")
