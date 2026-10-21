"""Workflow-only macOS ABI guard regression; no native compilation."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

REPOSITORY = Path(__file__).resolve().parents[1]


def _host_check_command():
    workflow = yaml.safe_load(
        (REPOSITORY / ".github/workflows/tests.yml").read_text(encoding="utf-8")
    )
    step = next(
        step
        for step in workflow["jobs"]["package"]["steps"]
        if step["name"] == "Verify macOS 26 arm64 SDK ABI"
    )
    checks = [
        line.strip()
        for line in step["run"].splitlines()
        if line.strip().startswith("rustc -vV | grep ")
    ]
    assert len(checks) == 1
    return checks[0]


def test_macos_arm64_abi_host_check_uses_a_draining_exact_match():
    assert _host_check_command() == ("rustc -vV | grep -x 'host: aarch64-apple-darwin' >/dev/null")


def test_macos_arm64_runs_and_uploads_installed_wheel_smoke():
    workflow = yaml.safe_load(
        (REPOSITORY / ".github/workflows/tests.yml").read_text(encoding="utf-8")
    )
    steps = workflow["jobs"]["package"]["steps"]
    smoke = next(step for step in steps if step["name"] == "Smoke installed wheel outside checkout")
    upload = next(
        step
        for step in steps
        if step["name"]
        == "Upload macOS 26 arm64 SDK, protocol, and installed-wheel evidence"
    )

    assert "if" not in smoke
    assert "verify_packaged_runner.py" in smoke["run"]
    assert "'smoke'" in smoke["run"]
    assert "installed-wheel-smoke.json" in smoke["run"]
    assert "${{ runner.temp }}/installed-wheel-smoke.json" in upload["with"]["path"]
    assert upload["if"].startswith("always()")


@pytest.mark.parametrize(
    ("host", "producer_exit", "expected_success"),
    [
        ("aarch64-apple-darwin", 0, True),
        ("x86_64-apple-darwin", 0, False),
        (None, 0, False),
        ("aarch64-apple-darwin", 7, False),
    ],
)
def test_macos_arm64_abi_host_check_consumes_rustc_output_under_pipefail(
    host, producer_exit, expected_success
):
    if os.name == "nt":
        pytest.skip("do not resolve bash through WSL on Windows")
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is required to exercise the workflow's shell pipeline")

    shell = """\
set -e -o pipefail
rustc() {
    if [ -n "$RUSTC_HOST" ]; then
        printf 'host: %s\\n' "$RUSTC_HOST"
    fi
    index=0
    while [ "$index" -lt 10000 ]; do
        printf 'additional rustc evidence line %05d\\n' "$index"
        index=$((index + 1))
    done
    return "$RUSTC_EXIT"
}
""" + _host_check_command()
    result = subprocess.run(
        [bash, "-c", shell],
        env={
            **os.environ,
            "RUSTC_HOST": host or "",
            "RUSTC_EXIT": str(producer_exit),
        },
        capture_output=True,
        timeout=15,
    )
    assert (result.returncode == 0) is expected_success
