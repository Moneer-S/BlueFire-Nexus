"""Pytest wrapper around ``scripts/smoke_release_candidate.py``.

The smoke script is the maintainer-facing pre-release gate. This
test file exercises a subset of the same checks as part of the
regular ``pytest`` suite so an accidental regression of any
rc1-polish invariant is caught in CI rather than only at release
cut.

The tests intentionally call the smoke-script's check functions
directly rather than spawning the script as a subprocess. That
keeps the failure surface narrow (no shelling out to the script
itself) and lets each test focus on a single invariant.

Pinned invariants (mirrors the rc1-polish acceptance gate):

1. The smoke script is importable as a module — protects against
   syntax errors landing in a script that's only run at release
   time.
2. A real ``apt29_credential_access`` run produces a complete
   canonical bundle (manifest / index.html / report.md /
   report.json / risk_summary.json / telemetry.jsonl).
3. Per-run ``index.html`` is non-empty and the top-level
   ``output/index.html`` aggregator is also written.
4. No filename in the run dir contains ``:`` (NTFS ADS guard
   from PR #94).
5. YARA-L files do not carry the legacy ``run_id = "manual"``
   placeholder (PR #89 correlation parity).
6. SPL drafts carry the ``DRAFT detection search`` comment
   header (PR #89 honest framing).
7. ``validate-run --json`` reports ``ok=true``.
8. CLI ``latest-run`` output contains no Unicode replacement
   character and no em-dash (PR #91 Windows mojibake guard).
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Iterator

import pytest


SMOKE_PATH = (
    Path(__file__).resolve().parents[1] / "scripts" / "smoke_release_candidate.py"
)


# ---------------------------------------------------------------------------
# Module-level smoke: the smoke script must at least import cleanly
# ---------------------------------------------------------------------------


def test_smoke_script_imports_cleanly() -> None:
    """Loading ``smoke_release_candidate`` as a module must not raise.

    Catches accidental syntax errors / import-time failures that
    would otherwise only surface at the next release cut.

    The module is registered in ``sys.modules`` BEFORE
    ``exec_module`` because ``@dataclass`` looks up its host
    module by name at decoration time and would otherwise see
    ``None`` and raise ``AttributeError``.
    """
    spec = importlib.util.spec_from_file_location(
        "smoke_release_candidate_under_test", SMOKE_PATH
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["smoke_release_candidate_under_test"] = module
    try:
        spec.loader.exec_module(module)
        assert hasattr(module, "CHECKS"), "module must expose CHECKS list"
        assert callable(module.main), "module must expose main()"
        for check in module.CHECKS:
            assert callable(check), f"non-callable check: {check!r}"
    finally:
        sys.modules.pop("smoke_release_candidate_under_test", None)


# ---------------------------------------------------------------------------
# Single canonical run + targeted assertions
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def smoke_run(tmp_path_factory: pytest.TempPathFactory) -> Iterator[dict]:
    """Run apt29_credential_access once; share the resulting run dir."""
    output_root = tmp_path_factory.mktemp("rc_smoke_output")
    env = dict(os.environ)
    env["BLUEFIRE_OUTPUT_ROOT"] = str(output_root)
    env["PYTHONIOENCODING"] = "utf-8"
    env["NO_COLOR"] = "1"
    env["COLUMNS"] = "240"
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "src.run_scenario",
            "--profile",
            "apt29_credential_access",
            "--output-json",
        ],
        capture_output=True,
        text=True,
        env=env,
        encoding="utf-8",
    )
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    yield {
        "data": data,
        "run_id": data["run_id"],
        "run_dir": Path(data["output_dir"]),
        "output_root": output_root,
        "env": env,
    }


def test_smoke_run_canonical_bundle_present(smoke_run: dict) -> None:
    run_dir: Path = smoke_run["run_dir"]
    for name in (
        "manifest.json",
        "index.html",
        "report.md",
        "report.json",
        "risk_summary.json",
        "telemetry.jsonl",
    ):
        assert (run_dir / name).exists(), f"canonical artifact missing: {name}"


def test_smoke_run_per_run_viewer_non_empty(smoke_run: dict) -> None:
    viewer = smoke_run["run_dir"] / "index.html"
    assert viewer.exists()
    assert viewer.stat().st_size >= 1024, "per-run viewer suspiciously small"


def test_smoke_run_top_level_aggregator_written(smoke_run: dict) -> None:
    aggregator = smoke_run["output_root"] / "index.html"
    assert aggregator.exists(), "output/index.html aggregator not written"
    assert aggregator.stat().st_size >= 256, "aggregator suspiciously small"


def test_smoke_run_no_colon_filenames(smoke_run: dict) -> None:
    """Cross-platform filename invariant from PR #94."""
    bad = [
        str(p.relative_to(smoke_run["run_dir"]))
        for p in smoke_run["run_dir"].rglob("*")
        if p.is_file() and ":" in p.name
    ]
    assert not bad, f"unsafe filenames present: {bad[:5]}"


def test_smoke_run_yara_l_real_run_id(smoke_run: dict) -> None:
    """YARA-L correlation parity invariant from PR #89."""
    yaral_dir = smoke_run["run_dir"] / "detections" / "yara_l"
    if not yaral_dir.exists():
        pytest.skip("no yara_l dir in this scenario")
    for path in yaral_dir.glob("*.yaral"):
        body = path.read_text(encoding="utf-8")
        assert 'run_id = "manual"' not in body, (
            f"{path.name} still has hardcoded manual run_id"
        )


def test_smoke_run_spl_carries_draft_header(smoke_run: dict) -> None:
    """SPL honest-framing invariant from PR #89."""
    spl_dir = smoke_run["run_dir"] / "detections" / "spl"
    if not spl_dir.exists():
        pytest.skip("no spl dir in this scenario")
    for path in spl_dir.glob("*.spl"):
        body = path.read_text(encoding="utf-8")
        assert "DRAFT detection search" in body, (
            f"{path.name} missing DRAFT header"
        )


def test_smoke_run_validate_run_reports_ok(smoke_run: dict) -> None:
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "src.core.cli",
            "validate-run",
            smoke_run["run_id"],
            "--json",
            "--output-root",
            str(smoke_run["output_root"]),
        ],
        capture_output=True,
        text=True,
        env=smoke_run["env"],
        encoding="utf-8",
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    report = json.loads(proc.stdout)
    assert report["ok"] is True
    assert report["missing"] == []
    assert report["broken_links"] == []


def test_smoke_run_cli_output_free_of_mojibake(smoke_run: dict) -> None:
    """Windows CLI mojibake invariant from PR #91."""
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "src.core.cli",
            "latest-run",
            "--output-root",
            str(smoke_run["output_root"]),
        ],
        capture_output=True,
        text=True,
        env=smoke_run["env"],
        encoding="utf-8",
    )
    combined = (proc.stdout or "") + (proc.stderr or "")
    assert "�" not in combined, "CLI output contains U+FFFD"
    assert "—" not in combined, "CLI output contains em-dash (Windows mojibake risk)"


def test_smoke_run_cli_file_uri_on_standalone_line(smoke_run: dict) -> None:
    """URL-line invariant from PR #91."""
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "src.core.cli",
            "latest-run",
            "--output-root",
            str(smoke_run["output_root"]),
        ],
        capture_output=True,
        text=True,
        env=smoke_run["env"],
        encoding="utf-8",
    )
    file_lines = [line for line in proc.stdout.splitlines() if "file://" in line]
    assert file_lines, "no file:// URI in stdout"
    standalone = [
        line for line in file_lines if line.lstrip().startswith("file://")
    ]
    assert standalone, (
        f"file:// URI must start a line; got: {file_lines!r}"
    )
