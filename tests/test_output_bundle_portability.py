"""Output bundle portability — pre-rc2 hardening.

A real defender often wants to zip / move / share a run output
directory: e.g. archive successful purple-team runs to a shared
drive, or hand a SOC team the bundle for a specific incident.
For that workflow the artifact tree must be self-contained:

- Internal links inside ``index.html`` are run-dir-relative
  (already pinned by ``test_demo_bundle_validation.py``).
- Every text artifact written into the run dir uses run-dir-
  relative paths internally so a recipient can move the dir to
  ``C:\\share\\incident-20260508\\`` (or any other location)
  and references continue to resolve.
- No machine-specific temp prefix leaks into the artifacts (it
  would break portability AND leak host-identifying information
  about the analyst that produced the run).
- No API keys / secrets land in any artifact (the offline /
  template default does not reference any, but a hardening
  guard cannot hurt).
- ``validate-run`` works against a moved/copied run directory.

Pinned invariants:

1. ``coverage_<run_id>.json`` references each detection draft via
   a run-dir-relative POSIX path (no absolute prefix).
2. ``report.md`` references each detection draft via a run-dir-
   relative path.
3. No text artifact under ``output/<run_id>/`` contains the
   run dir's absolute prefix as a substring (machine-specific
   leak guard).
4. No text artifact contains common API-key signatures (loose
   regex for ``sk-`` style tokens, ``Bearer `` headers, base64
   blobs that look like API keys).
5. The viewer's ``index.html`` ``<a href>`` values are all
   relative (no absolute filesystem paths, no external schemes).
6. After moving a freshly-generated run dir to a new location,
   ``validate_run_bundle`` still reports ``ok=true`` against the
   moved location (relative-link survival test).
7. ``manifest.json`` only carries run-dir-relative paths in its
   detections / reports / telemetry blocks.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Iterator

import pytest

from src.core.reporting import validate_run_bundle


# Loose regex for common secret leak signatures. Designed to catch
# "did an env var slip into an artifact?" rather than to be a
# full secrets-detection layer (the project already uses
# ``detect-secrets`` and ``gitleaks`` in CI for that).
_SECRET_PATTERNS = (
    re.compile(r"sk-[A-Za-z0-9]{20,}"),  # OpenAI-style
    re.compile(r"Bearer\s+[A-Za-z0-9\-_=]{20,}"),
    re.compile(r"x-api-key:\s*[A-Za-z0-9\-_=]{16,}"),
    re.compile(r'"api_key":\s*"[A-Za-z0-9\-_=]{16,}"'),
)


@pytest.fixture(scope="module")
def portable_run(tmp_path_factory: pytest.TempPathFactory) -> Iterator[dict]:
    """Run apt29_credential_access once; reuse run dir across checks."""
    output_root = tmp_path_factory.mktemp("portability_output")
    env = dict(os.environ)
    env["BLUEFIRE_OUTPUT_ROOT"] = str(output_root)
    env["PYTHONIOENCODING"] = "utf-8"
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
        "output_root": output_root,
        "run_id": data["run_id"],
        "run_dir": Path(data["output_dir"]),
        "env": env,
    }


# ---------------------------------------------------------------------------
# 1. Path leakage
# ---------------------------------------------------------------------------


def test_coverage_sidecar_uses_relative_paths(portable_run: dict) -> None:
    """``coverage_<run_id>.json`` references each draft via a relative POSIX path."""
    cov_files = list((portable_run["run_dir"] / "detections").glob("coverage_*.json"))
    assert cov_files, "coverage sidecar missing"
    for cov in cov_files:
        payload = json.loads(cov.read_text(encoding="utf-8"))
        for entry in payload.get("detections", []):
            for engine in ("sigma", "yara_l", "spl"):
                path = entry.get(engine)
                if not path:
                    continue
                # Must NOT be absolute.
                assert not Path(path).is_absolute(), (
                    f"coverage entry references absolute path: {path}"
                )
                # POSIX-style separator (forward slash).
                assert "\\" not in path, (
                    f"coverage path uses Windows separator: {path}"
                )


def test_report_md_uses_relative_detection_paths(portable_run: dict) -> None:
    """``report.md`` Detection Artifacts section references each draft relatively."""
    body = (portable_run["run_dir"] / "report.md").read_text(encoding="utf-8")
    detection_section = body.split("## Detection Artifacts", 1)[-1]
    paths = re.findall(r"`([^`]+\.(?:yml|yaral|spl))`", detection_section)
    assert paths, "no detection paths surfaced in report.md"
    for path in paths:
        assert not Path(path).is_absolute(), (
            f"report.md detection path is absolute: {path}"
        )


def test_no_text_artifact_leaks_machine_specific_prefix(
    portable_run: dict,
) -> None:
    """No text artifact under output/<run_id>/ contains the run dir's
    absolute prefix as a substring.

    A leak here is both a portability bug (recipient can't move
    the bundle) AND an info-leak (host paths identify the
    analyst's machine).
    """
    run_dir: Path = portable_run["run_dir"]
    output_root: Path = portable_run["output_root"]
    forbidden_substrings = (str(run_dir.resolve()), str(output_root.resolve()))
    text_extensions = {".md", ".json", ".yml", ".yaral", ".spl", ".txt", ".jsonl", ".html"}
    leaks: list[tuple[str, str]] = []
    for path in run_dir.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() not in text_extensions:
            continue
        try:
            body = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for forbidden in forbidden_substrings:
            if forbidden in body:
                rel = path.relative_to(run_dir).as_posix()
                leaks.append((rel, forbidden))
                break
    assert not leaks, (
        f"machine-specific path prefix in artifacts: {leaks[:5]}"
    )


# ---------------------------------------------------------------------------
# 2. Secret-leak guard
# ---------------------------------------------------------------------------


def test_no_text_artifact_contains_secret_signatures(
    portable_run: dict,
) -> None:
    """Loose regex sweep for accidental key / token leaks.

    Default offline run never references a real key, but a future
    regression that pasted an env-var value into an artifact
    would surface here. Belt-and-braces alongside the project's
    existing ``detect-secrets`` / ``gitleaks`` CI gates (which
    scan the *source*, not the run output).
    """
    run_dir: Path = portable_run["run_dir"]
    text_extensions = {".md", ".json", ".yml", ".yaral", ".spl", ".txt", ".jsonl", ".html"}
    hits: list[tuple[str, str]] = []
    for path in run_dir.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() not in text_extensions:
            continue
        try:
            body = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for pattern in _SECRET_PATTERNS:
            match = pattern.search(body)
            if match:
                rel = path.relative_to(run_dir).as_posix()
                hits.append((rel, match.group(0)[:30]))
                break
    assert not hits, f"possible secret signatures: {hits[:5]}"


# ---------------------------------------------------------------------------
# 3. Manifest path discipline
# ---------------------------------------------------------------------------


def test_manifest_carries_only_relative_paths_in_detection_block(
    portable_run: dict,
) -> None:
    manifest = json.loads(
        (portable_run["run_dir"] / "manifest.json").read_text(encoding="utf-8")
    )
    detections = manifest.get("detections") or {}
    per_step = detections.get("per_step") or []
    for entry in per_step:
        engines = entry.get("engines") or {}
        for engine, paths in engines.items():
            for path in paths:
                assert not Path(path).is_absolute(), (
                    f"manifest detection path is absolute: {engine} {path}"
                )


def test_manifest_telemetry_path_is_relative(portable_run: dict) -> None:
    manifest = json.loads(
        (portable_run["run_dir"] / "manifest.json").read_text(encoding="utf-8")
    )
    telemetry = manifest.get("telemetry") or {}
    path = telemetry.get("path")
    if path:
        assert not Path(path).is_absolute(), (
            f"manifest telemetry path is absolute: {path}"
        )


def test_manifest_reports_block_uses_relative_paths(portable_run: dict) -> None:
    manifest = json.loads(
        (portable_run["run_dir"] / "manifest.json").read_text(encoding="utf-8")
    )
    reports = manifest.get("reports") or {}
    for key, value in reports.items():
        if not value:
            continue
        assert not Path(value).is_absolute(), (
            f"manifest report path is absolute: {key} {value}"
        )


# ---------------------------------------------------------------------------
# 4. Viewer relative-link survival
# ---------------------------------------------------------------------------


def test_viewer_hrefs_are_all_relative(portable_run: dict) -> None:
    """Every ``<a href>`` in the viewer is a relative path."""
    body = (portable_run["run_dir"] / "index.html").read_text(encoding="utf-8")
    hrefs = re.findall(r'<a\s+[^>]*href="([^"]+)"', body)
    assert hrefs, "no hrefs in viewer index.html"
    for href in hrefs:
        # Anchor-only is fine.
        if href.startswith("#"):
            continue
        assert not href.startswith(
            ("http://", "https://", "file://", "//", "/")
        ), f"non-relative href in viewer: {href}"


# ---------------------------------------------------------------------------
# 5. Move-the-run-dir survival test
# ---------------------------------------------------------------------------


def test_validate_run_bundle_passes_after_moving_run_dir(
    tmp_path: pytest.TempPathFactory, portable_run: dict
) -> None:
    """Move the run dir to a NEW parent and re-validate.

    The whole point of a portable bundle: a recipient unzips it
    on their machine, opens the viewer, runs the validator, and
    everything works. This test simulates that workflow.

    Uses ``shutil.copytree`` to a fresh tmp dir so the original
    run dir stays usable for other tests in this module.
    """
    new_parent = Path(tmp_path) / "moved-bundle"
    new_run_dir = new_parent / portable_run["run_id"]
    shutil.copytree(portable_run["run_dir"], new_run_dir)

    report = validate_run_bundle(new_run_dir)
    assert report["ok"] is True, (
        f"validate-run failed at new location: missing={report['missing']}, "
        f"broken_links={report['broken_links']}"
    )
    assert report["missing"] == []
    assert report["broken_links"] == []
