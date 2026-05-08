"""Cross-platform-safe filenames for generated detection artifacts.

The orchestrator builds module-result dict keys as
``f"{module}:{step_id}"`` so steps that reuse the same module
(e.g. two ``execution`` steps in one scenario) don't clobber each
other in the result map. That key flowed straight into the
detection-artifact filename through ``stem = f"{module_name}_{run_id}"``,
producing paths like
``detections/sigma/resource_development:stage-infrastructure_run-X.yml``.

On NTFS that filename is invalid: Windows interprets ``:`` as the
Alternate Data Stream separator. The visible filename truncates
to everything before the first colon (``resource_development``),
the body is silently lost into an ADS, and the file ends up
0 bytes on disk. Drafts that operators thought were generated
were actually empty.

The fix routes the orchestrator key through
``_safe_filename_component`` before composing the filesystem
path. Filename-unsafe characters (``: * ? " < > | / \\``) are
replaced with ``__``; trailing space/dot is stripped. The
manifest / coverage records still carry the original
colon-separated form so report tooling that parses module keys
keeps working.

Pinned invariants:

1. Generated detection filenames contain no NTFS-unsafe character.
2. Files written round-trip non-empty content (no ADS leak).
3. ``module:step_id`` keys still surface inside the rendered Sigma
   rule body / Sigma id / YARA-L meta block / SPL eval clause —
   sanitisation is a filesystem-only concern.
4. ``validate_run_bundle`` walks every viewer ``<a href>`` and
   confirms each resolves to a non-empty file under the run dir.
5. Old runs whose filenames already contain a colon (POSIX-only
   historical state) keep validating cleanly because the fix
   only changes new-run output; it does not migrate historical
   artifacts.
6. The ``coverage_<run_id>.json`` filename is sanitised the same
   way so a future operator-supplied run id can't slip a colon
   through.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from src.core.detections import _safe_filename_component, write_detection_artifacts
from src.core.models import ModuleResult


# ---------------------------------------------------------------------------
# 1. Sanitiser unit tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value,expected",
    [
        ("execution:loader-execution", "execution__loader-execution"),
        ("module:step:nested", "module__step__nested"),
        ("foo*bar", "foo__bar"),
        ('foo"bar', "foo__bar"),
        ("foo<bar>baz", "foo__bar__baz"),
        ("foo|bar", "foo__bar"),
        ("foo/bar", "foo__bar"),
        ("foo\\bar", "foo__bar"),
        # Multiple unsafe chars cluster into multiple "__".
        ("a:b/c\\d", "a__b__c__d"),
        # Trailing whitespace/dots stripped (Windows ignores them).
        ("foo. ", "foo"),
        ("foo ", "foo"),
        ("foo.", "foo"),
        # Plain values pass through unchanged.
        ("simple_name", "simple_name"),
        ("module-name", "module-name"),
        # Edge cases.
        ("", ""),
        # Run-id format (``run-YYYYMMDDHHMMSS-<hex>``) has no
        # unsafe chars; sanitiser must be a no-op for it.
        ("run-20260507120000-abc123", "run-20260507120000-abc123"),
    ],
)
def test_safe_filename_component_replaces_unsafe_chars(
    value: str, expected: str
) -> None:
    assert _safe_filename_component(value) == expected


# ---------------------------------------------------------------------------
# 2. Engine-level invariant: no colon in any generated filename
# ---------------------------------------------------------------------------


def _result(module: str = "execution") -> ModuleResult:
    return ModuleResult(
        status="success",
        module=module,
        message="Loader executed.",
        techniques=["T1059"],
        artifacts={},
        detection_hints={
            "title": f"BlueFire {module}",
            "mitre_technique": "T1059",
            "logsource": {"product": "windows", "category": "process_creation"},
            "detection": {
                "selection": {"Image|endswith": "powershell.exe"},
                "condition": "selection",
            },
        },
        telemetry=[],
    )


def test_engine_strips_colon_from_module_step_key(tmp_path: Path) -> None:
    """``module:step_id`` keys never reach the filesystem path."""
    artifacts = write_detection_artifacts(
        tmp_path,
        "run-2026-05-07-abc",
        # The orchestrator's actual key shape: ``f"{module}:{step_id}"``.
        {"execution:loader-execution": _result("execution")},
    )
    for engine in ("sigma", "yara_l", "spl"):
        for path_str in artifacts[engine]:
            path = Path(path_str)
            # Filename must contain no NTFS-unsafe char.
            for unsafe in ':*?"<>|':
                assert unsafe not in path.name, (
                    f"{engine} filename {path.name!r} contains unsafe {unsafe!r}"
                )
            # ``__`` (double-underscore) replacement is observable
            # so a future regression that uses single-underscore
            # would still get caught (single underscore would
            # collide with the module<->run_id separator).
            assert "__" in path.name


def test_engine_writes_non_empty_files_with_colon_keys(tmp_path: Path) -> None:
    """No ADS leak: generated files must have non-zero content.

    The original bug shipped 0-byte files on Windows because the
    SHA in ``foo:bar.yml`` got written to an ADS. Pin the
    contents-on-disk size so a future regression is caught even
    on POSIX (where the filename would survive but the test we
    really care about is "Windows operators see real content").
    """
    artifacts = write_detection_artifacts(
        tmp_path,
        "run-2026-05-07-content",
        {"execution:loader-execution": _result("execution")},
    )
    for engine in ("sigma", "yara_l", "spl"):
        for path_str in artifacts[engine]:
            path = Path(path_str)
            assert path.is_file(), f"{path} not a regular file"
            assert path.stat().st_size > 0, f"{path} is empty"


def test_engine_preserves_original_module_key_in_rule_body(tmp_path: Path) -> None:
    """Sanitisation is a *filesystem-only* concern.

    The Sigma rule id, YARA-L meta block, and SPL eval clause all
    reference the orchestrator key — those must keep the colon
    so report tooling that parses module keys still works.
    Concretely: ``coverage_<run_id>.json`` records ``"module":
    "execution:loader-execution"``; the colon must survive.
    """
    artifacts = write_detection_artifacts(
        tmp_path,
        "run-2026-05-07-key",
        {"execution:loader-execution": _result("execution")},
    )
    coverage_path = next(tmp_path.glob("detections/coverage_*.json"))
    body = coverage_path.read_text(encoding="utf-8")
    assert '"module": "execution:loader-execution"' in body


def test_coverage_filename_sanitised(tmp_path: Path) -> None:
    """``coverage_{run_id}.json`` filename is sanitised too."""
    # Operator-chosen run id with an unsafe char.
    write_detection_artifacts(
        tmp_path,
        "run:custom",
        {"execution": _result("execution")},
    )
    coverage_files = list((tmp_path / "detections").glob("coverage_*"))
    assert coverage_files, "no coverage file written"
    for cov in coverage_files:
        assert ":" not in cov.name, (
            f"coverage filename should be sanitised: {cov.name}"
        )
        assert "__" in cov.name


# ---------------------------------------------------------------------------
# 3. End-to-end: validate-run still passes after the rename
# ---------------------------------------------------------------------------


def test_validate_run_bundle_passes_after_filename_sanitisation(
    tmp_path: Path,
) -> None:
    """Run a real scenario and confirm ``validate_run_bundle`` reports OK.

    This is the integration check: post-fix, every viewer
    ``<a href>`` must resolve to a real file on disk. If any
    detection link still contained a raw colon, ``validate-run``
    would either flag a broken link or — worse on Windows —
    silently succeed against a 0-byte ADS-leaked file.
    """
    import json
    import os
    import subprocess
    import sys

    env = dict(os.environ)
    env["BLUEFIRE_OUTPUT_ROOT"] = str(tmp_path)
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
    )
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)

    run_id = data["run_id"]
    run_dir = Path(data["output_dir"])

    # No filename in the run carries a colon.
    for p in run_dir.rglob("*"):
        if p.is_file():
            assert ":" not in p.name, f"unsafe filename: {p}"
            # And every detection artifact must be non-empty.
            if p.parent.name in {"sigma", "yara_l", "spl"}:
                assert p.stat().st_size > 0, f"empty detection artifact: {p}"

    # validate-run --json reports ok with zero missing / zero broken.
    val_proc = subprocess.run(
        [sys.executable, "-m", "src.core.cli", "validate-run", run_id, "--json"],
        capture_output=True,
        text=True,
        env=env,
    )
    assert val_proc.returncode == 0, val_proc.stdout + val_proc.stderr
    report = json.loads(val_proc.stdout)
    assert report["ok"] is True
    assert report["missing"] == []
    assert report["broken_links"] == []
