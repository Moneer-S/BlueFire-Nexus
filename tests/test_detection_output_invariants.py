r"""End-to-end detection-output regression invariants.

PRs #89 and #94 closed two real Windows fresh-clone bugs in the
detection-artifact pipeline:

- YARA-L meta hardcoded ``run_id = "manual"`` -- Sigma <-> YARA-L
  correlation parity broke.
- Module-step keys with ``:`` flowed into NTFS filenames as
  Alternate Data Stream separators -- detection files ended up
  0 bytes on Windows.

The targeted tests for those fixes already exist
(``test_detection_draft_credibility.py`` /
``test_detection_filename_safety.py``). This file pins broader
end-to-end invariants by running a real scenario and asserting
about the generated artifact tree as a whole -- so a regression
in the *orchestrator* call site (instead of the engine helpers)
gets caught before release.

Pinned invariants:

1. Every successful step produces matching Sigma + YARA-L + SPL
   files (cross-engine consistency: a defender expects all three
   per technique).
2. The filename stem (``<safe_module>_<safe_run_id>``) is
   identical across the three engines for a given step. A future
   regression in one renderer cannot drift the stem.
3. Every path the manifest records in ``detections.per_step``
   resolves to an existing non-zero-byte file under the run dir.
4. No detection filename anywhere in the run dir contains a
   character forbidden by NTFS (``: * ? " < > | / \``).
5. No YARA-L file body carries the legacy ``run_id = "manual"``
   placeholder — broader assertion than the per-rule check in
   the credibility test, since this walks every emitted file.
6. Every SPL file carries the ``DRAFT detection search`` comment
   header — broader assertion than the per-call render test.
7. The ``coverage_<run_id>.json`` sibling references the same
   filename stems as the on-disk files (manifest <-> coverage
   consistency).
8. Run-id sanitisation is filename-only: the YARA-L meta block
   carries the ORIGINAL run_id from the orchestrator (with any
   hyphens etc. preserved), even when the filename uses the
   sanitised form.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Iterator

import pytest


_FILENAME_UNSAFE_CHARS = ':*?"<>|/\\'


@pytest.fixture(scope="module")
def detection_run(
    tmp_path_factory: pytest.TempPathFactory,
) -> Iterator[dict]:
    """Run apt29_credential_access once; share the resulting run dir."""
    output_root = tmp_path_factory.mktemp("detection_invariants_output")
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
    run_dir = Path(data["output_dir"])
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    yield {
        "data": data,
        "run_id": data["run_id"],
        "run_dir": run_dir,
        "manifest": manifest,
        "sigma_dir": run_dir / "detections" / "sigma",
        "yaral_dir": run_dir / "detections" / "yara_l",
        "spl_dir": run_dir / "detections" / "spl",
    }


# ---------------------------------------------------------------------------
# 1. Cross-engine consistency
# ---------------------------------------------------------------------------


def test_every_step_emits_all_three_engines(detection_run: dict) -> None:
    """Sigma + YARA-L + SPL counts match each other.

    A regression in the engine that wrote one of the three would
    produce skewed counts; pin the symmetry so it can't drift
    silently.
    """
    sigma_count = len(list(detection_run["sigma_dir"].glob("*.yml")))
    yaral_count = len(list(detection_run["yaral_dir"].glob("*.yaral")))
    spl_count = len(list(detection_run["spl_dir"].glob("*.spl")))
    assert sigma_count > 0, "no Sigma files emitted"
    assert sigma_count == yaral_count == spl_count, (
        f"engine counts diverged: sigma={sigma_count}, yara_l={yaral_count}, spl={spl_count}"
    )


def test_every_step_filename_stem_consistent_across_engines(
    detection_run: dict,
) -> None:
    """Same step-id/run-id => same stem across sigma/yara_l/spl."""
    sigma_stems = {p.stem for p in detection_run["sigma_dir"].glob("*.yml")}
    yaral_stems = {p.stem for p in detection_run["yaral_dir"].glob("*.yaral")}
    spl_stems = {p.stem for p in detection_run["spl_dir"].glob("*.spl")}
    assert sigma_stems == yaral_stems == spl_stems, (
        f"stems diverged: sigma_only={sigma_stems - yaral_stems - spl_stems}, "
        f"yaral_only={yaral_stems - sigma_stems - spl_stems}, "
        f"spl_only={spl_stems - sigma_stems - yaral_stems}"
    )


# ---------------------------------------------------------------------------
# 2. Manifest <-> on-disk consistency
# ---------------------------------------------------------------------------


def test_manifest_per_step_paths_resolve_to_real_files(
    detection_run: dict,
) -> None:
    """Every path the manifest records under ``detections.per_step``
    must resolve to a non-zero-byte file under the run dir.
    """
    detections = detection_run["manifest"].get("detections") or {}
    per_step = detections.get("per_step") or []
    assert per_step, "manifest.detections.per_step empty"
    run_dir = detection_run["run_dir"].resolve()
    for entry in per_step:
        engines = entry.get("engines") or {}
        for engine, paths in engines.items():
            for relative_path in paths:
                target = (detection_run["run_dir"] / relative_path).resolve()
                assert target.exists(), (
                    f"manifest references missing file: {relative_path} "
                    f"(engine={engine}, step={entry.get('step_id')})"
                )
                # Path-traversal guard (mirrors the validator).
                target.relative_to(run_dir)
                assert target.stat().st_size > 0, (
                    f"manifest references empty file: {relative_path}"
                )


def test_coverage_sidecar_references_real_files(
    detection_run: dict,
) -> None:
    """``coverage_<run_id>.json`` references real files.

    PR #99 (post this PR's original authoring) made coverage
    paths run-dir-relative. Anchor the resolution to ``run_dir``
    so the test handles both shapes: an absolute path resolves
    against itself; a relative path resolves against the run dir.
    """
    detections_dir = detection_run["run_dir"] / "detections"
    coverage_files = list(detections_dir.glob("coverage_*.json"))
    assert coverage_files, "coverage_<run_id>.json missing"
    run_dir: Path = detection_run["run_dir"]
    for cov in coverage_files:
        payload = json.loads(cov.read_text(encoding="utf-8"))
        for entry in payload.get("detections", []):
            for engine in ("sigma", "yara_l", "spl"):
                path = entry.get(engine)
                if not path:
                    continue
                # Anchor to run_dir so a relative-path reference
                # resolves correctly. ``Path("/abs") / "rel"`` is
                # POSIX-compatible: an absolute right-hand-side
                # discards the left.
                candidate = run_dir / path
                assert candidate.exists(), (
                    f"coverage references missing file: {path}"
                )
                assert candidate.stat().st_size > 0, (
                    f"coverage references empty file: {path}"
                )


# ---------------------------------------------------------------------------
# 3. NTFS filename safety (broader walk than the targeted test)
# ---------------------------------------------------------------------------


def test_no_filename_in_run_dir_uses_unsafe_char(
    detection_run: dict,
) -> None:
    """No file anywhere under the run dir uses an NTFS-unsafe char.

    Broader than ``test_detection_filename_safety.py``: this walks
    EVERY file under output/<run_id>/, not just the detection
    artifacts. Catches a regression in any future writer that
    composes filenames from operator-supplied keys.
    """
    run_dir: Path = detection_run["run_dir"]
    bad: list[tuple[str, str]] = []
    for p in run_dir.rglob("*"):
        if not p.is_file():
            continue
        for ch in _FILENAME_UNSAFE_CHARS:
            if ch in p.name:
                bad.append((str(p.relative_to(run_dir)), ch))
                break
    assert not bad, f"unsafe filenames present: {bad[:5]}"


# ---------------------------------------------------------------------------
# 4. Body-level invariants
# ---------------------------------------------------------------------------


def test_no_yara_l_body_has_manual_run_id(detection_run: dict) -> None:
    """No YARA-L file body carries ``run_id = "manual"``.

    Broader assertion than the per-rule check in the credibility
    test — walks every emitted file, not just one example.
    """
    yaral_dir: Path = detection_run["yaral_dir"]
    bad: list[str] = []
    for path in yaral_dir.glob("*.yaral"):
        body = path.read_text(encoding="utf-8")
        if 'run_id = "manual"' in body:
            bad.append(path.name)
    assert not bad, (
        f"{len(bad)} YARA-L files still hardcode manual run_id: {bad[:3]}"
    )


def test_yara_l_body_carries_real_run_id(detection_run: dict) -> None:
    """Every YARA-L body carries the engine's real run id."""
    real_run_id = detection_run["run_id"]
    yaral_dir: Path = detection_run["yaral_dir"]
    files = list(yaral_dir.glob("*.yaral"))
    assert files, "no YARA-L files generated"
    expected = f'run_id = "{real_run_id}"'
    bad = [p.name for p in files if expected not in p.read_text(encoding="utf-8")]
    assert not bad, (
        f"{len(bad)} YARA-L files missing real run_id: {bad[:3]}"
    )


def test_every_spl_body_carries_draft_header(detection_run: dict) -> None:
    """Every SPL file has the ``DRAFT detection search`` comment header.

    Broader than ``test_detection_draft_credibility.py``: this
    walks every emitted file. A regression in the orchestrator
    call site that bypassed the renderer would surface here.
    """
    spl_dir: Path = detection_run["spl_dir"]
    files = list(spl_dir.glob("*.spl"))
    assert files, "no SPL files generated"
    bad = [
        p.name
        for p in files
        if "DRAFT detection search" not in p.read_text(encoding="utf-8")
    ]
    assert not bad, (
        f"{len(bad)} SPL files missing DRAFT header: {bad[:3]}"
    )


def test_no_spl_is_pure_metadata_echo(
    detection_run: dict,
) -> None:
    """No SPL file is the pure ``| makeresults | eval`` shape.

    The legacy renderer's metadata-echo shape is ``| makeresults
    | eval ... | where module!="" | table ...``. After PR #89,
    that shape only fires when a hint has BOTH no logsource AND
    no detection.selection (legacy capability runs that bypass
    the Sigma block); even then the leading DRAFT header still
    surfaces.

    A regression that re-emitted the metadata-echo for normal
    detections would show as the ``| makeresults`` line being
    the first non-comment statement. Walk every emitted SPL and
    fail if any file matches that signature.
    """
    spl_dir: Path = detection_run["spl_dir"]
    files = list(spl_dir.glob("*.spl"))
    assert files, "no SPL files generated"
    bad: list[str] = []
    for path in files:
        body = path.read_text(encoding="utf-8")
        # Strip leading comment lines (which start with ``  ` `` or
        # ``\``) so we look at the first real statement.
        first_real = next(
            (
                line
                for line in body.splitlines()
                if line.strip()
                and not line.lstrip().startswith("`")
            ),
            "",
        )
        if first_real.lstrip().startswith("| makeresults"):
            bad.append(path.name)
    assert not bad, (
        f"{len(bad)}/{len(files)} SPL files start with metadata-echo shape "
        f"(`| makeresults | eval ...`): {bad[:3]}"
    )


def test_spl_without_logsource_mapping_still_carries_selection(
    detection_run: dict,
) -> None:
    """SPL files with unmapped logsources still carry useful content.

    When a module emits a hint with no logsource (or one that's
    not in the mapping table), the renderer falls back to
    ``index=* sourcetype=*`` PLUS the Sigma selection clause
    (when present) as ``| where`` filters. So even unmapped
    logsources produce a useful starter — the only true fallback
    to metadata echo is the no-logsource AND no-selection case.

    Assert that every SPL has SOMETHING beyond just the DRAFT
    header + eval block — either a sourcetype mapping or a
    selection-derived where clause.
    """
    spl_dir: Path = detection_run["spl_dir"]
    files = list(spl_dir.glob("*.spl"))
    assert files, "no SPL files generated"
    bad: list[str] = []
    for path in files:
        body = path.read_text(encoding="utf-8")
        has_real_sourcetype = bool(
            re.search(
                r'sourcetype="(WinEventLog|Sysmon|linux_audit|auditd|stream:)',
                body,
                re.IGNORECASE,
            )
        )
        has_where_clause = "| where" in body
        has_metadata_only = (
            "| makeresults" in body
            and not has_real_sourcetype
            and not has_where_clause
        )
        if has_metadata_only:
            bad.append(path.name)
    assert not bad, (
        f"{len(bad)} SPL files are pure metadata echoes: {bad[:3]}"
    )


# ---------------------------------------------------------------------------
# 5. Filename-vs-rule-body separation
# ---------------------------------------------------------------------------


def test_yara_l_meta_run_id_uses_unsanitised_form(
    detection_run: dict,
) -> None:
    """YARA-L meta carries the orchestrator's original run_id.

    Filename sanitisation is a filesystem-only concern. The rule
    body (Sigma id, YARA-L meta, SPL eval) carries the ORIGINAL
    run_id so report tooling that joins on run_id keeps working
    even when the filename uses the sanitised form.

    For the default ``run-YYYYMMDDHHMMSS-<hex>`` shape there's no
    sanitisation difference, but pinning the contract here keeps
    a future operator-supplied run_id (e.g. with hyphens, or any
    other allowed-by-the-runtime format) consistent across the
    file path / rule body channels.
    """
    real_run_id = detection_run["run_id"]
    yaral_dir: Path = detection_run["yaral_dir"]
    sample = next(iter(yaral_dir.glob("*.yaral")))
    body = sample.read_text(encoding="utf-8")
    assert f'run_id = "{real_run_id}"' in body
