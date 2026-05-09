"""``coverage_<run_id>.json`` must carry every step, not just the last.

The orchestrator calls :func:`write_detection_artifacts` once per
scenario step, passing a single-entry ``module_results`` dict each
time. Pre-#146 each call overwrote the prior
``coverage_<run_id>.json`` with a one-row summary built from JUST
that call's results — the file's name promised whole-run coverage but
the on-disk content only reflected the LAST step. A defender pulling
the bundle saw 12 step-shaped Sigma / YARA-L / SPL drafts on disk but
``coverage_<run_id>.json`` listed only the impact step.

PR #146 upserts per-step rows by ``module`` key (``"<module>:<step_id>"``
for scenario steps), so each per-step call appends the new row,
preserves the earlier ones, and a re-run of the same step replaces
its prior row in place.

Pinned invariants:

1. Multiple per-step calls accumulate into one cumulative file —
   every step's row survives.
2. Single-batch callers (operator paths that pass the full
   ``module_results`` in one call) keep the legacy whole-batch shape.
3. Re-running the same ``module:step_id`` upserts in place, not
   appending a duplicate.
4. Malformed prior files don't poison subsequent writes — the engine
   treats them as a fresh slate.
5. End-to-end via the showcase scenario: the on-disk
   ``coverage_<run_id>.json`` carries all 12 steps.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

from src.core.detections import write_detection_artifacts
from src.core.models import ModuleResult


def _result(module: str, technique: str, *, severity: str = "medium") -> ModuleResult:
    return ModuleResult(
        status="success",
        module=module,
        message="ok",
        techniques=[technique],
        artifacts={},
        detection_hints={
            "logsource": {"product": "windows", "category": "process_creation"},
            "detection": {
                "selection": {"Image|endswith": "x.exe"},
                "condition": "selection",
            },
            "risk_severity": severity,
        },
        telemetry=[],
    )


def _coverage_file(run_dir: Path, run_id: str) -> Path:
    return run_dir / "detections" / f"coverage_{run_id}.json"


def _read_rows(run_dir: Path, run_id: str) -> list:
    return json.loads(_coverage_file(run_dir, run_id).read_text(encoding="utf-8"))[
        "detections"
    ]


# ---------------------------------------------------------------------------
# 1. Per-step calls accumulate into one cumulative coverage file
# ---------------------------------------------------------------------------


def test_per_step_calls_accumulate_into_single_coverage_file(tmp_path: Path) -> None:
    """Three back-to-back single-step calls produce a 3-row coverage file."""
    run_id = "run-cumul-1"
    write_detection_artifacts(
        tmp_path, run_id, {"discovery:enumerate-files": _result("discovery", "T1083")}
    )
    write_detection_artifacts(
        tmp_path, run_id, {"execution:loader": _result("execution", "T1059")}
    )
    write_detection_artifacts(
        tmp_path,
        run_id,
        {"impact:ransomware": _result("impact", "T1486", severity="critical")},
    )
    rows = _read_rows(tmp_path, run_id)
    keys = [row["module"] for row in rows]
    # Every step survives — pre-#146 only the last step's row landed.
    assert "discovery:enumerate-files" in keys
    assert "execution:loader" in keys
    assert "impact:ransomware" in keys
    assert len(rows) == 3
    # Insertion order is preserved (chain story reads top-to-bottom).
    assert keys == [
        "discovery:enumerate-files",
        "execution:loader",
        "impact:ransomware",
    ]


def test_re_running_same_step_upserts_instead_of_duplicating(tmp_path: Path) -> None:
    """Second call for same ``module:step_id`` replaces in place.

    The engine derives ``risk_score`` / ``risk_severity`` from the
    canonical scoring helper applied to the ``ModuleResult``, so the
    upsert is observed by mutating something stored verbatim in the
    coverage row — here, the technique. First call records T1083;
    second call (same module key) records T1057. The cumulative file
    must end up with ONE row carrying T1057, not two rows or a
    stale T1083.
    """
    run_id = "run-upsert-1"
    write_detection_artifacts(
        tmp_path,
        run_id,
        {"discovery:enumerate-files": _result("discovery", "T1083")},
    )
    rows_first = _read_rows(tmp_path, run_id)
    assert rows_first[0]["technique"] == "T1083"
    # Re-run same step with a different technique — should upsert in place.
    write_detection_artifacts(
        tmp_path,
        run_id,
        {"discovery:enumerate-files": _result("discovery", "T1057")},
    )
    rows_second = _read_rows(tmp_path, run_id)
    # No duplicate row.
    assert len(rows_second) == 1
    # New technique wins.
    assert rows_second[0]["technique"] == "T1057"


def test_single_batch_call_keeps_legacy_whole_batch_shape(tmp_path: Path) -> None:
    """Operator paths passing all results in one call still produce one row per result.

    Backwards-compat: callers (tests, scripts) that already build a
    full ``module_results`` dict and call ``write_detection_artifacts``
    once must keep getting the legacy whole-batch coverage file
    shape.
    """
    run_id = "run-batch-1"
    results = {
        "discovery:s1": _result("discovery", "T1083"),
        "execution:s2": _result("execution", "T1059"),
        "impact:s3": _result("impact", "T1486", severity="critical"),
    }
    write_detection_artifacts(tmp_path, run_id, results)
    rows = _read_rows(tmp_path, run_id)
    assert len(rows) == 3
    # Insertion order preserved.
    assert [row["module"] for row in rows] == [
        "discovery:s1",
        "execution:s2",
        "impact:s3",
    ]


def test_per_step_then_batch_calls_dedup_existing_rows(tmp_path: Path) -> None:
    """A per-step call followed by a single-batch call dedups by module key.

    Pin that the second call replaces the prior s1 row in place
    (technique-mutated to demonstrate upsert) AND adds two new rows.
    """
    run_id = "run-dedup-1"
    # First: a single per-step call with technique T1083.
    write_detection_artifacts(
        tmp_path,
        run_id,
        {"discovery:s1": _result("discovery", "T1083")},
    )
    # Second: a batch call that REPLACES s1 with a different technique
    # AND adds two new rows.
    write_detection_artifacts(
        tmp_path,
        run_id,
        {
            "discovery:s1": _result("discovery", "T1057"),
            "execution:s2": _result("execution", "T1059"),
            "impact:s3": _result("impact", "T1486", severity="critical"),
        },
    )
    rows = _read_rows(tmp_path, run_id)
    assert len(rows) == 3
    by_module = {row["module"]: row for row in rows}
    # s1 was upserted from T1083 -> T1057.
    assert by_module["discovery:s1"]["technique"] == "T1057"
    assert by_module["execution:s2"]["technique"] == "T1059"
    assert by_module["impact:s3"]["technique"] == "T1486"


# ---------------------------------------------------------------------------
# 2. Robustness against prior-file corruption
# ---------------------------------------------------------------------------


def test_malformed_prior_coverage_file_treated_as_fresh_slate(tmp_path: Path) -> None:
    """A corrupted prior file shouldn't poison the new write."""
    run_id = "run-malformed-1"
    # Plant a corrupted file at the expected path.
    detections_dir = tmp_path / "detections"
    detections_dir.mkdir()
    (detections_dir / f"coverage_{run_id}.json").write_text(
        "{not valid json}{", encoding="utf-8"
    )
    # The engine should treat this as fresh slate and write the new
    # row without raising.
    write_detection_artifacts(
        tmp_path, run_id, {"discovery:s1": _result("discovery", "T1083")}
    )
    rows = _read_rows(tmp_path, run_id)
    assert len(rows) == 1
    assert rows[0]["module"] == "discovery:s1"


def test_unexpected_shape_in_prior_file_treated_as_fresh_slate(
    tmp_path: Path,
) -> None:
    """Prior file with the wrong top-level shape -> fresh slate."""
    run_id = "run-shape-1"
    detections_dir = tmp_path / "detections"
    detections_dir.mkdir()
    # ``detections`` key absent — file isn't a known shape.
    (detections_dir / f"coverage_{run_id}.json").write_text(
        json.dumps({"unrelated": ["x", "y"]}), encoding="utf-8"
    )
    write_detection_artifacts(
        tmp_path, run_id, {"discovery:s1": _result("discovery", "T1083")}
    )
    rows = _read_rows(tmp_path, run_id)
    assert len(rows) == 1


# ---------------------------------------------------------------------------
# 3. End-to-end via the showcase scenario
# ---------------------------------------------------------------------------


def test_showcase_scenario_run_emits_cumulative_coverage(tmp_path: Path) -> None:
    """Real run against the showcase yields a coverage file with every step.

    Pin the headline regression Codex would catch in real triage:
    pre-#146 the showcase produced ``sigma/`` with 12 rules but
    ``coverage_<run_id>.json`` listed only the impact step. After the
    upsert, both surfaces are consistent.
    """
    env = dict(os.environ)
    env["BLUEFIRE_OUTPUT_ROOT"] = str(tmp_path)
    proc = subprocess.run(
        [
            "python",
            "-m",
            "src.run_scenario",
            "--scenario-file",
            "scenarios/enterprise_intrusion_chain.yaml",
            "--output-json",
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    out = json.loads(proc.stdout)
    run_dir = tmp_path / out["run_id"]
    coverage = next((run_dir / "detections").glob("coverage_*.json"))
    rows = json.loads(coverage.read_text(encoding="utf-8"))["detections"]
    assert len(rows) == 12, [row.get("module") for row in rows]
    # Every step in the showcase backbone surfaces.
    keys = {row["module"] for row in rows}
    expected = {
        "resource_development:stage-infrastructure",
        "reconnaissance:target-recon",
        "initial_access:phish-delivery",
        "execution:loader-execution",
        "defense_evasion:masquerade",
        "discovery:enumerate-files",
        "credential_access:harvest-browser-creds",
        "lateral_movement:lateral-to-fileshare",
        "collection:stage-collected-data",
        "command_control:c2-channel",
        "exfiltration:exfil-over-c2",
        "impact:ransomware-impact",
    }
    assert keys == expected, keys ^ expected


def test_showcase_coverage_matches_sigma_file_count(tmp_path: Path) -> None:
    """Coverage row count == on-disk Sigma file count.

    Pin the surface invariant: if there are N Sigma rules on disk,
    the cumulative coverage file lists N rows. Otherwise the file is
    silently lying about the run's coverage.
    """
    env = dict(os.environ)
    env["BLUEFIRE_OUTPUT_ROOT"] = str(tmp_path)
    proc = subprocess.run(
        [
            "python",
            "-m",
            "src.run_scenario",
            "--scenario-file",
            "scenarios/enterprise_intrusion_chain.yaml",
            "--output-json",
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    out = json.loads(proc.stdout)
    run_dir = tmp_path / out["run_id"]
    sigma_count = len(list((run_dir / "detections" / "sigma").glob("*.yml")))
    coverage = next((run_dir / "detections").glob("coverage_*.json"))
    rows = json.loads(coverage.read_text(encoding="utf-8"))["detections"]
    assert len(rows) == sigma_count
