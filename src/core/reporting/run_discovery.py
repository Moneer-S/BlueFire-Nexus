"""Helpers for discovering existing runs in an output root.

The CLI's ``list-runs`` / ``latest-run`` / ``show-run`` commands
all need to enumerate the run subdirectories under
``general.output_root`` (or ``BLUEFIRE_OUTPUT_ROOT``), surface
their high-level metadata (scenario name, start time, status),
and pick the most recent one. Centralising the logic here keeps
the CLI thin and gives the helpers focused tests.

Local-only: no network calls, no remote URLs. The helpers read
``manifest.json`` (the canonical run index from PR #71) when
present, and fall back to filesystem stat for runs that do not
yet have a manifest.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


# The orchestrator names runs ``run-YYYYMMDDHHMMSS-<short-uuid>``.
# We do not pin the exact format here — any directory under the
# output root that contains scenario-style artifacts counts.


def _is_run_dir(path: Path) -> bool:
    """Return True when ``path`` looks like a BlueFire run directory.

    Heuristic: a directory containing at least one of the
    canonical artifacts (``manifest.json``, ``report.md``,
    ``report.json``, ``risk_summary.json``,
    ``telemetry.jsonl``). This tolerates partial runs (e.g.
    a scenario that errored before the manifest was written) so
    the CLI can still surface them.
    """
    if not path.is_dir():
        return False
    canonical_files = (
        "manifest.json",
        "report.md",
        "report.json",
        "risk_summary.json",
        "telemetry.jsonl",
    )
    for name in canonical_files:
        if (path / name).exists():
            return True
    return False


def _read_manifest(run_dir: Path) -> Optional[Dict[str, Any]]:
    """Best-effort load of ``run_dir/manifest.json``.

    Returns ``None`` when the manifest is missing, unreadable, or
    not valid JSON. The CLI then falls back to filesystem stat
    for the metadata.
    """
    manifest_path = run_dir / "manifest.json"
    if not manifest_path.exists():
        return None
    try:
        return json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _stat_started_at(run_dir: Path) -> Optional[str]:
    """Filesystem-based fallback for "when did this run start"."""
    try:
        ctime = run_dir.stat().st_ctime
    except OSError:
        return None
    return datetime.fromtimestamp(ctime, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def list_runs(output_root: Path) -> List[Dict[str, Any]]:
    """Enumerate runs under ``output_root``.

    Returns a list of dicts with stable keys:
    ``run_id`` (str), ``run_dir`` (str), ``scenario_name`` (str),
    ``overall_status`` (str), ``started_at`` (str | None),
    ``module_count`` (int), ``has_manifest`` (bool),
    ``has_viewer`` (bool).

    Sorted descending by ``started_at`` so the most recent run
    is first. Runs without a manifest fall back to filesystem
    ctime so they still order sensibly.
    """
    if not output_root.exists() or not output_root.is_dir():
        return []
    rows: List[Dict[str, Any]] = []
    for child in output_root.iterdir():
        if not _is_run_dir(child):
            continue
        manifest = _read_manifest(child)
        if isinstance(manifest, dict):
            run_block = manifest.get("run") if isinstance(manifest.get("run"), dict) else {}
            rows.append(
                {
                    "run_id": str(run_block.get("run_id") or child.name),
                    "run_dir": str(child),
                    "scenario_name": str(run_block.get("scenario_name") or ""),
                    "overall_status": str(run_block.get("overall_status") or ""),
                    "started_at": run_block.get("started_at") or _stat_started_at(child),
                    "module_count": int(run_block.get("module_count") or 0),
                    "has_manifest": True,
                    "has_viewer": (child / "index.html").exists(),
                }
            )
        else:
            rows.append(
                {
                    "run_id": child.name,
                    "run_dir": str(child),
                    "scenario_name": "",
                    "overall_status": "",
                    "started_at": _stat_started_at(child),
                    "module_count": 0,
                    "has_manifest": False,
                    "has_viewer": (child / "index.html").exists(),
                }
            )
    # Sort descending by started_at; runs without a timestamp fall to
    # the bottom (None compares less-than every string when reversed).
    rows.sort(
        key=lambda row: (row.get("started_at") or ""),
        reverse=True,
    )
    return rows


def latest_run(output_root: Path) -> Optional[Dict[str, Any]]:
    """Return the most recent run dict, or ``None`` when no runs exist."""
    runs = list_runs(output_root)
    return runs[0] if runs else None


def find_run_dir(output_root: Path, run_id: str) -> Optional[Path]:
    """Resolve a ``run_id`` to a run directory under ``output_root``.

    Matches first by directory name, then by manifest's
    ``run.run_id`` field (since the directory name may be a
    sanitised form). Returns ``None`` when no match is found.
    """
    candidate = output_root / run_id
    if candidate.exists() and _is_run_dir(candidate):
        return candidate
    # Fall back to scanning manifests when the directory name does
    # not equal the run_id field.
    for run in list_runs(output_root):
        if run["run_id"] == run_id:
            return Path(run["run_dir"])
    return None


__all__ = [
    "find_run_dir",
    "latest_run",
    "list_runs",
]
