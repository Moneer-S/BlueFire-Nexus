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


def _is_within(parent: Path, child: Path) -> bool:
    """Return True iff ``child`` resolves to a descendant of ``parent``.

    Handles ``..`` segments via :meth:`Path.resolve` so a ``run_id``
    of ``../escape`` cannot point outside the output root. Returns
    ``False`` when either path cannot be resolved (e.g. on a
    different drive on Windows).
    """
    try:
        parent_resolved = parent.resolve()
        child_resolved = child.resolve()
    except OSError:
        return False
    try:
        child_resolved.relative_to(parent_resolved)
    except ValueError:
        return False
    return True


def find_run_dir(output_root: Path, run_id: str) -> Optional[Path]:
    """Resolve a ``run_id`` to a run directory under ``output_root``.

    Matches first by directory name, then by manifest's
    ``run.run_id`` field (since the directory name may be a
    sanitised form). Returns ``None`` when no match is found OR
    when the requested ``run_id`` would resolve outside the
    output root.

    Path-traversal guard (Codex P1 from PR #73 sweep): a
    ``run_id`` like ``../other-run`` or an absolute path like
    ``/tmp/run`` previously slipped through ``output_root /
    run_id`` because :class:`pathlib.Path` does not constrain
    its joining behaviour. ``find_run_dir`` now rejects any
    path-shaped ``run_id`` (one that contains a path separator
    or that resolves outside the output root) before it ever
    reaches the filesystem. Manifest-keyed lookup still works
    for sanitised directory names.
    """
    # Reject anything that looks like a path. Run ids in this
    # project are short opaque strings (``run-<timestamp>-<hex>``);
    # a separator means the operator is trying to traverse.
    if not run_id or any(sep in run_id for sep in ("/", "\\")) or run_id in {"..", "."}:
        return None

    candidate = output_root / run_id
    if candidate.exists() and _is_run_dir(candidate) and _is_within(output_root, candidate):
        return candidate
    # Fall back to scanning manifests when the directory name does
    # not equal the run_id field. ``list_runs`` only enumerates
    # children of ``output_root`` so the match is implicitly
    # in-bounds; verify defensively anyway.
    for run in list_runs(output_root):
        if run["run_id"] == run_id:
            run_dir = Path(run["run_dir"])
            if _is_within(output_root, run_dir):
                return run_dir
    return None


_REQUIRED_DEMO_ARTIFACTS: tuple[str, ...] = (
    "manifest.json",
    "index.html",
    "report.md",
    "report.json",
    "risk_summary.json",
    "telemetry.jsonl",
)


def validate_run_bundle(run_dir: Path) -> Dict[str, Any]:
    """Return a structured validation report for a single run.

    Checks the run directory against the canonical demo bundle:
    every required artifact is present, the manifest's
    ``detections.total > 0`` implies a real ``detections/``
    directory, and (when ``index.html`` is present) every
    ``<a href>`` resolves to a real file or directory under the
    run dir.

    The return value is always a dict with stable keys
    (``run_dir`` / ``ok`` / ``missing`` / ``broken_links`` /
    ``warnings``) so the CLI / operator scripts can rely on the
    shape regardless of which checks pass or fail. ``ok`` is
    True only when ``missing`` is empty AND ``broken_links`` is
    empty.

    Local-only: the function reads files under ``run_dir`` and
    never touches the network.
    """
    import json as _json
    import re as _re

    report: Dict[str, Any] = {
        "run_dir": str(run_dir),
        "ok": False,
        "missing": [],
        "broken_links": [],
        "warnings": [],
    }
    if not run_dir.exists() or not run_dir.is_dir():
        report["missing"] = list(_REQUIRED_DEMO_ARTIFACTS)
        report["warnings"].append(f"run directory does not exist: {run_dir}")
        return report

    missing = [
        name for name in _REQUIRED_DEMO_ARTIFACTS if not (run_dir / name).exists()
    ]
    report["missing"] = missing

    # Detection-directory cross-check against the manifest.
    manifest_path = run_dir / "manifest.json"
    if manifest_path.exists():
        try:
            manifest = _json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, _json.JSONDecodeError) as exc:
            report["warnings"].append(f"manifest unreadable: {exc}")
            manifest = {}
        if isinstance(manifest, dict):
            detections = manifest.get("detections") or {}
            total = int(detections.get("total") or 0)
            detections_dir = run_dir / "detections"
            if total > 0 and not detections_dir.is_dir():
                report["warnings"].append(
                    f"manifest claims {total} detection drafts but "
                    f"{detections_dir} is missing"
                )

    # Walk every <a href> in index.html and confirm it resolves
    # to a real path UNDER run_dir. Pure regex extraction so the
    # viewer module does not need to import any HTML parser.
    #
    # Closes the Codex P1 from PR #80 sweep: the previous
    # implementation accepted any href whose resolved path
    # existed on the filesystem, including ``../shared/...`` or
    # absolute paths outside the bundle. ``validate-run`` could
    # therefore return ok=True even when the bundle was not
    # self-contained — moving the run dir to another machine
    # would then expose the broken links the validator missed.
    href_re = _re.compile(r'<a\s+[^>]*href=["\']([^"\']*)["\'][^>]*>', _re.IGNORECASE)
    viewer_path = run_dir / "index.html"
    if viewer_path.exists():
        try:
            html = viewer_path.read_text(encoding="utf-8")
        except OSError as exc:
            report["warnings"].append(f"viewer unreadable: {exc}")
            html = ""
        broken: List[str] = []
        run_dir_resolved = run_dir.resolve()
        for href in href_re.findall(html):
            if not href or href.startswith("#"):
                continue
            target = (run_dir / href).resolve()
            # Must exist AND must sit under the run dir. Either
            # condition failing makes the link broken from the
            # bundle's perspective.
            if not target.exists():
                broken.append(href)
                continue
            try:
                target.relative_to(run_dir_resolved)
            except ValueError:
                broken.append(href)
        report["broken_links"] = broken

    report["ok"] = not missing and not report["broken_links"]
    return report


__all__ = [
    "find_run_dir",
    "latest_run",
    "list_runs",
    "validate_run_bundle",
]
