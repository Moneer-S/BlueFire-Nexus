"""Codex/Bugbot sweep regression tests for the viewer batch (PRs #71-#75).

Three real findings, all fixed in this sweep:

1. **P1 (PR #73)** — `find_run_dir` accepted absolute paths and
   `..` segments. ``show-run`` / ``build-report-view`` could
   read or write outside the configured output root when given
   inputs like ``/tmp/run`` or ``../escape``. The fix rejects
   path-shaped run_ids and verifies the resolved match is a
   descendant of the output root.

2. **P2 (PR #71)** — ``execute_operation`` and
   ``run_scenario_file`` returned ``manifest_path`` /
   ``viewer_path`` strings even when the underlying writes
   raised ``OSError``. Downstream consumers got a path to a file
   that did not exist, turning a handled I/O hiccup into a
   later, harder-to-diagnose failure. The fix returns ``None``
   for either path when the corresponding write did not
   succeed.

3. **P2 (PR #72)** — ``_render_artifact_links`` hardcoded
   ``detections/`` and ``manifest.json`` as present. Runs that
   never generated detection drafts (e.g. non-success
   ``execute_operation`` calls) rendered a clickable link to a
   missing directory. The fix consults the manifest's actual
   ``detections.total`` and ``schema_version`` before linking.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict
from unittest.mock import patch

import pytest

from src.core.bluefire_nexus import BlueFireNexus
from src.core.config import ConfigManager
from src.core.reporting.manifest import build_manifest
from src.core.reporting.run_discovery import find_run_dir
from src.core.reporting.viewer import render_html


# ---------------------------------------------------------------------------
# 1. Path-traversal guard in find_run_dir (Codex P1 from PR #73)
# ---------------------------------------------------------------------------


def _make_real_run(output_root: Path, run_id: str) -> Path:
    """Create a tiny run directory that ``_is_run_dir`` accepts."""
    run_dir = output_root / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "report.md").write_text("# r", encoding="utf-8")
    return run_dir


def test_find_run_dir_rejects_parent_directory_traversal(tmp_path: Path) -> None:
    """A ``run_id`` of ``..`` must not escape the output root.

    Even when a sibling directory of the output root happens to
    look like a run directory, ``find_run_dir`` must refuse the
    request so ``show-run`` / ``build-report-view`` cannot reach
    files outside the configured root.
    """
    output_root = tmp_path / "output"
    output_root.mkdir()
    # Sibling directory that LOOKS like a run dir.
    sibling = tmp_path / "evil"
    sibling.mkdir()
    (sibling / "report.md").write_text("# r", encoding="utf-8")
    # Naive resolution would pick this up via ``output_root / "../evil"``.
    assert find_run_dir(output_root, "../evil") is None


def test_find_run_dir_rejects_dotdot_only(tmp_path: Path) -> None:
    """``run_id`` of literally ``..`` is explicitly rejected."""
    output_root = tmp_path / "output"
    output_root.mkdir()
    assert find_run_dir(output_root, "..") is None
    assert find_run_dir(output_root, ".") is None


def test_find_run_dir_rejects_absolute_path(tmp_path: Path) -> None:
    """An absolute-path ``run_id`` is rejected before reaching the FS."""
    output_root = tmp_path / "output"
    output_root.mkdir()
    other = tmp_path / "other"
    other.mkdir()
    (other / "report.md").write_text("# r", encoding="utf-8")
    # On Windows ``str(other)`` includes the drive letter; on POSIX
    # it starts with ``/``. Both shapes contain a path separator,
    # which is the rejection signal.
    assert find_run_dir(output_root, str(other)) is None


@pytest.mark.parametrize(
    "evil_id",
    [
        "/etc/passwd",
        "..\\\\other-run",
        "../other-run",
        "..\\other-run",
        "subdir/run-123",
        "subdir\\run-123",
    ],
)
def test_find_run_dir_rejects_any_path_separator(
    tmp_path: Path, evil_id: str
) -> None:
    """Any forward / backward path separator in run_id is rejected."""
    output_root = tmp_path / "output"
    output_root.mkdir()
    assert find_run_dir(output_root, evil_id) is None


def test_find_run_dir_still_resolves_legitimate_run_ids(tmp_path: Path) -> None:
    """Defence-in-depth: the guard does NOT break the happy path."""
    output_root = tmp_path / "output"
    _make_real_run(output_root, "run-2026-05-07")
    found = find_run_dir(output_root, "run-2026-05-07")
    assert found is not None
    assert found.name == "run-2026-05-07"


def test_find_run_dir_rejects_empty_run_id(tmp_path: Path) -> None:
    output_root = tmp_path / "output"
    output_root.mkdir()
    assert find_run_dir(output_root, "") is None


# ---------------------------------------------------------------------------
# 2. manifest_path / viewer_path only set on successful write (Codex P2 from #71)
# ---------------------------------------------------------------------------


def test_manifest_path_is_none_when_manifest_write_fails(tmp_path: Path) -> None:
    """If the manifest write raises OSError, the result dict's
    ``manifest_path`` is ``None`` rather than pointing at a file
    that does not exist.

    Patches ``write_run_manifest`` at the call site so we don't
    have to actually fail a real disk write.
    """
    cfg_path = tmp_path / "config.yaml"
    cfg = ConfigManager(str(cfg_path))
    cfg.set("general.output_root", str(tmp_path / "output"))
    cfg.save()
    nexus = BlueFireNexus(str(cfg_path))
    with patch(
        "src.core.bluefire_nexus.write_run_manifest",
        side_effect=OSError("simulated disk-full"),
    ):
        summary = nexus.run_scenario_file(
            "scenarios/enterprise_intrusion_chain.yaml"
        )
    # Result dict surfaces None instead of a stale path.
    assert summary.get("manifest_path") is None
    # Viewer also skipped (it depends on the manifest).
    assert summary.get("viewer_path") is None


def test_viewer_path_is_none_when_viewer_write_fails(tmp_path: Path) -> None:
    """If the viewer write raises but the manifest succeeded, the
    manifest_path stays valid and the viewer_path becomes None.
    """
    cfg_path = tmp_path / "config.yaml"
    cfg = ConfigManager(str(cfg_path))
    cfg.set("general.output_root", str(tmp_path / "output"))
    cfg.save()
    nexus = BlueFireNexus(str(cfg_path))
    with patch(
        "src.core.bluefire_nexus.write_viewer_for_run",
        side_effect=OSError("simulated viewer write failure"),
    ):
        summary = nexus.run_scenario_file(
            "scenarios/enterprise_intrusion_chain.yaml"
        )
    # Manifest succeeded => path present.
    assert summary.get("manifest_path") is not None
    assert Path(summary["manifest_path"]).exists()
    # Viewer failed => path is None.
    assert summary.get("viewer_path") is None


def test_manifest_path_present_on_happy_path_e2e(tmp_path: Path) -> None:
    """Sanity: the happy path still surfaces both keys when both writes succeed."""
    cfg_path = tmp_path / "config.yaml"
    cfg = ConfigManager(str(cfg_path))
    cfg.set("general.output_root", str(tmp_path / "output"))
    cfg.save()
    nexus = BlueFireNexus(str(cfg_path))
    summary = nexus.run_scenario_file(
        "scenarios/enterprise_intrusion_chain.yaml"
    )
    assert summary.get("manifest_path")
    assert summary.get("viewer_path")
    assert Path(summary["manifest_path"]).exists()
    assert Path(summary["viewer_path"]).exists()


# ---------------------------------------------------------------------------
# 3. Detection artifact link reflects actual presence (Codex P2 from #72)
# ---------------------------------------------------------------------------


def test_artifact_links_marks_detections_not_present_when_total_is_zero(
    tmp_path: Path,
) -> None:
    """A manifest with ``detections.total == 0`` shows the
    detections row as "not present" rather than as a clickable
    link to a missing directory.

    Reproduces the prior bug: the previous renderer hardcoded
    "detections" as the path so every run rendered a clickable
    link regardless of whether any drafts were generated.
    """
    manifest = build_manifest(run_id="empty-detect", run_dir=tmp_path, steps=[])
    # Sanity precondition.
    assert manifest["detections"]["total"] == 0
    html = render_html(manifest)
    # The detections row appears as "not present" — no <a> tag
    # wrapping it.
    assert "detections/" in html
    assert "not present" in html
    # Specifically: there's no <a href="detections"> link.
    assert '<a href="detections"' not in html


def test_artifact_links_renders_detections_link_when_drafts_exist(
    tmp_path: Path,
) -> None:
    """When the run did emit detection drafts, the link is active."""
    steps = [
        {
            "step_id": "s",
            "module": "execution",
            "status": "success",
            "techniques": ["T1059"],
            "artifacts": {},
            "detections": {"sigma": ["detections/sigma/exec.yml"]},
        }
    ]
    # Create the actual file so the manifest's relative-path
    # rewriter resolves cleanly.
    (tmp_path / "detections" / "sigma").mkdir(parents=True)
    (tmp_path / "detections" / "sigma" / "exec.yml").write_text("title: x", encoding="utf-8")
    manifest = build_manifest(
        run_id="has-detect",
        run_dir=tmp_path,
        scenario_name="x",
        steps=steps,
    )
    assert manifest["detections"]["total"] >= 1
    html = render_html(manifest)
    # The artifact section's detections row is now an active link.
    assert '<a href="detections">' in html


def test_artifact_links_marks_manifest_not_present_when_schema_version_missing(
    tmp_path: Path,
) -> None:
    """Robustness: a manifest dict missing ``schema_version`` (a
    schema-broken input) renders the manifest row as "not
    present" rather than a clickable broken link.

    Defends the documented schema invariant: a real manifest
    always carries ``schema_version`` (set by ``build_manifest``).
    A renderer fed a hand-constructed dict without that field
    is signalling a problem; the row should reflect that.
    """
    html = render_html({})  # totally empty input
    assert "manifest.json" in html
    assert "not present" in html
    assert '<a href="manifest.json">' not in html
