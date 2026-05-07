"""Demo bundle validation — broken-link gate + cross-scenario coverage.

Companion to ``test_enterprise_chain_showcase.py``. The showcase
test pins shape against the flagship scenario; this file adds
two cross-cutting validators:

1. **No broken `<a href="...">` links in any rendered viewer.**
   Walks every link in ``output/<run_id>/index.html`` and asserts
   each one resolves to a real file or directory under
   ``run_dir``. Catches regressions where the manifest references
   an artifact that the viewer links but the writer never
   actually produced.

2. **The same broken-link contract holds for the default
   quickstart profile (``apt29_credential_access``).** Defends
   the README's first command — a fresh-clone operator must not
   see a broken link in the very first dashboard they open.

3. **No external URL or absolute filesystem path** appears in
   any ``href=`` attribute. The viewer is local-only by design;
   absolute paths would leak operator environment, and
   ``http(s)://`` would break the no-network contract.

These are gate-style tests: a regression that introduces a
broken or external link surfaces here at PR time, before any
operator hits it in the demo.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, List, Set

import pytest

from src.core.bluefire_nexus import BlueFireNexus
from src.core.config import ConfigManager


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


# Plain-HTML href extraction. Matches both single- and double-
# quoted hrefs. The viewer never emits unquoted hrefs but we
# tolerate both for safety.
_HREF_RE = re.compile(r'<a\s+[^>]*href=["\']([^"\']*)["\'][^>]*>', re.IGNORECASE)
# Schemes that signal a remote / non-local link. ``mailto:`` and
# ``tel:`` are also non-local but the viewer does not emit them
# either; ``data:`` / ``javascript:`` are blocked separately.
_REMOTE_SCHEMES = ("http://", "https://", "ftp://", "ws://", "wss://", "mailto:", "tel:")


def _extract_hrefs(html: str) -> List[str]:
    """Return every ``href`` value that appears inside ``<a ...>`` tags."""
    return _HREF_RE.findall(html)


def _run_scenario(
    tmp_path: Path, *, scenario_path: str
) -> Path:
    """Run a scenario in an isolated output root and return its run dir."""
    cfg_path = tmp_path / "config.yaml"
    cfg = ConfigManager(str(cfg_path))
    cfg.set("general.output_root", str(tmp_path / "output"))
    cfg.save()
    nexus = BlueFireNexus(str(cfg_path))
    summary = nexus.run_scenario_file(scenario_path)
    assert summary.get("status") in {"success", "partial_success"}, summary
    return Path(summary["output_dir"])


# ---------------------------------------------------------------------------
# 1. No broken links in the flagship scenario's viewer
# ---------------------------------------------------------------------------


def test_enterprise_chain_viewer_has_no_broken_artifact_links(
    tmp_path: Path,
) -> None:
    """Every <a href> in the flagship viewer resolves to a real file/dir.

    The viewer is opened with ``file://`` so a broken link is a
    direct demo regression. This test walks every <a href> and
    fails with the offending links listed if any do not exist.
    """
    run_dir = _run_scenario(
        tmp_path,
        scenario_path="scenarios/enterprise_intrusion_chain.yaml",
    )
    viewer = run_dir / "index.html"
    assert viewer.exists(), "viewer was not generated"
    html = viewer.read_text(encoding="utf-8")

    hrefs = _extract_hrefs(html)
    assert hrefs, "viewer should contain at least one <a href>"

    broken: List[str] = []
    for href in hrefs:
        # Skip in-page anchors (none today, but defensive).
        if href.startswith("#") or not href:
            continue
        target = (run_dir / href).resolve()
        if not target.exists():
            broken.append(f"{href} -> {target}")

    assert broken == [], f"broken links in flagship viewer: {broken}"


# ---------------------------------------------------------------------------
# 2. Same gate for the README quickstart profile
# ---------------------------------------------------------------------------


def test_apt29_quickstart_viewer_has_no_broken_artifact_links(
    tmp_path: Path,
) -> None:
    """The README's quickstart profile produces a viewer with no broken links."""
    run_dir = _run_scenario(
        tmp_path, scenario_path="scenarios/apt29_credential_access.yaml"
    )
    viewer = run_dir / "index.html"
    assert viewer.exists()
    html = viewer.read_text(encoding="utf-8")

    hrefs = _extract_hrefs(html)
    assert hrefs

    broken: List[str] = []
    for href in hrefs:
        if href.startswith("#") or not href:
            continue
        target = (run_dir / href).resolve()
        if not target.exists():
            broken.append(f"{href} -> {target}")
    assert broken == [], f"broken links in apt29 quickstart viewer: {broken}"


# ---------------------------------------------------------------------------
# 3. No href points to a remote scheme
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "scenario_path",
    [
        "scenarios/enterprise_intrusion_chain.yaml",
        "scenarios/apt29_credential_access.yaml",
    ],
)
def test_viewer_hrefs_have_no_external_scheme(
    tmp_path: Path, scenario_path: str
) -> None:
    """Every <a href> stays local — no http(s)/ftp/ws/mailto/tel links.

    Defends the local-only contract at the link-extraction layer:
    even if someone adds a section that injects a URL into the
    rendered HTML, the test catches it.
    """
    run_dir = _run_scenario(tmp_path, scenario_path=scenario_path)
    html = (run_dir / "index.html").read_text(encoding="utf-8")
    offenders: List[str] = []
    for href in _extract_hrefs(html):
        for scheme in _REMOTE_SCHEMES:
            if href.lower().startswith(scheme):
                offenders.append(href)
                break
    assert offenders == [], (
        f"viewer rendered hrefs with remote schemes: {offenders}"
    )


# ---------------------------------------------------------------------------
# 4. No href is an absolute filesystem path
# ---------------------------------------------------------------------------


def _looks_absolute(href: str) -> bool:
    """Heuristic: POSIX absolute starts with '/'; Windows starts with '<letter>:\\\\'."""
    if href.startswith("/"):
        return True
    if len(href) >= 3 and href[1] == ":" and href[2] in ("\\", "/"):
        # e.g. C:\Users\... or C:/Users/...
        return True
    return False


@pytest.mark.parametrize(
    "scenario_path",
    [
        "scenarios/enterprise_intrusion_chain.yaml",
        "scenarios/apt29_credential_access.yaml",
    ],
)
def test_viewer_hrefs_have_no_absolute_paths(
    tmp_path: Path, scenario_path: str
) -> None:
    """No <a href> embeds an absolute filesystem path.

    Absolute paths leak operator environment (home dirs, mount
    points) and break when the run directory is moved. Every
    artifact link must be run-dir-relative.
    """
    run_dir = _run_scenario(tmp_path, scenario_path=scenario_path)
    html = (run_dir / "index.html").read_text(encoding="utf-8")
    offenders: List[str] = []
    for href in _extract_hrefs(html):
        if _looks_absolute(href):
            offenders.append(href)
    assert offenders == [], (
        f"viewer rendered hrefs with absolute filesystem paths: {offenders}"
    )


# ---------------------------------------------------------------------------
# 5. Empty / missing href values are not emitted
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "scenario_path",
    [
        "scenarios/enterprise_intrusion_chain.yaml",
        "scenarios/apt29_credential_access.yaml",
    ],
)
def test_viewer_emits_no_empty_hrefs(tmp_path: Path, scenario_path: str) -> None:
    """A href="" / href="#" by mistake would render an inert link.

    The viewer's "not present" rendering uses no ``<a>`` tag at
    all; missing artifacts surface as muted plain text. This test
    asserts the artifact-links section honours that contract.
    """
    run_dir = _run_scenario(tmp_path, scenario_path=scenario_path)
    html = (run_dir / "index.html").read_text(encoding="utf-8")
    for href in _extract_hrefs(html):
        assert href and href != "#", (
            f"viewer rendered an empty / placeholder href: {href!r}"
        )


# ---------------------------------------------------------------------------
# 6. Demo bundle completeness — the canonical artifact set
# ---------------------------------------------------------------------------


_REQUIRED_ARTIFACTS = (
    "manifest.json",
    "index.html",
    "report.md",
    "report.json",
    "risk_summary.json",
    "telemetry.jsonl",
)


@pytest.mark.parametrize(
    "scenario_path",
    [
        "scenarios/enterprise_intrusion_chain.yaml",
        "scenarios/apt29_credential_access.yaml",
    ],
)
def test_demo_bundle_includes_all_required_artifacts(
    tmp_path: Path, scenario_path: str
) -> None:
    """Both flagship demo scenarios produce every canonical artifact.

    The README's quickstart screenshot and the static viewer
    both rely on this set. A missing file would break the
    operator's first impression after a fresh clone.
    """
    run_dir = _run_scenario(tmp_path, scenario_path=scenario_path)
    missing = [a for a in _REQUIRED_ARTIFACTS if not (run_dir / a).exists()]
    assert missing == [], f"missing demo artifacts: {missing}"


# ---------------------------------------------------------------------------
# 7. Detection drafts directory is present when manifest claims drafts
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "scenario_path",
    [
        "scenarios/enterprise_intrusion_chain.yaml",
        "scenarios/apt29_credential_access.yaml",
    ],
)
def test_detection_drafts_directory_matches_manifest(
    tmp_path: Path, scenario_path: str
) -> None:
    """``detections/`` exists iff manifest claims at least one draft.

    Closes the "is the link real?" question for the detection
    artifact specifically: the viewer only renders a clickable
    link when ``manifest.detections.total > 0`` (per PR #76's
    sweep), and that link must point at a real directory.
    """
    import json as _json

    run_dir = _run_scenario(tmp_path, scenario_path=scenario_path)
    manifest = _json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    total = int((manifest.get("detections") or {}).get("total") or 0)
    detections_dir = run_dir / "detections"
    if total > 0:
        assert detections_dir.exists() and detections_dir.is_dir(), (
            f"manifest claims {total} detection drafts but {detections_dir} "
            "is missing"
        )
    # When total == 0, the detections dir may or may not exist;
    # the viewer's link gating handles both states.


# ---------------------------------------------------------------------------
# 8. validate_run_bundle helper + CLI command
# ---------------------------------------------------------------------------


from src.core.reporting.run_discovery import validate_run_bundle  # noqa: E402


def test_validate_run_bundle_returns_ok_for_complete_flagship_run(
    tmp_path: Path,
) -> None:
    """A successful flagship run validates as ``ok`` with no issues."""
    run_dir = _run_scenario(
        tmp_path, scenario_path="scenarios/enterprise_intrusion_chain.yaml"
    )
    report = validate_run_bundle(run_dir)
    assert report["ok"] is True, report
    assert report["missing"] == []
    assert report["broken_links"] == []


def test_validate_run_bundle_flags_missing_required_artifact(
    tmp_path: Path,
) -> None:
    """Deleting a required artifact flips the validator to fail."""
    run_dir = _run_scenario(
        tmp_path, scenario_path="scenarios/enterprise_intrusion_chain.yaml"
    )
    (run_dir / "report.md").unlink()
    report = validate_run_bundle(run_dir)
    assert report["ok"] is False
    assert "report.md" in report["missing"]


def test_validate_run_bundle_returns_structured_report_for_missing_dir(
    tmp_path: Path,
) -> None:
    """Non-existent run dir yields a populated report rather than crashing."""
    fake = tmp_path / "no-such-run"
    report = validate_run_bundle(fake)
    assert report["ok"] is False
    assert sorted(report["missing"]) == sorted(
        ["manifest.json", "index.html", "report.md", "report.json",
         "risk_summary.json", "telemetry.jsonl"]
    )
    assert any("does not exist" in w for w in report["warnings"])


def test_cli_validate_run_succeeds_on_clean_run(tmp_path: Path) -> None:
    """The new ``validate-run`` CLI command returns 0 on a clean run."""
    from typer.testing import CliRunner
    from src.core.cli import app

    run_dir = _run_scenario(
        tmp_path, scenario_path="scenarios/enterprise_intrusion_chain.yaml"
    )
    output_root = run_dir.parent
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["validate-run", run_dir.name, "--output-root", str(output_root)],
        env={"COLUMNS": "200"},
    )
    assert result.exit_code == 0, result.stdout
    assert "OK" in result.stdout


def test_cli_validate_run_fails_with_exit_code_when_artifact_missing(
    tmp_path: Path,
) -> None:
    """A missing artifact triggers a non-zero exit so CI scripts can gate on it."""
    from typer.testing import CliRunner
    from src.core.cli import app

    run_dir = _run_scenario(
        tmp_path, scenario_path="scenarios/enterprise_intrusion_chain.yaml"
    )
    (run_dir / "telemetry.jsonl").unlink()
    output_root = run_dir.parent
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["validate-run", run_dir.name, "--output-root", str(output_root)],
        env={"COLUMNS": "200"},
    )
    assert result.exit_code != 0
    assert "FAIL" in result.stdout
    assert "telemetry.jsonl" in result.stdout


def test_cli_validate_run_supports_json_output(tmp_path: Path) -> None:
    """``--json`` prints a parseable validation report."""
    import json as _json
    from typer.testing import CliRunner
    from src.core.cli import app

    run_dir = _run_scenario(
        tmp_path, scenario_path="scenarios/enterprise_intrusion_chain.yaml"
    )
    output_root = run_dir.parent
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["validate-run", run_dir.name, "--output-root", str(output_root), "--json"],
        env={"COLUMNS": "200"},
    )
    assert result.exit_code == 0, result.stdout
    # Rich's print_json wraps the JSON in syntax highlighting via
    # ANSI codes when colour is on, but the test runs without
    # a tty so the output should be plain JSON. Strip any minor
    # surrounding whitespace and parse.
    payload = _json.loads(result.stdout.strip())
    assert payload["ok"] is True
    assert payload["missing"] == []
    assert payload["broken_links"] == []
