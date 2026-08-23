from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

UI_ROOT = Path(__file__).parents[1] / "bluefire" / "ui"


@pytest.fixture(scope="module")
def assets() -> dict[str, str]:
    return {
        name: (UI_ROOT / name).read_text(encoding="utf-8")
        for name in ("index.html", "styles.css", "app.js")
    }


def test_ui_is_dependency_free_and_has_no_external_assets(assets: dict[str, str]) -> None:
    combined = "\n".join(assets.values())
    assert not re.search(r"(?:src|href)=[\"']https?://", assets["index.html"], re.IGNORECASE)
    assert not re.search(r"@import\s+url", assets["styles.css"], re.IGNORECASE)
    assert "unpkg.com" not in combined
    assert "cdn." not in combined
    assert "node_modules" not in combined
    assert '<script type="module" src="/ui/app.js"></script>' in assets["index.html"]
    assert not re.search(r"<script(?:\s[^>]*)?>\s*[^<]", assets["index.html"], re.IGNORECASE)


def test_ui_has_three_accessible_product_workspaces(assets: dict[str, str]) -> None:
    html = assets["index.html"]
    assert '<main id="workspace-main"' in html
    assert 'aria-label="Primary workspace"' in html
    for workspace in ("build", "run", "compare"):
        assert f'data-workspace="{workspace}"' in html
        assert f'id="workspace-{workspace}"' in html
        assert f'aria-controls="workspace-{workspace}"' in html
    assert "Skip to workspace" in html
    assert "tabKeyboardNavigation" in assets["app.js"]


def test_effect_modes_are_exactly_simulate_and_execute_and_ai_is_independent(
    assets: dict[str, str],
) -> None:
    html = assets["index.html"]
    modes = re.findall(r'name="execution-mode"\s+value="([^"]+)"', html)
    assert modes == ["simulate", "execute"]
    mode_fieldset = re.search(r'<fieldset class="mode-fieldset">(.*?)</fieldset>', html, re.DOTALL)
    assert mode_fieldset
    assert 'id="ai-planner"' not in mode_fieldset.group(1)
    assert 'id="ai-planner"' in html
    assert "AI Planner is an independent proposal layer" in html


def test_execute_has_an_explicit_operator_bound_approval_gate(assets: dict[str, str]) -> None:
    html = assets["index.html"]
    script = assets["app.js"]
    assert 'id="execute-approval" hidden' in html
    confirmation = re.search(r'<input id="execute-approval-confirm"([^>]*)>', html)
    assert confirmation
    assert "checked" not in confirmation.group(1)
    assert 'id="approval-operator"' in html
    assert "Operator identity" in html
    assert 'mode === "execute"' in script
    assert "executeApprovalReady" in script
    assert "Execute preflight requires explicit approval" in script
    assert "approval: {" in script
    assert "confirmed:" in script and "approved_by:" in script
    assert 'value="sandbox.workspace"' in html


def test_build_workspace_exposes_graph_contract_controls(assets: dict[str, str]) -> None:
    html = assets["index.html"]
    script = assets["app.js"]
    for copy in (
        "Behavior palette",
        "Typed inputs",
        "Typed outputs",
        "Explicit outcome edges",
        "Compatible swap",
        "Swap node",
        "Validate graph",
    ):
        assert copy in html or copy in script
    assert 'aria-label="Editable scenario graph"' in html
    assert 'role: "button"' in script
    assert "ArrowLeft" in script and "ArrowRight" in script
    assert "application/x-bluefire-behavior" in script
    for outcome in ("success", "partial", "blocked", "failed"):
        assert outcome in script


def test_run_workspace_keeps_preflight_and_evidence_states_visible(assets: dict[str, str]) -> None:
    html = assets["index.html"]
    for copy in (
        "Runner profile",
        "Target scope",
        "Capabilities",
        "Safety tier",
        "Approval",
        "Cleanup plan",
        "Queued",
        "Planning",
        "Running",
        "Succeeded",
        "Partial",
        "Blocked",
        "Failed",
        "Skipped",
        "Refused",
        "Planner",
        "Policy",
        "Runner",
        "Evidence",
        "Detections",
    ):
        assert copy in html
    assert 'id="start-run" type="button" disabled' in html
    assert "state.preflight" in assets["app.js"]


def test_replay_and_multi_run_compare_controls_are_present(assets: dict[str, str]) -> None:
    html = assets["index.html"]
    script = assets["app.js"]
    for copy in (
        "Exact",
        "From node",
        "Compatible swap",
        "Profile override",
        "AI Planner override",
        "Declared defense change",
        "First blocked node",
        "Objective reached",
        "Evidence provenance",
        "Detection lifecycle",
        "Cleanup result",
        "Latency delta",
    ):
        assert copy in html
    assert 'type="checkbox"' in script
    assert "runIds.length < 2" in script
    assert 'request("/comparisons"' in script
    assert "/replays" in script


def test_browser_has_no_direct_runner_or_arbitrary_shell_surface(assets: dict[str, str]) -> None:
    combined = "\n".join(assets.values()).lower()
    forbidden = (
        "websocket(",
        "runner_client",
        "subprocess",
        "shell command",
        "command input",
        "arbitrary command",
        "/runner/execute",
    )
    for value in forbidden:
        assert value not in combined
    assert "fetch(`${api}${path}`" in combined


def test_public_ui_has_no_actor_branding_or_private_review_residue(assets: dict[str, str]) -> None:
    combined = "\n".join(assets.values())
    assert not re.search(r"\bAPT\s*\d+\b|\bFIN\s*7\b|threat actor", combined, re.IGNORECASE)
    assert not re.search(r"PR\s*#\d+|Codex P[0-9]", combined, re.IGNORECASE)


def test_css_is_responsive_and_supports_reduced_motion(assets: dict[str, str]) -> None:
    css = assets["styles.css"]
    assert css.count("@media (max-width:") >= 3
    assert "@media (prefers-reduced-motion: no-preference)" in css
    assert ":focus-visible" in css
    assert "min-width: 320px" in css


def test_javascript_passes_node_syntax_check_when_node_is_available() -> None:
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is not installed; the UI has no Node runtime dependency")
    completed = subprocess.run(
        [node, "--check", str(UI_ROOT / "app.js")],
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert completed.returncode == 0, completed.stderr
