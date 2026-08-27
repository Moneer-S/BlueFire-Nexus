from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).parents[1]
UI_ROOT = PROJECT_ROOT / "bluefire" / "ui"
FRONTEND_ROOT = PROJECT_ROOT / "frontend"
SOURCE_ROOT = FRONTEND_ROOT / "src"


@pytest.fixture(scope="module")
def assets() -> dict[str, str]:
    return {
        name: (UI_ROOT / name).read_text(encoding="utf-8")
        for name in ("index.html", "styles.css", "app.js")
    }


@pytest.fixture(scope="module")
def source() -> str:
    return "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted(SOURCE_ROOT.rglob("*"))
        if path.suffix in {".ts", ".tsx", ".css"}
    )


def test_packaged_ui_is_self_contained_and_uses_fixed_assets(assets: dict[str, str]) -> None:
    combined = "\n".join(assets.values())
    assert not re.search(r"(?:src|href)=[\"']https?://", assets["index.html"], re.IGNORECASE)
    assert not re.search(r"@import\s+url", assets["styles.css"], re.IGNORECASE)
    assert "unpkg.com" not in combined
    assert "node_modules" not in combined
    assert re.search(r'<script[^>]+type="module"[^>]+src="/ui/app\.js"', assets["index.html"])
    assert 'href="/ui/styles.css"' in assets["index.html"]
    assert (UI_ROOT / "app.js").stat().st_size > 50_000
    assert (UI_ROOT / "styles.css").stat().st_size > 10_000


def test_frontend_toolchain_is_locked_and_componentized() -> None:
    package = (FRONTEND_ROOT / "package.json").read_text(encoding="utf-8")
    assert (FRONTEND_ROOT / "pnpm-lock.yaml").is_file()
    assert (FRONTEND_ROOT / "vite.config.ts").is_file()
    assert (FRONTEND_ROOT / "vitest.config.ts").is_file()
    assert (FRONTEND_ROOT / "playwright.config.ts").is_file()
    for dependency in ("react", "@xyflow/react", "@tanstack/react-query", "@radix-ui/react-dialog"):
        assert f'"{dependency}"' in package
    assert (SOURCE_ROOT / "components" / "AppShell.tsx").is_file()
    assert (SOURCE_ROOT / "state" / "ProductContext.tsx").is_file()


def test_all_required_product_routes_are_present() -> None:
    app = (SOURCE_ROOT / "App.tsx").read_text(encoding="utf-8")
    routes = (
        "scenarios",
        "builder",
        "runs",
        "compare",
        "behaviors",
        "runner-profiles",
        "runners",
        "actions",
        "detection-lab",
        "research-sources",
        "ai-planner",
        "settings",
        "help",
    )
    for route in routes:
        assert f'path="{route}"' in app


def test_modes_and_autonomy_are_exact_and_independent(source: str) -> None:
    types = (SOURCE_ROOT / "types.ts").read_text(encoding="utf-8")
    assert 'RunMode = "simulate" | "execute"' in types
    assert 'AutonomyLevel = "off" | "assist" | "auto"' in types
    api = (SOURCE_ROOT / "lib" / "api.ts").read_text(encoding="utf-8")
    assert "autonomy: config.autonomy" in api
    assert "ai_provider_id: config.provider" in api
    assert "autonomy_level: config.autonomy" not in api
    assert "ai_enabled: config.autonomy" not in api
    assert "Independent from Simulate or Execute mode" in source


def test_execute_approval_is_ephemeral_and_operator_bound() -> None:
    context = (SOURCE_ROOT / "state" / "ProductContext.tsx").read_text(encoding="utf-8")
    runs = (SOURCE_ROOT / "pages" / "Runs.tsx").read_text(encoding="utf-8")
    assert "approved: false" in context
    assert 'approvedBy: ""' in context
    assert "clearApproval" in context
    assert (
        'const preferenceFields = new Set(["schema_version", "theme", "effect_mode", "autonomy"])'
        in context
    )
    assert "const preferences = readBrowserUiPreferences()" in context
    assert "writeBrowserUiPreferences(buildUiPreferenceDocument" in context
    assert "Explicit one-time Execute approval" in runs
    assert "onSettled: clearApproval" in runs
    assert "I approve this exact immutable" in runs
    assert '"job envelope"' in runs
    assert "never sent as an execution capability" in runs
    assert "Operator identity" in runs


def test_run_ui_uses_durable_job_lifecycle_routes() -> None:
    api = (SOURCE_ROOT / "lib" / "api.ts").read_text(encoding="utf-8")
    runs = (SOURCE_ROOT / "pages" / "Runs.tsx").read_text(encoding="utf-8")
    types = (SOURCE_ROOT / "types.ts").read_text(encoding="utf-8")
    for route in (
        'request("/runs"',
        "request(`/jobs/${encodeURIComponent(jobId)}`)",
        "/approval`",
        "/${action}`",
    ):
        assert route in api
    assert "submitRun" in api and "approveJob" in api and "controlJob" in api
    for state in ("awaiting_approval", "running", "paused", "cancelling", "completed"):
        assert state in runs + types
    assert "Pause at the next cooperative checkpoint" in runs
    assert "Approve and release job" in runs


def test_management_ui_uses_durable_secret_safe_routes() -> None:
    api = (SOURCE_ROOT / "lib" / "api.ts").read_text(encoding="utf-8")
    builder = (SOURCE_ROOT / "pages" / "Builder.tsx").read_text(encoding="utf-8")
    settings = (SOURCE_ROOT / "pages" / "SettingsHelp.tsx").read_text(encoding="utf-8")
    catalog = (SOURCE_ROOT / "pages" / "CatalogPages.tsx").read_text(encoding="utf-8")
    action_packages = (SOURCE_ROOT / "pages" / "ActionPackages.tsx").read_text(encoding="utf-8")
    detection = (SOURCE_ROOT / "pages" / "DetectionLab.tsx").read_text(encoding="utf-8")

    for route in (
        "/settings/${encodeURIComponent(key)}",
        'request("/scenario-versions"',
        "/resources/${kind}/${encodeURIComponent(id)}",
    ):
        assert route in api
    assert "api.saveScenarioVersion(scenario)" in builder
    assert 'api.saveSetting("ui.preferences"' in settings
    assert "buildUiPreferenceDocument(theme, runConfig.mode, runConfig.autonomy)" in settings
    assert "parseUiPreferenceDocument" in settings
    assert "No authority fields were accepted" in settings
    for kind in ('"runner-profiles"', '"runners"', '"plugins"', '"research-sources"'):
        assert f"api.saveResource({kind}" in catalog
    assert "api.upsertDetection(" in detection
    assert "api.detectionAction(" in detection
    for action in ("parse", "exercise-fixtures", "exercise-observed", "evaluate-benign", "reject"):
        assert action in detection
    assert 'api.activateResource("runner-profiles"' in catalog
    assert 'api.deactivateResource("runner-profiles"' in catalog
    assert "api.probeRunnerProfile(" in catalog
    assert 'api.activateResource("plugins"' not in catalog
    assert 'api.deactivateResource("plugins"' not in catalog
    assert "api.installActionPackage(" in action_packages
    assert "api.activateActionPackage(" in action_packages
    assert "api.deactivateActionPackage(" in action_packages
    assert "api.removeActionPackage(" in action_packages
    assert "api.trustActionPackagePublisher" in action_packages
    assert "api.transitionActionPackagePublisher(" in action_packages
    assert "does not launch, enroll, authenticate, or attest" in catalog
    assert "does not download, verify bytes, install code" in catalog
    assert "decorative activation control has been removed" in catalog


def test_graph_editor_exposes_typed_contract_controls(source: str) -> None:
    builder = (SOURCE_ROOT / "pages" / "Builder.tsx").read_text(encoding="utf-8")
    for capability in (
        "application/x-bluefire-behavior",
        "ReactFlow",
        "MiniMap",
        "Controls",
        "onConnect",
        "copySelected",
        "duplicateSelected",
        "undo",
        "redo",
        "Validate",
        "Action implementation",
    ):
        assert capability in builder
    for outcome in ("success", "partial", "blocked", "failed"):
        assert outcome in builder
    assert "Incompatible artifact contract" in builder


def test_run_ui_separates_preview_preferences_from_canonical_preflight() -> None:
    runs = (SOURCE_ROOT / "pages" / "Runs.tsx").read_text(encoding="utf-8")
    for copy in (
        "Profile-owned enforcement",
        "Browser intent",
        "Unsupported browser overrides are intentionally not shown",
        "Canonical preflight",
        "Resolved canonical plan",
        "Plan digest",
        "Expected outputs",
        "Required capabilities",
        "sent for exact binding",
    ):
        assert copy in runs
    api = (SOURCE_ROOT / "lib" / "api.ts").read_text(encoding="utf-8")
    for unsupported in (
        "budgets:",
        "detection_backends:",
        "cleanup_policy:",
        "counterfactual_policy:",
    ):
        assert unsupported not in api
    assert 'config.mode === "execute"' in api
    assert "collectors:" in api
    assert "[...config.collectors]" in api
    assert "action_implementations" in api
    assert "Simulate ignores and clears action selections" in (
        SOURCE_ROOT / "pages" / "Builder.tsx"
    ).read_text(encoding="utf-8")


def test_replay_compare_requires_fresh_execute_approval_and_strict_parameters() -> None:
    compare = (SOURCE_ROOT / "pages" / "Compare.tsx").read_text(encoding="utf-8")
    api = (SOURCE_ROOT / "lib" / "api.ts").read_text(encoding="utf-8")
    assert "parseParameterOverrides" in compare
    assert "Run prospective base-plan check" in compare
    assert "I approve this reviewed Execute replay request once" in compare
    assert "Not the replay binding" in compare
    assert "The source bundle never changes" in compare
    assert "Source run" in compare
    assert "Replay created" in compare and "replayMutation.data.run_id" in compare
    assert "buildReplayPayload" in api
    assert "parameter_overrides" in api
    assert "target_scope" in api and "approval" in api
    assert "autonomy:" in api and "ai_provider_id:" in api


def test_durable_proposal_review_and_retry_stay_separate_from_execute_approval() -> None:
    api = (SOURCE_ROOT / "lib" / "api.ts").read_text(encoding="utf-8")
    runs = (SOURCE_ROOT / "pages" / "Runs.tsx").read_text(encoding="utf-8")
    planner = (SOURCE_ROOT / "pages" / "AIPlanner.tsx").read_text(encoding="utf-8")
    review = (SOURCE_ROOT / "components" / "ProposalReview.tsx").read_text(encoding="utf-8")
    for route in ("/retry`", "/proposals`", "/${action}`"):
        assert route in api
    for digest in ("state_digest", "plan_digest", "proposal_digest"):
        assert digest in api and digest in review
    assert 'aria-label="AI decision boundaries"' in review
    assert "Separate fresh one-time capability" in review
    assert "Fresh Execute approval after proposal acceptance" in runs
    assert "Retry as replacement" in runs
    for capability in (
        "exact observed next edge",
        "compatible registered behavior",
        "typed primitive parameters",
        "exact active profile",
        "one bounded retry",
        "every Execute mutation stops for fresh one-time approval",
    ):
        assert capability in planner
    for boundary in (
        "arbitrary commands",
        "widen scope",
        "change profile, tier, or policy",
        "edge for another outcome",
        "runtime-apply detection or replay proposals",
    ):
        assert boundary in planner


def test_browser_has_no_direct_runner_or_shell_surface(source: str) -> None:
    lowered = source.lower()
    for forbidden in (
        "websocket(",
        "subprocess",
        "shell command input",
        "/runner/execute",
    ):
        assert forbidden not in lowered
    assert 'const api_root = "/api/v1"' in lowered
    assert 'credentials: "same-origin"' in lowered


def test_public_ui_has_no_actor_branding_or_review_residue(source: str) -> None:
    assert not re.search(r"\bAPT\s*\d+\b|\bFIN\s*7\b|threat actor", source, re.IGNORECASE)
    assert not re.search(r"PR\s*#\d+|Codex P[0-9]", source, re.IGNORECASE)


def test_css_is_responsive_accessible_and_reduced_motion_safe(assets: dict[str, str]) -> None:
    css = assets["styles.css"]
    assert len(re.findall(r"@media\s*\(max-width:", css)) >= 3
    assert "@media(prefers-reduced-motion:reduce)" in css.replace(" ", "")
    assert ":focus-visible" in css
    assert "min-width:320px" in css.replace(" ", "")
    assert ".skip-link" in css


def test_javascript_passes_node_syntax_check_when_node_is_available() -> None:
    node = shutil.which("node")
    if not node:
        pytest.skip(
            "Node.js is not installed; the packaged UI still has no runtime Node dependency"
        )
    completed = subprocess.run(
        [node, "--check", str(UI_ROOT / "app.js")],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
