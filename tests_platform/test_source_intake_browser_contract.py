from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "frontend" / "tests" / "e2e" / "source-intake-production.spec.ts"
CONFIG = ROOT / "frontend" / "playwright.source-intake.config.ts"
RUNNER = ROOT / "tools" / "run_source_intake_browser_journey.mjs"


def _source(path: Path) -> str:
    assert path.is_file()
    return path.read_text(encoding="utf-8")


def test_source_intake_browser_config_is_single_worker_and_artifact_free() -> None:
    source = _source(CONFIG)

    assert 'testMatch: "source-intake-production.spec.ts"' in source
    assert "workers: 1" in source
    assert "retries: 0" in source
    assert 'trace: "off"' in source
    assert 'screenshot: "off"' in source
    assert 'video: "off"' in source
    assert "globalSetup" not in source
    assert "webServer" not in source
    assert "BLUEFIRE_PRODUCTION_URL" in source
    assert "BLUEFIRE_BROWSER_REPORT_PATH" in source
    assert "BLUEFIRE_BROWSER_ARTIFACT_DIR" in source
    assert "#bluefire-session=" in source
    assert "VITE_DEMO_MODE" in source


def test_source_intake_spec_uses_production_ui_without_api_shortcuts() -> None:
    source = _source(SPEC)
    compact = source.lower().replace(" ", "")

    for required in (
        'getByRole("link", { name: "Research Sources" })',
        'getByRole("link", { name: "Behaviors" })',
        'getByRole("heading", { name: "Research sources", level: 1 })',
        'locator("summary", { hasText: "Intake review" })',
        'getByLabel("Reviewed intake destination ID")',
        'getByLabel("Reviewed intake runner profile")',
        'getByRole("button", { name: "Import and activate reviewed T1082" })',
        'getByTestId("reviewed-intake-result")',
        '"metadata_import"',
        '"T1082"',
        '"LicenseRef-MITRE-ATTACK-2026"',
        "page.reload",
        'fs.open(path, "wx"',
        "production_browser_interaction: true",
        'schema_version: "bluefire.source-intake-production-browser.v1"',
        "behavior_provenance_reference",
        "already_active_revalidated",
    ):
        assert required in source

    for forbidden in (
        "page.route(",
        "context.route(",
        "page.request",
        "request.newcontext",
        "fetch(",
        "addcookies(",
        "localstorage",
        "sessionstorage",
    ):
        assert forbidden not in compact
    assert "fs.unlink(path)" not in source


def test_source_intake_browser_runner_redacts_capability_and_cleans_process_tree() -> None:
    source = _source(RUNNER)

    assert 'args.length !== 2 || args[0] !== "--report"' in source
    assert "--url" not in source
    assert "BLUEFIRE_PRODUCTION_URL" in source
    assert "BLUEFIRE_GATE09_PROFILE_ID" in source
    assert "BLUEFIRE_GATE09_EXPECTED_RECORD_SHA256" in source
    assert '.replaceAll(capability, "<redacted-capability>")' in source
    assert "TIMEOUT_MS = 120_000" in source
    assert "MAX_PROCESS_OUTPUT_BYTES" in source
    assert "sameKeys(report, REPORT_KEYS)" in source
    assert "report.production_browser_interaction !== true" in source
    assert "report.demo_mode !== false" in source
    assert 'report.activation_operation !== "already_active_revalidated"' in source
    assert "report.behavior_provenance_visible !== true" in source
    assert "report.intake_record_sha256 !== expectedRecordSha256" in source
    assert "raw.includes(capability)" in source
    assert "shell: false" in source
    assert "terminateProcessTree" in source
    assert 'join(systemRoot, "System32", "taskkill.exe")' in source
    assert 'process.kill(-pid, "SIGKILL")' in source
    assert 'detached: process.platform !== "win32"' in source
    assert 'VITE_DEMO_MODE: "false"' in source
    assert "artifactIdentity = lstatSync(artifactRoot)" in source
    assert "currentArtifact.dev === artifactIdentity.dev" in source
