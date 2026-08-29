from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "frontend" / "tests" / "e2e" / "detection-production.spec.ts"
CONFIG = ROOT / "frontend" / "playwright.detection.config.ts"
RUNNER = ROOT / "tools" / "run_detection_browser_journey.mjs"


def _source(path: Path) -> str:
    assert path.is_file()
    return path.read_text(encoding="utf-8")


def test_production_browser_config_is_single_worker_and_artifact_free() -> None:
    source = _source(CONFIG)

    assert 'testMatch: "detection-production.spec.ts"' in source
    assert "workers: 1" in source
    assert "retries: 0" in source
    assert 'trace: "off"' in source
    assert 'screenshot: "off"' in source
    assert 'video: "off"' in source
    assert "globalSetup" not in source
    assert "webServer" not in source
    assert "BLUEFIRE_PRODUCTION_URL" in source
    assert "BLUEFIRE_BROWSER_REPORT_PATH" in source
    assert "#bluefire-session=" in source
    assert "VITE_DEMO_MODE" in source


def test_production_spec_drives_ui_without_mock_or_direct_api_shortcuts() -> None:
    source = _source(SPEC)
    compact = source.lower().replace(" ", "")

    for required in (
        'getByRole("link", { name: "Detection Lab" })',
        'selectOption("sqlite")',
        'getByRole("button", { name: "Save strict hypothesis" })',
        'getByRole("button", { name: "Parse / compile honestly" })',
        'getByRole("button", { name: "Exercise malicious fixtures" })',
        "page.reload",
        '"Source query executed"',
        '"Evaluated records"',
        '"Matched records"',
        'fs.open(path, "wx"',
        "production_browser_interaction: true",
        'schema_version: "bluefire.detection-production-browser.v1"',
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


def test_runner_keeps_capability_out_of_arguments_and_revalidates_report() -> None:
    source = _source(RUNNER)

    assert 'args.length !== 2 || args[0] !== "--report"' in source
    assert "--url" not in source
    assert "BLUEFIRE_PRODUCTION_URL" in source
    assert '.replaceAll(capability, "<redacted-capability>")' in source
    assert "TIMEOUT_MS = 120_000" in source
    assert "MAX_PROCESS_OUTPUT_BYTES" in source
    assert "sameKeys(report, REPORT_KEYS)" in source
    assert "sameKeys(report.backend, BACKEND_KEYS)" in source
    assert "report.production_browser_interaction !== true" in source
    assert "report.demo_mode !== false" in source
    assert 'report.visible_state !== "fixture_exercised"' in source
    assert "raw.includes(capability)" in source
    assert "shell: false" in source
    assert "terminateProcessTree" in source
    assert 'join(systemRoot, "System32", "taskkill.exe")' in source
    assert 'process.kill(-pid, "SIGKILL")' in source
    assert 'detached: process.platform !== "win32"' in source
    assert 'VITE_DEMO_MODE: "false"' in source
    assert "artifactIdentity = lstatSync(artifactRoot)" in source
    assert 'artifactDirectory = join(artifactRoot, "results")' in source
    assert "currentArtifact.dev === artifactIdentity.dev" in source
