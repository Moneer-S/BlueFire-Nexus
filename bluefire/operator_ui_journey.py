"""Production operator-console journey for GATE-08."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import threading
from pathlib import Path
from typing import Any, Mapping, cast

from .api import browser_console_url, create_server, generate_browser_bootstrap_capability
from .runner_lifecycle import ManagedRunnerLifecycle
from .service import BlueFireService

BROWSER_REPORT = "gate08-browser-report.json"
JOURNEY_REPORT = "gate08-journey-report.json"
PRODUCT_DB_ARTIFACT = "runs/bluefire-product.sqlite3"
SCREENSHOT_ARTIFACTS = (
    "screenshots/operator-builder.png",
    "screenshots/operator-run-review.png",
    "screenshots/operator-compare.png",
)
REPORT_PATHS = (BROWSER_REPORT, JOURNEY_REPORT)

HELPER_SCHEMA = "bluefire.gate-08-helper.v1"
BROWSER_SCHEMA = "bluefire.operator-production-browser.v1"
JOURNEY_SCHEMA = "bluefire.operator-ui-gate-journey.v1"
OPERATION_SEQUENCE = (
    "bootstrap_production_session",
    "export_scenario",
    "create_scenario_draft",
    "import_scenario",
    "edit_graph_and_history",
    "resize_collapse_and_focus_panels",
    "validate_and_version_scenario",
    "persist_strict_settings",
    "exercise_ai_modes_and_provider",
    "manage_runner_profile",
    "manage_runner_record",
    "review_action_package_controls",
    "review_source_and_detection_surfaces",
    "review_execute_approval_boundary",
    "run_production_preflight",
    "submit_and_observe_simulate_job",
    "review_canonical_run",
    "create_production_replay",
    "compare_material_run_delta",
)

PROFILE_ID = "gate08.operator.profile.v1"
RUNNER_ID = "gate08.operator.runner.v1"
_RUN_ID = re.compile(r"^run-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}$")
_COMPARISON_ID = re.compile(r"^comparison-[0-9a-f]{20}$")
_MAX_REPORT_BYTES = 2 * 1024 * 1024
_MAX_PROCESS_OUTPUT_BYTES = 512 * 1024
_MAX_SCREENSHOT_BYTES = 12 * 1024 * 1024
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


class OperatorUIJourneyError(ValueError):
    """Raised when the production operator journey is not established."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise OperatorUIJourneyError(message)


def _is_link_or_reparse(details: os.stat_result) -> bool:
    return stat.S_ISLNK(details.st_mode) or bool(
        int(getattr(details, "st_file_attributes", 0)) & _REPARSE_POINT
    )


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    payload = (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    )
    _require(
        path.parent.is_dir() and not path.exists() and 0 < len(payload) <= _MAX_REPORT_BYTES,
        "a GATE-08 report output is stale or unbounded",
    )
    descriptor: int | None = None
    try:
        descriptor = os.open(
            path,
            os.O_CREAT
            | os.O_EXCL
            | os.O_WRONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            _require(written > 0, "a GATE-08 report write made no progress")
            offset += written
        os.fsync(descriptor)
    except OSError as exc:
        raise OperatorUIJourneyError("a GATE-08 report could not be written") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _read_json(path: Path) -> Mapping[str, Any]:
    _require(path.is_file() and not path.is_symlink(), "the GATE-08 browser report is absent")
    _require(path.stat().st_size <= _MAX_REPORT_BYTES, "the GATE-08 browser report is unbounded")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise OperatorUIJourneyError("the GATE-08 browser report is invalid JSON") from exc
    if not isinstance(value, Mapping):
        raise OperatorUIJourneyError("the GATE-08 browser report is not an object")
    return value


def _packaged_ui(repository: Path) -> Path:
    ui_root = repository / "bluefire" / "ui"
    expected = {"index.html", "app.js", "styles.css"}
    _require(ui_root.is_dir() and not ui_root.is_symlink(), "the packaged production UI is absent")
    entries = {item.name: item for item in ui_root.iterdir()}
    _require(set(entries) == expected, "the packaged production UI inventory is not exact")
    for path in entries.values():
        details = path.lstat()
        _require(
            details.st_size > 0
            and details.st_size <= 8 * 1024 * 1024
            and stat.S_ISREG(details.st_mode)
            and not _is_link_or_reparse(details),
            "a packaged production UI asset is unsafe or unbounded",
        )
    shell = entries["index.html"].read_bytes()
    _require(
        b"/ui/app.js" in shell and b"/ui/styles.css" in shell,
        "the packaged production UI shell does not bind committed assets",
    )
    return ui_root


def _node_binary() -> Path:
    raw = os.environ.get("BLUEFIRE_GATE_NODE") or shutil.which("node")
    if not isinstance(raw, str) or not raw:
        raise OperatorUIJourneyError("the pinned GATE-08 Node runtime is unavailable")
    node = Path(raw).resolve(strict=True)
    _require(node.is_file(), "the pinned GATE-08 Node runtime is invalid")
    return node


def _run_browser(
    repository: Path,
    evidence_dir: Path,
    service: BlueFireService,
    baseline_run_id: str,
) -> Mapping[str, Any]:
    node = _node_binary()
    frontend = repository / "frontend"
    cli = frontend / "node_modules" / "@playwright" / "test" / "cli.js"
    config = frontend / "playwright.operator.config.ts"
    spec = frontend / "tests" / "e2e" / "operator-production.spec.ts"
    _require(
        all(path.is_file() and not path.is_symlink() for path in (cli, config, spec)),
        "the committed GATE-08 Playwright harness is unavailable",
    )
    screenshots = evidence_dir / "screenshots"
    screenshots.mkdir(mode=0o700, exist_ok=False)
    report_path = evidence_dir / BROWSER_REPORT
    capability = generate_browser_bootstrap_capability()
    server = create_server(
        service,
        browser_bootstrap_capability=capability,
        host="127.0.0.1",
        port=0,
        ui_root=_packaged_ui(repository),
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    launch_url = ""
    try:
        launch_url = browser_console_url("127.0.0.1", int(server.server_address[1]), capability)
        with tempfile.TemporaryDirectory(
            prefix=".gate08-playwright-", dir=evidence_dir
        ) as temporary:
            environment = dict(os.environ)
            environment.update(
                {
                    "BLUEFIRE_PRODUCTION_URL": launch_url,
                    "BLUEFIRE_BROWSER_REPORT_PATH": os.fspath(report_path),
                    "BLUEFIRE_BROWSER_SCREENSHOT_DIR": os.fspath(screenshots),
                    "BLUEFIRE_BROWSER_ARTIFACT_DIR": temporary,
                    "BLUEFIRE_BASELINE_RUN_ID": baseline_run_id,
                    "VITE_DEMO_MODE": "false",
                }
            )
            completed = subprocess.run(
                [
                    os.fspath(node),
                    os.fspath(cli),
                    "test",
                    "--config",
                    os.fspath(config),
                    "operator-production.spec.ts",
                    "--project=chromium",
                ],
                cwd=frontend,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=300,
            )
        _require(
            len(completed.stdout) <= _MAX_PROCESS_OUTPUT_BYTES
            and len(completed.stderr) <= _MAX_PROCESS_OUTPUT_BYTES,
            "the GATE-08 browser process exceeded its output bound",
        )
        if completed.returncode != 0:
            diagnostic = (completed.stdout + b"\n" + completed.stderr).decode("utf-8", "replace")
            for sensitive in (
                launch_url,
                capability,
                os.fspath(repository),
                os.fspath(evidence_dir),
            ):
                diagnostic = diagnostic.replace(sensitive, "[redacted]")
            raise OperatorUIJourneyError(
                "the GATE-08 production browser process failed: "
                + " ".join(diagnostic[-5000:].split())
            )
    except subprocess.TimeoutExpired as exc:
        raise OperatorUIJourneyError("the GATE-08 production browser process timed out") from exc
    finally:
        capability = ""
        launch_url = ""
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    return _read_json(report_path)


def _screenshot_artifacts(evidence_dir: Path) -> tuple[Mapping[str, Any], ...]:
    artifacts: list[Mapping[str, Any]] = []
    for relative in SCREENSHOT_ARTIFACTS:
        path = evidence_dir / relative
        details = path.lstat()
        _require(
            stat.S_ISREG(details.st_mode)
            and not _is_link_or_reparse(details)
            and 8 < details.st_size <= _MAX_SCREENSHOT_BYTES,
            "a GATE-08 screenshot is absent, unsafe, or unbounded",
        )
        payload = path.read_bytes()
        _require(payload.startswith(b"\x89PNG\r\n\x1a\n"), "a GATE-08 screenshot is not PNG")
        artifacts.append(
            {
                "path": relative,
                "size_bytes": len(payload),
                "sha256": "sha256:" + hashlib.sha256(payload).hexdigest(),
            }
        )
    return tuple(artifacts)


def _browser_run_ids(browser: Mapping[str, Any]) -> tuple[str, str, str]:
    live = browser.get("live_workflow")
    if not isinstance(live, Mapping):
        raise OperatorUIJourneyError("the GATE-08 browser run summary is absent")
    values = tuple(live.get(name) for name in ("run_id", "replay_run_id", "baseline_run_id"))
    _require(
        all(isinstance(value, str) and _RUN_ID.fullmatch(value) for value in values),
        "the GATE-08 browser run identities are invalid",
    )
    return cast(tuple[str, str, str], values)


def produce_operator_ui_gate_evidence(repository: Path, evidence_dir: Path) -> Mapping[str, Any]:
    """Exercise the committed UI against one real local production service."""

    root = repository.resolve(strict=True)
    destination = evidence_dir.resolve(strict=True)
    _require(root.is_dir() and destination.is_dir(), "GATE-08 roots must be directories")
    _require(
        all(not (destination / path).exists() for path in (*REPORT_PATHS, "screenshots", "runs")),
        "GATE-08 evidence contains stale owned artifacts",
    )
    run_root = destination / "runs"
    run_root.mkdir(mode=0o700, exist_ok=False)
    service = BlueFireService(
        project_root=root,
        runs_dir=run_root,
        product_db_path=run_root / "bluefire-product.sqlite3",
        runner_lifecycle=ManagedRunnerLifecycle(destination / ".gate08-managed-runner"),
    )
    try:
        base_request = {
            "scenario_id": "scenario.ai-adaptive.safe-chain.v1",
            "mode": "simulate",
            "autonomy": "auto",
            "ai_provider_id": "deterministic-offline.v1",
            "target_scope": {"scope_refs": ["sandbox.workspace"]},
        }
        baseline = service.run(base_request)
        seeded_variant = service.replay(
            str(baseline["run_id"]),
            {"autonomy": "assist", "ai_provider_id": "deterministic-offline.v1"},
        )
        browser = _run_browser(root, destination, service, str(baseline["run_id"]))
        _require(
            browser.get("schema_version") == BROWSER_SCHEMA
            and browser.get("production_browser_interaction") is True
            and browser.get("demo_mode") is False
            and browser.get("operation_sequence") == list(OPERATION_SEQUENCE),
            "the GATE-08 browser report did not establish the locked journey",
        )
        browser_run_id, browser_replay_id, reported_baseline_id = _browser_run_ids(browser)
        _require(
            reported_baseline_id == baseline["run_id"],
            "the GATE-08 browser comparison used the wrong seeded baseline",
        )
        run_ids = (
            str(baseline["run_id"]),
            str(seeded_variant["run_id"]),
            browser_run_id,
            browser_replay_id,
        )
        _require(len(set(run_ids)) == 4, "the GATE-08 run inventory is not unique")
        listed = service.list().get("runs")
        _require(
            isinstance(listed, list)
            and {str(item.get("run_id")) for item in listed if isinstance(item, Mapping)}
            == set(run_ids),
            "the GATE-08 service did not persist exactly four canonical runs",
        )
        for run_id in run_ids:
            _require(
                service.store.validate_bundle(run_id).get("valid") is True
                and service.detail(run_id).get("status") == "completed",
                "a GATE-08 canonical run bundle failed validation",
            )
        settings = service.settings().get("settings")
        _require(
            isinstance(settings, list) and len(settings) == 1, "GATE-08 settings did not persist"
        )
        setting = cast(list[Any], settings)[0]
        _require(
            isinstance(setting, Mapping)
            and setting.get("key") == "ui.preferences"
            and setting.get("value")
            == {
                "schema_version": "bluefire.ui-preferences.v1",
                "theme": "light",
                "effect_mode": "simulate",
                "autonomy": "auto",
            },
            "GATE-08 settings did not retain the strict preference document",
        )
        profile = service.resource("runner_profile", PROFILE_ID)["resource"]
        runner = service.resource("runner", RUNNER_ID)["resource"]
        _require(
            isinstance(profile, Mapping)
            and isinstance(runner, Mapping)
            and profile.get("status") == "draft"
            and runner.get("status") == "draft",
            "GATE-08 UI-managed resource drafts were not persisted",
        )
        detections = service.resources("detection").get("resources")
        _require(
            isinstance(detections, list)
            and any(
                isinstance(item, Mapping)
                and isinstance(item.get("document"), Mapping)
                and item["document"].get("title") == "Gate 08 operator hypothesis"
                for item in detections
            ),
            "the GATE-08 UI-created detection hypothesis was not persisted",
        )
        screenshots = _screenshot_artifacts(destination)
        live_workflow = cast(Mapping[str, Any], browser["live_workflow"])
        comparison_id = live_workflow.get("comparison_id")
        _require(
            isinstance(comparison_id, str) and _COMPARISON_ID.fullmatch(comparison_id) is not None,
            "the GATE-08 comparison identity is invalid",
        )
        comparison_id = cast(str, comparison_id)
        journey = {
            "schema_version": JOURNEY_SCHEMA,
            "passed": True,
            "run_bundles": [{"run_id": run_id, "path": f"runs/{run_id}"} for run_id in run_ids],
            "roles": {
                "seeded_baseline": run_ids[0],
                "seeded_autonomy_variant": run_ids[1],
                "browser_run": run_ids[2],
                "browser_exact_replay": run_ids[3],
            },
            "comparison_id": comparison_id,
            "screenshots": list(screenshots),
            "product_database": PRODUCT_DB_ARTIFACT,
            "preference_key": "ui.preferences",
            "runner_profile_id": PROFILE_ID,
            "runner_record_id": RUNNER_ID,
            "browser_report": BROWSER_REPORT,
            "browser_report_sha256": "sha256:"
            + hashlib.sha256((destination / BROWSER_REPORT).read_bytes()).hexdigest(),
        }
        _write_json(destination / JOURNEY_REPORT, journey)
    finally:
        service.close()
    return {
        "schema_version": HELPER_SCHEMA,
        "status": "passed",
        "reports": list(REPORT_PATHS),
        "run_count": 4,
        "blocking_check": None,
    }


__all__ = [
    "BROWSER_REPORT",
    "BROWSER_SCHEMA",
    "HELPER_SCHEMA",
    "JOURNEY_REPORT",
    "JOURNEY_SCHEMA",
    "OPERATION_SEQUENCE",
    "OperatorUIJourneyError",
    "PRODUCT_DB_ARTIFACT",
    "PROFILE_ID",
    "REPORT_PATHS",
    "RUNNER_ID",
    "SCREENSHOT_ARTIFACTS",
    "produce_operator_ui_gate_evidence",
]
