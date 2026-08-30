"""Independent persisted-evidence validation for GATE-08."""

from __future__ import annotations

import hashlib
import json
import re
import stat
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping, cast

from .comparison import compare_runs
from .operator_ui_journey import (
    BROWSER_REPORT,
    BROWSER_SCHEMA,
    JOURNEY_REPORT,
    JOURNEY_SCHEMA,
    OPERATION_SEQUENCE,
    PRODUCT_DB_ARTIFACT,
    PROFILE_ID,
    RUNNER_ID,
    SCREENSHOT_ARTIFACTS,
)
from .product_store import ProductStore
from .run_store import RunStore

CHECK_NAMES = frozenset(
    {
        "scenario_authoring",
        "graph_editor",
        "layers_branches_parameters",
        "safety_collectors_detections",
        "ai_replay_diff",
        "accessibility_palette",
        "mode_autonomy_providers",
        "runner_pack_management",
        "live_workflow",
        "provenance_settings",
        "no_raw_shell_approval",
        "canonical_requests",
    }
)

_MAX_REPORT_BYTES = 2 * 1024 * 1024
_MAX_SCREENSHOT_BYTES = 12 * 1024 * 1024
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_RUN_ID = re.compile(r"^run-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}$")
_COMPARISON_ID = re.compile(r"^comparison-[0-9a-f]{20}$")
_ORIGIN = re.compile(r"^http://127\.0\.0\.1:[1-9][0-9]{0,4}$")
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_RUN_ROLE_SEQUENCE = (
    "seeded_baseline",
    "seeded_autonomy_variant",
    "browser_run",
    "browser_exact_replay",
)


class OperatorUIGateValidationError(ValueError):
    """A GATE-08 artifact did not establish its claimed semantics."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise OperatorUIGateValidationError(message)


def _mapping(value: Any, message: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise OperatorUIGateValidationError(message)
    return value


def _exact(value: Mapping[str, Any], names: set[str], message: str) -> None:
    _require(set(value) == names, message)


def _read_json(path: Path) -> Mapping[str, Any]:
    _require(path.is_file() and not path.is_symlink(), "a GATE-08 report is absent or unsafe")
    _require(0 < path.stat().st_size <= _MAX_REPORT_BYTES, "a GATE-08 report is unbounded")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise OperatorUIGateValidationError("a GATE-08 report is invalid JSON") from exc
    return _mapping(value, "a GATE-08 report must be an object")


def _is_unsafe(details: Any) -> bool:
    return stat.S_ISLNK(details.st_mode) or bool(
        int(getattr(details, "st_file_attributes", 0)) & _REPARSE_POINT
    )


def _validate_browser(browser: Mapping[str, Any]) -> Mapping[str, bool]:
    _exact(
        browser,
        {
            "schema_version",
            "production_browser_interaction",
            "demo_mode",
            "origin",
            "operation_sequence",
            "scenario_authoring",
            "graph_editor",
            "configuration",
            "management",
            "live_workflow",
            "canonical_requests",
            "screenshots",
            "observed_at",
        },
        "the GATE-08 browser report schema is not exact",
    )
    _require(
        browser.get("schema_version") == BROWSER_SCHEMA
        and browser.get("production_browser_interaction") is True
        and browser.get("demo_mode") is False
        and isinstance(browser.get("origin"), str)
        and _ORIGIN.fullmatch(str(browser["origin"])) is not None
        and browser.get("operation_sequence") == list(OPERATION_SEQUENCE),
        "the GATE-08 browser report identity or journey is invalid",
    )
    try:
        datetime.fromisoformat(str(browser["observed_at"]).replace("Z", "+00:00"))
    except ValueError as exc:
        raise OperatorUIGateValidationError("the GATE-08 browser timestamp is invalid") from exc

    authoring = _mapping(browser.get("scenario_authoring"), "scenario authoring evidence is absent")
    _exact(
        authoring,
        {
            "exported",
            "created_draft",
            "imported",
            "validated",
            "versioned",
            "scenario_id",
            "scenario_title",
            "version",
            "request_keys",
        },
        "the scenario authoring evidence is not exact",
    )
    authoring_ok = bool(
        all(
            authoring.get(name) is True
            for name in ("exported", "created_draft", "imported", "validated", "versioned")
        )
        and isinstance(authoring.get("scenario_id"), str)
        and isinstance(authoring.get("scenario_title"), str)
        and "Gate 08 operator proof" in str(authoring["scenario_title"])
        and isinstance(authoring.get("version"), int)
        and not isinstance(authoring.get("version"), bool)
        and int(authoring["version"]) >= 1
        and authoring.get("request_keys") == ["scenario"]
    )

    graph = _mapping(browser.get("graph_editor"), "graph-editor evidence is absent")
    _exact(
        graph,
        {
            "initial_nodes",
            "graph_edges",
            "typed_handles",
            "layers",
            "branch_outcomes",
            "undo_redo_copy_paste",
            "keyboard_command_palette",
            "focus_mode",
            "collapsible_panels",
            "resizable_panels",
            "palette_width_px",
            "inspector_width_px",
            "compatibility_feedback",
            "parameters_actions_observables_visible",
        },
        "the graph-editor evidence is not exact",
    )
    graph_ok = bool(
        isinstance(graph.get("initial_nodes"), int)
        and int(graph["initial_nodes"]) > 1
        and isinstance(graph.get("graph_edges"), int)
        and int(graph["graph_edges"]) > 0
        and isinstance(graph.get("typed_handles"), int)
        and int(graph["typed_handles"]) > 0
        and graph.get("layers") == ["environment", "behavior", "evidence"]
        and graph.get("branch_outcomes") == ["success", "partial", "blocked", "failed"]
        and all(
            graph.get(name) is True
            for name in (
                "undo_redo_copy_paste",
                "keyboard_command_palette",
                "focus_mode",
                "collapsible_panels",
                "resizable_panels",
                "compatibility_feedback",
                "parameters_actions_observables_visible",
            )
        )
        and graph.get("palette_width_px") == 380
        and graph.get("inspector_width_px") == 420
    )

    configuration = _mapping(browser.get("configuration"), "configuration evidence is absent")
    _exact(
        configuration,
        {
            "effect_modes",
            "autonomy_levels",
            "provider_id",
            "profile_id",
            "target_scope",
            "settings_changed_backend_request",
            "strict_preference_fields",
            "approval_human_first",
            "raw_shell_input",
        },
        "the GATE-08 configuration evidence is not exact",
    )
    configuration_ok = bool(
        configuration.get("effect_modes") == ["simulate", "execute"]
        and configuration.get("autonomy_levels") == ["off", "assist", "auto"]
        and configuration.get("provider_id") == "deterministic-offline.v1"
        and configuration.get("profile_id") == "sandbox-simulate.v1"
        and configuration.get("target_scope") == {"scope_refs": ["sandbox.workspace"]}
        and configuration.get("settings_changed_backend_request") is True
        and configuration.get("strict_preference_fields")
        == ["autonomy", "effect_mode", "schema_version", "theme"]
        and configuration.get("approval_human_first") is True
        and configuration.get("raw_shell_input") is False
    )

    management = _mapping(browser.get("management"), "management evidence is absent")
    _exact(
        management,
        {
            "runner_profile_id",
            "runner_record_id",
            "profile_request_keys",
            "runner_request_keys",
            "signed_action_package_controls_visible",
            "arbitrary_package_code_input",
            "detection_hypothesis_saved",
            "detection_hypothesis_title",
        },
        "the GATE-08 management evidence is not exact",
    )
    management_ok = bool(
        management.get("runner_profile_id") == PROFILE_ID
        and management.get("runner_record_id") == RUNNER_ID
        and management.get("profile_request_keys") == ["document", "status"]
        and management.get("runner_request_keys") == ["document", "status"]
        and management.get("signed_action_package_controls_visible") is True
        and management.get("arbitrary_package_code_input") is False
        and management.get("detection_hypothesis_saved") is True
        and management.get("detection_hypothesis_title") == "Gate 08 operator hypothesis"
    )

    live = _mapping(browser.get("live_workflow"), "live-workflow evidence is absent")
    _exact(
        live,
        {
            "run_id",
            "baseline_run_id",
            "replay_run_id",
            "comparison_id",
            "preflight_ready",
            "timeline",
            "planner",
            "policy",
            "live_graph",
            "runner",
            "evidence",
            "detections",
            "ai_proposal_diff",
            "replay_diff",
            "source_provenance",
        },
        "the GATE-08 live-workflow evidence is not exact",
    )
    live_ok = bool(
        all(
            isinstance(live.get(name), str) and _RUN_ID.fullmatch(str(live[name]))
            for name in ("run_id", "baseline_run_id", "replay_run_id")
        )
        and isinstance(live.get("comparison_id"), str)
        and _COMPARISON_ID.fullmatch(str(live["comparison_id"]))
        and all(
            live.get(name) is True
            for name in (
                "preflight_ready",
                "timeline",
                "planner",
                "policy",
                "live_graph",
                "runner",
                "evidence",
                "detections",
                "ai_proposal_diff",
                "replay_diff",
                "source_provenance",
            )
        )
    )

    canonical = _mapping(browser.get("canonical_requests"), "canonical request evidence is absent")
    _exact(
        canonical,
        {
            "preflight_keys",
            "run_keys",
            "replay_keys",
            "comparison_keys",
            "visible_controls_bound",
        },
        "the canonical request evidence is not exact",
    )
    canonical_keys = [
        "ai_provider_id",
        "autonomy",
        "layout",
        "mode",
        "runner_profile_id",
        "scenario",
        "target_scope",
    ]
    canonical_ok = bool(
        canonical.get("preflight_keys") == canonical_keys
        and canonical.get("run_keys") == canonical_keys
        and canonical.get("replay_keys") == ["exact"]
        and canonical.get("comparison_keys") == ["run_ids"]
        and canonical.get("visible_controls_bound") is True
    )
    _require(
        browser.get("screenshots") == [Path(path).name for path in SCREENSHOT_ARTIFACTS],
        "the GATE-08 browser screenshot inventory is not exact",
    )
    return {
        "authoring": authoring_ok,
        "graph": graph_ok,
        "configuration": configuration_ok,
        "management": management_ok,
        "live": live_ok,
        "canonical": canonical_ok,
    }


def _validate_journey(
    evidence_dir: Path,
    journey: Mapping[str, Any],
    browser: Mapping[str, Any],
) -> tuple[tuple[Mapping[str, str], ...], Mapping[str, Any]]:
    _exact(
        journey,
        {
            "schema_version",
            "passed",
            "run_bundles",
            "roles",
            "comparison_id",
            "screenshots",
            "product_database",
            "preference_key",
            "runner_profile_id",
            "runner_record_id",
            "browser_report",
            "browser_report_sha256",
        },
        "the GATE-08 journey report schema is not exact",
    )
    _require(
        journey.get("schema_version") == JOURNEY_SCHEMA
        and journey.get("passed") is True
        and journey.get("product_database") == PRODUCT_DB_ARTIFACT
        and journey.get("preference_key") == "ui.preferences"
        and journey.get("runner_profile_id") == PROFILE_ID
        and journey.get("runner_record_id") == RUNNER_ID
        and journey.get("browser_report") == BROWSER_REPORT,
        "the GATE-08 journey identity is invalid",
    )
    browser_payload = (evidence_dir / BROWSER_REPORT).read_bytes()
    _require(
        journey.get("browser_report_sha256")
        == "sha256:" + hashlib.sha256(browser_payload).hexdigest(),
        "the GATE-08 journey is not bound to its browser report",
    )
    raw_bundles = journey.get("run_bundles")
    _require(isinstance(raw_bundles, list) and len(raw_bundles) == 4, "run bundles are incomplete")
    raw_bundles = cast(list[Any], raw_bundles)
    bundles: list[Mapping[str, str]] = []
    for raw in raw_bundles:
        bundle = _mapping(raw, "a GATE-08 run-bundle reference is invalid")
        _require(set(bundle) == {"run_id", "path"}, "a GATE-08 run-bundle shape is invalid")
        run_id = bundle.get("run_id")
        _require(
            isinstance(run_id, str)
            and _RUN_ID.fullmatch(run_id) is not None
            and bundle.get("path") == f"runs/{run_id}",
            "a GATE-08 run-bundle identity is invalid",
        )
        run_id = cast(str, run_id)
        bundles.append({"run_id": run_id, "path": str(bundle["path"])})
    roles = _mapping(journey.get("roles"), "GATE-08 run roles are absent")
    _exact(roles, set(_RUN_ROLE_SEQUENCE), "GATE-08 run roles are not exact")
    _require(
        [roles[role] for role in _RUN_ROLE_SEQUENCE] == [bundle["run_id"] for bundle in bundles],
        "run roles do not match bundles",
    )
    live = _mapping(browser["live_workflow"], "browser live workflow is absent")
    _require(
        roles["seeded_baseline"] == live["baseline_run_id"]
        and roles["browser_run"] == live["run_id"]
        and roles["browser_exact_replay"] == live["replay_run_id"]
        and journey.get("comparison_id") == live["comparison_id"],
        "journey and browser run identities diverge",
    )

    raw_screenshots = journey.get("screenshots")
    _require(
        isinstance(raw_screenshots, list) and len(raw_screenshots) == 3,
        "screenshots are incomplete",
    )
    raw_screenshots = cast(list[Any], raw_screenshots)
    expected_paths = list(SCREENSHOT_ARTIFACTS)
    for expected, raw in zip(expected_paths, raw_screenshots, strict=True):
        artifact = _mapping(raw, "a screenshot artifact record is invalid")
        _require(
            set(artifact) == {"path", "size_bytes", "sha256"}
            and artifact.get("path") == expected
            and isinstance(artifact.get("size_bytes"), int)
            and 8 < int(artifact["size_bytes"]) <= _MAX_SCREENSHOT_BYTES
            and isinstance(artifact.get("sha256"), str)
            and _SHA256.fullmatch(str(artifact["sha256"])) is not None,
            "a screenshot artifact record is invalid",
        )
        path = evidence_dir / expected
        details = path.lstat()
        payload = path.read_bytes()
        _require(
            stat.S_ISREG(details.st_mode)
            and not _is_unsafe(details)
            and len(payload) == artifact["size_bytes"]
            and payload.startswith(b"\x89PNG\r\n\x1a\n")
            and artifact["sha256"] == "sha256:" + hashlib.sha256(payload).hexdigest(),
            "a screenshot does not match its content-addressed record",
        )
    return tuple(bundles), roles


def _authored_scenario_matches(
    scenarios: list[Mapping[str, Any]],
    authoring: Mapping[str, Any],
) -> bool:
    matches = [
        scenario
        for scenario in scenarios
        if scenario.get("scenario_id") == authoring.get("scenario_id")
    ]
    return bool(
        len(matches) == 1
        and matches[0].get("version") == authoring.get("version")
        and isinstance(matches[0].get("document"), Mapping)
        and matches[0]["document"].get("title") == authoring.get("scenario_title")
    )


def _validate_persistence(
    repository: Path,
    evidence_dir: Path,
    browser: Mapping[str, Any],
    roles: Mapping[str, Any],
) -> Mapping[str, bool]:
    store = RunStore(evidence_dir / "runs")
    runs: dict[str, Mapping[str, Any]] = {}
    for role, run_id in roles.items():
        _require(isinstance(run_id, str), "a GATE-08 run role is invalid")
        _require(
            store.validate_bundle(run_id).get("valid") is True, "a GATE-08 run failed integrity"
        )
        run = store.get_run(run_id)
        _require(run.get("status") == "completed", "a GATE-08 run is not finalized")
        runs[role] = run
    baseline = runs["seeded_baseline"]
    variant = runs["seeded_autonomy_variant"]
    browser_run = runs["browser_run"]
    replay = runs["browser_exact_replay"]
    ai_ok = bool(
        baseline.get("scenario_id") == "scenario.ai-adaptive.safe-chain.v1"
        and baseline.get("autonomy") == "auto"
        and isinstance(baseline.get("ai_proposals"), list)
        and len(baseline["ai_proposals"]) > 0
        and variant.get("autonomy") == "assist"
        and isinstance(variant.get("replay"), Mapping)
        and variant["replay"].get("source_run_id") == baseline["run_id"]
        and browser_run.get("mode") == "simulate"
        and browser_run.get("autonomy") == "auto"
        and isinstance(browser_run.get("ai_proposals"), list)
        and len(browser_run["ai_proposals"]) > 0
        and isinstance(replay.get("replay"), Mapping)
        and replay["replay"].get("source_run_id") == browser_run["run_id"]
    )
    comparison = compare_runs(store, [str(baseline["run_id"]), str(replay["run_id"])])
    deltas = comparison.get("deltas")
    compare_ok = bool(
        comparison.get("comparison_id") == browser["live_workflow"]["comparison_id"]  # type: ignore[index]
        and isinstance(deltas, list)
        and len(deltas) == 1
        and isinstance(deltas[0], Mapping)
        and deltas[0].get("assessment") != "no_material_change"
    )

    product = ProductStore(evidence_dir / PRODUCT_DB_ARTIFACT)
    settings = product.list_settings()
    preferences_ok = bool(
        len(settings) == 1
        and settings[0].get("key") == "ui.preferences"
        and settings[0].get("value")
        == {
            "schema_version": "bluefire.ui-preferences.v1",
            "theme": "light",
            "effect_mode": "simulate",
            "autonomy": "auto",
        }
    )
    scenarios = product.list_scenarios()
    authoring = _mapping(browser["scenario_authoring"], "scenario authoring is absent")
    scenario_ok = _authored_scenario_matches(scenarios, authoring)
    profile = product.get_resource("runner_profile", PROFILE_ID)
    runner = product.get_resource("runner", RUNNER_ID)
    resources_ok = bool(
        profile.get("status") == "draft"
        and runner.get("status") == "draft"
        and isinstance(profile.get("document"), Mapping)
        and "secrets" not in profile["document"]
        and isinstance(runner.get("document"), Mapping)
        and runner["document"].get("connectivity") == "not_verified"
    )
    detections = product.list_resources("detection")
    detection_ok = any(
        isinstance(item.get("document"), Mapping)
        and item["document"].get("title") == "Gate 08 operator hypothesis"
        and item["document"].get("state") == "hypothesis"
        for item in detections
    )

    builder_source = (repository / "frontend" / "src" / "pages" / "Builder.tsx").read_text(
        encoding="utf-8"
    )
    runs_source = (repository / "frontend" / "src" / "pages" / "Runs.tsx").read_text(
        encoding="utf-8"
    )
    package_source = (repository / "frontend" / "src" / "pages" / "ActionPackages.tsx").read_text(
        encoding="utf-8"
    )
    structural_ok = bool(
        "Behavior palette width" in builder_source
        and "Node inspector width" in builder_source
        and "Environment <em>profile + scope</em>" in builder_source
        and "Review before durable job creation" in runs_source
        and "Raw complete approval envelope" in runs_source
        and runs_source.index("Review before durable job creation")
        < runs_source.index("Raw complete approval envelope")
        and "raw editor" not in package_source.lower()
        and not re.search(
            r'(?:label|aria-label)=["\'](?:raw )?(?:shell|command)(?: input)?["\']',
            "\n".join((builder_source, runs_source, package_source)),
            re.IGNORECASE,
        )
    )
    return {
        "ai": ai_ok,
        "comparison": compare_ok,
        "preferences": preferences_ok,
        "scenario": scenario_ok,
        "resources": resources_ok,
        "detection": detection_ok,
        "structural": structural_ok,
    }


def validate_persisted_operator_ui_gate(
    repository: Path,
    evidence_dir: Path,
) -> tuple[Mapping[str, bool], tuple[Mapping[str, str], ...]]:
    root = repository.resolve(strict=True)
    destination = evidence_dir.resolve(strict=True)
    browser = _read_json(destination / BROWSER_REPORT)
    journey = _read_json(destination / JOURNEY_REPORT)
    browser_checks = _validate_browser(browser)
    bundles, roles = _validate_journey(destination, journey, browser)
    persisted = _validate_persistence(root, destination, browser, roles)
    checks = {
        "scenario_authoring": browser_checks["authoring"] and persisted["scenario"],
        "graph_editor": browser_checks["graph"],
        "layers_branches_parameters": browser_checks["graph"],
        "safety_collectors_detections": browser_checks["live"] and persisted["detection"],
        "ai_replay_diff": browser_checks["live"] and persisted["ai"] and persisted["comparison"],
        "accessibility_palette": browser_checks["graph"],
        "mode_autonomy_providers": browser_checks["configuration"],
        "runner_pack_management": browser_checks["management"] and persisted["resources"],
        "live_workflow": browser_checks["live"],
        "provenance_settings": browser_checks["configuration"] and persisted["preferences"],
        "no_raw_shell_approval": persisted["structural"],
        "canonical_requests": browser_checks["canonical"],
    }
    _require(set(checks) == CHECK_NAMES, "the GATE-08 semantic check inventory is incomplete")
    return checks, bundles


__all__ = [
    "CHECK_NAMES",
    "OperatorUIGateValidationError",
    "validate_persisted_operator_ui_gate",
]
