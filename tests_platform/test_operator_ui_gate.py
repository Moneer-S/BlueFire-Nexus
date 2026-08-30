from __future__ import annotations

import copy
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Mapping

import pytest

import bluefire.operator_ui_gate as operator_ui_gate
import bluefire.product_gates as product_gates
import tools.run_operator_ui_gate_journey as journey_helper
from bluefire.operator_ui_gate_validation import (
    _RUN_ROLE_SEQUENCE,
    CHECK_NAMES,
    OperatorUIGateValidationError,
    _authored_scenario_matches,
    _validate_browser,
)
from bluefire.operator_ui_journey import (
    BROWSER_SCHEMA,
    HELPER_SCHEMA,
    OPERATION_SEQUENCE,
    REPORT_PATHS,
    SCREENSHOT_ARTIFACTS,
    OperatorUIJourneyError,
)
from bluefire.product_acceptance import load_release_contract
from bluefire.util import content_hash

ROOT = Path(__file__).resolve().parents[1]


def _gate() -> Any:
    return next(gate for gate in load_release_contract().gates if gate.gate_id == "GATE-08")


def _browser_report() -> dict[str, Any]:
    run_ids = [
        "run-20260829T120000Z-0123456789abcdef",
        "run-20260829T120001Z-1123456789abcdef",
        "run-20260829T120002Z-2123456789abcdef",
    ]
    return {
        "schema_version": BROWSER_SCHEMA,
        "production_browser_interaction": True,
        "demo_mode": False,
        "origin": "http://127.0.0.1:43180",
        "operation_sequence": list(OPERATION_SEQUENCE),
        "scenario_authoring": {
            "exported": True,
            "created_draft": True,
            "imported": True,
            "validated": True,
            "versioned": True,
            "scenario_id": "scenario.test.v1",
            "scenario_title": "Example · Gate 08 operator proof",
            "version": 1,
            "request_keys": ["scenario"],
        },
        "graph_editor": {
            "initial_nodes": 3,
            "graph_edges": 2,
            "typed_handles": 4,
            "layers": ["environment", "behavior", "evidence"],
            "branch_outcomes": ["success", "partial", "blocked", "failed"],
            "undo_redo_copy_paste": True,
            "keyboard_command_palette": True,
            "focus_mode": True,
            "collapsible_panels": True,
            "resizable_panels": True,
            "palette_width_px": 380,
            "inspector_width_px": 420,
            "compatibility_feedback": True,
            "parameters_actions_observables_visible": True,
        },
        "configuration": {
            "effect_modes": ["simulate", "execute"],
            "autonomy_levels": ["off", "assist", "auto"],
            "provider_id": "deterministic-offline.v1",
            "profile_id": "sandbox-simulate.v1",
            "target_scope": {"scope_refs": ["sandbox.workspace"]},
            "settings_changed_backend_request": True,
            "strict_preference_fields": [
                "autonomy",
                "effect_mode",
                "schema_version",
                "theme",
            ],
            "approval_human_first": True,
            "raw_shell_input": False,
        },
        "management": {
            "runner_profile_id": "gate08.operator.profile.v1",
            "runner_record_id": "gate08.operator.runner.v1",
            "profile_request_keys": ["document", "status"],
            "runner_request_keys": ["document", "status"],
            "signed_action_package_controls_visible": True,
            "arbitrary_package_code_input": False,
            "detection_hypothesis_saved": True,
            "detection_hypothesis_title": "Gate 08 operator hypothesis",
        },
        "live_workflow": {
            "run_id": run_ids[0],
            "baseline_run_id": run_ids[1],
            "replay_run_id": run_ids[2],
            "comparison_id": "comparison-0123456789abcdefabcd",
            "preflight_ready": True,
            "timeline": True,
            "planner": True,
            "policy": True,
            "live_graph": True,
            "runner": True,
            "evidence": True,
            "detections": True,
            "ai_proposal_diff": True,
            "replay_diff": True,
            "source_provenance": True,
        },
        "canonical_requests": {
            "preflight_keys": [
                "ai_provider_id",
                "autonomy",
                "layout",
                "mode",
                "runner_profile_id",
                "scenario",
                "target_scope",
            ],
            "run_keys": [
                "ai_provider_id",
                "autonomy",
                "layout",
                "mode",
                "runner_profile_id",
                "scenario",
                "target_scope",
            ],
            "replay_keys": ["exact"],
            "comparison_keys": ["run_ids"],
            "visible_controls_bound": True,
        },
        "screenshots": [Path(path).name for path in SCREENSHOT_ARTIFACTS],
        "observed_at": "2026-08-29T12:00:00Z",
    }


def _passing_gate_dependencies(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Mapping[str, bool], tuple[Mapping[str, str], ...]]:
    checks = {name: True for name in CHECK_NAMES}
    bundles = tuple(
        {
            "run_id": f"run-20260829T12000{index}Z-{index}123456789abcdef",
            "path": f"runs/run-20260829T12000{index}Z-{index}123456789abcdef",
        }
        for index in range(4)
    )
    monkeypatch.setattr(
        operator_ui_gate,
        "_run_helper",
        lambda *_args: {
            "passed": True,
            "exit_code": 0,
            "command": ["{python}", "tools/run_operator_ui_gate_journey.py"],
            "protocol_valid": True,
        },
    )
    monkeypatch.setattr(operator_ui_gate, "_run_frontend_suite", lambda *_args: {"passed": True})
    monkeypatch.setattr(operator_ui_gate, "_frontend_suite_is_exact", lambda _value: True)
    monkeypatch.setattr(
        operator_ui_gate,
        "_run_pytest_suite",
        lambda *_args, **_kwargs: {"passed": True, "suite_id": "operator-ui-contracts"},
    )
    monkeypatch.setattr(operator_ui_gate, "_suite_is_exact", lambda _value: True)
    monkeypatch.setattr(
        operator_ui_gate,
        "validate_persisted_operator_ui_gate",
        lambda *_args: (checks, bundles),
    )
    monkeypatch.setattr(operator_ui_gate, "_acceptance_binding", lambda: {"gate_id": "GATE-08"})
    monkeypatch.setattr(
        operator_ui_gate,
        "validated_run_bundle",
        lambda _gate, _root, raw, **_kwargs: (dict(raw), {}),
    )
    return checks, bundles


def test_gate08_workflow_is_registered() -> None:
    assert product_gates._WORKFLOWS["GATE-08"] is product_gates._gate_08_workflow


def test_gate08_locked_contract_matches_authoritative_workflow() -> None:
    contract = {assertion.assertion_id: assertion.proof for assertion in _gate().assertions}
    expected = {
        assertion_id: row[0] for assertion_id, row in operator_ui_gate._EXPECTED_ASSERTIONS.items()
    }

    assert contract == expected
    assert len(contract) == 12
    assert set(contract.values()) == {"dynamic", "structural"}
    assert len({row[3] for row in operator_ui_gate._EXPECTED_ASSERTIONS.values()}) == 12


def test_gate08_check_and_operation_inventories_are_exact() -> None:
    assert CHECK_NAMES == {
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
    assert len(OPERATION_SEQUENCE) == len(set(OPERATION_SEQUENCE)) == 19
    assert _RUN_ROLE_SEQUENCE == (
        "seeded_baseline",
        "seeded_autonomy_variant",
        "browser_run",
        "browser_exact_replay",
    )


def test_production_browser_harness_is_separate_and_fail_closed() -> None:
    default_config = (ROOT / "frontend" / "playwright.config.ts").read_text(encoding="utf-8")
    config = (ROOT / "frontend" / "playwright.operator.config.ts").read_text(encoding="utf-8")
    spec = (ROOT / "frontend" / "tests" / "e2e" / "operator-production.spec.ts").read_text(
        encoding="utf-8"
    )

    assert 'testIgnore: ["**/*-production.spec.ts"]' in default_config
    assert 'testMatch: "operator-production.spec.ts"' in config
    assert "VITE_DEMO_MODE" in config and "cannot run in demo mode" in config
    assert "CAPABILITY_FRAGMENT" in config and "LOOPBACK_HOSTS" in config
    assert all(
        path in spec for path in ("/api/v1/runs/preflight", "/api/v1/runs", "/api/v1/comparisons")
    )
    assert all(Path(path).name in spec for path in SCREENSHOT_ARTIFACTS)


def test_builder_exposes_resizable_panels_and_three_semantic_layers() -> None:
    source = (ROOT / "frontend" / "src" / "pages" / "Builder.tsx").read_text(encoding="utf-8")

    assert 'aria-label="Behavior palette width"' in source
    assert 'aria-label="Node inspector width"' in source
    assert "Environment <em>profile + scope</em>" in source
    assert "Behavior <em>typed intent</em>" in source
    assert "Evidence <em>artifacts + telemetry</em>" in source


def test_gate08_frontend_environment_scrubs_secrets_and_isolates_home(tmp_path: Path) -> None:
    environment = operator_ui_gate._frontend_environment(tmp_path)

    assert environment["HOME"] == str(tmp_path / "home")
    assert environment["USERPROFILE"] == str(tmp_path / "home")
    assert environment["VITE_DEMO_MODE"] == "false"
    assert all("TOKEN" not in key.upper() and "SECRET" not in key.upper() for key in environment)


def test_vitest_inventory_is_canonical_and_rejects_escaped_paths(tmp_path: Path) -> None:
    frontend = tmp_path / "frontend"
    test_file = frontend / "src" / "example.test.ts"
    test_file.parent.mkdir(parents=True)
    test_file.write_text("test", encoding="utf-8")
    report = {
        "testResults": [
            {
                "name": str(test_file),
                "assertionResults": [
                    {"status": "passed", "title": "works", "ancestorTitles": ["Example"]}
                ],
            }
        ]
    }

    assert operator_ui_gate._vitest_ids(report, frontend) == ["src/example.test.ts::Example::works"]
    escaped = copy.deepcopy(report)
    outside = tmp_path / "outside.test.ts"
    outside.write_text("test", encoding="utf-8")
    escaped["testResults"][0]["name"] = str(outside)
    with pytest.raises(ValueError, match="escaped"):
        operator_ui_gate._vitest_ids(escaped, frontend)


def test_frontend_suite_is_bound_to_exact_passed_inventory(monkeypatch: pytest.MonkeyPatch) -> None:
    tests = ["src/a.test.ts::A::one", "src/b.test.ts::B::two"]
    monkeypatch.setattr(operator_ui_gate, "_EXPECTED_FRONTEND_TEST_COUNT", len(tests))
    monkeypatch.setattr(operator_ui_gate, "_EXPECTED_FRONTEND_TESTS_SHA256", content_hash(tests))
    report = {
        "schema_version": operator_ui_gate.FRONTEND_SCHEMA,
        "passed": True,
        "commands": {},
        "exit_codes": {"typecheck": 0, "lint": 0, "unit": 0},
        "tests": len(tests),
        "passed_tests": tests,
        "failed_tests": [],
        "skipped_tests": [],
    }

    assert operator_ui_gate._frontend_suite_is_exact(report) is True
    report["passed_tests"] = tests[:-1]
    assert operator_ui_gate._frontend_suite_is_exact(report) is False


def test_contract_suite_is_bound_to_exact_passed_inventory(monkeypatch: pytest.MonkeyPatch) -> None:
    tests = ["tests_platform.test_operator_ui_gate::test_inventory_binding"]
    monkeypatch.setattr(operator_ui_gate, "_EXPECTED_CONTRACT_TEST_COUNT", len(tests))
    monkeypatch.setattr(operator_ui_gate, "_EXPECTED_CONTRACT_TESTS_SHA256", content_hash(tests))
    report = {
        "schema_version": "bluefire.architecture-dynamic-check.v1",
        "suite_id": "operator-ui-contracts",
        "command": [
            "{python}",
            "-m",
            "pytest",
            "-p",
            "no:cacheprovider",
            "-q",
            *operator_ui_gate._CONTRACT_TESTS,
            "--junitxml={temporary}",
        ],
        "exit_code": 0,
        "passed": True,
        "tests": len(tests),
        "passed_tests": tests,
        "failed_tests": [],
        "skipped_tests": [],
    }

    assert operator_ui_gate._suite_is_exact(report) is True
    report["skipped_tests"] = [tests[0]]
    assert operator_ui_gate._suite_is_exact(report) is False


def test_browser_validator_accepts_exact_semantics_and_rejects_schema_drift() -> None:
    report = _browser_report()

    assert all(_validate_browser(report).values())
    authoring = report["scenario_authoring"]
    scenarios = [
        {"scenario_id": "scenario.seeded.v1", "version": 1, "document": {"title": "Seeded"}},
        {
            "scenario_id": authoring["scenario_id"],
            "version": authoring["version"],
            "document": {"title": authoring["scenario_title"]},
        },
    ]
    assert _authored_scenario_matches(scenarios, authoring)
    assert not _authored_scenario_matches(scenarios + [dict(scenarios[-1])], authoring)
    report["unexpected"] = True
    with pytest.raises(OperatorUIGateValidationError, match="schema is not exact"):
        _validate_browser(report)


def test_gate08_emits_one_exact_proof_per_assertion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    _checks, bundles = _passing_gate_dependencies(monkeypatch)

    outcome = operator_ui_gate.run_gate_08(_gate(), evidence, repository_root=ROOT)

    assert outcome.status == "passed"
    assert outcome.failure_reason is None
    assert len(outcome.proofs) == 12
    assert len({proof["test_id"] for proof in outcome.proofs}) == 12
    assert {proof["kind"] for proof in outcome.proofs} == {"dynamic", "structural"}
    assert all(
        proof["run_bundles"] == list(bundles)
        and proof["run_ids"] == [bundle["run_id"] for bundle in bundles]
        and proof["environment_limitations"] == []
        for proof in outcome.proofs
    )
    assert (evidence / operator_ui_gate.VERIFICATION_REPORT).is_file()


def test_gate08_fails_closed_for_contract_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    monkeypatch.setattr(
        operator_ui_gate,
        "_run_helper",
        lambda *_args: pytest.fail("helper must not run for a mismatched contract"),
    )

    outcome = operator_ui_gate.run_gate_08(
        SimpleNamespace(assertions=()), evidence, repository_root=ROOT
    )

    assert outcome.status == "failed"
    assert outcome.proofs == ()
    assert "assertion set mismatch" in str(outcome.failure_reason)


def test_gate08_refuses_stale_owned_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / operator_ui_gate.FRONTEND_REPORT).write_text("stale", encoding="utf-8")
    monkeypatch.setattr(
        operator_ui_gate,
        "_run_helper",
        lambda *_args: pytest.fail("helper must not run with stale evidence"),
    )

    outcome = operator_ui_gate.run_gate_08(_gate(), evidence, repository_root=ROOT)

    assert outcome.status == "failed"
    assert "stale owned artifacts" in str(outcome.failure_reason)


def test_gate08_rejects_incomplete_semantic_check_inventory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    checks, bundles = _passing_gate_dependencies(monkeypatch)
    incomplete = dict(checks)
    incomplete.pop("canonical_requests")
    monkeypatch.setattr(
        operator_ui_gate,
        "validate_persisted_operator_ui_gate",
        lambda *_args: (incomplete, bundles),
    )

    outcome = operator_ui_gate.run_gate_08(_gate(), evidence, repository_root=ROOT)

    assert outcome.status == "failed"
    assert outcome.proofs == ()
    assert "semantic check inventory" in str(outcome.failure_reason)


def test_gate08_failure_redacts_private_paths() -> None:
    outcome = operator_ui_gate._failure((r"C:\private\operator\report.json failed",))

    assert outcome.status == "failed"
    assert outcome.proofs == ()
    assert "C:\\private" not in str(outcome.failure_reason)
    assert "private-path-redacted" in str(outcome.failure_reason)


def test_fixed_helper_requires_both_persisted_reports(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()

    def produce(_repository: Path, destination: Path) -> Mapping[str, object]:
        for relative in REPORT_PATHS:
            (destination / relative).write_text("{}", encoding="utf-8")
        return {
            "schema_version": HELPER_SCHEMA,
            "status": "passed",
            "reports": list(REPORT_PATHS),
            "run_count": 4,
            "blocking_check": None,
        }

    monkeypatch.setattr(journey_helper, "produce_operator_ui_gate_evidence", produce)
    summary = journey_helper.run_operator_ui_gate_journey(ROOT, evidence)
    assert summary["status"] == "passed"

    (evidence / REPORT_PATHS[-1]).unlink()
    monkeypatch.setattr(
        journey_helper,
        "produce_operator_ui_gate_evidence",
        lambda *_args: summary,
    )
    with pytest.raises(OperatorUIJourneyError, match="omitted"):
        journey_helper.run_operator_ui_gate_journey(ROOT, evidence)
