from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import bluefire.defense_frontier as frontier_module
import bluefire.defense_frontier_gate as gate_module
import bluefire.defense_frontier_validation as validation_module
import bluefire.product_gates as product_gates
from bluefire.defense_frontier import (
    PROVIDER_ID,
    REAL_PROVIDER_ID,
    SCENARIO_ID,
    STRUCTURAL_SCHEMA,
    DefenseFrontierError,
)
from bluefire.defense_frontier_validation import DefenseFrontierValidationError, load_report
from bluefire.runner_bootstrap import RunnerBootstrapError
from bluefire.util import content_hash, file_hash

REPOSITORY = Path(__file__).resolve().parents[1]


def test_token_known_folder_access_includes_query_and_impersonate() -> None:
    assert frontier_module._TOKEN_KNOWN_FOLDER_ACCESS == 0x000C


@pytest.mark.skipif(os.name != "nt", reason="Windows token-known-folder contract")
def test_runtime_temp_parent_ignores_isolated_environment_aliases(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    poisoned = tmp_path / "environment-controlled-profile"
    local = poisoned / "AppData" / "Local"
    roaming = poisoned / "AppData" / "Roaming"
    local.mkdir(parents=True)
    roaming.mkdir(parents=True)
    for name, value in {
        "HOME": poisoned,
        "USERPROFILE": poisoned,
        "LOCALAPPDATA": local,
        "APPDATA": roaming,
        "TEMP": local,
        "TMP": local,
    }.items():
        monkeypatch.setenv(name, os.fspath(value))

    parent = frontier_module._runtime_temp_parent()

    assert parent.is_dir()
    assert parent != local.resolve()
    assert not parent.is_relative_to(poisoned.resolve())


def test_external_native_runtime_is_removed_when_bootstrap_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime_parent = tmp_path / "token-temp"
    evidence = tmp_path / "evidence"
    runtime_parent.mkdir()
    evidence.mkdir()
    monkeypatch.setattr(
        frontier_module,
        "_runtime_temp_parent",
        lambda: runtime_parent,
    )

    def unavailable(**_kwargs: object) -> object:
        raise RunnerBootstrapError("unavailable")

    monkeypatch.setattr(frontier_module, "bootstrap_runner", unavailable)

    with pytest.raises(DefenseFrontierError, match="packaged native runner"):
        frontier_module.produce_defense_frontier_evidence(REPOSITORY, evidence)

    assert list(runtime_parent.iterdir()) == []


def test_runtime_removal_still_happens_when_service_shutdown_fails(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    (runtime / "private-state").write_bytes(b"sensitive")
    shutdown_failure = RuntimeError("shutdown failed")
    close_calls = 0

    def fail_shutdown() -> None:
        nonlocal close_calls
        close_calls += 1
        if close_calls == 1:
            raise shutdown_failure

    with pytest.raises(RuntimeError) as caught:
        frontier_module._close_runtime_and_remove(runtime, fail_shutdown)

    assert caught.value is shutdown_failure
    assert close_calls == 2
    assert not runtime.exists()


def test_runtime_cleanup_preserves_shutdown_and_removal_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    shutdown_failure = RuntimeError("shutdown failed")
    removal_failure = OSError("removal failed")
    close_calls = 0
    removal_calls = 0
    real_rmtree = frontier_module.shutil.rmtree

    def fail_shutdown() -> None:
        nonlocal close_calls
        close_calls += 1
        if close_calls == 1:
            raise shutdown_failure

    def fail_removal(target: Path) -> None:
        nonlocal removal_calls
        removal_calls += 1
        if removal_calls == 1:
            raise removal_failure
        real_rmtree(target)

    monkeypatch.setattr(frontier_module.shutil, "rmtree", fail_removal)

    with pytest.raises(frontier_module._RuntimeCleanupError) as caught:
        frontier_module._close_runtime_and_remove(runtime, fail_shutdown)

    assert caught.value.failures == (shutdown_failure, removal_failure)
    assert caught.value.__cause__ is shutdown_failure
    assert close_calls == 2
    assert removal_calls == 2
    assert not runtime.exists()


def test_runtime_cleanup_rejects_a_noop_removal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    monkeypatch.setattr(frontier_module.shutil, "rmtree", lambda _runtime: None)

    with pytest.raises(DefenseFrontierError, match="runtime was not removed"):
        frontier_module._close_runtime_and_remove(runtime, lambda: None)


def _structural_report() -> dict[str, Any]:
    source = REPOSITORY / "scenarios" / "ai_adaptive_safe_chain.yaml"
    packaged = REPOSITORY / "bluefire" / "data" / source.name
    return {
        "schema_version": STRUCTURAL_SCHEMA,
        "passed": True,
        "scenario_contract": {
            "scenario_id": SCENARIO_ID,
            "source_sha256": file_hash(source),
            "packaged_sha256": file_hash(packaged),
        },
        "real_provider_contract": {
            "provider_id": REAL_PROVIDER_ID,
            "kind": "openai_responses",
            "endpoint_scheme": "https",
            "credential_reference": "OPENAI_API_KEY",
            "fallback_provider_id": PROVIDER_ID,
            "manual_key_required_for_release": False,
            "proposal_only": True,
        },
    }


@pytest.mark.parametrize(
    ("section", "field", "replacement", "message"),
    [
        (
            "scenario_contract",
            "source_sha256",
            "sha256:" + "0" * 64,
            "scenario packaging contract",
        ),
        (
            "real_provider_contract",
            "endpoint_scheme",
            "http",
            "provider contract",
        ),
    ],
)
def test_structural_validation_rejects_material_contract_tampering(
    section: str,
    field: str,
    replacement: str,
    message: str,
) -> None:
    report = _structural_report()
    validation_module._validate_structural(report, REPOSITORY)

    report[section][field] = replacement

    with pytest.raises(DefenseFrontierValidationError, match=message):
        validation_module._validate_structural(report, REPOSITORY)


def test_load_report_accepts_only_a_bounded_json_object(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report_path = tmp_path / "report.json"
    report_path.write_text('{"passed":true}\n', encoding="utf-8")
    assert load_report(report_path) == {"passed": True}

    monkeypatch.setattr(validation_module, "_REPORT_LIMIT", report_path.stat().st_size - 1)
    with pytest.raises(DefenseFrontierValidationError, match="exceeded its byte bound"):
        load_report(report_path)


class _SymlinkReportPath:
    def is_file(self) -> bool:
        return True

    def is_symlink(self) -> bool:
        return True

    def stat(self) -> None:
        raise AssertionError("a symlink must be rejected before metadata is read")

    def read_text(self, *, encoding: str) -> str:
        raise AssertionError("a symlink must be rejected before content is read")


def test_load_report_rejects_symlink_before_reading_it() -> None:
    with pytest.raises(DefenseFrontierValidationError, match="report is unavailable"):
        load_report(_SymlinkReportPath())  # type: ignore[arg-type]


@pytest.mark.parametrize("mutation", ["extra_step", "action_swap"])
def test_locked_native_path_rejects_unapproved_rows(mutation: str) -> None:
    steps = [
        {
            "step_id": step_id,
            "behavior_id": behavior_id,
            "action_id": action_id,
            "status": status,
        }
        for step_id, behavior_id, action_id, status in validation_module._CANONICAL_PATH
    ]
    if mutation == "extra_step":
        steps.insert(
            -1,
            {
                "step_id": "unapproved_effect",
                "behavior_id": "sandbox.export.local.v1",
                "action_id": "sandbox.export.local.v1",
                "status": "success",
            },
        )
    else:
        steps[0]["action_id"] = "sandbox.export.local.v1"

    with pytest.raises(DefenseFrontierValidationError, match="locked scenario path"):
        validation_module._validate_locked_execution_path(
            {"steps": steps}, validation_module._CANONICAL_PATH
        )


def test_gate_helper_environment_passes_only_explicit_acceptance_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for name in gate_module._ACCEPTANCE_ENVIRONMENT:
        monkeypatch.setenv(name, f"value-for-{name.lower()}")
    monkeypatch.setenv("OPENAI_API_KEY", "must-not-cross-the-gate")
    monkeypatch.setenv("BLUEFIRE_PRIVATE_VALUE", "must-not-cross-the-gate")

    environment = gate_module._isolated_python_environment(
        tmp_path,
        passthrough=gate_module._ACCEPTANCE_ENVIRONMENT,
    )

    assert {name: environment[name] for name in gate_module._ACCEPTANCE_ENVIRONMENT} == {
        name: f"value-for-{name.lower()}" for name in gate_module._ACCEPTANCE_ENVIRONMENT
    }
    assert "OPENAI_API_KEY" not in environment
    assert "BLUEFIRE_PRIVATE_VALUE" not in environment
    assert environment["PYTHONDONTWRITEBYTECODE"] == "1"
    assert environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] == "1"
    assert {environment[name] for name in ("TEMP", "TMP", "TMPDIR")} == {str(tmp_path.resolve())}
    if gate_module.os.name == "nt":
        assert Path(environment["PATH"]).name.casefold() == "system32"


def _approval_run(binding: dict[str, str]) -> dict[str, Any]:
    intent_id = "intent-" + content_hash(binding).removeprefix("sha256:")[:32]
    approval = {
        "schema_version": "bluefire.approval-request.v1",
        "approval_id": "approval-" + "a" * 32,
        "run_id": intent_id,
        **binding,
        "status": "claimed",
        "requested_at": "2026-08-28T00:00:00Z",
        "expires_at": "2026-08-28T00:10:00Z",
        "approved_at": "2026-08-28T00:01:00Z",
        "approved_by": "gate-04-reviewer",
        "consumed_at": "2026-08-28T00:02:00Z",
        "claimed_at": "2026-08-28T00:03:00Z",
    }
    target_scope = {"kind": "disposable-fixture"}
    provider = {"provider_id": PROVIDER_ID}
    return {
        "approval": approval,
        "policy": {
            "approval": dict(approval),
            "approval_binding": dict(binding),
            "approval_context": {},
            "runner_readiness": None,
            "catalog_authority": None,
            "authorized_target_scope": target_scope,
            "autonomy": "auto",
            "ai_provider": provider,
        },
        "scenario": {},
        "plan": {},
        "profile": {},
        "authorized_target_scope": target_scope,
        "autonomy": "auto",
        "ai_provider": provider,
        "created_at": "2026-08-28T00:04:00Z",
        "finalized_at": "2026-08-28T00:05:00Z",
    }


@pytest.mark.parametrize("mutation", ["intent_id", "scope_duplicate"])
def test_approval_validation_binds_derived_intent_and_policy_duplicates(
    mutation: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    binding = {
        "state_digest": "sha256:" + "1" * 64,
        "plan_digest": "sha256:" + "2" * 64,
        "profile_id": "sandbox-blocked-network.v1",
        "target_scope_digest": "sha256:" + "3" * 64,
        "maximum_tier": "controlled",
    }
    monkeypatch.setattr(
        validation_module,
        "execution_approval_binding",
        lambda **_kwargs: dict(binding),
    )
    monkeypatch.setattr(
        validation_module.ScenarioDefinition,
        "from_mapping",
        staticmethod(lambda _value: object()),
    )
    monkeypatch.setattr(
        validation_module.RunnerProfile,
        "from_mapping",
        staticmethod(lambda _value: object()),
    )
    run = _approval_run(binding)
    assert validation_module._approval_id(run) == "approval-" + "a" * 32

    if mutation == "intent_id":
        run["approval"]["run_id"] = "intent-" + "0" * 32
        run["policy"]["approval"] = dict(run["approval"])
    else:
        run["policy"]["authorized_target_scope"] = {"kind": "different"}

    with pytest.raises(DefenseFrontierValidationError, match="freshly claimed"):
        validation_module._approval_id(run)


def _planner_frontier() -> dict[str, Any]:
    run_id = "run-20260828T000001Z-1111111111111111"
    decision_id = "decision-" + "a" * 20
    plan = {"schema_version": "bluefire.plan.v1", "steps": []}
    steps = [
        {
            "step_id": "stage_evidence",
            "behavior_id": "sandbox.collection.stage.v1",
            "action_id": "sandbox.collection.stage.v1",
            "status": "success",
            "artifacts": {"staged": True},
        },
        {
            "step_id": "try_internal_transport",
            "behavior_id": "sandbox.network.loopback.v1",
            "action_id": "sandbox.network.loopback.v1",
            "status": "blocked",
            "artifacts": {},
            "planner_decision_id": decision_id,
        },
    ]
    digest_rows = [dict(row) for row in steps]
    digest_rows[-1].pop("planner_decision_id")
    state_digest = content_hash(
        {
            "artifacts": {row["step_id"]: row["artifacts"] for row in digest_rows},
            "steps": digest_rows,
        }
    )
    completed = [
        {
            "step_id": row["step_id"],
            "behavior_id": row["behavior_id"],
            "status": row["status"],
        }
        for row in digest_rows
    ]
    planner_state = {
        "schema_version": "bluefire.planner-state.v1",
        "source_state_digest": state_digest,
        "mode": "execute",
        "current_step_id": "try_internal_transport",
        "outcome": "blocked",
        "completed_steps": completed,
        "deterministic_decision": {
            "decision_id": decision_id,
            "selected_step_id": "preserve_approved_copy",
            "selected_behavior_id": "sandbox.export.local.v1",
            "execution_disposition": "execute",
        },
        "registered_options": [],
        "remaining_budgets": {"steps": 1, "retries": 1},
    }
    record = {
        "schema_version": "bluefire.ai-proposal-record.v3",
        "run_id": run_id,
        "plan_digest": content_hash(plan),
        "current_step_id": "try_internal_transport",
        "outcome": "blocked",
        "state_digest": state_digest,
        "deterministic_decision_id": decision_id,
        "planner_state": planner_state,
        "planner_state_digest": content_hash(planner_state),
        "proposal": {
            "proposal_type": "select_registered",
            "selected_step_id": "preserve_approved_copy",
            "selected_behavior_id": "sandbox.export.local.v1",
        },
        "provider": {"effective_provider_id": PROVIDER_ID, "used_fallback": False},
        "proposal_policy_evaluation": {
            "status": "permitted",
            "mutation": False,
            "execute_requires_fresh_approval": False,
        },
        "application_status": "accepted_registered_default",
    }
    return {
        "run_id": run_id,
        "plan": plan,
        "steps": steps,
        "ai_proposals": [record],
        "planner_decisions": [
            {
                "decision_id": decision_id,
                "run_id": run_id,
                "current_state_digest": state_digest,
                "selected_step_id": "preserve_approved_copy",
                "selected_behavior_id": "sandbox.export.local.v1",
                "execution_disposition": "execute",
            }
        ],
    }


@pytest.mark.parametrize("mutation", ["run_id", "plan_digest", "prefix", "decision"])
def test_planner_validation_binds_run_plan_prefix_and_decision(
    mutation: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    frontier = _planner_frontier()
    record = frontier["ai_proposals"][0]
    monkeypatch.setattr(
        validation_module,
        "validate_persisted_proposal_record",
        lambda _record: SimpleNamespace(proposal_type=SimpleNamespace(value="select_registered")),
    )
    assert validation_module._validate_planner(frontier) is record

    if mutation == "run_id":
        record["run_id"] = "run-20260828T000002Z-2222222222222222"
    elif mutation == "plan_digest":
        record["plan_digest"] = "sha256:" + "0" * 64
    elif mutation == "prefix":
        record["planner_state"]["completed_steps"][0]["behavior_id"] = "sandbox.cleanup.v1"
        record["planner_state_digest"] = content_hash(record["planner_state"])
    else:
        frontier["planner_decisions"][0]["selected_behavior_id"] = "sandbox.cleanup.v1"

    with pytest.raises(DefenseFrontierValidationError):
        validation_module._validate_planner(frontier)


def _locked_gate() -> SimpleNamespace:
    assertions = tuple(
        SimpleNamespace(assertion_id=assertion_id, proof=definition[0])
        for assertion_id, definition in gate_module._EXPECTED_ASSERTIONS.items()
    )
    return SimpleNamespace(assertions=assertions)


def _passed_checks() -> dict[str, bool]:
    return {definition[1]: True for definition in gate_module._EXPECTED_ASSERTIONS.values()}


def _run_bundles() -> tuple[dict[str, str], ...]:
    return tuple(
        {
            "run_id": f"run-20260828T00000{index}Z-000000000000000{index}",
            "path": f"runs/run-20260828T00000{index}Z-000000000000000{index}",
        }
        for index in range(1, 4)
    )


def _patch_gate_dependencies(
    monkeypatch: pytest.MonkeyPatch,
    validator: Any,
) -> None:
    monkeypatch.setattr(
        gate_module,
        "_run_helper",
        lambda *_args: {
            "passed": True,
            "exit_code": 0,
            "command": ["{python}", "{helper}"],
            "protocol_valid": True,
        },
    )
    monkeypatch.setattr(
        gate_module,
        "_run_pytest_suite",
        lambda *_args, **_kwargs: {"passed": True},
    )
    monkeypatch.setattr(gate_module, "validate_persisted_frontier", validator)
    monkeypatch.setattr(gate_module, "_acceptance_binding", lambda: {})
    monkeypatch.setattr(
        gate_module,
        "validated_run_bundle",
        lambda _destination, _parent, bundle, **_kwargs: (dict(bundle), Path("manifest")),
    )


def _assert_no_passed_verification_report(evidence_dir: Path) -> None:
    report_path = evidence_dir / gate_module.VERIFICATION_REPORT
    if report_path.exists():
        assert json.loads(report_path.read_text(encoding="utf-8"))["passed"] is False


def test_gate_never_leaves_a_passed_report_when_final_validation_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    evidence_dir = tmp_path / "evidence"
    repository.mkdir()
    evidence_dir.mkdir()
    bundles = _run_bundles()
    calls = 0

    def validate(_repository: Path, _evidence_dir: Path):
        nonlocal calls
        calls += 1
        if calls == 1:
            return _passed_checks(), bundles
        raise DefenseFrontierValidationError("late semantic validation failed")

    _patch_gate_dependencies(monkeypatch, validate)

    outcome = gate_module.run_gate_04(
        _locked_gate(),
        evidence_dir,
        repository_root=repository,
    )

    assert calls == 2
    assert outcome.status == "failed"
    assert outcome.proofs == ()
    assert "late semantic validation failed" in str(outcome.failure_reason)
    _assert_no_passed_verification_report(evidence_dir)


def test_gate_success_publishes_exact_proofs_and_passed_verification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    evidence_dir = tmp_path / "evidence"
    repository.mkdir()
    evidence_dir.mkdir()
    bundles = _run_bundles()
    calls = 0

    def validate(_repository: Path, _evidence_dir: Path):
        nonlocal calls
        calls += 1
        return _passed_checks(), bundles

    _patch_gate_dependencies(monkeypatch, validate)

    outcome = gate_module.run_gate_04(
        _locked_gate(),
        evidence_dir,
        repository_root=repository,
    )

    assert calls == 2
    assert outcome.status == "passed"
    assert outcome.failure_reason is None
    assert len(outcome.proofs) == 12
    assert {proof["status"] for proof in outcome.proofs} == {"passed"}
    assert len({proof["test_id"] for proof in outcome.proofs}) == 12
    assert {proof["assertion_ids"][0] for proof in outcome.proofs} == set(
        gate_module._EXPECTED_ASSERTIONS
    )
    verification = json.loads(
        (evidence_dir / gate_module.VERIFICATION_REPORT).read_text(encoding="utf-8")
    )
    assert verification["passed"] is True
    assert verification["checks"] == _passed_checks()
    assert verification["run_ids"] == [bundle["run_id"] for bundle in bundles]


def test_gate_04_is_registered_in_product_gate_dispatcher() -> None:
    assert product_gates._WORKFLOWS["GATE-04"] is product_gates._gate_04_workflow


@pytest.mark.parametrize(
    "issue",
    [
        r"validation failed at C:\Users\Example User\Private Runs\result.json",
        r"validation failed at \\bluefire-server\Private Share\result.json",
        "validation failed at /home/example-user/private runs/result.json",
    ],
)
def test_bounded_issue_fully_redacts_absolute_private_paths(issue: str) -> None:
    assert gate_module._bounded_issue(issue) == "validation failure [private-path-redacted]"
