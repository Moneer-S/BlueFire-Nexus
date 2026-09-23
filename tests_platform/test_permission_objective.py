"""Authored software evidence; no GNU chmod, model, or Linux lab is invoked."""

from copy import deepcopy
from dataclasses import replace

import pytest

from bluefire.config import AutonomyLevel
from bluefire.contracts import ExecutionMode
from bluefire.evidence import EvidenceProvenance, EvidenceRecord, SandboxObserver
from bluefire.observation_integrity import evaluate_observation_integrity
from bluefire.permission_objective import ACTION_ID, permission_objective_evidence
from tests_platform.test_permission_orchestration import (
    FULL_TARGET_SCOPE,
    PermissionFakeRunner,
    _approval_kwargs,
    _linux_profile,
    _orchestrator,
    _scenario,
)

PATH = "fixtures/transformed.jsonl"


def permission_fields(mode="0660"):
    bits = int(mode, 8)
    return {
        "permission_status": "available",
        "permission_mode_octal": mode,
        "group_write_bit": bool(bits & 0o020),
        "other_write_bit": bool(bits & 0o002),
        "non_owner_write_bit": bool(bits & 0o022),
        "effective_access": "not_evaluated",
    }


def evidence(*, mode="0660", collector=False):
    common = dict(
        run_id="run-permission-review",
        step_id="permission",
        behavior_id="sandbox.permission.relax.v1",
        action_id=ACTION_ID,
        runner_profile_id="profile-review",
        target_scope_ref="runner-profile:profile-review",
    )
    execution = EvidenceRecord.create(
        **common,
        provenance=EvidenceProvenance.EXECUTED,
        producer="bluefire-rust-runner",
        timestamp="2026-09-20T00:00:00Z",
        content={
            "runner_status": "success",
            "expected_observable_paths": [PATH],
            **permission_objective_evidence(ACTION_ID, {"mode": mode}),
            "output": {
                "artifact": PATH,
                "sha256": "a" * 64,
                "size": 128,
                "requested_mode": mode,
                "before_mode": "0644",
                "after_mode": mode,
                "exit_code": 0,
            },
        },
    )
    fields = {"path": PATH, "sha256": "a" * 64, "size_bytes": 128, **permission_fields(mode)}
    observation = EvidenceRecord.create(
        **common,
        provenance=EvidenceProvenance.OBSERVED,
        producer="collector.filesystem.sandbox.v1" if collector else "sandbox-observer.v1",
        parent_evidence_ids=(execution.evidence_id,),
        timestamp="2026-09-20T00:00:01Z",
        content=(
            {
                "artifact_type": "collector_observation",
                "observation_kind": "filesystem",
                "observed_fields": fields,
            }
            if collector
            else {"artifact_type": "file_observation", **fields}
        ),
    )
    return execution, observation


@pytest.mark.parametrize("mode", ["0600", "0640", "0660", "0666"])
@pytest.mark.parametrize("collector", [False, True])
def test_exact_independent_mode_verifies_only_permission_bits(mode, collector):
    execution, observation = evidence(mode=mode, collector=collector)
    report = evaluate_observation_integrity([execution, observation])
    postcondition = report["file_postconditions"][0]
    assert report["satisfied"] is True
    assert postcondition["permission_postcondition"] == {
        "expected_mode": mode,
        "state": "verified",
        "unavailable_evidence_ids": [],
        "effective_access": "not_evaluated",
    }
    assert postcondition["observed_evidence_ids"] == [observation.evidence_id]
    assert postcondition["verified_dimensions"] == [
        "path",
        "sha256",
        "size_bytes",
        "permission_mode_octal",
    ]


@pytest.mark.parametrize(
    "fields",
    [
        {},
        {"permission_status": "unavailable_windows", "effective_access": "not_evaluated"},
        {"permission_status": "unsupported_platform", "effective_access": "not_evaluated"},
        {"permission_status": "available", "permission_mode_octal": "0660"},
        {**permission_fields(), "group_write_bit": False},
    ],
)
def test_missing_or_invalid_permission_telemetry_stays_unknown(fields):
    execution, observed = evidence()
    observed = replace(
        observed,
        content={
            "artifact_type": "file_observation",
            "path": PATH,
            "sha256": "a" * 64,
            "size_bytes": 128,
            **fields,
        },
    )
    report = evaluate_observation_integrity([execution, observed])
    postcondition = report["file_postconditions"][0]
    assert report["satisfied"] is False
    assert postcondition["state"] == "observation_unavailable"
    assert postcondition["permission_postcondition"]["state"] == "unknown"
    assert postcondition["permission_postcondition"]["unavailable_evidence_ids"] == [
        observed.evidence_id
    ]
    assert postcondition["verified_dimensions"] == []


def test_independent_mismatch_is_not_hidden_by_unchanged_bytes_or_another_match():
    execution, observed = evidence()
    mismatch = replace(
        observed,
        evidence_id="evidence-other-mode",
        content={
            **observed.content,
            **permission_fields("0644"),
        },
    )
    report = evaluate_observation_integrity([execution, observed, mismatch])
    assert report["satisfied"] is False
    postcondition = report["file_postconditions"][0]
    assert postcondition["state"] == "conflicting_observation"
    assert postcondition["permission_postcondition"]["state"] == "mismatch"
    assert postcondition["conflicting_evidence_ids"] == [mismatch.evidence_id]


@pytest.mark.parametrize(
    "change", ["native-objective", "reported-request", "reported-mode", "reported-exit"]
)
def test_native_objective_not_established_cannot_be_promoted_by_observation(change):
    execution, observed = evidence()
    content = deepcopy(execution.content)
    content["runner_status"] = "partial"
    if change == "native-objective":
        content["error"] = {"code": "objective_not_established"}
    elif change == "reported-request":
        content["output"]["requested_mode"] = "0644"
    elif change == "reported-mode":
        content["output"]["after_mode"] = "0644"
    else:
        content["output"]["exit_code"] = False
    report = evaluate_observation_integrity([replace(execution, content=content), observed])
    assert report["satisfied"] is False
    postcondition = report["file_postconditions"][0]
    assert postcondition["state"] == "permission_not_established"
    assert postcondition["permission_postcondition"]["state"] == "not_established"


def test_expected_mode_never_falls_back_to_runner_output_and_alias_keeps_requirement():
    execution, observed = evidence()
    content = dict(execution.content)
    content.pop("expected_permission_mode")
    assert (
        evaluate_observation_integrity([replace(execution, content=content), observed])["satisfied"]
        is False
    )
    alias = replace(execution, action_id="test.permission-alias.v1")
    report = evaluate_observation_integrity([alias, observed])
    assert report["satisfied"] is True
    assert "permission_mode_octal" in report["file_postconditions"][0]["verified_dimensions"]
    assert permission_objective_evidence("sandbox.fixture.transform.v1", {"mode": "0660"}) == {}


@pytest.mark.parametrize(
    "change",
    [
        {"provenance": EvidenceProvenance.EXECUTED},
        {"provenance": EvidenceProvenance.SYNTHETIC},
        {"producer": "bluefire-rust-runner"},
    ],
)
def test_self_reported_permission_mode_never_substitutes_for_independent_evidence(change):
    execution, observed = evidence()
    assert (
        evaluate_observation_integrity([execution, replace(observed, **change)])["satisfied"]
        is False
    )


@pytest.mark.parametrize(
    "case,expected",
    [
        ("verified", True),
        ("native-partial", False),
        ("missing", False),
        ("mismatch", False),
    ],
)
def test_permission_run_objective_uses_independent_mode_and_preserves_cleanup(
    tmp_path, monkeypatch, case, expected
):
    class ObjectiveRunner(PermissionFakeRunner):
        def execute(self, manifest, profile):
            result = dict(super().execute(manifest, profile))
            if manifest["action_id"] == ACTION_ID and case == "native-partial":
                result.update(
                    status="partial",
                    error={
                        "code": "objective_not_established",
                        "message": "Authored partial case.",
                    },
                )
                result["output"] = {**result["output"], "after_mode": "0644"}
            return result

    def observe(_observer, *, relative_path, **kwargs):
        action_id = kwargs["action_id"]
        facts = {
            "artifact_type": "file_observation",
            "path": relative_path,
            "sha256": ("1" if action_id == "sandbox.fixture.create.v1" else "2") * 64,
            "size_bytes": 128,
        }
        if action_id == ACTION_ID and case != "missing":
            facts.update(
                permission_fields("0644" if case in {"native-partial", "mismatch"} else "0660")
            )
        return EvidenceRecord.create(
            **kwargs,
            provenance=EvidenceProvenance.OBSERVED,
            producer="sandbox-observer.v1",
            target_scope_ref=f"runner-profile:{kwargs['runner_profile_id']}",
            content=facts,
            limitations=("Authored observer; no live Linux permission evidence.",),
        )

    monkeypatch.setattr("bluefire.orchestrator.current_platform", lambda: "linux")
    monkeypatch.setattr("bluefire.runner_contracts.current_platform", lambda: "linux")
    monkeypatch.setattr(SandboxObserver, "observe_file", observe)
    runner = ObjectiveRunner()
    orchestrator = _orchestrator(tmp_path, runner)
    scenario, profile = _scenario(tmp_path), _linux_profile()
    choices = {"permission": ACTION_ID}
    result = orchestrator.run(
        scenario,
        mode=ExecutionMode.EXECUTE,
        profile=profile,
        sandbox_root=tmp_path,
        target_scope=FULL_TARGET_SCOPE,
        autonomy=AutonomyLevel.OFF,
        action_implementations=choices,
        **_approval_kwargs(
            orchestrator,
            scenario=scenario,
            profile=profile,
            target_scope=FULL_TARGET_SCOPE,
            action_implementations=choices,
        ),
    )
    assert result["objective_reached"] is expected
    assert result["status"] == ("completed" if expected else "incomplete")
    permission = next(row for row in result["steps"] if row["step_id"] == "permission")
    transformed = next(row for row in result["steps"] if row["step_id"] == "transform_fixture")
    assert permission["receipts"] == transformed["receipts"]
    assert permission["status"] == ("partial" if case == "native-partial" else "success")
    assert result["cleanup"]["success"] is True
    assert result["cleanup"]["outstanding_receipt_count"] == 0
