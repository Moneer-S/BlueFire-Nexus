"""Pure contracts for the optional installed retained-redaction wrapper."""

from __future__ import annotations

import json
from copy import deepcopy
from io import BytesIO
from pathlib import Path

import pytest

from tools.verify_installed_browser import (
    _RUNTIME_PROCESS_CLEANUP_KEYS,
    _drain_receiver_child_stderr,
    _receiver_blocked_requests_for_receipt,
    _receiver_child_exit_diagnostic,
    _receiver_driver_passed,
    _receiver_report_for_receipt,
    _receiver_retained_redaction_accepted,
    _resolve_receiver_driver,
    _runtime_cleanup_confirmed,
    _runtime_process_cleanup_confirmed,
)


def test_receiver_child_exit_diagnostic_drains_and_sanitizes_bounded_stderr() -> None:
    secret = b"private-capability-and-workspace-path"
    state: dict[str, object] = {"drained": False}
    _drain_receiver_child_stderr(BytesIO(b"Error [ERR_MODULE_NOT_FOUND]: " + secret * 400), state)
    diagnostic = _receiver_child_exit_diagnostic(1, state)
    assert diagnostic == {
        "returncode": 1,
        "stderr_class": "module_link",
        "stderr_bytes_capped": 8193,
        "stderr_truncated": True,
        "stderr_drained": True,
    }
    assert len(state["prefix"]) == 8192
    assert secret not in repr(diagnostic).encode()


def test_receiver_child_exit_diagnostic_refuses_incomplete_drain() -> None:
    assert _receiver_child_exit_diagnostic(None, {"drained": False}) == {
        "returncode": None,
        "stderr_class": "none",
        "stderr_bytes_capped": 0,
        "stderr_truncated": False,
        "stderr_drained": False,
    }


def test_receiver_child_exit_diagnostic_refuses_non_oserror_read_failure() -> None:
    class FailedStream:
        closed = False

        def read(self, _size: int) -> bytes:
            raise ValueError("inert read failure")

        def close(self) -> None:
            self.closed = True

    stream = FailedStream()
    state: dict[str, object] = {"drained": False}
    _drain_receiver_child_stderr(stream, state)
    assert stream.closed
    assert state["read_failed"] is True
    assert _receiver_child_exit_diagnostic(1, state)["stderr_drained"] is False


def test_receiver_child_exit_diagnostic_retains_only_allowlisted_stack_location() -> None:
    secret = b"private-capability-and-workspace-path"
    stderr = (
        b"Error: " + secret + b"\n"
        b"    at unexpected (C:\\private\\wrong-helper.mjs:88:3)\n"
        b"    at route (C:\\private\\receiver-guards.mjs:206:13)\n"
        b"    at file:///private/installed-receiver.mjs:1240:7\n"
    )
    state: dict[str, object] = {"drained": False}
    _drain_receiver_child_stderr(BytesIO(stderr), state)
    diagnostic = _receiver_child_exit_diagnostic(1, state)
    assert diagnostic["stderr_source"] == {"file": "receiver-guards.mjs", "line": 206}
    assert secret not in repr(diagnostic).encode()
    assert b"private" not in repr(diagnostic).encode()

    state["prefix"] = b"    at route (C:\\private\\unshipped-helper.mjs:999:1)\n"
    assert "stderr_source" not in _receiver_child_exit_diagnostic(1, state)
    state["prefix"] = b"    at route (C:\\private\\receiver-guards.mjs:10000:1)\n"
    assert "stderr_source" not in _receiver_child_exit_diagnostic(1, state)


@pytest.mark.parametrize("name", ["receiver-knowledge.mjs", "receiver-evidence-proposal.mjs"])
def test_history_helper_failure_keeps_only_its_shipped_basename_and_line(name: str) -> None:
    state = {"prefix": f"    at inspect (C:\\private\\{name}:123:4)\n".encode(), "drained": True}
    value = _receiver_child_exit_diagnostic(1, state)
    assert value["stderr_source"] == {"file": name, "line": 123}
    assert "private" not in repr(value)


def receiver_report() -> dict[str, object]:
    return {
        "schema_version": "bluefire.installed-receiver-retained-redaction.v1",
        "status": "passed",
        "installed_wheel_service": True,
        "native_execution_required": True,
        "workflow": "retained_redaction_original_and_linked_retest",
        "external_credentials": False,
        "live_model_inference": False,
        "generated_record_count": 8,
        "runner_profile": "sandbox-endpoint-deep-lab.v1",
        "target_scope": ["sandbox.workspace", "network.loopback"],
        "checks": [
            "packaged_starter_duplicated_and_saved_through_ui",
            "original_baseline_protected_and_legitimate_use_completed_with_retained_policy",
            "fresh_retest_created_through_retained_control_ui_with_original_lineage",
            "linked_fresh_protected_refusal_and_legitimate_use_completed_under_retained_policy",
            "finite_composed_attempt_settled_with_authenticated_policy_refusal_and_objective_false",
            "single_loopback_composition_proposal_reopened_and_applied_to_existing_attempt",
            "composed_attempt_grant_revoked_after_verified_cleanup",
            "receiver_distinct_model_authorizations_revoked_after_one_proposal_each",
            "history_proposal_reopened_with_original_records_and_no_additional_execution",
            "saved_composed_comparison_reopened_with_false_capability_objective_and_recorded_graph_result",
            "failed_objective_findings_opened_from_verified_run_without_new_attempt",
        ],
        "blocked_requests": [],
        "errors": [],
        "cleanup": {
            "original_owner_completed_retained": True,
            "linked_owner_completed_retained": True,
            "runner_stopped": True,
            "composition_grant_revoked": True,
            "model_authorization_revoked": True,
        },
        "owner_status": "completed",
        "unique_receiver_session_count": 5,
        "request_counts": {
            "save_scenario": 1,
            "owner": 2,
            "prepare": 5,
            "review": 5,
            "approval": 5,
            "cancel": 0,
            "composition_list": 3,
            "composition_context": 1,
            "composition_grant": 1,
            "composition_proposal_context": 2,
            "composition_proposal": 1,
            "composition_attempt": 1,
            "composition_knowledge": 2,
            "composition_evidence_context": 2,
            "composition_evidence_proposal": 1,
            "composition_revoke": 1,
            "comparison": 1,
            "provider_save": 1,
            "provider_activate": 1,
            "model_authorization": 2,
            "model_authorization_revoke": 2,
        },
        "source_starter_scenario_id": "scenario.receiver-defense.redaction-validation.v1",
        "saved_scenario_copy": {
            "scenario_id": "scenario.receiver-defense.redaction-validation.copy.12345678-1234-4234-8234-123456789abc.v1",
            "version": 1,
            "digest": "sha256:" + "a" * 64,
        },
        "baseline": {
            "status": "completed",
            "execution_state": "completed",
            "mode": "execute",
            "scenario_id": "scenario.receiver-defense.redaction-validation.copy.12345678-1234-4234-8234-123456789abc.v1",
            "run_profile": "sandbox-endpoint-deep-lab.v1",
            "receiver_decision": "accepted",
            "observation_state": "verified",
            "receiver_terminal": {
                "decision": "accepted",
                "authenticated": True,
                "record_count": 8,
                "redacted_record_count": 0,
                "retained_record_count": 8,
            },
        },
        "run_id": "run-20261021T120000Z-aaaaaaaaaaaaaaaa",
        "receiver_job_id": "job-11111111111111111111111111111111",
        "original_owner_job_id": "job-11111111111111111111111111111111",
        "composition": {
            "control_owner_job_id": "job-11111111111111111111111111111111",
            "objective_owner_job_id": "job-33333333333333333333333333333333",
            "grant_id": "grant-33333333333333333333333333333333",
            "grant_status": "revoked",
            "attempt_job_id": "job-44444444444444444444444444444444",
            "attempt_id": "attempt-44444444444444444444444444444444",
            "settlement": "settled",
            "run_id": "run-20261021T120007Z-2222222222222222",
            "verified_result_digest": "sha256:" + "c" * 64,
            "receiver_decision": "policy_refused",
            "receiver_authenticated": True,
            "record_count": 8,
            "redacted_record_count": 0,
            "retained_record_count": 8,
            "empty_record_count": 0,
            "cleanup": {"run": "complete", "receiver": "verified_closed"},
            "objective_established": False,
            "finalized_run_objective_reached": False,
            "graph_objective_reached": False,
            "knowledge": {
                "schema_version": "bluefire.installed-composition-knowledge.v1",
                "owner_id": "job-33333333333333333333333333333333",
                "attempt_id": "attempt-44444444444444444444444444444444",
                "job_id": "job-44444444444444444444444444444444",
                "run_id": "run-20261021T120007Z-2222222222222222",
                "knowledge_digest": "sha256:" + "d" * 64,
                "source_binding_digest": "sha256:" + "e" * 64,
                "manifest_digest": "sha256:" + "f" * 64,
                "evidence_digest": "sha256:" + "a" * 64,
                "findings_count": 12,
                "observed_findings_count": 3,
                "source_status": "verified",
                "historical_only": True,
                "source_matches_run": True,
                "objective_established": False,
                "opened_through_ui": True,
                "rendered_findings": True,
                "unchanged_attempts": True,
            },
            "model_proposal": {
                "job_id": "job-55555555555555555555555555555555",
                "proposal_digest": "sha256:" + "6" * 64,
                "context_digest": "sha256:" + "7" * 64,
                "provider_id": "provider.installed-receiver-composition.v1",
                "candidate_ready": True,
                "reopened": True,
                "same_initial_graph": True,
                "model_authorization_requests": 1,
            },
            "evidence_proposal": {
                "schema_version": "bluefire.installed-evidence-proposal.v1",
                "owner_id": "job-33333333333333333333333333333333",
                "attempt_id": "attempt-44444444444444444444444444444444",
                "source_run_id": "run-20261021T120007Z-2222222222222222",
                "job_id": "job-66666666666666666666666666666666",
                "proposal_digest": "sha256:" + "9" * 64,
                "context_digest": "sha256:" + "8" * 64,
                "knowledge_digest": "sha256:" + "d" * 64,
                "purpose": "bluefire_receiver_evidence_composition_proposal",
                "provider_id": "provider.installed-receiver-composition.v1",
                "model_authorization_requests": 1,
                "reconsidered_step_id": "transform_fixture",
                "supporting_findings": 1,
                "later_finding_reused": True,
                "original_redact_values": False,
                "proposed_redact_values": True,
                "original_objective_established": False,
                "candidate_ready": True,
                "source_matches_run": True,
                "historical_only": True,
                "reopened": True,
                "rendered_reasoning": True,
                "unchanged_attempts": True,
                "additional_executions": 0,
            },
            "comparison": {
                "baseline_run_id": "run-20261021T120000Z-aaaaaaaaaaaaaaaa",
                "snapshot_id": "run-comparison-" + "d" * 64,
                "snapshot_digest": "sha256:" + "e" * 64,
                "source_integrity": "verified",
                "objective_comparability": "different_objectives",
                "objective_changed": False,
                "objective_recovered": False,
                "reopened": True,
            },
        },
        "linked_owner_job_id": "job-22222222222222222222222222222222",
        "original_control": {
            "status": "retained",
            "receiver_state": "stopped",
            "control_digest": "sha256:" + "b" * 64,
            "source_baseline_run_id": "run-20261021T120000Z-aaaaaaaaaaaaaaaa",
        },
        "linked_retest": {
            "status": "completed",
            "phases": [
                {
                    "phase": "protected",
                    "status": "completed",
                    "run_id": "run-20261021T120005Z-ffffffffffffffff",
                    "decision": "policy_refused",
                },
                {
                    "phase": "legitimate",
                    "status": "completed",
                    "run_id": "run-20261021T120006Z-1111111111111111",
                    "decision": "accepted",
                },
            ],
            "source_control_job_id": "job-11111111111111111111111111111111",
            "source_control_digest": "sha256:" + "b" * 64,
            "source_baseline_run_id": "run-20261021T120000Z-aaaaaaaaaaaaaaaa",
            "retained_control_status": "retained",
            "receiver_state": "stopped",
        },
        "phase_evidence": [
            {
                "owner_role": "original",
                "owner_job_id": "job-11111111111111111111111111111111",
                "phase": "baseline",
                "status": "completed",
                "execution_state": "completed",
                "observation_state": "verified",
                "execution_job_id": "job-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "preparation_digest": "sha256:" + "1" * 64,
                "run_id": "run-20261021T120000Z-aaaaaaaaaaaaaaaa",
                "artifact": {"sha256": "1" * 64, "size_bytes": 200},
                "decision": "accepted",
                "terminal_decision": "accepted",
                "legitimate_use": None,
                "cleanup": {"receiver": "verified_closed", "run": "complete"},
            },
            {
                "owner_role": "original",
                "owner_job_id": "job-11111111111111111111111111111111",
                "phase": "protected",
                "status": "completed",
                "execution_state": "completed",
                "observation_state": "verified",
                "execution_job_id": "job-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "preparation_digest": "sha256:" + "2" * 64,
                "run_id": "run-20261021T120003Z-dddddddddddddddd",
                "artifact": {"sha256": "1" * 64, "size_bytes": 200},
                "decision": "policy_refused",
                "terminal_decision": "policy_refused",
                "legitimate_use": None,
                "cleanup": {"receiver": "verified_closed", "run": "complete"},
            },
            {
                "owner_role": "original",
                "owner_job_id": "job-11111111111111111111111111111111",
                "phase": "legitimate",
                "status": "completed",
                "execution_state": "completed",
                "observation_state": "verified",
                "execution_job_id": "job-cccccccccccccccccccccccccccccccc",
                "preparation_digest": "sha256:" + "3" * 64,
                "run_id": "run-20261021T120004Z-eeeeeeeeeeeeeeee",
                "artifact": {"sha256": "2" * 64, "size_bytes": 201},
                "decision": "accepted",
                "terminal_decision": "accepted",
                "legitimate_use": {
                    "baseline_run_id": "run-20261021T120000Z-aaaaaaaaaaaaaaaa",
                    "established": True,
                },
                "cleanup": {"receiver": "verified_closed", "run": "complete"},
            },
            {
                "owner_role": "linked",
                "owner_job_id": "job-22222222222222222222222222222222",
                "phase": "protected",
                "status": "completed",
                "execution_state": "completed",
                "observation_state": "verified",
                "execution_job_id": "job-dddddddddddddddddddddddddddddddd",
                "preparation_digest": "sha256:" + "4" * 64,
                "run_id": "run-20261021T120005Z-ffffffffffffffff",
                "artifact": {"sha256": "1" * 64, "size_bytes": 200},
                "decision": "policy_refused",
                "terminal_decision": "policy_refused",
                "legitimate_use": None,
                "cleanup": {"receiver": "verified_closed", "run": "complete"},
            },
            {
                "owner_role": "linked",
                "owner_job_id": "job-22222222222222222222222222222222",
                "phase": "legitimate",
                "status": "completed",
                "execution_state": "completed",
                "observation_state": "verified",
                "execution_job_id": "job-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                "preparation_digest": "sha256:" + "5" * 64,
                "run_id": "run-20261021T120006Z-1111111111111111",
                "artifact": {"sha256": "3" * 64, "size_bytes": 202},
                "decision": "accepted",
                "terminal_decision": "accepted",
                "legitimate_use": {
                    "baseline_run_id": "run-20261021T120000Z-aaaaaaaaaaaaaaaa",
                    "established": True,
                },
                "cleanup": {"receiver": "verified_closed", "run": "complete"},
            },
        ],
    }


def clean_wrapper_report() -> dict[str, object]:
    return {
        **{key: True for key in _RUNTIME_PROCESS_CLEANUP_KEYS},
        "receiver_model_fixture": {
            "request_count": 2,
            "purposes": [
                "bluefire_composition_proposal",
                "bluefire_receiver_evidence_composition_proposal",
            ],
            "request_bytes": 1024,
            "failed": False,
        },
        "browser_phase_status": "passed",
        "receiver_phase_status": "passed",
        "receiver_driver_started": True,
        "receiver_driver_cleanup_confirmed": True,
        "temporary_state_removed": True,
        "receiver_retained_redaction_driver_passed": True,
        "cleanup_errors": [],
    }


def test_receiver_retained_redaction_requires_original_and_linked_evidence() -> None:
    report = receiver_report()
    for row in report["phase_evidence"]:
        redacted = 8 if row["phase"] == "legitimate" else 0
        row.update(
            terminal_authenticated=True,
            terminal_record_count=8,
            terminal_redacted_record_count=redacted,
            terminal_retained_record_count=8 - redacted,
        )
    assert _receiver_driver_passed(report)

    for path, value in (
        ("baseline.receiver_terminal.redacted_record_count", 1),
        ("baseline.receiver_terminal.retained_record_count", 0),
        ("baseline.receiver_terminal.retained_record_count", True),
        ("baseline.receiver_terminal.redacted_record_count", False),
        ("baseline.receiver_terminal.record_count", True),
        ("generated_record_count", True),
        ("baseline.receiver_terminal.record_count", 7),
        ("baseline.scenario_id", "scenario.receiver-defense.redaction-validation.v1"),
        ("request_counts.save_scenario", True),
        ("source_starter_scenario_id", "scenario.other.v1"),
    ):
        changed = deepcopy(report)
        if path.startswith("baseline.receiver_terminal."):
            field = path.split("receiver_terminal.", 1)[1]
            changed["baseline"]["receiver_terminal"][field] = value
        elif path.startswith("baseline."):
            changed["baseline"][path.split(".", 1)[1]] = value
        elif path.startswith("request_counts."):
            changed["request_counts"][path.split(".", 1)[1]] = value
        else:
            changed[path] = value
        assert not _receiver_driver_passed(changed), path

    for mutate in (
        lambda value: value["phase_evidence"][0].__setitem__("artifact", None),
        lambda value: value["phase_evidence"][0].__setitem__(
            "artifact", {"sha256": "bad", "size_bytes": 200}
        ),
        lambda value: value["phase_evidence"][0]["artifact"].__setitem__("size_bytes", True),
        lambda value: value["phase_evidence"][0].__setitem__(
            "terminal_redacted_record_count", False
        ),
        lambda value: value["phase_evidence"][0].__setitem__(
            "terminal_retained_record_count", False
        ),
        lambda value: value["phase_evidence"][0].__setitem__("terminal_redacted_record_count", 9),
        lambda value: value["phase_evidence"][0].__setitem__("terminal_retained_record_count", -1),
    ):
        changed = deepcopy(report)
        mutate(changed)
        assert not _receiver_driver_passed(changed)

    for field, value in (
        ("version", 2),
        ("digest", "not-a-digest"),
        ("scenario_id", "scenario.other.v1"),
    ):
        changed = deepcopy(report)
        changed["saved_scenario_copy"][field] = value
        assert not _receiver_driver_passed(changed), f"saved_scenario_copy.{field}"

    for mutate in (
        lambda value: value["linked_retest"].__setitem__(
            "source_control_digest", "sha256:" + "f" * 64
        ),
        lambda value: value["linked_retest"]["phases"][0].__setitem__("decision", "accepted"),
        lambda value: value["phase_evidence"][3].__setitem__(
            "run_id", value["phase_evidence"][0]["run_id"]
        ),
        lambda value: value["phase_evidence"][1].__setitem__(
            "artifact", {"sha256": "f" * 64, "size_bytes": 200}
        ),
        lambda value: value["original_control"].__setitem__("receiver_state", "active"),
        lambda value: value["request_counts"].__setitem__("approval", 4),
        lambda value: value["phase_evidence"][0].__setitem__(
            "receiver_session_id", "sensitive-bearer"
        ),
        lambda value: value.__setitem__("session_id", "sensitive-bearer"),
    ):
        changed = deepcopy(report)
        mutate(changed)
        assert not _receiver_driver_passed(changed)

    for value in (None, True, 4):
        changed = deepcopy(report)
        changed["unique_receiver_session_count"] = value
        assert not _receiver_driver_passed(changed)


def test_receiver_bearer_fields_are_rejected_before_receipt_projection() -> None:
    report = receiver_report()
    report["phase_evidence"][0]["receiver_session_id"] = "secret-bearer-value"
    with pytest.raises(ValueError) as raised:
        _receiver_report_for_receipt(report)
    assert "secret-bearer-value" not in str(raised.value)
    assert "credential" in str(raised.value)


def test_receiver_receipt_projects_only_finite_blocked_post_diagnostics() -> None:
    report = receiver_report()
    report["blocked_requests"] = [
        {
            "method": "POST",
            "path": "loopback",
            "reason": "write_not_allowlisted_or_budget_exceeded",
            "route_family": "composition_objective_list",
            "denial_category": "budget_exhausted",
            "budget_count": 5,
            "budget_limit": 5,
            "url": "http://127.0.0.1/private?token=secret",
            "body": {"private": "request"},
        },
        {
            "method": "POST",
            "path": "loopback",
            "reason": "write_not_allowlisted_or_budget_exceeded",
            "route_family": ["private"],
            "denial_category": "budget_exhausted",
            "budget_count": True,
            "budget_limit": 999,
        },
    ]
    receipt = _receiver_report_for_receipt(report)
    assert receipt["blocked_requests"] == [
        {
            "method": "POST",
            "path": "loopback",
            "reason": "write_not_allowlisted_or_budget_exceeded",
            "route_family": "composition_objective_list",
            "denial_category": "budget_exhausted",
            "budget_count": 5,
            "budget_limit": 5,
        },
        {
            "method": "POST",
            "path": "loopback",
            "reason": "write_not_allowlisted_or_budget_exceeded",
            "route_family": "other",
            "denial_category": "other",
        },
    ]
    assert "secret" not in json.dumps(receipt["blocked_requests"])
    assert "private" not in json.dumps(receipt["blocked_requests"])


def test_receiver_blocked_request_projection_bounds_count_and_legacy_websocket() -> None:
    projected = _receiver_blocked_requests_for_receipt(
        [
            {"kind": "websocket", "destination": "blocked", "url": "/private"},
            {
                "method": "POST",
                "path": "loopback",
                "reason": "invalid_json_body",
                "route_family": "session",
                "denial_category": "invalid_json_body",
            },
        ]
        * 40
    )
    assert len(projected) == 32
    assert projected[0] == {"kind": "websocket", "destination": "blocked"}
    assert projected[1] == {
        "method": "POST",
        "path": "loopback",
        "reason": "invalid_json_body",
        "route_family": "session",
        "denial_category": "invalid_json_body",
    }


def test_receiver_receipt_preserves_bounded_composition_failure_categories() -> None:
    report = receiver_report()
    report["errors"] = [
        {
            "stage": "composition-attempt",
            "kind": "journey_failed",
            "error_type": "TimeoutError",
            "message": "private exception",
            "composition_interaction": {
                "schema_version": "bluefire.installed-receiver-composition-interaction.v1",
                "step": "click",
                "button_enabled": False,
                "pending_kind": "proposal",
                "context_digest_matches": True,
                "private": "private request",
            },
        },
        {"stage": "composition-attempt", "kind": "page_wait_failed", "method": "waitForResponse"},
        {"stage": ["private"], "kind": "private kind", "error_type": "private type"},
    ]
    errors = _receiver_report_for_receipt(report)["errors"]
    assert isinstance(errors, list)
    assert errors[0]["stage"] == "composition-attempt"
    assert errors[0]["error_type"] == "TimeoutError"
    assert errors[0]["composition_interaction"]["step"] == "click"
    assert errors[0]["composition_interaction"]["button_enabled"] is False
    assert errors[1]["method"] == "waitForResponse"
    assert errors[2] == {"kind": "other", "error_type": "other"}
    assert "private" not in json.dumps(errors)
    report["errors"] *= 20
    assert len(_receiver_report_for_receipt(report)["errors"]) == 32


def test_composed_receiver_receipt_requires_false_objective_and_current_saved_comparison() -> None:
    report = receiver_report()
    for row in report["phase_evidence"]:
        redacted = 8 if row["phase"] == "legitimate" else 0
        row.update(
            terminal_authenticated=True,
            terminal_record_count=8,
            terminal_redacted_record_count=redacted,
            terminal_retained_record_count=8 - redacted,
        )
    assert _receiver_driver_passed(report)
    assert _receiver_report_for_receipt(report)["composition"] == report["composition"]
    aligned_true = deepcopy(report)
    aligned_true["composition"]["finalized_run_objective_reached"] = True
    aligned_true["composition"]["graph_objective_reached"] = True
    assert _receiver_driver_passed(aligned_true)

    for field, value in (
        ("control_owner_job_id", "job-ffffffffffffffffffffffffffffffff"),
        ("grant_status", "active"),
        ("settlement", "pending_cleanup"),
        ("run_id", report["run_id"]),
        ("receiver_decision", "accepted"),
        ("receiver_authenticated", False),
        ("record_count", True),
        ("redacted_record_count", 8),
        ("objective_established", True),
        ("graph_objective_reached", True),
        ("finalized_run_objective_reached", True),
        ("graph_objective_reached", None),
        ("finalized_run_objective_reached", None),
    ):
        changed = deepcopy(report)
        changed["composition"][field] = value
        assert not _receiver_driver_passed(changed), field

    for field, value in (
        ("baseline_run_id", "run-20261021T120007Z-2222222222222222"),
        ("source_integrity", "changed"),
        ("objective_comparability", "comparable"),
        ("objective_changed", True),
        ("objective_recovered", True),
        ("reopened", False),
    ):
        changed = deepcopy(report)
        changed["composition"]["comparison"][field] = value
        assert not _receiver_driver_passed(changed), field

    changed = deepcopy(report)
    changed["composition"]["cleanup"]["receiver"] = "unknown"
    assert not _receiver_driver_passed(changed)
    changed = deepcopy(report)
    changed["request_counts"]["composition_attempt"] = 0
    assert not _receiver_driver_passed(changed)
    changed = deepcopy(report)
    changed["composition"]["receiver_session_id"] = "sensitive-bearer"
    with pytest.raises(ValueError):
        _receiver_report_for_receipt(changed)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("job_id", "job-invalid"),
        ("proposal_digest", "sha256:invalid"),
        ("context_digest", "sha256:invalid"),
        ("provider_id", "provider.unexpected.v1"),
        ("candidate_ready", False),
        ("reopened", False),
        ("same_initial_graph", False),
        ("model_authorization_requests", 2),
        ("model_authorization_requests", True),
    ],
)
def test_receiver_requires_exact_saved_model_proposal_proof(field: str, value: object) -> None:
    report = receiver_report()
    for row in report["phase_evidence"]:
        redacted = 8 if row["phase"] == "legitimate" else 0
        row.update(
            terminal_authenticated=True,
            terminal_record_count=8,
            terminal_redacted_record_count=redacted,
            terminal_retained_record_count=8 - redacted,
        )
    assert _receiver_driver_passed(report)
    report["composition"]["model_proposal"][field] = value
    assert not _receiver_driver_passed(report)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("composition_proposal_context", 1),
        ("composition_proposal_context", 4),
        ("composition_proposal", 0),
        ("model_authorization", 0),
        ("model_authorization_revoke", 0),
        ("provider_save", 2),
        ("provider_activate", 2),
    ],
)
def test_receiver_requires_single_proposal_and_exact_authorization_controls(
    field: str, value: object
) -> None:
    report = receiver_report()
    for row in report["phase_evidence"]:
        redacted = 8 if row["phase"] == "legitimate" else 0
        row.update(
            terminal_authenticated=True,
            terminal_record_count=8,
            terminal_redacted_record_count=redacted,
            terminal_retained_record_count=8 - redacted,
        )
    assert _receiver_driver_passed(report)
    report["request_counts"][field] = value
    assert not _receiver_driver_passed(report)


def test_receiver_composition_list_bound_matches_installed_driver_limit() -> None:
    report = receiver_report()
    for row in report["phase_evidence"]:
        redacted = 8 if row["phase"] == "legitimate" else 0
        row.update(
            terminal_authenticated=True,
            terminal_record_count=8,
            terminal_redacted_record_count=redacted,
            terminal_retained_record_count=8 - redacted,
        )

    # Three additional bounded reads cover history Settings return, proposal and reopening.
    report["request_counts"]["composition_list"] = 9
    assert _receiver_driver_passed(report)

    for invalid_count in (0, 10):
        changed = deepcopy(report)
        changed["request_counts"]["composition_list"] = invalid_count
        assert not _receiver_driver_passed(changed), invalid_count


@pytest.mark.parametrize(
    "field,value",
    [
        ("owner_id", "job-" + "f" * 32),
        ("attempt_id", "attempt-" + "f" * 32),
        ("job_id", "job-" + "f" * 32),
        ("run_id", "run-other"),
        ("source_status", "unavailable"),
        ("historical_only", False),
        ("source_matches_run", False),
        ("objective_established", True),
        ("opened_through_ui", False),
        ("rendered_findings", False),
        ("unchanged_attempts", False),
        ("findings_count", 0),
        ("findings_count", 33),
        ("findings_count", True),
        ("observed_findings_count", 0),
        ("observed_findings_count", 13),
        ("knowledge_digest", "sha256:invalid"),
    ],
)
def test_receiver_knowledge_proof_requires_actual_historical_source(field, value) -> None:
    from tools.verify_installed_browser import _valid_receiver_composition

    report = receiver_report()
    assert _valid_receiver_composition(report)
    report["composition"]["knowledge"][field] = value
    assert not _valid_receiver_composition(report)


def test_receiver_requires_two_explicit_knowledge_reads_across_settings_navigation() -> None:
    from tools.verify_installed_browser import _valid_receiver_composition

    for count in (0, 1, 3, True):
        report = receiver_report()
        report["request_counts"]["composition_knowledge"] = count
        assert not _valid_receiver_composition(report)
    report = receiver_report()
    del report["composition"]["knowledge"]
    assert not _valid_receiver_composition(report)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("owner_id", "job-" + "7" * 32),
        ("attempt_id", "attempt-" + "7" * 32),
        ("source_run_id", "run-other"),
        ("job_id", "job-" + "5" * 32),
        ("knowledge_digest", "sha256:" + "7" * 64),
        ("purpose", "bluefire_composition_proposal"),
        ("supporting_findings", 0),
        ("supporting_findings", True),
        ("supporting_findings", 17),
        ("later_finding_reused", False),
        ("original_redact_values", True),
        ("proposed_redact_values", False),
        ("original_objective_established", True),
        ("historical_only", False),
        ("source_matches_run", False),
        ("reopened", False),
        ("rendered_reasoning", False),
        ("unchanged_attempts", False),
        ("additional_executions", 1),
        ("additional_executions", False),
    ],
)
def test_history_proposal_requires_captured_source_and_no_execution(field, value) -> None:
    from tools.verify_installed_browser import _valid_receiver_composition

    report = receiver_report()
    assert _valid_receiver_composition(report)
    report["composition"]["evidence_proposal"][field] = value
    assert not _valid_receiver_composition(report)


def test_history_proposal_requires_distinct_finite_request_counts() -> None:
    from tools.verify_installed_browser import _valid_receiver_composition

    for name, expected in {
        "composition_evidence_proposal": 1,
        "model_authorization": 2,
        "model_authorization_revoke": 2,
    }.items():
        for count in (0, expected + 1, True):
            report = receiver_report()
            report["request_counts"][name] = count
            assert not _valid_receiver_composition(report)
    for count in (2, 3):
        report = receiver_report()
        report["request_counts"]["composition_evidence_context"] = count
        assert _valid_receiver_composition(report)
    for count in (0, 1, 4, True):
        report = receiver_report()
        report["request_counts"]["composition_evidence_context"] = count
        assert not _valid_receiver_composition(report)
    report = receiver_report()
    del report["composition"]["evidence_proposal"]
    assert not _valid_receiver_composition(report)


def test_receiver_requires_observed_model_revocation_after_proposal() -> None:
    report = receiver_report()
    for row in report["phase_evidence"]:
        redacted = 8 if row["phase"] == "legitimate" else 0
        row.update(
            terminal_authenticated=True,
            terminal_record_count=8,
            terminal_redacted_record_count=redacted,
            terminal_retained_record_count=8 - redacted,
        )
    assert _receiver_driver_passed(report)
    report["checks"].remove(
        "receiver_distinct_model_authorizations_revoked_after_one_proposal_each"
    )
    assert not _receiver_driver_passed(report)
    report["checks"].append(
        "receiver_distinct_model_authorizations_revoked_after_one_proposal_each"
    )
    report["cleanup"]["model_authorization_revoked"] = False
    assert not _receiver_driver_passed(report)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("request_count", 0),
        ("request_count", 1),
        ("request_count", 3),
        ("request_count", True),
        ("purposes", ["bluefire_ai_graph_draft"]),
        ("purposes", ["bluefire_composition_proposal", "bluefire_composition_proposal"]),
        (
            "purposes",
            ["bluefire_receiver_evidence_composition_proposal", "bluefire_composition_proposal"],
        ),
        ("request_bytes", 0),
        ("request_bytes", True),
        ("request_bytes", 524_289),
        ("failed", True),
    ],
)
def test_receiver_wrapper_rejects_unbound_model_fixture(field: str, value: object) -> None:
    report = clean_wrapper_report()
    assert _receiver_retained_redaction_accepted(report)
    report["receiver_model_fixture"][field] = value
    assert not _receiver_retained_redaction_accepted(report)


def test_receiver_browser_driver_uses_authenticated_readiness_and_safe_diagnostic() -> None:
    driver = (
        Path(__file__).resolve().parents[1]
        / "frontend"
        / "tests"
        / "installed"
        / "installed-receiver.mjs"
    ).read_text(encoding="utf-8")
    assert 'assert.equal(ready.process, "authenticated")' in driver
    assert 'assert.equal(ready.process, "running")' not in driver
    assert '"/ui/fonts/InterVariable.woff2"' in driver
    assert "report.runner_status_diagnostic" in driver
    assert "profile_matches: ready.profile_id === PROFILE" in driver
    assert (
        'safeStatus(ready.process, ["authenticated", "absent", "stale", "unavailable"])' in driver
    )


@pytest.mark.parametrize("driver_requested", [False, True])
def test_receiver_driver_paths_require_copied_driver_and_adjacent_modules(
    tmp_path: Path, driver_requested: bool
) -> None:
    checkout = tmp_path / "checkout"
    copied = tmp_path / "copied"
    checkout.mkdir()
    copied.mkdir()
    if not driver_requested:
        assert _resolve_receiver_driver(None, checkout) == (None, None, None)
        return

    driver = copied / "installed-receiver.mjs"
    guard = copied / "receiver-guards.mjs"
    deadline = copied / "receiver-deadline.mjs"
    knowledge = copied / "receiver-knowledge.mjs"
    evidence = copied / "receiver-evidence-proposal.mjs"
    driver.write_text("// pinned browser driver\n", encoding="utf-8")
    guard.write_text("// pinned request contract\n", encoding="utf-8")
    deadline.write_text("// pinned driver deadline\n", encoding="utf-8")
    knowledge.write_text("// historical findings proof\n", encoding="utf-8")
    evidence.write_text("// historical proposal proof\n", encoding="utf-8")
    assert _resolve_receiver_driver(driver, checkout) == (
        driver.resolve(),
        guard.resolve(),
        deadline.resolve(),
    )

    in_checkout_driver = checkout / driver.name
    in_checkout_driver.write_text("// not an external copy\n", encoding="utf-8")
    (checkout / guard.name).write_text("// guard\n", encoding="utf-8")
    (checkout / deadline.name).write_text("// deadline\n", encoding="utf-8")
    (checkout / knowledge.name).write_text("// knowledge\n", encoding="utf-8")
    (checkout / evidence.name).write_text("// evidence\n", encoding="utf-8")
    with pytest.raises(RuntimeError):
        _resolve_receiver_driver(in_checkout_driver, checkout)


def test_missing_receiver_guard_fails_before_launch(tmp_path: Path) -> None:
    driver = tmp_path / "installed-receiver.mjs"
    driver.write_text("// driver\n", encoding="utf-8")
    (tmp_path / "receiver-deadline.mjs").write_text("// deadline\n", encoding="utf-8")
    with pytest.raises(FileNotFoundError):
        _resolve_receiver_driver(driver, tmp_path / "checkout")


def test_missing_receiver_deadline_fails_before_launch(tmp_path: Path) -> None:
    driver = tmp_path / "installed-receiver.mjs"
    driver.write_text("// driver\n", encoding="utf-8")
    (tmp_path / "receiver-guards.mjs").write_text("// guard\n", encoding="utf-8")
    with pytest.raises(FileNotFoundError):
        _resolve_receiver_driver(driver, tmp_path / "checkout")


def test_missing_receiver_knowledge_helper_fails_before_launch(tmp_path: Path) -> None:
    driver = tmp_path / "installed-receiver.mjs"
    driver.write_text("// driver\n", encoding="utf-8")
    (tmp_path / "receiver-guards.mjs").write_text("// guard\n", encoding="utf-8")
    (tmp_path / "receiver-deadline.mjs").write_text("// deadline\n", encoding="utf-8")
    with pytest.raises(FileNotFoundError):
        _resolve_receiver_driver(driver, tmp_path / "checkout")


def test_missing_receiver_evidence_helper_fails_before_launch(tmp_path: Path) -> None:
    driver = tmp_path / "installed-receiver.mjs"
    driver.write_text("// driver\n", encoding="utf-8")
    for name in ("receiver-guards.mjs", "receiver-deadline.mjs", "receiver-knowledge.mjs"):
        (tmp_path / name).write_text("// helper\n", encoding="utf-8")
    with pytest.raises(FileNotFoundError):
        _resolve_receiver_driver(driver, tmp_path / "checkout")


def test_each_unconfirmed_cleanup_state_blocks_runtime_removal_and_acceptance() -> None:
    report = clean_wrapper_report()
    assert _runtime_process_cleanup_confirmed(report)
    assert _runtime_cleanup_confirmed(report)
    assert _receiver_retained_redaction_accepted(report)

    for key in (*_RUNTIME_PROCESS_CLEANUP_KEYS, "temporary_state_removed"):
        changed = clean_wrapper_report()
        changed[key] = False
        assert not _runtime_cleanup_confirmed(changed), key
        assert not _receiver_retained_redaction_accepted(changed), key


def test_cleanup_confirmation_requires_boolean_true() -> None:
    report = clean_wrapper_report()
    report["receiver_driver_cleanup_confirmed"] = 1
    assert not _runtime_process_cleanup_confirmed(report)
    assert not _receiver_retained_redaction_accepted(report)


@pytest.mark.parametrize("browser_status", ["failed", "not_attempted", None])
def test_receiver_acceptance_requires_successful_primary_browser_phase(browser_status) -> None:
    report = clean_wrapper_report()
    report["browser_phase_status"] = browser_status
    assert _runtime_cleanup_confirmed(report)
    assert not _receiver_retained_redaction_accepted(report)


@pytest.mark.parametrize("cleanup_errors", [["receiver_http_shutdown"], None, "", {}, False])
def test_cleanup_errors_block_acceptance_without_blocking_safe_removal(cleanup_errors) -> None:
    report = clean_wrapper_report()
    report["cleanup_errors"] = cleanup_errors
    assert _runtime_process_cleanup_confirmed(report)
    assert _runtime_cleanup_confirmed(report)
    assert not _receiver_retained_redaction_accepted(report)


def test_cleanup_error_confirmation_is_required_for_acceptance() -> None:
    report = clean_wrapper_report()
    del report["cleanup_errors"]
    assert _runtime_process_cleanup_confirmed(report)
    assert not _receiver_retained_redaction_accepted(report)
