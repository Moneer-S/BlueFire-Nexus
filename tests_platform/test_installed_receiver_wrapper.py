"""Pure contracts for the optional installed retained-redaction wrapper."""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace

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


def retained_execution_report() -> dict[str, object]:
    source = {
        "run_id": "run-20261029T120008Z-8888888888888888",
        "attempt_id": "attempt-" + "8" * 32,
        "lineage_id": "lineage-" + "c" * 64,
        "step_id": "stage_records",
        "artifact": "bundle",
        "artifact_type": "artifact.sandbox.bundle.v1",
        "sha256": "d" * 64,
        "size_bytes": 1024,
    }
    source["source_ref"] = (
        "sha256:"
        + hashlib.sha256(
            json.dumps(source, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        ).hexdigest()
    )
    return {
        "schema_version": "bluefire.installed-retained-execution.v1",
        "pack": "bluefire.receiver-composition-pack.v2",
        "owner_id": "job-" + "7" * 32,
        "control_owner_id": "job-" + "1" * 32,
        "grant_id": "grant-" + "7" * 32,
        "grant_status": "revoked",
        "policy_digest": "sha256:" + "7" * 64,
        "source": source,
        "original": {
            "job_id": "job-" + "8" * 32,
            "attempt_id": source["attempt_id"],
            "run_id": source["run_id"],
            "objective_established": False,
            "receiver_decision": "policy_refused",
            "record_count": 8,
            "redacted_record_count": 0,
            "cleanup": {"run": "complete", "receiver": "verified_closed"},
            "capture_digest": "sha256:" + "8" * 64,
            "producer_record_hash": "sha256:" + "d" * 64,
            "observation_record_hash": "sha256:" + "e" * 64,
            "receipt_id": "8" * 64,
        },
        "continuation": {
            "job_id": "job-" + "9" * 32,
            "attempt_id": "attempt-" + "9" * 32,
            "run_id": "run-20261029T120009Z-9999999999999999",
            "objective_established": True,
            "receiver_decision": "accepted",
            "record_count": 8,
            "redacted_record_count": 8,
            "cleanup": {"run": "complete", "receiver": "verified_closed"},
            "materialize_step_id": "reuse_retained_bundle",
            "source_ref": source["source_ref"],
            "materialized_sha256": source["sha256"],
            "materialized_size_bytes": source["size_bytes"],
            "receipt_id": "9" * 64,
            "independent_observation": True,
            "workspace_lineage_match": True,
            "no_fixture_create": True,
        },
        "model": {
            "purpose": "bluefire_receiver_retained_composition_proposal",
            "requests": 2,
            "authorization_max_requests": 2,
            "initial_job_id": "job-" + "0a" * 16,
            "revised_job_id": "job-" + "0b" * 16,
            "metadata_only": True,
            "reopened": True,
            "reasoning_rendered": True,
            "current_sources_rechecked": True,
        },
        "capture_before_cleanup": True,
        "original_failure_preserved": True,
        "source_metadata_preserved_after_cleanup": True,
        "source_disposition": "sealed_until_run_bundle_deleted",
        "comparison": {
            "snapshot_id": "run-comparison-" + "f" * 64,
            "snapshot_digest": "sha256:" + "f" * 64,
            "run_ids": [source["run_id"], "run-20261029T120009Z-9999999999999999"],
            "source_integrity": "verified",
            "objective_comparability": "comparable",
            "objective_changed": True,
            "objective_recovered": True,
            "reopened": True,
        },
    }


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
        "runner_profile": "sandbox-endpoint-deep-lab.v2",
        "target_scope": ["sandbox.workspace", "network.loopback"],
        "checks": [
            "packaged_starter_duplicated_and_saved_through_ui",
            "original_baseline_protected_and_legitimate_use_completed_with_retained_policy",
            "fresh_retest_created_through_retained_control_ui_with_original_lineage",
            "linked_fresh_protected_refusal_and_legitimate_use_completed_under_retained_policy",
            "finite_composed_attempt_settled_with_authenticated_policy_refusal_and_objective_false",
            "single_loopback_composition_proposal_reopened_and_applied_to_existing_attempt",
            "composed_attempt_grant_revoked_after_verified_cleanup",
            "receiver_composition_and_history_authorizations_revoked_after_one_proposal_each",
            "receiver_superseded_model_authorization_remained_revoked",
            "history_proposal_reopened_with_original_records_and_no_additional_execution",
            "saved_composed_comparison_reopened_with_false_capability_objective_and_recorded_graph_result",
            "failed_objective_findings_opened_from_verified_run_without_new_attempt",
            "retained_result_reused_in_fresh_successful_attempt_without_prefix_replay",
        ],
        "blocked_requests": [],
        "errors": [],
        "cleanup": {
            "original_owner_completed_retained": True,
            "linked_owner_completed_retained": True,
            "runner_stopped": True,
            "composition_grant_revoked": True,
            "model_authorization_revoked": True,
            "retained_grant_revoked": True,
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
            "model_authorization": 3,
            "model_authorization_revoke": 1,
            "retained_list": 3,
            "retained_review": 1,
            "retained_grant": 1,
            "retained_initial_context": 1,
            "retained_history_context": 2,
            "retained_proposal": 2,
            "retained_attempt": 2,
            "retained_knowledge": 1,
            "retained_revoke": 1,
            "retained_comparison": 1,
        },
        "retained_execution": retained_execution_report(),
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
            "run_profile": "sandbox-endpoint-deep-lab.v2",
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


def custody_receipt(proof: dict) -> dict[str, object]:
    source = proof["source"]
    return {
        "schema_version": "bluefire.installed-retained-source-custody.v1",
        "status": "verified",
        "owner_id": proof["owner_id"],
        "grant_id": proof["grant_id"],
        "source_ref": source["source_ref"],
        "run_id": source["run_id"],
        "attempt_id": source["attempt_id"],
        "job_id": proof["original"]["job_id"],
        "compiled_digest": "sha256:" + "c" * 64,
        "continuation_job_id": proof["continuation"]["job_id"],
        "continuation_run_id": proof["continuation"]["run_id"],
        "sha256": source["sha256"],
        "size_bytes": source["size_bytes"],
        "payload_reads": 1,
        "verified_after_driver_cleanup": True,
        "original_objective_established": False,
        "continuation_objective_established": True,
    }


def clean_wrapper_report() -> dict[str, object]:
    retained = retained_execution_report()
    return {
        **{key: True for key in _RUNTIME_PROCESS_CLEANUP_KEYS},
        "receiver_retained_redaction": {"retained_execution": retained},
        "receiver_retained_source_custody": custody_receipt(retained),
        "receiver_model_fixture": {
            "request_count": 4,
            "purposes": [
                "bluefire_composition_proposal",
                "bluefire_receiver_evidence_composition_proposal",
                "bluefire_receiver_retained_composition_proposal",
                "bluefire_receiver_retained_composition_proposal",
            ],
            "request_bytes": 1024,
            "failed": False,
        },
        "browser_phase_status": "passed",
        "receiver_phase_status": "passed",
        "receiver_phase_elapsed_seconds": 535.25,
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


@pytest.mark.parametrize(
    "stage",
    [
        "retained-model-authorization",
        "retained-objective-review",
        "retained-review-response",
        "retained-review-binding",
        "retained-original-proposal",
        "retained-original-execute",
        "retained-history-selection",
        "retained-continuation-proposal",
        "retained-proposal-reopen",
        "retained-continuation-execute",
        "retained-grant-revoke",
        "retained-result-comparison",
    ],
)
def test_receiver_receipt_preserves_retained_failure_stage_without_private_material(stage) -> None:
    report = receiver_report()
    report["errors"] = [
        {
            "stage": stage,
            "kind": "journey_failed",
            "error_type": "AssertionError",
            "message": "private exception",
            "body": {"detail": "private response"},
            "owner_id": "private identity",
        }
    ]
    assert _receiver_report_for_receipt(report)["errors"] == [
        {"stage": stage, "kind": "journey_failed", "error_type": "AssertionError"}
    ]


def test_receiver_receipt_maps_unknown_retained_failure_stage_to_other() -> None:
    report = receiver_report()
    report["errors"] = [
        {"stage": "retained-private-owner-id", "kind": "journey_failed"},
        {"stage": {"private": "response"}, "kind": "console_error"},
    ]
    assert _receiver_report_for_receipt(report)["errors"] == [
        {"stage": "other", "kind": "journey_failed"},
        {"kind": "console_error"},
    ]


@pytest.mark.parametrize("legacy_fields", ["runner", "baseline", "both"])
def test_receiver_current_candidate_rejects_legacy_profile_without_relabeling(
    legacy_fields,
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
    if legacy_fields in {"runner", "both"}:
        report["runner_profile"] = "sandbox-endpoint-deep-lab.v1"
    if legacy_fields in {"baseline", "both"}:
        report["baseline"]["run_profile"] = "sandbox-endpoint-deep-lab.v1"
    historical_report = deepcopy(report)
    assert not _receiver_driver_passed(report)
    assert report == historical_report
    assert _receiver_report_for_receipt(report)["runner_profile"] == report["runner_profile"]


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
        ("model_authorization_revoke", 2),
        ("model_authorization_revoke", 3),
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
        "model_authorization": 3,
        "model_authorization_revoke": 1,
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


@pytest.mark.parametrize(
    ("path", "replacement"),
    [
        (("pack",), "bluefire.receiver-composition-pack.v1"),
        (("owner_id",), "job-" + "3" * 32),
        (("control_owner_id",), "job-" + "2" * 32),
        (("grant_status",), "active"),
        (("policy_digest",), "not-a-digest"),
        (("source", "run_id"), "run-20261021T120000Z-aaaaaaaaaaaaaaaa"),
        (("source", "attempt_id"), "attempt-" + "9" * 32),
        (("source", "lineage_id"), "lineage-other"),
        (("source", "step_id"), "create_fixture"),
        (("source", "artifact"), "other"),
        (("source", "artifact_type"), "artifact.other.v1"),
        (("source", "sha256"), "a" * 64),
        (("source", "size_bytes"), 0),
        (("source", "size_bytes"), True),
        (("source", "size_bytes"), 262_145),
        (("source", "source_ref"), "sha256:" + "0" * 64),
        (("original", "objective_established"), True),
        (("original", "receiver_decision"), "accepted"),
        (("original", "record_count"), 7),
        (("original", "redacted_record_count"), 8),
        (("original", "cleanup"), {"run": "pending", "receiver": "verified_closed"}),
        (("original", "producer_record_hash"), "sha256:" + "e" * 64),
        (("original", "observation_record_hash"), "invalid"),
        (("continuation", "job_id"), "job-" + "8" * 32),
        (("continuation", "attempt_id"), "attempt-" + "8" * 32),
        (("continuation", "run_id"), "run-20261029T120008Z-8888888888888888"),
        (("continuation", "objective_established"), False),
        (("continuation", "receiver_decision"), "policy_refused"),
        (("continuation", "record_count"), True),
        (("continuation", "redacted_record_count"), 0),
        (("continuation", "cleanup"), {"run": "complete", "receiver": "unknown"}),
        (("continuation", "source_ref"), "sha256:" + "0" * 64),
        (("continuation", "materialized_sha256"), "a" * 64),
        (("continuation", "materialized_size_bytes"), 1023),
        (("continuation", "receipt_id"), "8" * 64),
        (("continuation", "independent_observation"), False),
        (("continuation", "workspace_lineage_match"), False),
        (("continuation", "no_fixture_create"), False),
        (("model", "purpose"), "bluefire_receiver_evidence_composition_proposal"),
        (("model", "requests"), 1),
        (("model", "requests"), True),
        (("model", "authorization_max_requests"), 3),
        (("model", "authorization_max_requests"), True),
        (("model", "initial_job_id"), "job-" + "a" * 32),
        (("model", "revised_job_id"), "job-" + "0a" * 16),
        (("model", "metadata_only"), False),
        (("model", "reopened"), False),
        (("model", "reasoning_rendered"), False),
        (("model", "current_sources_rechecked"), False),
        (("capture_before_cleanup",), False),
        (("original_failure_preserved",), False),
        (("source_metadata_preserved_after_cleanup",), False),
        (("source_disposition",), "discarded"),
        (
            ("comparison", "run_ids"),
            ["run-20261029T120009Z-9999999999999999", "run-20261029T120008Z-8888888888888888"],
        ),
        (("comparison", "source_integrity"), "unverified"),
        (("comparison", "objective_comparability"), "different_objectives"),
        (("comparison", "objective_changed"), False),
        (("comparison", "objective_recovered"), False),
        (("comparison", "reopened"), False),
    ],
)
def test_retained_execution_requires_exact_failed_source_and_fresh_success(
    path, replacement
) -> None:
    from tools.verify_installed_browser import _valid_retained_execution

    report = receiver_report()
    assert _valid_retained_execution(report)
    selected = report["retained_execution"]
    for key in path[:-1]:
        selected = selected[key]
    selected[path[-1]] = replacement
    assert not _valid_retained_execution(report)


def test_retained_execution_requires_cleanup_finite_counts_and_explicit_check() -> None:
    from tools.verify_installed_browser import _valid_retained_execution

    limits = {
        "retained_list": (1, 8),
        "retained_review": (1, 1),
        "retained_grant": (1, 1),
        "retained_initial_context": (1, 2),
        "retained_history_context": (2, 4),
        "retained_proposal": (2, 2),
        "retained_attempt": (2, 2),
        "retained_knowledge": (1, 1),
        "retained_revoke": (1, 1),
        "retained_comparison": (1, 1),
    }
    for key, (minimum, maximum) in limits.items():
        for count in (minimum, maximum):
            report = receiver_report()
            report["request_counts"][key] = count
            assert _valid_retained_execution(report), (key, count)
        for count in (minimum - 1, maximum + 1, True):
            report = receiver_report()
            report["request_counts"][key] = count
            assert not _valid_retained_execution(report), (key, count)
    report = receiver_report()
    report["cleanup"]["retained_grant_revoked"] = False
    assert not _valid_retained_execution(report)
    report = receiver_report()
    report["checks"].remove(
        "retained_result_reused_in_fresh_successful_attempt_without_prefix_replay"
    )
    assert not _valid_retained_execution(report)
    for field in ("retained_execution", "composition"):
        report = receiver_report()
        del report[field]
        assert not _valid_retained_execution(report)


def test_retained_execution_receipt_preserves_failed_history_without_passing_it() -> None:
    report = receiver_report()
    report["status"] = "failed_or_incomplete"
    receipt = _receiver_report_for_receipt(report)
    assert receipt["status"] == "failed_or_incomplete"
    assert receipt["retained_execution"] == report["retained_execution"]
    assert receipt["composition"] == report["composition"]
    assert not _receiver_driver_passed(report)


def custody_state(monkeypatch):
    """Owned in-memory contracts only; this fixture never starts a product service."""
    from bluefire import retained_artifacts
    from bluefire.util import content_hash

    report = receiver_report()
    proof = report["retained_execution"]
    payload = b'{"generated":true}\n'
    source = proof["source"]
    source["sha256"], source["size_bytes"] = hashlib.sha256(payload).hexdigest(), len(payload)
    source["source_ref"] = content_hash(
        {key: item for key, item in source.items() if key != "source_ref"}
    )
    proof["continuation"].update(
        source_ref=source["source_ref"],
        materialized_sha256=source["sha256"],
        materialized_size_bytes=len(payload),
    )
    grant = {
        "grant_id": proof["grant_id"],
        "grant_digest": content_hash("grant"),
        "pack": proof["pack"],
        "environment": {"control_owner_id": proof["control_owner_id"]},
    }
    owner = {
        "job_id": proof["owner_id"],
        "kind": "composition.objective",
        "state": "completed",
        "request": {"grant_id": grant["grant_id"], "grant_digest": grant["grant_digest"]},
        "progress": {"admission": {"accepted": True, "problem": None}},
    }
    job_rows = {owner["job_id"]: owner}
    attempts = {}
    for role, established in (("original", False), ("continuation", True)):
        expected = proof[role]
        compiled = {
            "scenario": {},
            **(
                {"retained_sources": {"reuse_retained_bundle": deepcopy(source)}}
                if established
                else {}
            ),
        }
        compiled["compiled_digest"] = content_hash(compiled)
        marker = {
            "parent_job_id": owner["job_id"],
            "grant_id": grant["grant_id"],
            "grant_digest": grant["grant_digest"],
            "attempt_id": expected["attempt_id"],
            "run_id": expected["run_id"],
            "compiled_digest": compiled["compiled_digest"],
        }
        result = {
            "objective": {"established": established},
            "cleanup": expected["cleanup"],
            "receiver_result": {"decision": expected["receiver_decision"]},
        }
        child = {
            "job_id": expected["job_id"],
            "kind": "composition.attempt",
            "request": {"composition_attempt": marker},
            "progress": {
                "settlement": "settled",
                "verified_result": result,
                "verified_result_digest": content_hash(result),
            },
        }
        if not established:
            child["progress"]["retained_artifact_capture"] = {"source": deepcopy(source)}
        job_rows[child["job_id"]] = child
        attempts[expected["attempt_id"]] = {
            "state": "settled",
            "compiled": compiled,
            "lease": {
                **{key: item for key, item in marker.items() if key != "parent_job_id"},
                "job_id": child["job_id"],
            },
        }
    view = {"document": grant, "status": "revoked", "lineage_id": source["lineage_id"]}
    store = SimpleNamespace(
        get_job=lambda job_id: job_rows[job_id],
        get_capability_grant=lambda _grant, **_: view,
        get_capability_attempt=lambda attempt_id: attempts[attempt_id],
    )
    jobs = SimpleNamespace(
        store=store,
        clock=lambda: 1,
        _verified_result=lambda attempt: deepcopy(
            job_rows[attempt["lease"]["job_id"]]["progress"]["verified_result"]
        ),
    )
    run_store = object()
    service = SimpleNamespace(composition=jobs, detection_lab=SimpleNamespace(run_store=run_store))
    reads = []
    history = [deepcopy(source)]

    def historical(actual_jobs, actual_grant, *, owner_id):
        assert actual_jobs is jobs and actual_grant is grant and owner_id == owner["job_id"]
        return history

    def resolve(actual_store, actual_source):
        assert actual_store is run_store and actual_source == source
        reads.append(actual_source["source_ref"])
        return payload

    monkeypatch.setattr(retained_artifacts, "historical_sources", historical)
    monkeypatch.setattr(retained_artifacts, "resolve", resolve)
    return report, service, job_rows, attempts, view, history, reads, payload


def test_post_driver_custody_resolves_one_exact_saved_source_without_recording_payload(
    monkeypatch,
) -> None:
    from tools.verify_installed_browser import (
        _valid_receiver_retained_custody,
        _verify_receiver_retained_custody,
    )

    report, service, _, _, _, _, reads, payload = custody_state(monkeypatch)
    receipt = _verify_receiver_retained_custody(service, report)
    assert _valid_receiver_retained_custody(receipt, report["retained_execution"])
    assert reads == [report["retained_execution"]["source"]["source_ref"]]
    assert payload.decode().strip() not in json.dumps(receipt)
    assert receipt["original_objective_established"] is False
    assert receipt["continuation_objective_established"] is True


@pytest.mark.parametrize("mutation", ["owner", "compiled", "objective", "history", "active_grant"])
def test_post_driver_custody_refuses_saved_binding_changes_before_payload_read(
    monkeypatch, mutation
) -> None:
    from tools.verify_installed_browser import _verify_receiver_retained_custody

    report, service, jobs, attempts, view, history, reads, _ = custody_state(monkeypatch)
    proof = report["retained_execution"]
    if mutation == "owner":
        jobs[proof["original"]["job_id"]]["request"]["composition_attempt"][
            "parent_job_id"
        ] = "job-other"
    elif mutation == "compiled":
        attempts[proof["original"]["attempt_id"]]["compiled"]["scenario"] = {"changed": True}
    elif mutation == "objective":
        jobs[proof["continuation"]["job_id"]]["progress"]["verified_result"]["objective"][
            "established"
        ] = False
    elif mutation == "history":
        history.append({**history[0], "attempt_id": "attempt-other"})
    else:
        view["status"] = "active"
    receipt = _verify_receiver_retained_custody(service, report)
    assert receipt["status"] == "unknown"
    assert receipt["reason"] in {
        "saved_owner_binding_unverified",
        "saved_attempt_binding_unverified",
        "captured_source_binding_unverified",
    }
    assert reads == []


def test_post_driver_custody_retains_unknown_when_saved_run_verification_raises_api_error(
    monkeypatch,
) -> None:
    from bluefire.application_errors import APIError
    from tools.verify_installed_browser import _verify_receiver_retained_custody

    report, service, _, _, _, _, reads, _ = custody_state(monkeypatch)

    def unavailable(_attempt):
        raise APIError(422, "invalid_evidence", "private saved run details")

    service.composition._verified_result = unavailable
    receipt = _verify_receiver_retained_custody(service, report)
    assert receipt == {
        "schema_version": "bluefire.installed-retained-source-custody.v1",
        "status": "unknown",
        "reason": "saved_attempt_binding_unverified",
    }
    assert reads == []


def test_post_driver_custody_keeps_missing_payload_unknown_with_historical_metadata(
    monkeypatch,
) -> None:
    from bluefire import retained_artifacts
    from tools.verify_installed_browser import _verify_receiver_retained_custody

    report, service, _, _, _, _, _, _ = custody_state(monkeypatch)

    def unavailable(_store, _source):
        raise retained_artifacts.PayloadUnavailable("private storage location must not be recorded")

    monkeypatch.setattr(retained_artifacts, "resolve", unavailable)
    receipt = _verify_receiver_retained_custody(service, report)
    assert receipt == {
        "schema_version": "bluefire.installed-retained-source-custody.v1",
        "status": "unknown",
        "reason": "retained_payload_unavailable_or_invalid",
    }
    assert report["retained_execution"]["source_metadata_preserved_after_cleanup"] is True


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("status", "unknown"),
        ("owner_id", "job-other"),
        ("source_ref", "sha256:" + "0" * 64),
        ("compiled_digest", "unverified"),
        ("continuation_job_id", "job-other"),
        ("sha256", "0" * 64),
        ("size_bytes", True),
        ("payload_reads", True),
        ("payload_reads", 2),
        ("verified_after_driver_cleanup", False),
        ("original_objective_established", True),
        ("continuation_objective_established", False),
    ],
)
def test_outer_acceptance_requires_actual_post_driver_custody(field, value) -> None:
    report = clean_wrapper_report()
    assert _receiver_retained_redaction_accepted(report)
    report["receiver_retained_source_custody"][field] = value
    assert not _receiver_retained_redaction_accepted(report)


def test_receiver_authorization_persistence_supersedes_same_provider_with_one_final_revoke(
    tmp_path: Path,
) -> None:
    from bluefire import product_store_ai_authorizations as authorization_store
    from bluefire.ai_live_authorization import create_authorization
    from bluefire.ai_wire import AIProviderTransportError
    from bluefire.config import AIProviderConfig
    from bluefire.product_store import ProductStore

    provider = AIProviderConfig.from_mapping(
        {
            "id": "provider.installed-receiver-composition.v1",
            "kind": "openai_responses",
            "model": "bluefire-local-graph-fixture-v1",
            "endpoint": "http://127.0.0.1:8080/v1/responses",
            "api_key": None,
            "timeout_seconds": 20,
            "max_retries": 0,
            "max_output_tokens": 1024,
        }
    )
    context = {"kind": "direct", "binding_digest": "sha256:" + "a" * 64}
    store = ProductStore(tmp_path / "authorizations.db")
    purposes = [
        ("bluefire_composition_proposal", 1),
        ("bluefire_receiver_evidence_composition_proposal", 1),
        ("bluefire_receiver_retained_composition_proposal", 2),
    ]
    grants = []
    reservation = {"requests": 1, "request_bytes": 128, "reserved_output_tokens": 64}
    for purpose, requests in purposes:
        grant = create_authorization(
            {
                "provider": provider.to_dict(),
                "purposes": [purpose],
                "data_scope": "reviewed_lab_context",
                "limits": {
                    "max_requests": requests,
                    "max_request_bytes": requests * 262144,
                    "max_reserved_output_tokens": requests * 1024,
                },
                "expires_in_seconds": 300,
                "approved_by": "installed-receiver-persistence-test",
                "usage_authorized": True,
                "local_endpoint_authorized": True,
            },
            context,
        )
        authorization_store.save_authorization(store, grant)
        rows = authorization_store.list_authorizations(store, context["binding_digest"])
        assert {row["authorization_id"]: row["status"] for row in rows} == {
            **{prior["authorization_id"]: "revoked" for prior in grants},
            grant["authorization_id"]: "active",
        }
        for prior in grants:
            with pytest.raises(AIProviderTransportError):
                authorization_store.reserve(
                    store, prior["authorization_id"], context["binding_digest"], reservation
                )
        for _ in range(requests):
            authorization_store.reserve(
                store, grant["authorization_id"], context["binding_digest"], reservation
            )
        grants.append(grant)

    # Supersession already closed every older grant; only the latest needs a revoke.
    authorization_store.revoke_authorization(
        store, grants[-1]["authorization_id"], context["binding_digest"]
    )
    reopened = ProductStore(tmp_path / "authorizations.db")
    rows = authorization_store.list_authorizations(reopened, context["binding_digest"])
    assert len(rows) == len(grants)
    for row, grant, (purpose, requests) in zip(reversed(rows), grants, purposes, strict=True):
        assert row["authorization_id"] == grant["authorization_id"]
        assert row["authorization_digest"] == grant["authorization_digest"]
        assert row["purposes"] == [purpose]
        assert row["status"] == "revoked"
        assert row["usage"] == {
            "requests": requests,
            "request_bytes": requests * 128,
            "reserved_output_tokens": requests * 64,
        }


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
        "receiver_composition_and_history_authorizations_revoked_after_one_proposal_each"
    )
    assert not _receiver_driver_passed(report)
    report["checks"].append(
        "receiver_composition_and_history_authorizations_revoked_after_one_proposal_each"
    )
    report["checks"].remove("receiver_superseded_model_authorization_remained_revoked")
    assert not _receiver_driver_passed(report)
    report["checks"].append("receiver_superseded_model_authorization_remained_revoked")
    report["cleanup"]["model_authorization_revoked"] = False
    assert not _receiver_driver_passed(report)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("request_count", 0),
        ("request_count", 1),
        ("request_count", 3),
        ("request_count", 2),
        ("request_count", 5),
        ("request_count", True),
        ("purposes", ["bluefire_ai_graph_draft"]),
        ("purposes", ["bluefire_composition_proposal", "bluefire_composition_proposal"]),
        (
            "purposes",
            ["bluefire_receiver_evidence_composition_proposal", "bluefire_composition_proposal"],
        ),
        ("request_bytes", 0),
        ("request_bytes", True),
        ("request_bytes", 1_048_577),
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
    retained = copied / "receiver-retained.mjs"
    retained_proof = copied / "receiver-retained-proof.mjs"
    driver.write_text("// pinned browser driver\n", encoding="utf-8")
    guard.write_text("// pinned request contract\n", encoding="utf-8")
    deadline.write_text("// pinned driver deadline\n", encoding="utf-8")
    knowledge.write_text("// historical findings proof\n", encoding="utf-8")
    evidence.write_text("// historical proposal proof\n", encoding="utf-8")
    retained.write_text("// retained result journey\n", encoding="utf-8")
    retained_proof.write_text("// retained result proof\n", encoding="utf-8")
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
    (checkout / retained.name).write_text("// retained\n", encoding="utf-8")
    (checkout / retained_proof.name).write_text("// retained proof\n", encoding="utf-8")
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


@pytest.mark.parametrize("missing", ["receiver-retained.mjs", "receiver-retained-proof.mjs"])
def test_missing_retained_helpers_fail_before_launch(tmp_path: Path, missing: str) -> None:
    driver = tmp_path / "installed-receiver.mjs"
    driver.write_text("// driver\n", encoding="utf-8")
    for name in (
        "receiver-guards.mjs",
        "receiver-deadline.mjs",
        "receiver-knowledge.mjs",
        "receiver-evidence-proposal.mjs",
        "receiver-retained.mjs",
        "receiver-retained-proof.mjs",
    ):
        if name != missing:
            (tmp_path / name).write_text("// helper\n", encoding="utf-8")
    with pytest.raises(FileNotFoundError):
        _resolve_receiver_driver(driver, tmp_path / "checkout")


@pytest.mark.parametrize("elapsed", [-1, True, "535", None, float("inf"), float("nan"), 1015.01])
def test_receiver_elapsed_receipt_refuses_unbounded_or_invalid_values(elapsed) -> None:
    report = clean_wrapper_report()
    report["receiver_phase_elapsed_seconds"] = elapsed
    assert not _receiver_retained_redaction_accepted(report)


def test_receiver_elapsed_receipt_allows_teardown_after_child_budget() -> None:
    for elapsed in (0, 540.25, 600, 1015):
        report = clean_wrapper_report()
        report["receiver_phase_elapsed_seconds"] = elapsed
        assert _receiver_retained_redaction_accepted(report)


def test_receiver_phase_records_elapsed_when_outer_deadline_prevents_start(
    monkeypatch, tmp_path: Path
) -> None:
    from tools import verify_installed_browser as verifier

    clock = iter([10.0, 10.25])
    observed_caps = []
    monkeypatch.setattr(verifier.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(
        verifier, "_phase_timeout", lambda _deadline, cap: observed_caps.append(cap)
    )
    report = {}
    verifier._run_receiver_phase(
        report=report,
        driver=tmp_path / "driver",
        guards=tmp_path / "guard",
        deadline_file=tmp_path / "deadline",
        node=tmp_path / "node",
        playwright=tmp_path / "playwright",
        output=tmp_path / "out",
        runtime=tmp_path / "runtime",
        environment={},
        work_deadline=9,
        service_type=None,
        runner_lifecycle_type=None,
        create_server=None,
        generate_capability=None,
        cleanup_errors=[],
    )
    assert report == {
        "receiver_phase_status": "not_attempted",
        "receiver_phase_reason": "outer_work_deadline_reached",
        "receiver_phase_elapsed_seconds": 0.25,
    }
    assert observed_caps == [540]
    assert verifier._OVERALL_WORK_BUDGET_SECONDS == 16 * 60
    assert not (tmp_path / "runtime").exists()


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
