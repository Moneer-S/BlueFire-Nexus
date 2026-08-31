"""Fail-closed release workflow for GATE-11 cross-platform proof."""

from __future__ import annotations

import json
import os
import re
import stat
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence, cast

from .architecture_gate import _run_pytest_suite
from .cross_platform_gate_validation import (
    ASSERTION_REPORTS,
    CHECK_NAMES,
    CLASSIFICATION_LIMITATIONS,
    LINUX_UNAVAILABLE_REASON,
    REPORT_PATHS,
    VERIFICATION_REPORT,
    CrossPlatformGateValidationError,
    LinuxRuntimeUnavailableError,
    validate_gate11_verification,
    validate_linux_unavailable_report,
    validate_persisted_cross_platform_gate,
)
from .defense_frontier import _runtime_temp_parent
from .defense_frontier_gate import (
    _isolated_python_environment,
    _run_bounded_helper_process,
)
from .product_acceptance_run_bundle import acceptance_run_binding
from .runner_bootstrap import current_architecture

HELPER_SCHEMA = "bluefire.cross-platform-helper.v1"
VERIFICATION_SCHEMA = "bluefire.cross-platform-gate-verification.v1"
_ACCEPTANCE_ENVIRONMENT = (
    "BLUEFIRE_ACCEPTANCE_ID",
    "BLUEFIRE_ACCEPTANCE_GATE_ID",
    "BLUEFIRE_ACCEPTANCE_CONTRACT_SHA256",
    "BLUEFIRE_ACCEPTANCE_REPOSITORY_COMMIT",
    "BLUEFIRE_ACCEPTANCE_REPOSITORY_TREE",
    "BLUEFIRE_ACCEPTANCE_RELEASE",
    "BLUEFIRE_GATE11_LINUX_WHEELHOUSE",
)
_CONTRACT_TESTS = (
    "tests_platform/test_cross_platform_committed_linux_artifact.py",
    "tests_platform/test_cross_platform_gate.py",
    "tests_platform/test_cross_platform_linux_cleanup_validation.py",
    "tests_platform/test_cross_platform_linux_distribution.py",
    "tests_platform/test_cross_platform_linux_worker_security.py",
    "tests_platform/test_cross_platform_posix_containment.py",
    "tests_platform/test_cross_platform_runtime.py",
    (
        "tests_platform/test_install_gate.py::"
        "test_committed_source_archive_uses_fixed_git_outside_ambient_path"
    ),
    ("tests_platform/test_install_gate.py::test_trusted_git_executable_ignores_ambient_path_entry"),
    "tests_platform/test_packaged_runner_verifier.py",
    (
        "tests_platform/test_runner_cancellation.py::"
        "test_execute_task_cancellation_confirms_descendant_process_is_stopped"
    ),
    ("tests_platform/test_runner_cancellation.py::test_linux_identity_change_is_never_signalled"),
    (
        "tests_platform/test_runner_cancellation.py::"
        "test_linux_process_identity_accepts_zero_scoped_namespace_process"
    ),
    (
        "tests_platform/test_runner_cancellation.py::"
        "test_linux_process_identity_rejects_negative_scope"
    ),
    (
        "tests_platform/test_runner_cancellation.py::"
        "test_linux_private_session_scan_ignores_zero_scoped_namespace_process"
    ),
    (
        "tests_platform/test_runner_cancellation.py::"
        "test_linux_private_registration_rejects_zero_scoped_target"
    ),
    (
        "tests_platform/test_runner_cancellation.py::"
        "test_linux_private_leader_is_reaped_only_after_wnowait_and_empty_session"
    ),
    (
        "tests_platform/test_runner_cancellation.py::"
        "test_linux_private_session_cleanup_includes_alternate_process_groups"
    ),
    (
        "tests_platform/test_runner_cancellation.py::"
        "test_outer_cancellation_cleanup_refuses_missing_lease"
    ),
    (
        "tests_platform/test_runner_cancellation.py::"
        "test_preexisting_or_mismatched_witness_state_never_claims_cooperative_cancel"
    ),
    (
        "tests_platform/test_runner_cancellation.py::"
        "test_private_posix_session_members_are_not_filtered_by_process_group"
    ),
    (
        "tests_platform/test_runner_cancellation.py::"
        "test_watchdog_readiness_failure_retains_and_stops_spawned_process"
    ),
    (
        "tests_platform/test_runner_cancellation.py::"
        "test_watchdog_rejects_parent_death_helper_digest_change"
    ),
    (
        "tests_platform/test_disposable_receiver.py::"
        "test_disposable_peer_wire_documents_bind_process_and_terminal_lifecycle"
    ),
    (
        "tests_platform/test_authenticated_runner_transport.py::"
        "test_client_recovers_exact_result_when_execution_response_is_lost"
    ),
    (
        "tests_platform/test_authenticated_runner_transport.py::"
        "test_completed_result_is_recoverable_after_server_restart"
    ),
    (
        "tests_platform/test_authenticated_runner_transport.py::"
        "test_current_watchdog_cancellation_requires_exact_proof_fields"
    ),
    (
        "tests_platform/test_authenticated_runner_transport.py::"
        "test_restart_reconciles_confirmed_watchdog_terminal_status"
    ),
    (
        "tests_platform/test_authenticated_runner_transport.py::"
        "test_transport_identity_binds_authenticated_peer_and_detects_binary_change"
    ),
    (
        "tests_platform/test_runner_lifecycle.py::"
        "test_real_process_boundary_requires_mtls_health_and_graceful_shutdown"
    ),
    (
        "tests_platform/test_runner_lifecycle.py::"
        "test_recovery_interruption_requires_the_exact_retained_process_handle"
    ),
    "tests_platform/test_registry.py::test_process_tree_cancellation_witness_is_fixed_and_windows_only",
    "tests_platform/test_registry.py::test_representative_actions_are_versioned_bounded_and_cross_platform",
)
_EXPECTED_SUITE_TESTS = (
    "tests_platform.test_authenticated_runner_transport::test_client_recovers_exact_result_when_execution_response_is_lost",
    "tests_platform.test_authenticated_runner_transport::test_completed_result_is_recoverable_after_server_restart",
    "tests_platform.test_authenticated_runner_transport::test_current_watchdog_cancellation_requires_exact_proof_fields[ack_without_request]",
    "tests_platform.test_authenticated_runner_transport::test_current_watchdog_cancellation_requires_exact_proof_fields[cleanup_unverified]",
    "tests_platform.test_authenticated_runner_transport::test_current_watchdog_cancellation_requires_exact_proof_fields[extra]",
    "tests_platform.test_authenticated_runner_transport::test_current_watchdog_cancellation_requires_exact_proof_fields[missing]",
    "tests_platform.test_authenticated_runner_transport::test_current_watchdog_cancellation_requires_exact_proof_fields[non_boolean]",
    "tests_platform.test_authenticated_runner_transport::test_restart_reconciles_confirmed_watchdog_terminal_status[cancelled-cancelled-cancelled-task_cancelled]",
    "tests_platform.test_authenticated_runner_transport::test_restart_reconciles_confirmed_watchdog_terminal_status[failed-timed_out-timed_out-task_timed_out]",
    "tests_platform.test_authenticated_runner_transport::test_transport_identity_binds_authenticated_peer_and_detects_binary_change",
    "tests_platform.test_cross_platform_committed_linux_artifact::test_linux_artifact_rejects_wrong_acceptance_tree",
    "tests_platform.test_cross_platform_committed_linux_artifact::test_linux_artifact_uses_exact_commit_blobs_not_live_worktree",
    "tests_platform.test_cross_platform_committed_linux_artifact::test_linux_product_stage_replaces_live_runner_with_commit_blobs",
    "tests_platform.test_cross_platform_gate::test_boolean_only_recovery_claim_is_not_evidence",
    "tests_platform.test_cross_platform_gate::test_cancellation_validator_reprobes_exact_process_identities",
    "tests_platform.test_cross_platform_gate::test_fresh_cancellation_validator_executes_exact_wheel_member",
    "tests_platform.test_cross_platform_gate::test_gate11_event_stream_uses_canonical_event_type",
    "tests_platform.test_cross_platform_gate::test_gate11_execute_approval_identity_is_pre_run_intent_bound",
    "tests_platform.test_cross_platform_gate::test_gate11_fails_with_the_exact_typed_linux_reason",
    "tests_platform.test_cross_platform_gate::test_gate11_locked_contract_matches_authoritative_workflow",
    "tests_platform.test_cross_platform_gate::test_gate11_new_production_modules_stay_within_the_locked_line_budget",
    "tests_platform.test_cross_platform_gate::test_gate11_observation_uses_canonical_filesystem_collector_contract",
    "tests_platform.test_cross_platform_gate::test_gate11_publishes_only_acceptance_bundle_reference_fields",
    "tests_platform.test_cross_platform_gate::test_gate11_runner_evidence_uses_sealed_profile_digest",
    "tests_platform.test_cross_platform_gate::test_invalid_committed_wheelhouse_lock_is_not_a_dependency_blocker",
    "tests_platform.test_cross_platform_gate::test_linux_dependency_unavailability_is_exact_and_typed",
    "tests_platform.test_cross_platform_gate::test_linux_distribution_unavailability_is_exact_and_typed[absent]",
    "tests_platform.test_cross_platform_gate::test_linux_distribution_unavailability_is_exact_and_typed[incompatible]",
    "tests_platform.test_cross_platform_gate::test_linux_report_reader_rejects_nonfinite_or_noncanonical_json[noncanonical]",
    "tests_platform.test_cross_platform_gate::test_linux_report_reader_rejects_nonfinite_or_noncanonical_json[nonfinite]",
    "tests_platform.test_cross_platform_linux_cleanup_validation::test_linux_cleanup_absence_reprobe_targets_disposable_distribution",
    "tests_platform.test_cross_platform_linux_cleanup_validation::test_linux_cleanup_boundary_binds_exact_persisted_identities",
    "tests_platform.test_cross_platform_linux_cleanup_validation::test_linux_cleanup_boundary_rehashes_repository_verifier",
    "tests_platform.test_cross_platform_linux_cleanup_validation::test_linux_cleanup_boundary_rejects_live_absence_mismatch",
    "tests_platform.test_cross_platform_linux_cleanup_validation::test_linux_cleanup_boundary_rejects_unbound_or_tampered_claims[duplicate_identity]",
    "tests_platform.test_cross_platform_linux_cleanup_validation::test_linux_cleanup_boundary_rejects_unbound_or_tampered_claims[identity_count]",
    "tests_platform.test_cross_platform_linux_cleanup_validation::test_linux_cleanup_boundary_rejects_unbound_or_tampered_claims[identity_digest]",
    "tests_platform.test_cross_platform_linux_cleanup_validation::test_linux_cleanup_boundary_rejects_unbound_or_tampered_claims[identity_fields]",
    "tests_platform.test_cross_platform_linux_cleanup_validation::test_linux_cleanup_boundary_rejects_unbound_or_tampered_claims[identity_workspace]",
    "tests_platform.test_cross_platform_linux_cleanup_validation::test_linux_cleanup_boundary_rejects_unbound_or_tampered_claims[outer_workspace]",
    "tests_platform.test_cross_platform_linux_cleanup_validation::test_linux_cleanup_boundary_rejects_unbound_or_tampered_claims[verifier_digest]",
    "tests_platform.test_cross_platform_linux_cleanup_validation::test_linux_cleanup_boundary_rejects_unbound_or_tampered_claims[worker_identity]",
    "tests_platform.test_cross_platform_linux_distribution::test_disposable_cleanup_unregisters_and_removes_storage",
    "tests_platform.test_cross_platform_linux_distribution::test_failed_clone_cleans_private_storage",
    "tests_platform.test_cross_platform_linux_distribution::test_stream_clone_pipes_export_directly_into_import",
    "tests_platform.test_cross_platform_linux_worker_security::test_linux_cleanup_falls_back_for_invalid_supervisor_publication[invalid-ready]",
    "tests_platform.test_cross_platform_linux_worker_security::test_linux_cleanup_falls_back_for_invalid_supervisor_publication[malformed-supervisor]",
    "tests_platform.test_cross_platform_linux_worker_security::test_linux_cleanup_ignores_unready_supervisor_publication",
    "tests_platform.test_cross_platform_linux_worker_security::test_linux_control_json_parses_descriptor_verified_payload",
    "tests_platform.test_cross_platform_linux_worker_security::test_linux_run_scan_rejects_every_derived_key_encoding[0]",
    "tests_platform.test_cross_platform_linux_worker_security::test_linux_run_scan_rejects_every_derived_key_encoding[1]",
    "tests_platform.test_cross_platform_linux_worker_security::test_linux_run_scan_rejects_every_derived_key_encoding[2]",
    "tests_platform.test_cross_platform_linux_worker_security::test_linux_run_scan_rejects_every_derived_key_encoding[3]",
    "tests_platform.test_cross_platform_linux_worker_security::test_linux_run_scan_rejects_every_derived_key_encoding[4]",
    "tests_platform.test_cross_platform_linux_worker_security::test_linux_run_scan_rejects_every_derived_key_encoding[5]",
    "tests_platform.test_cross_platform_linux_worker_security::test_linux_run_scan_rejects_every_derived_key_encoding[6]",
    "tests_platform.test_cross_platform_linux_worker_security::test_linux_supervisor_publication_fails_closed_before_ready[after-link]",
    "tests_platform.test_cross_platform_linux_worker_security::test_linux_supervisor_publication_fails_closed_before_ready[after-unlink]",
    "tests_platform.test_cross_platform_linux_worker_security::test_linux_supervisor_publication_fails_closed_before_ready[ready-open]",
    "tests_platform.test_cross_platform_linux_worker_security::test_linux_supervisor_publication_is_atomic_across_short_writes",
    "tests_platform.test_cross_platform_linux_worker_security::test_linux_supervisor_publication_refuses_destination_collision",
    "tests_platform.test_cross_platform_linux_worker_security::test_linux_supervisor_publication_rejects_zero_progress",
    "tests_platform.test_cross_platform_linux_worker_security::test_linux_supervisor_ready_creation_is_publication_commit_point",
    "tests_platform.test_cross_platform_linux_worker_security::test_linux_worker_executes_only_the_registered_alternate",
    "tests_platform.test_cross_platform_linux_worker_security::test_linux_worker_uses_gate_bound_review_identity",
    "tests_platform.test_cross_platform_linux_worker_security::test_receiver_task_key_factory_retains_every_derived_key",
    "tests_platform.test_cross_platform_posix_containment::test_failure_cleanup_stops_verified_session_members_before_reaping_leader",
    "tests_platform.test_cross_platform_posix_containment::test_linux_bundle_rejects_watchdog_containment_substitution[boolean-only]",
    "tests_platform.test_cross_platform_posix_containment::test_linux_bundle_rejects_watchdog_containment_substitution[claim-only]",
    "tests_platform.test_cross_platform_posix_containment::test_linux_bundle_rejects_watchdog_containment_substitution[report-only]",
    "tests_platform.test_cross_platform_posix_containment::test_linux_bundle_requires_watchdog_containment_field",
    "tests_platform.test_cross_platform_posix_containment::test_linux_watchdog_containment_proof_is_exact_and_hash_bound",
    "tests_platform.test_cross_platform_posix_containment::test_parent_death_helper_is_execution_layer_and_bounded",
    "tests_platform.test_cross_platform_posix_containment::test_pidfd_identity_change_is_closed_without_signal_authority",
    "tests_platform.test_cross_platform_runtime::test_authenticated_transport_recovery_is_full_and_independently_validated",
    "tests_platform.test_cross_platform_runtime::test_disposable_receiver_retains_the_exact_process_handle_and_job",
    "tests_platform.test_cross_platform_runtime::test_report_only_recovery_claim_cannot_substitute_for_live_witness",
    "tests_platform.test_cross_platform_runtime::test_windows_evidence_scan_includes_derived_receiver_task_key",
    "tests_platform.test_cross_platform_runtime::test_windows_execution_summary_binds_actual_step_count",
    "tests_platform.test_disposable_receiver::test_disposable_peer_wire_documents_bind_process_and_terminal_lifecycle",
    "tests_platform.test_install_gate::test_committed_source_archive_uses_fixed_git_outside_ambient_path",
    "tests_platform.test_install_gate::test_trusted_git_executable_ignores_ambient_path_entry",
    "tests_platform.test_packaged_runner_verifier::test_disposable_workspace_proof_is_sanitized_and_machine_checkable",
    "tests_platform.test_packaged_runner_verifier::test_disposable_workspace_proof_refuses_checkout_work_root",
    "tests_platform.test_packaged_runner_verifier::test_disposable_workspace_proof_refuses_escaped_or_dirty_sandbox",
    "tests_platform.test_packaged_runner_verifier::test_packaged_wheel_refuses_foreign_native_runner_sibling",
    "tests_platform.test_packaged_runner_verifier::test_wheel_member_extraction_preserves_binary_bytes",
    "tests_platform.test_registry::test_process_tree_cancellation_witness_is_fixed_and_windows_only",
    "tests_platform.test_registry::test_representative_actions_are_versioned_bounded_and_cross_platform",
    "tests_platform.test_runner_cancellation::test_execute_task_cancellation_confirms_descendant_process_is_stopped",
    "tests_platform.test_runner_cancellation::test_linux_identity_change_is_never_signalled",
    "tests_platform.test_runner_cancellation::test_linux_private_leader_is_reaped_only_after_wnowait_and_empty_session",
    "tests_platform.test_runner_cancellation::test_linux_private_registration_rejects_zero_scoped_target",
    "tests_platform.test_runner_cancellation::test_linux_private_session_cleanup_includes_alternate_process_groups",
    "tests_platform.test_runner_cancellation::test_linux_private_session_scan_ignores_zero_scoped_namespace_process",
    "tests_platform.test_runner_cancellation::test_linux_process_identity_accepts_zero_scoped_namespace_process",
    "tests_platform.test_runner_cancellation::test_linux_process_identity_rejects_negative_scope",
    "tests_platform.test_runner_cancellation::test_outer_cancellation_cleanup_refuses_missing_lease",
    "tests_platform.test_runner_cancellation::test_preexisting_or_mismatched_witness_state_never_claims_cooperative_cancel",
    "tests_platform.test_runner_cancellation::test_private_posix_session_members_are_not_filtered_by_process_group",
    "tests_platform.test_runner_cancellation::test_watchdog_readiness_failure_retains_and_stops_spawned_process",
    "tests_platform.test_runner_cancellation::test_watchdog_rejects_parent_death_helper_digest_change",
    "tests_platform.test_runner_lifecycle::test_real_process_boundary_requires_mtls_health_and_graceful_shutdown",
    "tests_platform.test_runner_lifecycle::test_recovery_interruption_requires_the_exact_retained_process_handle",
)

_EXPECTED_ASSERTIONS: Mapping[
    str, tuple[str, str, tuple[str, ...], str, tuple[int, ...], tuple[str, ...]]
] = {
    "GATE-11-WINDOWS-PACKAGED-EXECUTE": (
        "dynamic",
        "windows_packaged_execute",
        (REPORT_PATHS[0], VERIFICATION_REPORT),
        "GATE-11.windows-packaged-execute.v1",
        (0,),
        (),
    ),
    "GATE-11-LINUX-CONTAINER-EXECUTE": (
        "dynamic",
        "linux_container_execute",
        (REPORT_PATHS[1], VERIFICATION_REPORT),
        "GATE-11.linux-disposable-execute.v1",
        (1,),
        (),
    ),
    "GATE-11-PROCESS-TREE-CANCEL": (
        "dynamic",
        "process_tree_cancel",
        (REPORT_PATHS[2], VERIFICATION_REPORT),
        "GATE-11.process-tree-cancellation.v1",
        (),
        (),
    ),
    "GATE-11-NETWORK-RECEIVER": (
        "dynamic",
        "network_receiver",
        (REPORT_PATHS[3], VERIFICATION_REPORT),
        "GATE-11.authenticated-loopback-receiver.v1",
        (),
        (CLASSIFICATION_LIMITATIONS[1],),
    ),
    "GATE-11-TRANSPORT-RECOVERY": (
        "dynamic",
        "transport_recovery",
        (REPORT_PATHS[4], VERIFICATION_REPORT),
        "GATE-11.authenticated-multiprocess-recovery.v1",
        (),
        (),
    ),
    "GATE-11-PLATFORM-READINESS": (
        "dynamic",
        "platform_readiness",
        (REPORT_PATHS[5], VERIFICATION_REPORT),
        "GATE-11.platform-readiness-errors.v1",
        (),
        (),
    ),
    "GATE-11-MACOS-CONTRACT": (
        "structural",
        "macos_contract",
        (REPORT_PATHS[6], VERIFICATION_REPORT),
        "GATE-11.macos-structural-contract.v1",
        (),
        (CLASSIFICATION_LIMITATIONS[0],),
    ),
    "GATE-11-PROOF-CLASSIFICATION": (
        "structural",
        "proof_classification",
        (REPORT_PATHS[7], VERIFICATION_REPORT),
        "GATE-11.proof-classification.v1",
        (),
        CLASSIFICATION_LIMITATIONS,
    ),
}


@dataclass(frozen=True)
class Gate11Outcome:
    status: str
    proofs: tuple[Mapping[str, Any], ...]
    failure_reason: str | None


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate helper key")
        value[key] = item
    return value


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    payload = (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    )
    if len(payload) > 2 * 1024 * 1024 or path.exists() or not path.parent.is_dir():
        raise ValueError("Gate 11 verification destination is unsafe")
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    identity: tuple[int, int] | None = None
    try:
        descriptor = os.open(path, flags, 0o600)
        details = os.fstat(descriptor)
        identity = (int(details.st_dev), int(details.st_ino))
        if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
            raise ValueError("Gate 11 verification destination is unsafe")
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("Gate 11 verification write made no progress")
            offset += written
        os.fsync(descriptor)
        current = os.fstat(descriptor)
        if (
            (int(current.st_dev), int(current.st_ino)) != identity
            or not stat.S_ISREG(current.st_mode)
            or current.st_nlink != 1
            or current.st_size != len(payload)
        ):
            raise ValueError("Gate 11 verification destination changed during publication")
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
            descriptor = None
        try:
            current = path.lstat()
            if (
                identity == (int(current.st_dev), int(current.st_ino))
                and not stat.S_ISLNK(current.st_mode)
                and not int(getattr(current, "st_file_attributes", 0))
                & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            ):
                path.unlink()
        except OSError:
            pass
        raise
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _run_helper(repository: Path, evidence_dir: Path) -> Mapping[str, Any]:
    command = [
        sys.executable,
        "-I",
        "-B",
        "-X",
        "utf8",
        os.fspath(repository / "tools" / "run_cross_platform_gate_journey.py"),
        "--repository",
        os.fspath(repository),
        "--evidence-dir",
        os.fspath(evidence_dir),
    ]
    reported = ["{python}", "tools/run_cross_platform_gate_journey.py", "{fixed-arguments}"]
    try:
        with tempfile.TemporaryDirectory(prefix=".gate11-helper-", dir=evidence_dir) as temporary:
            temporary_root = Path(temporary)
            environment = _isolated_python_environment(
                temporary_root,
                passthrough=_ACCEPTANCE_ENVIRONMENT,
            )
            isolated_home = temporary_root / "home"
            isolated_local = isolated_home / "AppData" / "Local"
            isolated_roaming = isolated_home / "AppData" / "Roaming"
            isolated_local.mkdir(parents=True)
            isolated_roaming.mkdir(parents=True)
            environment.update(
                {
                    "HOME": os.fspath(isolated_home),
                    "USERPROFILE": os.fspath(isolated_home),
                    "LOCALAPPDATA": os.fspath(isolated_local),
                    "APPDATA": os.fspath(isolated_roaming),
                }
            )
            if os.name == "nt":
                environment["PROCESSOR_ARCHITECTURE"] = {
                    "x86_64": "AMD64",
                    "aarch64": "ARM64",
                }[current_architecture()]
            returncode, output = _run_bounded_helper_process(
                command,
                repository=repository,
                environment=environment,
                timeout_seconds=1_500,
            )
            summary = json.loads(
                output.decode("utf-8"),
                object_pairs_hook=_strict_object,
                parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
            )
        valid_shape = bool(
            isinstance(summary, Mapping)
            and set(summary)
            == {"schema_version", "status", "blocking_check", "reports", "run_count"}
            and summary.get("schema_version") == HELPER_SCHEMA
            and summary.get("status") in {"passed", "failed"}
            and summary.get("reports") == list(REPORT_PATHS)
            and type(summary.get("run_count")) is int
            and 0 <= int(summary["run_count"]) <= 2
            and (
                summary.get("blocking_check") is None
                or summary.get("blocking_check") == "linux_container_execute"
            )
        )
        passed = bool(
            valid_shape
            and returncode == 0
            and summary.get("status") == "passed"
            and summary.get("blocking_check") is None
            and summary.get("run_count") == 2
        )
        return {
            "schema_version": summary.get("schema_version") if valid_shape else None,
            "status": summary.get("status") if valid_shape else "failed",
            "blocking_check": summary.get("blocking_check") if valid_shape else None,
            "reports": summary.get("reports") if valid_shape else [],
            "run_count": summary.get("run_count") if valid_shape else 0,
            "exit_code": returncode,
            "command": reported,
            "protocol_valid": valid_shape,
            "passed": passed,
        }
    except (OSError, UnicodeError, json.JSONDecodeError, RuntimeError, TypeError, ValueError):
        return {
            "schema_version": None,
            "status": "failed",
            "blocking_check": None,
            "reports": [],
            "run_count": 0,
            "exit_code": None,
            "command": reported,
            "protocol_valid": False,
            "passed": False,
        }


def _acceptance_binding() -> Mapping[str, str]:
    fields = (
        ("acceptance_id", "BLUEFIRE_ACCEPTANCE_ID"),
        ("gate_id", "BLUEFIRE_ACCEPTANCE_GATE_ID"),
        ("contract_sha256", "BLUEFIRE_ACCEPTANCE_CONTRACT_SHA256"),
        ("repository_commit", "BLUEFIRE_ACCEPTANCE_REPOSITORY_COMMIT"),
        ("repository_tree", "BLUEFIRE_ACCEPTANCE_REPOSITORY_TREE"),
        ("release", "BLUEFIRE_ACCEPTANCE_RELEASE"),
    )
    values: dict[str, str] = {}
    for field, name in fields:
        value = os.environ.get(name)
        if not isinstance(value, str) or not value or len(value) > 512:
            raise ValueError(f"required acceptance binding {name} is unavailable")
        values[field] = value
    if values["gate_id"] != "GATE-11" or values["release"] not in {"true", "false"}:
        raise ValueError("GATE-11 acceptance binding is invalid")
    return cast(Mapping[str, str], acceptance_run_binding(**values))


def _suite_is_exact(value: Any) -> bool:
    expected_fields = {
        "schema_version",
        "suite_id",
        "command",
        "exit_code",
        "passed",
        "tests",
        "passed_tests",
        "failed_tests",
        "skipped_tests",
    }
    return bool(
        isinstance(value, Mapping)
        and set(value) == expected_fields
        and value.get("schema_version") == "bluefire.architecture-dynamic-check.v1"
        and value.get("suite_id") == "cross-platform-contracts"
        and value.get("command")
        == [
            "{python}",
            "-m",
            "pytest",
            "-p",
            "no:cacheprovider",
            "-q",
            *_CONTRACT_TESTS,
            "--junitxml={temporary}",
        ]
        and value.get("exit_code") == 0
        and value.get("passed") is True
        and value.get("tests") == len(_EXPECTED_SUITE_TESTS)
        and value.get("passed_tests") == list(_EXPECTED_SUITE_TESTS)
        and value.get("failed_tests") == []
        and value.get("skipped_tests") == []
    )


def _failure(issues: Sequence[object]) -> Gate11Outcome:
    absolute = re.compile(r"(?:^|[\s(\[{'\"=])(?:[A-Za-z]:[\\/]|\\\\[^\\/\s]+[\\/]|/[^\s])")
    safe: list[str] = []
    for issue in issues:
        raw = str(issue)
        value = (
            "validation failure [private-path-redacted]"
            if absolute.search(raw)
            else " ".join(raw.split())
        )
        safe.append((value or "unknown validation failure")[:300])
    reason = "GATE-11 failed checks: " + ", ".join(dict.fromkeys(safe))
    return Gate11Outcome(status="failed", proofs=(), failure_reason=reason[:1800])


def _proof(
    assertion_id: str,
    kind: str,
    test_id: str,
    artifacts: Sequence[str],
    bundles: Sequence[Mapping[str, str]],
    limitations: Sequence[str],
) -> Mapping[str, Any]:
    return {
        "kind": kind,
        "status": "passed",
        "test_id": test_id,
        "assertion_ids": [assertion_id],
        "evidence_artifacts": list(artifacts),
        "run_ids": [bundle["run_id"] for bundle in bundles],
        "run_bundles": [dict(bundle) for bundle in bundles],
        "environment_limitations": list(limitations),
    }


def run_gate_11(
    gate: Any,
    evidence_dir: Path,
    *,
    repository_root: Path | None = None,
) -> Gate11Outcome:
    raw_repository = repository_root or Path.cwd()
    try:
        repository_details = raw_repository.lstat()
        destination_details = evidence_dir.lstat()
    except OSError:
        return _failure(("Gate 11 roots are absent or unreadable",))
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    if (
        not stat.S_ISDIR(repository_details.st_mode)
        or stat.S_ISLNK(repository_details.st_mode)
        or int(getattr(repository_details, "st_file_attributes", 0)) & reparse
        or not stat.S_ISDIR(destination_details.st_mode)
        or stat.S_ISLNK(destination_details.st_mode)
        or int(getattr(destination_details, "st_file_attributes", 0)) & reparse
    ):
        return _failure(("Gate 11 roots are unsafe",))
    repository = raw_repository.resolve(strict=True)
    destination = evidence_dir.resolve(strict=True)
    contract_assertions = {
        assertion.assertion_id: assertion.proof for assertion in getattr(gate, "assertions", ())
    }
    expected = {assertion_id: details[0] for assertion_id, details in _EXPECTED_ASSERTIONS.items()}
    if contract_assertions != expected or tuple(expected) != tuple(
        row[0] for row in ASSERTION_REPORTS
    ):
        return _failure(("locked GATE-11 assertion set mismatch",))
    if any((destination / name).exists() for name in (*REPORT_PATHS, VERIFICATION_REPORT, "runs")):
        return _failure(("Gate 11 evidence directory contains stale owned artifacts",))

    started = datetime.now(timezone.utc)
    helper = _run_helper(repository, destination)
    finished = datetime.now(timezone.utc)
    if helper.get("blocking_check") == "linux_container_execute":
        try:
            reason = validate_linux_unavailable_report(destination)
        except (OSError, ValueError, CrossPlatformGateValidationError) as exc:
            return _failure(("Linux helper failed without a valid typed availability report", exc))
        return Gate11Outcome(status="failed", proofs=(), failure_reason=reason)
    if helper.get("passed") is not True:
        return _failure(("cross-platform helper failed or returned an invalid protocol",))

    suite = _run_pytest_suite(
        repository,
        _runtime_temp_parent(),
        suite_id="cross-platform-contracts",
        tests=_CONTRACT_TESTS,
        timeout_seconds=420,
    )
    issues: list[object] = []
    if not _suite_is_exact(suite):
        issues.append("cross-platform focused regression suite failed, changed, or skipped")
    checks: Mapping[str, bool] = {}
    bundles: tuple[Mapping[str, str], ...] = ()
    try:
        checks, bundles = validate_persisted_cross_platform_gate(
            repository,
            destination,
            expected_binding=_acceptance_binding(),
            not_before=started,
            not_after=finished,
        )
        if set(checks) != CHECK_NAMES or any(value is not True for value in checks.values()):
            raise CrossPlatformGateValidationError("Gate 11 semantic check inventory is incomplete")
        if len(bundles) != 2:
            raise CrossPlatformGateValidationError("Gate 11 requires exactly two run bundles")
    except LinuxRuntimeUnavailableError:
        return Gate11Outcome(status="failed", proofs=(), failure_reason=LINUX_UNAVAILABLE_REASON)
    except (LookupError, OSError, TypeError, ValueError, CrossPlatformGateValidationError) as exc:
        issues.append(exc)
    if issues:
        return _failure(issues)

    try:
        final_checks, final_bundles = validate_persisted_cross_platform_gate(
            repository,
            destination,
            expected_binding=_acceptance_binding(),
            not_before=started,
            not_after=finished,
        )
        if final_checks != checks or final_bundles != bundles:
            raise CrossPlatformGateValidationError(
                "Gate 11 evidence changed after independent validation"
            )
    except (LookupError, OSError, TypeError, ValueError, CrossPlatformGateValidationError) as exc:
        return _failure((exc,))

    verification = {
        "schema_version": VERIFICATION_SCHEMA,
        "passed": True,
        "helper": {
            key: helper.get(key)
            for key in (
                "schema_version",
                "status",
                "reports",
                "run_count",
                "blocking_check",
                "exit_code",
                "command",
                "protocol_valid",
            )
        },
        "suite": suite,
        "checks": dict(checks),
        "run_ids": [bundle["run_id"] for bundle in bundles],
        "reports": list(REPORT_PATHS),
        "proof_kinds": ["dynamic", "structural"],
    }
    try:
        _write_json(destination / VERIFICATION_REPORT, verification)
        validate_gate11_verification(
            destination,
            expected_checks=checks,
            expected_run_ids=[bundle["run_id"] for bundle in bundles],
            expected_suite_tests=_EXPECTED_SUITE_TESTS,
        )
    except (OSError, TypeError, ValueError, CrossPlatformGateValidationError) as exc:
        return _failure((exc,))

    proofs = tuple(
        _proof(
            assertion_id,
            kind,
            test_id,
            artifacts,
            tuple(bundles[index] for index in bundle_indexes),
            limitations,
        )
        for assertion_id, (
            kind,
            check,
            artifacts,
            test_id,
            bundle_indexes,
            limitations,
        ) in _EXPECTED_ASSERTIONS.items()
        if checks.get(check) is True
    )
    if (
        len(proofs) != 8
        or len({proof["test_id"] for proof in proofs}) != 8
        or {proof["kind"] for proof in proofs} != {"dynamic", "structural"}
    ):
        return _failure(("Gate 11 proof cardinality is not exact",))
    return Gate11Outcome(status="passed", proofs=proofs, failure_reason=None)


__all__ = [
    "Gate11Outcome",
    "HELPER_SCHEMA",
    "VERIFICATION_SCHEMA",
    "run_gate_11",
]
