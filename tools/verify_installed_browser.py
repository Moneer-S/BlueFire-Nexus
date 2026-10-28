"""Exercise the installed wheel's real HTTP service and packaged desktop UI.

Run this copied verifier with the wheel-only interpreter, outside the checkout.
The default Linux browser journey permits saved generated work and AI-Off
simulation; it does not establish native execution. An optional receiver driver
can run one scoped installed retained-redaction workflow, but not live inference
or external access.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import re
import shutil
import signal
import subprocess
import sys
import sysconfig
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write_new(path: Path, value: object) -> None:
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


_FIXTURE_PURPOSES = (
    "bluefire_experiment_assistance",
    "bluefire_ai_graph_draft",
    "bluefire_experiment_assistance",
    "bluefire_detection_source_creation",
)
_COMPOSITION_PURPOSES = (
    "bluefire_linux_file_access_composition_proposal",
    "bluefire_macos_file_access_composition_proposal",
)
_FIXTURE_MODEL = "bluefire-local-graph-fixture-v1"
_RECEIVER_PROFILE = "sandbox-endpoint-deep-lab.v1"
_RECEIVER_SCENARIO = "scenario.receiver-defense.redaction-validation.v1"
_RECEIVER_COPY_SCENARIO = re.compile(
    r"scenario\.receiver-defense\.redaction-validation\.copy\."
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.v1"
)
_OVERALL_WORK_BUDGET_SECONDS = 16 * 60
_OVERALL_CLEANUP_RESERVE_SECONDS = 55


class _WorkDeadlineReached(RuntimeError):
    def __init__(self, phase: str) -> None:
        super().__init__(phase)
        self.phase = phase


def _contains_receiver_session_token_field(value: object) -> bool:
    if isinstance(value, dict):
        return any(
            key in {"session_id", "receiver_session_id"}
            or _contains_receiver_session_token_field(item)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return any(_contains_receiver_session_token_field(item) for item in value)
    return False


def _receiver_report_for_receipt(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError("Receiver driver report has an invalid shape")
    if _contains_receiver_session_token_field(value):
        raise ValueError("Receiver driver report contains a forbidden credential field")
    if not isinstance(value.get("cleanup"), dict):
        raise ValueError("Receiver driver report has an invalid shape")
    keys = (
        "status",
        "workflow",
        "runner_profile",
        "target_scope",
        "generated_record_count",
        "unique_receiver_session_count",
        "source_starter_scenario_id",
        "saved_scenario_copy",
        "run_id",
        "original_owner_job_id",
        "linked_owner_job_id",
        "baseline",
        "original_control",
        "linked_retest",
        "composition",
        "phase_evidence",
        "checks",
        "request_counts",
        "blocked_requests",
        "cleanup",
        "owner_status",
    )
    return {
        key: value.get(key, [] if key in {"checks", "blocked_requests"} else {}) for key in keys
    }


def _valid_receiver_artifact(value: object) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == {"sha256", "size_bytes"}
        and isinstance(value.get("sha256"), str)
        and re.fullmatch(r"[0-9a-f]{64}", value["sha256"]) is not None
        and type(value.get("size_bytes")) is int
        and value["size_bytes"] > 0
    )


def _valid_receiver_composition(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    composition = value.get("composition")
    counts = value.get("request_counts")
    checks = value.get("checks")
    cleanup = value.get("cleanup")
    evidence = value.get("phase_evidence")
    if not all(isinstance(item, dict) for item in (composition, counts, cleanup)):
        return False
    if not isinstance(checks, list) or not isinstance(evidence, list):
        return False
    comparison = composition.get("comparison")
    result_cleanup = composition.get("cleanup")
    if not isinstance(comparison, dict) or not isinstance(result_cleanup, dict):
        return False
    return (
        set(composition)
        == {
            "control_owner_job_id",
            "objective_owner_job_id",
            "grant_id",
            "grant_status",
            "attempt_job_id",
            "attempt_id",
            "settlement",
            "run_id",
            "verified_result_digest",
            "receiver_decision",
            "receiver_authenticated",
            "record_count",
            "redacted_record_count",
            "retained_record_count",
            "empty_record_count",
            "cleanup",
            "objective_established",
            "finalized_run_objective_reached",
            "graph_objective_reached",
            "comparison",
        }
        and composition["control_owner_job_id"] == value.get("original_owner_job_id")
        and isinstance(composition["objective_owner_job_id"], str)
        and re.fullmatch(r"job-[0-9a-f]{32}", composition["objective_owner_job_id"]) is not None
        and isinstance(composition["grant_id"], str)
        and re.fullmatch(r"grant-[0-9a-f]{32}", composition["grant_id"]) is not None
        and composition["grant_status"] == "revoked"
        and isinstance(composition["attempt_job_id"], str)
        and re.fullmatch(r"job-[0-9a-f]{32}", composition["attempt_job_id"]) is not None
        and composition["attempt_job_id"] != composition["objective_owner_job_id"]
        and isinstance(composition["attempt_id"], str)
        and re.fullmatch(r"attempt-[0-9a-f]{32}", composition["attempt_id"]) is not None
        and composition["settlement"] == "settled"
        and isinstance(composition["run_id"], str)
        and re.fullmatch(r"run-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}", composition["run_id"]) is not None
        and composition["run_id"] != value.get("run_id")
        and composition["run_id"]
        not in {row.get("run_id") for row in evidence if isinstance(row, dict)}
        and isinstance(composition["verified_result_digest"], str)
        and re.fullmatch(r"sha256:[0-9a-f]{64}", composition["verified_result_digest"]) is not None
        and composition["receiver_decision"] == "policy_refused"
        and composition["receiver_authenticated"] is True
        and type(composition["record_count"]) is int
        and composition["record_count"] == 8
        and type(composition["redacted_record_count"]) is int
        and composition["redacted_record_count"] == 0
        and type(composition["retained_record_count"]) is int
        and composition["retained_record_count"] == 8
        and type(composition["empty_record_count"]) is int
        and composition["empty_record_count"] == 0
        and result_cleanup == {"run": "complete", "receiver": "verified_closed"}
        and composition["objective_established"] is False
        and type(composition["finalized_run_objective_reached"]) is bool
        and type(composition["graph_objective_reached"]) is bool
        and composition["graph_objective_reached"] is composition["finalized_run_objective_reached"]
        and set(comparison)
        == {
            "baseline_run_id",
            "snapshot_id",
            "snapshot_digest",
            "source_integrity",
            "objective_comparability",
            "objective_changed",
            "objective_recovered",
            "reopened",
        }
        and comparison["baseline_run_id"] == value.get("run_id")
        and isinstance(comparison["snapshot_id"], str)
        and re.fullmatch(r"run-comparison-[0-9a-f]{64}", comparison["snapshot_id"]) is not None
        and isinstance(comparison["snapshot_digest"], str)
        and re.fullmatch(r"sha256:[0-9a-f]{64}", comparison["snapshot_digest"]) is not None
        and comparison["source_integrity"] == "verified"
        and comparison["objective_comparability"] == "different_objectives"
        and comparison["objective_changed"] is False
        and comparison["objective_recovered"] is False
        and comparison["reopened"] is True
        and cleanup.get("composition_grant_revoked") is True
        and "finite_composed_attempt_settled_with_authenticated_policy_refusal_and_objective_false"
        in checks
        and "composed_attempt_grant_revoked_after_verified_cleanup" in checks
        and "saved_composed_comparison_reopened_with_false_capability_objective_and_recorded_graph_result"
        in checks
        and type(counts.get("composition_list")) is int
        and 1 <= counts["composition_list"] <= 5
        and all(
            type(counts.get(name)) is int and counts[name] == 1
            for name in (
                "composition_context",
                "composition_grant",
                "composition_proposal_context",
                "composition_attempt",
                "composition_revoke",
                "comparison",
            )
        )
    )


def _receiver_driver_passed(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    if _contains_receiver_session_token_field(value):
        return False
    cleanup = value.get("cleanup")
    baseline = value.get("baseline")
    counts = value.get("request_counts")
    copy = value.get("saved_scenario_copy")
    original_control = value.get("original_control")
    linked = value.get("linked_retest")
    evidence = value.get("phase_evidence")
    linked_phases = linked.get("phases") if isinstance(linked, dict) else None
    terminal = baseline.get("receiver_terminal") if isinstance(baseline, dict) else None
    generated_count = value.get("generated_record_count")
    record_count = terminal.get("record_count") if isinstance(terminal, dict) else None
    redacted_count = terminal.get("redacted_record_count") if isinstance(terminal, dict) else None
    retained_count = terminal.get("retained_record_count") if isinstance(terminal, dict) else None
    return (
        value.get("schema_version") == "bluefire.installed-receiver-retained-redaction.v1"
        and value.get("status") == "passed"
        and value.get("installed_wheel_service") is True
        and value.get("native_execution_required") is True
        and value.get("workflow") == "retained_redaction_original_and_linked_retest"
        and _valid_receiver_composition(value)
        and value.get("external_credentials") is False
        and value.get("live_model_inference") is False
        and type(generated_count) is int
        and generated_count == 8
        and value.get("runner_profile") == _RECEIVER_PROFILE
        and value.get("target_scope") == ["sandbox.workspace", "network.loopback"]
        and isinstance(value.get("checks"), list)
        and isinstance(value.get("blocked_requests"), list)
        and not value["blocked_requests"]
        and isinstance(value.get("errors"), list)
        and not value["errors"]
        and isinstance(cleanup, dict)
        and cleanup.get("original_owner_completed_retained") is True
        and cleanup.get("linked_owner_completed_retained") is True
        and cleanup.get("runner_stopped") is True
        and value.get("owner_status") == "completed"
        and type(value.get("unique_receiver_session_count")) is int
        and value["unique_receiver_session_count"] == 5
        and isinstance(counts, dict)
        and type(counts.get("owner")) is int
        and counts["owner"] == 2
        and all(
            type(counts.get(name)) is int and counts[name] == 5
            for name in ("prepare", "review", "approval")
        )
        and type(counts.get("cancel")) is int
        and counts["cancel"] == 0
        and type(counts.get("save_scenario")) is int
        and counts.get("save_scenario") == 1
        and isinstance(value.get("checks"), list)
        and "packaged_starter_duplicated_and_saved_through_ui" in value["checks"]
        and "original_baseline_protected_and_legitimate_use_completed_with_retained_policy"
        in value["checks"]
        and "fresh_retest_created_through_retained_control_ui_with_original_lineage"
        in value["checks"]
        and "linked_fresh_protected_refusal_and_legitimate_use_completed_under_retained_policy"
        in value["checks"]
        and value.get("source_starter_scenario_id") == _RECEIVER_SCENARIO
        and isinstance(copy, dict)
        and set(copy) == {"scenario_id", "version", "digest"}
        and isinstance(copy.get("scenario_id"), str)
        and _RECEIVER_COPY_SCENARIO.fullmatch(copy["scenario_id"]) is not None
        and type(copy.get("version")) is int
        and copy["version"] == 1
        and isinstance(copy.get("digest"), str)
        and re.fullmatch(r"sha256:[0-9a-f]{64}", copy["digest"]) is not None
        and isinstance(baseline, dict)
        and baseline.get("status") == "completed"
        and baseline.get("execution_state") == "completed"
        and baseline.get("mode") == "execute"
        and baseline.get("scenario_id") == copy.get("scenario_id")
        and baseline.get("run_profile") == _RECEIVER_PROFILE
        and baseline.get("receiver_decision") == "accepted"
        and baseline.get("observation_state") == "verified"
        and isinstance(terminal, dict)
        and terminal.get("decision") == "accepted"
        and terminal.get("authenticated") is True
        and type(record_count) is int
        and record_count == generated_count
        and type(redacted_count) is int
        and redacted_count == 0
        and type(retained_count) is int
        and 0 < retained_count <= record_count
        and isinstance(value.get("original_owner_job_id"), str)
        and re.fullmatch(r"job-[0-9a-f]{32}", value["original_owner_job_id"]) is not None
        and value.get("receiver_job_id") == value.get("original_owner_job_id")
        and isinstance(value.get("linked_owner_job_id"), str)
        and re.fullmatch(r"job-[0-9a-f]{32}", value["linked_owner_job_id"]) is not None
        and value["original_owner_job_id"] != value["linked_owner_job_id"]
        and isinstance(original_control, dict)
        and original_control.get("status") == "retained"
        and original_control.get("receiver_state") == "stopped"
        and isinstance(original_control.get("control_digest"), str)
        and re.fullmatch(r"sha256:[0-9a-f]{64}", original_control["control_digest"]) is not None
        and original_control.get("source_baseline_run_id") == value.get("run_id")
        and isinstance(linked, dict)
        and linked.get("status") == "completed"
        and linked.get("source_control_job_id") == value.get("original_owner_job_id")
        and linked.get("source_control_digest") == original_control.get("control_digest")
        and linked.get("source_baseline_run_id") == value.get("run_id")
        and linked.get("retained_control_status") == "retained"
        and linked.get("receiver_state") == "stopped"
        and isinstance(linked_phases, list)
        and len(linked_phases) == 2
        and [
            (
                (row.get("phase"), row.get("status"), row.get("decision"))
                if isinstance(row, dict)
                else None
            )
            for row in linked_phases
        ]
        == [("protected", "completed", "policy_refused"), ("legitimate", "completed", "accepted")]
        and isinstance(evidence, list)
        and len(evidence) == 5
        and [row.get("phase") for row in evidence if isinstance(row, dict)]
        == ["baseline", "protected", "legitimate", "protected", "legitimate"]
        and [row.get("owner_role") for row in evidence if isinstance(row, dict)]
        == ["original", "original", "original", "linked", "linked"]
        and all(
            isinstance(row, dict)
            and row.get("owner_job_id")
            == (
                value["original_owner_job_id"]
                if row.get("owner_role") == "original"
                else value["linked_owner_job_id"]
            )
            and row.get("status") == "completed"
            and row.get("execution_state") == "completed"
            and row.get("observation_state") == "verified"
            and row.get("terminal_decision") == row.get("decision")
            and row.get("terminal_authenticated") is True
            and type(row.get("terminal_record_count")) is int
            and row["terminal_record_count"] == generated_count
            and type(row.get("terminal_redacted_record_count")) is int
            and 0 <= row["terminal_redacted_record_count"] <= generated_count
            and type(row.get("terminal_retained_record_count")) is int
            and 0 <= row["terminal_retained_record_count"] <= generated_count
            and row["terminal_redacted_record_count"] + row["terminal_retained_record_count"]
            == generated_count
            and _valid_receiver_artifact(row.get("artifact"))
            and isinstance(row.get("execution_job_id"), str)
            and re.fullmatch(r"job-[0-9a-f]{32}", row["execution_job_id"]) is not None
            and isinstance(row.get("preparation_digest"), str)
            and re.fullmatch(r"sha256:[0-9a-f]{64}", row["preparation_digest"]) is not None
            and isinstance(row.get("run_id"), str)
            and re.fullmatch(r"run-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}", row["run_id"]) is not None
            and isinstance(row.get("cleanup"), dict)
            and row["cleanup"] == {"receiver": "verified_closed", "run": "complete"}
            for row in evidence
        )
        and len({row["execution_job_id"] for row in evidence}) == 5
        and len({row["run_id"] for row in evidence}) == 5
        and evidence[0].get("decision") == "accepted"
        and evidence[0].get("terminal_redacted_record_count") == 0
        and evidence[0].get("terminal_retained_record_count") == generated_count
        and evidence[0].get("run_id") == value.get("run_id")
        and evidence[1].get("decision") == "policy_refused"
        and evidence[1].get("artifact") == evidence[0].get("artifact")
        and evidence[2].get("decision") == "accepted"
        and evidence[2].get("artifact") != evidence[0].get("artifact")
        and evidence[2].get("legitimate_use")
        == {"baseline_run_id": value.get("run_id"), "established": True}
        and evidence[2].get("terminal_redacted_record_count") == generated_count
        and evidence[2].get("terminal_retained_record_count") == 0
        and evidence[3].get("decision") == "policy_refused"
        and evidence[3].get("artifact") == evidence[0].get("artifact")
        and evidence[4].get("decision") == "accepted"
        and evidence[4].get("artifact") != evidence[0].get("artifact")
        and evidence[4].get("legitimate_use")
        == {"baseline_run_id": value.get("run_id"), "established": True}
        and evidence[4].get("terminal_redacted_record_count") == generated_count
        and evidence[4].get("terminal_retained_record_count") == 0
        and linked_phases[0].get("run_id") == evidence[3].get("run_id")
        and linked_phases[1].get("run_id") == evidence[4].get("run_id")
        and evidence[1].get("owner_job_id") == value.get("original_owner_job_id")
        and evidence[2].get("owner_job_id") == value.get("original_owner_job_id")
        and evidence[3].get("owner_job_id") == value.get("linked_owner_job_id")
        and evidence[4].get("owner_job_id") == value.get("linked_owner_job_id")
    )


def _resolve_receiver_driver(
    driver_argument: Path | None, forbidden: Path
) -> tuple[Path | None, Path | None, Path | None]:
    if driver_argument is None:
        return None, None, None
    driver = driver_argument.resolve(strict=True)
    guards = driver.with_name("receiver-guards.mjs").resolve(strict=True)
    deadline = driver.with_name("receiver-deadline.mjs").resolve(strict=True)
    if (
        not driver.is_file()
        or not guards.is_file()
        or not deadline.is_file()
        or driver.is_relative_to(forbidden)
        or guards.is_relative_to(forbidden)
        or deadline.is_relative_to(forbidden)
        or guards.parent != driver.parent
        or deadline.parent != driver.parent
    ):
        raise RuntimeError(
            "Copy the receiver driver and its adjacent guard and deadline modules outside checkout"
        )
    return driver, guards, deadline


def _stop_http_server(server, thread, label: str, cleanup_errors: list[str]) -> tuple[bool, bool]:
    """Stop a serving thread before closing its listening socket."""
    thread_started = thread is not None and thread.ident is not None
    if thread_started:
        if thread.is_alive():
            try:
                server.shutdown()
            except Exception:
                cleanup_errors.append(f"{label}_shutdown")
        else:
            cleanup_errors.append(f"{label}_thread_already_stopped")
        try:
            thread.join(timeout=10)
        except Exception:
            cleanup_errors.append(f"{label}_join")
    thread_stopped = thread is None or not thread.is_alive()
    server_closed = False
    if thread_stopped:
        try:
            server.server_close()
            server_closed = True
        except Exception:
            cleanup_errors.append(f"{label}_close")
    else:
        cleanup_errors.append(f"{label}_close_deferred_thread_alive")
    return thread_stopped, server_closed


_RUNTIME_PROCESS_CLEANUP_KEYS = (
    "browser_process_group_stopped",
    "assistant_process_group_stopped",
    "receiver_process_group_stopped",
    "fixture_thread_stopped",
    "fixture_http_server_closed",
    "service_thread_stopped",
    "http_server_closed",
    "assistant_service_thread_stopped",
    "assistant_http_server_closed",
    "service_closed",
    "receiver_service_closed",
    "receiver_http_server_closed",
    "receiver_service_thread_stopped",
)

_PRIMARY_PHASE_CLEANUP_KEYS = (
    "browser_process_group_stopped",
    "assistant_process_group_stopped",
    "fixture_thread_stopped",
    "fixture_http_server_closed",
    "service_thread_stopped",
    "http_server_closed",
    "assistant_service_thread_stopped",
    "assistant_http_server_closed",
    "service_closed",
)


def _phase_timeout(deadline: float, maximum: float, *, now: float | None = None) -> float | None:
    remaining = deadline - (time.monotonic() if now is None else now)
    return min(maximum, remaining) if remaining > 0 else None


def _receiver_phase_block_reason(
    report: dict[str, object], *, runtime_admitted: bool, work_remaining: float | None
) -> str | None:
    if not runtime_admitted:
        return "installed_runtime_not_admitted"
    if report.get("browser_phase_status") != "passed":
        return "primary_browser_phase_not_passed"
    if any(report.get(key) is not True for key in _PRIMARY_PHASE_CLEANUP_KEYS):
        return "primary_phase_cleanup_unconfirmed"
    if work_remaining is None or work_remaining <= 0:
        return "outer_work_deadline_reached"
    return None


def _required_phases_passed(report: dict[str, object]) -> bool:
    if report.get("browser_phase_status") != "passed":
        return False
    for key in ("assistant_fixture_phase_status", "receiver_phase_status"):
        status = report.get(key)
        if status not in {"passed", "not_requested"}:
            return False
    return True


def _runtime_process_cleanup_confirmed(report: dict[str, object]) -> bool:
    receiver_started = report.get("receiver_driver_started") is True
    if report.get("receiver_phase_status") == "passed" and not receiver_started:
        return False
    return all(report.get(key) is True for key in _RUNTIME_PROCESS_CLEANUP_KEYS) and (
        not receiver_started or report.get("receiver_driver_cleanup_confirmed") is True
    )


def _runtime_cleanup_confirmed(report: dict[str, object]) -> bool:
    return (
        _runtime_process_cleanup_confirmed(report) and report.get("temporary_state_removed") is True
    )


def _receiver_retained_redaction_accepted(report: dict[str, object]) -> bool:
    return (
        report.get("browser_phase_status") == "passed"
        and report.get("receiver_phase_status") == "passed"
        and report.get("receiver_driver_started") is True
        and report.get("receiver_retained_redaction_driver_passed") is True
        and _runtime_cleanup_confirmed(report)
        and report.get("cleanup_errors") == []
    )


def _fixture_outputs() -> tuple[dict[str, object], ...]:
    return (
        {
            "message": "Create a separate registered proposal for native review.",
            "steps": [
                {
                    "capability_id": "graph.propose_and_validate",
                    "detector_ref": "none",
                    "reason": "Use the current registered catalog.",
                }
            ],
        },
        {
            "schema_version": "bluefire.ai-graph-draft.v1",
            "title": "Create, transform, and clean up a bounded fixture",
            "purpose": "Prepare a typed fixture, normalize it for inspection, and explicitly remove its files.",
            "start": "create_fixture",
            "steps": [
                {
                    "id": "create_fixture",
                    "behavior_id": "sandbox.fixture.create.v1",
                    "parameters": {"record_count": 4},
                },
                {
                    "id": "transform_fixture",
                    "behavior_id": "sandbox.fixture.transform.v1",
                    "parameters": {"redact_values": True},
                },
                {
                    "id": "cleanup_workspace",
                    "behavior_id": "sandbox.cleanup.v1",
                    "parameters": {"verify_removal": True},
                },
            ],
            "edges": [
                {
                    "from_step": "create_fixture",
                    "outcome": "success",
                    "to_step": "transform_fixture",
                },
                {
                    "from_step": "transform_fixture",
                    "outcome": "success",
                    "to_step": "cleanup_workspace",
                },
            ],
            "rationale": "All three nodes are registered, typed artifacts connect, and cleanup is explicit.",
            "assumptions": ["The operator will review this unsaved draft."],
        },
        {
            "message": "Create a reviewed initial rule from this exact observed run.",
            "steps": [
                {
                    "capability_id": "detection.create_and_evaluate",
                    "detector_ref": "none",
                    "reason": "Use only the selected run's observed evidence and retain its development-case limits.",
                }
            ],
        },
        {
            "title": "Generated fixture collection rule",
            "source": "SELECT fixture_id FROM logs WHERE artifact_type = 'collector_observation'",
            "reason": "Exercise the reviewed source workflow against the supplied normalized observation schema.",
            "evidence_refs": [],
            "limitations": [
                "Generated fixture observations only; normalized metadata, not target telemetry.",
                "Development-case evaluation only; this does not establish held-out detection quality.",
            ],
        },
    )


def _fixture_output_for_request(index: int, request: object) -> dict[str, object]:
    outputs = _fixture_outputs()
    if not 0 <= index < len(outputs) or not isinstance(request, dict):
        raise ValueError("fixture request index is unavailable")
    output = dict(outputs[index])
    if index == 3:
        try:
            context = json.loads(request["input"])
            observations = context["observations"]
            evidence_id = observations[0]["evidence_id"]
        except (KeyError, IndexError, TypeError, json.JSONDecodeError) as exc:
            raise ValueError(
                "detection fixture requires a supplied observed evidence reference"
            ) from exc
        if not isinstance(evidence_id, str) or not re.fullmatch(
            r"evidence-[0-9a-f]{20}", evidence_id
        ):
            raise ValueError("detection fixture evidence reference is invalid")
        output["evidence_refs"] = [evidence_id]
    return output


def _assistant_fixture_journey_passed(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    execute = value.get("generated_fixture_execute")
    preflight = value.get("execute_preflight")
    graph = value.get("graph_simulation")
    detection = value.get("detection_application")
    cleanup = value.get("cleanup")
    counts = value.get("request_counts")
    observed_ids = execute.get("observed_evidence_ids") if isinstance(execute, dict) else None
    observed_records = execute.get("observed_records") if isinstance(execute, dict) else None
    provider_requests = value.get("provider_requests")
    purpose_proof = value.get("model_purpose_authorizations")
    route_counts = value.get("route_counts")
    deadline_controls = value.get("deadline_controls")
    checks = value.get("checks")
    return (
        value.get("schema_version") == "bluefire.installed-assistant-fixture.v2"
        and value.get("status") == "passed"
        and value.get("evidence_scope")
        == "Generated fixture observations are normalized metadata, not target telemetry or held-out detection evidence."
        and value.get("blocked_requests") == []
        and isinstance(deadline_controls, dict)
        and type(deadline_controls.get("outer_budget_remaining_at_browser_launch_ms")) is int
        and 0 < deadline_controls["outer_budget_remaining_at_browser_launch_ms"] <= 240_000
        and deadline_controls.get("work_deadline_enforced") is True
        and deadline_controls.get("cleanup_reserve_ms") == 55_000
        and deadline_controls.get("outer_margin_ms") == 2_000
        and isinstance(value.get("errors"), list)
        and not value["errors"]
        and isinstance(checks, list)
        and "approved_fixture_execute_run_completed_with_explicit_cleanup_and_observed_generated_fixture_metadata"
        in checks
        and "reviewed_fixture_detection_saved_and_evaluated_against_its_development_run" in checks
        and "saved_detection_candidate_and_development_evaluation_reopened_by_exact_ids" in checks
        and all(
            f"composition_purpose_{purpose}_separate_from_receiver_in_settings" in checks
            and f"composition_purpose_{purpose}_persisted_and_revoked_without_request" in checks
            for purpose in _COMPOSITION_PURPOSES
        )
        and purpose_proof
        == {
            "original_authorization": "revoked",
            "selected_purposes": [
                {"purpose": purpose, "status": "revoked", "model_requests": 0}
                for purpose in _COMPOSITION_PURPOSES
            ],
            "receiver_purpose_selected": False,
            "model_requests_before": 4,
            "model_requests_after": 4,
        }
        and purpose_proof["receiver_purpose_selected"] is False
        and type(purpose_proof["model_requests_before"]) is int
        and type(purpose_proof["model_requests_after"]) is int
        and all(type(row["model_requests"]) is int for row in purpose_proof["selected_purposes"])
        and isinstance(route_counts, dict)
        and all(
            type(route_counts.get(name)) is int and route_counts[name] == expected
            for name, expected in (
                ("authorization", 1),
                ("composition_purpose_authorization", 2),
                ("authorization_revoke", 3),
            )
        )
        and isinstance(graph, dict)
        and graph.get("native_execution") is False
        and isinstance(execute, dict)
        and execute.get("status") == "completed"
        and execute.get("native_execution") is True
        and execute.get("mode") == "execute"
        and execute.get("autonomy") == "off"
        and execute.get("runner_profile_id") == "sandbox-execute.v1"
        and isinstance(execute.get("run_id"), str)
        and re.fullmatch(r"run-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}", execute["run_id"]) is not None
        and isinstance(execute.get("job_id"), str)
        and re.fullmatch(r"job-[0-9a-f]{32}", execute["job_id"]) is not None
        and type(execute.get("step_count")) is int
        and execute["step_count"] == 3
        and type(execute.get("observed_metadata_record_count")) is int
        and 1 <= execute["observed_metadata_record_count"] <= 2
        and isinstance(observed_ids, list)
        and len(observed_ids) == execute["observed_metadata_record_count"]
        and all(
            isinstance(item, str) and re.fullmatch(r"evidence-[0-9a-f]{20}", item)
            for item in observed_ids
        )
        and len(set(observed_ids)) == len(observed_ids)
        and isinstance(observed_records, list)
        and len(observed_records) == len(observed_ids)
        and all(
            isinstance(item, dict) and isinstance(item.get("evidence_id"), str)
            for item in observed_records
        )
        and {item["evidence_id"] for item in observed_records} == set(observed_ids)
        and all(
            isinstance(item, dict)
            and item.get("run_id") == execute.get("run_id")
            and item.get("producer") == "collector.filesystem.sandbox.v1"
            and item.get("step_id") in {"create_fixture", "transform_fixture"}
            and item.get("behavior_id")
            == {
                "create_fixture": "sandbox.fixture.create.v1",
                "transform_fixture": "sandbox.fixture.transform.v1",
            }.get(item.get("step_id"))
            and item.get("action_id") == item.get("behavior_id")
            for item in observed_records
        )
        and isinstance(preflight, dict)
        and preflight.get("mode") == "execute"
        and preflight.get("autonomy") == "off"
        and preflight.get("ai_enabled") is False
        and preflight.get("ai_provider_id") == "deterministic-offline.v1"
        and preflight.get("actions")
        == [
            "sandbox.fixture.create.v1",
            "sandbox.fixture.transform.v1",
            "sandbox.cleanup.v1",
        ]
        and isinstance(execute.get("cleanup"), dict)
        and execute["cleanup"].get("attempted") is True
        and execute["cleanup"].get("success") is True
        and isinstance(detection, dict)
        and isinstance(detection.get("candidate_id"), str)
        and re.fullmatch(r"detection-[0-9a-f]{20}", detection["candidate_id"]) is not None
        and isinstance(detection.get("evaluation_id"), str)
        and re.fullmatch(r"detection-evaluation-[0-9a-f]{64}", detection["evaluation_id"])
        is not None
        and detection.get("run_id") == execute.get("run_id")
        and detection.get("development_case") is True
        and detection.get("backend_executed") is True
        and isinstance(detection.get("result_state"), str)
        and bool(detection["result_state"])
        and type(detection.get("observed_match_count")) is int
        and detection["observed_match_count"] >= 0
        and isinstance(value.get("detection_reopened"), dict)
        and value["detection_reopened"].get("candidate_id") == detection.get("candidate_id")
        and value["detection_reopened"].get("evaluation_id") == detection.get("evaluation_id")
        and value["detection_reopened"].get("run_id") == execute.get("run_id")
        and type(value["detection_reopened"].get("revision")) is int
        and value["detection_reopened"]["revision"] > 0
        and isinstance(value["detection_reopened"].get("definition_digest"), str)
        and re.fullmatch(r"sha256:[0-9a-f]{64}", value["detection_reopened"]["definition_digest"])
        is not None
        and value["detection_reopened"].get("development_case") is True
        and value["detection_reopened"].get("evaluation_use") == "development"
        and isinstance(provider_requests, dict)
        and provider_requests.get("count") == 4
        and provider_requests.get("purposes") == list(_FIXTURE_PURPOSES)
        and type(provider_requests.get("request_bytes")) is int
        and 0 < provider_requests["request_bytes"] <= 2_097_152
        and isinstance(cleanup, dict)
        and cleanup.get("runner_stopped") is True
        and cleanup.get("execute_job_terminal") is True
        and cleanup.get("model_authorizations_revoked") is True
        and isinstance(counts, dict)
        and counts
        == {
            "assistant_turns": 2,
            "model_requests": 4,
            "run_preflight": 1,
            "run_submission": 1,
            "execute_approval": 1,
            "runner_bootstrap": 1,
            "runner_start": 1,
            "runner_stop": 1,
            "detection_source": 1,
            "detection_context": 1,
            "detection_validate": 1,
            "detection_review": 1,
        }
    )


def _fixture_request_allowed(
    request: object,
    *,
    purpose: object,
    model: object,
    body_bytes: int,
    authorization: str | None,
    request_index: int,
    accumulated_bytes: int,
) -> bool:
    if not isinstance(request, dict):
        return False
    text = request.get("text")
    format_document = text.get("format") if isinstance(text, dict) else None
    return (
        set(request)
        == {
            "model",
            "instructions",
            "input",
            "max_output_tokens",
            "store",
            "parallel_tool_calls",
            "tools",
            "tool_choice",
            "text",
        }
        and isinstance(text, dict)
        and set(text) == {"format"}
        and isinstance(format_document, dict)
        and set(format_document) == {"type", "name", "schema", "strict"}
        and format_document.get("type") == "json_schema"
        and format_document.get("strict") is True
        and isinstance(format_document.get("schema"), dict)
        and isinstance(request.get("instructions"), str)
        and isinstance(request.get("input"), str)
        and request.get("max_output_tokens") == 64
        and request.get("store") is False
        and request.get("parallel_tool_calls") is False
        and request.get("tools") == []
        and request.get("tool_choice") == "none"
        and authorization is None
        and request_index < len(_FIXTURE_PURPOSES)
        and purpose == _FIXTURE_PURPOSES[request_index]
        and format_document.get("name") == purpose
        and model == _FIXTURE_MODEL
        and body_bytes > 0
        and body_bytes <= 1_048_576
        and accumulated_bytes + body_bytes <= 2_097_152
    )


class LocalGraphFixture:
    """Strict four-request structured-output endpoint; stores no prompt or response text."""

    def __init__(self) -> None:
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def setup(self) -> None:
                super().setup()
                self.connection.settimeout(10)

            def _send(self, status: int, payload: object) -> None:
                data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(data)
                self.close_connection = True

            def do_GET(self) -> None:
                if self.path != "/__fixture/state":
                    self._send(404, {"error": "not_found"})
                    return
                with fixture.lock:
                    fixture.state_reads += 1
                    if fixture.state_reads > 250:
                        fixture.failed = True
                        self._send(429, {"error": "state_read_limit"})
                        return
                    state = {
                        "request_count": len(fixture.purposes),
                        "purposes": list(fixture.purposes),
                        "request_bytes": fixture.request_bytes,
                        "released": fixture.release.is_set(),
                        "failed": fixture.failed,
                    }
                self._send(200, state)

            def do_POST(self) -> None:
                raw_length = self.headers.get("Content-Length", "0")
                if (
                    not raw_length.isascii()
                    or not raw_length.isdecimal()
                    or len(raw_length) > 7
                    or (len(raw_length) > 1 and raw_length.startswith("0"))
                ):
                    fixture._fail()
                    self._send(400, {"error": "invalid_length"})
                    return
                length = int(raw_length)
                with fixture.lock:
                    if fixture.post_count >= 5 or fixture.post_bytes + length > 2_097_152:
                        fixture.failed = True
                        self._send(429, {"error": "fixture_budget_exceeded"})
                        return
                    fixture.post_count += 1
                    fixture.post_bytes += length
                if self.path == "/__fixture/release":
                    if length != 0:
                        fixture._fail()
                        self._send(400, {"error": "release_body_not_allowed"})
                        return
                    with fixture.lock:
                        if fixture.release_called:
                            fixture.failed = True
                            self._send(409, {"error": "release_already_used"})
                            return
                        fixture.release_called = True
                    fixture.release.set()
                    self._send(200, {"released": True})
                    return
                if self.path != "/v1/responses":
                    self._send(404, {"error": "not_found"})
                    return
                if length == 0:
                    fixture._fail()
                    self._send(400, {"error": "invalid_length"})
                    return
                if length > 1_048_576:
                    fixture._fail()
                    self._send(413, {"error": "request_too_large"})
                    return
                try:
                    request = json.loads(self.rfile.read(length))
                    purpose = request["text"]["format"]["name"]
                    model = request["model"]
                except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError):
                    fixture._fail()
                    self._send(400, {"error": "invalid_request"})
                    return
                with fixture.lock:
                    index = len(fixture.purposes)
                    if not _fixture_request_allowed(
                        request,
                        purpose=purpose,
                        model=model,
                        body_bytes=length,
                        authorization=self.headers.get("Authorization"),
                        request_index=index,
                        accumulated_bytes=fixture.request_bytes,
                    ):
                        fixture.failed = True
                        self._send(400, {"error": "request_out_of_scope"})
                        return
                    fixture.purposes.append(purpose)
                    fixture.request_bytes += length
                if purpose == "bluefire_ai_graph_draft" and not fixture.release.wait(30):
                    fixture._fail()
                    self._send(504, {"error": "fixture_deadline"})
                    return
                try:
                    output = _fixture_output_for_request(index, request)
                except ValueError:
                    fixture._fail()
                    self._send(400, {"error": "fixture_output_binding_failed"})
                    return
                self._send(
                    200,
                    {
                        "id": f"fixture-response-{index + 1}",
                        "model": _FIXTURE_MODEL,
                        "status": "completed",
                        "output_text": json.dumps(output, separators=(",", ":")),
                        "usage": {"input_tokens": 16, "output_tokens": 24},
                    },
                )

            def log_message(self, _format: str, *_args: object) -> None:
                return

        class Server(ThreadingHTTPServer):
            daemon_threads = False
            block_on_close = True

            def handle_error(self, _request: object, _client_address: object) -> None:
                return

        self.lock = threading.Lock()
        self.release = threading.Event()
        self.purposes: list[str] = []
        self.request_bytes = 0
        self.post_count = 0
        self.post_bytes = 0
        self.state_reads = 0
        self.release_called = False
        self.failed = False
        self.server = Server(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=False)

    @property
    def port(self) -> int:
        return int(self.server.server_address[1])

    def _fail(self) -> None:
        with self.lock:
            self.failed = True

    def start(self) -> None:
        self.thread.start()

    def close(self) -> tuple[bool, bool, list[str]]:
        self.release.set()
        cleanup_errors: list[str] = []
        thread_stopped, server_closed = _stop_http_server(
            self.server, self.thread, "fixture_http", cleanup_errors
        )
        return thread_stopped, server_closed, cleanup_errors


def _close_fixture_for_report(
    fixture: LocalGraphFixture,
    report: dict[str, object],
    cleanup_errors: list[str],
) -> None:
    try:
        thread_stopped, server_closed, fixture_errors = fixture.close()
    except (OSError, RuntimeError):
        report["fixture_thread_stopped"] = False
        report["fixture_http_server_closed"] = False
        report["status"] = "failed_or_incomplete"
        cleanup_errors.append("assistant_fixture")
        return
    report["fixture_thread_stopped"] = thread_stopped
    report["fixture_http_server_closed"] = server_closed
    cleanup_errors.extend(fixture_errors)
    if fixture.failed or fixture_errors or not thread_stopped or not server_closed:
        report["status"] = "failed_or_incomplete"


def stop_group(process: subprocess.Popen[bytes]) -> bool:
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            process.wait(timeout=10)
            return True
        time.sleep(0.2)
    process.wait(timeout=10)
    try:
        os.killpg(process.pid, 0)
    except ProcessLookupError:
        return True
    return False


def _run_receiver_phase(
    *,
    report: dict[str, object],
    driver: Path,
    guards: Path,
    deadline_file: Path,
    node: Path,
    playwright: Path,
    output: Path,
    runtime: Path,
    environment: dict[str, str],
    work_deadline: float,
    service_type,
    runner_lifecycle_type,
    create_server,
    generate_capability,
    cleanup_errors: list[str],
) -> None:
    """Run the independent receiver driver with phase-owned state and limits."""
    timeout = _phase_timeout(work_deadline, 360)
    if timeout is None:
        report["receiver_phase_status"] = "not_attempted"
        report["receiver_phase_reason"] = "outer_work_deadline_reached"
        return

    receiver_root = runtime / "receiver"
    receiver_service = None
    receiver_capability = ""
    receiver_server = None
    receiver_thread = None
    receiver_child = None
    receiver_driver_report: dict[str, object] | None = None
    prior_environment = dict(os.environ)
    prior_cwd = Path.cwd()
    report["receiver_phase_status"] = "running"
    report["receiver_process_group_stopped"] = True
    report["receiver_http_server_closed"] = True
    report["receiver_service_thread_stopped"] = True
    report["receiver_service_closed"] = True
    report["receiver_driver_cleanup_confirmed"] = False
    try:
        receiver_root.mkdir(mode=0o700, exist_ok=False)
        for name in ("home", "state", "temp", "work"):
            (receiver_root / name).mkdir(mode=0o700, exist_ok=False)
        receiver_environment = dict(environment)
        receiver_environment.update(
            {
                "HOME": str(receiver_root / "home"),
                "XDG_STATE_HOME": str(receiver_root / "state"),
                "XDG_CONFIG_HOME": str(receiver_root / "state"),
                "XDG_CACHE_HOME": str(receiver_root / "temp"),
                "TMPDIR": str(receiver_root / "temp"),
            }
        )
        os.environ.clear()
        os.environ.update(receiver_environment)
        os.chdir(receiver_root / "work")
        from bluefire.runner_bootstrap import managed_product_root

        receiver_service = service_type(
            runs_dir=receiver_root / "runs",
            runner_lifecycle=runner_lifecycle_type(managed_product_root()),
        )
        report["receiver_service_closed"] = False
        receiver_capability = generate_capability()
        receiver_server = create_server(
            receiver_service,
            host="127.0.0.1",
            port=0,
            browser_bootstrap_capability=receiver_capability,
        )
        receiver_thread = threading.Thread(target=receiver_server.serve_forever, daemon=False)
        receiver_thread.start()
        report["receiver_service_thread_stopped"] = False
        report["receiver_http_server_closed"] = False
        timeout = _phase_timeout(work_deadline, 360)
        if timeout is None:
            report["receiver_phase_status"] = "not_attempted"
            report["receiver_phase_reason"] = "outer_work_deadline_reached"
            return
        receiver_child = subprocess.Popen(
            [
                str(node),
                str(driver),
                str(playwright),
                str(output),
                str(receiver_server.server_address[1]),
            ],
            env=receiver_environment,
            cwd=receiver_root / "work",
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        report["receiver_driver_started"] = True
        report["receiver_process_group_stopped"] = False
        timeout = _phase_timeout(work_deadline, 360)
        receiver_child.communicate(
            json.dumps({"capability": receiver_capability}).encode(),
            timeout=timeout if timeout is not None else 0,
        )
        receiver_capability = ""
        receiver_report_path = output / "installed-receiver-report.json"
        receiver_driver_report = json.loads(receiver_report_path.read_text(encoding="utf-8"))
        receiver_receipt = _receiver_report_for_receipt(receiver_driver_report)
        driver_cleanup = receiver_driver_report["cleanup"]
        report["receiver_driver_cleanup_confirmed"] = (
            driver_cleanup.get("original_owner_completed_retained") is True
            and driver_cleanup.get("linked_owner_completed_retained") is True
            and driver_cleanup.get("runner_stopped") is True
            and receiver_driver_report.get("owner_status") == "completed"
        )
        report["receiver_retained_redaction"] = {
            **receiver_receipt,
            "driver_sha256": digest(driver),
            "guard_sha256": digest(guards),
            "deadline_sha256": digest(deadline_file),
            "browser_returncode": receiver_child.returncode,
        }
        report["receiver_retained_redaction_driver_passed"] = (
            receiver_child.returncode == 0 and _receiver_driver_passed(receiver_driver_report)
        )
        report["receiver_phase_status"] = (
            "passed" if report["receiver_retained_redaction_driver_passed"] else "failed"
        )
        if report["receiver_phase_status"] == "failed":
            report["status"] = "failed_or_incomplete"
    except Exception as error:
        report["receiver_phase_status"] = "failed"
        report["receiver_error_type"] = type(error).__name__
        report["receiver_driver_cleanup_confirmed"] = bool(
            receiver_driver_report and _receiver_driver_passed(receiver_driver_report)
        )
        report["status"] = "failed_or_incomplete"
    finally:
        receiver_capability = ""
        if receiver_child is not None:
            try:
                report["receiver_process_group_stopped"] = stop_group(receiver_child)
            except (OSError, subprocess.TimeoutExpired):
                report["receiver_process_group_stopped"] = False
                cleanup_errors.append("receiver_browser_process_group")
        if receiver_server is not None:
            (
                report["receiver_service_thread_stopped"],
                report["receiver_http_server_closed"],
            ) = _stop_http_server(receiver_server, receiver_thread, "receiver_http", cleanup_errors)
        if (
            receiver_service is not None
            and report["receiver_service_thread_stopped"]
            and report["receiver_http_server_closed"]
        ):
            try:
                receiver_service.close()
                report["receiver_service_closed"] = True
            except Exception:
                report["receiver_service_closed"] = False
                cleanup_errors.append("receiver_service_close")
        elif receiver_service is not None:
            cleanup_errors.append("receiver_service_close_deferred")
        try:
            os.chdir(prior_cwd)
        except OSError:
            cleanup_errors.append("receiver_working_directory_restore")
        try:
            os.environ.clear()
            os.environ.update(prior_environment)
        except Exception:
            cleanup_errors.append("receiver_environment_restore")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--forbid-root", required=True, type=Path)
    parser.add_argument("--node", required=True, type=Path)
    parser.add_argument("--playwright", required=True, type=Path)
    parser.add_argument("--browser-driver", required=True, type=Path)
    parser.add_argument("--assistant-driver", type=Path)
    parser.add_argument("--receiver-driver", type=Path)
    parser.add_argument("--browser-cache", required=True, type=Path)
    parser.add_argument("--wheel", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    outer_deadline = time.monotonic() + _OVERALL_WORK_BUDGET_SECONDS
    work_deadline = outer_deadline - _OVERALL_CLEANUP_RESERVE_SECONDS
    if sys.platform != "linux" or not sys.flags.isolated:
        raise RuntimeError("Use isolated installed Linux Python for this verifier")
    forbidden = args.forbid_root.resolve(strict=True)
    output = args.output.resolve()
    driver = args.browser_driver.resolve(strict=True)
    assistant_driver = args.assistant_driver.resolve(strict=True) if args.assistant_driver else None
    receiver_driver, receiver_guards, receiver_deadline = _resolve_receiver_driver(
        args.receiver_driver, forbidden
    )
    wheel = args.wheel.resolve(strict=True)
    node = args.node.resolve(strict=True)
    playwright = args.playwright.resolve(strict=True)
    cache = args.browser_cache.resolve(strict=True)
    if output.is_relative_to(forbidden) or output.exists():
        raise RuntimeError("A fresh output folder outside checkout is required")
    if (
        not driver.is_file()
        or (assistant_driver is not None and not assistant_driver.is_file())
        or driver.is_relative_to(forbidden)
        or (assistant_driver is not None and assistant_driver.is_relative_to(forbidden))
        or Path.cwd().is_relative_to(forbidden)
    ):
        raise RuntimeError("Copy the browser driver outside checkout before verification")
    output.mkdir(mode=0o700)
    runtime = output / "runtime"
    runtime.mkdir(mode=0o700)
    for name in ("home", "state", "temp", "work"):
        (runtime / name).mkdir(mode=0o700)
    hosted_image = {
        name: os.environ.get(name)
        for name in ("ImageOS", "ImageVersion", "RUNNER_OS", "RUNNER_ARCH")
    }
    environment = {
        "PATH": os.pathsep.join((str(node.parent), "/usr/bin", "/bin")),
        "HOME": str(runtime / "home"),
        "XDG_STATE_HOME": str(runtime / "state"),
        "XDG_CONFIG_HOME": str(runtime / "state"),
        "XDG_CACHE_HOME": str(runtime / "temp"),
        "TMPDIR": str(runtime / "temp"),
        "LANG": "C.UTF-8",
        "PLAYWRIGHT_BROWSERS_PATH": str(cache),
        "PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD": "1",
    }
    os.environ.clear()
    os.environ.update(environment)
    os.chdir(runtime / "work")

    import bluefire
    from bluefire.api import create_server, generate_browser_bootstrap_capability
    from bluefire.runner_lifecycle import ManagedRunnerLifecycle
    from bluefire.service import BlueFireService

    package = Path(bluefire.__file__).resolve(strict=True).parent
    site = Path(sysconfig.get_path("purelib")).resolve(strict=True)
    distribution = importlib.metadata.distribution("bluefire-nexus")
    if (
        not package.is_relative_to(site)
        or package.is_relative_to(forbidden)
        or Path(sys.prefix).resolve() == Path(sys.base_prefix).resolve()
        or any(Path(entry or ".").resolve().is_relative_to(forbidden) for entry in sys.path)
        or '"editable": true' in (distribution.read_text("direct_url.json") or "").lower()
    ):
        raise RuntimeError("The package must be wheel-installed outside checkout")
    build_info = json.loads((package / "_build_info.json").read_text(encoding="utf-8"))
    write_new(
        output / "identity.json",
        {
            "schema_version": "bluefire.installed-browser-identity.v1",
            "os_release": platform.freedesktop_os_release(),
            "kernel": platform.release(),
            "architecture": platform.machine(),
            "hosted_image": hosted_image,
            "python_version": platform.python_version(),
            "product_version": distribution.version,
            "source_revision": build_info["source_revision"],
            "source_provenance": build_info["source_provenance"],
            "wheel_filename": wheel.name,
            "wheel_sha256": digest(wheel),
            "ui_sha256": {
                name: digest(package / "ui" / name)
                for name in (
                    "index.html",
                    "app.js",
                    "styles.css",
                    "fonts/InterVariable.woff2",
                )
            },
            "installed_outside_checkout": True,
            "harness_sha256": digest(Path(__file__)),
            "browser_driver_sha256": digest(driver),
            "assistant_driver_sha256": digest(assistant_driver) if assistant_driver else None,
            "receiver_driver_sha256": digest(receiver_driver) if receiver_driver else None,
            "receiver_guard_sha256": digest(receiver_guards) if receiver_guards else None,
            "environment_names": sorted(environment),
            "not_proven": [
                "CLI launch",
                "native execution beyond the owned generated-fixture and optional retained-redaction receiver journeys",
                "effective-access validation",
                "live model inference",
                "Assistant recovery across process restart",
                "AD, AWS, or external endpoint access",
                "other operating systems or Linux security configurations",
            ],
        },
    )
    service = BlueFireService(runs_dir=runtime / "runs")
    capability = generate_browser_bootstrap_capability()
    server = create_server(
        service, host="127.0.0.1", port=0, browser_bootstrap_capability=capability
    )
    thread = threading.Thread(target=server.serve_forever, daemon=False)
    child = None
    assistant_child = None
    assistant_capability = ""
    assistant_server = None
    assistant_thread = None
    fixture = None
    report: dict[str, object] = {
        "schema_version": "bluefire.installed-browser-verification.v1",
        "status": "failed_or_incomplete",
        "browser_phase_status": "not_attempted",
        "assistant_fixture_phase_status": "not_attempted" if assistant_driver else "not_requested",
        "receiver_phase_status": "not_attempted" if receiver_driver else "not_requested",
        "real_installed_service": True,
        "simulation_assistant_native_execution": False,
        "receiver_native_retained_redaction": False,
        "receiver_driver_cleanup_confirmed": receiver_driver is None,
        "receiver_driver_started": False,
        "live_model_inference": False,
        "assistant_process_group_stopped": True,
        "fixture_thread_stopped": True,
        "fixture_http_server_closed": True,
        "http_server_closed": False,
        "assistant_http_server_closed": True,
        "assistant_service_thread_stopped": True,
        "service_closed": False,
        "receiver_http_server_closed": True,
        "receiver_service_closed": True,
        "receiver_service_thread_stopped": True,
    }
    runtime_admitted = False
    thread.start()
    runtime_admitted = True
    try:
        browser_timeout = _phase_timeout(work_deadline, 240)
        if browser_timeout is None:
            raise _WorkDeadlineReached("browser")
        report["browser_phase_status"] = "running"
        child = subprocess.Popen(
            [str(node), str(driver), str(playwright), str(output), str(server.server_address[1])],
            env=environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        browser_timeout = _phase_timeout(work_deadline, 240)
        child.communicate(
            json.dumps({"capability": capability}).encode(),
            timeout=browser_timeout if browser_timeout is not None else 0,
        )
        capability = ""
        report["browser_returncode"] = child.returncode
        report["browser_phase_status"] = "running" if child.returncode == 0 else "failed"
        if assistant_driver is not None and child.returncode != 0:
            report["assistant_fixture_phase_reason"] = "browser_phase_not_passed"
        browser_report_path = output / "browser-report.json"
        if child.returncode == 0:
            browser_report = json.loads(browser_report_path.read_text(encoding="utf-8"))
            font = browser_report.get("font_asset")
            network_font = font.get("network_response") if isinstance(font, dict) else None
            font_state = font.get("document_font_state") if isinstance(font, dict) else None
            comparison_assistant = browser_report.get("comparison_assistant")
            screenshot_names = {
                item.get("name")
                for item in browser_report.get("screenshots", [])
                if isinstance(item, dict)
            }
            packaged_font_sha256 = digest(package / "ui" / "fonts" / "InterVariable.woff2")
            if (
                browser_report.get("status") != "passed"
                or not isinstance(network_font, dict)
                or network_font.get("status") != 200
                or type(network_font.get("bytes")) is not int
                or network_font["bytes"] <= 0
                or network_font.get("sha256") != packaged_font_sha256
                or not isinstance(font_state, dict)
                or not any(
                    isinstance(face, dict)
                    and face.get("family") == "Inter"
                    and face.get("status") == "loaded"
                    for face in font_state.get("faces", [])
                )
                or font_state.get("check") is not True
                or not isinstance(font_state.get("conclusion_family"), str)
                or "Inter" not in font_state["conclusion_family"]
                or not isinstance(comparison_assistant, dict)
                or comparison_assistant.get("status") != "passed"
                or comparison_assistant.get("snapshot_id")
                != browser_report.get("comparison_snapshot_id")
                or re.fullmatch(
                    r"sha256:[0-9a-f]{64}", comparison_assistant.get("snapshot_digest", "")
                )
                is None
                or re.fullmatch(
                    r"sha256:[0-9a-f]{64}", comparison_assistant.get("context_digest", "")
                )
                is None
                or comparison_assistant.get("saved_run_count") != 2
                or comparison_assistant.get("selected_exactly") is not True
                or comparison_assistant.get("analysis_only_context") is not True
                or comparison_assistant.get("active_mode") != "Off"
                or comparison_assistant.get("explanation_mode_available") is not True
                or comparison_assistant.get("assistant_turn_posts") != 0
                or comparison_assistant.get("read_only_post_attempts") != 0
                or comparison_assistant.get("reopened_same_snapshot") is not True
                or not {"comparison-assistant-1440x900", "comparison-assistant-1366x768"}.issubset(
                    screenshot_names
                )
            ):
                raise ValueError(
                    "Installed browser journey did not verify saved-comparison Assistant and packaged Inter evidence"
                )
            report["comparison_assistant"] = comparison_assistant
            report["font_asset"] = {
                "path": "ui/fonts/InterVariable.woff2",
                "packaged_sha256": packaged_font_sha256,
                "network_sha256": network_font["sha256"],
                "network_bytes": network_font["bytes"],
                "matches_installed_wheel": True,
                "document_font_state": font_state,
            }
        if child.returncode == 0:
            report["browser_phase_status"] = "passed"
            report["status"] = "passed"
        if assistant_driver is not None and child.returncode == 0:
            assistant_timeout = _phase_timeout(work_deadline, 240)
            if assistant_timeout is None:
                raise _WorkDeadlineReached("assistant_fixture")
            report["assistant_fixture_phase_status"] = "running"
            assistant_outer_budget_ms = min(
                238_000, max(0, int((work_deadline - time.monotonic()) * 1000))
            )
            if assistant_outer_budget_ms <= 0:
                raise _WorkDeadlineReached("assistant_fixture")
            assistant_outer_deadline_ms = time.time_ns() // 1_000_000 + assistant_outer_budget_ms
            fixture = LocalGraphFixture()
            fixture.start()
            assistant_capability = generate_browser_bootstrap_capability()
            assistant_server = create_server(
                service,
                host="127.0.0.1",
                port=0,
                browser_bootstrap_capability=assistant_capability,
            )
            assistant_thread = threading.Thread(target=assistant_server.serve_forever, daemon=False)
            assistant_thread.start()
            assistant_child = subprocess.Popen(
                [
                    str(node),
                    str(assistant_driver),
                    str(playwright),
                    str(output),
                    str(assistant_server.server_address[1]),
                    str(fixture.port),
                    str(assistant_outer_deadline_ms),
                ],
                env=environment,
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            assistant_timeout = _phase_timeout(work_deadline, 240)
            assistant_child.communicate(
                json.dumps({"capability": assistant_capability}).encode(),
                timeout=assistant_timeout if assistant_timeout is not None else 0,
            )
            assistant_capability = ""
            assistant_report_path = output / "assistant-browser-report.json"
            assistant_report = json.loads(assistant_report_path.read_text(encoding="utf-8"))
            with fixture.lock:
                fixture_summary = {
                    "model": _FIXTURE_MODEL,
                    "endpoint_kind": "local_loopback_structured_fixture",
                    "request_count": len(fixture.purposes),
                    "purposes": list(fixture.purposes),
                    "request_bytes": fixture.request_bytes,
                    "failed": fixture.failed,
                }
            report["assistant_fixture"] = {
                "status": assistant_report.get("status"),
                "driver_sha256": digest(assistant_driver),
                "evidence_scope": assistant_report.get("evidence_scope"),
                "provider": fixture_summary,
                "checks": assistant_report.get("checks", []),
                "screenshots": assistant_report.get("screenshots", []),
                "blocked_requests": assistant_report.get("blocked_requests", []),
                "graph_simulation": assistant_report.get("graph_simulation"),
                "generated_fixture_execute": assistant_report.get("generated_fixture_execute"),
                "detection_proposal": assistant_report.get("detection_proposal"),
                "detection_application": assistant_report.get("detection_application"),
                "detection_reopened": assistant_report.get("detection_reopened"),
                "deadline_controls": assistant_report.get("deadline_controls"),
                "model_purpose_authorizations": assistant_report.get(
                    "model_purpose_authorizations"
                ),
                "route_counts": assistant_report.get("route_counts"),
                "request_counts": assistant_report.get("request_counts"),
                "cleanup": assistant_report.get("cleanup"),
            }
            report["assistant_browser_returncode"] = assistant_child.returncode
            if (
                assistant_child.returncode != 0
                or not _assistant_fixture_journey_passed(assistant_report)
                or fixture.failed
                or fixture_summary["request_count"] != 4
                or fixture_summary["purposes"] != list(_FIXTURE_PURPOSES)
            ):
                report["assistant_fixture_phase_status"] = "failed"
                report["status"] = "failed_or_incomplete"
            else:
                report["assistant_fixture_phase_status"] = "passed"
    except _WorkDeadlineReached as error:
        phase_key = {
            "browser": "browser_phase_status",
            "assistant_fixture": "assistant_fixture_phase_status",
        }[error.phase]
        report[phase_key] = "not_attempted"
        report[f"{error.phase}_phase_reason"] = "outer_work_deadline_reached"
        if error.phase == "browser" and assistant_driver is not None:
            report["assistant_fixture_phase_reason"] = "browser_phase_not_passed"
        report["status"] = "failed_or_incomplete"
    except Exception as error:
        report["error_type"] = type(error).__name__
        report["status"] = "failed_or_incomplete"
        for phase_key in ("browser_phase_status", "assistant_fixture_phase_status"):
            if report[phase_key] == "running":
                report[phase_key] = "failed"
        if (
            assistant_driver is not None
            and report["assistant_fixture_phase_status"] == "not_attempted"
        ):
            report["assistant_fixture_phase_reason"] = "browser_phase_not_passed"
    finally:
        capability = ""
        assistant_capability = ""
        cleanup_errors = []
        report["browser_process_group_stopped"] = child is None
        try:
            if child is not None:
                report["browser_process_group_stopped"] = stop_group(child)
        except (OSError, subprocess.TimeoutExpired):
            cleanup_errors.append("browser_process_group")
        report["assistant_process_group_stopped"] = assistant_child is None
        try:
            if assistant_child is not None:
                report["assistant_process_group_stopped"] = stop_group(assistant_child)
        except (OSError, subprocess.TimeoutExpired):
            cleanup_errors.append("assistant_browser_process_group")
        if fixture is not None:
            _close_fixture_for_report(fixture, report, cleanup_errors)
        if assistant_server is not None:
            (
                report["assistant_service_thread_stopped"],
                report["assistant_http_server_closed"],
            ) = _stop_http_server(
                assistant_server, assistant_thread, "assistant_http", cleanup_errors
            )
        (
            report["service_thread_stopped"],
            report["http_server_closed"],
        ) = _stop_http_server(server, thread, "http", cleanup_errors)
        if (
            report["service_thread_stopped"]
            and report["http_server_closed"]
            and report["assistant_service_thread_stopped"]
            and report["assistant_http_server_closed"]
        ):
            try:
                service.close()
                report["service_closed"] = True
            except Exception:
                cleanup_errors.append("service_close")
        if receiver_driver is not None:
            block_reason = _receiver_phase_block_reason(
                report,
                runtime_admitted=runtime_admitted,
                work_remaining=work_deadline - time.monotonic(),
            )
            if block_reason is not None:
                report["receiver_phase_status"] = "not_attempted"
                report["receiver_phase_reason"] = block_reason
                report["receiver_process_group_stopped"] = True
                report["receiver_http_server_closed"] = True
                report["receiver_service_thread_stopped"] = True
                report["receiver_service_closed"] = True
            else:
                _run_receiver_phase(
                    report=report,
                    driver=receiver_driver,
                    guards=receiver_guards,
                    deadline_file=receiver_deadline,
                    node=node,
                    playwright=playwright,
                    output=output,
                    runtime=runtime,
                    environment=environment,
                    work_deadline=work_deadline,
                    service_type=BlueFireService,
                    runner_lifecycle_type=ManagedRunnerLifecycle,
                    create_server=create_server,
                    generate_capability=generate_browser_bootstrap_capability,
                    cleanup_errors=cleanup_errors,
                )
        os.chdir(output)
        if _runtime_process_cleanup_confirmed(report):
            try:
                shutil.rmtree(runtime)
            except OSError:
                cleanup_errors.append("temporary_state")
        report["temporary_state_removed"] = not runtime.exists()
        report["cleanup_errors"] = cleanup_errors
        report["receiver_native_retained_redaction"] = _receiver_retained_redaction_accepted(report)
        if (
            cleanup_errors
            or not _runtime_cleanup_confirmed(report)
            or not _required_phases_passed(report)
        ):
            report["status"] = "failed_or_incomplete"
        else:
            report["status"] = "passed"
        # Close the receipt before returning; non-daemon service threads then
        # keep a failed harness under the workflow timeout if any thread lives.
        write_new(output / "receipt.json", report)
        print(json.dumps(report, sort_keys=True))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
