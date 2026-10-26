"""Focused contracts for the installed explicit-replacement verifier."""

from __future__ import annotations

import copy
from unittest.mock import Mock

from tools import verify_installed_assistant_replacement as verifier


def request() -> dict[str, object]:
    return {
        "model": verifier.MODEL,
        "instructions": "Explain the bounded saved comparison.",
        "input": "synthetic saved comparison facts",
        "max_output_tokens": 64,
        "store": False,
        "parallel_tool_calls": False,
        "tools": [],
        "tool_choice": "none",
        "text": {
            "format": {
                "type": "json_schema",
                "name": verifier.PURPOSE,
                "schema": {"type": "object"},
                "strict": True,
            }
        },
    }


def marker() -> dict[str, object]:
    return {
        "schema_version": "bluefire.assistant-replacement.phase-one.v1",
        "snapshot_id": "run-comparison-" + "a" * 64,
        "snapshot_digest": "sha256:" + "a" * 64,
        "run_ids": [
            "run-20261026T000000Z-" + "b" * 16,
            "run-20261026T000001Z-" + "c" * 16,
        ],
        "original_job_id": "job-" + "d" * 32,
        "context_digest": "sha256:" + "e" * 64,
        "original_request_digest": "f" * 64,
        "first_authorization": {
            "authorization_id": "ai-authorization-" + "2" * 32,
            "expires_at_ms": 1793030400000,
            "requests": 1,
            "request_bytes": 8192,
            "reserved_output_tokens": 64,
            "remaining_requests": 0,
            "remaining_request_bytes": 516096,
            "remaining_reserved_output_tokens": 0,
        },
    }


def test_loopback_provider_accepts_only_exact_credential_free_structured_explanations() -> None:
    original = request()
    assert verifier.valid_model_request(original, length=256, authorization=None)
    assert not verifier.valid_model_request(original, length=0, authorization=None)
    assert not verifier.valid_model_request(original, length=262145, authorization=None)
    assert not verifier.valid_model_request(original, length=256, authorization="Bearer secret")
    for change in (
        lambda value: value.update(model="another-model"),
        lambda value: value.update(tools=[{"type": "function"}]),
        lambda value: value.update(max_output_tokens=True),
        lambda value: value.update(extra="unexpected"),
        lambda value: value["text"]["format"].update(name="another-purpose"),
    ):
        altered = copy.deepcopy(original)
        change(altered)
        assert not verifier.valid_model_request(altered, length=256, authorization=None)


def test_first_phase_marker_binds_two_ordered_runs_and_original_context() -> None:
    original = marker()
    assert verifier._phase_one_valid(original)
    for change in (
        lambda value: value["run_ids"].__setitem__(1, value["run_ids"][0]),
        lambda value: value.update(context_digest="sha256:bad"),
        lambda value: value.update(original_job_id="job-other"),
        lambda value: value.update(original_request_digest="0" * 63),
        lambda value: value["first_authorization"].update(remaining_requests=1),
        lambda value: value["first_authorization"].update(remaining_request_bytes=524288),
        lambda value: value.update(extra="forged"),
    ):
        altered = copy.deepcopy(original)
        change(altered)
        assert not verifier._phase_one_valid(altered)


def test_browser_contract_requires_blocked_original_and_only_explicit_replacement() -> None:
    first = marker()
    later = "job-" + "1" * 32
    browser = {
        "schema_version": "bluefire.installed-assistant-replacement.browser.v1",
        "status": "passed",
        "installed_service": True,
        "native_execution": False,
        "live_model_inference": False,
        "same_turn_continuation": False,
        "same_run_inspection_retry": False,
        "blocked_requests": [],
        "errors": [],
        "phase_one": first,
        "snapshot_id": first["snapshot_id"],
        "snapshot_digest": first["snapshot_digest"],
        "run_ids": first["run_ids"],
        "provider_request_count": 2,
        "screenshots": [
            {
                "file": "assistant-blocked-original-1440x900.png",
                "sha256": "a" * 64,
                "bytes": 153600,
            },
            {
                "file": "assistant-completed-replacement-1440x900.png",
                "sha256": "b" * 64,
                "bytes": 156700,
            },
        ],
        "checks": [
            "two_real_service_synthetic_simulations_and_immutable_comparison",
            "labeled_loopback_provider_authorized_for_one_bounded_explanation",
            "original_comparison_request_and_first_model_call_retained_before_process_loss",
            "restart_kept_original_blocked_without_provider_replay_or_continue_action",
            "new_service_session_required_fresh_normal_settings_authorization",
            "visible_explicit_new_request_created_distinct_completed_explanation",
            "snapshot_run_order_and_request_context_remained_unchanged_without_effectful_writes",
        ],
        "original": {
            "job_id": first["original_job_id"],
            "state": "interrupted",
            "status": "blocked",
        },
        "replacement": {"job_id": later, "state": "completed", "status": "completed"},
        "authorization": {
            "prior": {
                **first["first_authorization"],
                "status_after_restart": "context_unavailable",
            },
            "replacement": {
                "authorization_id": "ai-authorization-" + "3" * 32,
                "expires_at_ms": 1793030500000,
                "requests": 1,
                "request_bytes": 9216,
                "reserved_output_tokens": 64,
                "remaining_requests": 0,
                "remaining_request_bytes": 515072,
                "remaining_reserved_output_tokens": 0,
            },
        },
        "write_counts": {
            "setup": {
                "run_preflight": 2,
                "run": 2,
                "comparison": 1,
                "provider_save": 1,
                "provider_activate": 1,
                "authorization": 1,
                "assistant_turn": 1,
                "session": 1,
            },
            "recovery": {
                "authorization": 1,
                "assistant_turn": 1,
                "session": 1,
                "other_attempts": 0,
            },
        },
    }
    assert verifier._browser_report_passed(browser, first)
    for change in (
        lambda value: value["original"].update(state="completed"),
        lambda value: value["replacement"].update(job_id=first["original_job_id"]),
        lambda value: value["write_counts"]["recovery"].update(run=1),
        lambda value: value["authorization"]["prior"].update(status_after_restart="active"),
        lambda value: value["authorization"]["replacement"].update(
            authorization_id=first["first_authorization"]["authorization_id"]
        ),
        lambda value: value.update(provider_request_count=3),
        lambda value: value["screenshots"][0].update(file="settings-authorization.png"),
        lambda value: value["screenshots"][1].update(bytes=4 * 1024 * 1024 + 1),
        lambda value: value.update(same_turn_continuation=True),
    ):
        altered = copy.deepcopy(browser)
        change(altered)
        assert not verifier._browser_report_passed(altered, first)


def test_failure_progress_retains_only_bounded_stages_counts_and_observed_states() -> None:
    attempts = {
        "first_session": 1,
        "second_session": 0,
        "run_preflight": 2,
        "run": 2,
        "comparison": 1,
        "provider_save": 1,
        "provider_activate": 1,
        "authorization": 1,
        "assistant_turn": 1,
        "recovery_other_denied": 0,
    }
    source = {
        "errors": [
            {
                "stage": "first-explanation",
                "kind": "journey_failed",
                "secret": "never copy",  # pragma: allowlist secret - Fixed test sentinel.
            }
        ],
        "attempted_writes": attempts,
        "observed_states": {
            "original_before_loss": {"job": "running", "turn": "working"},
            "replacement": {"job": "completed", "turn": "completed", "path": "never copy"},
        },
        "provider_payload": "never copy",
    }
    assert verifier._browser_failure_diagnostic(source) == {
        "browser_stage": "first-explanation",
        "attempted_writes": attempts,
        "observed_states": {"original_before_loss": {"job": "running", "turn": "working"}},
    }
    source["errors"] = [{"stage": ["unhashable"], "kind": "journey_failed"}]
    source["attempted_writes"]["run"] = True
    source["observed_states"]["original_before_loss"]["job"] = ["unhashable"]
    assert verifier._browser_failure_diagnostic(source) == {}


def test_first_process_loss_requires_sigkill_reap_and_absent_owned_group(monkeypatch) -> None:
    calls = []
    sigkill = 9
    monkeypatch.setattr(
        verifier.support, "_signal_number", lambda name: sigkill if name == "SIGKILL" else None
    )
    child = Mock()
    child.pid = 4812
    child.returncode = -sigkill
    child.wait.return_value = child.returncode

    def killed_group(pid: int, signum: int) -> None:
        calls.append((pid, signum))
        if signum == 0:
            raise ProcessLookupError

    monkeypatch.setattr(verifier.support, "_kill_process_group", killed_group)
    assert verifier._hard_stop_first(child)
    assert calls == [(4812, sigkill), (4812, 0)]
    child.wait.assert_called_once_with(timeout=8)

    child.returncode = 0
    calls.clear()
    assert not verifier._hard_stop_first(child)
    assert calls == [(4812, sigkill), (4812, 0)]
