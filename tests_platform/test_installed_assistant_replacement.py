"""Focused contracts for the installed explicit-replacement verifier."""

from __future__ import annotations

import copy
import json
import shutil
import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest

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


def replacement_failure() -> dict[str, str]:
    return {
        "substage": "terminal_job",
        "error_category": "assertion",
        "submission_status": "accepted",
        "job_state": "failed",
        "turn_status": "blocked",
        "job_error_shape": "object",
        "result_ref_shape": "absent",
        "plan_shape": "empty",
        "results_shape": "empty",
    }


def test_replacement_failure_keeps_terminal_failure_distinct_from_rendering_failure() -> None:
    diagnostic = replacement_failure()
    report = {
        "errors": [{"stage": "explicit-replacement", "kind": "journey_failed"}],
        "replacement_diagnostic": diagnostic,
    }
    assert verifier._browser_failure_diagnostic(report) == {
        "browser_stage": "explicit-replacement",
        "replacement_diagnostic": diagnostic,
    }
    diagnostic.update(
        substage="completion_heading",
        error_category="timeout",
        job_state="completed",
        turn_status="completed",
        job_error_shape="absent",
    )
    assert verifier._browser_failure_diagnostic(report)["replacement_diagnostic"] == diagnostic
    report["errors"][0]["stage"] = "fresh-session"
    assert verifier._browser_failure_diagnostic(report) == {"browser_stage": "fresh-session"}


@pytest.mark.parametrize("field", list(replacement_failure()))
@pytest.mark.parametrize("unsafe", ["unrecognized-private-detail", ["unhashable"], None, True])
def test_replacement_failure_rejects_unexpected_diagnostic_values(field, unsafe) -> None:
    diagnostic = replacement_failure()
    diagnostic[field] = unsafe
    assert verifier._browser_failure_diagnostic(
        {
            "errors": [{"stage": "explicit-replacement", "kind": "journey_failed"}],
            "replacement_diagnostic": diagnostic,
        }
    ) == {"browser_stage": "explicit-replacement"}


def test_replacement_failure_rejects_missing_or_extra_fields() -> None:
    for diagnostic in (
        {**replacement_failure(), "message": "unbounded private detail"},
        {key: value for key, value in replacement_failure().items() if key != "plan_shape"},
    ):
        assert verifier._browser_failure_diagnostic(
            {
                "errors": [{"stage": "explicit-replacement", "kind": "journey_failed"}],
                "replacement_diagnostic": diagnostic,
            }
        ) == {"browser_stage": "explicit-replacement"}


def run_driver_contract(script: str) -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is required for the installed driver contract")
    driver = (
        Path(__file__).resolve().parents[1]
        / "frontend/tests/installed/installed-assistant-replacement.mjs"
    )
    result = subprocess.run(
        [node, "--input-type=module", "-", str(driver)],
        input=script,
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_driver_projection_withholds_raw_result_content_and_unexpected_states() -> None:
    run_driver_contract(r"""
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
const source = readFileSync(process.argv[2], 'utf8').replaceAll('\r\n', '\n');
const start = source.indexOf('function replacementFailureDiagnostic(');
const end = source.indexOf('async function submitThroughUi(', start);
assert.ok(start >= 0 && end > start);
const project = runInNewContext(`${source.slice(start, end)}; replacementFailureDiagnostic`);
const privateValue = 'PRIVATE_SENTINEL_MUST_NOT_ESCAPE';
const observed = {
  job: {state: 'failed', error: {message: privateValue, stack: privateValue}, result_ref: privateValue},
  turn: {status: 'blocked', message: privateValue, plan: [privateValue], results: []},
};
const error = {name: 'AssertionError', message: privateValue, stack: privateValue};
const actual = JSON.parse(JSON.stringify(project('terminal_job', observed, 202, error)));
assert.deepEqual(actual, {
  substage: 'terminal_job', error_category: 'assertion', submission_status: 'accepted',
  job_state: 'failed', turn_status: 'blocked', job_error_shape: 'object',
  result_ref_shape: 'string', plan_shape: 'nonempty', results_shape: 'empty',
});
for (const hostile of [privateValue, [], null, true, {job: {state: privateValue}, turn: {status: privateValue}}]) {
  const result = project(privateValue, hostile, privateValue, {name: privateValue});
  assert.equal(result.substage, 'unknown');
  assert.equal(result.error_category, 'other');
  assert.equal(result.submission_status, 'other');
  assert.equal(result.job_state, 'unknown');
  assert.equal(result.turn_status, 'unknown');
  assert.equal(JSON.stringify(result).includes(privateValue), false);
  assert.ok(JSON.stringify(result).length < 500);
}
const malformed = project('empty_results', {job: {error: [], result_ref: {}}, turn: {plan: null, results: {content: privateValue}}});
assert.equal(malformed.job_error_shape, 'invalid');
assert.equal(malformed.result_ref_shape, 'invalid');
assert.equal(malformed.plan_shape, 'invalid');
assert.equal(malformed.results_shape, 'invalid');
assert.equal(project('terminal_poll', undefined).job_error_shape, 'missing');
assert.equal(JSON.stringify(malformed).includes(privateValue), false);
""")


def test_submission_diagnostic_precedes_status_and_identity_assertions() -> None:
    run_driver_contract(r"""
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
const source = readFileSync(process.argv[2], 'utf8').replaceAll('\r\n', '\n');
const start = source.indexOf('async function submitThroughUi(');
const end = source.indexOf('\ntry {\n  const firstCapability', start);
assert.ok(start >= 0 && end > start);
for (const status of [409, 202]) {
  const calls = [];
  const envelope = {job: {job_id: 'invalid', state: 'queued'}};
  const response = {status: () => status, request: () => ({postData: () => '{}'}), json: async () => envelope};
  const panel = {getByRole: () => ({fill: async () => {}, click: async () => {}})};
  const submit = runInNewContext(`${source.slice(start, end)}; submitThroughUi`, {
    page: {waitForResponse: () => Promise.resolve(response)}, assert, prompt: 'fixture',
    jobPattern: /^job-[0-9a-f]{32}$/,
  });
  await assert.rejects(submit(panel, (...args) => calls.push(args)), {name: 'AssertionError'});
  assert.deepEqual(calls.slice(0, 4).map(row => row[0]), ['submission_fill', 'submission_click', 'submission_response', 'submission_status']);
  assert.equal(calls[3][1], status);
  assert.equal(calls.at(-1)[0], status === 409 ? 'submission_status' : 'submission_identity');
  if (status === 202) assert.equal(calls.at(-1)[2], envelope);
}
""")


@pytest.mark.parametrize("failure", ["backend", "heading"])
def test_replacement_captures_observation_before_terminal_or_heading_failure(failure) -> None:
    run_driver_contract(r"""
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
const source = readFileSync(process.argv[2], 'utf8').replaceAll('\r\n', '\n');
const start = source.indexOf('  replacementSubstage = "terminal_poll";');
const end = source.indexOf('  report.observed_states.replacement =', start);
assert.ok(start >= 0 && end > start);
const backend = FAILURE === 'backend';
const value = {job: {state: backend ? 'failed' : 'completed'}, turn: {status: backend ? 'blocked' : 'completed'}};
const context = {
  assert, replacementId: 'job-' + 'a'.repeat(32), replacementSubstage: null, replacementObserved: null,
  api: async () => value,
  poll: async (fn, wanted, timeout) => {assert.equal(timeout, 30000); const result = await fn(); assert.ok(wanted(result)); return result;},
  replacementPanel: {getByRole: (role, options) => {
    assert.equal(role, 'heading'); assert.equal(options.name, 'Work completed'); assert.equal(options.exact, true);
    return {waitFor: async () => {throw Object.assign(new Error('private diagnostic'), {name: 'TimeoutError'});}};
  }},
};
const run = runInNewContext(`(async () => {${source.slice(start, end)}})`, context);
await assert.rejects(run(), {name: backend ? 'AssertionError' : 'TimeoutError'});
assert.equal(context.replacementObserved, value);
assert.equal(context.replacementSubstage, backend ? 'terminal_job' : 'completion_heading');
""".replace("FAILURE", json.dumps(failure)))


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
