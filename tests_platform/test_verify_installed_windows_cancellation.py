from __future__ import annotations

import json
import os
import queue
import shutil
import subprocess
import threading
import time
import zipfile
from pathlib import Path

import pytest

from bluefire.runner_private_files import _PinnedPrivateDirectory
from tools import verify_installed_windows_cancellation as verifier


def _write_private_ready(task: Path, ready: dict[str, object]) -> None:
    with _PinnedPrivateDirectory(task) as control:
        control.create(
            "ready.json", json.dumps(ready).encode("utf-8"), maximum=verifier._MAX_READY_BYTES
        )


def test_receipt_is_written_directly_and_exclusively(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "receipt.json"
    value = {"status": "failed_or_incomplete"}
    real_write = os.write
    descriptors: list[int] = []

    def short_write(descriptor, payload):
        descriptors.append(descriptor)
        return real_write(descriptor, payload[:7])

    monkeypatch.setattr(verifier.os, "write", short_write)
    verifier._write_receipt(destination, value, maximum=4096)
    assert len(descriptors) > 1
    with pytest.raises(OSError):
        os.fstat(descriptors[-1])
    assert json.loads(destination.read_text(encoding="utf-8")) == value


def test_receipt_never_replaces_existing_file_or_link(tmp_path: Path) -> None:
    destination = tmp_path / "receipt.json"
    existing = tmp_path / "existing.json"
    existing.write_bytes(b"preexisting")
    for candidate in (destination,):
        candidate.write_bytes(b"prior receipt")
        with pytest.raises(FileExistsError):
            verifier._write_receipt(candidate, {"status": "failed"})
        assert candidate.read_bytes() == b"prior receipt"
        candidate.unlink()
    try:
        destination.symlink_to(existing)
    except OSError as error:
        pytest.skip(f"file symlinks unavailable: {type(error).__name__}")
    with pytest.raises(FileExistsError):
        verifier._write_receipt(destination, {"status": "failed"})
    assert existing.read_bytes() == b"preexisting"


def test_interrupted_receipt_remains_invalid_and_is_not_cleaned_up(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "receipt.json"
    real_write = os.write

    def interrupted_write(descriptor, payload):
        real_write(descriptor, payload[:7])
        raise OSError("fixture interrupted write")

    monkeypatch.setattr(verifier.os, "write", interrupted_write)
    with pytest.raises(OSError, match="interrupted write"):
        verifier._write_receipt(destination, {"status": "failed"})
    assert destination.exists()
    with pytest.raises(json.JSONDecodeError):
        json.loads(destination.read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    ("scenario", "valid"),
    [
        ("valid", True),
        ("mismatched_pids", False),
        ("malformed_capability", False),
        ("oversized_capability", False),
        ("oversized_tail", False),
        ("oversized_tail_coalesced", False),
        ("malformed_permit", False),
        ("oversized_permit", False),
        ("extra_frame", False),
        ("truncated_capability", False),
        ("truncated_permit", False),
        ("denied", False),
    ],
)
def test_real_driver_stdin_frames_are_bounded_and_bind_full_ready_record(
    scenario: str, valid: bool
) -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is required to exercise the installed cancellation driver")
    driver = (
        Path(__file__).resolve().parents[1]
        / "frontend/tests/installed/installed-windows-cancellation.mjs"
    )
    script = r"""
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
const source = readFileSync(process.argv[2], 'utf8');
const scenario = process.argv[3];
const readStart = source.indexOf('async function readInputLine(');
const readEnd = source.indexOf('async function readBoundedResponse(', readStart);
const permitStart = source.indexOf('async function waitForPermit(', readEnd);
const permitEnd = source.indexOf('\nfunction projectFailureRunDetail', permitStart);
assert.ok(readStart >= 0 && readEnd > readStart && permitStart > readEnd && permitEnd > permitStart);
const ready = {
  schema_version: 'bluefire.process-tree-cancellation-ready.v1',
  task_id: `execute-${'a'.repeat(64)}`,
  request_hash: `sha256:${'a'.repeat(64)}`,
  parent_process_id: 101,
  descendant_process_id: 202,
};
const capability = JSON.stringify({type: 'capability', capability: 'c'.repeat(64)});
let permit = JSON.stringify({type: 'witness_permit', ready});
if (scenario === 'mismatched_pids') {
  permit = JSON.stringify({type: 'witness_permit', ready: {...ready, descendant_process_id: 303}});
}
if (scenario === 'malformed_permit') permit = '{broken';
if (scenario === 'oversized_permit') permit = 'x'.repeat(1025);
if (scenario === 'denied') permit = JSON.stringify({type: 'witness_denied'});
if (scenario === 'extra_frame') permit += `\n${JSON.stringify({type: 'extra'})}`;
let payload;
if (scenario === 'malformed_capability') payload = '{broken\n';
else if (scenario === 'oversized_capability') payload = `${'x'.repeat(1025)}\n`;
else if (scenario === 'oversized_tail' || scenario === 'oversized_tail_coalesced') payload = `${capability}\n${'x'.repeat(2051)}`;
else if (scenario === 'truncated_capability') payload = capability;
else if (scenario === 'truncated_permit') payload = `${capability}\n${permit}`;
else payload = `${capability}\n${permit}\n`;
const chunks = [];
if (scenario === 'oversized_tail_coalesced') {
  chunks.push(Buffer.from(payload));
} else {
  for (let offset = 0; offset < payload.length; offset += 13) {
    chunks.push(Buffer.from(payload.slice(offset, offset + 13)));
  }
}
let index = 0;
const context = {
  assert, Buffer, Date, setTimeout, clearTimeout, MAX_INPUT_BYTES: 2050, witnessFailureCode: '', scenario,
  ready_json: JSON.stringify(ready),
  stdinBuffer: Buffer.alloc(0), stdinDone: false, stdinBytesRead: 0,
  stdinReader: {async next() {
    return index < chunks.length ? {done: false, value: chunks[index++]} : {done: true};
  }},
};
const helpers = source.slice(readStart, readEnd) + source.slice(permitStart, permitEnd);
const run = runInNewContext(`${helpers}; (async () => {
  const expectedReady = JSON.parse(ready_json);
  const initialFailures = ['malformed_capability', 'oversized_capability', 'oversized_tail_coalesced', 'truncated_capability'];
  if (initialFailures.includes(scenario)) {
    await assert.rejects(readInputLine(1024, Date.now() + 1000));
    return;
  }
  const initial = await readInputLine(1024, Date.now() + 1000);
  assert.equal(initial.type, 'capability');
  assert.equal(initial.capability, 'c'.repeat(64));
  if (scenario === 'valid') {
    await waitForPermit(expectedReady);
    return;
  }
  await assert.rejects(waitForPermit(expectedReady));
})()`, context);
await run;
"""
    result = subprocess.run(
        [node, "--input-type=module", "-", str(driver), scenario],
        input=script,
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )
    assert valid is (scenario == "valid")
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    "snapshot", ["missing_controls", "empty_controls", "ambiguous", "redirected"]
)
def test_real_driver_labels_ready_deadline_separately_from_assertions(snapshot: str) -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is required to exercise the installed cancellation driver")
    driver = (
        Path(__file__).resolve().parents[1]
        / "frontend/tests/installed/installed-windows-cancellation.mjs"
    )
    script = r"""
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
const source = readFileSync(process.argv[2], 'utf8');
const start = source.indexOf('async function waitForWitnessReady()');
const end = source.indexOf('async function waitForPermit(', start);
assert.ok(start >= 0 && end > start);
const snapshot = process.argv[3];
let now = 0;
let sleeps = 0;
let reads = 0;
const context = {
  assert, ready: null, witnessCheck: 'workspace', witnessFailureCode: '', Date: {now: () => now},
  async sleep(milliseconds) { assert.equal(milliseconds, 50); sleeps += 1; now = 45_000; },
};
context.witnessReady = async () => {
  reads += 1;
  context.witnessCheck = 'task';
  if (snapshot === 'missing_controls') throw Object.assign(new Error('fixture missing'), {code: 'ENOENT'});
  if (snapshot === 'ambiguous') assert.equal(2, 1);
  if (snapshot === 'redirected') assert.ok(false);
  return null;
};
const wait = runInNewContext(`${source.slice(start, end)}; waitForWitnessReady`, context);
await assert.rejects(wait(), {name: 'AssertionError'});
const deadline = ['missing_controls', 'empty_controls'].includes(snapshot);
assert.equal(context.witnessFailureCode, deadline ? 'witness_ready_deadline' : 'witness_ready_assertion');
assert.equal(context.witnessCheck, 'task');
assert.equal(reads, 1);
assert.equal(sleeps, deadline ? 1 : 0);
"""
    result = subprocess.run(
        [node, "--input-type=module", "-", str(driver), snapshot],
        input=script,
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    "binding",
    [
        "blocked",
        "run",
        "scenario",
        "digest",
        "profile",
        "step",
        "duplicate",
        "planned_step",
        "unknown",
        "secret",
        "transport_known",
        "transport_io",
        "transport_terminal",
        "transport_unknown",
        "transport_secret",
        "transport_wrong_code",
    ],
)
def test_real_driver_failure_projection_binds_source_and_excludes_unreviewed_values(
    binding: str,
) -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is required to exercise the installed cancellation driver")
    driver = (
        Path(__file__).resolve().parents[1]
        / "frontend/tests/installed/installed-windows-cancellation.mjs"
    )
    script = r"""
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
const source = readFileSync(process.argv[2], 'utf8');
const start = source.indexOf('function projectFailureRunDetail(');
const end = source.indexOf('async function diagnoseTerminalRun(', start);
assert.ok(start >= 0 && end > start);
const binding = process.argv[3];
const ACTION = 'sandbox.execution.process-tree-cancellation-witness.v1';
const PROFILE = 'gate11-windows-cancellation-witness.v1';
const selected = {scenario_id: 'scenario.fixture.v1', digest: `sha256:${'a'.repeat(64)}`};
const ownRun = `run-20261021T120000Z-${'c'.repeat(16)}`;
const secret = 'PRIVATE_SYNTHETIC_SECRET_42'; // pragma: allowlist secret - synthetic test sentinel
const step = {step_id: 'witness', behavior_id: ACTION, action_id: ACTION};
const value = {
  run_id: ownRun, scenario: {id: selected.scenario_id}, profile: {id: PROFILE}, status: 'completed',
  plan: {scenario_id: selected.scenario_id, scenario_digest: selected.digest, mode: 'execute',
    runner_profile_id: PROFILE, steps: [{...step}]},
  steps: [{...step, status: 'blocked', execution_disposition: 'execute', runner_status: 'refused',
    error: {code: 'cancellation_witness_blocked', message: secret}}],
  stdout: secret, evidence: {records: [{content: secret}]}, path: secret,
};
if (binding === 'run') value.run_id = 'other';
if (binding === 'scenario') value.scenario.id = 'other';
if (binding === 'digest') value.plan.scenario_digest = `sha256:${'b'.repeat(64)}`;
if (binding === 'profile') value.profile.id = 'other';
if (binding === 'step') value.steps[0].action_id = 'other';
if (binding === 'duplicate') value.steps.push({...value.steps[0]});
if (binding === 'planned_step') value.plan.steps[0].step_id = 'other';
if (['unknown', 'secret'].includes(binding)) {
  const unsafe = binding === 'secret' ? secret : 'not_reviewed';
  value.status = unsafe;
  Object.assign(value.steps[0], {status: unsafe, execution_disposition: unsafe, runner_status: unsafe, error: {code: unsafe, message: secret}});
}
const transportReasons = {transport_known: 'windows_suspended_start_failed',
  transport_io: 'runner_io_failed', transport_terminal: 'watchdog_terminal_timeout'};
if (binding.startsWith('transport_')) {
  value.steps[0].error = {code: binding === 'transport_wrong_code'
    ? 'cancellation_witness_blocked' : 'runner_transport_failed', message: secret,
    transport_failure_reason: binding === 'transport_unknown' ? 'unreviewed_reason'
      : binding === 'transport_secret' ? secret : transportReasons[binding] ?? 'windows_suspended_start_failed'};
}
const project = runInNewContext(`${source.slice(start, end)}; projectFailureRunDetail`, {ACTION, PROFILE});
const result = JSON.parse(JSON.stringify(project(value, ownRun, selected)));
if (['blocked', 'unknown', 'secret'].includes(binding) || binding.startsWith('transport_')) {
  const unknown = ['unknown', 'secret'].includes(binding);
  const transport = binding.startsWith('transport_') && binding !== 'transport_wrong_code';
  assert.deepEqual(result, {status: 'available', run_status: unknown ? 'other' : 'completed',
    step_status: unknown ? 'other' : 'blocked',
    execution_disposition: unknown ? 'other' : 'execute',
    runner_status: unknown ? 'other' : 'refused',
    error_code: unknown ? 'other' : transport ? 'runner_transport_failed' : 'cancellation_witness_blocked',
    transport_failure_reason: !transport ? 'absent' : transportReasons[binding] ?? 'other'});
} else assert.deepEqual(result, {status: 'unavailable', reason: 'source_binding_mismatch'});
assert.equal(JSON.stringify(result).includes(secret), false);
assert.equal(JSON.stringify(result).includes('not_reviewed'), false);
"""
    result = subprocess.run(
        [node, "--input-type=module", "-", str(driver), binding],
        input=script,
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def _passed_driver_report() -> dict[str, object]:
    return {
        "schema_version": "bluefire.installed-windows-cancellation.v1",
        "status": "passed",
        "profile_id": verifier.PROFILE_ID,
        "scenario_id": "scenario.installed-windows-cancel.12345678-1234-4234-8234-123456789abc.v1",
        "scenario_version": 1,
        "scenario_digest": "sha256:" + "a" * 64,
        "job_id": "job-" + "b" * 32,
        "run_id": "run-20261021T120000Z-" + "c" * 16,
        "preflight_status": "approval_required",
        "approval_status_before": "pending",
        "approval_status_after": "consumed",
        "job_state_after_cancel": "cancelled",
        "witness_request_hash": "sha256:" + "d" * 64,
        "runner_stopped": True,
        "execution_interruption": {
            "cooperative_requested": True,
            "cooperative_acknowledged": True,
            "forced_tree_termination": True,
            "control_cleanup_verified": True,
            "process_tree_stopped": True,
        },
        "checks": [
            "ephemeral_authenticated_session_created",
            "shipped_gate11_profile_and_action_verified",
            "fresh_installed_runner_bootstrapped_and_started_through_service",
            "exact_execute_preflight_and_fresh_approval_consumed",
            "cancel_requested_only_after_fresh_witness_processes_were_pinned",
            "retained_interruption_confirmed_cancellation_and_cleanup",
            "both_witness_process_handles_signaled_and_control_tree_removed",
            "managed_runner_stopped_through_service",
        ],
        "request_counts": {
            "session": 1,
            "catalog": 1,
            "runner_status": 2,
            "runner_bootstrap": 1,
            "runner_start": 1,
            "scenario_save": 1,
            "preflight": 1,
            "run_submit": 1,
            "approval": 1,
            "cancel": 1,
            "retained_observations": 1,
            "runner_stop": 1,
            "job_status": 2,
        },
    }


def test_profile_authority_accepts_only_shipped_gate11_bounds() -> None:
    profile = {
        "id": verifier.PROFILE_ID,
        "mode": "execute",
        "platforms": ["windows"],
        "scope": ["sandbox.workspace"],
        "network_allowlist": [],
        "approval_required": True,
        "enabled_actions": [verifier.ACTION_ID, "sandbox.cleanup.v1"],
        "blocked_actions": [],
        "budgets": {"max_steps": 1, "max_seconds": 30, "max_artifacts": 4, "max_bytes": 65536},
    }
    assert verifier._profile_authority_valid(profile)
    for field, value in (
        ("network_allowlist", ["127.0.0.1/32"]),
        ("approval_required", False),
        ("enabled_actions", [verifier.ACTION_ID, "sandbox.network.loopback.v1"]),
        ("budgets", {"max_steps": 2, "max_seconds": 30, "max_artifacts": 4, "max_bytes": 65536}),
    ):
        changed = dict(profile)
        changed[field] = value
        assert not verifier._profile_authority_valid(changed)


def test_ready_record_requires_exact_request_bound_process_identity() -> None:
    digest = "a" * 64
    record = {
        "schema_version": "bluefire.process-tree-cancellation-ready.v1",
        "task_id": f"execute-{digest}",
        "request_hash": f"sha256:{digest}",
        "parent_process_id": 100,
        "descendant_process_id": 200,
    }
    assert verifier._ready_record_valid(record, directory_name=digest)
    for field, value in (
        ("parent_process_id", True),
        ("descendant_process_id", 100),
        ("request_hash", "sha256:" + "A" * 64),
    ):
        changed = dict(record)
        changed[field] = value
        assert not verifier._ready_record_valid(changed, directory_name=digest)
    extra = {**record, "unreviewed": True}
    assert not verifier._ready_record_valid(extra, directory_name=digest)


@pytest.mark.parametrize("directory_name", ["abcd", "A" * 64, "g" * 64])
def test_witness_observer_rejects_malformed_directory_name_before_pin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, directory_name: str
) -> None:
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    task = (
        sandbox
        / ".bluefire-executions"
        / "approval-test"
        / ".bluefire-cancellation-witness-v1"
        / directory_name
    )
    task.mkdir(parents=True)
    ready = {
        "schema_version": "bluefire.process-tree-cancellation-ready.v1",
        "task_id": f"execute-{directory_name}",
        "request_hash": f"sha256:{directory_name}",
        "parent_process_id": 101,
        "descendant_process_id": 202,
    }
    _write_private_ready(task, ready)
    pinned: list[dict[str, object]] = []
    monkeypatch.setattr(
        verifier, "_pin_windows_processes", lambda value: pinned.append(value.copy())
    )

    with pytest.raises(ValueError, match="witness record"):
        verifier._private_ready_record(sandbox, threading.Event())

    assert pinned == []


def test_witness_observer_uses_fresh_approval_workspace_and_pins_before_permit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    digest = "e" * 64
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    task = (
        sandbox
        / ".bluefire-executions"
        / "approval-test"
        / ".bluefire-cancellation-witness-v1"
        / digest
    )
    task.mkdir(parents=True)
    ready = {
        "schema_version": "bluefire.process-tree-cancellation-ready.v1",
        "task_id": f"execute-{digest}",
        "request_hash": f"sha256:{digest}",
        "parent_process_id": 101,
        "descendant_process_id": 202,
    }
    _write_private_ready(task, ready)
    pinned: list[dict[str, object]] = []
    monkeypatch.setattr(
        verifier, "_pin_windows_processes", lambda value: pinned.append(value.copy())
    )

    result = verifier._private_ready_record(sandbox, threading.Event())

    assert pinned == [ready]
    assert result["control_path"] == task


def test_witness_observer_rejects_ambiguous_approval_workspaces(tmp_path: Path) -> None:
    sandbox = tmp_path / "sandbox"
    executions = sandbox / ".bluefire-executions"
    executions.mkdir(parents=True)
    (executions / "approval-one").mkdir()
    (executions / "approval-two").mkdir()
    with pytest.raises(ValueError, match="workspace identity"):
        verifier._private_ready_record(sandbox, threading.Event())


def test_witness_observer_retries_empty_workspace_construction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    executions = sandbox / ".bluefire-executions"
    executions.mkdir()
    ready = {
        "schema_version": "bluefire.process-tree-cancellation-ready.v1",
        "task_id": "execute-" + "1" * 64,
        "request_hash": "sha256:" + "1" * 64,
        "parent_process_id": 101,
        "descendant_process_id": 202,
    }
    task = executions / "owner" / ".bluefire-cancellation-witness-v1" / ("1" * 64)
    snapshots = 0
    pinned: list[dict[str, object]] = []

    def advance(_seconds):
        nonlocal snapshots
        snapshots += 1
        if snapshots == 1:
            (executions / "owner").mkdir()
        elif snapshots == 2:
            (executions / "owner" / ".bluefire-cancellation-witness-v1").mkdir()
        elif snapshots == 3:
            task.mkdir()
        elif snapshots == 4:
            _write_private_ready(task, ready)

    monkeypatch.setattr(verifier.time, "sleep", advance)
    monkeypatch.setattr(
        verifier, "_pin_windows_processes", lambda value: pinned.append(value.copy())
    )
    result = verifier._private_ready_record(sandbox, threading.Event())
    assert snapshots == 4
    assert result["control_path"] == task and pinned == [ready]


@pytest.mark.parametrize(
    "snapshot",
    ["staged", "multiple_owners", "multiple_tasks", "redirected_owner", "invalid_ready"],
)
def test_real_driver_ready_reader_waits_only_for_empty_construction_snapshots(
    snapshot: str,
) -> None:
    """Run the shipped reader against deterministic filesystem snapshots, without processes."""
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is required to exercise the installed cancellation driver")
    driver = (
        Path(__file__).resolve().parents[1]
        / "frontend/tests/installed/installed-windows-cancellation.mjs"
    )
    script = r"""
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { runInNewContext } from 'node:vm';
const source = readFileSync(process.argv[2], 'utf8');
const start = source.indexOf('async function witnessReady() {');
const end = source.indexOf('async function waitForPermit(', start);
assert.ok(start >= 0 && end > start);
const snapshot = process.argv[3];
const digest = 'e'.repeat(64);
const ready = {
  schema_version: 'bluefire.process-tree-cancellation-ready.v1',
  task_id: `execute-${digest}`, request_hash: `sha256:${digest}`,
  parent_process_id: 101, descendant_process_id: 202,
};
let phase = 0;
const sandbox = 'fixture-sandbox';
const executions = join(sandbox, '.bluefire-executions');
const owner = join(executions, 'approval-fixture');
const controls = join(owner, '.bluefire-cancellation-witness-v1');
const context = {
  assert, join, sandbox, witnessCheck: 'workspace',
  readdirSync(path) {
    if (path === executions) {
      if (snapshot === 'multiple_owners') return ['approval-one', 'approval-two'];
      if (snapshot === 'staged' && phase === 0) return [];
      return ['approval-fixture'];
    }
    assert.equal(path, controls);
    if (snapshot === 'multiple_tasks') return [digest, 'f'.repeat(64)];
    return snapshot === 'staged' && phase === 1 ? [] : [digest];
  },
  lstatSync(path) {
    return {
      isDirectory: () => !path.endsWith('ready.json'),
      isFile: () => path.endsWith('ready.json'),
      isSymbolicLink: () => snapshot === 'redirected_owner' && path === owner,
      size: 256,
    };
  },
  readFileSync() {
    return JSON.stringify(snapshot === 'invalid_ready' ? {...ready, unreviewed: true} : ready);
  },
};
const readReady = runInNewContext(`${source.slice(start, end)}; witnessReady`, context);
if (snapshot === 'staged') {
  assert.equal(await readReady(), null);
  assert.equal(context.witnessCheck, 'workspace');
  phase = 1;
  assert.equal(await readReady(), null);
  assert.equal(context.witnessCheck, 'task');
  phase = 2;
  const result = await readReady();
  assert.deepEqual(JSON.parse(JSON.stringify(result.value)), ready);
  assert.equal(result.task, join(controls, digest));
} else {
  await assert.rejects(readReady(), {name: 'AssertionError'});
}
"""
    result = subprocess.run(
        [node, "--input-type=module", "-", str(driver), snapshot],
        input=script,
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_wheel_identity_requires_installed_package_bytes_to_match(tmp_path: Path) -> None:
    wheel = tmp_path / "bluefire_nexus-1.2.3-py3-none-any.whl"
    package = tmp_path / "site-packages" / "bluefire"
    package.mkdir(parents=True)
    files = {
        "bluefire/__init__.py": b"__version__ = '1.2.3'\n",
        "bluefire/example.py": b"VALUE = 1\n",
        "bluefire/native/bluefire-runner.exe": b"fixture binary\n",
    }
    (package / "__init__.py").write_bytes(files["bluefire/__init__.py"])
    (package / "example.py").write_bytes(files["bluefire/example.py"])
    (package / "native").mkdir()
    (package / "native" / "bluefire-runner.exe").write_bytes(
        files["bluefire/native/bluefire-runner.exe"]
    )
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(
            "bluefire_nexus-1.2.3.dist-info/METADATA", "Name: bluefire-nexus\nVersion: 1.2.3\n\n"
        )
        for name, content in files.items():
            archive.writestr(name, content)

    assert verifier._installed_package_matches_wheel(wheel, package, "1.2.3")
    assert not verifier._installed_package_matches_wheel(wheel, package, "1.2.4")
    (package / "example.py").write_text("VALUE = 2\n", encoding="utf-8")
    assert not verifier._installed_package_matches_wheel(wheel, package, "1.2.3")


@pytest.mark.parametrize("library", ["purelib", "platlib"])
def test_wheel_identity_normalizes_standard_data_package_layouts(
    tmp_path: Path, library: str
) -> None:
    wheel = tmp_path / "bluefire_nexus-1.2.3-py3-none-any.whl"
    package = tmp_path / "site-packages" / "bluefire"
    package.mkdir(parents=True)
    files = {
        "__init__.py": b"__version__ = '1.2.3'\n",
        "native/bluefire-runner.exe": b"fixture binary\n",
    }
    (package / "__init__.py").write_bytes(files["__init__.py"])
    (package / "native").mkdir()
    (package / "native" / "bluefire-runner.exe").write_bytes(files["native/bluefire-runner.exe"])
    data_root = f"bluefire_nexus-1.2.3.data/{library}/bluefire"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(
            "bluefire_nexus-1.2.3.dist-info/METADATA", "Name: bluefire-nexus\nVersion: 1.2.3\n\n"
        )
        for name, content in files.items():
            archive.writestr(f"{data_root}/{name}", content)

    assert verifier._installed_package_matches_wheel(wheel, package, "1.2.3")


def test_wheel_identity_rejects_conflicting_package_layouts(tmp_path: Path) -> None:
    wheel = tmp_path / "bluefire_nexus-1.2.3-py3-none-any.whl"
    package = tmp_path / "site-packages" / "bluefire"
    package.mkdir(parents=True)
    package_file = package / "__init__.py"
    package_file.write_bytes(b"__version__ = '1.2.3'\n")
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(
            "bluefire_nexus-1.2.3.dist-info/METADATA", "Name: bluefire-nexus\nVersion: 1.2.3\n\n"
        )
        archive.writestr("bluefire/__init__.py", package_file.read_bytes())
        archive.writestr(
            "bluefire_nexus-1.2.3.data/purelib/bluefire/__init__.py",
            b"__version__ = '1.2.4'\n",
        )

    assert not verifier._installed_package_matches_wheel(wheel, package, "1.2.3")


def test_wheel_identity_rejects_symlinked_installed_package_directory(tmp_path: Path) -> None:
    wheel = tmp_path / "bluefire_nexus-1.2.3-py3-none-any.whl"
    package = tmp_path / "site-packages" / "bluefire"
    package.mkdir(parents=True)
    (package / "__init__.py").write_bytes(b"__version__ = '1.2.3'\n")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "injected.py").write_text("VALUE = 1\n", encoding="utf-8")
    try:
        os.symlink(outside, package / "linked", target_is_directory=True)
    except OSError as error:
        pytest.skip(f"directory symlinks unavailable: {type(error).__name__}")
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(
            "bluefire_nexus-1.2.3.dist-info/METADATA", "Name: bluefire-nexus\nVersion: 1.2.3\n\n"
        )
        archive.writestr("bluefire/__init__.py", b"__version__ = '1.2.3'\n")

    assert not verifier._installed_package_matches_wheel(wheel, package, "1.2.3")


def test_driver_receipt_contract_and_job_count_are_strict() -> None:
    report = _passed_driver_report()
    assert verifier._driver_passed(report)
    for value in (True, 1, 101):
        changed = {**report, "request_counts": {**report["request_counts"], "job_status": value}}
        assert not verifier._driver_passed(changed)
    changed = {**report, "scenario_version": True}
    assert not verifier._driver_passed(changed)
    changed = {**report, "request_counts": {**report["request_counts"], "cancel": True}}
    assert not verifier._driver_passed(changed)
    changed = {**report, "checks": report["checks"][1:]}
    assert not verifier._driver_passed(changed)


@pytest.mark.parametrize(
    ("report", "expected"),
    [
        ({"driver_job_created": False}, True),
        (
            {"driver_job_created": True, "driver_job_empty": True, "driver_process_exited": True},
            True,
        ),
        (
            {"driver_job_created": True, "driver_job_empty": False, "driver_process_exited": True},
            False,
        ),
        (
            {"driver_job_created": True, "driver_job_empty": True, "driver_process_exited": False},
            False,
        ),
    ],
)
def test_cleanup_requires_every_created_job_to_drain(report, expected: bool) -> None:
    assert verifier._all_owned_groups_stopped(report) is expected


def _cleanup_ready_report() -> dict[str, object]:
    return {
        "driver_job_created": False,
        "driver_job_empty": True,
        "driver_process_exited": True,
        "driver_input_writer_stopped": True,
        "managed_runner_stopped": True,
        "service_thread_stopped": True,
        "service_http_server_closed": True,
        "service_closed": True,
        "witness_could_have_started": False,
        "witness_observer_stopped": True,
        "witness_process_handles_stopped": True,
        "witness_control_tree_removed": True,
    }


def test_runtime_removal_requires_all_owned_resources_closed() -> None:
    assert verifier._runtime_removal_allowed(_cleanup_ready_report())
    for field in (
        "managed_runner_stopped",
        "service_thread_stopped",
        "service_http_server_closed",
        "service_closed",
        "witness_observer_stopped",
        "driver_input_writer_stopped",
    ):
        changed = _cleanup_ready_report()
        changed[field] = False
        assert not verifier._runtime_removal_allowed(changed), field


@pytest.mark.parametrize(
    "field",
    ["witness_process_handles_stopped", "witness_control_tree_removed", "witness_observer_stopped"],
)
def test_runtime_removal_requires_witness_cleanup_after_possible_start(field: str) -> None:
    report = _cleanup_ready_report()
    report["witness_could_have_started"] = True
    report[field] = False
    assert not verifier._runtime_removal_allowed(report)


def test_runtime_removal_accepts_complete_witness_cleanup() -> None:
    report = _cleanup_ready_report()
    report["witness_could_have_started"] = True
    assert verifier._runtime_removal_allowed(report)


@pytest.mark.parametrize("state", ["stopped", "unbootstrapped"])
def test_unstarted_runner_is_a_confirmed_clean_state(state: str) -> None:
    class Lifecycle:
        def status(self, **_kwargs):
            return {"state": state}

        def stop(self, **_kwargs):
            pytest.fail("already stopped or unbootstrapped runner should not be mutated")

    assert verifier._stop_managed_runner(Lifecycle())


def test_active_runner_must_stop_and_recheck() -> None:
    class Lifecycle:
        states = iter(("ready", "stopped"))

        def status(self, **_kwargs):
            return {"state": next(self.states)}

        def stop(self, *, profile_id: str):
            assert profile_id == verifier.PROFILE_ID
            self.stopped = True

    lifecycle = Lifecycle()
    assert verifier._stop_managed_runner(lifecycle)
    assert lifecycle.stopped


@pytest.mark.parametrize("machine, expected", [("AMD64", "x86_64"), ("ARM64", "aarch64")])
def test_private_environment_preserves_supported_architecture_without_ambient_values(
    monkeypatch: pytest.MonkeyPatch, machine: str, expected: str
) -> None:
    from bluefire import runner_bootstrap

    monkeypatch.delenv("PROCESSOR_ARCHITECTURE", raising=False)
    monkeypatch.delenv("PROCESSOR_ARCHITEW6432", raising=False)
    monkeypatch.setattr(
        runner_bootstrap.host_platform,
        "machine",
        lambda: os.environ.get("PROCESSOR_ARCHITECTURE", ""),
    )
    with pytest.raises(runner_bootstrap.RunnerBootstrapError):
        runner_bootstrap.current_architecture()
    environment = verifier._windows_architecture_environment(machine)
    assert environment == {"PROCESSOR_ARCHITECTURE": machine}
    for name, value in environment.items():
        monkeypatch.setenv(name, value)
    assert runner_bootstrap.current_architecture() == expected


@pytest.mark.parametrize("machine", ["", "x86", "unsupported", "AMD64\ncredential"])
def test_private_environment_rejects_unreviewed_architecture_values(machine: str) -> None:
    with pytest.raises(RuntimeError, match="architecture"):
        verifier._windows_architecture_environment(machine)


@pytest.mark.parametrize(
    ("permit_pin", "approval_gate"),
    [
        (True, "ready"),
        (False, "ready"),
        (True, "permit_mismatched_pids"),
        (True, "delayed"),
        (True, "construction_snapshots"),
        (True, "ambiguous_workspace"),
        (False, "delayed_cleanup"),
        (False, "cancel_uncertain"),
        (False, "blocked_run"),
        (False, "absent_run_link"),
        (False, "conflicting_run_link"),
        (True, "approval_rejected"),
        (True, "unexpected"),
        (True, "wrong_receipt"),
        (True, "wrong_identity"),
    ],
)
def test_real_driver_api_and_observer_contracts_without_native_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, permit_pin: bool, approval_gate: str
) -> None:
    """Exercise the shipped JS and API guards with fixture PIDs, never native actions."""
    from bluefire.api import create_server, generate_browser_bootstrap_capability
    from bluefire.contracts import ScenarioDefinition

    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is required to exercise the installed cancellation driver")
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    output = tmp_path / "output"
    output.mkdir()
    digest = "e" * 64
    task = (
        sandbox
        / ".bluefire-executions"
        / "approval-fixture"
        / ".bluefire-cancellation-witness-v1"
        / digest
    )
    ready = {
        "schema_version": "bluefire.process-tree-cancellation-ready.v1",
        "task_id": "execute-" + digest,
        "request_hash": "sha256:" + digest,
        "parent_process_id": 101,
        "descendant_process_id": 202,
    }
    job_id = "job-" + "b" * 32
    run_id = "run-20261021T120000Z-" + "c" * 16
    interruption = _passed_driver_report()["execution_interruption"]
    pins: list[dict[str, object]] = []
    sent_frames: list[dict[str, object]] = []

    def pin(record):
        if not permit_pin:
            raise RuntimeError("fixture process pin refused")
        pins.append(record.copy())

    monkeypatch.setattr(verifier, "_pin_windows_processes", pin)

    class FixtureService:
        state = {"delayed": "queued", "unexpected": "running"}.get(
            approval_gate, "awaiting_approval"
        )
        runner_state = "unbootstrapped"
        saved = None
        approval_calls = 0
        cancel_calls = 0
        cleanup_status_reads = 0
        detail_calls = 0

        def catalog(self):
            return {
                "runner_profiles": [
                    {
                        "id": verifier.PROFILE_ID,
                        "mode": "execute",
                        "platforms": ["windows"],
                        "scope": ["sandbox.workspace"],
                        "network_allowlist": [],
                        "approval_required": True,
                        "enabled_actions": [verifier.ACTION_ID, "sandbox.cleanup.v1"],
                        "blocked_actions": [],
                        "budgets": {
                            "max_steps": 1,
                            "max_seconds": 30,
                            "max_artifacts": 4,
                            "max_bytes": 65536,
                        },
                    }
                ]
            }

        def bootstrap_runner(self, *, profile_id, allow_upgrade=False):
            assert profile_id == verifier.PROFILE_ID and allow_upgrade is False
            self.runner_state = "stopped"
            return self.runner_status(profile_id=profile_id)

        def start_runner(self, *, profile_id):
            assert self.runner_state == "stopped"
            self.runner_state = "ready"
            return self.runner_status(profile_id=profile_id)

        def runner_status(self, *, profile_id):
            assert profile_id == verifier.PROFILE_ID
            return {"profile_id": profile_id, "state": self.runner_state}

        def stop_runner(self, *, profile_id):
            assert self.state == "cancelled"
            self.runner_state = "stopped"
            return self.runner_status(profile_id=profile_id)

        def save_scenario_version(self, request):
            assert set(request) == {"scenario"}
            self.saved = request["scenario"]
            ScenarioDefinition.from_mapping(self.saved)
            return {
                "scenario": {
                    "scenario_id": self.saved["id"],
                    "version": 1,
                    "digest": "sha256:" + "a" * 64,
                }
            }

        def preflight(self, request):
            assert request["scenario"] == self.saved
            assert request["mode"] == "execute" and request["autonomy"] == "off"
            assert request["runner_profile_id"] == verifier.PROFILE_ID
            assert request["target_scope"] == {"scope_refs": ["sandbox.workspace"]}
            assert request["collectors"] == ["collector.filesystem.sandbox.v1"]
            return {
                "status": "approval_required",
                "runner_profile": verifier.PROFILE_ID,
                "scope": request["target_scope"],
                "problems": ["Explicit operator approval is required."],
            }

        def submit_run(self, request):
            result = {"job": self.job(job_id), "preflight": self.preflight(request)}
            result["job"]["job_id"] = job_id
            if approval_gate == "delayed":
                self.state = "planning"
            return result

        def job(self, requested_id):
            assert requested_id == job_id
            if approval_gate == "delayed_cleanup" and self.state == "cancelling":
                self.cleanup_status_reads += 1
                if self.cleanup_status_reads >= 3:
                    self.state = "cancelled"
                    shutil.rmtree(task)
            result = {
                "job_id": "job-" + "d" * 32 if approval_gate == "wrong_identity" else job_id,
                "state": self.state,
                "approval_request": {
                    "status": (
                        "pending"
                        if self.state == "awaiting_approval" and approval_gate != "wrong_receipt"
                        else "consumed"
                    )
                },
                "progress": (
                    {"run_id": run_id}
                    if self.approval_calls and approval_gate != "absent_run_link"
                    else {}
                ),
            }
            if approval_gate == "conflicting_run_link":
                result["result_ref"] = "run-20261021T120000Z-" + "f" * 16
            if approval_gate == "delayed" and self.state == "planning":
                self.state = "awaiting_approval"
            return result

        def approve_job(self, requested_id, request):
            assert request == {"approved_by": "installed-windows-cancellation-reviewer"}
            assert self.state == "awaiting_approval"
            if approval_gate == "approval_rejected":
                raise RuntimeError("fixture approval refusal")
            self.approval_calls += 1
            task.mkdir(parents=True)
            _write_private_ready(task, ready)
            if approval_gate == "ambiguous_workspace":
                (sandbox / ".bluefire-executions" / "approval-unexpected").mkdir()
            self.state = "running"
            return {"job": self.job(requested_id)}

        def cancel_job(self, requested_id):
            assert requested_id == job_id
            self.cancel_calls += 1
            if approval_gate in {
                "unexpected",
                "wrong_receipt",
                "wrong_identity",
                "approval_rejected",
            }:
                assert self.approval_calls == 0 and not pins and not task.exists()
                self.state = "cancelled"
                return self.job(requested_id)
            if not permit_pin or approval_gate in {"ambiguous_workspace", "permit_mismatched_pids"}:
                assert self.approval_calls == 1
                assert pins == (
                    [] if not permit_pin or approval_gate == "ambiguous_workspace" else [ready]
                )
                if approval_gate == "permit_mismatched_pids":
                    assert (
                        sent_frames[0]["type"] == "witness_permit"
                        and sent_frames[0]["ready"] != ready
                    )
                else:
                    assert not any(frame["type"] == "witness_permit" for frame in sent_frames)
                if approval_gate == "cancel_uncertain":
                    self.state = "cancelling"
                    raise RuntimeError("fixture cancellation response uncertain")
                if approval_gate == "delayed_cleanup":
                    self.state = "cancelling"
                    return self.job(requested_id)
                shutil.rmtree(task)
                self.state = "completed" if approval_gate == "blocked_run" else "cancelled"
                return self.job(requested_id)
            assert pins == [ready]
            assert sent_frames == [{"type": "witness_permit", "ready": ready}]
            shutil.rmtree(task)
            self.state = "cancelled"
            return self.job(requested_id)

        def retained_observations(self, requested_id):
            assert requested_id == run_id and self.state == "cancelled"
            return {
                "run_id": run_id,
                "observations": {
                    "evidence": {
                        "records": [
                            {"content": {"artifact_type": "execution_interruption", **interruption}}
                        ]
                    }
                },
            }

        def detail(self, requested_id):
            assert requested_id == run_id and self.state in {"completed", "cancelled"}
            self.detail_calls += 1
            assert self.detail_calls == 1
            step = {
                "step_id": "witness",
                "behavior_id": verifier.ACTION_ID,
                "action_id": verifier.ACTION_ID,
            }
            return {
                "run_id": run_id,
                "status": self.state,
                "scenario": {"id": self.saved["id"]},
                "profile": {"id": verifier.PROFILE_ID},
                "plan": {
                    "scenario_id": self.saved["id"],
                    "scenario_digest": "sha256:" + "a" * 64,
                    "mode": "execute",
                    "runner_profile_id": verifier.PROFILE_ID,
                    "steps": [step],
                },
                "steps": [
                    {
                        **step,
                        "status": "blocked",
                        "execution_disposition": "execute",
                        "runner_status": "refused",
                        "error": {
                            "code": "cancellation_witness_blocked",
                            "message": "PRIVATE_SYNTHETIC_SECRET_42",
                        },
                    }
                ],
                "stdout": "PRIVATE_SYNTHETIC_SECRET_42",
            }

    capability = generate_browser_bootstrap_capability()
    service = FixtureService()
    server = create_server(
        service, host="127.0.0.1", port=0, browser_bootstrap_capability=capability
    )
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.start()
    stop = threading.Event()
    observed = []
    observer_errors = []
    witness_messages = queue.Queue()

    def observe():
        try:
            record = verifier._private_ready_record(sandbox, stop)
            observed.append(record)
            witness_messages.put(
                (
                    "permit",
                    {
                        key: record[key]
                        for key in (
                            "schema_version",
                            "task_id",
                            "request_hash",
                            "parent_process_id",
                            "descendant_process_id",
                        )
                    },
                )
            )
        except (RuntimeError, ValueError, OSError) as error:
            observer_errors.append(type(error).__name__)
            witness_messages.put(("denied", None))

    observer = threading.Thread(target=observe)
    observer.start()
    driver = (
        Path(__file__).resolve().parents[1]
        / "frontend/tests/installed/installed-windows-cancellation.mjs"
    )
    node_options = []
    snapshots = output / "construction-snapshots.json"
    if approval_gate == "construction_snapshots":
        preload = tmp_path / "construction-snapshots.mjs"
        preload.write_text(
            "import fs from 'node:fs';\n"
            "import { syncBuiltinESMExports } from 'node:module';\n"
            "import { join } from 'node:path';\n"
            f"const executions = {json.dumps(str(sandbox / '.bluefire-executions'))};\n"
            f"const controls = {json.dumps(str(task.parent))};\n"
            f"const record = {json.dumps(str(snapshots))};\n"
            "const original = fs.readdirSync;\n"
            "const seen = [];\n"
            "fs.readdirSync = function(path, ...args) {\n"
            "  if ([executions, controls].includes(path) && !seen.includes(path)) {\n"
            "    seen.push(path); fs.writeFileSync(record, JSON.stringify(seen)); return [];\n"
            "  }\n"
            "  return original.call(this, path, ...args);\n"
            "};\n"
            "syncBuiltinESMExports();\n",
            encoding="utf-8",
        )
        node_options = ["--import", preload.as_uri()]
    try:
        process = subprocess.Popen(
            [node, *node_options, str(driver), str(server.server_port), str(sandbox), str(output)],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        assert process.stdin is not None
        process.stdin.write(json.dumps({"type": "capability", "capability": capability}) + "\n")
        process.stdin.flush()
        deadline = time.monotonic() + 25
        frame_sent = False
        while process.poll() is None and time.monotonic() < deadline:
            if not frame_sent and (observed or observer_errors):
                kind, payload = witness_messages.get(timeout=1)
                if approval_gate != "ambiguous_workspace":
                    if kind == "permit" and payload is not None:
                        assert pins == [ready]
                        if approval_gate == "permit_mismatched_pids":
                            payload["descendant_process_id"] += 1
                        frame = {"type": "witness_permit", "ready": payload}
                    else:
                        frame = {"type": "witness_denied"}
                    sent_frames.append(frame)
                    process.stdin.write(json.dumps(frame) + "\n")
                    process.stdin.flush()
                    process.stdin.close()
                frame_sent = True
            else:
                time.sleep(0.05)
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
            pytest.fail("installed cancellation driver exceeded its test deadline")
        result = subprocess.CompletedProcess(
            process.args, process.returncode, stdout="", stderr=process.stderr.read()
        )
    finally:
        if "process" in locals() and process.stdin is not None and not process.stdin.closed:
            process.stdin.close()
        if "process" in locals() and process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        stop.set()
        observer.join(timeout=5)
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=5)
    assert not observer.is_alive() and not server_thread.is_alive()
    report = json.loads((output / "driver-report.json").read_text(encoding="utf-8"))
    assert capability not in json.dumps(report)
    assert "PRIVATE_SYNTHETIC_SECRET_42" not in json.dumps(report)
    expected_pass = permit_pin and approval_gate in {"ready", "delayed", "construction_snapshots"}
    assert result.returncode == (0 if expected_pass else 1), result.stderr
    if expected_pass:
        assert not observer_errors and observed[0]["control_path"] == task
        assert verifier._driver_passed(report)
        assert report["request_counts"]["job_status"] == (4 if approval_gate == "delayed" else 3)
        assert service.approval_calls == 1 and service.cancel_calls == 1
        assert "failure_cleanup" not in report
        assert "failure_run_diagnostic" not in report and service.detail_calls == 0
        if approval_gate == "construction_snapshots":
            assert json.loads(snapshots.read_text(encoding="utf-8")) == [
                str(sandbox / ".bluefire-executions"),
                str(task.parent),
            ]
    elif not permit_pin or approval_gate in {"ambiguous_workspace", "permit_mismatched_pids"}:
        if approval_gate == "permit_mismatched_pids":
            assert not observer_errors and observed and pins == [ready]
            assert sent_frames == [
                {
                    "type": "witness_permit",
                    "ready": {**ready, "descendant_process_id": ready["descendant_process_id"] + 1},
                }
            ]
        else:
            expected_observer_error = (
                "ValueError" if approval_gate == "ambiguous_workspace" else "RuntimeError"
            )
            assert observer_errors == [expected_observer_error] and not observed and not pins
        assert report["status"] == "failed_or_incomplete"
        assert report["error"]["stage"] == "independent-witness-handshake"
        assert report["request_counts"]["approval"] == 1
        assert report["request_counts"]["cancel"] == 1
        assert report["request_counts"]["runner_stop"] == 0
        assert report["request_counts"]["job_status"] == (
            4
            if approval_gate == "delayed_cleanup"
            else (2 if approval_gate == "cancel_uncertain" else 3)
        )
        assert report["error"]["witness_check"] == (
            "process_pin_permit"
            if not permit_pin or approval_gate == "permit_mismatched_pids"
            else "workspace"
        )
        assert service.approval_calls == 1 and service.cancel_calls == 1
        if approval_gate == "cancel_uncertain":
            assert report["error"]["cleanup_error_type"] == "AssertionError"
            assert report["failure_cleanup"] == {
                "cancel_attempted": True,
                "approval_request_attempted": True,
            }
            assert service.state == "cancelling" and task.exists()
        else:
            assert report["failure_cleanup"] == {
                "cancel_attempted": True,
                "approval_request_attempted": True,
                "cancel_accepted": True,
                "terminal_state": "completed" if approval_gate == "blocked_run" else "cancelled",
            }
            assert service.state == ("completed" if approval_gate == "blocked_run" else "cancelled")
            assert not task.exists()
            if approval_gate in {"absent_run_link", "conflicting_run_link"}:
                assert service.detail_calls == 0
                assert "failure_run_detail" not in report["request_counts"]
                assert report["failure_run_diagnostic"] == {
                    "status": "unavailable",
                    "reason": (
                        "owned_run_link_absent"
                        if approval_gate == "absent_run_link"
                        else "owned_run_link_invalid"
                    ),
                }
            else:
                assert service.detail_calls == report["request_counts"]["failure_run_detail"] == 1
                assert report["failure_run_diagnostic"] == {
                    "status": "available",
                    "run_status": service.state,
                    "step_status": "blocked",
                    "execution_disposition": "execute",
                    "runner_status": "refused",
                    "error_code": "cancellation_witness_blocked",
                    "transport_failure_reason": "absent",
                }
        assert report["checks"] == _passed_driver_report()["checks"][:3]
        assert not verifier._driver_passed(report)
    elif approval_gate == "approval_rejected":
        assert report["status"] == "failed_or_incomplete"
        assert report["error"]["stage"] == "normal-submit-and-approval"
        assert report["request_counts"]["job_status"] == 2
        assert report["request_counts"]["approval"] == 1
        assert report["request_counts"]["cancel"] == 1
        assert report["failure_cleanup"] == {
            "cancel_attempted": True,
            "approval_request_attempted": True,
            "cancel_accepted": True,
            "terminal_state": "cancelled",
        }
        assert service.approval_calls == 0 and service.cancel_calls == 1
        assert service.state == "cancelled" and not task.exists() and not pins
        assert not verifier._driver_passed(report)
    else:
        assert report["status"] == "failed_or_incomplete"
        assert report["error"]["stage"] == "normal-submit-and-approval"
        assert set(report["error"]) == {"stage", "error_type"}
        assert report["job_id"] == job_id
        assert (
            report["request_counts"]["job_status"]
            == {"unexpected": 1, "wrong_receipt": 2, "wrong_identity": 2}[approval_gate]
        )
        assert report["request_counts"]["approval"] == 0
        assert report["request_counts"]["cancel"] == 1
        assert service.approval_calls == 0 and service.cancel_calls == 1
        assert service.state == "cancelled" and not task.exists() and not pins
        expected_cleanup = {
            "cancel_attempted": True,
            "approval_request_attempted": False,
            "cancel_accepted": True,
        }
        if approval_gate == "wrong_identity":
            expected_cleanup["settlement_error_type"] = "AssertionError"
        else:
            expected_cleanup["terminal_state"] = "cancelled"
        assert report["failure_cleanup"] == expected_cleanup
        assert not verifier._driver_passed(report)
