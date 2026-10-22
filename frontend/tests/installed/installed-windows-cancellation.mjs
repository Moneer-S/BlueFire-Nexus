/* global process, Buffer, fetch, crypto, setTimeout, AbortSignal */
import assert from "node:assert/strict";
import { readdirSync, lstatSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const [portText, sandboxText, output] = process.argv.slice(2);
assert.match(portText ?? "", /^\d{1,5}$/);
const port = Number(portText);
assert.ok(port > 0 && port <= 65535);
let input = "";
for await (const chunk of process.stdin) {
  input += chunk;
  assert.ok(Buffer.byteLength(input, "utf8") <= 256);
}
let { capability } = JSON.parse(input);
input = "";
assert.match(capability ?? "", /^[A-Za-z0-9_-]{64}$/);

const PROFILE = "gate11-windows-cancellation-witness.v1";
const ACTION = "sandbox.execution.process-tree-cancellation-witness.v1";
const MAX_RESPONSE_BYTES = 1_048_576;
const origin = `http://127.0.0.1:${port}`;
const sandbox = sandboxText;
const counts = {
  session: 0, catalog: 0, runner_status: 0, runner_bootstrap: 0, runner_start: 0,
  scenario_save: 0, preflight: 0, run_submit: 0, approval: 0, cancel: 0,
  retained_observations: 0, runner_stop: 0, job_status: 0,
};
const report = {
  schema_version: "bluefire.installed-windows-cancellation.v1",
  status: "failed_or_incomplete",
  profile_id: PROFILE,
  checks: [],
  request_counts: counts,
};
let stage = "session";
let session = "";
let jobId = "";
let runId = "";
let ready = null;
let approvalStatusBefore = "";
let approvalStatusAfter = "";

async function readBoundedResponse(response) {
  const reader = response.body?.getReader();
  if (!reader) return "";
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_RESPONSE_BYTES) {
        await reader.cancel().catch(() => {});
        throw new Error("service response exceeded fixture bound");
      }
      chunks.push(Buffer.from(value));
    }
  } finally {
    reader.releaseLock();
  }
  return Buffer.concat(chunks, total).toString("utf8");
}

async function call(method, path, body) {
  const permitted = new Set([
    "POST /api/v1/session",
    "GET /api/v1/catalog",
    `GET /api/v1/runner?profile_id=${PROFILE}`,
    "POST /api/v1/runner/bootstrap",
    "POST /api/v1/runner/start",
    "POST /api/v1/runner/stop",
    "POST /api/v1/scenario-versions",
    "POST /api/v1/runs/preflight",
    "POST /api/v1/runs",
  ]);
  if (jobId) {
    permitted.add(`GET /api/v1/jobs/${jobId}`);
    permitted.add(`POST /api/v1/jobs/${jobId}/approval`);
    permitted.add(`POST /api/v1/jobs/${jobId}/cancel`);
  }
  if (runId) permitted.add(`GET /api/v1/runs/${runId}/retained-observations`);
  const key = `${method} ${path}`;
  assert.ok(permitted.has(key), `unexpected local service route: ${method} ${path}`);
  const counter = {
    "POST /api/v1/session": "session",
    "GET /api/v1/catalog": "catalog",
    [`GET /api/v1/runner?profile_id=${PROFILE}`]: "runner_status",
    "POST /api/v1/runner/bootstrap": "runner_bootstrap",
    "POST /api/v1/runner/start": "runner_start",
    "POST /api/v1/runner/stop": "runner_stop",
    "POST /api/v1/scenario-versions": "scenario_save",
    "POST /api/v1/runs/preflight": "preflight",
    "POST /api/v1/runs": "run_submit",
    [`GET /api/v1/jobs/${jobId}`]: "job_status",
    [`POST /api/v1/jobs/${jobId}/approval`]: "approval",
    [`POST /api/v1/jobs/${jobId}/cancel`]: "cancel",
    [`GET /api/v1/runs/${runId}/retained-observations`]: "retained_observations",
  }[key];
  if (counter) counts[counter] += 1;
  const headers = { Accept: "application/json", Origin: origin };
  if (method === "POST" && path !== "/api/v1/session") headers["Content-Type"] = "application/json";
  if (path !== "/api/v1/session") headers["X-BlueFire-Session"] = session;
  else headers["X-BlueFire-Browser-Bootstrap"] = capability;
  const response = await fetch(`${origin}${path}`, {
    method, headers, ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    redirect: "error",
    signal: AbortSignal.timeout(path.endsWith("/runner/bootstrap") ? 120_000
      : path.endsWith("/runner/start") || path.endsWith("/runner/stop") ? 45_000 : 20_000),
  });
  const text = await readBoundedResponse(response);
  let value = null;
  if (text) value = JSON.parse(text);
  assert.ok(response.ok, `local service refused ${method} ${path} with ${response.status}`);
  return { status: response.status, value };
}

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
let witnessCheck = "workspace";

async function witnessReady() {
  witnessCheck = "workspace";
  const executions = join(sandbox, ".bluefire-executions");
  const ownerNames = readdirSync(executions);
  if (ownerNames.length === 0) return null;
  assert.equal(ownerNames.length, 1, "one fresh approval workspace expected");
  const owner = join(executions, ownerNames[0]);
  assert.ok(lstatSync(owner).isDirectory() && !lstatSync(owner).isSymbolicLink());
  witnessCheck = "task";
  const controls = join(owner, ".bluefire-cancellation-witness-v1");
  const names = readdirSync(controls);
  if (names.length === 0) return null;
  assert.equal(names.length, 1, "one fresh cancellation task expected");
  const task = join(controls, names[0]);
  const stat = lstatSync(task);
  assert.ok(stat.isDirectory() && !stat.isSymbolicLink());
  witnessCheck = "ready_record";
  const readyPath = join(task, "ready.json");
  const readyStat = lstatSync(readyPath);
  assert.ok(readyStat.isFile() && !readyStat.isSymbolicLink() && readyStat.size <= 4096);
  const value = JSON.parse(readFileSync(readyPath, "utf8"));
  assert.deepEqual(Object.keys(value).sort(), [
    "descendant_process_id", "parent_process_id", "request_hash", "schema_version", "task_id",
  ]);
  assert.equal(value.schema_version, "bluefire.process-tree-cancellation-ready.v1");
  assert.match(value.request_hash, /^sha256:[0-9a-f]{64}$/);
  assert.equal(value.task_id, `execute-${value.request_hash.slice(7)}`);
  for (const field of ["parent_process_id", "descendant_process_id"]) {
    assert.ok(Number.isInteger(value[field]) && value[field] > 0 && value[field] <= 0xffffffff);
  }
  assert.notEqual(value.parent_process_id, value.descendant_process_id);
  return { value, task };
}

async function waitForPermit(expectedHash) {
  const path = join(output, "witness-permit.json");
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    try {
      const stat = lstatSync(path);
      assert.ok(stat.isFile() && !stat.isSymbolicLink() && stat.size <= 4096);
      const permit = JSON.parse(readFileSync(path, "utf8"));
      assert.deepEqual(permit, { witness_request_hash: expectedHash });
      return;
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
    await sleep(50);
  }
  throw new Error("independent witness process pin was not confirmed");
}

async function main() {
  stage = "bootstrap-session";
  const sessionResponse = await call("POST", "/api/v1/session");
  assert.equal(sessionResponse.status, 200);
  assert.deepEqual(Object.keys(sessionResponse.value).sort(), ["session"]);
  session = sessionResponse.value.session;
  assert.match(session, /^[A-Za-z0-9_-]{64}$/);
  capability = "";
  report.checks.push("ephemeral_authenticated_session_created");

  stage = "profile-authority";
  const catalog = (await call("GET", "/api/v1/catalog")).value;
  const profile = catalog.runner_profiles?.find(row => row.id === PROFILE);
  assert.ok(profile, "shipped Gate 11 Windows witness profile is installed");
  assert.equal(profile.mode, "execute");
  assert.deepEqual(profile.platforms, ["windows"]);
  assert.deepEqual(profile.scope, ["sandbox.workspace"]);
  assert.deepEqual(profile.network_allowlist, []);
  assert.equal(profile.approval_required, true);
  assert.deepEqual(profile.enabled_actions, [ACTION, "sandbox.cleanup.v1"]);
  assert.deepEqual(profile.blocked_actions, []);
  assert.deepEqual(profile.budgets, { max_steps: 1, max_seconds: 30, max_artifacts: 4, max_bytes: 65536 });
  report.checks.push("shipped_gate11_profile_and_action_verified");

  stage = "runner-bootstrap-start";
  await call("POST", "/api/v1/runner/bootstrap", { profile_id: PROFILE });
  await call("POST", "/api/v1/runner/start", { profile_id: PROFILE });
  const runnerStatus = (await call("GET", `/api/v1/runner?profile_id=${PROFILE}`)).value;
  assert.equal(runnerStatus.profile_id, PROFILE);
  assert.equal(runnerStatus.state, "ready");
  report.checks.push("fresh_installed_runner_bootstrapped_and_started_through_service");

  stage = "fresh-scenario-save";
  const scenarioId = `scenario.installed-windows-cancel.${crypto.randomUUID()}.v1`;
  const scenario = {
    schema_version: "bluefire.scenario.v1",
    id: scenarioId,
    title: "Installed Windows cancellation witness",
    purpose: "Verify bounded cancellation of the fixed local process-tree witness.",
    start: "witness",
    steps: [{ id: "witness", behavior_id: ACTION }],
    edges: [],
    provenance: { source: "BlueFire installed cancellation verifier", reference: scenarioId, license: "MIT", derived: false, notes: "One fixed registered witness action; no external content." },
    limitations: ["This generated scenario proves only the packaged Windows cancellation witness profile."],
  };
  const saved = (await call("POST", "/api/v1/scenario-versions", { scenario })).value.scenario;
  assert.equal(saved.scenario_id, scenarioId);
  assert.equal(saved.version, 1);
  assert.match(saved.digest, /^sha256:[0-9a-f]{64}$/);

  stage = "normal-execute-preflight";
  const payload = {
    scenario: { ...scenario, layout: undefined },
    layout: { schema_version: "bluefire.layout.v1", nodes: [] },
    mode: "execute",
    autonomy: "off",
    ai_provider_id: null,
    runner_profile_id: PROFILE,
    target_scope: { scope_refs: ["sandbox.workspace"] },
    collectors: ["collector.filesystem.sandbox.v1"],
  };
  const preflight = (await call("POST", "/api/v1/runs/preflight", payload)).value;
  assert.equal(preflight.status, "approval_required");
  assert.equal(preflight.runner_profile, PROFILE);
  assert.deepEqual(preflight.scope, { scope_refs: ["sandbox.workspace"] });
  assert.deepEqual(preflight.problems, ["Explicit operator approval is required."]);

  stage = "normal-submit-and-approval";
  const submission = (await call("POST", "/api/v1/runs", payload)).value;
  const submittedJobId = submission.job.job_id;
  assert.match(submittedJobId, /^job-[0-9a-f]{32}$/);
  jobId = submittedJobId;
  report.job_id = jobId;
  assert.equal(submission.preflight.status, "approval_required");
  assert.ok(new Set(["queued", "planning", "awaiting_approval"]).has(submission.job.state));
  const before = await waitForJobState(new Set(["awaiting_approval"]), new Set(["queued", "planning"]));
  approvalStatusBefore = before.approval_request?.status;
  assert.equal(approvalStatusBefore, "pending");
  await call("POST", `/api/v1/jobs/${jobId}/approval`, { approved_by: "installed-windows-cancellation-reviewer" });
  const approved = await waitForJobState(new Set(["running", "completed", "failed", "cancelled"]));
  assert.equal(approved.state, "running", "witness Execute must still be running before cancellation");

  stage = "independent-witness-handshake";
  const deadline = Date.now() + 45_000;
  while (!ready && Date.now() < deadline) {
    try { ready = await witnessReady(); }
    catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
    if (!ready) await sleep(50);
  }
  assert.ok(ready, "fresh witness ready record appeared in the isolated approval workspace");
  const { task_id, request_hash, parent_process_id, descendant_process_id } = ready.value;
  writeFileSync(join(output, "witness-observed.json"), `${JSON.stringify({
    task_id, request_hash, parent_process_id, descendant_process_id,
  })}\n`, { flag: "wx" });
  witnessCheck = "process_pin_permit";
  await waitForPermit(ready.value.request_hash);
  report.checks.push("exact_execute_preflight_and_fresh_approval_consumed");
  report.checks.push("cancel_requested_only_after_fresh_witness_processes_were_pinned");

  stage = "cancel-and-retained-proof";
  const cancel = await call("POST", `/api/v1/jobs/${jobId}/cancel`, {});
  assert.equal(cancel.status, 202);
  const cancelled = await waitForJobState(new Set(["cancelled", "completed", "failed", "interrupted"]));
  assert.equal(cancelled.state, "cancelled");
  runId = cancelled.progress?.run_id ?? cancelled.result_ref;
  assert.match(runId ?? "", /^run-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}$/);
  approvalStatusAfter = cancelled.approval_request?.status;
  assert.ok(["consumed", "claimed"].includes(approvalStatusAfter));
  const retained = (await call("GET", `/api/v1/runs/${runId}/retained-observations`)).value;
  assert.equal(retained.run_id, runId);
  const evidence = retained.observations?.evidence?.records;
  assert.ok(Array.isArray(evidence));
  const interruption = evidence.map(row => row.content).find(content => content?.artifact_type === "execution_interruption");
  assert.ok(interruption, "retained interruption evidence exists");
  const expectedInterruption = {
    cooperative_requested: true,
    cooperative_acknowledged: true,
    forced_tree_termination: true,
    control_cleanup_verified: true,
    process_tree_stopped: true,
  };
  for (const [key, value] of Object.entries(expectedInterruption)) assert.equal(interruption[key], value);
  const taskPath = ready.task;
  let controlRemoved = false;
  try { lstatSync(taskPath); } catch (error) { if (error?.code === "ENOENT") controlRemoved = true; else throw error; }
  assert.ok(controlRemoved, "witness control directory was removed after cancellation");
  report.checks.push("retained_interruption_confirmed_cancellation_and_cleanup");
  report.checks.push("both_witness_process_handles_signaled_and_control_tree_removed");
  report.approval_status_before = approvalStatusBefore;
  report.approval_status_after = approvalStatusAfter;
  report.job_state_after_cancel = cancelled.state;
  report.witness_request_hash = ready.value.request_hash;
  report.execution_interruption = expectedInterruption;

  stage = "runner-stop";
  await call("POST", "/api/v1/runner/stop", { profile_id: PROFILE });
  const stopped = (await call("GET", `/api/v1/runner?profile_id=${PROFILE}`)).value;
  assert.equal(stopped.profile_id, PROFILE);
  assert.ok(["stopped", "unbootstrapped"].includes(stopped.state));
  report.runner_stopped = true;
  report.checks.push("managed_runner_stopped_through_service");
  report.scenario_id = scenarioId;
  report.scenario_version = saved.version;
  report.scenario_digest = saved.digest;
  report.job_id = jobId;
  report.run_id = runId;
  report.preflight_status = preflight.status;
  report.request_counts = counts;
  report.status = "passed";
}

async function waitForJobState(terminal, transient = null) {
  const deadline = Date.now() + 45_000;
  while (Date.now() < deadline && counts.job_status < 100) {
    const job = (await call("GET", `/api/v1/jobs/${jobId}`)).value;
    assert.equal(job.job_id, jobId);
    if (terminal.has(job.state)) return job;
    assert.ok(transient === null || transient.has(job.state), "job left its expected approval planning states");
    await sleep(1000);
  }
  throw new Error("job state did not settle before its bounded deadline");
}

try {
  await main();
} catch (error) {
  report.error = { stage, error_type: error instanceof Error ? error.name : "unknown" };
  if (stage === "independent-witness-handshake") report.error.witness_check = witnessCheck;
  if (jobId && counts.cancel === 0) {
    report.failure_cleanup = {
      cancel_attempted: true,
      approval_request_attempted: counts.approval > 0,
    };
    try {
      const cleanup = await call("POST", `/api/v1/jobs/${jobId}/cancel`, {});
      report.failure_cleanup.cancel_accepted = cleanup.status === 202;
      if (cleanup.status === 202) {
        try {
          const settled = await waitForJobState(
            new Set(["cancelled", "completed", "failed", "interrupted"]),
          );
          report.failure_cleanup.terminal_state = settled.state;
        } catch (settlementError) {
          report.failure_cleanup.settlement_error_type = (
            settlementError instanceof Error ? settlementError.name : "unknown"
          );
        }
      }
    } catch (cleanupError) {
      report.error.cleanup_error_type = cleanupError instanceof Error ? cleanupError.name : "unknown";
    }
  }
} finally {
  capability = "";
  session = "";
  writeFileSync(join(output, "driver-report.json"), `${JSON.stringify(report, null, 2)}\n`, { flag: "wx" });
}
process.exitCode = report.status === "passed" ? 0 : 1;
