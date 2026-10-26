import assert from "node:assert/strict";
import test from "node:test";
import { receiverPreparationDiagnostic, receiverPrepareHttpDiagnostic } from "./receiver-diagnostics.mjs";

test("projects bounded owner and preparation status plus shared preflight labels", () => {
  const owner = {
    status: "active",
    next_action: { kind: "wait", native_path: "/secret/path" },
    phases: [{
      phase: "baseline",
      status: "failed",
      problem: { code: "receiver_session_unavailable", message: "private text" },
      cleanup: { receiver: "verified_closed", run: "not_started" },
      receiver_job: {
        job_id: "job-private-id",
        state: "failed",
        error: { code: "execution_callback_failed", message: "private message" },
        progress: {
          prepare_started: false,
          execution_started: false,
          receiver_closed: true,
          preparation: null,
          preflight_refusal: {
            status: "refused",
            ready: false,
            approval_required: true,
            plan: { mode: "execute", runner_profile_id: "sandbox-endpoint-deep-lab.v1" },
            actions: ["sandbox.fixture.create.v1"],
            problems: ["target scope is outside the selected profile: /private/scope"],
          },
        },
      },
    }],
  };

  const result = receiverPreparationDiagnostic(owner, "baseline");
  assert.equal(result.owner_status, "active");
  assert.equal(result.owner_next_action, "wait");
  assert.equal(result.phase_status, "failed");
  assert.equal(result.phase_problem_code, "receiver_session_unavailable");
  assert.equal(result.receiver_cleanup, "verified_closed");
  assert.equal(result.receiver_job_state, "failed");
  assert.equal(result.receiver_job_error_code, "execution_callback_failed");
  assert.deepEqual(result.preflight_refusal?.problem_labels, ["target_scope_outside_profile"]);
  assert.equal(result.preflight_refusal?.problem_count, 1);
  const serialized = JSON.stringify(result);
  for (const secret of ["job-private-id", "/secret/path", "/private/scope", "private text", "private message"]) {
    assert.equal(serialized.includes(secret), false, secret);
  }
});

test("captures only numeric prepare HTTP status and known API codes", () => {
  assert.deepEqual(receiverPrepareHttpDiagnostic(409, {
    error: { code: "receiver_defense_refused", message: "private body" },
  }), {
    schema_version: "bluefire.installed-receiver-prepare-http-diagnostic.v1",
    status: 409,
    error_code: "receiver_defense_refused",
  });
  assert.equal(receiverPrepareHttpDiagnostic(401, {
    error: { code: "browser_session_required", message: "private body" },
  }).error_code, "browser_session_required");
  const unknown = receiverPrepareHttpDiagnostic(700, {
    error: { code: "browser_session_unavailable", message: "private body" },
  });
  assert.equal(unknown.status, null);
  assert.equal(unknown.error_code, "unknown");
  assert.equal(JSON.stringify(unknown).includes("secret"), false);
});

test("malformed or missing owner state stays unknown without retaining extra fields", () => {
  const result = receiverPreparationDiagnostic({
    status: "private status",
    phases: "malformed",
    context: { path: "/private" },
  }, "baseline");
  assert.equal(result.owner_status, "other");
  assert.equal(result.phase_status, "missing");
  assert.equal(result.receiver_job_state, "missing");
  assert.equal(result.preflight_refusal, null);
  assert.equal(JSON.stringify(result).includes("/private"), false);
});
