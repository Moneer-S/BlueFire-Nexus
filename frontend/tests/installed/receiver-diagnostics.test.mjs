import assert from "node:assert/strict";
import { test } from "vitest";
import { receiverPreparationDiagnostic, receiverPrepareHttpDiagnostic, readReceiverCompositionUi, receiverCompositionInteractionDiagnostic, receiverPostDenialDiagnostic } from "./receiver-diagnostics.mjs";
import { handleReceiverRoute } from "./receiver-guards.mjs";
/* global document, localStorage, location, history */

test("composition interaction retains finite button, pending and context facts without private data", () => {
  const previous = location.href;
  const expected = { origin: location.origin, owner: "owned", control: "control", proposal: "proposal" };
  history.replaceState(null, "", "/#/composition?objective=owned&control=control&proposal=proposal");
  const container = document.createElement("div");
  container.innerHTML = '<div class="composition-page"><button disabled>Start fresh attempt within grant</button><div class="callout"><strong>Request confirmation pending</strong><p>private body</p></div></div>';
  document.body.append(container);
  localStorage.setItem("bluefire.composition.pending.v1", JSON.stringify({ kind: "proposal", body: "private request", token: "private token" }));
  try {
    const ui = readReceiverCompositionUi(expected);
    assert.equal(ui.button_enabled, false);
    assert.equal(ui.confirmation_pending, true);
    assert.equal(ui.pending_kind, "proposal");
    assert.equal(ui.center_hit, "out_of_view");
    const result = receiverCompositionInteractionDiagnostic("click", ui,
      { grant: { status: "active", document: { grant_id: "g", expires_at_ms: 90_001 } } },
      { grant_id: "g", context_digest: "c", private: "private context" },
      { candidate_ready: true, proposal: { context_digest: "c", candidate: "private graph" } }, 1);
    assert.equal(result.step, "click");
    assert.equal(result.context_grant_matches, true);
    assert.equal(result.context_digest_matches, true);
    assert.equal(result.grant_time, "over_30_seconds");
    assert.equal(JSON.stringify(result).includes("private"), false);
    assert.deepEqual(readReceiverCompositionUi({ ...expected, owner: "other" }), { route_matches: false });
  } finally {
    container.remove();
    localStorage.removeItem("bluefire.composition.pending.v1");
    history.replaceState(null, "", previous);
  }
});

test("composition diagnostics distinguish response wait and collapse unknown values", () => {
  const result = receiverCompositionInteractionDiagnostic("response", { pending_kind: "/private/path", button_enabled: "true" },
    { grant: { status: "private status", document: { expires_at_ms: 10 } } }, undefined, undefined, 10);
  assert.equal(result.step, "response");
  assert.equal(result.button_enabled, null);
  assert.equal(result.pending_kind, "other");
  assert.equal(result.grant_status, "other");
  assert.equal(result.grant_time, "expired");
  assert.equal(result.context_present, false);
  assert.equal(JSON.stringify(result).includes("private"), false);
});

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
        error: {
          code: "execution_callback_failed",
          exception_type: "ReceiverSessionError",
          message: "private message",
        },
        progress: {
          prepare_started: false,
          execution_started: false,
          receiver_closed: true,
          prepare_failure_stage: "generation_frame",
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
  assert.equal(result.receiver_job_error_type, "ReceiverSessionError");
  assert.equal(result.receiver_prepare_failure_stage, "generation_frame");
  assert.deepEqual(result.preflight_refusal?.problem_labels, ["target_scope_outside_profile"]);
  assert.equal(result.preflight_refusal?.problem_count, 1);
  const serialized = JSON.stringify(result);
  for (const secret of ["job-private-id", "/secret/path", "/private/scope", "private text", "private message"]) {
    assert.equal(serialized.includes(secret), false, secret);
  }
});

test("unknown exception class names are collapsed without changing cleanup facts", () => {
  const result = receiverPreparationDiagnostic({
    status: "active",
    phases: [{
      phase: "baseline",
      status: "failed",
      cleanup: { receiver: "verified_closed", run: "not_started" },
      receiver_job: {
        state: "failed",
        error: {
          code: "execution_callback_failed",
          exception_type: "PrivatePathAndSecretCanary",
          message: "private path and token canary",
        },
        progress: { prepare_started: true, receiver_closed: true },
      },
    }],
  }, "baseline");
  assert.equal(result.receiver_job_error_code, "execution_callback_failed");
  assert.equal(result.receiver_job_error_type, "other");
  assert.equal(result.receiver_prepare_failure_stage, "missing");
  assert.equal(result.receiver_cleanup, "verified_closed");
  const serialized = JSON.stringify(result);
  assert.equal(serialized.includes("PrivatePathAndSecretCanary"), false);
  assert.equal(serialized.includes("private path and token canary"), false);
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
  assert.equal(result.receiver_job_error_type, "other");
  assert.equal(result.receiver_prepare_failure_stage, "missing");
  assert.equal(result.preflight_refusal, null);
  assert.equal(JSON.stringify(result).includes("/private"), false);
});

test("preparation-stage projection accepts only fixed stage codes", () => {
  const base = stage => receiverPreparationDiagnostic({
    phases: [{
      phase: "baseline",
      receiver_job: { progress: { prepare_failure_stage: stage } },
    }],
  }, "baseline");
  assert.equal(base("armed_read").receiver_prepare_failure_stage, "armed_read");
  assert.equal(base("ready_read").receiver_prepare_failure_stage, "ready_read");
  assert.equal(base("worker_prepare_validation").receiver_prepare_failure_stage, "worker_prepare_validation");
  assert.equal(base("worker_enrollment").receiver_prepare_failure_stage, "worker_enrollment");
  assert.equal(base("worker_listener_startup").receiver_prepare_failure_stage, "worker_listener_startup");
  assert.equal(base("worker_ready_frame").receiver_prepare_failure_stage, "worker_ready_frame");
  assert.equal(base("/private/path").receiver_prepare_failure_stage, "other");
  assert.equal(base("private frame contents").receiver_prepare_failure_stage, "other");
});

test("blocked POST diagnostics retain fixed route and budget facts without request data", () => {
  const known = receiverPostDenialDiagnostic(
    "/api/v1/composition/objective-list", "write_not_allowlisted_or_budget_exceeded",
    { key: "composition_list", count: 5, limit: 5 },
  );
  assert.deepEqual(known, {
    route_family: "composition_objective_list",
    denial_category: "budget_exhausted",
    budget_count: 5,
    budget_limit: 5,
  });
  assert.deepEqual(receiverPostDenialDiagnostic("/api/v1/session", "write_not_allowlisted_or_budget_exceeded"), {
    route_family: "session", denial_category: "route_guard_rejected",
  });
  assert.deepEqual(receiverPostDenialDiagnostic("/private/secret", "write_not_allowlisted_or_budget_exceeded"), {
    route_family: "other", denial_category: "unknown_route",
  });
  assert.deepEqual(receiverPostDenialDiagnostic("/api/v1/session", "invalid_json_body"), {
    route_family: "session", denial_category: "invalid_json_body",
  });
  assert.deepEqual(receiverPostDenialDiagnostic("/api/v1/session", "non_loopback", {
    key: "session", count: 1, limit: 1,
  }), { route_family: "session", denial_category: "origin_rejected" });
  const malformed = receiverPostDenialDiagnostic("/api/v1/session", "write_not_allowlisted_or_budget_exceeded", {
    key: "session", count: 1000, limit: 1, private: "C:\\private\\token",
  });
  assert.deepEqual(malformed, { route_family: "session", denial_category: "route_guard_rejected" });
  assert.equal(JSON.stringify([known, malformed]).includes("private"), false);
});

test("blocked POST route families cover the owned write surface with fixed labels", () => {
  const routes = [
    ["/api/v1/session", "session"],
    ["/api/v1/resources/model-providers/provider.installed-receiver-composition.v1", "provider_save"],
    ["/api/v1/resources/model-providers/provider.installed-receiver-composition.v1/activate", "provider_activate"],
    ["/api/v1/ai/authorizations", "model_authorization_create"],
    [`/api/v1/ai/authorizations/ai-authorization-${"a".repeat(32)}/revoke`, "model_authorization_revoke"],
    ["/api/v1/runner/bootstrap", "runner_bootstrap"],
    ["/api/v1/runner/start", "runner_start"],
    ["/api/v1/runner/stop", "runner_stop"],
    ["/api/v1/scenario-versions", "scenario_version_save"],
    ["/api/v1/composition/objective-list", "composition_objective_list"],
    ["/api/v1/composition/context", "composition_context"],
    ["/api/v1/composition/objectives", "composition_objective_create"],
    [`/api/v1/composition/objectives/job-${"b".repeat(32)}/proposal-context`, "composition_proposal_context"],
    [`/api/v1/composition/objectives/job-${"b".repeat(32)}/proposals`, "composition_proposal"],
    [`/api/v1/composition/objectives/job-${"b".repeat(32)}/attempts`, "composition_attempt"],
    [`/api/v1/composition/objectives/job-${"b".repeat(32)}/revoke`, "composition_revoke"],
    ["/api/v1/comparisons", "comparison_create"],
    ["/api/v1/receiver-defense/context", "receiver_context"],
    ["/api/v1/receiver-defense/jobs", "receiver_owner_create"],
    [`/api/v1/receiver-defense/jobs/job-${"c".repeat(32)}/prepare`, "receiver_prepare"],
    [`/api/v1/receiver-defense/jobs/job-${"c".repeat(32)}/review`, "receiver_review"],
    [`/api/v1/jobs/job-${"d".repeat(32)}/approval`, "execution_approval"],
    [`/api/v1/jobs/job-${"d".repeat(32)}/cancel`, "receiver_cancel"],
  ];
  for (const [path, expected] of routes) {
    assert.equal(
      receiverPostDenialDiagnostic(path, "write_not_allowlisted_or_budget_exceeded").route_family,
      expected,
      path,
    );
  }
  assert.equal(
    receiverPostDenialDiagnostic("/api/v1/unowned", "write_not_allowlisted_or_budget_exceeded").route_family,
    "other",
  );
});

test("route denial diagnostics do not alter fail-closed POST behavior", async () => {
  let aborted = false;
  let continued = false;
  const blocked = [];
  const request = {
    url: () => "http://127.0.0.1:4312/api/v1/composition/objective-list?private=secret",
    method: () => "POST",
    postData: () => "{\"private\":\"secret\"}",
    postDataJSON: () => ({ private: "secret" }),
  };
  await handleReceiverRoute({
    request: () => request,
    abort: async () => { aborted = true; },
    continue: async () => { continued = true; },
  }, {
    expectedOrigin: "http://127.0.0.1:4312",
    allowedRead: () => false,
    authorizePost: () => false,
    describeBlockedPost: (url, reason) => receiverPostDenialDiagnostic(url.pathname, reason, {
      key: "composition_list", count: 5, limit: 5,
    }),
    onBlocked: entry => blocked.push(entry),
    onFailure: () => assert.fail("route handling must retain its bounded diagnostic"),
  });
  assert.equal(aborted, true);
  assert.equal(continued, false);
  assert.deepEqual(blocked, [{
    method: "POST", path: "loopback", reason: "write_not_allowlisted_or_budget_exceeded",
    route_family: "composition_objective_list", denial_category: "budget_exhausted",
    budget_count: 5, budget_limit: 5,
  }]);
  assert.equal(JSON.stringify(blocked).includes("secret"), false);
});
