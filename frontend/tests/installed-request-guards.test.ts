import { describe, expect, it } from "vitest";
import {
  classifyRequest,
  consumeRequestBudget,
  receiverContextRequestAllowed,
  receiverContextRequestIsFinal,
  receiverContextResponseMatchesRequest,
  receiverOwnerContextMatches,
  sameJson,
} from "./installed/receiver-guards.mjs";

const origin = "http://127.0.0.1:4317";
const limits = { stop: 1 };
const selection = { kind: "saved_scenario", scenario_id: "scenario.receiver-defense.copy.12345678-1234-4123-8123-123456789abc.v1", version: 1, digest: `sha256:${"a".repeat(64)}` };
const finalRunIntent = {
  mode: "execute",
  autonomy: "off",
  ai_provider_id: null,
  runner_profile_id: "sandbox-endpoint-deep-lab.v1",
  target_scope: { scope_refs: ["sandbox.workspace", "network.loopback"] },
  collectors: ["collector.filesystem.sandbox.v1"],
};
const contextExpected = {
  selection,
  workflow: "retained_redaction",
  sourceControl: null,
  profileIdsByMode: { simulate: ["sandbox-simulate.v1"], execute: ["sandbox-execute.v1", "sandbox-endpoint-deep-lab.v1"] },
  scopeRefs: ["sandbox.workspace", "network.loopback"],
  collectors: ["collector.filesystem.sandbox.v1"],
  finalRunIntent,
};

describe("installed receiver request guards", () => {
  it("compares canonical saved objects without changing array or value semantics", () => {
    const requested = { id: "owned-copy", steps: [{ id: "create", parameters: { count: 8, redact: false } }, { id: "send" }] };
    const persisted = { steps: [{ parameters: { redact: false, count: 8 }, id: "create" }, { id: "send" }], id: "owned-copy" };
    expect(JSON.stringify(requested)).not.toBe(JSON.stringify(persisted));
    expect(sameJson(requested, persisted)).toBe(true);
    expect(sameJson(requested, { ...persisted, steps: [...persisted.steps].reverse() })).toBe(false);
    expect(sameJson(requested, { ...persisted, extra: null })).toBe(false);
    expect(sameJson({ count: 8 }, { count: "8" })).toBe(false);
    expect(sameJson({ redact: false }, { redact: true })).toBe(false);
    expect(sameJson({ selected: null }, {})).toBe(false);
  });

  it("authorizes an allowlisted POST independently of read allowlists", () => {
    const counts = { stop: 0 };
    const decision = classifyRequest({
      origin,
      expectedOrigin: origin,
      method: "POST",
      url: new URL(`${origin}/api/v1/runner/stop`),
      body: { profile_id: "sandbox-endpoint-deep-lab.v1" },
      allowedRead: () => false,
      authorizePost: () => consumeRequestBudget(counts, limits, "stop"),
    });

    expect(decision).toEqual({ allowed: true });
    expect(counts.stop).toBe(1);
  });

  it("rejects denied origins, malformed bodies, unlisted methods, and exhausted budgets", () => {
    const url = new URL(`${origin}/api/v1/runner/stop`);
    const base = { expectedOrigin: origin, url, body: {}, allowedRead: () => false, authorizePost: () => true };

    expect(classifyRequest({ ...base, origin: "https://example.invalid", method: "GET" })).toEqual({ allowed: false, reason: "non_loopback" });
    expect(classifyRequest({ ...base, origin, method: "POST", bodyError: true })).toEqual({ allowed: false, reason: "invalid_json_body" });
    expect(classifyRequest({ ...base, origin, method: "PUT" })).toEqual({ allowed: false, reason: "method_not_allowlisted" });

    const counts = { stop: 1 };
    expect(consumeRequestBudget(counts, limits, "stop")).toBe(false);
    expect(counts.stop).toBe(1);
  });

  it("caps the five phase approvals and the two owner creations independently", () => {
    const limits = { owner: 2, prepare: 5, review: 5, approval: 5 };
    const counts = { owner: 0, prepare: 0, review: 0, approval: 0 };
    for (let index = 0; index < 5; index += 1) {
      expect(consumeRequestBudget(counts, limits, "prepare")).toBe(true);
      expect(consumeRequestBudget(counts, limits, "review")).toBe(true);
      expect(consumeRequestBudget(counts, limits, "approval")).toBe(true);
    }
    expect(consumeRequestBudget(counts, limits, "prepare")).toBe(false);
    expect(consumeRequestBudget(counts, limits, "review")).toBe(false);
    expect(consumeRequestBudget(counts, limits, "approval")).toBe(false);
    expect(consumeRequestBudget(counts, limits, "owner")).toBe(true);
    expect(consumeRequestBudget(counts, limits, "owner")).toBe(true);
    expect(consumeRequestBudget(counts, limits, "owner")).toBe(false);
    expect(counts).toEqual({ owner: 2, prepare: 5, review: 5, approval: 5 });
  });

  it("accepts only finite context-selection shapes and identifies the exact final request", () => {
    const intermediateRequests = [
      { selection, workflow: "retained_redaction", run_intent: {
        mode: "simulate", autonomy: "off", ai_provider_id: null, runner_profile_id: "sandbox-simulate.v1",
        target_scope: { scope_refs: ["sandbox.workspace"] },
      } },
      { selection, workflow: "retained_redaction", run_intent: {
        mode: "execute", autonomy: "off", ai_provider_id: null, runner_profile_id: "sandbox-execute.v1",
        target_scope: { scope_refs: ["sandbox.workspace"] }, collectors: ["collector.filesystem.sandbox.v1"],
      } },
      { selection, workflow: "retained_redaction", run_intent: {
        ...finalRunIntent, target_scope: { scope_refs: ["sandbox.workspace"] },
      } },
    ];
    for (const request of intermediateRequests) {
      expect(receiverContextRequestAllowed(request, contextExpected)).toBe(true);
      expect(receiverContextRequestIsFinal(request, contextExpected)).toBe(false);
    }

    const finalRequest = { selection, workflow: "retained_redaction", run_intent: finalRunIntent };
    expect(receiverContextRequestAllowed(finalRequest, contextExpected)).toBe(true);
    expect(receiverContextRequestIsFinal(finalRequest, contextExpected)).toBe(true);
    for (const invalid of [
      { ...finalRequest, extra: true },
      { ...finalRequest, run_intent: { ...finalRunIntent, action_implementations: {} } },
      { ...finalRequest, run_intent: { ...finalRunIntent, runner_profile_id: "other" } },
      { ...finalRequest, run_intent: { ...finalRunIntent, target_scope: { scope_refs: ["sandbox.workspace", "sandbox.workspace"] } } },
      { ...finalRequest, run_intent: { ...finalRunIntent, collectors: ["collector.filesystem.sandbox.v1", "other"] } },
      { ...finalRequest, workflow: "comparison" },
      { ...finalRequest, selection: { ...selection, version: 2 } },
    ]) expect(receiverContextRequestAllowed(invalid, contextExpected)).toBe(false);
  });

  it("binds the authorized context response and owner request to the same final payload", () => {
    const finalRequest = { selection, workflow: "retained_redaction", run_intent: finalRunIntent };
    const response = {
      schema_version: "bluefire.receiver-defense-context.v2",
      context_digest: `sha256:${"b".repeat(64)}`,
      selection,
      workflow: "retained_redaction",
      run_intent: finalRunIntent,
    };
    expect(receiverContextResponseMatchesRequest(finalRequest, finalRequest, response)).toBe(true);
    expect(receiverContextResponseMatchesRequest(intermediateContextRequest(), finalRequest, response)).toBe(false);
    expect(receiverContextResponseMatchesRequest(finalRequest, undefined, response)).toBe(false);

    const owner = { ...finalRequest, submission_id: "submission", context_digest: response.context_digest };
    expect(receiverOwnerContextMatches(owner, finalRequest, response)).toBe(true);
    expect(receiverOwnerContextMatches({ ...owner, context_digest: `sha256:${"c".repeat(64)}` }, finalRequest, response)).toBe(false);
    expect(receiverOwnerContextMatches({ ...owner, run_intent: { ...finalRunIntent, target_scope: { scope_refs: ["sandbox.workspace"] } } }, finalRequest, response)).toBe(false);
  });

  it("requires linked context and owner creation to echo the exact retained source control", () => {
    const sourceControl = { job_id: `job-${"1".repeat(32)}`, control_digest: `sha256:${"d".repeat(64)}` };
    const linkedExpected = {
      ...contextExpected,
      sourceControl,
      finalRunIntent,
    };
    const linkedRequest = { selection, workflow: "retained_redaction", run_intent: finalRunIntent, source_control: sourceControl };
    const originalRequest = finalRequestFor(selection);
    expect(receiverContextRequestAllowed(linkedRequest, linkedExpected)).toBe(true);
    expect(receiverContextRequestIsFinal(linkedRequest, linkedExpected)).toBe(true);
    expect(receiverContextRequestAllowed({ ...linkedRequest, source_control: { ...sourceControl, job_id: `job-${"2".repeat(32)}` } }, linkedExpected)).toBe(false);
    expect(receiverContextRequestAllowed({ ...linkedRequest, source_control: { ...sourceControl, control_digest: `sha256:${"e".repeat(64)}` } }, linkedExpected)).toBe(false);
    expect(receiverContextRequestAllowed({ selection, workflow: "retained_redaction", run_intent: finalRunIntent }, linkedExpected)).toBe(false);

    const linkedResponse = {
      schema_version: "bluefire.receiver-defense-context.v2",
      context_digest: `sha256:${"f".repeat(64)}`,
      selection,
      workflow: "retained_redaction",
      run_intent: finalRunIntent,
      source_control: sourceControl,
    };
    expect(receiverContextResponseMatchesRequest(linkedRequest, linkedRequest, linkedResponse)).toBe(true);
    expect(receiverContextResponseMatchesRequest(linkedRequest, linkedRequest, {
      ...linkedResponse,
      source_control: { ...sourceControl, control_digest: `sha256:${"e".repeat(64)}` },
    })).toBe(false);
    expect(receiverContextResponseMatchesRequest(linkedRequest, linkedRequest, {
      ...linkedResponse,
      source_control: undefined,
    })).toBe(false);
    expect(receiverContextResponseMatchesRequest(linkedRequest, originalRequest, {
      ...linkedResponse,
      source_control: undefined,
    })).toBe(false);

    const linkedOwner = { ...linkedRequest, submission_id: "submission", context_digest: linkedResponse.context_digest };
    expect(receiverOwnerContextMatches(linkedOwner, linkedRequest, linkedResponse)).toBe(true);
    expect(receiverOwnerContextMatches({ ...linkedOwner, source_control: { ...sourceControl, job_id: `job-${"2".repeat(32)}` } }, linkedRequest, linkedResponse)).toBe(false);
    expect(receiverOwnerContextMatches({ ...linkedOwner, source_control: undefined }, linkedRequest, linkedResponse)).toBe(false);
    expect(receiverOwnerContextMatches({ ...linkedOwner, context_digest: `sha256:${"a".repeat(64)}` }, linkedRequest, linkedResponse)).toBe(false);
    const originalResponse = { ...linkedResponse, source_control: undefined };
    expect(receiverOwnerContextMatches(linkedOwner, linkedRequest, originalResponse)).toBe(false);
  });
});

function finalRequestFor(value: typeof selection) {
  return { selection: value, workflow: "retained_redaction", run_intent: finalRunIntent };
}

function intermediateContextRequest() {
  return { selection, workflow: "retained_redaction", run_intent: {
    mode: "simulate", autonomy: "off", ai_provider_id: null, runner_profile_id: "sandbox-simulate.v1",
    target_scope: { scope_refs: ["sandbox.workspace"] },
  } };
}
