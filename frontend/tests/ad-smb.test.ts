import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { adConfirmed, adPhaseCurrent, adSmbApi, checkedAdEnvironments, checkedAdList, checkedAdReview, checkedAdWorkflow, clearAdPending, readAdPending, storeAdPending } from "../src/lib/ad-smb";
import { request } from "../src/lib/api";
import { adChild, adOwner, adPendingFixture, adSids, auditWindowStartForFixture, rawAdAcknowledgement, rawAdEnvironments, rawAdNormalizedObservation, rawAdReview, rawAdWorkflow } from "./ad-smb-fixture";

vi.mock("../src/lib/api", () => ({ DEMO_MODE: false, request: vi.fn() }));
beforeEach(() => localStorage.clear());
afterEach(() => vi.restoreAllMocks());
it("minimizes saved evidence without retaining handles, descriptor bytes or protected task data", () => {
  const value = checkedAdWorkflow(rawAdWorkflow({ phases: ["inspect", "baseline", "harden", "retest", "audit"], allowed: ["rollback"] }), adOwner);
  expect(value.operations).toHaveLength(5);
  expect(value.operations[4]!.executions[0]!.audit).toEqual({ events: 3, truncated: true, digest: expect.any(String) });
  expect(JSON.stringify(value)).not.toMatch(/credential_handle|credential-fff|PRIVATE_DESCRIPTOR_BYTES|binary_b64|transport_identity/);
  expect(value.operations[3]!.expectation).toBe("matched");
});
function auditWorkflowWithNormalized(count = 3) {
  const raw = rawAdWorkflow({ phases: ["audit"] });
  const observation = raw.workflow.progress.operations[0]!.executions[0]!.observation;
  if (!("events" in observation)) throw new Error("Expected audit fixture");
  const payload = observation as unknown as Record<string, any>;
  payload.normalized_observation = rawAdNormalizedObservation(count, auditWindowStartForFixture(raw.workflow.request.environment.scope.created_at));
  payload.events = count;
  payload.truncated = false;
  return raw;
}
it("accepts only bounded normalized event projection and retains legacy count semantics", () => {
  const workflow = checkedAdWorkflow(auditWorkflowWithNormalized(), adOwner);
  const audit = workflow.operations[0]!.executions[0]!.audit!;
  expect(audit).toMatchObject({ events: 3, truncated: false, normalized: { inputEvents: 3, duplicateEvents: 0, events: expect.any(Array) } });
  expect(audit.normalized!.events[1]).toMatchObject({ eventId: 5145, binding: "matched", shareCheck: "denied", relativeTarget: "records.jsonl", serverLogon: "ambiguous" });
  expect(audit.normalized!.events[2]).toMatchObject({ eventId: 5145, binding: "incomplete", logonId: "0xdef" });
  expect(audit.normalized!.events[2]).not.toHaveProperty("principalSid");
  expect(JSON.stringify(workflow)).not.toMatch(/<Event|EventData|TargetUserName|probe-user|raw_xml/);
});
it("keeps capture truncation explicit and accounts for omitted duplicate records", () => {
  const raw = auditWorkflowWithNormalized();
  const observation = raw.workflow.progress.operations[0]!.executions[0]!.observation as unknown as Record<string, any>;
  const normalized = observation.normalized_observation;
  normalized.capture_state = "byte_limit";
  normalized.reported_completeness = "truncated";
  normalized.input_events = 4;
  normalized.duplicate_events = 1;
  observation.events = 4;
  observation.truncated = true;
  expect(checkedAdWorkflow(raw, adOwner).operations[0]!.executions[0]!.audit!.normalized).toMatchObject({ captureState: "byte_limit", completeness: "truncated", inputEvents: 4, duplicateEvents: 1, events: expect.any(Array) });
});
it("binds the exact UTC scope start while preserving Windows 100ns event and correlation ordering", () => {
  const raw = auditWorkflowWithNormalized();
  const scope = raw.workflow.request.environment.scope;
  scope.created_at = "2026-10-18T16:59:00.123456+02:00";
  const observation = raw.workflow.progress.operations[0]!.executions[0]!.observation as unknown as Record<string, any>;
  const normalized = observation.normalized_observation;
  normalized.window_start = "2026-10-18T14:59:00.1234560Z";
  const [logon, share] = normalized.events;
  logon.principal_role = "probe"; logon.principal_sid = adSids.probe;
  share.server_logon = "kerberos_network"; share.logon_record_id = logon.record_id;
  expect(checkedAdWorkflow(raw, adOwner).operations[0]!.executions[0]!.audit!.normalized!.windowStart).toBe("2026-10-18T14:59:00.1234560Z");
  logon.observed_at = "2026-10-18T15:00:01.0000001Z";
  share.server_logon = "ambiguous"; delete share.logon_record_id;
  expect(checkedAdWorkflow(raw, adOwner).operations[0]!.executions[0]!.audit!.normalized!.events[1]!.serverLogon).toBe("ambiguous");
  share.server_logon = "kerberos_network"; share.logon_record_id = logon.record_id;
  expect(() => checkedAdWorkflow(raw, adOwner)).toThrow();
  normalized.window_start = "2026-10-18T14:59:00.1234570Z";
  expect(() => checkedAdWorkflow(raw, adOwner)).toThrow();
});
it("retains canonical uint64 event references losslessly and compares them numerically", () => {
  const raw = auditWorkflowWithNormalized();
  const observation = raw.workflow.progress.operations[0]!.executions[0]!.observation as unknown as Record<string, any>;
  const normalized = observation.normalized_observation;
  const [logon, share] = normalized.events;
  logon.record_id = "18446744073709551614";
  logon.principal_role = "probe"; logon.principal_sid = adSids.probe;
  share.record_id = "18446744073709551615";
  share.server_logon = "kerberos_network"; share.logon_record_id = logon.record_id;
  const events = checkedAdWorkflow(raw, adOwner).operations[0]!.executions[0]!.audit!.normalized!.events;
  expect(events[0]!.recordId).toBe("18446744073709551614");
  expect(events[1]!.recordId).toBe("18446744073709551615");
  expect(events[1]!.logonRecordId).toBe("18446744073709551614");
});
it.each([0, "0", "00", "01", "+1", " 1", "18446744073709551616", 9007199254740992])("rejects noncanonical or non-string uint64 event references: %s", invalid => {
  const raw = auditWorkflowWithNormalized();
  const observation = raw.workflow.progress.operations[0]!.executions[0]!.observation as unknown as Record<string, any>;
  observation.normalized_observation.events[0].record_id = invalid;
  expect(() => checkedAdWorkflow(raw, adOwner)).toThrow();
});
it.each([0, "0", "01", "18446744073709551616", 10])("rejects noncanonical or non-string correlated uint64 references: %s", invalid => {
  const raw = auditWorkflowWithNormalized();
  const observation = raw.workflow.progress.operations[0]!.executions[0]!.observation as unknown as Record<string, any>;
  const [logon, share] = observation.normalized_observation.events;
  logon.principal_role = "probe"; logon.principal_sid = adSids.probe;
  share.server_logon = "kerberos_network"; share.logon_record_id = invalid;
  expect(() => checkedAdWorkflow(raw, adOwner)).toThrow();
});
it.each([
  (value: any) => { value.effective_access_claim = true; },
  (value: any) => { value.events[0].username = "private-user"; },
  (value: any) => { value.events[0].record_id = value.events[1].record_id; },
  (value: any) => { value.input_events = 1001; },
  (value: any) => { value.input_bytes = 4 * 1024 * 1024 + 1; },
  (value: any) => { value.input_bytes = 2; value.input_events = 3; },
  (value: any) => { value.duplicate_events = 1; },
  (value: any) => { value.events[1].client_ip = "10.44.0.4"; },
])("rejects a changed normalized audit contract", mutate => {
  const raw = auditWorkflowWithNormalized();
  const observation = raw.workflow.progress.operations[0]!.executions[0]!.observation;
  if (!("events" in observation)) throw new Error("Expected audit fixture");
  mutate((observation as unknown as Record<string, any>).normalized_observation);
  expect(() => checkedAdWorkflow(raw, adOwner)).toThrow();
});
it("does not turn fixture availability into native enrollment", () => { const value = checkedAdEnvironments(rawAdEnvironments()); expect(value.nativeAvailable).toBe(false); expect(value.environments[0]!.available).toBe(true); });
it.each(["scope_not_current", "member_channel_unavailable", "client_channel_unavailable", "role_channels_unavailable"])("keeps the finite %s readiness failure unavailable", problem => {
  const raw = rawAdEnvironments();
  const entry = raw.environments[0]!;
  const value = { ...raw, environments: [{ ...entry, available: false, readiness: { ...entry.readiness, available: false, problem } }] };
  expect(checkedAdEnvironments(value).environments[0]!.readiness.problem).toBe(problem);
  value.environments[0]!.readiness.problem = "private diagnostic";
  expect(() => checkedAdEnvironments(value)).toThrow();
});
it("accepts configured admission without inventing allowed work or native enrollment", () => {
  const raw = rawAdWorkflow({ allowed: [], stopped: true }); raw.execution_integration = "configured_admission";
  const value = checkedAdWorkflow(raw, adOwner);
  expect(value.integration).toBe("configured_admission"); expect(value.allowed).toEqual([]); expect(value.stopped).toBe(true);
  expect(checkedAdEnvironments(rawAdEnvironments()).nativeAvailable).toBe(false);
  raw.execution_integration = "connected"; expect(() => checkedAdWorkflow(raw, adOwner)).toThrow();
});
it("refuses an overstated native or access claim", () => {
  const env = rawAdEnvironments(); env.native_execution_available = true; expect(() => checkedAdEnvironments(env)).toThrow();
  const raw = rawAdWorkflow(); raw.effective_access_claim = true; expect(() => checkedAdWorkflow(raw)).toThrow();
});
it("refuses a different owner, unsafe run link, or truncated complete stage", () => {
  expect(() => checkedAdWorkflow(rawAdWorkflow(), adChild)).toThrow();
  const raw = rawAdWorkflow({ phases: ["baseline"] }); raw.workflow.progress.operations[0]!.run_id = "https://external.example/test"; expect(() => checkedAdWorkflow(raw)).toThrow();
  raw.workflow.progress.operations[0]!.run_id = "run-original"; raw.workflow.progress.operations[0]!.executions.pop(); expect(() => checkedAdWorkflow(raw)).toThrow();
});
it("rejects duplicate saved exercises and pending work offered as executable", () => { const raw = rawAdWorkflow(); expect(() => checkedAdList({ workflows: [raw, raw] })).toThrow(); expect(() => checkedAdWorkflow(rawAdWorkflow({ pending: adChild, allowed: ["inspect"] }))).toThrow(); });
it("keeps a known counterexample distinct from unknown execution", () => { const value = checkedAdWorkflow(rawAdWorkflow({ phases: ["retest"], expectation: "not_met" })); expect(value.operations[0]).toMatchObject({ state: "complete", expectation: "not_met", cleanup: "verified" }); });
it("requires exact selected review identity, revision, phase and steps", () => { const value = checkedAdWorkflow(rawAdWorkflow()); expect(checkedAdReview(rawAdReview(), value, "inspect").revision).toBe(0); for (const delta of [{ workflow_job_id: adChild }, { revision: 1 }, { phase: "harden" }, { steps: ["other"] }]) expect(() => checkedAdReview({ ...rawAdReview(), ...delta }, value, "inspect")).toThrow(); });
it("rejects an altered displayed reservation rather than understate its cost", () => { const value = checkedAdWorkflow(rawAdWorkflow({ allowed: ["baseline"] })); const review = rawAdReview("baseline"); review.budget.sessions = 0; expect(() => checkedAdReview(review, value, "baseline")).toThrow(); });
it("rejects an ACL display with changed owner or missing restoration preimage", () => {
  const value = checkedAdWorkflow(rawAdWorkflow({ allowed: ["harden"] })); const review = rawAdReview("harden");
  review.change!.after_descriptor.owner_sid = "S-1-5-21-1-2-3-1999"; expect(() => checkedAdReview(review, value, "harden")).toThrow();
  expect(() => checkedAdReview({ ...rawAdReview("harden"), change: null }, value, "harden")).toThrow();
});
it("refuses reordered reader outcomes rather than mislabel their meaning", () => { const raw = rawAdWorkflow({ phases: ["baseline"] }); raw.workflow.progress.operations[0]!.executions.reverse(); expect(() => checkedAdWorkflow(raw)).toThrow(); });
it("rejects control characters in operator-facing environment text", () => { const raw = rawAdWorkflow(); raw.workflow.request.environment.scope.hosts.member.fqdn = "member\n.example.test"; expect(() => checkedAdWorkflow(raw)).toThrow(); });
it("retains cleanup stages after the business window without refreshing expiry", () => { const value = checkedAdWorkflow(rawAdWorkflow()); const time = Date.parse(value.environment.createdAt) + 1900_000; expect(adPhaseCurrent(value, "retest", time)).toBe(false); expect(adPhaseCurrent(value, "rollback", time)).toBe(true); expect(adPhaseCurrent(value, "rollback", Date.parse(value.environment.expiresAt))).toBe(false); });
it("persists only the original request and refuses replacement or forged storage", () => { const pending = adPendingFixture(); storeAdPending(pending); expect(readAdPending()).toEqual(pending); expect(() => storeAdPending({ ...pending, body: { ...pending.body, reviewed_by: "other" } })).toThrow(); expect(() => clearAdPending({ ...pending, body: { ...pending.body, reviewed_by: "other" } })).toThrow(); clearAdPending(pending); expect(readAdPending()).toBeUndefined(); localStorage.setItem("bluefire.ad-smb.pending.v1", JSON.stringify({ ...pending, profile: {} })); expect(() => readAdPending()).toThrow(); });
it("matches exact original confirmation, not just an operation identifier", () => { const pending = adPendingFixture(); expect(adConfirmed(rawAdAcknowledgement(), pending)).toBe(true); const wrong = rawAdAcknowledgement(); wrong.request.submitted_request.reviewed_by = "other"; expect(adConfirmed(wrong, pending)).toBe(false); });
it("uses existing authenticated request transport and exact empty control bodies", async () => { await adSmbApi.stop(adOwner); await adSmbApi.recover(adOwner); expect(request).toHaveBeenNthCalledWith(1, `/ad-smb/workflows/${adOwner}/stop`, { method: "POST", body: "{}" }); expect(request).toHaveBeenNthCalledWith(2, `/ad-smb/workflows/${adOwner}/recover`, { method: "POST", body: "{}" }); });
