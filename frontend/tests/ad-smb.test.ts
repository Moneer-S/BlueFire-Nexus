import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { adConfirmed, adPhaseCurrent, adSmbApi, checkedAdEnvironments, checkedAdList, checkedAdReview, checkedAdWorkflow, clearAdPending, readAdPending, storeAdPending } from "../src/lib/ad-smb";
import { request } from "../src/lib/api";
import { adChild, adOwner, adPendingFixture, rawAdAcknowledgement, rawAdEnvironments, rawAdReview, rawAdWorkflow } from "./ad-smb-fixture";

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
