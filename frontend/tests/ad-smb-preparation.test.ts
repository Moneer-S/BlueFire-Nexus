import { expect, it, vi } from "vitest";
import { checkedAdPreparationJob, checkedAdWorkflow } from "../src/lib/ad-smb";
import { adChild, adOwner, rawAdOperation, rawAdPreparation, rawAdPreparationJob, rawAdPreparationWorkflow, rawAdWorkflow } from "./ad-smb-fixture";

vi.mock("../src/lib/api", () => ({ DEMO_MODE: false, request: vi.fn() }));

it("keeps legacy owners readable without adding preparation evidence", () => {
  expect(checkedAdWorkflow(rawAdWorkflow()).preparations).toEqual([]);
});

it.each(["cancelled", "failed", "interrupted"] as const)("retains a %s preparation separately from execution and consumed authority", state => {
  const value = checkedAdWorkflow(rawAdPreparationWorkflow(state), adOwner);
  expect(value.preparations).toEqual([{ id: adChild, phase: "baseline", state, reservedAt: "2026-10-23T15:00:00Z", settledAt: "2026-10-23T15:01:00Z", digest: expect.stringMatching(/^sha256:/) }]);
  expect(value.operations).toEqual([]);
  expect(value.pending).toBeNull();
  expect(value.stopped).toBe(true);
  expect(value.remaining).toMatchObject({ business_attempts: 3, sessions: 3 });
  expect(value.preparations[0]).not.toHaveProperty("runId");
  expect(value.preparations[0]).not.toHaveProperty("cleanup");
});

it.each([
  { schema_version: "other" }, { boundary: "dispatched" }, { producer: "runner" },
  { operation_job_id: "https://external.example/test" }, { phase: "execute" },
  { terminal_state: "completed" }, { terminal_state: "running" },
  { reserved_at: "invalid" }, { settled_at: "2026-10-23T14:59:00Z" }, { request_digest: "invalid" },
  { run_id: "run-not-created" }, { cleanup: "verified" }, { observation: {} }, { evidence: [] },
])("rejects malformed or execution-like preparation records: %j", patch => {
  const raw = rawAdPreparationWorkflow();
  Object.assign(raw.workflow.progress.preparation_history[0]!, patch);
  expect(() => checkedAdWorkflow(raw, adOwner)).toThrow();
});

it.each(Object.keys(rawAdPreparation()))("requires preparation field %s when history is present", field => {
  const raw = rawAdPreparationWorkflow();
  delete (raw.workflow.progress.preparation_history[0]! as Record<string, unknown>)[field];
  expect(() => checkedAdWorkflow(raw, adOwner)).toThrow();
});

it.each([null, {}, "invalid", undefined])("rejects invalid explicit history instead of treating it as a legacy owner: %j", history => {
  const raw = rawAdPreparationWorkflow();
  Object.assign(raw.workflow.progress, { preparation_history: history });
  expect(() => checkedAdWorkflow(raw, adOwner)).toThrow();
});

it("preserves six ordered records and refuses overflow or duplicate child pointers", () => {
  const raw = rawAdPreparationWorkflow();
  raw.workflow.progress.preparation_history = Array.from({ length: 6 }, (_, index) => ({ ...rawAdPreparation(), operation_job_id: `job-${String(index + 3).repeat(32)}` }));
  expect(checkedAdWorkflow(raw).preparations).toHaveLength(6);
  raw.workflow.progress.preparation_history.push({ ...rawAdPreparation() });
  expect(() => checkedAdWorkflow(raw)).toThrow();
  raw.workflow.progress.preparation_history.pop();
  raw.workflow.progress.preparation_history[1] = raw.workflow.progress.preparation_history[0]!;
  expect(() => checkedAdWorkflow(raw)).toThrow();
});

it("rejects owner, pending, executed and reversed chronology preparation references", () => {
  for (const collision of ["owner", "pending", "executed"] as const) {
    const raw = rawAdPreparationWorkflow();
    if (collision === "owner") raw.workflow.progress.preparation_history[0]!.operation_job_id = adOwner;
    if (collision === "pending") raw.workflow.progress.pending_operation = adChild;
    if (collision === "executed") raw.workflow.progress.operations = [{ ...rawAdOperation("inspect"), job_id: adChild }];
    expect(() => checkedAdWorkflow(raw)).toThrow();
  }
  const raw = rawAdPreparationWorkflow();
  raw.workflow.progress.preparation_history.push({ ...rawAdPreparation(), operation_job_id: `job-${"3".repeat(32)}`, settled_at: "2026-10-23T15:00:30Z" });
  expect(() => checkedAdWorkflow(raw)).toThrow();
});

it("projects only the exact settled child's bounded failure code, never raw request or error text", () => {
  const selected = checkedAdWorkflow(rawAdPreparationWorkflow()).preparations[0]!;
  expect(checkedAdPreparationJob(rawAdPreparationJob(), adOwner, selected)).toEqual({ errorCode: "execution_callback_failed" });
});

it.each([
  { schema_version: "other" }, { job_id: adOwner }, { kind: "scenario.run" }, { state: "completed" },
  { created_at: "2026-10-23T14:59:00Z" }, { result_ref: "run-other" },
  { request: { ad_smb: { workflow_job_id: adChild, operation_job_id: adChild, phase: "baseline" } } },
  { request: { ad_smb: { workflow_job_id: adOwner, operation_job_id: adChild, phase: "inspect" } } },
  { request: { ad_smb: { workflow_job_id: adOwner, operation_job_id: adOwner, phase: "baseline" } } },
  { request: { ad_smb: { workflow_job_id: adOwner, phase: "baseline" } } },
])("rejects a saved preparation detail rebound outside its selected history: %j", patch => {
  const selected = checkedAdWorkflow(rawAdPreparationWorkflow()).preparations[0]!;
  expect(() => checkedAdPreparationJob({ ...rawAdPreparationJob(), ...patch }, adOwner, selected)).toThrow();
});

it.each([{ tasks: [{}] }, { run_id: "run-other" }, { initial_run: {} }, { preparation_settlement: { ...rawAdPreparation(), request_digest: `sha256:${"b".repeat(64)}` } }])("rejects executed or mismatched saved preparation details: %j", patch => {
  const raw = rawAdPreparationJob(), selected = checkedAdWorkflow(rawAdPreparationWorkflow()).preparations[0]!;
  expect(() => checkedAdPreparationJob({ ...raw, progress: { ...raw.progress, ...patch } }, adOwner, selected)).toThrow();
});

it.each(["cancelled", "failed", "interrupted"] as const)("validates the exact allowed saved phase for %s preparation", state => {
  const selected = checkedAdWorkflow(rawAdPreparationWorkflow(state)).preparations[0]!;
  const allowed = state === "cancelled" ? ["cancelled"] : state === "failed" ? [undefined, null, "failed"] : [undefined, null, "queued", "planning", "awaiting_approval", "running", "paused", "cancelling"];
  for (const phase of allowed) {
    const raw = rawAdPreparationJob(state);
    expect(() => checkedAdPreparationJob({ ...raw, progress: { ...raw.progress, phase } }, adOwner, selected)).not.toThrow();
  }
  for (const phase of ["completed", "executing", true, {}, [], ...(state === "cancelled" ? [null, undefined, "running"] : ["cancelled"])]) {
    const raw = rawAdPreparationJob(state);
    expect(() => checkedAdPreparationJob({ ...raw, progress: { ...raw.progress, phase } }, adOwner, selected)).toThrow();
  }
});
