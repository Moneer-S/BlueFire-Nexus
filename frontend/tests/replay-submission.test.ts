import { expect, it, vi } from "vitest";
import { api, type ReplayPreparation } from "../src/lib/api";
import { demoScenario } from "../src/lib/demo";
import { clearPendingReplay, readPendingReplay, settlePendingReplay, storePendingReplay } from "../src/lib/replay-submission";
import type { RunJob } from "../src/types";

const key = "bluefire.replay.pending-submission.v1";
function receipt() {
  const payload = { mode: "simulate", strategy: "exact" };
  const preparation: ReplayPreparation = {
    schema_version: "bluefire.replay-preparation.v1", preparation_id: "replay-preparation-test",
    preparation_context: { schema_version: "bluefire.replay-preparation-context.v1", runner_readiness: null },
    binding: { source: { run_id: "run-source" }, replay_request: payload }, replay_request: payload,
    replay_extent: "full", scenario: structuredClone(demoScenario), lineage: {}, preflight: { ready: true, status: "ready" }, approval_created: false, effects_started: false,
  };
  return { sourceId: "run-source", payload, preparation, submissionId: "01234567-89ab-4def-8123-456789abcdef" };
}

it("preserves an unresolved receipt against a different UUID or changed request", () => {
  const original = receipt();
  expect(storePendingReplay(original)).toBe(true);
  expect(storePendingReplay(structuredClone(original))).toBe(true);
  expect(storePendingReplay({ ...original, submissionId: crypto.randomUUID() })).toBe(false);
  expect(storePendingReplay({ ...original, payload: { mode: "execute" } })).toBe(false);
  clearPendingReplay(crypto.randomUUID());
  expect(readPendingReplay()).toEqual(original);
});

it.each(["{", "null", JSON.stringify({ submissionId: "invalid" })])("does not overwrite an unreadable pending receipt: %s", (stored) => {
  sessionStorage.setItem(key, stored);
  expect(readPendingReplay()).toBeUndefined();
  expect(storePendingReplay(receipt())).toBe(false);
  expect(sessionStorage.getItem(key)).toBe(stored);
});

it("rejects approval-bearing and source-mismatched receipts", () => {
  const original = receipt();
  expect(storePendingReplay({ ...original, payload: { ...original.payload, approval: { approved_by: "operator" } } })).toBe(false);
  sessionStorage.setItem(key, JSON.stringify({ ...original, sourceId: "different-run" }));
  expect(readPendingReplay()).toBeUndefined();
});

it("requires storage read-back before reporting a durable receipt", () => {
  vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {});
  expect(storePendingReplay(receipt())).toBe(false);
});

it("settles only a job with the exact saved source, preparation, request, and identity", () => {
  const original = receipt();
  storePendingReplay(original);
  const job: RunJob = { schema_version: "bluefire.job.v1", job_id: `job-${original.submissionId.replaceAll("-", "")}`, kind: "scenario.replay", state: "completed", progress: {}, request: { source_run_id: original.sourceId, replay_request: original.payload, replay_preparation: original.preparation } };
  expect(settlePendingReplay({ ...job, job_id: "job-different" })).toBe(false);
  expect(settlePendingReplay({ ...job, request: { ...job.request, source_run_id: "different-run" } })).toBe(false);
  expect(settlePendingReplay({ ...job, request: { ...job.request, replay_preparation: { ...original.preparation, preparation_id: "changed" } } })).toBe(false);
  expect(readPendingReplay()).toEqual(original);
  expect(settlePendingReplay(job)).toBe(true);
  expect(sessionStorage.getItem(key)).toBeNull();
});

it("posts the reviewed preparation and submission UUID without an inline approval", async () => {
  const original = receipt();
  const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({ job: { job_id: "saved" } }), { status: 202, headers: { "Content-Type": "application/json" } }));
  await api.submitReplay(original.sourceId, original.preparation, original.submissionId);
  expect(fetchMock).toHaveBeenCalledOnce();
  const [path, options] = fetchMock.mock.calls[0]!;
  expect(path).toBe("/api/v1/runs/run-source/replay-jobs");
  expect(options?.method).toBe("POST");
  expect(JSON.parse(String(options?.body))).toEqual({ ...original.payload, preparation_id: original.preparation.preparation_id, preparation_context: original.preparation.preparation_context, submission_id: original.submissionId });
});

it("restores the saved replay review without recompiling a different plan", async () => {
  const original = receipt();
  original.preparation.preflight = { ready: false, status: "approval_required", plan: { mode: "execute" }, approval_binding: { state_digest: "reviewed-state", plan_digest: "reviewed-plan", target_scope_digest: "reviewed-scope", profile_id: "lab", maximum_tier: "controlled" }, approval_envelope: { schema_version: "bluefire.approval-envelope.v1", envelope_digest: "reviewed-envelope", scenario_id: demoScenario.id, steps: [] } };
  const job: RunJob = { schema_version: "bluefire.job.v1", job_id: "job-test", kind: "scenario.replay", state: "awaiting_approval", progress: {}, request: { source_run_id: original.sourceId, replay_request: original.payload, replay_preparation: original.preparation } };
  const fetchMock = vi.spyOn(globalThis, "fetch");
  const review = await api.preflightStoredJobRequest(job);
  expect(review).toEqual(original.preparation.preflight);
  expect(review).not.toBe(original.preparation.preflight);
  await expect(api.preflightStoredJobRequest({ ...job, request: { ...job.request, source_run_id: "changed-source" } })).rejects.toMatchObject({ code: "job_preflight_unavailable" });
  await expect(api.preflightStoredJobRequest({ ...job, request: { ...job.request, replay_request: { changed: true } } })).rejects.toMatchObject({ code: "job_preflight_unavailable" });
  expect(fetchMock).not.toHaveBeenCalled();
});
