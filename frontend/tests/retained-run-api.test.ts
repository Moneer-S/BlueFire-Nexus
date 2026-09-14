import { expect, it, vi } from "vitest";
import { api } from "../src/lib/api";

const runId = "run-retained-observations";
const retained = { run_id: runId, mode: "execute", status: "interrupted",
  steps: [{ step_id: "collect", action_id: "sandbox.fixture.create.v1", status: "success" }],
  evidence: { records: [{ evidence_id: "evidence-one", provenance: "observed", content: { records: 8 } }] } };
function respond(value: unknown) {
  return vi.spyOn(globalThis, "fetch").mockImplementation(async url => new Response(JSON.stringify(
    String(url).endsWith("/retained-observations") ? envelope(value) : value,
  ), { status: 200 }));
}
function envelope(observations: unknown) {
  return { schema_version: "bluefire.retained-run-observations.v1", run_id: runId,
    record_state: "unsealed", display_only: true, canonical: false, replay_available: false, events_complete: true, observations };
}

it("reads unfinished observations with GET while keeping finalized result reads strict", async () => {
  const fetch = respond(retained);
  expect(await api.retainedRunDetail(runId)).toEqual({ ...retained, retained_events_complete: true });
  await expect(api.runDetail(runId)).rejects.toMatchObject({ code: "run_not_finalized" });
  expect(fetch).toHaveBeenCalledTimes(2);
  expect(fetch.mock.calls.map(([url]) => url)).toEqual([
    `/api/v1/runs/${runId}/retained-observations`, `/api/v1/runs/${runId}`,
  ]);
  for (const [, options] of fetch.mock.calls) {
    expect(options?.method ?? "GET").toBe("GET");
    expect(options?.body).toBeUndefined();
    expect(options?.credentials).toBe("same-origin");
  }
});

it.each([
  ["missing envelope", retained],
  ["wrong schema", { ...envelope(retained), schema_version: "unknown" }],
  ["foreign run", { ...envelope(retained), run_id: "run-other" }],
  ["sealed claim", { ...envelope(retained), record_state: "sealed" }],
  ["missing display boundary", { ...envelope(retained), display_only: undefined }],
  ["canonical claim", { ...envelope(retained), canonical: true }],
  ["replay claim", { ...envelope(retained), replay_available: true }],
  ["missing event completeness", { ...envelope(retained), events_complete: undefined }],
])("refuses an invalid retained observation envelope: %s", async (_case, value) => {
  vi.spyOn(globalThis, "fetch").mockImplementation(async () => new Response(JSON.stringify(value), { status: 200 }));
  await expect(api.retainedRunDetail(runId)).rejects.toMatchObject({ code: "invalid_retained_run" });
});

it.each([
  null, { ...retained, run_id: "run-other" }, { ...retained, mode: "unknown" },
  { ...retained, mode: ["execute"] },
  { ...retained, steps: [null] }, { ...retained, steps: [{ step_id: "collect" }] },
  { ...retained, evidence: { records: [null] } },
  { ...retained, evidence: { records: [{ provenance: "observed", limitations: "reason" }] } },
  { ...retained, evidence: { records: [{ provenance: "observed", limitations: [{}] }] } },
  { ...retained, detections: { candidates: [{}] } },
  { ...retained, events: "not an event list" },
])("refuses a mismatched or malformed retained record (%j)", async value => {
  respond(value);
  await expect(api.retainedRunDetail(runId)).rejects.toMatchObject({ code: "invalid_retained_run" });
});

it.each(["created", "interrupted"])("reads the actual unfinished %s shape using its persisted plan mode", async status => {
  const { mode, ...progress } = retained;
  const stored = { ...progress, status, plan: { mode } };
  respond(stored);
  expect(await api.retainedRunDetail(runId)).toEqual({ ...stored, mode, retained_events_complete: true });
  expect(stored).not.toHaveProperty("mode");
  expect(stored).not.toHaveProperty("finalized_at");
  await expect(api.runDetail(runId)).rejects.toMatchObject({ code: "run_not_finalized" });
});

it.each([
  { status: "completed", plan: { mode: "execute" } },
  { status: "interrupted", finalized_at: "2030-01-01T00:00:00Z", plan: { mode: "execute" } },
  { status: "interrupted", plan: { mode: ["execute"] } },
  { status: "interrupted", plan: {} },
])("does not infer a missing mode from an unsupported record shape (%j)", async patch => {
  respond({ ...retained, mode: undefined, ...patch });
  await expect(api.retainedRunDetail(runId)).rejects.toMatchObject({ code: "invalid_retained_run" });
});
