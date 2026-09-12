import { expect, it, vi } from "vitest";
import { api } from "../src/lib/api";

const runId = "run-retained-observations";
const retained = { run_id: runId, mode: "execute", status: "interrupted",
  steps: [{ step_id: "collect", action_id: "sandbox.fixture.create.v1", status: "success" }],
  evidence: { records: [{ evidence_id: "evidence-one", provenance: "observed", content: { records: 8 } }] } };
function respond(value: unknown) {
  return vi.spyOn(globalThis, "fetch").mockImplementation(async () => new Response(JSON.stringify(value), { status: 200 }));
}

it("reads unfinished observations with GET while keeping finalized result reads strict", async () => {
  const fetch = respond(retained);
  expect(await api.retainedRunDetail(runId)).toEqual(retained);
  await expect(api.runDetail(runId)).rejects.toMatchObject({ code: "run_not_finalized" });
  expect(fetch).toHaveBeenCalledTimes(2);
  for (const [url, options] of fetch.mock.calls) {
    expect(url).toBe(`/api/v1/runs/${runId}`);
    expect(options?.method ?? "GET").toBe("GET");
    expect(options?.body).toBeUndefined();
    expect(options?.credentials).toBe("same-origin");
  }
});

it.each([
  null, { ...retained, run_id: "run-other" }, { ...retained, mode: "unknown" },
  { ...retained, mode: ["execute"] },
  { ...retained, steps: [null] }, { ...retained, steps: [{ step_id: "collect" }] },
  { ...retained, evidence: { records: [null] } },
  { ...retained, evidence: { records: [{ provenance: "observed", limitations: "reason" }] } },
  { ...retained, evidence: { records: [{ provenance: "observed", limitations: [{}] }] } },
  { ...retained, detections: { candidates: [{}] } },
])("refuses a mismatched or malformed retained record (%j)", async value => {
  respond(value);
  await expect(api.retainedRunDetail(runId)).rejects.toMatchObject({ code: "invalid_retained_run" });
});
