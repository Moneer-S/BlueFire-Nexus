import { afterEach, expect, it, vi } from "vitest";
import { api } from "../src/lib/api";
import { runLabel as compatibleRunLabel } from "../src/lib/run-presentation";
import { isRunPresentation, runLabel, runMatchesSearch } from "../src/lib/runPresentation";
import type { RunPresentation, RunRecord } from "../src/types";

const runId = "run-20260908T120000Z-0123456789abcdef";
const presentation: RunPresentation = {
  schema_version: "bluefire.run-presentation.v1", run_id: runId,
  display_name: "Collection check", default_name: "File collection", updated_at: "2026-09-08T12:00:00Z",
};
const run: RunRecord = { run_id: runId, mode: "execute", status: "cancelled", steps: [], scenario_title: "File collection", presentation };
afterEach(() => { vi.unstubAllGlobals(); });

it("shares renamed, reset, historical and neutral labels without changing evidence", () => {
  const original = structuredClone(run);
  expect(runLabel(run)).toBe("Collection check");
  expect(compatibleRunLabel(run)).toBe(runLabel(run));
  expect(runLabel({ ...run, presentation: { ...presentation, display_name: null } })).toBe("File collection");
  expect(runLabel({ ...run, presentation: undefined })).toBe("File collection");
  expect(runLabel({ run_id: runId })).toBe("Run");
  expect(runLabel({ run_id: runId, objective: "Long recorded objective\n".repeat(30) })).toBe("Run");
  expect(run).toEqual(original);
});

it("searches actual names and immutable IDs while duplicate names retain identities", () => {
  const other = { ...run, run_id: "run-other", presentation: { ...presentation, run_id: "run-other" } };
  expect(runLabel(other)).toBe(runLabel(run));
  expect([run, other].filter((item) => runMatchesSearch(item, "collection CHECK"))).toHaveLength(2);
  expect([run, other].filter((item) => runMatchesSearch(item, "0123456789abcdef"))).toEqual([run]);
  expect(runMatchesSearch(run, "prevented")).toBe(false);
  expect(runMatchesSearch(run, " ")).toBe(true);
});

it("does not display another run's editable metadata or malformed names", () => {
  for (const bad of [{ ...presentation, run_id: "another-run" }, { ...presentation, display_name: "name\ncontinued" }, { ...presentation, display_name: "a".repeat(121) }]) {
    expect(isRunPresentation(bad, runId)).toBe(false);
    expect(runLabel({ ...run, presentation: bad })).toBe("File collection");
  }
});

it("persists only the requested display name through the normal authenticated API", async () => {
  const fetcher = vi.fn().mockResolvedValue(new Response(JSON.stringify(presentation), { status: 200 }));
  vi.stubGlobal("fetch", fetcher);
  expect(await api.renameRun(runId, "  Collection check  ")).toEqual(presentation);
  expect(fetcher).toHaveBeenCalledOnce();
  expect(fetcher).toHaveBeenCalledWith(`/api/v1/runs/${runId}/presentation`, expect.objectContaining({
    method: "POST", credentials: "same-origin", body: JSON.stringify({ display_name: "  Collection check  " }),
  }));
  expect(run.presentation).toEqual(presentation);
});

it("confirms reset and refuses mismatched rename acknowledgements without retries", async () => {
  const fetcher = vi.fn().mockResolvedValueOnce(new Response(JSON.stringify({ ...presentation, display_name: null }), { status: 200 }))
    .mockResolvedValueOnce(new Response(JSON.stringify({ ...presentation, run_id: "other" }), { status: 200 }))
    .mockResolvedValueOnce(new Response(JSON.stringify(presentation), { status: 200 }));
  vi.stubGlobal("fetch", fetcher);
  expect((await api.renameRun(runId, null)).display_name).toBeNull();
  await expect(api.renameRun(runId, "Collection check")).rejects.toMatchObject({ code: "run_name_unconfirmed" });
  await expect(api.renameRun(runId, "Different request")).rejects.toMatchObject({ code: "run_name_unconfirmed" });
  expect(fetcher).toHaveBeenCalledTimes(3);
});
