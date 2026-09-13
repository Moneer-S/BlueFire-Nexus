import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, it, vi } from "vitest";
import { RunExports } from "../src/components/RunExports";
import { api } from "../src/lib/api";
import { runReport } from "../src/lib/run-report";
import { demoScenario } from "../src/lib/demo";
import type { RunRecord } from "../src/types";

const run: RunRecord = { run_id: "run-20260906T120000Z-0123456789abcdef", mode: "simulate", status: "cancelled", finalized_at: "2026-09-06T12:00:00Z", scenario_title: "Frozen experiment", steps: [{ step_id: "collect", behavior_id: "collection.original", simulation_id: "sim.collection", status: "success" }, { step_id: "policy_stop", status: "blocked", policy: { allowed: false } }] };

it("exports source notes separately while retaining additional run limitations", () => {
  const source = "No approval is supplied by this graph";
  const runtime = "Partial observations after cancellation";
  const record = { ...run, scenario: { ...demoScenario, limitations: [source] }, limitations: [source, runtime] };
  const before = structuredClone(record);
  const report = runReport(record);
  expect(report).toContain(`## Run limitations\n\n- ${runtime}`);
  expect(report).toContain("## Scenario assumptions and source notes");
  expect(report).toContain("Recorded when the saved experiment was authored");
  expect(report).toContain(`- ${source}`);
  expect(record).toEqual(before);
  expect(runReport({ ...record, scenario: undefined })).toContain("## Recorded limitations");
});

it.each([
  ["cancelled", ["Partial observations", "Source caveat", "Partial observations"]],
  ["interrupted", undefined],
  ["cancelled", []],
] as const)("exports complete source notes even when %s result copies are incomplete (%j)", (status, resultNotes) => {
  const sourceNotes = ["Source caveat", "Unobserved behavior remains unverified", "Source caveat"];
  const record = { ...run, status, scenario: { ...demoScenario, limitations: sourceNotes }, limitations: resultNotes ? [...resultNotes] : undefined };
  const before = structuredClone(record);
  const report = runReport(record);
  const sourceSection = report.split("## Scenario assumptions and source notes\n")[1]?.split("\n## ")[0];
  expect(sourceSection?.split("\n").filter((line) => line.startsWith("- "))).toEqual(sourceNotes.map((note) => `- ${note}`));
  if (resultNotes?.length) {
    const runtimeSection = report.split("## Run limitations\n")[1]?.split("\n## ")[0];
    expect(runtimeSection?.split("\n").filter((line) => line.startsWith("- "))).toEqual(["- Partial observations", "- Partial observations"]);
  } else {
    expect(report).not.toContain("No limitations were attached");
  }
  expect(record).toEqual(before);
});

function downloads() {
  const create = vi.fn<(blob: Blob) => string>(() => "blob:saved-run");
  vi.stubGlobal("URL", class extends URL { static createObjectURL = create; static revokeObjectURL = vi.fn(); });
  const clicked: Array<{ filename: string; href: string }> = [];
  vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (this: HTMLAnchorElement) { clicked.push({ filename: this.download, href: this.href }); });
  return { create, clicked };
}
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });

it("reports actual frozen outcomes, missing evidence and cleanup without claiming defense validation", () => {
  const report = runReport(run);
  expect(report).toContain("Frozen experiment");
  expect(report).toContain("Not established");
  expect(report).toContain("Simulated success");
  expect(report).toContain("Simulated stop");
  expect(report).toContain("Independently observed: Not reported");
  expect(report).toContain("Cleanup: Not recorded");
  expect(report).toContain("outside this run bundle");
  expect(report).toContain("incomplete metadata");
  const execute = runReport({ ...run, mode: "execute", objective_reached: false, evidence: { records: [] }, cleanup: { success: false, outstanding_effects: 2 } });
  expect(execute).toContain("Not achieved");
  expect(execute).toContain("Stopped by BlueFire policy");
  expect(execute).toContain("2 outstanding effects");
  expect(execute).toContain("Independently observed: 0");
  expect(runReport({ ...run, objective_reached: true })).toContain("Achieved (synthetic)");
  expect(runReport({ ...run, objective: "<img src=x> [link](https://bad.test)" })).not.toContain("<img");
});

it("downloads the Markdown report on click with a run-specific filename", async () => {
  const { create, clicked } = downloads();
  const fetchBundle = vi.spyOn(api, "runBundle");
  render(<RunExports run={run}/>);
  expect(create).not.toHaveBeenCalled();
  await userEvent.click(screen.getByRole("button", { name: "Download report" }));
  expect(clicked).toEqual([{ filename: `${run.run_id}.md`, href: "blob:saved-run" }]);
  const blob = create.mock.calls[0]![0] as Blob;
  expect(blob.type).toBe("text/markdown;charset=utf-8");
  expect(await new Promise((resolve) => { const reader = new FileReader(); reader.onload = () => resolve(reader.result); reader.readAsText(blob); })).toBe(runReport(run));
  expect(fetchBundle).not.toHaveBeenCalled();
});

it("downloads the exact bundle Blob and exposes pending state without repeat requests", async () => {
  const { create, clicked } = downloads();
  let resolve!: (blob: Blob) => void;
  const fetchBundle = vi.spyOn(api, "runBundle").mockReturnValue(new Promise((done) => { resolve = done; }));
  render(<RunExports run={run}/>);
  await userEvent.click(screen.getByRole("button", { name: "Download run bundle" }));
  expect(screen.getByRole("button", { name: "Preparing bundle…" })).toBeDisabled();
  expect(screen.getByRole("status")).toHaveTextContent("Validating");
  expect(fetchBundle).toHaveBeenCalledTimes(1);
  expect(fetchBundle.mock.calls[0]![0]).toBe(run.run_id);
  const blob = new Blob(["exact server bytes"], { type: "application/zip" });
  await act(async () => resolve(blob));
  expect(create).toHaveBeenCalledWith(blob);
  expect(clicked[0]!.filename).toBe(`${run.run_id}.zip`);
});

it("shows failure and allows retry without saving a fake archive", async () => {
  const { create } = downloads();
  vi.spyOn(api, "runBundle").mockRejectedValue(new Error("Manifest validation failed"));
  render(<RunExports run={run}/>);
  await userEvent.click(screen.getByRole("button", { name: "Download run bundle" }));
  expect(await screen.findByText("Manifest validation failed")).toBeVisible();
  expect(screen.getByRole("button", { name: "Download run bundle" })).toBeEnabled();
  expect(create).not.toHaveBeenCalled();
});

it("aborts on navigation and ignores late completion while the next run stays usable", async () => {
  const { create } = downloads();
  let resolve!: (blob: Blob) => void;
  const fetchBundle = vi.spyOn(api, "runBundle").mockReturnValue(new Promise((done) => { resolve = done; }));
  const view = render(<RunExports run={run}/>);
  await userEvent.click(screen.getByRole("button", { name: "Download run bundle" }));
  const signal = fetchBundle.mock.calls[0]![1];
  view.rerender(<RunExports run={{ ...run, run_id: "run-20260906T120001Z-0123456789abcdef" }}/>);
  expect(signal.aborted).toBe(true);
  await act(async () => resolve(new Blob(["late"])));
  expect(create).not.toHaveBeenCalled();
  expect(screen.getByRole("button", { name: "Download run bundle" })).toBeEnabled();
});

it("keeps unfinalized downloads unavailable and demo bundles unavailable", () => {
  const view = render(<RunExports run={{ ...run, finalized_at: undefined }}/>);
  expect(screen.getByRole("button", { name: "Download report" })).toBeDisabled();
  expect(screen.getByRole("button", { name: "Download run bundle" })).toBeDisabled();
  view.rerender(<RunExports run={{ ...run, is_demo: true }}/>);
  expect(screen.getByRole("button", { name: "Download report" })).toBeEnabled();
  expect(screen.getByRole("button", { name: "Download run bundle" })).toBeDisabled();
});

it("uses same-origin binary fetch and preserves structured API failures", async () => {
  const blob = new Blob(["zip"], { type: "application/zip" });
  const fetch = vi.fn().mockResolvedValue({ ok: true, headers: new Headers({ "Content-Type": "application/zip" }), blob: async () => blob });
  vi.stubGlobal("fetch", fetch);
  expect(await api.runBundle(run.run_id, new AbortController().signal)).toBe(blob);
  expect(fetch).toHaveBeenCalledWith(`/api/v1/runs/${run.run_id}/bundle`, expect.objectContaining({ credentials: "same-origin", cache: "no-store", headers: { Accept: "application/zip" } }));
  fetch.mockResolvedValue({ ok: false, status: 409, json: async () => ({ error: { code: "run_bundle_unavailable", message: "Not finalized" } }) });
  await expect(api.runBundle(run.run_id, new AbortController().signal)).rejects.toMatchObject({ code: "run_bundle_unavailable", status: 409, message: "Not finalized" });
  await expect(api.runBundle("../private", new AbortController().signal)).rejects.toMatchObject({ code: "invalid_run_id" });
  await waitFor(() => expect(fetch).toHaveBeenCalledTimes(2));
});
