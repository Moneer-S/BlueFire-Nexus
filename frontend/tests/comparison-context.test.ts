import { describe, expect, it } from "vitest";
import { clearComparisonContext, MAX_COMPARISON_RUNS, readComparisonContext, writeComparisonContext, type ComparisonSelection } from "../src/lib/comparison-context";

const emptySelection: ComparisonSelection = { runIds: [], baselineId: "", revisedId: "" };

function contextParams(runIds: string[] = ["run-second", "run-first"], baselineId?: string, revisedId?: string): URLSearchParams {
  const params = new URLSearchParams({ compare_context: "1" });
  runIds.forEach(id => params.append("compare_run", id));
  if (baselineId !== undefined) params.set("compare_baseline", baselineId);
  if (revisedId !== undefined) params.set("compare_revised", revisedId);
  return params;
}

describe("comparison navigation context", () => {
  it("leaves an absent context empty without inventing a selection", () => {
    expect(readComparisonContext(new URLSearchParams())).toEqual({ ...emptySelection, explicit: false, invalid: false });
  });

  it.each([
    { label: "ordered source and replay", source: "run-source", replay: "run-replay", expected: ["run-source", "run-replay"] },
    { label: "same source and replay", source: "run-same", replay: "run-same", expected: ["run-same"] },
    { label: "source only", source: "run-source", replay: "", expected: ["run-source"] },
    { label: "replay only", source: "", replay: "run-replay", expected: ["run-replay"] },
    { label: "invalid legacy source", source: "run\ninvalid", replay: "run-replay", expected: ["run-replay"] },
    { label: "oversize legacy replay", source: "run-source", replay: "r".repeat(201), expected: ["run-source"] },
  ])("retains legacy recovery for $label", ({ source, replay, expected }) => {
    expect(readComparisonContext(new URLSearchParams({ source, replay }))).toEqual({ runIds: expected, baselineId: "", revisedId: "", explicit: false, invalid: false });
  });

  it("keeps the existing first-value semantics of repeated legacy keys", () => {
    expect(readComparisonContext(new URLSearchParams("source=run-first&source=run-other&replay=run-second"))).toEqual({ runIds: ["run-first", "run-second"], baselineId: "", revisedId: "", explicit: false, invalid: false });
  });

  it("restores explicit ordered runs independently of legacy source and replay", () => {
    const params = contextParams();
    params.set("source", "run-legacy-source");
    params.set("replay", "run-legacy-replay");
    expect(readComparisonContext(params)).toEqual({ runIds: ["run-second", "run-first"], baselineId: "", revisedId: "", explicit: true, invalid: false });
  });

  it("retains an explicitly empty selection instead of falling back to legacy runs", () => {
    const params = new URLSearchParams("compare_context=1&source=run-source&replay=run-replay");
    expect(readComparisonContext(params)).toEqual({ ...emptySelection, explicit: true, invalid: false });
  });

  it.each([
    { label: "baseline only", baselineId: "rule-baseline", revisedId: "" },
    { label: "baseline and revised", baselineId: "rule-baseline", revisedId: "rule-revised" },
  ])("retains $label as detector IDs distinct from the run selection", ({ baselineId, revisedId }) => {
    const params = contextParams(["run-second", "run-first"], baselineId, revisedId || undefined);
    expect(readComparisonContext(params)).toEqual({ runIds: ["run-second", "run-first"], baselineId, revisedId, explicit: true, invalid: false });
  });

  it("accepts the exact run-count and identifier-length boundaries without truncation", () => {
    const runIds = ["r".repeat(200), ...Array.from({ length: 31 }, (_, index) => `run-${index}`)];
    const params = contextParams(runIds, "b".repeat(200), "v".repeat(200));
    expect(MAX_COMPARISON_RUNS).toBe(32);
    expect(readComparisonContext(params)).toEqual({ runIds, baselineId: "b".repeat(200), revisedId: "v".repeat(200), explicit: true, invalid: false });
  });

  const invalidContexts: { label: string; params: URLSearchParams }[] = [
    { label: "33 runs", params: contextParams(Array.from({ length: 33 }, (_, index) => `run-${index}`)) },
    { label: "duplicate runs", params: contextParams(["run-one", "run-one"]) },
    { label: "missing marker", params: new URLSearchParams("compare_run=run-one") },
    { label: "unknown marker version", params: new URLSearchParams("compare_context=2&compare_run=run-one") },
    { label: "duplicate marker", params: new URLSearchParams("compare_context=1&compare_context=1&compare_run=run-one") },
    { label: "empty run", params: contextParams([""]) },
    { label: "leading whitespace", params: contextParams([" run-one"]) },
    { label: "trailing whitespace", params: contextParams(["run-one "]) },
    { label: "C0 control", params: contextParams(["run\u0000one"]) },
    { label: "DEL control", params: contextParams(["run\u007fone"]) },
    { label: "201-character run", params: contextParams(["r".repeat(201)]) },
    { label: "detectors without runs", params: contextParams([], "rule-before", "rule-after") },
    { label: "baseline with one run", params: contextParams(["run-one"], "rule-before") },
    { label: "revised without baseline", params: contextParams(undefined, undefined, "rule-after") },
    { label: "identical detector IDs", params: contextParams(undefined, "rule-same", "rule-same") },
    { label: "empty baseline scalar", params: contextParams(undefined, "") },
    { label: "empty revised scalar", params: contextParams(undefined, "rule-before", "") },
    { label: "201-character baseline", params: contextParams(undefined, "b".repeat(201)) },
    { label: "control in revised ID", params: contextParams(undefined, "rule-before", "rule\nafter") },
    { label: "duplicate baseline scalar", params: new URLSearchParams("compare_context=1&compare_run=run-one&compare_run=run-two&compare_baseline=rule-before&compare_baseline=rule-before") },
    { label: "duplicate revised scalar", params: new URLSearchParams("compare_context=1&compare_run=run-one&compare_run=run-two&compare_baseline=rule-before&compare_revised=rule-after&compare_revised=rule-after") },
  ];

  it.each(invalidContexts)("refuses the complete context for $label without legacy fallback", ({ params }) => {
    const input = new URLSearchParams(params);
    input.set("source", "run-legacy-source");
    input.set("replay", "run-legacy-replay");
    const before = input.toString();
    expect(readComparisonContext(input)).toEqual({ ...emptySelection, explicit: true, invalid: true });
    expect(input.toString()).toBe(before);
  });

  it.each<ComparisonSelection>([
    emptySelection,
    { runIds: ["run-second", "run-first"], baselineId: "rule-before", revisedId: "" },
    { runIds: ["run & one+%/α", "run-two"], baselineId: "rule & before", revisedId: "rule+after" },
  ])("round-trips the exact ordered selection through URL encoding: %j", selection => {
    const written = writeComparisonContext(new URLSearchParams("source=legacy&replay=older"), selection);
    const restored = readComparisonContext(new URLSearchParams(written.toString()));
    expect(restored).toEqual({ ...selection, explicit: true, invalid: false });
  });

  it("replaces only known context keys and keeps the input and legacy handoffs unchanged", () => {
    const input = new URLSearchParams("source=legacy-source&replay=legacy-replay&method_job=job-one&tag=first&compare_context=0&compare_context=1&compare_run=old&compare_run=old&compare_baseline=old-rule&compare_revised=old-revision&tag=second&compare_note=keep");
    const before = input.toString();
    const selection = { runIds: ["run-second", "run-first"], baselineId: "rule-before", revisedId: "" };
    const selectionBefore = structuredClone(selection);
    const written = writeComparisonContext(input, selection);
    expect(written).not.toBe(input);
    expect(input.toString()).toBe(before);
    expect(selection).toEqual(selectionBefore);
    expect(Array.from(written.entries())).toEqual([
      ["source", "legacy-source"], ["replay", "legacy-replay"], ["method_job", "job-one"],
      ["tag", "first"], ["tag", "second"], ["compare_note", "keep"],
      ["compare_context", "1"], ["compare_run", "run-second"], ["compare_run", "run-first"], ["compare_baseline", "rule-before"],
    ]);
    expect(readComparisonContext(written)).toEqual({ ...selection, explicit: true, invalid: false });
  });

  it("clears only explicit context while retaining legacy recovery and unrelated repeated keys", () => {
    const input = new URLSearchParams("compare_context=1&compare_run=run-one&compare_baseline=rule-before&compare_revised=rule-after&source=legacy-source&replay=legacy-replay&tag=first&tag=second");
    const before = input.toString();
    const cleared = clearComparisonContext(input);
    expect(cleared).not.toBe(input);
    expect(input.toString()).toBe(before);
    expect(Array.from(cleared.entries())).toEqual([["source", "legacy-source"], ["replay", "legacy-replay"], ["tag", "first"], ["tag", "second"]]);
    expect(readComparisonContext(cleared)).toEqual({ runIds: ["legacy-source", "legacy-replay"], baselineId: "", revisedId: "", explicit: false, invalid: false });
  });

  it.each<{ label: string; selection: ComparisonSelection }>([
    { label: "too many runs", selection: { ...emptySelection, runIds: Array.from({ length: 33 }, (_, index) => `run-${index}`) } },
    { label: "duplicate runs", selection: { ...emptySelection, runIds: ["run-one", "run-one"] } },
    { label: "empty run", selection: { ...emptySelection, runIds: [""] } },
    { label: "oversize run", selection: { ...emptySelection, runIds: ["r".repeat(201)] } },
    { label: "control in run", selection: { ...emptySelection, runIds: ["run\u007fone"] } },
    { label: "untrimmed run", selection: { ...emptySelection, runIds: ["run-one "] } },
    { label: "detectors without runs", selection: { runIds: [], baselineId: "rule-before", revisedId: "rule-after" } },
    { label: "baseline with one run", selection: { runIds: ["run-one"], baselineId: "rule-before", revisedId: "" } },
    { label: "revised without baseline", selection: { runIds: ["run-one", "run-two"], baselineId: "", revisedId: "rule-after" } },
    { label: "identical detector IDs", selection: { runIds: ["run-one", "run-two"], baselineId: "rule-same", revisedId: "rule-same" } },
    { label: "oversize baseline", selection: { runIds: ["run-one", "run-two"], baselineId: "b".repeat(201), revisedId: "" } },
    { label: "control in revised ID", selection: { runIds: ["run-one", "run-two"], baselineId: "rule-before", revisedId: "rule\nafter" } },
  ])("refuses to write $label without mutating existing context", ({ selection }) => {
    const input = contextParams(["run-original", "run-retained"], "rule-original");
    input.set("source", "legacy-source");
    const before = input.toString();
    expect(() => writeComparisonContext(input, selection)).toThrow("Invalid comparison selection.");
    expect(input.toString()).toBe(before);
  });
});
