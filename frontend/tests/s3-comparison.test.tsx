import { render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { expect, it } from "vitest";
import capture from "../../tests_platform/fixtures/s3_comparison_v1.json";
import { S3AccessComparisonResults } from "../src/components/S3AccessComparison";
import { checkedComparisonResponse, checkedS3AccessComparison } from "../src/lib/s3-comparison";
import { ComparisonResult } from "../src/pages/Compare";
import type { ComparisonResponse, S3AccessComparison } from "../src/types";

const cases = (capture as unknown as { cases: Array<{ name: string; response: ComparisonResponse }> }).cases;
function response(name: string): ComparisonResponse {
  const selected = cases.find((item) => item.name === name)?.response;
  if (!selected) throw new Error(`The backend capture is missing ${name}.`);
  return selected;
}
function projection(name: string): S3AccessComparison {
  const captured = response(name);
  const value = captured.s3_access;
  if (!value) throw new Error(`The backend capture has no S3 projection for ${name}.`);
  return checkedS3AccessComparison(value, captured.run_ids);
}

it.each([
  "paired_denied", "baseline_only", "retest_only", "partial_selection", "reversed_selection",
  "missing_context", "unchanged_probe", "legitimate_denied", "failed_legitimate",
  "failed_assume_role", "not_started", "unknown_cleanup", "mixed_provenance",
])("accepts the actual backend comparison capture for %s without rewriting its response", (name) => {
  const captured = response(name);
  if (!captured.s3_access) throw new Error(`The backend capture has no S3 projection for ${name}.`);
  expect(checkedComparisonResponse(captured)).toBe(captured);
  expect(checkedS3AccessComparison(captured.s3_access, captured.run_ids)).toBe(captured.s3_access);
});

it("accepts the actual paired S3 comparison capture and preserves its fixed read-purpose ordering", () => {
  const value = projection("paired_denied");
  expect(value.state).toBe("paired");
  if (value.state !== "paired") throw new Error("The paired capture is not paired.");
  expect(value.rows.map(({ reader, purpose }) => [reader, purpose])).toEqual([
    ["probe", "primary"], ["legitimate", "primary"], ["legitimate", "health"],
  ]);
  expect(value.proof_scope).toBe("saved_read_results_only");
  expect(value.effective_access_claim).toBe(false);
  expect(value.defensive_effectiveness_claim).toBe(false);
  expect(() => checkedS3AccessComparison(value, ["run_not_in_comparison"])).toThrow("S3 access comparison is invalid");
});

it.each(["wrong row identity", "unsupported claim", "invalid digest"])("rejects a malformed captured S3 projection: %s", (change) => {
  const original = projection("paired_denied");
  if (original.state !== "paired") throw new Error("The paired capture is not paired.");
  let malformed: Record<string, unknown>;
  if (change === "wrong row identity") {
    malformed = { ...original, rows: [...original.rows].reverse() };
  } else if (change === "unsupported claim") {
    malformed = { ...original, defensive_effectiveness_claim: true };
  } else malformed = { ...original, source_digest: "sha256:invalid" };
  expect(() => checkedS3AccessComparison(malformed)).toThrow("S3 access comparison is invalid");
});

it.each(["phase summary", "phase run ordering", "comparison run binding", "cross-phase run reuse"])("rejects a captured projection with inconsistent %s", (change) => {
  const original = projection("paired_denied");
  if (original.state !== "paired") throw new Error("The paired capture is not paired.");
  let malformed: Record<string, unknown>;
  if (change === "phase summary") {
    malformed = { ...original, baseline: { ...original.baseline!, selection_complete: false } };
  } else if (change === "phase run ordering") {
    malformed = { ...original, baseline: { ...original.baseline!, run_ids: [...original.baseline!.run_ids].reverse() } };
  } else if (change === "comparison run binding") {
    malformed = { ...original, baseline: { ...original.baseline!, run_ids: ["run_unselected"] } };
  } else {
    const runId = original.baseline!.run_ids[0];
    if (runId === undefined) throw new Error("The paired baseline has no selected run.");
    malformed = { ...original, retest: { ...original.retest!, run_ids: [runId, ...original.retest!.run_ids.slice(1)] } };
    const rows = [...original.rows] as typeof original.rows;
    const probe = rows[0];
    rows[0] = { ...probe, retest: { ...probe.retest, run_id: runId } };
    malformed.rows = rows;
  }
  expect(() => checkedS3AccessComparison(malformed)).toThrow("S3 access comparison is invalid");
});

it("rejects malformed S3 bindings without rewriting the comparison response identity", () => {
  const captured = response("paired_denied");
  const projectionValue = captured.s3_access;
  if (!projectionValue || projectionValue.state !== "paired") throw new Error("The paired capture is not paired.");
  const malformed = {
    ...captured,
    s3_access: { ...projectionValue, baseline: { ...projectionValue.baseline!, selection_complete: false } },
  };
  expect(checkedComparisonResponse(captured)).toBe(captured);
  expect(() => checkedComparisonResponse(malformed)).toThrow("S3 access comparison is invalid");
});

it("renders captured run links and reports synthetic/runner provenance and cleanup without inference", () => {
  const value = projection("paired_denied");
  if (value.state === "unavailable") throw new Error("The paired capture is unavailable.");
  render(<MemoryRouter><S3AccessComparisonResults result={value} /></MemoryRouter>);
  const region = screen.getByRole("region", { name: "S3 baseline and retest outcomes" });
  expect(within(region).getByRole("table").querySelector("caption")).toHaveTextContent("Read results by purpose");
  expect(screen.getByRole("link", { name: "Open saved S3 exercise" })).toHaveAttribute("href", expect.stringContaining("/s3-access?exercise="));
  const expectedRunLinks = new Set(value.rows.flatMap((row) => [row.baseline.run_id, row.retest.run_id]).filter((id): id is string => id !== null).map((id) => `/runs/${encodeURIComponent(id)}`));
  const actualRunLinks = new Set(Array.from(region.querySelectorAll<HTMLAnchorElement>('a[href^="/runs/"]')).map((link) => link.getAttribute("href")!));
  expect(actualRunLinks).toEqual(expectedRunLinks);
  for (const row of value.rows) for (const result of [row.baseline, row.retest]) {
    if (result.run_id) expect(region).toHaveTextContent(result.provenance === "synthetic" ? "Synthetic" : "Runner reported");
    expect(region).toHaveTextContent(result.cleanup === null ? "Cleanup: Not recorded" : `Cleanup: ${result.cleanup === "verified" ? "Verified" : "Unknown"}`);
  }
  expect(screen.getByText(/does not establish defensive effectiveness/i)).toBeVisible();
  expect(screen.getByText(/Legitimate-use checks stay visible alongside probe results/i)).toBeVisible();
  expect(screen.getByRole("heading", { name: "S3 access outcomes" })).toBeVisible();
  expect(region).not.toHaveTextContent(/prevention rate|coverage percentage|effectiveness percentage/i);
});

it("keeps unknown cleanup and unavailable projection distinct from task-level no-change language", () => {
  const comparison = response("unknown_cleanup");
  const unknown = projection("unknown_cleanup");
  if (unknown.state === "unavailable") throw new Error("The unknown-cleanup capture must be available.");
  expect(unknown.change_state).toBe("unknown");
  const view = render(<MemoryRouter><ComparisonResult comparison={comparison} /></MemoryRouter>);
  expect(screen.getByRole("region", { name: "S3 access comparison" })).toHaveTextContent("Unknown");
  expect(screen.getByRole("region", { name: "S3 access comparison" })).toHaveTextContent("Cleanup: Unknown");
  expect(screen.getByRole("region", { name: "S3 access comparison" })).toHaveTextContent("Cleanup unresolved");
  expect(screen.getByText(/S3 saved read results are shown separately/)).toBeVisible();
  expect(screen.getByText(/with meaningful recorded changes/)).toBeVisible();
  expect(screen.queryByText("No meaningful change reported against the baseline.")).not.toBeInTheDocument();

  const unavailable = projection("missing_context");
  if (unavailable.state !== "unavailable") throw new Error("The missing-context capture must be unavailable.");
  expect(unavailable.reason).toBe("saved_context_unavailable");
  view.unmount();
  render(<MemoryRouter><ComparisonResult comparison={response("missing_context")} /></MemoryRouter>);
  expect(screen.getByRole("region", { name: "S3 access comparison" })).toHaveTextContent("Saved S3 comparison is unavailable: Saved context unavailable");
  expect(screen.getByText(/S3 saved read results are shown separately/)).toBeVisible();
  expect(screen.queryByText("No meaningful change reported against the baseline.")).not.toBeInTheDocument();
});
