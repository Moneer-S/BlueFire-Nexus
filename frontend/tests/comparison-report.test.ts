import { expect, it } from "vitest";
import { comparisonReport } from "../src/lib/comparison-report";
import { compareDemoRuns, demoRuns } from "../src/lib/demo";

it("exports unmet objectives, unknown evidence and failed cleanup without substituting success", () => {
  const comparison = compareDemoRuns(demoRuns.map((run) => run.run_id));
  const run = comparison.summaries[0]!;
  run.objective_reached = false;
  run.evidence_details = undefined;
  run.cleanup_success = false;
  const report = comparisonReport(comparison, { [run.run_id]: "Compare retained records" });
  expect(report).toContain(`| Baseline | Compare retained records | ${run.mode} | Not achieved | Not reported | Not reported | Needs attention |`);
  expect(report).toContain(`Run ID: ${run.run_id}`);
  expect(report).toContain("Simulate outcomes are synthetic");
  expect(report).toContain("Missing observations do not establish defense success");
  expect(report).toContain(comparison.comparison_id);
  expect(report).toContain('"objective_reached": false');
});

it("keeps untrusted gap content inert in the readable report and preserves it in JSON", () => {
  const comparison = compareDemoRuns(demoRuns.map((run) => run.run_id));
  const untrusted = '<img src="https://example.invalid/pixel"> ``` [remote](https://example.invalid)';
  comparison.summaries[0]!.evidence_details = { observed_artifacts: [], evidence_gaps: [{ reason: untrusted }] };
  const report = comparisonReport(comparison, { [comparison.summaries[0]!.run_id]: untrusted });
  const [readable, json] = report.split("```json\n");
  expect(readable).not.toContain("<img");
  expect(readable).not.toContain("[remote]");
  expect(JSON.parse(json!.slice(0, json!.lastIndexOf("\n```"))).summaries[0].evidence_details.evidence_gaps[0].reason).toBe(untrusted);
});
