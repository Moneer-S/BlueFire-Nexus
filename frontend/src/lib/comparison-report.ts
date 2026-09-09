import type { ComparisonResponse } from "../types";

function cell(value: unknown): string {
  return String(value ?? "Not reported").replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replace(/[\\`*[\]|]/g, "\\$&").replace(/[\r\n]+/g, " ");
}

/** A readable export of actual comparison fields, with no inferred defense success. */
export function comparisonReport(comparison: ComparisonResponse, names: Record<string, string> = {}, createdAt: Record<string, string | undefined> = {}): string {
  const rows = comparison.summaries.map((run) => {
    const observed = run.evidence_details?.observed_artifacts;
    const gaps = run.evidence_details?.evidence_gaps;
    return [
      run.run_id === comparison.baseline_run_id ? "Baseline" : "Variant",
      names[run.run_id] ?? run.run_id,
      run.mode,
      run.objective_reached === true ? (run.mode === "simulate" ? "Achieved (synthetic)" : "Achieved") : run.objective_reached === false ? "Not achieved" : "Not established",
      Array.isArray(observed) ? observed.length : "Not reported",
      Array.isArray(gaps) ? gaps.length : "Not reported",
      run.cleanup_success === false ? "Needs attention" : run.cleanup_success === true ? (run.mode === "simulate" ? "No real effects" : "Complete") : "Not reported",
      createdAt[run.run_id] ?? "Not reported",
    ].map(cell).join(" | ");
  });
  const details = comparison.summaries.flatMap((run) => [
    `## ${cell(names[run.run_id] ?? run.run_id)}`,
    "",
    `Run ID: ${cell(run.run_id)}`,
    `Created: ${cell(createdAt[run.run_id])}`,
    "",
    `Profile: ${cell(run.profile_id)}. First stopped step: ${cell(run.first_blocked_step ?? "None recorded")}.`,
    "",
    "| Step | Reported outcome |",
    "| --- | --- |",
    ...run.path.map((step) => `| ${cell(step)} | ${cell(run.outcomes[step])} |`),
    "",
    "Evidence gaps:",
    Array.isArray(run.evidence_details?.evidence_gaps)
      ? run.evidence_details.evidence_gaps.length
        ? run.evidence_details.evidence_gaps.map((gap) => `- ${cell(JSON.stringify(gap))}`).join("\n")
        : "- No gaps recorded."
      : "- Not reported.",
    "",
  ]);
  return [
    "# BlueFire experiment comparison",
    "",
    `Comparison: ${cell(comparison.comparison_id)}`,
    `Baseline: ${cell(comparison.baseline_run_id)}`,
    "",
    "| Role | Run | Mode | Objective | Independently observed items | Recorded gaps | Cleanup | Created |",
    "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ...rows.map((row) => `| ${row} |`),
    "",
    "This report describes the retained run comparison. Simulate outcomes are synthetic. An unmet objective or a stopped step does not establish target prevention. Missing observations do not establish defense success.",
    "",
    "Query evaluations and rule revisions are separate records. Export the selected detector comparison and revised rule from Compare detector results to include those measured results.",
    "",
    ...details,
    "## Comparison record",
    "",
    "The JSON below retains the reported changes, identities, and limitations for further analysis.",
    "",
    "```json",
    JSON.stringify(comparison, null, 2).replaceAll("```", "\\u0060\\u0060\\u0060"),
    "```",
    "",
  ].join("\n");
}


