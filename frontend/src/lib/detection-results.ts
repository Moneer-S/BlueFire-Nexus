import type { DetectionRunEvaluation } from "../types";

export interface DetectorComparisonRow {
  runId: string;
  baseline: DetectionRunEvaluation[];
  revised: DetectionRunEvaluation[];
  roles: string[];
  change: string;
}

export function evaluationLabel(report: DetectionRunEvaluation): string {
  if (report.result.state === "backend_error") return "Engine error";
  if (report.result.state === "insufficient_evidence" || !report.backend.executed || report.result.match_count === null || report.result.gap_count > 0 || report.result.missing_fields.length > 0) return "Not enough evidence";
  return report.result.state === "matched" ? `${report.result.match_count} matched event${report.result.match_count === 1 ? "" : "s"}` : "No matches";
}

function sourceKey(report: DetectionRunEvaluation): string {
  return JSON.stringify([report.source.manifest_digest, report.source.evidence_digest, [...report.result.evaluated_evidence_ids].sort()]);
}

function outcomeKey(report: DetectionRunEvaluation): string {
  return JSON.stringify([report.result.state, report.result.match_count, [...report.result.matched_evidence_ids].sort(), evaluationLabel(report)]);
}

export function compareDetectorEvaluations(baseline: DetectionRunEvaluation[], revised: DetectionRunEvaluation[], runIds?: string[]): DetectorComparisonRow[] {
  const selected = runIds ? new Set(runIds) : undefined;
  const ids = [...new Set([...baseline, ...revised].map((report) => report.source.run_id))].filter((id) => !selected || selected.has(id));
  // Include runs with no evaluation on either side. Missing results must stay visible.
  for (const id of runIds ?? []) if (!ids.includes(id)) ids.push(id);
  return ids.map((runId) => {
    const left = baseline.filter((report) => report.source.run_id === runId);
    const right = revised.filter((report) => report.source.run_id === runId);
    const all = [...left, ...right];
    const roles = [...new Set(all.map(activityLabel))];
    let change = "Evaluate both revisions";
    if (left.length && right.length) {
      if (new Set(all.map(sourceKey)).size !== 1) change = "Different evidence — review separately";
      else if (all.some((report) => ["Engine error", "Not enough evidence"].includes(evaluationLabel(report)))) change = "Not enough evidence to compare";
      else if (new Set(left.map(outcomeKey)).size > 1 || new Set(right.map(outcomeKey)).size > 1) change = "Results differ across evaluations";
      else if (roles.length !== 1) change = "Case labels differ — review context";
      else if (outcomeKey(left[0]!) === outcomeKey(right[0]!)) change = "Same measured matches";
      else if (left[0]!.result.state === "not_matched" && right[0]!.result.state === "matched") change = roles[0] === "benign" ? "New match in a declared benign case" : "New match";
      else if (left[0]!.result.state === "matched" && right[0]!.result.state === "not_matched") change = roles[0] === "benign" ? "Declared benign match removed" : "Previously matched event missed";
      else change = "Matched events changed";
    }
    return { runId, baseline: left, revised: right, roles, change };
  });
}

// Legacy role values describe mixed dimensions; they never establish independence.
export function activityLabel(report: DetectionRunEvaluation): string {
  return report.classification?.activity_label ?? (["attack", "benign"].includes(report.case_role) ? report.case_role : "unknown");
}

export function evaluationUseLabel(report: DetectionRunEvaluation): string {
  if (report.development_case || report.classification?.evaluation_use === "development") return "Development data";
  if (report.classification?.evaluation_use === "independent") return "Independent test data · operator declared";
  return "Data use unknown";
}
