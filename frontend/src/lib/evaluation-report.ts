import type { DetectionRunEvaluation, RunRecord } from "../types";
import { activityLabel, compareDetectorEvaluations, evaluationLabel, evaluationUseLabel } from "./detection-results";
import { runLabel } from "./run-presentation";
import { sameJson } from "./replay-review";

export interface EvaluationReportGroup {
  id: string;
  label: string;
  status: "loaded" | "loading" | "unavailable";
  reports: DetectionRunEvaluation[];
}

// Labels are data, not Markdown instructions. Exact originals remain in JSON.
function text(value: unknown): string {
  return String(value).replace(/[\r\n]+/g, " ").replace(/([\\`*_{}[\]<>()#+.!|~-])/g, "\\$1");
}

export function evaluationReportMarkdown(groups: EvaluationReportGroup[], runs: RunRecord[]): string {
  const ids = new Set<string>();
  const retained = new Map<string, DetectionRunEvaluation>();
  groups = groups.map(group => {
    if (!group.id || ids.has(group.id)) throw new Error("The selected revision identities are ambiguous. Reload their histories before exporting.");
    ids.add(group.id);
    const included: DetectionRunEvaluation[] = [];
    if (group.status === "loaded") for (const report of group.reports) {
      if (!report.evaluation_id || report.candidate.candidate_id !== group.id) throw new Error("Loaded reports do not match the selected revision. Reload its history before exporting.");
      const previous = retained.get(report.evaluation_id);
      if (previous && !sameJson(previous, report)) throw new Error("Conflicting retained evaluation identities prevent export. Reload the histories.");
      if (!previous) { retained.set(report.evaluation_id, report); included.push(report); }
    }
    return { ...group, reports: included };
  });
  const loaded = groups.filter(group => group.status === "loaded");
  const reports = loaded.flatMap(group => group.reports);
  if (!reports.length) throw new Error("Load a retained evaluation before downloading its report.");
  const runName = (id: string) => { const run = runs.find(value => value.run_id === id); return run ? runLabel(run) : id; };
  const lines = [`# Detection evaluation report${groups.some(group => group.status !== "loaded") ? " (partial)" : ""}`, "", `${reports.length} retained evaluation record${reports.length === 1 ? "" : "s"} included. This is a snapshot of loaded reports, not an export of draft evaluation inputs.`, ""];
  for (const group of groups) lines.push(`- ${text(group.label)}: ${group.status === "loaded" ? `${group.reports.length} loaded record${group.reports.length === 1 ? "" : "s"}` : `${group.status}; no records from this revision included`}.`);
  if (groups.some(group => group.status !== "loaded")) lines.push("", "**Partial report:** some requested revision history is not loaded. A complete revision comparison is unavailable.");
  lines.push("", "## Measured evaluations", "");
  for (const group of loaded) {
    for (const report of group.reports) {
      const run = runs.find(value => value.run_id === report.source.run_id);
      const supported = !["Engine error", "Not enough evidence"].includes(evaluationLabel(report));
      lines.push(`### ${text(runName(report.source.run_id))} · detector revision ${report.candidate.revision}`, "",
        `- Revision selection: ${text(group.label)}.`,
        `- Source run created: ${text(run?.created_at ?? "Not available in the loaded run list")}.`,
        `- Evaluation recorded: ${text(report.created_at)}.`,
        `- Result: **${text(evaluationLabel(report))}** (${text(report.result.state)}).`,
        `- Matched records: ${supported && report.result.match_count !== null ? `${report.result.match_count} of ${report.result.evaluated_evidence_ids.length} evaluated evidence records` : `No supported match count; ${report.result.evaluated_evidence_ids.length} evaluated evidence IDs recorded`}.`,
        `- Source records: ${report.source.observed_count} observed / ${report.source.evidence_count} total.`,
        `- Activity: ${text(activityLabel(report))} · operator assigned. Data use: ${text(evaluationUseLabel(report))}.`,
        `- Source lineage: ${text(report.classification?.source_lineage ?? "unknown (legacy report)")}.`,
        `- Backend: ${text(report.backend.name)}${report.backend.version ? ` ${text(report.backend.version)}` : ""} · ${report.backend.executed ? "executed" : "not executed"}.`,
        `- Evidence gaps: ${report.result.gap_count}. Missing fields: ${text(report.result.missing_fields.join(", ") || "None reported")}.`,
        `- Diagnostics: ${text(report.result.diagnostic_codes.join(", ") || "None reported")}.`);
      if (report.question) lines.push(`- Recorded question: ${text(report.question)}.`);
      if (report.development_case || report.classification?.evaluation_use === "development") lines.push("- **Development evidence:** this data was used or declared for rule development; it is not an untouched independent test.");
      for (const limitation of report.limitations) lines.push(`- Recorded limit: ${text(limitation)}.`);
      lines.push("");
    }
  }
  if (groups.length === 2 && loaded.length === 2) {
    const [selected, related] = loaded;
    lines.push("## Revision comparison", "", `Related: ${text(related!.label)}. Selected: ${text(selected!.label)}.`, "",
      "| Source run | Related revision | Selected revision | Measured change |", "| --- | --- | --- | --- |");
    const result = (items: DetectionRunEvaluation[]) => items.length ? items.map(item => `${evaluationLabel(item)}; ${item.result.evaluated_evidence_ids.length} evaluated evidence IDs`).map(text).join("; ") : "Not evaluated";
    for (const row of compareDetectorEvaluations(related!.reports, selected!.reports)) lines.push(`| ${text(runName(row.runId))} | ${result(row.baseline)} | ${result(row.revised)} | ${text(row.change)} |`);
    lines.push("");
  }
  lines.push("## Interpretation and coverage limits", "",
    "- These results describe query evaluation on retained observations. They do not establish deployed detection, host prevention or broad attack coverage.",
    "- Missing evaluations, insufficient evidence and backend errors are not negative detection results.",
    "- Activity and independent-data labels are operator declarations. They do not prove independence; recorded development use takes precedence.",
    "- The export includes only the successfully loaded records identified above. It makes no claim that unselected runs, missing telemetry or additional revisions were evaluated.", "",
    "## Details · exact retained records", "",
    "Run names are presentation labels from the loaded run list. Immutable run IDs, evidence and query digests, detector identities, backend details and original report fields are retained below.", "",
    "<details>", "<summary>Immutable report records and export selections</summary>", "", "```json",
    JSON.stringify({ selections: groups.map(group => ({ id: group.id, label: group.label, status: group.status, included_evaluation_ids: group.status === "loaded" ? group.reports.map(report => report.evaluation_id) : [] })), evaluations: reports }, null, 2),
    "```", "", "</details>", "");
  return lines.join("\n");
}
