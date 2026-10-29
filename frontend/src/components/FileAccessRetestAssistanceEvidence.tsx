import type { FileAccessRetestAssistanceSummary } from "../lib/file-access-retest-assistance";

export function FileAccessRetestAssistanceEvidence({ summary }: { summary: FileAccessRetestAssistanceSummary }) {
  const { baseline, change, retest, comparison } = summary;
  const decision = (value: string | null) => value === "allowed" ? "Allowed" : value === "permission_denied" ? "Denied" : "Unknown";
  const conclusion = retest.objective_established === null ? "No verified retest conclusion"
    : retest.objective_established ? "Recorded objective established" : "Recorded objective not established";
  return <>
    <div className="assistant-comparison-summary" role="group" aria-label="Saved file-access comparison summary">
      <strong>{conclusion}</strong>
      <p>Historical baseline: both reads allowed. Reviewed mode change: {baseline.mode} → {change.mode}. A mode change alone does not establish denied access.</p>
    </div>
    <details className="assistant-source-details"><summary>Baseline, change and retest evidence</summary>
      <p>Baseline revision {baseline.control_revision}: {baseline.record_count} generated records; non-owner and owner reads allowed. Reviewed hardening revision {change.control_revision}: mode {change.mode}.</p>
      <p>Selected retest: non-owner {decision(retest.non_owner_decision).toLowerCase()}; owner {decision(retest.owner_decision).toLowerCase()}. {retest.record_count === null ? "Retest records are not verified." : `${retest.record_count} recorded retest records.`}</p>
      <p>Content: {comparison.content_preserved === null ? "not verified" : comparison.content_preserved ? "preserved" : "not preserved"}. Attempt cleanup: {comparison.cleanup_verified === null ? "not verified" : comparison.cleanup_verified ? "verified" : "incomplete"}.</p>
      <p>This explains the selected historical comparison only. It does not assess current readiness, repeat a read, change permissions or recover work.</p>
    </details>
  </>;
}
