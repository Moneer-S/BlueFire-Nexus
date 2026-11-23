import { useQuery } from "@tanstack/react-query";
import { ArrowRight, CircleHelp, MessageSquareText, ShieldCheck } from "lucide-react";
import { useMemo } from "react";
import { Link } from "react-router-dom";
import type { CompositionAttempt, CompositionObjective } from "../lib/composition";
import { checkedFileAccessRetestLinkage, fileAccessLinkageApi } from "../lib/file-access-linkage";
import { fileAccessRetestSelection } from "../lib/file-access-retest-assistance";
import { useAssistancePanel, usePublishFileAccessRetestSelection } from "../state/AssistanceContext";
import { Button, DataList, ErrorState, LoadingState } from "./Primitives";

export function FileAccessRetestComparison({ objective, attempt }: { objective: CompositionObjective; attempt: CompositionAttempt }) {
  const binding = attempt.request.composition_attempt;
  const query = useQuery({
    queryKey: ["file-access-retest-linkage", objective.owner.job_id, binding.attempt_id, attempt.state, attempt.progress.verified_result_digest ?? null],
    queryFn: async () => checkedFileAccessRetestLinkage(await fileAccessLinkageApi.read(objective.owner.job_id, binding.attempt_id), objective, attempt),
    retry: false,
  });
  const assistance = useAssistancePanel();
  const selection = useMemo(() => query.isSuccess && !query.isFetching
    ? fileAccessRetestSelection(query.data, objective, attempt) : undefined, [query.isSuccess, query.isFetching, query.data, objective, attempt]);
  usePublishFileAccessRetestSelection(selection);
  if (query.error) return <ErrorState title="Saved comparison unavailable" error={query.error} retry={() => { void query.refetch(); }} />;
  if (!query.data) return <LoadingState label="Opening baseline and retest evidence" />;
  const { baseline, change, retest, comparison, control_owner_id: control, linkage_digest: linkageDigest } = query.data;
  const established = comparison.state === "established";
  const unknown = comparison.state === "unknown";
  const conclusion = established ? "Non-owner access blocked; owner access preserved"
    : unknown ? "The retest has no verified conclusion yet" : "The expected access change was not established";
  const decision = (value: string | null) => value === "allowed" ? "Allowed" : value === "permission_denied" ? "Denied" : "Unknown";
  const controlLink = (operation: string) => `/file-access?${new URLSearchParams({ control, operation })}`;
  return <section className={`file-access-retest-comparison${established ? " is-established" : ""}`} aria-label="Baseline and fresh retest">
    <div className="file-access-retest-heading">
      {established ? <ShieldCheck aria-hidden="true" /> : <CircleHelp aria-hidden="true" />}
      <div><p className="file-access-retest-kicker">Baseline → fresh retest</p><h3>{conclusion}</h3>
        <p>{established ? `${baseline.record_count} generated records retained the same content in the owner's fresh read.`
          : unknown ? "The original baseline and reviewed change remain available. Missing retest evidence is not a preventive result."
            : "Review the recorded reads and cleanup below before drawing a broader conclusion."}</p>
      </div>
    </div>
    <table className="file-access-retest-table">
      <caption>Read results for the same generated resource</caption>
      <thead><tr><th scope="col">Identity</th><th scope="col">Baseline</th><th scope="col">Fresh retest</th></tr></thead>
      <tbody>
        <tr><th scope="row">Non-owner test identity</th><td>Allowed</td><td className={retest.non_owner_decision === "permission_denied" ? "access-denied" : undefined}>{decision(retest.non_owner_decision)}</td></tr>
        <tr><th scope="row">Resource owner</th><td>Allowed</td><td>{decision(retest.owner_decision)}</td></tr>
      </tbody>
    </table>
    <div className="file-access-retest-support">
      <div><span>Reviewed permission change</span><strong><code>{baseline.mode}</code><ArrowRight aria-hidden="true" /><code>{change.mode}</code></strong><small>Recorded for this retest, revision {change.control_revision}.</small></div>
      <div><span>Content</span><strong>{comparison.content_preserved === true ? "Preserved" : comparison.content_preserved === false ? "Changed" : "Not verified"}</strong><small>{retest.record_count === null ? "Awaiting verified read evidence." : `${retest.record_count} records in the retest.`}</small></div>
      <div><span>Test cleanup</span><strong>{comparison.cleanup_verified === true ? "Verified" : comparison.cleanup_verified === false ? "Needs review" : "Not verified"}</strong><small>{comparison.cleanup_verified === true ? "Run cleaned and probe request closed." : retest.request_cleanup === "verified_closed" ? "Probe request closed; run cleanup incomplete." : "Run and request closure remain unverified."}</small></div>
    </div>
    <p className="file-access-retest-retention">This comparison preserves the recorded permission change. Cleanup does not roll it back; later control changes do not rewrite these results.</p>
    <Button variant="secondary" disabled={!selection || !assistance} onClick={() => { if (selection) assistance?.setOpen(true); }}><MessageSquareText aria-hidden="true" />Explain this comparison</Button>
    <nav className="file-access-retest-links" aria-label="Comparison source records">
      <Link to={controlLink(baseline.operation_job_id)}>Baseline reads<ArrowRight aria-hidden="true" /></Link>
      <Link to={controlLink(change.operation_job_id)}>Reviewed change<ArrowRight aria-hidden="true" /></Link>
      {retest.state === "verified" || attempt.progress.finalized_run_id === retest.run_id
        ? <Link to={`/runs/${encodeURIComponent(retest.run_id)}`}>Retest run<ArrowRight aria-hidden="true" /></Link>
        : <span>Retest run is not finalized.</span>}
    </nav>
    <details className="file-access-retest-provenance"><summary>Evidence identity and recorded state</summary><DataList items={[
      { label: "Comparison digest", value: <code>{linkageDigest}</code> },
      { label: "Resource generation", value: <code>{baseline.resource_generation}</code> },
      { label: "Baseline revision", value: baseline.control_revision },
      { label: "Baseline content", value: <code>{baseline.sha256}</code> },
      { label: "Retest content", value: retest.sha256 ? <code>{retest.sha256}</code> : "Not verified" },
      { label: "Retest result", value: retest.result_digest ? <code>{retest.result_digest}</code> : "Not verified" },
      { label: "Run cleanup", value: retest.run_cleanup ?? "Not verified" },
      { label: "Probe request", value: retest.request_cleanup ?? "Not verified" },
    ]} /></details>
  </section>;
}
