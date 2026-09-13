import { displayTitle } from "../lib/display-title";
import { useQuery } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../lib/api";
import { comparisonReport } from "../lib/comparison-report";
import { evaluationLabel } from "../lib/detection-results";
import type { MethodProposal, MethodResult, MethodSource } from "../lib/method-comparison";
import { sameJson } from "../lib/replay-review";
import type { ComparisonResponse, DetectionRunEvaluation } from "../types";
import { Callout, ErrorState, LoadingState, Panel, PanelHeader, sentence } from "./Primitives";

function SavedComparisonDownload({ comparison }: { comparison: ComparisonResponse }) {
  const [report, setReport] = useState<{ comparison: ComparisonResponse; url: string }>();
  useEffect(() => {
    const url = URL.createObjectURL(new Blob([comparisonReport(comparison)], { type: "text/markdown;charset=utf-8" }));
    setReport({ comparison, url });
    return () => URL.revokeObjectURL(url);
  }, [comparison]);
  return report?.comparison === comparison ? <a className="button button-secondary button-medium" href={report.url} download="bluefire-method-comparison.md">Download saved run comparison</a> : null;
}

function sourceMatches(actual: DetectionRunEvaluation["source"], expected: MethodSource) {
  return Object.entries(expected).every(([key, value]) => sameJson((actual as unknown as Record<string, unknown>)[key], value));
}

/** Reads an existing comparison only; recovery never creates a new comparison or evaluation. */
export function MethodComparisonResult({ receipt, proposal, replaySource }: { receipt: MethodResult; proposal: MethodProposal; replaySource: MethodSource }) {
  const retained = useQuery({
    queryKey: ["method-comparison-result", receipt, proposal.source_run, proposal.detector, proposal.proposal_digest, replaySource],
    retry: false,
    queryFn: async () => {
      const fail = () => { throw new Error("The retained records do not match this method comparison. Reload the saved operation before reviewing results."); };
      if (receipt.proposal_digest !== proposal.proposal_digest || receipt.source_run_id !== proposal.source_run.run_id ||
        receipt.candidate_id !== proposal.detector.candidate_id || receipt.candidate_definition_digest !== proposal.detector.definition_digest ||
        receipt.child_run_id === receipt.source_run_id || receipt.baseline_evaluation_id === receipt.child_evaluation_id) return fail();
      const [saved, reports] = await Promise.all([api.savedComparison(receipt.comparison_id), api.detectionRunEvaluations(receipt.candidate_id)]);
      const comparison = saved.resource?.document;
      const ids = [receipt.source_run_id, receipt.child_run_id];
      if (saved.resource?.id !== receipt.comparison_id || saved.resource.digest !== receipt.comparison_digest ||
        !comparison || comparison.comparison_id !== receipt.comparison_id || comparison.baseline_run_id !== receipt.source_run_id ||
        !sameJson(comparison.run_ids, ids) || !sameJson(comparison.summaries.map((summary) => summary.run_id), ids)) return fail();
      const left = reports.evaluations.filter((item) => item.evaluation_id === receipt.baseline_evaluation_id);
      const right = reports.evaluations.filter((item) => item.evaluation_id === receipt.child_evaluation_id);
      const baseline = left[0], child = right[0];
      if (left.length !== 1 || right.length !== 1 || !baseline || !child ||
        baseline.candidate.candidate_id !== receipt.candidate_id || baseline.candidate.definition_digest !== receipt.candidate_definition_digest ||
        (baseline.candidate as DetectionRunEvaluation["candidate"] & { resource_digest_at_evaluation?: string }).resource_digest_at_evaluation !== proposal.detector.resource_digest ||
        baseline.candidate.target_language !== proposal.detector.target_language || !sameJson(baseline.candidate, child.candidate) ||
        !sourceMatches(baseline.source, proposal.source_run) || child.source.run_id !== receipt.child_run_id ||
        replaySource.run_id !== receipt.child_run_id || !sourceMatches(child.source, replaySource)) return fail();
      return { comparison, evaluations: [baseline, child] };
    },
  });
  const data = retained.isSuccess ? retained.data : undefined;
  const insufficient = data?.evaluations.some((item) => item.source.observed_count === 0 || ["Not enough evidence", "Engine error"].includes(evaluationLabel(item)));
  return <Panel>
    <PanelHeader eyebrow="Measured method comparison" title="Same detector, two methods" detail={`${displayTitle(proposal.option.title_from)} → ${displayTitle(proposal.option.title)}. Results use the same saved detector definition on the original and replay evidence.`} />
    <div className="detail-body">
      {retained.isPending ? <LoadingState label="Checking retained comparison and evaluations" /> : retained.isError ? <ErrorState title="Comparison results unavailable" error={retained.error} retry={() => { void retained.refetch(); }} /> : data ? <>
        <Callout tone={insufficient ? "warning" : "info"} title={insufficient ? "Not enough evidence to compare detection" : "Exploratory comparison"}>
          <p>These are query results on retained observations, not proof of deployed detection or prevention. Missing observations, gaps, and an engine that did not execute cannot establish defense success. Changing a method can also change the evidence available.</p>
          {data.evaluations.some((item) => item.development_case) ? <p>Includes development evidence used to propose a rule; this is not an independent held-out validation.</p> : null}
        </Callout>
        <div className="detector-comparison-table" role="region" aria-label="Same detector method results" tabIndex={0}>
          <table><caption>Retained evaluations of the same saved detector</caption><thead><tr><th scope="col">Method / run</th><th scope="col">Detector result</th><th scope="col">Observed / all records</th><th scope="col">Evidence gaps</th><th scope="col">Query engine</th></tr></thead>
            <tbody>{data.evaluations.map((item, index) => <tr key={item.evaluation_id}>
              <th scope="row">{index === 0 ? "Original method" : "Replay method"}<small>{displayTitle(index === 0 ? proposal.option.title_from : proposal.option.title)}</small><Link to={`/runs/${encodeURIComponent(item.source.run_id)}`}>Review {index === 0 ? "original" : "replay"} run</Link></th>
              <td><strong>{item.source.observed_count === 0 ? "Not enough evidence" : evaluationLabel(item)}</strong><small>State: {sentence(item.result.state)}</small><small>Matched events: {item.result.match_count === null ? "Not measured" : item.result.match_count}</small><small>Case: {sentence(item.case_role)} (operator declared)</small></td>
              <td>{item.source.observed_count} observed / {item.source.evidence_count} total</td>
              <td>{item.result.gap_count} recorded gaps<small>Missing fields: {item.result.missing_fields.join(", ") || "None reported"}</small></td>
              <td>{item.backend.executed ? "Executed" : "Not executed"}<small>{item.backend.name}{item.backend.version ? ` ${item.backend.version}` : ""}</small></td>
            </tr>)}</tbody>
          </table>
        </div>
        <div className="detector-comparison-table" role="region" aria-label="Method run outcomes" tabIndex={0}>
          <table><caption>Recorded run outcomes</caption><thead><tr><th scope="col">Run</th><th scope="col">Mode</th><th scope="col">Objective</th><th scope="col">First stopped step</th><th scope="col">Cleanup</th></tr></thead>
            <tbody>{data.comparison.summaries.map((run, index) => <tr key={run.run_id}><th scope="row">{index === 0 ? "Original" : "Replay"}</th><td>{run.mode ? sentence(run.mode) : "Not reported"}</td><td>{run.objective_reached === true ? run.mode === "simulate" ? "Achieved (synthetic)" : "Achieved" : run.objective_reached === false ? "Not achieved" : "Not established"}</td><td>{run.first_blocked_step ?? "None recorded"}</td><td>{run.cleanup_success === false ? "Needs attention" : run.cleanup_success === true ? run.mode === "simulate" ? "No real effects" : "Complete" : "Not reported"}</td></tr>)}</tbody>
          </table>
        </div>
        <p className="field-note">The replay covers the full scenario with runtime AI Off. Simulate outcomes are synthetic. This comparison does not isolate every possible cause of a result change.</p>
        <SavedComparisonDownload comparison={data.comparison} />
        <p className="field-note">The download contains the retained run report. The detector evaluations and their evidence are available below.</p>
        <details><summary>Evaluation evidence and limitations</summary>
          <ul>{[...new Set([...proposal.comparison_limitations, ...data.evaluations.flatMap((item) => item.limitations)])].map((limit) => <li key={limit}>{limit}</li>)}</ul>
          {data.evaluations.map((item, index) => <details key={item.evaluation_id}><summary>{index === 0 ? "Original" : "Replay"} evaluation record</summary><pre>{JSON.stringify(item, null, 2)}</pre></details>)}
        </details>
      </> : null}
    </div>
  </Panel>;
}
