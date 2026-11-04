import { ArrowRight, CircleHelp, ShieldAlert, ShieldCheck, TriangleAlert } from "lucide-react";
import type { EngineDefenseChange, EngineExperimentConclusion } from "../lib/engine-experiment";
import { Badge, Callout, DataList, Panel, sentence } from "./Primitives";

export interface EngineComparisonConclusion {
  title: string;
  detail: string;
  tone: "success" | "warning" | "danger" | "info";
}

export interface EngineSourceRunLink {
  label: string;
  runId: string;
}

const securityConclusion = (value: EngineExperimentConclusion): EngineComparisonConclusion => {
  switch (value.headline) {
    case "original_mechanism_still_succeeds":
      return { title: "The original mechanism still works", detail: "The independent reproducer did not establish prevention.", tone: "danger" };
    case "original_blocked_legitimate_use_failed":
      return { title: "The change disrupted legitimate use", detail: "Review or roll back the defensive change before treating this result as an improvement.", tone: "danger" };
    case "original_blocked_alternate_path_found":
      return { title: "Original route blocked; another path remains", detail: "The retained reproducer was prevented, while a fresh adaptive attempt found a different observed route toward the objective.", tone: "warning" };
    case "original_blocked_no_remaining_path_observed_within_limits":
      return { title: "Original route blocked; bounded search found no new path", detail: "Legitimate use passed. No remaining path was observed within the recorded limits, which is not proof that no other path exists.", tone: "warning" };
    case "original_blocked_legitimate_use_unknown":
      return { title: "Original route blocked; legitimate use remains unknown", detail: "The defense result is incomplete until the legitimate-use control is established.", tone: "warning" };
    case "original_blocked_adaptive_result_unknown":
      return { title: "Original route blocked; adaptive result remains unknown", detail: "The exact reproducer was prevented, but the fresh search did not establish whether another route remains.", tone: "warning" };
    case "inconclusive_retest":
      return { title: "The original mechanism retest is inconclusive", detail: "The baseline mechanism was established, but the fresh independent reproducer did not establish prevention or continued success.", tone: "warning" };
    case "inconclusive_original_mechanism":
      return { title: "The original mechanism was not established", detail: "A defense conclusion requires an independently established baseline mechanism.", tone: "info" };
  }
};

export function engineComparisonConclusion(value: EngineExperimentConclusion): EngineComparisonConclusion {
  if (value.defense.state === "unknown" || value.defense.current_target_snapshot_ref === null) return { title: "Current target state needs reconciliation", detail: "Recorded outcomes remain available as history, but they cannot establish the target’s current state after an uncertain defensive operation.", tone: "warning" };
  const conclusion = securityConclusion(value);
  if (conclusion.tone === "danger" || value.headline === "original_blocked_alternate_path_found") return conclusion;
  if (value.cleanup.status === "residue") return { title: "Retest recorded; cleanup left residue", detail: "Keep the security result and retained worker or target effects separate. Review cleanup evidence before disposition.", tone: "danger" };
  if (value.cleanup.status === "unknown") return { title: "Retest recorded; cleanup remains unknown", detail: "Worker or target cleanup is not established, so the experiment is not fully settled.", tone: "warning" };
  if (value.cleanup.status === "pending" || value.cleanup.status === "not_started") return { title: "Retest recorded; cleanup is not complete", detail: "Wait for verified cessation or review an explicit cleanup result before disposition.", tone: "warning" };
  if (value.telemetry_health.status !== "complete" && value.headline === "original_blocked_no_remaining_path_observed_within_limits") return { title: "Original route blocked; observation is incomplete", detail: "Missing target-side telemetry means an absent adaptive finding cannot establish that no route was observed.", tone: "warning" };
  return conclusion;
}

const conclusionSourceRuns = (value: EngineExperimentConclusion): EngineSourceRunLink[] => {
  const candidates: Array<EngineSourceRunLink | null> = [
    value.original_mechanism.run_id ? { label: "Baseline exploration run", runId: value.original_mechanism.run_id } : null,
    value.retained_reproducer.run_id ? { label: "Original mechanism retest run", runId: value.retained_reproducer.run_id } : null,
    value.adaptive_search.run_id ? { label: "Fresh adaptive search run", runId: value.adaptive_search.run_id } : null,
    value.legitimate_use.run_id ? { label: "Legitimate-use check run", runId: value.legitimate_use.run_id } : null,
  ];
  const seen = new Set<string>();
  return candidates.filter((candidate): candidate is EngineSourceRunLink => {
    if (!candidate || seen.has(candidate.runId)) return false;
    seen.add(candidate.runId);
    return true;
  });
};

const originalLabel = (value: EngineExperimentConclusion["original_mechanism"]["status"]): string => ({ not_attempted: "Not attempted", established: "Established", not_established: "Not established", unknown: "Unknown" })[value];
const reproducerLabel = (value: EngineExperimentConclusion["retained_reproducer"]["status"]): string => ({ not_attempted: "Not attempted", still_succeeds: "Still succeeds", blocked: "Blocked", not_established: "Not established", unknown: "Unknown" })[value];
const adaptiveLabel = (value: EngineExperimentConclusion["adaptive_search"]["status"]): string => ({ not_attempted: "Not attempted", remaining_path_found: "Remaining path found", no_path_observed_within_limits: "No path observed within limits", inconclusive: "Inconclusive", pending: "Pending" })[value];
const legitimateUseLabel = (value: EngineExperimentConclusion["legitimate_use"]["status"]): string => ({ not_attempted: "Not attempted", passed: "Passed", failed: "Failed", unknown: "Unknown" })[value];

export function EngineRetestComparison({ conclusion: value, defensiveChange, sourceRuns, runHref = runId => `/runs/${encodeURIComponent(runId)}`, comparisonHref }: { conclusion: EngineExperimentConclusion; defensiveChange: EngineDefenseChange | null; sourceRuns?: EngineSourceRunLink[]; runHref?: (runId: string) => string; comparisonHref?: string }) {
  const conclusion = engineComparisonConclusion(value);
  const runs = sourceRuns ?? conclusionSourceRuns(value);
  const Icon = conclusion.tone === "success" ? ShieldCheck : conclusion.tone === "danger" ? ShieldAlert : conclusion.tone === "warning" ? TriangleAlert : CircleHelp;
  const observationIncomplete = value.telemetry_health.status !== "complete";
  const cleanupUnsettled = value.cleanup.status !== "verified_absent";
  return <Panel className={`engine-retest-comparison is-${conclusion.tone}`} aria-label="Attack, defense and fresh retest conclusion">
    <header className="engine-comparison-conclusion"><Icon aria-hidden="true" /><div><p>Attack → defense → fresh retest</p><h2>{conclusion.title}</h2><span>{conclusion.detail}</span></div></header>
    {observationIncomplete ? <Callout tone="warning" title="Observation is incomplete"><p>Verified {value.telemetry_health.verified_sources.length} of {value.telemetry_health.expected_sources.length} expected telemetry sources. An absent engine finding cannot be interpreted as prevention.</p>{value.telemetry_health.missing_sources.length ? <p>Missing: {value.telemetry_health.missing_sources.join(", ")}.</p> : null}</Callout> : null}
    {cleanupUnsettled ? <Callout tone={value.cleanup.status === "residue" ? "danger" : "warning"} title={value.cleanup.status === "residue" ? "Cleanup left residue" : "Cleanup is not verified"}><p>{value.cleanup.status === "not_started" ? "Cleanup has not started." : value.cleanup.status === "pending" ? "Cleanup is still pending." : value.cleanup.status === "unknown" ? "Worker or target cleanup is unknown." : "Owned worker or target effects remain."}</p></Callout> : null}
    <div className="engine-comparison-grid">
      <article><span>Original mechanism</span><strong>{originalLabel(value.original_mechanism.status)}</strong><Badge tone={value.original_mechanism.status === "established" ? "success" : value.original_mechanism.status === "not_established" ? "danger" : "warning"}>Independent baseline</Badge></article>
      <article><span>Original mechanism retest</span><strong>{reproducerLabel(value.retained_reproducer.status)}</strong><Badge tone={value.retained_reproducer.status === "blocked" ? "success" : value.retained_reproducer.status === "still_succeeds" ? "danger" : "warning"}>Exact reproducer</Badge></article>
      <article><span>Fresh adaptive search</span><strong>{adaptiveLabel(value.adaptive_search.status)}</strong><Badge tone={value.adaptive_search.status === "remaining_path_found" ? "warning" : value.adaptive_search.status === "no_path_observed_within_limits" ? "info" : "neutral"}>New attempt</Badge></article>
      <article><span>Legitimate use</span><strong>{legitimateUseLabel(value.legitimate_use.status)}</strong><Badge tone={value.legitimate_use.status === "passed" ? "success" : value.legitimate_use.status === "failed" ? "danger" : "warning"}>Independent control</Badge></article>
    </div>
    {defensiveChange ? <div className="engine-defense-summary"><div><span>{sentence(defensiveChange.kind)} change</span><strong>{defensiveChange.summary}</strong></div><Badge tone={["applied", "retained"].includes(defensiveChange.state) ? "success" : defensiveChange.state === "unknown" ? "warning" : "neutral"}>{sentence(defensiveChange.state)}</Badge></div> : <Callout tone="warning" title="Defensive change unavailable"><p>No reviewed change is linked to this comparison.</p></Callout>}
    {value.unknowns.length ? <details className="engine-comparison-unknowns" open><summary>Unknowns and unattempted work</summary><ul>{value.unknowns.map(item => <li key={item}>{item}</li>)}</ul></details> : null}
    {runs.length || comparisonHref ? <nav className="engine-comparison-links" aria-label="Comparison source runs">{runs.map(source => <a href={runHref(source.runId)} key={source.runId}>{source.label}<ArrowRight aria-hidden="true" /></a>)}{comparisonHref ? <a href={comparisonHref}>Open full comparison<ArrowRight aria-hidden="true" /></a> : null}</nav> : <Callout tone="warning" title="Supporting runs unavailable"><p>The conclusion has no linked run route to inspect.</p></Callout>}
    <details><summary>Recorded change and proof boundary</summary><DataList items={[
      { label: "Defensive state", value: sentence(value.defense.state) },
      { label: "Telemetry health", value: sentence(value.telemetry_health.status) },
      { label: "Cleanup", value: sentence(value.cleanup.status) },
      { label: "Change identity", value: defensiveChange?.change_id ?? value.defense.change_id ?? "Not recorded" },
      { label: "Rollback plan", value: defensiveChange?.rollback_digest ? <code>{defensiveChange.rollback_digest}</code> : "Not recorded" },
      { label: "Application receipt", value: value.defense.application_receipt_ref ? <code>{value.defense.application_receipt_ref}</code> : "Not recorded" },
      { label: "Reconciliation receipt", value: value.defense.reconciliation_receipt_ref ? <code>{value.defense.reconciliation_receipt_ref}</code> : "Not recorded" },
      { label: "Rollback operation", value: value.defense.rollback_operation_ref ? <code>{value.defense.rollback_operation_ref}</code> : "Not recorded" },
      { label: "Rollback receipt", value: value.defense.rollback_receipt_ref ? <code>{value.defense.rollback_receipt_ref}</code> : "Not recorded" },
      { label: "Current target snapshot", value: value.defense.current_target_snapshot_ref ?? "Not established" },
    ]} /></details>
  </Panel>;
}
