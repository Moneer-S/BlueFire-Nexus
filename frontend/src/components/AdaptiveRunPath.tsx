import { displayTitle } from "../lib/display-title";
import type { CatalogResponse, RunRecord } from "../types";
import { adaptiveRecords, decisionObservations, decisionOrigin, decisionProvenance, dispatchDescription, recordedMethodName, recordedPathNodes, selectedAttempt, type RuntimeRecord } from "../lib/adaptive-run";
import { stepOutcomeLabel } from "../lib/run-presentation";
import { DataList, sentence } from "./Primitives";
import "./AdaptiveRunPath.css";

export function AdaptiveRunPath({ run, catalog }: { run: RunRecord; catalog: CatalogResponse }) {
  const decisions = adaptiveRecords(run);
  if (!decisions.length) return null;
  const nodes = recordedPathNodes(run);
  return <section className="adaptive-run-path" aria-label="Recorded adaptive path">
    <header><h2>Methods tried</h2><p>Each node keeps its recorded attempts. A chosen method needs a matching runner result before execution is established.</p></header>
    <ol className="adaptive-path-nodes">{nodes.map(node => <li key={node.stepId} className="adaptive-path-node"><h3>{displayTitle(catalog.behaviors.find(item => item.id === node.attempts[0]?.step.behavior_id)?.title ?? "Recorded step")}</h3>
      <ol aria-label="Attempts at this step">{node.attempts.map(({ step, index }, attemptIndex) => <li key={index}>
        <span>Attempt {attemptIndex + 1} · run position {index + 1}</span><strong>{recordedMethodName(catalog, step.behavior_id, step.action_id)}</strong>
        <p>{stepOutcomeLabel(step, run.mode)} · {dispatchDescription(step, run)}</p>
        <small>{(run.evidence?.records ?? []).filter(item => item.evidence_id && step.evidence_ids?.includes(item.evidence_id) && item.provenance === "observed").length} independently observed records</small>
        {node.decisions.filter(record => decisionOrigin(run, record) === index).map((record, number) => <AdaptiveDecision key={String(record.proposal_record_id ?? number)} run={run} record={record} catalog={catalog} />)}
      </li>)}</ol>
    </li>)}</ol>
    <p className="field-note">Nodes follow their first recorded visit; attempt positions preserve the execution order. The objective and independent observations remain separate from method selection.</p>
    {decisions.filter(record => decisionOrigin(run, record) < 0).map((record, index) => <div key={index}><p>A decision could not be linked to its original attempt.</p><AdaptiveDecision run={run} record={record} catalog={catalog} /></div>)}
  </section>;
}

export function AdaptiveDecision({ run, record, catalog }: { run: RunRecord; record: RuntimeRecord; catalog: CatalogResponse }) {
  const proposed = record.proposal, attempted = selectedAttempt(run, record);
  const provenance = decisionProvenance(record), observations = decisionObservations(run, record);
  const applied = record.application_status === "applied_reviewed_method";
  const method = proposed?.selected_action_id ? recordedMethodName(catalog, proposed.selected_behavior_id, proposed.selected_action_id) : null;
  return <section className="adaptive-path-decision" aria-label="Recorded adaptive decision">
    <strong>{method ? `${applied ? "Chosen" : "Proposed"} alternative: ${method}` : "No alternative selected"}</strong>
    <p>{applied ? attempted ? dispatchDescription(attempted, run) : "Selection applied; no matching attempt is recorded." : sentence(String(record.application_status ?? "Decision recorded"))}</p>
    <p>{provenance.label}{record.application_reason ? ` · ${String(record.application_reason)}` : ""}</p>
    {proposed?.rationale ? <p>{proposed.rationale}</p> : null}
    <details aria-label="Recorded observations at this decision"><summary>Recorded observations at this decision</summary>
      {!observations.available ? <p>This record does not contain a matching, readable observation summary for this attempt.</p> : <>
        <p>These observations were retained when this decision was recorded. They do not establish what a provider received or whether the objective was achieved.</p>
        <DataList items={[
          { label: "Records retained", value: observations.evidence.length },
          { label: "Missing evidence records", value: observations.missing },
          { label: "Evidence records omitted from this summary", value: observations.omitted },
          { label: "Earlier attempts omitted from this summary", value: observations.omittedAttempts },
          { label: "Telemetry gap", value: observations.telemetryGap === true ? "Reported" : observations.telemetryGap === false ? "Not reported by this attempt" : "Unknown; not recorded" },
        ]}/>
        {observations.evidence.length ? <ol aria-label="Retained observation records">{observations.evidence.map((item, index) => <li key={item.evidence_id}>
          <strong>Record {index + 1} · {item.label}</strong>
          {item.facts === null ? <p>The recorded facts are unreadable or outside the supported format.</p> : item.facts.length ? <DataList items={item.facts}/> : <p>No normalized facts were retained for this record.</p>}
          <details><summary>Record identity</summary><DataList items={[{ label: "Evidence ID", value: <code>{item.evidence_id}</code> }, { label: "Recorded hash", value: <code>{item.record_hash}</code> }]}/></details>
        </li>)}</ol> : <p>No evidence records were retained in this summary. This does not establish that nothing happened.</p>}
      </>}
    </details>
    <details><summary>Decision, observations and limits</summary><DataList items={[
      { label: "Provider", value: provenance.provider }, { label: "Model", value: provenance.model },
      { label: "Observed result", value: sentence(String(record.outcome ?? "not recorded")) },
      { label: "Failure classification", value: sentence(String(observations.classification ?? "unknown")) },
      { label: "Remaining execution limits", value: `${observations.budgets.steps ?? "Unknown"} steps · ${observations.budgets.seconds ?? "Unknown"} seconds · ${observations.budgets.retries ?? "Unknown"} retries` },
      { label: "Evidence references", value: observations.evidence.map(item => String(item.evidence_id)).join(", ") || "None retained in this projection" },
    ]}/>{observations.unknowns.length ? <ul>{observations.unknowns.map((unknown, index) => <li key={index}>{unknown}</li>)}</ul> : <p>Observation limitations were not retained.</p>}<details><summary>Exact decision record</summary><pre>{JSON.stringify(record, null, 2)}</pre></details></details>
  </section>;
}
