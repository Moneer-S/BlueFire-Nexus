import { Link } from "react-router-dom";
import type { ReceiverAssistanceProgress } from "../lib/receiver-assistance";
import { AssistantRunReference } from "./AssistantRunReference";
import { sentence } from "./Primitives";

const phaseNames = { baseline: "Baseline", protected: "Protected", restored: "Restoration" };
const decisions = { accepted: "Receiver accepted the records", policy_refused: "Receiver policy refused the records", insufficient_evidence: "Receiver decision is not established" };
const count = (value: number | null) => value === null ? "Unknown" : String(value);
/** Native receipts are evidence; model text is separately labelled interpretation. */
export function ReceiverAssistantProgress({ progress, onNavigate, showNativeLink = false }: { progress: ReceiverAssistanceProgress; onNavigate: () => void; showNativeLink?: boolean }) {
  return <section className="assistant-receiver" aria-label="Receiver evidence and analysis">
    <h4>{progress.owns_lifecycle ? "Control test and evidence" : "Selected test · evidence analysis"}</h4>
    <p>{progress.owns_lifecycle ? "The saved test holds the reviewed settings. Preparing each receiver and approving each Execute run remain your explicit actions." : "This request analyses its selected evidence prefix. It does not own or stop the receiver test; later phases remain separate native work."}</p>
    {showNativeLink ? <Link className="button button-secondary button-medium" onClick={onNavigate} to={progress.native_path}>Open control test and phase comparison</Link> : null}
    <ol className="assistant-receiver-phases">{progress.phases.map((phase) => <li key={phase.phase}>
      <strong>{phaseNames[phase.phase]}</strong>
      <span>{phase.result ? decisions[phase.result.decision] : sentence(phase.status)}</span>
      {phase.result ? <><small>Receiver cleanup: {sentence(phase.cleanup.receiver)} · Run cleanup: {sentence(phase.cleanup.run)}</small><AssistantRunReference runId={phase.result.run_id} label={`${phaseNames[phase.phase]} run`} onNavigate={onNavigate}/></> : null}
    </li>)}</ol>
    {[...progress.inspections].reverse().map((item, index) => <details className="assistant-receiver-analysis" key={item.job.job_id} open={index === 0} aria-label={`Receiver analysis ${progress.inspections.length - index}`}>
      <summary>{index === 0 ? "Latest analysis" : "Earlier analysis"} · through {phaseNames[item.phases[item.phases.length - 1]!.phase].toLowerCase()}</summary>
      {item.interpretation ? <><p className="assistant-model-label">Model interpretation · {item.interpretation.provider.model} · {item.interpretation.provider.provider_id}</p><p>{item.interpretation.summary}</p><ul>{item.interpretation.findings.map((finding, findingIndex) => <li key={findingIndex}><p>{finding.claim}</p><small>Evidence: {finding.evidence_refs.join(" · ")}</small></li>)}</ul><p><strong>Suggested next step: </strong>{item.interpretation.next_phase ? `${phaseNames[item.interpretation.next_phase]} phase` : "No further phase suggested"}. {item.interpretation.reason}</p><p className="assistant-model-label">Advice does not prepare a receiver or approve a run. Native readiness and review determine what can happen next.</p>{item.interpretation.limitations.length ? <details><summary>Analysis limitations</summary><ul>{item.interpretation.limitations.map((line, n) => <li key={n}>{line}</li>)}</ul></details> : null}</> : <p role="status">{["failed", "interrupted", "cancelled"].includes(item.job.state) ? "This analysis has no retained interpretation. Existing runs and evidence remain available; recovery does not replay effects." : "Reading the verified phase evidence…"}</p>}
      <details><summary>Verified facts supplied to this analysis</summary>{item.phases.map((phase) => <div key={phase.phase} className="assistant-receiver-facts"><strong>{phaseNames[phase.phase]}</strong><dl><dt>Receiver decision</dt><dd>{decisions[phase.decision]}</dd><dt>Handoff transport</dt><dd>{sentence(phase.transport_state)}</dd><dt>Records / retained / redacted</dt><dd>{count(phase.record_count)} / {count(phase.retained_record_count)} / {count(phase.redacted_record_count)}</dd><dt>Same artifact as baseline</dt><dd>{phase.artifact_matches_baseline === null ? "Unknown" : phase.artifact_matches_baseline ? "Yes" : "No"}</dd><dt>Cleanup at observation</dt><dd>Receiver: {sentence(phase.receiver_cleanup)} · Run: {sentence(phase.run_cleanup)}</dd><dt>Evidence reference</dt><dd>{phase.evidence_ref}</dd><dt>Immutable result digest</dt><dd>{phase.result_digest}</dd></dl></div>)}</details>
    </details>)}
    <p className="assistant-model-label">Restoration uses a fresh baseline-policy receiver. This controlled development test does not establish host rollback or effectiveness in a deployed environment.</p>
  </section>;
}
