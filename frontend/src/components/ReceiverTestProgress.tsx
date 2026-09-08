import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import type { ReceiverContext, ReceiverDecision, ReceiverDefenseEnvelope, ReceiverPhase, ReceiverPhaseView } from "../lib/receiver-defense-types";
import { phaseTitle, policyTitle, receiverOutcome } from "../lib/receiver-defense";
import { downloadArtifact } from "../lib/download";
import { savedExperimentPath } from "../lib/receiver-navigation";
import { CanonicalPlanReview } from "./CanonicalPlanReview";
import { RunWorkspace } from "./RunWorkspace";
import { Button, Callout, DataList, Field } from "./Primitives";

type PrepareRequest = { submission_id: string; phase: ReceiverPhase; reviewed_by: string };
const phaseDescription = {
  baseline: "Start a fresh receiver that accepts reviewed synthetic records, then run the selected experiment.",
  protected: "Start a fresh receiver that requires redaction. Replay the same staged bytes to measure whether this policy refuses them.",
  restored: "Start another fresh receiver with the original policy. Replay again to check whether restoring the policy restores acceptance.",
};
export function ReceiverTestProgress({ envelope, disabled: externalDisabled, onPrepare, onReview }: {
  envelope: ReceiverDefenseEnvelope & { context: ReceiverContext }; disabled: boolean; onPrepare: (body: PrepareRequest) => void; onReview: (body: ReceiverDecision) => void;
}) {
  const [executionStopRequested, setExecutionStopRequested] = useState(false);
  const disabled = externalDisabled || executionStopRequested;
  const current = envelope.phases.find((item) => item.phase === envelope.next_action.phase);
  const [reviewer, setReviewer] = useState("");
  const [acknowledged, setAcknowledged] = useState(false);
  const [now, setNow] = useState(Date.now);
  const reviewKey = `${current?.phase}:${current?.preparation?.preparation_digest ?? ""}`;
  const focusKey = `${reviewKey}:${envelope.next_action.kind}`;
  const heading = useRef<HTMLHeadingElement>(null), workspace = useRef<HTMLElement>(null);
  const priorKey = useRef(focusKey);
  useEffect(() => {
    setReviewer(""); setAcknowledged(false);
  }, [reviewKey]);
  useEffect(() => {
    if (priorKey.current !== focusKey && (document.activeElement === document.body || workspace.current?.contains(document.activeElement))) heading.current?.focus({ preventScroll: true });
    priorKey.current = focusKey;
  }, [focusKey]);
  useEffect(() => {
    if (!current?.preparation || current.execution_job) return;
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [current?.preparation, current?.execution_job]);
  const preparation = current?.preparation;
  const remaining = preparation ? Math.max(0, Math.ceil((preparation.session.expires_at_ms - now) / 1000)) : 0;
  const canReview = current?.review_ready && envelope.next_action.kind === "review_replay" && Boolean(preparation) && remaining > 0 && !disabled;
  const results = envelope.phases.filter((phase) => phase.result);
  const baseline = envelope.phases.find((phase) => phase.phase === "baseline")?.result;
  const protectedResult = envelope.phases.find((phase) => phase.phase === "protected")?.result;
  const restored = envelope.phases.find((phase) => phase.phase === "restored")?.result;
  const complete = envelope.status === "completed";
  const cleanupSettled = current && ["not_started", "verified_closed"].includes(current.cleanup.receiver) && ["not_started", "complete"].includes(current.cleanup.run);
  const prepare = () => { if (current?.prepare_allowed && !disabled && reviewer.trim()) onPrepare({ submission_id: crypto.randomUUID(), phase: current.phase, reviewed_by: reviewer.trim() }); };
  const review = (decision: "accept" | "reject") => {
    if (current && preparation && canReview && reviewer.trim() && (decision === "reject" || acknowledged)) onReview({ submission_id: crypto.randomUUID(), phase: current.phase, preparation_digest: preparation.preparation_digest, decision, reviewed_by: reviewer.trim() });
  };
  return <section className="receiver-progress" aria-label="Receiver control test" ref={workspace}>
    {executionStopRequested && envelope.status !== "stopped" ? <Callout tone="warning" title="Checking receiver shutdown">Cancellation was requested through this test's run. New phase preparation and release stay disabled while the saved owner, run and cleanup are reconciled. The test's Stop control remains available if the response was uncertain.</Callout> : null}
    <div className="receiver-context"><strong>{envelope.context.scenario_title}</strong><span>Version {envelope.context.selection.version} · Execute · {envelope.context.run_intent.target_scope.scope_refs.join(", ")}</span><Link to={savedExperimentPath(envelope.context.selection, envelope.job.job_id)}>Inspect saved experiment</Link></div>
    <ol className="receiver-phases" aria-label="Control test phases">{envelope.phases.map((phase, index) => <li key={phase.phase} aria-current={current?.phase === phase.phase ? "step" : undefined}>
      <span className="receiver-phase-number" aria-hidden="true">{index + 1}</span><div><strong>{phaseTitle[phase.phase]}</strong><p>{receiverOutcome(phase)}</p></div>
    </li>)}</ol>
    {results.length ? <section className="receiver-results" aria-label="Measured receiver outcomes"><h2>{complete ? "Measured control outcome" : "Results so far"}</h2>
      <p>Receiver acceptance and prevention are separate from detection. Missing or unverified receiver evidence leaves the outcome unknown.</p>
      <div className="receiver-table-scroll"><table><caption>Same experiment, separately prepared receiver policies</caption><thead><tr><th scope="col">Phase</th><th scope="col">Receiver policy</th><th scope="col">Observed outcome</th><th scope="col">Cleanup</th><th scope="col">Evidence</th></tr></thead><tbody>{results.map((phase) => <tr key={phase.phase}><th scope="row">{phaseTitle[phase.phase]}</th><td>{policyTitle[phase.policy_id]}</td><td><strong>{receiverOutcome(phase)}</strong></td><td><CleanupSummary phase={phase} /></td><td><Link to={`/runs/${encodeURIComponent(phase.result!.run_id)}`}>Inspect run</Link></td></tr>)}</tbody></table></div>
      <div className="receiver-actions"><Button variant={complete ? "primary" : "secondary"} onClick={() => downloadReceiverReport(envelope)}>Download control report</Button>{baseline && protectedResult ? <Link className="button button-secondary button-medium" to={`/compare?${new URLSearchParams({ source: baseline.run_id, replay: protectedResult.run_id })}`}>Compare baseline and protected run</Link> : null}{baseline && restored ? <Link className="button button-secondary button-medium" to={`/compare?${new URLSearchParams({ source: baseline.run_id, replay: restored.run_id })}`}>Check restoration against baseline</Link> : null}</div>
    </section> : null}
    {current ? <section className="receiver-current" aria-label="Current test phase">
      <h2 ref={heading} tabIndex={-1}>{phaseTitle[current.phase]}</h2>
      <p>{phaseDescription[current.phase]}</p>
      {current.problem ? <Callout tone="warning" title="This phase needs attention">{current.problem.message}</Callout> : null}
      {envelope.next_action.kind === "prepare_receiver" ? <>
        <DataList items={[{ label: "Receiver policy", value: policyTitle[current.policy_id] }, { label: "Lifetime", value: "One decision in a short-lived, memory-only receiver" }, { label: "Experiment actions", value: "Wait for separate review and fresh run approval" }]} />
        <p>Preparing starts the bounded receiver in the owned lab. It can expire while you review. A replacement is available only after BlueFire verifies shutdown of the previous receiver.</p>
        <Field label="Prepared by"><input autoComplete="off" maxLength={128} value={reviewer} onChange={(event) => setReviewer(event.target.value)} /></Field>
        <Button variant="primary" disabled={disabled || !current.prepare_allowed || !reviewer.trim()} onClick={prepare}>Prepare {current.phase === "protected" ? "protected" : current.phase === "restored" ? "restored" : "baseline"} receiver</Button>
      </> : null}
      {preparation && !current.execution_job && envelope.next_action.kind === "review_replay" ? <>
        <div className="receiver-review-summary"><strong>{current.phase === "baseline" ? "Review the baseline run" : "Review the policy change and replay"}</strong><p>{current.phase === "protected" ? "Accept reviewed records → Require redacted records" : current.phase === "restored" ? "Require redacted records → Accept reviewed records" : "The deliberately permissive baseline accepts authenticated, reviewed synthetic records."}</p><p>{current.phase === "baseline" ? "The actual staged artifact is bound when the approved handoff runs." : "Replay must match the staged artifact independently recorded in the baseline."}</p></div>
        <p className="receiver-expiry">{remaining ? `Receiver review expires in ${Math.floor(remaining / 60)}:${String(remaining % 60).padStart(2, "0")}.` : "This receiver review has expired. Wait for verified cleanup before preparing a fresh receiver."}</p>
        {preparation.preflight.plan ? <CanonicalPlanReview plan={preparation.preflight.plan} scope={preparation.preflight.scope} cleanup={preparation.preflight.cleanup} binding={preparation.preflight.approval_binding} envelope={preparation.preflight.approval_envelope} /> : <Callout title="Run plan unavailable">This preparation cannot be accepted without the complete run review.</Callout>}
        <label className="check-row"><input type="checkbox" checked={acknowledged} disabled={!canReview} onChange={(event) => setAcknowledged(event.target.checked)} /><span>I reviewed this receiver policy and the complete run plan.</span></label>
        <Field label="Reviewed by"><input autoComplete="off" maxLength={128} value={reviewer} disabled={!canReview} onChange={(event) => setReviewer(event.target.value)} /></Field>
        <p>Accepting saves this review and creates the ordinary run job. Fresh Execute approval remains a separate step here before experiment actions start.</p>
        <div className="receiver-actions"><Button variant="primary" disabled={!canReview || !preparation.preflight.plan || !acknowledged || !reviewer.trim()} onClick={() => review("accept")}>Accept and review run approval</Button><Button disabled={!canReview || !reviewer.trim()} onClick={() => review("reject")}>Decline this phase</Button></div>
      </> : null}
      {current.execution_job && (!current.result || !["completed", "failed", "interrupted", "cancelled"].includes(current.execution_job.state)) ? <RunWorkspace key={current.execution_job.job_id} embedded={{ job: current.execution_job, onCancelRequested: () => setExecutionStopRequested(true), controlsEnabled: !disabled && envelope.status === "active", releaseEnabled: !disabled && envelope.status === "active" && envelope.next_action.kind === "approve_execute" }} /> : null}
      {envelope.next_action.kind === "wait" ? <p role="status">{current.status === "preparing" ? "Preparing and checking the owned receiver…" : "Waiting for saved execution evidence and cleanup…"}</p> : null}
      {envelope.next_action.kind === "cleanup_required" ? <Callout tone="warning" title={cleanupSettled ? "This phase cannot continue" : "Cleanup must be confirmed"}><CleanupSummary phase={current} /><p>{cleanupSettled ? "Inspect the retained review and outcome. A separate test becomes available when the service confirms that all owned work is settled." : "A new receiver or replay stays unavailable while the previous session or run is uncertain."}</p></Callout> : null}
    </section> : null}
    {envelope.status === "stopping" ? <Callout title="Stopping and checking cleanup">Cancellation is requested. Keep this saved test available until the receiver and run shutdown are confirmed.</Callout> : null}
    {envelope.status === "stopped" ? <Callout title="Control test stopped">This test cannot resume. Its recorded phases remain available; an unfinished phase is not a successful defense test. After the service confirms cleanup, use Set up another control test to start separately.</Callout> : null}
    <details className="receiver-records"><summary>Phase history, evidence and exact review records</summary>{envelope.phases.map((phase) => <section key={phase.phase}><h3>{phaseTitle[phase.phase]}</h3><CleanupSummary phase={phase} />{phase.attempts.length ? <p>{phase.attempts.length} earlier preparation attempt{phase.attempts.length === 1 ? "" : "s"} retained. Earlier reviews cannot approve a replacement.</p> : null}<pre>{JSON.stringify(phase, null, 2)}</pre></section>)}</details>
    <details><summary>Supported scope and limitations</summary><ul>{envelope.limitations.map((item, index) => <li key={index}>{item}</li>)}</ul><p>This experiment measures a local receiver's policy. It does not establish general prevention coverage or detection quality.</p></details>
  </section>;
}

function CleanupSummary({ phase }: { phase: ReceiverPhaseView }) {
  const cleanup = phase.cleanup;
  const receiver = cleanup.receiver === "verified_closed" ? "Receiver shutdown verified" : cleanup.receiver === "not_started" ? "Receiver not started" : cleanup.receiver === "active" ? "Receiver active" : "Receiver shutdown uncertain";
  const run = cleanup.run === "complete" ? "Run cleanup complete" : cleanup.run === "not_started" ? "Run not started" : cleanup.run === "incomplete" ? "Run cleanup incomplete" : cleanup.run === "pending" ? "Run cleanup pending" : "Run cleanup unknown";
  return <span className="receiver-cleanup"><span>{receiver}</span><span>{run}</span></span>;
}

function downloadReceiverReport(envelope: ReceiverDefenseEnvelope & { context: ReceiverContext }) {
  const lines = ["# Receiver control test", "", envelope.context.scenario_title, "", `Status: ${envelope.status}`, "", "This local lab experiment uses a deliberately permissive baseline and fresh receiver sessions. It measures prevention separately from detection.", ""];
  for (const phase of envelope.phases) {
    lines.push(`## ${phaseTitle[phase.phase]}`, "", `Policy: ${policyTitle[phase.policy_id]}`, `Outcome: ${receiverOutcome(phase)}`, `Receiver cleanup: ${phase.cleanup.receiver}; run cleanup: ${phase.cleanup.run}`, "");
    if (phase.result) lines.push(`Run: ${phase.result.run_id}`, "", "```json", JSON.stringify(phase.result, null, 2), "```", "");
  }
  lines.push("## Limitations", "", ...envelope.limitations.map((item) => `- ${item}`), "", "Unverified or missing evidence is not a prevention pass. No general detection or prevention coverage is established.", "");
  downloadArtifact(new Blob([lines.join("\n")], { type: "text/markdown;charset=utf-8" }), `${envelope.job.job_id}-receiver-control.md`);
}
