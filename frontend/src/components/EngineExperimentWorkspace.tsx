import { ArrowRight, Bot, CircleCheck, CircleDashed, ExternalLink, FlaskConical, Gauge, RotateCcw, ShieldCheck, Square, TriangleAlert } from "lucide-react";
import { useId } from "react";
import {
  engineAttemptLabel,
  engineControllerCheckLabel,
  engineControllerCheckStateLabel,
  engineStateLabel,
  engineWorkflowLabel,
  type EngineControllerCheck,
  type EngineExperiment,
  type EngineProjectionAttempt,
  type EngineProjectionCheck,
  type EngineWorkspaceActionKind,
  type EngineWorkflowState,
} from "../lib/engine-experiment";
import { Badge, Button, Callout, DataList, Panel, formatDate, sentence } from "./Primitives";
import { EngineAttemptEvidence } from "./EngineAttemptEvidence";
import { EngineRetestComparison, type EngineSourceRunLink } from "./EngineRetestComparison";
import "./EngineExperimentWorkspace.css";

export interface EngineExperimentWorkspaceProps {
  experiment: EngineExperiment;
  selectedAttemptId?: string | null;
  selectedCheckId?: string | null;
  onSelectAttempt: (attemptId: string) => void;
  onSelectCheck?: (checkId: string) => void;
  onPrimaryAction?: (action: EngineWorkspaceActionKind) => void;
  onCancelAttempt?: (attemptId: string) => void;
  onCancelCheck?: (checkId: string) => void;
  runHref?: (runId: string) => string;
  comparisonHref?: string;
}

const activeAttemptState = (state: string) => ["queued", "preflight", "running", "stopping"].includes(state);
const activeCheckState = (state: string) => state === "reserved";
const stateTone = (state: string, cleanup: string): "neutral" | "info" | "success" | "warning" | "danger" => {
  if (cleanup === "residue") return "danger";
  if (cleanup === "unknown") return "warning";
  if (["failed", "unknown"].includes(state)) return "danger";
  if (["partial", "budget_exhausted", "cancelled", "stopping"].includes(state)) return "warning";
  if (state === "completed") return "success";
  if (activeAttemptState(state) || activeCheckState(state)) return "info";
  return "neutral";
};

const checkObservationLabel = (category: EngineControllerCheck["observations"][number]["category"]) => ({
  independent_target_effect: "Independent target effect",
  independent_security_outcome: "Checked security outcome",
  legitimate_use: "Legitimate-use result",
})[category];

function AttemptSelector({ attempt, selected, onSelect, runHref }: { attempt: EngineProjectionAttempt; selected: boolean; onSelect: () => void; runHref: (runId: string) => string }) {
  return <li className={selected ? "is-selected" : undefined}>
    <button type="button" aria-pressed={selected} onClick={onSelect}>
      <span className="engine-attempt-marker"><Bot aria-hidden="true" /></span>
      <span><strong>{engineAttemptLabel(attempt.role)}</strong><small>{engineStateLabel(attempt)}</small></span>
      <Badge tone={stateTone(attempt.state, attempt.cleanup.state)}>{sentence(attempt.state)}</Badge>
    </button>
    <a href={runHref(attempt.run_id)} aria-label={`Open ${engineAttemptLabel(attempt.role)} run`}><ExternalLink aria-hidden="true" /></a>
  </li>;
}

function ControllerCheckCard({ check, detail, selected, runHref, onSelect, onCancel }: { check: EngineProjectionCheck; detail?: EngineControllerCheck; selected: boolean; runHref: (runId: string) => string; onSelect?: () => void; onCancel?: (checkId: string) => void }) {
  return <Panel className={`engine-check-card${selected ? " is-selected" : ""}`}>
    <header><span className="engine-check-icon"><ShieldCheck aria-hidden="true" /></span><div><p>Trusted controller check</p><h3>{engineControllerCheckLabel(check.role)}</h3></div><Badge tone={stateTone(check.state, check.cleanup.state)}>{engineControllerCheckStateLabel(check)}</Badge></header>
    <p>{check.role === "retained_reproducer" ? "Repeats the retained mechanism without assigning model or engine authorship." : "Verifies the intended workflow separately from the attack objective."}</p>
    {detail?.observations.length ? <ul>{detail.observations.map(observation => <li key={observation.evidence_id}><strong>{checkObservationLabel(observation.category)}</strong><span>{observation.summary}</span><details><summary>Evidence identity and limits</summary><code>{observation.evidence_id}</code><p>{observation.limitations.length ? observation.limitations.join(" ") : "No additional limitation was recorded."}</p></details></li>)}</ul> : selected ? <Callout tone="warning" title="No checked outcome yet"><p>This controller operation has not established its result.</p></Callout> : null}
    <footer><a href={runHref(check.run_id)}>Inspect run evidence<ArrowRight aria-hidden="true" /></a><span>{onSelect ? <Button type="button" size="small" variant="secondary" aria-pressed={selected} onClick={onSelect}>{selected ? "Selected" : `Review ${engineControllerCheckLabel(check.role).toLowerCase()}`}</Button> : null}{check.state === "reserved" && onCancel ? <Button type="button" size="small" variant="danger" onClick={() => onCancel(check.check_id)}><Square aria-hidden="true" />Cancel check</Button> : null}</span></footer>
    <details><summary>Controller source and custody</summary><DataList items={[
      { label: "Performer", value: check.performer },
      { label: "Input", value: <code>{check.input_digest}</code> },
      { label: "Result", value: check.result_digest ? <code>{check.result_digest}</code> : "Not recorded" },
      { label: "Target snapshot", value: <code>{check.target_snapshot_ref}</code> },
      { label: "Mechanism", value: <code>{check.mechanism_ref}</code> },
      { label: "Cleanup", value: sentence(check.cleanup.state) },
    ]} /></details>
  </Panel>;
}

const currentPhase = (workflow: EngineWorkflowState, phase: string): boolean => ({
  baseline: ["ready_for_baseline", "baseline_active"],
  verification: ["review_defense"],
  defense: ["apply_defense", "reconcile_defense"],
  reproducer: ["run_retained_reproducer", "retained_reproducer_active"],
  adaptive: ["run_adaptive_search", "adaptive_search_active"],
  legitimate: ["run_legitimate_use", "legitimate_use_active"],
  comparison: ["choose_defense_disposition", "complete"],
}[phase]?.includes(workflow) ?? false);

export function EngineExperimentWorkspace({ experiment, selectedAttemptId, selectedCheckId, onSelectAttempt, onSelectCheck, onPrimaryAction, onCancelAttempt, onCancelCheck, runHref = runId => `/runs/${encodeURIComponent(runId)}`, comparisonHref }: EngineExperimentWorkspaceProps) {
  const titleId = useId();
  const { projection } = experiment;
  const ambiguousSelection = Boolean(selectedAttemptId && selectedCheckId);
  const selectedAttemptSummary = !ambiguousSelection && selectedAttemptId ? projection.attempts.find(item => item.attempt_id === selectedAttemptId) : undefined;
  const selectedCheckSummary = !ambiguousSelection && selectedCheckId ? projection.checks.find(item => item.check_id === selectedCheckId) : undefined;
  const explicitAttemptMissing = Boolean(selectedAttemptId) && !selectedAttemptSummary;
  const explicitCheckMissing = Boolean(selectedCheckId) && !selectedCheckSummary;
  const contextAttempt = experiment.selected_context?.kind === "engine_attempt" ? experiment.selected_context.attempt : undefined;
  const contextCheck = experiment.selected_context?.kind === "controller_check" ? experiment.selected_context.check : undefined;
  const selectedAttempt = ambiguousSelection ? undefined : (selectedAttemptId ? contextAttempt?.attempt_id === selectedAttemptId ? contextAttempt : undefined : !selectedCheckId ? contextAttempt : undefined);
  const selectedCheck = ambiguousSelection ? undefined : (selectedCheckId ? contextCheck?.check_id === selectedCheckId ? contextCheck : undefined : !selectedAttemptId ? contextCheck : undefined);
  const selectedAttemptProjection = selectedAttempt ? projection.attempts.find(item => item.attempt_id === selectedAttempt.attempt_id) : undefined;
  const selectedAttemptKey = selectedAttemptId ?? selectedAttempt?.attempt_id;
  const selectedCheckKey = selectedCheckId ?? selectedCheck?.check_id;
  const baseline = projection.attempts.find(attempt => attempt.role === "baseline");
  const adaptive = projection.attempts.find(attempt => attempt.role === "adaptive_search");
  const reproducer = projection.checks.find(check => check.role === "retained_reproducer");
  const legitimate = projection.checks.find(check => check.role === "legitimate_use");
  const sourceRuns: EngineSourceRunLink[] = [
    baseline ? { label: "Baseline exploration run", runId: baseline.run_id } : null,
    reproducer ? { label: "Original mechanism retest run", runId: reproducer.run_id } : null,
    adaptive ? { label: "Fresh adaptive search run", runId: adaptive.run_id } : null,
    legitimate ? { label: "Legitimate-use check run", runId: legitimate.run_id } : null,
  ].filter((item): item is EngineSourceRunLink => item !== null);
  const activeAttempt = projection.attempts.find(attempt => activeAttemptState(attempt.state));
  const activeCheck = projection.checks.find(check => activeCheckState(check.state));
  const primaryAction = experiment.actions.find(action => action.primary);
  const baselineEvidence = baseline ? projection.observations.filter(item => item.attempt_id === baseline.attempt_id) : [];
  const phaseState = (available: boolean, current: boolean, complete: boolean) => current ? "Current" : complete ? "Recorded" : available ? "Available" : "Pending";
  const phases = [
    { key: "baseline", label: "Baseline exploration", state: phaseState(Boolean(baseline), currentPhase(projection.workflow_state, "baseline"), Boolean(baseline && !activeAttemptState(baseline.state))), icon: FlaskConical },
    { key: "verification", label: "Independent verification", state: phaseState(Boolean(baselineEvidence.length), currentPhase(projection.workflow_state, "verification"), Boolean(baselineEvidence.length)), icon: CircleCheck },
    { key: "defense", label: "Defensive change", state: phaseState(Boolean(experiment.defensive_change), currentPhase(projection.workflow_state, "defense"), Boolean(experiment.defensive_change && ["applied", "retained", "rolled_back"].includes(experiment.defensive_change.state))), icon: ShieldCheck },
    { key: "reproducer", label: "Original mechanism retest", state: phaseState(Boolean(reproducer), currentPhase(projection.workflow_state, "reproducer"), Boolean(reproducer && !activeCheckState(reproducer.state))), icon: RotateCcw },
    { key: "adaptive", label: "Fresh adaptive search", state: phaseState(Boolean(adaptive), currentPhase(projection.workflow_state, "adaptive"), Boolean(adaptive && !activeAttemptState(adaptive.state))), icon: Bot },
    { key: "legitimate", label: "Legitimate-use check", state: phaseState(Boolean(legitimate), currentPhase(projection.workflow_state, "legitimate"), Boolean(legitimate && !activeCheckState(legitimate.state))), icon: ShieldCheck },
    { key: "comparison", label: "Comparison and disposition", state: phaseState(true, currentPhase(projection.workflow_state, "comparison"), projection.workflow_state === "complete"), icon: Gauge },
  ];

  return <section className="engine-experiment-workspace" aria-labelledby={titleId}>
    <header className="engine-workspace-header">
      <div className="engine-workspace-title"><p>Defense experiment</p><h1 id={titleId}>{experiment.objective.title}</h1><span>{experiment.objective.summary}</span><div><Badge tone="info">{sentence(experiment.environment.platform)}</Badge><Badge tone="neutral">{experiment.environment.display_name}</Badge>{experiment.engine_setup.model.test_provider ? <Badge tone="warning">Labeled test provider</Badge> : <Badge tone="violet">{experiment.engine_setup.engine.display_name}</Badge>}</div></div>
      <div className="engine-workspace-actions"><div><span>Workflow</span><strong>{engineWorkflowLabel(projection.workflow_state)}</strong></div><div><span>Revision</span><strong>{experiment.revision.toLocaleString()}</strong></div>{primaryAction ? <Button type="button" variant="primary" disabled={!primaryAction.enabled || !onPrimaryAction} onClick={() => onPrimaryAction?.(primaryAction.kind)}>{primaryAction.label}<ArrowRight aria-hidden="true" /></Button> : null}{activeAttempt && activeAttempt.state !== "stopping" && onCancelAttempt ? <Button type="button" variant="danger" onClick={() => onCancelAttempt(activeAttempt.attempt_id)}><Square aria-hidden="true" />Cancel attempt</Button> : activeAttempt?.state === "stopping" ? <Button type="button" disabled><Square aria-hidden="true" />Stopping</Button> : null}</div>
    </header>
    {primaryAction?.reason ? <Callout tone={primaryAction.enabled ? "info" : "warning"} title={primaryAction.enabled ? "Next useful action" : "Action not available"}><p>{primaryAction.reason}</p></Callout> : null}
    {experiment.current_target === null ? <Callout tone="warning" title="Current target state is not established"><p>BlueFire preserved the earlier evidence, but it cannot treat that history as proof of the target’s current state. Reconcile the defensive operation before starting another effect or drawing a current-state conclusion.</p></Callout> : null}
    {activeCheck ? <p className="engine-active-check" role="status">Trusted check in progress: <strong>{engineControllerCheckLabel(activeCheck.role)}</strong></p> : null}
    <ol className="engine-phase-rail" aria-label="Experiment phases">{phases.map((phase, index) => <li className={phase.state === "Current" ? "is-current" : phase.state === "Recorded" ? "is-recorded" : undefined} key={phase.key}><span>{index + 1}</span><phase.icon aria-hidden="true" /><div><strong>{phase.label}</strong><small>{phase.state}</small></div></li>)}</ol>

    <div className="engine-workspace-layout">
      <div className="engine-workspace-main">
        <Panel className="engine-attempt-panel"><header className="engine-section-heading"><div><span>Model-driven work</span><h2>Engine attempts</h2></div><Badge>{projection.attempts.length}</Badge></header>{projection.attempts.length ? <ul className="engine-attempt-selector">{projection.attempts.map(attempt => <AttemptSelector key={attempt.attempt_id} attempt={attempt} selected={selectedAttemptKey === attempt.attempt_id} onSelect={() => onSelectAttempt(attempt.attempt_id)} runHref={runHref} />)}</ul> : <p className="engine-evidence-note">No external-engine attempt has been admitted.</p>}</Panel>
        {ambiguousSelection ? <Callout tone="warning" title="Selection is ambiguous"><p>Select either one engine attempt or one trusted check.</p></Callout> : explicitAttemptMissing ? <Callout tone="warning" title="Selected attempt is unavailable"><p>The route refers to an attempt that is not part of this saved experiment. Choose a recorded engine attempt to continue.</p></Callout> : selectedAttemptId && !selectedAttempt ? <Callout tone="warning" title="Selected attempt details are unavailable"><p>Reload this exact attempt context before reviewing its findings and artifacts.</p></Callout> : null}
        {selectedAttempt ? <Panel className="engine-selected-attempt"><header><div><p>Selected engine attempt</p><h2>{engineAttemptLabel(selectedAttempt.role)}</h2><span>{engineStateLabel(selectedAttempt)}. Review completeness and independent observations before drawing a conclusion.</span></div><Badge tone={stateTone(selectedAttempt.state, selectedAttempt.cleanup.state)}>{sentence(selectedAttempt.completeness)}</Badge></header><div className="engine-attempt-stats"><div><span>State</span><strong>{sentence(selectedAttempt.state)}</strong></div><div><span>Tool calls</span><strong>{selectedAttempt.usage.tool_calls.toLocaleString()}</strong></div><div><span>Duration</span><strong>{Math.round(selectedAttempt.usage.duration_ms / 1000).toLocaleString()}s</strong></div><div><span>Cleanup</span><strong>{sentence(selectedAttempt.cleanup.state)}</strong></div></div>{selectedAttempt.exit_reason ? <Callout tone={selectedAttempt.state === "failed" ? "danger" : "warning"} title="Attempt exit"><p>{selectedAttempt.exit_reason}</p></Callout> : null}{["unknown", "residue"].includes(selectedAttempt.cleanup.state) ? <Callout tone="warning" title="Cleanup is not established"><p>Preserved evidence does not establish that worker and target effects are absent.</p></Callout> : null}<EngineAttemptEvidence attempt={selectedAttempt} /><details className="engine-attempt-identity"><summary>Attempt identity and usage</summary><DataList items={[{ label: "Attempt", value: <code>{selectedAttempt.attempt_id}</code> }, { label: "Durable job", value: <code>{selectedAttempt.job_id}</code> }, { label: "BlueFire run", value: <code>{selectedAttempt.run_id}</code> }, { label: "Execution approval", value: selectedAttemptProjection ? <code>{selectedAttemptProjection.execution_approval_id}</code> : "Unavailable" }, { label: "Approval binding", value: selectedAttemptProjection ? <code>{selectedAttemptProjection.execution_approval_digest}</code> : "Unavailable" }, { label: "Upstream session", value: selectedAttempt.upstream_session_id ? <code>{selectedAttempt.upstream_session_id}</code> : "Not assigned" }, { label: "Started", value: formatDate(selectedAttempt.started_at ?? undefined) }, { label: "Finished", value: formatDate(selectedAttempt.finished_at ?? undefined) }]} /></details></Panel> : !selectedAttemptId && !selectedCheckId && !selectedCheck ? <Callout title="No work item selected"><p>Start the reviewed baseline or select a saved attempt or trusted check.</p></Callout> : null}

        {projection.checks.length ? <section className="engine-checks" aria-labelledby={`${titleId}-checks`}><header className="engine-section-heading"><div><span>Independent of the engine</span><h2 id={`${titleId}-checks`}>Trusted controller checks</h2></div><Badge tone="info">{projection.checks.length}</Badge></header>{explicitCheckMissing ? <Callout tone="warning" title="Selected check is unavailable"><p>The route refers to a check that is not part of this saved experiment.</p></Callout> : selectedCheckId && !selectedCheck ? <Callout tone="warning" title="Selected check details are unavailable"><p>Reload this exact trusted-check context before reviewing its observations.</p></Callout> : null}{projection.checks.map(check => <ControllerCheckCard key={check.check_id} check={check} detail={selectedCheck?.check_id === check.check_id ? selectedCheck : undefined} selected={selectedCheckKey === check.check_id} runHref={runHref} onSelect={onSelectCheck ? () => onSelectCheck(check.check_id) : undefined} onCancel={onCancelCheck} />)}</section> : null}
        <EngineRetestComparison conclusion={projection.conclusion} defensiveChange={experiment.defensive_change} sourceRuns={sourceRuns} runHref={runHref} comparisonHref={comparisonHref} />
      </div>

      <aside className="engine-context-rail" aria-label="Experiment setup and limits">
        <Panel><header><CircleDashed aria-hidden="true" /><div><span>Authorized environment</span><h2>{experiment.environment.display_name}</h2></div></header><DataList items={[{ label: "Platform", value: sentence(experiment.environment.platform) }, { label: "Disposable", value: "Required" }, { label: "Current state", value: experiment.current_target ? "Established" : "Not established" }, { label: "Snapshot", value: experiment.current_target ? <code>{experiment.current_target.snapshot_ref}</code> : "Unavailable until reconciliation" }, { label: "Captured", value: experiment.current_target ? formatDate(experiment.current_target.captured_at) : "Not available" }]} /></Panel>
        <Panel><header><Bot aria-hidden="true" /><div><span>Pinned engine</span><h2>{experiment.engine_setup.engine.display_name}</h2></div></header><DataList items={[{ label: "Package", value: experiment.engine_setup.engine.version }, { label: "Model", value: experiment.engine_setup.model.id }, { label: "Data destination", value: experiment.engine_setup.model.data_destination }, { label: "Provider", value: experiment.engine_setup.model.test_provider ? "Labeled test provider" : experiment.engine_setup.model.provider }]} /><details><summary>Exact build identity</summary><DataList items={[{ label: "Source revision", value: <code>{experiment.engine_setup.engine.revision}</code> }, { label: "Package", value: <code>{experiment.engine_setup.engine.package_digest}</code> }, { label: "Sandbox image", value: <code>{experiment.engine_setup.engine.sandbox_image_digest}</code> }]} /></details></Panel>
        <Panel><header><Gauge aria-hidden="true" /><div><span>Finite authorization</span><h2>Attempt limits</h2></div></header><DataList items={[{ label: "Wall clock", value: `${experiment.authorization.wall_clock_seconds.toLocaleString()} seconds` }, { label: "Actions", value: experiment.authorization.action_limit.toLocaleString() }, { label: "Artifacts", value: `${Math.round(experiment.authorization.artifact_byte_limit / 1024 / 1024)} MiB` }, { label: "Cost limit", value: `${experiment.authorization.cost_limit_microunits.toLocaleString()} microunits` }]} /><details><summary>Authorization identity</summary><DataList items={[{ label: "Scope", value: <code>{experiment.authorization.scope_ref}</code> }, { label: "Scope version", value: experiment.authorization.scope_version }, { label: "Model authorization", value: <code>{experiment.engine_setup.model.authorization_digest}</code> }]} /></details></Panel>
        <Panel><header><ShieldCheck aria-hidden="true" /><div><span>Controller-owned</span><h2>Defensive change</h2></div></header>{experiment.defensive_change ? <><strong>{experiment.defensive_change.summary}</strong><DataList items={[{ label: "Kind", value: sentence(experiment.defensive_change.kind) }, { label: "State", value: sentence(experiment.defensive_change.state) }, { label: "Rollback plan", value: "Recorded" }, { label: "Rollback operation", value: projection.conclusion.defense.rollback_operation_ref ? "Recorded" : "Not recorded" }, { label: "Rollback receipt", value: projection.conclusion.defense.rollback_receipt_ref ? "Recorded" : "Not recorded" }]} /></> : <p>No reviewed defensive change is linked yet.</p>}</Panel>
        {experiment.limitations.length ? <Panel className="engine-limitations"><header><TriangleAlert aria-hidden="true" /><div><span>Proof boundary</span><h2>Known limitations</h2></div></header><ul>{experiment.limitations.map(item => <li key={item}>{item}</li>)}</ul></Panel> : null}
      </aside>
    </div>
  </section>;
}
