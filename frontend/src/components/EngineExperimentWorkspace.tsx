import { ArrowRight, Bot, CircleCheck, CircleDashed, FlaskConical, Gauge, RotateCcw, ShieldCheck, Square, TriangleAlert } from "lucide-react";
import { useEffect, useId, useRef } from "react";
import { Link } from "react-router-dom";
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
} from "../lib/engine-experiment";
import { Badge, Button, Callout, DataList, Panel, formatDate, sentence } from "./Primitives";
import { EngineAttemptEvidence } from "./EngineAttemptEvidence";
import { EngineRetestComparison, type EngineSourceRunLink } from "./EngineRetestComparison";
import "./EngineExperimentWorkspace.css";

export interface EngineExperimentWorkspaceProps {
  experiment: EngineExperiment;
  workspaceEvidenceState?: "current" | "refreshing" | "unavailable";
  selectedAttemptId?: string | null;
  selectedCheckId?: string | null;
  onSelectAttempt: (attemptId: string) => void;
  onSelectCheck?: (checkId: string) => void;
  onPrimaryAction?: (action: EngineWorkspaceActionKind) => void;
  onCancelAttempt?: (attemptId: string) => void;
  onCancelCheck?: (checkId: string) => void;
  cancellingAttemptId?: string | null;
  cancellingCheckId?: string | null;
  runHref?: (runId: string) => string;
  comparisonHref?: string;
}

type EnginePhaseState = {
  kind: "active" | "current" | "recorded" | "unknown" | "not_attempted";
  label: string;
};

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

function AttemptSelector({ attempt, selected, detailAvailable, detailId, onSelect, runHref }: { attempt: EngineProjectionAttempt; selected: boolean; detailAvailable: boolean; detailId: string; onSelect: () => void; runHref: (runId: string) => string }) {
  return <li className={selected ? "is-selected" : undefined}>
    <button type="button" aria-pressed={selected} aria-controls={selected && detailAvailable ? detailId : undefined} onClick={onSelect}>
      <span className="engine-attempt-marker"><Bot aria-hidden="true" /></span>
      <span><strong>{engineAttemptLabel(attempt.role)}</strong><small>{engineStateLabel(attempt)}</small></span>
      <Badge tone={stateTone(attempt.state, attempt.cleanup.state)}>{sentence(attempt.state)}</Badge>
    </button>
    <Link to={runHref(attempt.run_id)} aria-label={`Open ${engineAttemptLabel(attempt.role)} run`}><ArrowRight aria-hidden="true" /></Link>
  </li>;
}

function ControllerCheckCard({ check, detail, selected, detailId, runHref, onSelect, onCancel, cancelling }: { check: EngineProjectionCheck; detail?: EngineControllerCheck; selected: boolean; detailId: string; runHref: (runId: string) => string; onSelect?: () => void; onCancel?: (checkId: string) => void; cancelling?: boolean }) {
  return <Panel className={`engine-check-card${selected ? " is-selected" : ""}`} id={selected ? detailId : undefined} tabIndex={selected ? -1 : undefined} aria-labelledby={selected ? `${detailId}-heading` : undefined}>
    <header><span className="engine-check-icon"><ShieldCheck aria-hidden="true" /></span><div><p>Trusted controller check</p><h3 id={selected ? `${detailId}-heading` : undefined}>{engineControllerCheckLabel(check.role)}</h3></div><Badge tone={stateTone(check.state, check.cleanup.state)}>{engineControllerCheckStateLabel(check)}</Badge></header>
    <p>{check.role === "retained_reproducer" ? "Repeats the retained mechanism without assigning model or engine authorship." : "Verifies the intended workflow separately from the attack objective."}</p>
    {detail?.observations.length ? <ul>{detail.observations.map(observation => <li key={observation.evidence_id}><strong>{checkObservationLabel(observation.category)}</strong><span>{observation.summary}</span><details><summary>Evidence identity and limits</summary><code>{observation.evidence_id}</code><p>{observation.limitations.length ? observation.limitations.join(" ") : "No additional limitation was recorded."}</p></details></li>)}</ul> : selected ? <Callout tone="warning" title="No checked outcome yet"><p>This controller operation has not established its result.</p></Callout> : null}
    <footer><Link to={runHref(check.run_id)}>Inspect run evidence<ArrowRight aria-hidden="true" /></Link><span>{onSelect ? <Button type="button" size="small" variant="secondary" aria-pressed={selected} aria-controls={selected ? detailId : undefined} onClick={onSelect}>{selected ? "Selected" : `Review ${engineControllerCheckLabel(check.role).toLowerCase()}`}</Button> : null}{check.state === "reserved" && onCancel ? <Button type="button" size="small" variant="danger" disabled={cancelling} onClick={() => onCancel(check.check_id)}><Square aria-hidden="true" />{cancelling ? "Requesting cancellation" : "Cancel check"}</Button> : null}</span></footer>
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

const phaseState = (kind: EnginePhaseState["kind"], label: string): EnginePhaseState => ({ kind, label });
const recordedOrCurrent = (workspaceEvidenceState: NonNullable<EngineExperimentWorkspaceProps["workspaceEvidenceState"]>, matchesCurrentSnapshot: boolean): EnginePhaseState =>
  workspaceEvidenceState === "current" && matchesCurrentSnapshot ? phaseState("current", "Current and verified") : phaseState("recorded", "Recorded history");

export function EngineExperimentWorkspace({ experiment, workspaceEvidenceState = "current", selectedAttemptId, selectedCheckId, onSelectAttempt, onSelectCheck, onPrimaryAction, onCancelAttempt, onCancelCheck, cancellingAttemptId, cancellingCheckId, runHref = runId => `/runs/${encodeURIComponent(runId)}`, comparisonHref }: EngineExperimentWorkspaceProps) {
  const titleId = useId();
  const attemptDetailId = `${titleId}-selected-attempt`;
  const checkDetailId = `${titleId}-selected-check`;
  const phaseHintId = `${titleId}-phase-hint`;
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
  const actualSelection = selectedAttempt ? `attempt:${selectedAttempt.attempt_id}` : selectedCheck ? `check:${selectedCheck.check_id}` : undefined;
  const previousSelection = useRef<string | undefined>(undefined);
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
  const dispositionActions = experiment.actions.filter(action => action.kind === "retain_defense" || action.kind === "rollback_defense");
  const baselineEvidence = baseline ? projection.observations.filter(item => item.attempt_id === baseline.attempt_id) : [];
  const currentSnapshot = experiment.current_target?.snapshot_ref ?? null;
  const integrityFor = (runId: string) => projection.run_integrity.find(item => item.run_id === runId);
  const recordState = ({
    exists,
    active,
    runId,
    complete,
    cleanup,
    targetSnapshot,
    outcomeKnown,
  }: {
    exists: boolean;
    active: boolean;
    runId?: string;
    complete: boolean;
    cleanup?: string;
    targetSnapshot?: string | null;
    outcomeKnown: boolean;
  }): EnginePhaseState => {
    if (!exists) return phaseState("not_attempted", "Not attempted");
    if (active) {
      if (workspaceEvidenceState === "unavailable") return phaseState("unknown", "State unavailable");
      return phaseState("active", workspaceEvidenceState === "refreshing" ? "Active, refreshing" : "Active");
    }
    const integrity = runId ? integrityFor(runId) : undefined;
    if (!integrity || integrity.state !== "verified") return phaseState("unknown", "Run unavailable");
    if (!integrity.terminal || !complete || cleanup !== undefined && cleanup !== "verified_absent") return phaseState("unknown", "Incomplete");
    if (!outcomeKnown) return phaseState("unknown", "Outcome unknown");
    return recordedOrCurrent(workspaceEvidenceState, Boolean(currentSnapshot && targetSnapshot === currentSnapshot));
  };
  const baselineState = recordState({
    exists: Boolean(baseline),
    active: Boolean(baseline && activeAttemptState(baseline.state)),
    runId: baseline?.run_id,
    complete: Boolean(baseline && baseline.state === "completed" && baseline.completeness === "complete"),
    cleanup: baseline?.cleanup.state,
    targetSnapshot: baseline?.target_snapshot_ref,
    outcomeKnown: projection.conclusion.original_mechanism.status !== "unknown" && projection.conclusion.original_mechanism.status !== "not_attempted",
  });
  const baselineIntegrity = baseline ? integrityFor(baseline.run_id) : undefined;
  const baselineEvidenceIntegrity = baselineEvidence.map(item => integrityFor(item.run_id));
  const verificationState = !baseline
    ? phaseState("not_attempted", "Not attempted")
    : activeAttemptState(baseline.state)
      ? workspaceEvidenceState === "unavailable" ? phaseState("unknown", "State unavailable") : phaseState("active", workspaceEvidenceState === "refreshing" ? "Active, refreshing" : "Active")
      : !baselineIntegrity || baselineIntegrity.state !== "verified" || baselineEvidenceIntegrity.some(item => !item || item.state !== "verified")
        ? phaseState("unknown", "Run unavailable")
        : !baselineIntegrity.terminal || baseline.state !== "completed" || baseline.completeness !== "complete" || baseline.cleanup.state !== "verified_absent"
          ? phaseState("unknown", "Incomplete")
          : !baselineEvidence.length || baselineEvidence.some(item => item.assessment === "unknown")
            ? phaseState("unknown", "Outcome unknown")
            : recordedOrCurrent(workspaceEvidenceState, Boolean(currentSnapshot && baselineEvidence.every(item => item.target_snapshot_ref === currentSnapshot)));
  const defenseState = !experiment.defensive_change
    ? phaseState("not_attempted", "Not attempted")
    : experiment.defensive_change.state === "unknown" || experiment.current_target === null
      ? phaseState("unknown", "Current state unknown")
      : experiment.defensive_change.state === "applied" || experiment.defensive_change.state === "retained"
        ? projection.conclusion.defense.application_receipt_ref
          ? recordedOrCurrent(workspaceEvidenceState, experiment.defensive_change.after_target_snapshot_ref === currentSnapshot)
          : phaseState("unknown", "Application unverified")
        : phaseState("recorded", "Recorded history");
  const reproducerState = recordState({
    exists: Boolean(reproducer),
    active: Boolean(reproducer && activeCheckState(reproducer.state)),
    runId: reproducer?.run_id,
    complete: Boolean(reproducer && reproducer.state === "completed" && reproducer.result_digest && reproducer.independent_evidence_refs.length),
    cleanup: reproducer?.cleanup.state,
    targetSnapshot: reproducer?.target_snapshot_ref,
    outcomeKnown: ["blocked", "still_succeeds"].includes(projection.conclusion.retained_reproducer.status),
  });
  const adaptiveState = recordState({
    exists: Boolean(adaptive),
    active: Boolean(adaptive && activeAttemptState(adaptive.state)),
    runId: adaptive?.run_id,
    complete: Boolean(adaptive && adaptive.state === "completed" && adaptive.completeness === "complete"),
    cleanup: adaptive?.cleanup.state,
    targetSnapshot: adaptive?.target_snapshot_ref,
    outcomeKnown: ["remaining_path_found", "no_path_observed_within_limits"].includes(projection.conclusion.adaptive_search.status),
  });
  const legitimateState = recordState({
    exists: Boolean(legitimate),
    active: Boolean(legitimate && activeCheckState(legitimate.state)),
    runId: legitimate?.run_id,
    complete: Boolean(legitimate && legitimate.state === "completed" && legitimate.result_digest && legitimate.independent_evidence_refs.length),
    cleanup: legitimate?.cleanup.state,
    targetSnapshot: legitimate?.target_snapshot_ref,
    outcomeKnown: ["passed", "failed"].includes(projection.conclusion.legitimate_use.status),
  });
  const comparisonRunIds = [baseline?.run_id, reproducer?.run_id, adaptive?.run_id, legitimate?.run_id].filter((runId): runId is string => Boolean(runId));
  const comparisonRunsVerified = comparisonRunIds.length === 4
    && new Set(comparisonRunIds).size === 4
    && comparisonRunIds.every(runId => {
      const integrity = integrityFor(runId);
      return integrity?.state === "verified" && integrity.terminal;
    });
  const comparisonKnown = projection.conclusion.telemetry_health.status === "complete"
    && projection.conclusion.cleanup.status === "verified_absent"
    && !["unknown", "not_attempted"].includes(projection.conclusion.original_mechanism.status)
    && !["unknown", "not_attempted"].includes(projection.conclusion.retained_reproducer.status)
    && !["pending", "inconclusive", "not_attempted"].includes(projection.conclusion.adaptive_search.status)
    && !["unknown", "not_attempted"].includes(projection.conclusion.legitimate_use.status)
    && comparisonRunsVerified;
  const comparisonState = projection.workflow_state !== "complete"
    ? phaseState("not_attempted", "Not attempted")
    : !comparisonKnown || experiment.current_target === null
      ? phaseState("unknown", "Conclusion incomplete")
      : recordedOrCurrent(workspaceEvidenceState, true);
  const phases = [
    { key: "baseline", label: "Baseline exploration", state: baselineState, icon: FlaskConical },
    { key: "verification", label: "Independent verification", state: verificationState, icon: CircleCheck },
    { key: "defense", label: "Defensive change", state: defenseState, icon: ShieldCheck },
    { key: "reproducer", label: "Original mechanism retest", state: reproducerState, icon: RotateCcw },
    { key: "adaptive", label: "Fresh adaptive search", state: adaptiveState, icon: Bot },
    { key: "legitimate", label: "Legitimate-use check", state: legitimateState, icon: ShieldCheck },
    { key: "comparison", label: "Comparison and disposition", state: comparisonState, icon: Gauge },
  ];
  const completed = projection.workflow_state === "complete";
  const comparison = <EngineRetestComparison conclusion={projection.conclusion} evidence={projection} defensiveChange={experiment.defensive_change} dispositionActions={dispositionActions} onDispositionAction={onPrimaryAction} sourceRuns={sourceRuns} runHref={runHref} comparisonHref={comparisonHref} />;

  useEffect(() => {
    if (actualSelection && previousSelection.current !== actualSelection) {
      document.getElementById(selectedAttempt ? attemptDetailId : checkDetailId)?.focus();
    }
    previousSelection.current = actualSelection;
  }, [actualSelection, attemptDetailId, checkDetailId, selectedAttempt]);

  return <section className="engine-experiment-workspace" aria-labelledby={titleId}>
    <header className="engine-workspace-header">
      <div className="engine-workspace-title"><p>Defense experiment</p><h1 id={titleId}>{experiment.objective.title}</h1><span>{experiment.objective.summary}</span><div><Badge tone="info">{sentence(experiment.environment.platform)}</Badge><Badge tone="neutral">{experiment.environment.display_name}</Badge>{experiment.engine_setup.model.test_provider ? <Badge tone="warning">Labeled test provider</Badge> : <Badge tone="violet">{experiment.engine_setup.engine.display_name}</Badge>}</div></div>
      <div className="engine-workspace-actions"><div><span>Workflow</span><strong>{engineWorkflowLabel(projection.workflow_state)}</strong></div><div><span>Revision</span><strong>{experiment.revision.toLocaleString()}</strong></div>{primaryAction && onPrimaryAction ? <Button type="button" variant="primary" disabled={!primaryAction.enabled} onClick={() => onPrimaryAction(primaryAction.kind)}>{primaryAction.label}<ArrowRight aria-hidden="true" /></Button> : null}{activeAttempt && activeAttempt.state !== "stopping" && onCancelAttempt ? <Button type="button" variant="danger" disabled={cancellingAttemptId === activeAttempt.attempt_id} onClick={() => onCancelAttempt(activeAttempt.attempt_id)}><Square aria-hidden="true" />{cancellingAttemptId === activeAttempt.attempt_id ? "Requesting cancellation" : "Cancel attempt"}</Button> : activeAttempt?.state === "stopping" ? <Button type="button" disabled><Square aria-hidden="true" />Stopping</Button> : null}</div>
    </header>
    {!completed && primaryAction?.reason ? <Callout tone={primaryAction.enabled && onPrimaryAction ? "info" : "warning"} title={primaryAction.enabled && onPrimaryAction ? "Next useful action" : primaryAction.enabled ? "Next action is not available here" : "Action not available"}><p>{primaryAction.reason}</p></Callout> : null}
    {experiment.current_target === null ? <Callout tone="warning" title="Current target state is not established"><p>BlueFire preserved the earlier evidence, but it cannot treat that history as proof of the target’s current state. Reconcile the defensive operation before starting another effect or drawing a current-state conclusion.</p></Callout> : null}
    {activeCheck ? <span className="sr-only" role="status">Trusted check in progress: {engineControllerCheckLabel(activeCheck.role)}</span> : null}
    <span className="sr-only" id={phaseHintId}>This path scrolls horizontally when space is constrained. Focus it and use the arrow keys to review every phase.</span>
    <ol className="engine-phase-rail" aria-label="Experiment phases" aria-describedby={phaseHintId} tabIndex={0}>{phases.map((phase, index) => <li className={["active", "current"].includes(phase.state.kind) ? "is-current" : phase.state.kind === "recorded" ? "is-recorded" : undefined} data-state={phase.state.kind} aria-current={phase.state.kind === "active" ? "step" : undefined} key={phase.key}><span>{index + 1}</span><phase.icon aria-hidden="true" /><div><strong>{phase.label}</strong><small>{phase.state.label}</small></div></li>)}</ol>
    {completed ? <div className="engine-outcome-first" aria-label="Established experiment outcome">{comparison}</div> : null}

    <div className="engine-workspace-layout">
      <div className="engine-workspace-main">
        <Panel className="engine-attempt-panel"><header className="engine-section-heading"><div><span>Model-driven work</span><h2>Engine attempts</h2></div><Badge>{projection.attempts.length}</Badge></header>{projection.attempts.length ? <ul className="engine-attempt-selector">{projection.attempts.map(attempt => <AttemptSelector key={attempt.attempt_id} attempt={attempt} selected={selectedAttemptKey === attempt.attempt_id} detailAvailable={selectedAttempt?.attempt_id === attempt.attempt_id} detailId={attemptDetailId} onSelect={() => onSelectAttempt(attempt.attempt_id)} runHref={runHref} />)}</ul> : <p className="engine-evidence-note">No external-engine attempt has been admitted.</p>}</Panel>
        {ambiguousSelection ? <Callout tone="warning" title="Selection is ambiguous"><p>Select either one engine attempt or one trusted check.</p></Callout> : explicitAttemptMissing ? <Callout tone="warning" title="Selected attempt is unavailable"><p>The route refers to an attempt that is not part of this saved experiment. Choose a recorded engine attempt to continue.</p></Callout> : selectedAttemptId && !selectedAttempt ? <Callout tone="warning" title="Selected attempt details are unavailable"><p>Reload this exact attempt context before reviewing its findings and artifacts.</p></Callout> : null}
        {selectedAttempt ? <Panel className="engine-selected-attempt" id={attemptDetailId} tabIndex={-1} aria-labelledby={`${attemptDetailId}-heading`}><header><div><p>Selected engine attempt</p><h2 id={`${attemptDetailId}-heading`}>{engineAttemptLabel(selectedAttempt.role)}</h2><span>{engineStateLabel(selectedAttempt)}. Review completeness and independent observations before drawing a conclusion.</span></div><Badge tone={stateTone(selectedAttempt.state, selectedAttempt.cleanup.state)}>{sentence(selectedAttempt.completeness)}</Badge></header><div className="engine-attempt-stats"><div><span>State</span><strong>{sentence(selectedAttempt.state)}</strong></div><div><span>Tool calls</span><strong>{selectedAttempt.usage.tool_calls.toLocaleString()}</strong></div><div><span>Duration</span><strong>{Math.round(selectedAttempt.usage.duration_ms / 1000).toLocaleString()}s</strong></div><div><span>Cleanup</span><strong>{sentence(selectedAttempt.cleanup.state)}</strong></div></div>{selectedAttempt.exit_reason ? <Callout tone={selectedAttempt.state === "failed" ? "danger" : "warning"} title="Attempt exit"><p>{selectedAttempt.exit_reason}</p></Callout> : null}{["unknown", "residue"].includes(selectedAttempt.cleanup.state) ? <Callout tone="warning" title="Cleanup is not established"><p>Preserved evidence does not establish that worker and target effects are absent.</p></Callout> : null}<EngineAttemptEvidence attempt={selectedAttempt} /><details className="engine-attempt-identity"><summary>Attempt identity and usage</summary><DataList items={[{ label: "Attempt", value: <code>{selectedAttempt.attempt_id}</code> }, { label: "Durable job", value: <code>{selectedAttempt.job_id}</code> }, { label: "BlueFire run", value: <code>{selectedAttempt.run_id}</code> }, { label: "Execution approval", value: selectedAttemptProjection ? <code>{selectedAttemptProjection.execution_approval_id}</code> : "Unavailable" }, { label: "Approval binding", value: selectedAttemptProjection ? <code>{selectedAttemptProjection.execution_approval_digest}</code> : "Unavailable" }, { label: "Upstream session", value: selectedAttempt.upstream_session_id ? <code>{selectedAttempt.upstream_session_id}</code> : "Not assigned" }, { label: "Started", value: formatDate(selectedAttempt.started_at ?? undefined) }, { label: "Finished", value: formatDate(selectedAttempt.finished_at ?? undefined) }]} /></details></Panel> : !selectedAttemptId && !selectedCheckId && !selectedCheck ? <Callout title="No work item selected"><p>Start the reviewed baseline or select a saved attempt or trusted check.</p></Callout> : null}

        {projection.checks.length ? <section className="engine-checks" aria-labelledby={`${titleId}-checks`}><header className="engine-section-heading"><div><span>Independent of the engine</span><h2 id={`${titleId}-checks`}>Trusted controller checks</h2></div><Badge tone="info">{projection.checks.length}</Badge></header>{explicitCheckMissing ? <Callout tone="warning" title="Selected check is unavailable"><p>The route refers to a check that is not part of this saved experiment.</p></Callout> : selectedCheckId && !selectedCheck ? <Callout tone="warning" title="Selected check details are unavailable"><p>Reload this exact trusted-check context before reviewing its observations.</p></Callout> : null}{projection.checks.map(check => <ControllerCheckCard key={check.check_id} check={check} detail={selectedCheck?.check_id === check.check_id ? selectedCheck : undefined} selected={selectedCheckKey === check.check_id} detailId={checkDetailId} runHref={runHref} onSelect={onSelectCheck ? () => onSelectCheck(check.check_id) : undefined} onCancel={onCancelCheck} cancelling={cancellingCheckId === check.check_id} />)}</section> : null}
        {!completed ? comparison : null}
      </div>

      <aside className="engine-context-rail" aria-label="Experiment setup and limits">
        <Panel className="engine-environment-card"><header><CircleDashed aria-hidden="true" /><div><span>Authorized environment</span><h2>{experiment.environment.display_name}</h2></div></header><DataList items={[{ label: "Platform", value: sentence(experiment.environment.platform) }, { label: "Disposable", value: "Required" }, { label: "Current state", value: experiment.current_target ? "Established" : "Not established" }, { label: "Current target", value: experiment.current_target?.display_name ?? "Unavailable until reconciliation" }, { label: "Captured", value: experiment.current_target ? formatDate(experiment.current_target.captured_at) : "Not available" }]} />{experiment.current_target ? <details className="engine-context-details"><summary>Exact target identity and provenance</summary><DataList items={[{ label: "Snapshot reference", value: <code>{experiment.current_target.snapshot_ref}</code> }, { label: "Environment", value: <code>{experiment.environment.environment_ref}</code> }]} /></details> : null}</Panel>
        <Panel className="engine-setup-card"><header><Bot aria-hidden="true" /><div><span>Pinned engine</span><h2>{experiment.engine_setup.engine.display_name}</h2></div></header><p className="engine-context-summary">{experiment.engine_setup.engine.version} · {experiment.engine_setup.model.id} · {experiment.engine_setup.model.test_provider ? "Labeled test provider" : experiment.engine_setup.model.provider}</p><details className="engine-context-details"><summary>Engine, model, and build details</summary><p className="engine-evidence-note">Provider setup is configuration, not proof of native execution or live-model inference. Inspect each saved run for its execution evidence.</p><DataList items={[{ label: "Data destination", value: experiment.engine_setup.model.data_destination }, { label: "Source revision", value: <code>{experiment.engine_setup.engine.revision}</code> }, { label: "Package", value: <code>{experiment.engine_setup.engine.package_digest}</code> }, { label: "Sandbox image", value: <code>{experiment.engine_setup.engine.sandbox_image_digest}</code> }]} /></details></Panel>
        <Panel className="engine-limits-card"><header><Gauge aria-hidden="true" /><div><span>Finite authorization</span><h2>Attempt limits</h2></div></header><p className="engine-context-summary">{experiment.authorization.wall_clock_seconds.toLocaleString()}s · {experiment.authorization.action_limit.toLocaleString()} actions · {Math.round(experiment.authorization.artifact_byte_limit / 1024 / 1024)} MiB</p><details className="engine-context-details"><summary>Exact limits and authorization</summary><DataList items={[{ label: "Cost limit", value: `${experiment.authorization.cost_limit_microunits.toLocaleString()} microunits` }, { label: "Scope", value: <code>{experiment.authorization.scope_ref}</code> }, { label: "Scope version", value: experiment.authorization.scope_version }, { label: "Model authorization", value: <code>{experiment.engine_setup.model.authorization_digest}</code> }]} /></details></Panel>
        <Panel><header><ShieldCheck aria-hidden="true" /><div><span>Controller-owned</span><h2>Defensive change</h2></div></header>{experiment.defensive_change ? <><strong>{experiment.defensive_change.summary}</strong><DataList items={[{ label: "Kind", value: sentence(experiment.defensive_change.kind) }, { label: "State", value: sentence(experiment.defensive_change.state) }, { label: "Rollback plan", value: "Recorded" }, { label: "Rollback operation", value: projection.conclusion.defense.rollback_operation_ref ? "Recorded" : "Not recorded" }, { label: "Rollback receipt", value: projection.conclusion.defense.rollback_receipt_ref ? "Recorded" : "Not recorded" }]} /></> : <p>No reviewed defensive change is linked yet.</p>}</Panel>
        {experiment.limitations.length ? <Panel className="engine-limitations"><header><TriangleAlert aria-hidden="true" /><div><span>Proof boundary</span><h2>Known limitations</h2></div></header><ul>{experiment.limitations.map(item => <li key={item}>{item}</li>)}</ul></Panel> : null}
      </aside>
    </div>
  </section>;
}
