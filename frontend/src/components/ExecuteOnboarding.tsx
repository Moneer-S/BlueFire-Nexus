import { Activity, ArrowRight, CheckCircle2, CircleDashed, Play, ShieldCheck } from "lucide-react";
import type { ReactNode } from "react";
import { runnerDiagnosticsPath } from "../lib/runner-diagnostics";
import { Link } from "react-router-dom";
import type { PreflightReport, RunConfiguration, RunJob, RunRecord, RunnerLifecycleStatus, RunnerProfile, Scenario } from "../types";
import { Badge, Button, Callout, Panel, PanelHeader, sentence } from "./Primitives";

export const GUIDED_EXECUTE_PROFILE_ID = "sandbox-restricted-owned.v1";
export const GUIDED_EXECUTE_SCENARIO_ID = "scenario.restricted.persistence-canary.v1";
export const GUIDED_EXECUTE_SCOPE = "sandbox.workspace";
export const GUIDED_EXECUTE_COLLECTOR_ID = "collector.filesystem.sandbox.v1";

export function guidedExecuteConfiguration(current: RunConfiguration, profile: RunnerProfile): RunConfiguration {
  return {
    ...current,
    mode: "execute",
    autonomy: "off",
    provider: "deterministic-offline.v1",
    model: "deterministic-planner.v1",
    endpoint: "",
    profileId: profile.id,
    runnerIds: [],
    scopeRefs: [GUIDED_EXECUTE_SCOPE],
    safetyTier: "restricted",
    approvalPolicy: "profile",
    approved: false,
    approvedBy: "",
    maxSeconds: profile.budgets.max_seconds ?? current.maxSeconds,
    maxSteps: profile.budgets.max_steps ?? current.maxSteps,
    maxBytes: profile.budgets.max_bytes ?? current.maxBytes,
    collectors: [GUIDED_EXECUTE_COLLECTOR_ID],
    cleanupPolicy: "always",
    counterfactual: "disabled",
    fixtureMode: false,
    actionImplementations: {},
  };
}

export function isCompletedGuidedExecuteRun(job: RunJob | null, run: RunRecord | null): boolean {
  if (!job || job.state !== "completed" || !job.result_ref || !run || run.run_id !== job.result_ref) return false;
  const executedRunnerEvidence = run.evidence?.records.some((record) => record.provenance === "executed" && record.producer === "bluefire-rust-runner") === true;
  const observedFilesystemEvidence = run.evidence?.records.some((record) => record.provenance === "observed" && record.producer === GUIDED_EXECUTE_COLLECTOR_ID && record.content?.collector_id === GUIDED_EXECUTE_COLLECTOR_ID && record.content.artifact_type === "file_observation" && record.content.path === "restricted/persistence-marker.json") === true;
  const cleanup = run.cleanup;
  const cleanupComplete = Boolean(cleanup && typeof cleanup === "object" && cleanup.attempted === true && cleanup.success === true && cleanup.outstanding_receipt_count === 0);
  return run.is_demo !== true && run.mode === "execute" && run.status === "completed" && run.objective_reached === true && run.scenario_id === GUIDED_EXECUTE_SCENARIO_ID && run.runner_profile_id === GUIDED_EXECUTE_PROFILE_ID && executedRunnerEvidence && observedFilesystemEvidence && cleanupComplete;
}

type RunnerAction = "bootstrap" | "start";
type StepState = "complete" | "current" | "upcoming";

interface ExecuteOnboardingProps {
  profile?: RunnerProfile;
  seededScenario?: Scenario;
  selectedScenario: Scenario;
  config: RunConfiguration;
  runner?: RunnerLifecycleStatus;
  runnerPending: boolean;
  runnerError: unknown;
  runnerActionPending: boolean;
  preflight?: PreflightReport;
  preflightPending: boolean;
  preflightDisabled: boolean;
  job: RunJob | null;
  approvalReleased: boolean;
  run: RunRecord | null;
  jobSubmissionPending: boolean;
  canCreateJob: boolean;
  demoMode: boolean;
  submissionControls?: ReactNode;
  onRunnerAction: (action: RunnerAction) => void;
  onSelectScenario: () => void;
  onPreflight: () => void;
  onCreateJob: () => void;
  onReviewEnvelope: () => void;
  onReviewApproval: () => void;
}

function StepMarker({ state, number }: { state: StepState; number: number }) {
  return state === "complete" ? <CheckCircle2 aria-label={`Step ${number} complete`} /> : state === "current" ? <Activity aria-label={`Step ${number} current`} /> : <CircleDashed aria-label={`Step ${number} upcoming`} />;
}

function Step({ number, state, title, detail, status, action }: { number: number; state: StepState; title: string; detail: string; status: string; action?: ReactNode }) {
  return <li data-state={state} aria-current={state === "current" ? "step" : undefined}>
    <span className="execute-step-marker"><StepMarker state={state} number={number} /></span>
    <div><strong>{title}</strong><small>{detail}</small></div>
    <div className="execute-step-action"><Badge tone={state === "complete" ? "success" : state === "current" ? "warning" : "neutral"}>{status}</Badge>{action}</div>
  </li>;
}

export function isExecuteRunnerReady(runner?: RunnerLifecycleStatus): boolean {
  return runner?.state === "ready" && runner.enrollment === "active" && runner.process === "authenticated" && runner.health?.accepting_execute === true;
}

export function ExecuteOnboarding(props: ExecuteOnboardingProps) {
  const runnerReady = isExecuteRunnerReady(props.runner);
  // Selection only makes the graph available for review. The server still
  // resolves allowed effects and returns the approval authority for that graph.
  const scenarioReady = Boolean(props.selectedScenario.id && props.selectedScenario.steps.length);
  const preflightReady = Boolean(scenarioReady && props.config.mode === "execute" && props.config.profileId && (props.preflight?.ready || props.preflight?.status === "approval_required") && props.preflight?.plan?.mode === "execute" && props.preflight.plan.runner_profile_id === props.config.profileId && props.preflight.approval_binding?.profile_id === props.config.profileId && props.preflight.approval_envelope?.scenario_id === props.selectedScenario.id && props.preflight.runner_profile === props.config.profileId);
  const awaitingApproval = props.job?.state === "awaiting_approval";
  const approvalReleased = Boolean(preflightReady && props.approvalReleased);
  const resultReady = Boolean(approvalReleased && props.job?.state === "completed" && props.run && props.job.result_ref === props.run.run_id && props.run.finalized_at && props.run.is_demo !== true && props.run.mode === "execute" && props.run.scenario_id === props.selectedScenario.id && props.run.runner_profile_id === props.config.profileId);
  const completed = resultReady && isCompletedGuidedExecuteRun(props.job, props.run);
  const currentStep = props.job ? awaitingApproval ? 4 : 5 : !runnerReady ? 1 : !scenarioReady ? 2 : preflightReady ? 4 : 3;
  const stepState = (number: number, complete: boolean): StepState => complete ? "complete" : currentStep === number ? "current" : "upcoming";
  const runnerState = stepState(1, runnerReady);
  const scenarioState = stepState(2, scenarioReady);
  const preflightState = stepState(3, preflightReady);
  const approvalState = stepState(4, approvalReleased);
  const runState = stepState(5, completed);

  const runnerAction = currentStep === 1 && !props.demoMode && !runnerReady && !props.runnerPending && !props.runnerError && props.profile
    ? props.runner?.state === "unbootstrapped"
      ? <Button size="small" variant="primary" disabled={props.runnerActionPending} onClick={() => props.onRunnerAction("bootstrap")}><ShieldCheck/>{props.runnerActionPending ? "Preparing runner" : "Prepare runner"}</Button>
      : props.runner?.state === "stopped" && props.runner.enrollment === "active"
        ? <Button size="small" variant="primary" disabled={props.runnerActionPending} onClick={() => props.onRunnerAction("start")}><Play/>{props.runnerActionPending ? "Starting runner" : "Start runner"}</Button>
        : <Link className="execute-guide-link" to={runnerDiagnosticsPath(props.config.profileId)}>Open runner diagnostics <ArrowRight/></Link>
    : undefined;
  const approvalAction = !props.job
    ? props.canCreateJob
      ? props.submissionControls ? undefined : <Button size="small" variant="primary" disabled={props.jobSubmissionPending} onClick={props.onCreateJob}><ShieldCheck/>{props.jobSubmissionPending ? "Creating request" : "Create run request"}</Button>
      : <Button size="small" variant="primary" onClick={props.onReviewEnvelope}>Review run details</Button>
    : awaitingApproval
      ? <Button size="small" variant="primary" onClick={props.onReviewApproval}>Review approval</Button>
      : undefined;

  return <Panel className="execute-onboarding" id="guided-execute" aria-label="Guided local Execute">
    <PanelHeader eyebrow="Guided local Execute" title="Prepare, review, and run" detail="Follow the current step. Execution needs a separate approval for this run." actions={<Badge tone={completed ? "success" : resultReady ? "info" : "warning"}>{completed ? "Completed" : resultReady ? "Results ready" : "Review required"}</Badge>} />
    {props.demoMode ? <Callout tone="warning" title="Production local service required">Demo mode cannot enroll a runner or execute effects. Relaunch the installed local service to use this guide.</Callout> : null}
    <ol className="execute-onboarding-steps">
      <Step number={1} state={runnerState} title="Make the local runner ready" detail="Prepare the installed runner, then start it in your chosen environment." status={props.runnerPending ? "Checking" : runnerReady ? "Ready" : props.runnerError ? "Unavailable" : sentence(props.runner?.state ?? "unavailable")} action={runnerAction} />
      <Step number={2} state={scenarioState} title="Review the selected experiment" detail={scenarioReady ? `${props.selectedScenario.title || props.selectedScenario.id} · ${props.selectedScenario.steps.length} steps. Preflight will check which effects are allowed.` : "Choose or build an experiment, or load the optional starter example."} status={scenarioReady ? "Selected for review" : "Choose an experiment"} action={scenarioState === "current" && props.profile && props.seededScenario ? <Button size="small" variant="primary" onClick={props.onSelectScenario}>Load starter example</Button> : undefined} />
      <Step number={3} state={preflightState} title="Check what will run" detail="Check the selected graph, environment, observations, and cleanup before creating a run request." status={preflightReady ? "Ready for review" : props.preflightPending ? "Checking" : props.preflight ? sentence(props.preflight.status) : "Required"} action={preflightState === "current" && !props.submissionControls ? <Button size="small" variant="primary" disabled={props.preflightPending || props.preflightDisabled} onClick={props.onPreflight}><ShieldCheck/>{props.preflightPending ? "Running preflight" : "Check selected experiment"}</Button> : undefined} />
      <Step number={4} state={approvalState} title="Approve this run" detail={awaitingApproval ? "Execution is stopped. Review the returned run details and identify yourself to approve this one run." : "Review the preflight details and create a run request. Creating the request does not approve execution."} status={approvalReleased ? "Released" : awaitingApproval && preflightReady ? "Awaiting approval" : preflightReady ? "Review required" : "Locked"} action={approvalState === "current" ? approvalAction : undefined} />
      <Step number={5} state={runState} title="Run, observe, and clean up" detail="Review what ran, the observations, and cleanup in the saved results." status={completed ? "Completed" : resultReady ? "Results ready" : approvalReleased ? props.job?.state === "completed" ? "Awaiting saved result" : sentence(props.job?.state ?? "running") : "Waiting for approval"} action={resultReady && props.run ? <Link className="execute-guide-link" to={`/runs/${encodeURIComponent(props.run.run_id)}`}>Review results <ArrowRight/></Link> : undefined} />
    </ol>
    {props.submissionControls}
    <details><summary>Technical details</summary><p>The installed runner is verified and enrolled before its authenticated loopback host starts. Certificate, HMAC, revocation, and removal controls are available in runner diagnostics.</p><p>Preflight binds the exact graph and profile to an immutable approval envelope. Creating a saved request does not approve execution. One exact, current approval releases that request. The starter canary's completion check additionally requires its exact observed marker and successful cleanup. Other finalized runs expose their recorded results without claiming that canary check.</p><p>Profile: <code>{props.config.profileId || "None selected"}</code> · Scope: <code>{props.config.scopeRefs.join(", ") || "None selected"}</code></p><Link to={runnerDiagnosticsPath(props.config.profileId)}>Advanced runner diagnostics <ArrowRight/></Link></details>
  </Panel>;
}
