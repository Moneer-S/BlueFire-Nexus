import { Activity, ArrowRight, CheckCircle2, CircleDashed, Play, ShieldCheck } from "lucide-react";
import type { ReactNode } from "react";
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
  job: RunJob | null;
  approvalReleased: boolean;
  run: RunRecord | null;
  jobSubmissionPending: boolean;
  canCreateJob: boolean;
  demoMode: boolean;
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

export function ExecuteOnboarding(props: ExecuteOnboardingProps) {
  const runnerReady = props.runner?.state === "ready" && props.runner.enrollment === "active" && props.runner.process === "authenticated" && props.runner.health?.accepting_execute === true;
  const scenarioReady = Boolean(props.profile && props.seededScenario && props.selectedScenario.id === GUIDED_EXECUTE_SCENARIO_ID && props.config.mode === "execute" && props.config.profileId === GUIDED_EXECUTE_PROFILE_ID && props.config.autonomy === "off" && props.config.provider === "deterministic-offline.v1" && props.config.safetyTier === "restricted" && props.config.cleanupPolicy === "always" && props.config.scopeRefs.length === 1 && props.config.scopeRefs[0] === GUIDED_EXECUTE_SCOPE && props.config.collectors.length === 1 && props.config.collectors[0] === GUIDED_EXECUTE_COLLECTOR_ID);
  const preflightReady = Boolean(scenarioReady && props.preflight?.status === "approval_required" && props.preflight.plan && props.preflight.approval_binding && props.preflight.approval_envelope && props.preflight.runner_profile === GUIDED_EXECUTE_PROFILE_ID);
  const awaitingApproval = props.job?.state === "awaiting_approval";
  const approvalReleased = Boolean(preflightReady && props.approvalReleased);
  const completed = approvalReleased && isCompletedGuidedExecuteRun(props.job, props.run);
  const runnerState: StepState = runnerReady ? "complete" : "current";
  const scenarioState: StepState = scenarioReady ? "complete" : runnerReady ? "current" : "upcoming";
  const preflightState: StepState = preflightReady ? "complete" : scenarioReady ? "current" : "upcoming";
  const approvalState: StepState = approvalReleased ? "complete" : preflightReady ? "current" : "upcoming";
  const runState: StepState = completed ? "complete" : approvalReleased ? "current" : "upcoming";

  const runnerAction = !props.demoMode && !runnerReady && !props.runnerPending && !props.runnerError && props.profile
    ? props.runner?.state === "unbootstrapped"
      ? <Button size="small" variant="primary" disabled={props.runnerActionPending} onClick={() => props.onRunnerAction("bootstrap")}><ShieldCheck/>{props.runnerActionPending ? "Verifying package" : "Verify & enroll local runner"}</Button>
      : props.runner?.state === "stopped" && props.runner.enrollment === "active"
        ? <Button size="small" variant="primary" disabled={props.runnerActionPending} onClick={() => props.onRunnerAction("start")}><Play/>{props.runnerActionPending ? "Starting host" : "Start authenticated runner"}</Button>
        : <Link className="execute-guide-link" to="/runners">Open runner diagnostics <ArrowRight/></Link>
    : undefined;
  const approvalAction = !props.job
    ? props.canCreateJob
      ? <Button size="small" variant="primary" disabled={props.jobSubmissionPending} onClick={props.onCreateJob}><ShieldCheck/>{props.jobSubmissionPending ? "Creating request" : "Create approval-gated job"}</Button>
      : <Button size="small" variant="secondary" onClick={props.onReviewEnvelope}>Review exact envelope</Button>
    : awaitingApproval
      ? <Button size="small" variant="primary" onClick={props.onReviewApproval}>Review one-time approval</Button>
      : undefined;

  return <Panel className="execute-onboarding" id="guided-execute" aria-label="Guided local Execute">
    <PanelHeader eyebrow="Guided local Execute" title="Runner ready to approved run" detail="One next action at a time. BlueFire creates local trust automatically; execution stays stopped until the exact durable job is approved." actions={<Badge tone={completed ? "success" : "warning"}>{completed ? "Completed" : "Safety-gated"}</Badge>} />
    {props.demoMode ? <Callout tone="warning" title="Production local service required">Demo mode cannot enroll a runner or execute effects. Relaunch the installed local service to use this guide.</Callout> : null}
    <ol className="execute-onboarding-steps">
      <Step number={1} state={runnerState} title="Make the local runner ready" detail="Verify the packaged native runner, establish recoverable local trust, then start its authenticated loopback host." status={props.runnerPending ? "Checking" : runnerReady ? "Ready" : props.runnerError ? "Unavailable" : sentence(props.runner?.state ?? "unavailable")} action={runnerAction} />
      <Step number={2} state={scenarioState} title="Choose the seeded Execute scenario" detail="Use the fixed restricted persistence canary, exact sandbox.workspace scope, AI Off, mandatory cleanup, and filesystem observation." status={scenarioReady ? "Selected" : !props.profile || !props.seededScenario ? "Unavailable" : "Not selected"} action={scenarioState === "current" && props.profile && props.seededScenario ? <Button size="small" variant="primary" onClick={props.onSelectScenario}>Use seeded restricted canary</Button> : undefined} />
      <Step number={3} state={preflightState} title="Preflight the exact intent" detail="Resolve policy, action contracts, scope, collector, cleanup, and immutable approval digests before creating a job." status={preflightReady ? "Envelope ready" : props.preflightPending ? "Resolving" : props.preflight ? sentence(props.preflight.status) : "Required"} action={preflightState === "current" ? <Button size="small" variant="primary" disabled={props.preflightPending} onClick={props.onPreflight}><ShieldCheck/>{props.preflightPending ? "Running preflight" : "Run guided preflight"}</Button> : undefined} />
      <Step number={4} state={approvalState} title="Approve the immutable job once" detail={awaitingApproval ? "Execution is stopped. Review the server-returned job envelope, confirm it, and supply the operator identity for this one release." : "First acknowledge the displayed preflight envelope locally and create its durable job; that acknowledgement is not execution approval."} status={approvalReleased ? "Released" : awaitingApproval && preflightReady ? "Awaiting approval" : preflightReady ? "Review required" : "Locked"} action={approvalState === "current" ? approvalAction : undefined} />
      <Step number={5} state={runState} title="Run, observe, and clean up" detail="Approval releases only this job. The live controller reports runner execution, independent observation, final cleanup, and the canonical run record." status={completed ? "Completed" : approvalReleased ? sentence(props.job?.state ?? "running") : "Waiting for approval"} />
    </ol>
    <footer><span>Certificate, HMAC, revocation, and removal controls stay out of the normal path.</span><Link to="/runners">Advanced runner diagnostics <ArrowRight/></Link></footer>
  </Panel>;
}
