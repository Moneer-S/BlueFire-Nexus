import { useMutation, useQuery } from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { EngineExperimentWorkspace } from "../components/EngineExperimentWorkspace";
import { Callout, ErrorState, LoadingState } from "../components/Primitives";
import { engineExperimentApi, engineExperimentId, engineExperimentPath } from "../lib/engine-experiment-api";
import { engineExperimentSelection } from "../lib/engine-assistance";
import { usePublishEngineExperimentSelection } from "../state/AssistanceContext";
import { useRememberDefensiveWork } from "../state/activeDefensiveWork";
import { CompositionPage } from "./Composition";
import { EngineActionReview } from "../components/EngineActionReview";
import { engineActionLabels, type EngineActionAcceptance, type PreparedActionKind } from "../lib/engine-actions";
import type { EngineExperiment } from "../lib/engine-experiment";
import { api } from "../lib/api";

const ATTEMPT_ID = /^engine-attempt-[0-9a-f]{32}$/;
const CHECK_ID = /^controller-check-[0-9a-f]{32}$/;

export type EngineExperimentRouteSelection = { kind: "engine_attempt" | "controller_check"; id: string } | null;
export type EngineExperimentRouteRequest = { experimentId: string; selection: EngineExperimentRouteSelection };

type EngineCancellationRequest = { kind: "engine_attempt"; id: string; jobId: string };

const attemptSelection = (experiment: EngineExperiment, role: "baseline" | "adaptive_search"): EngineExperimentRouteSelection => {
  const attempt = experiment.projection.attempts.find(item => item.role === role);
  return attempt ? { kind: "engine_attempt", id: attempt.attempt_id } : null;
};
const checkSelection = (experiment: EngineExperiment, role: "retained_reproducer" | "legitimate_use"): EngineExperimentRouteSelection => {
  const check = experiment.projection.checks.find(item => item.role === role);
  return check ? { kind: "controller_check", id: check.check_id } : null;
};

export function engineReviewSelection(experiment: EngineExperiment): EngineExperimentRouteSelection {
  const baseline = () => attemptSelection(experiment, "baseline");
  const reproducer = () => checkSelection(experiment, "retained_reproducer");
  const adaptive = () => attemptSelection(experiment, "adaptive_search");
  const legitimate = () => checkSelection(experiment, "legitimate_use");
  switch (experiment.projection.workflow_state) {
    case "baseline_active": return baseline();
    case "retained_reproducer_active": return reproducer();
    case "adaptive_search_active": return adaptive();
    case "legitimate_use_active": return legitimate();
    case "review_defense":
    case "apply_defense":
    case "reconcile_defense":
    case "run_retained_reproducer": return baseline();
    case "run_adaptive_search": return reproducer() ?? baseline();
    case "run_legitimate_use": return adaptive() ?? reproducer() ?? baseline();
    case "choose_defense_disposition":
    case "complete": return legitimate() ?? adaptive() ?? reproducer() ?? baseline();
    default: return null;
  }
}

export function resolvedEngineActionAcceptance(accepted: EngineActionAcceptance, experiment: EngineExperiment): { resolved: boolean; selection: EngineExperimentRouteSelection } {
  if (accepted.experiment_id !== experiment.experiment_id) return { resolved: false, selection: null };
  if (accepted.transition) return {
    resolved: experiment.revision === accepted.transition.revision && experiment.experiment_digest === accepted.transition.digest,
    selection: null,
  };
  const attempt = experiment.projection.attempts.find(item => item.job_id === accepted.job?.job_id);
  if (attempt) return { resolved: true, selection: { kind: "engine_attempt", id: attempt.attempt_id } };
  const check = experiment.projection.checks.find(item => item.job_id === accepted.job?.job_id);
  return check ? { resolved: true, selection: { kind: "controller_check", id: check.check_id } } : { resolved: false, selection: null };
}

export function parseEngineExperimentRoute(search: string): EngineExperimentRouteRequest | null {
  const params = new URLSearchParams(search);
  const experimentValues = params.getAll("engine_experiment");
  if (!experimentValues.length) return null;
  const rawQuery = search.startsWith("?") ? search.slice(1) : search;
  if (params.toString() !== rawQuery) throw new Error("This engine experiment link is invalid.");
  if (experimentValues.length !== 1 || [...params.keys()].some(key => !["engine_experiment", "attempt", "check"].includes(key))) throw new Error("This engine experiment link is invalid.");
  const attempts = params.getAll("attempt"), checks = params.getAll("check");
  if (!engineExperimentId(experimentValues[0]) || attempts.length > 1 || checks.length > 1 || attempts.length && checks.length
    || attempts.length === 1 && !ATTEMPT_ID.test(attempts[0]!) || checks.length === 1 && !CHECK_ID.test(checks[0]!)) throw new Error("This engine experiment link is invalid.");
  return {
    experimentId: experimentValues[0]!,
    selection: attempts.length ? { kind: "engine_attempt", id: attempts[0]! } : checks.length ? { kind: "controller_check", id: checks[0]! } : null,
  };
}

export function CompositionRoute() {
  const location = useLocation();
  const parsed = useMemo(() => {
    try { return { request: parseEngineExperimentRoute(location.search), error: undefined }; }
    catch (error) { return { request: undefined, error }; }
  }, [location.search]);
  if (parsed.error) return <div className="page"><Link to="/composition">Composition workspace</Link><ErrorState title="Engine experiment link unavailable" error={parsed.error} /></div>;
  return parsed.request ? <EngineExperimentRoute key={parsed.request.experimentId} request={parsed.request} /> : <CompositionPage />;
}

function EngineExperimentRoute({ request }: { request: EngineExperimentRouteRequest }) {
  const navigate = useNavigate();
  const [reviewAction, setReviewAction] = useState<PreparedActionKind | null>(null);
  const [reviewOpen, setReviewOpen] = useState(false);
  const [uncertainAction, setUncertainAction] = useState<PreparedActionKind | null>(null);
  const [reviewNotice, setReviewNotice] = useState<string>();
  const [accepted, setAccepted] = useState<EngineActionAcceptance>();
  const [pollUntil, setPollUntil] = useState(0);
  const workspace = useQuery({ queryKey: ["engine-experiment-workspace", request.experimentId, request.selection?.kind ?? null, request.selection?.id ?? null], queryFn: () => engineExperimentApi.workspace(request.experimentId, request.selection), retry: false, refetchInterval: state => {
    const projection = state.state.data?.projection;
    return accepted && Date.now() < pollUntil || projection && ([...projection.attempts].some(item => ["queued", "preflight", "running", "stopping"].includes(item.state)) || projection.checks.some(item => item.state === "reserved")) ? 1500 : false;
  } });
  const experiment = workspace.data;
  const selectedAttempt = request.selection?.kind === "engine_attempt" ? request.selection.id : null;
  const selectedCheck = request.selection?.kind === "controller_check" ? request.selection.id : null;
  const assistantSelection = useMemo(() => experiment ? engineExperimentSelection(experiment, selectedAttempt, selectedCheck) : undefined, [experiment, selectedAttempt, selectedCheck]);
  usePublishEngineExperimentSelection(assistantSelection, experiment?.objective.title);
  useRememberDefensiveWork("engine", experiment?.experiment_id);
  const select = (selection: EngineExperimentRouteSelection) => navigate(engineExperimentPath(request.experimentId, selection));
  const cancellation = useMutation({
    mutationFn: (request: EngineCancellationRequest) => api.controlJob(request.jobId, "cancel"),
    onSuccess: () => { void workspace.refetch(); },
  });
  const cancelAttempt = (id: string) => {
    if (cancellation.isPending) return;
    const item = experiment?.projection.attempts.find(candidate => candidate.attempt_id === id);
    if (item) cancellation.mutate({ kind: "engine_attempt", id, jobId: item.job_id });
  };
  useEffect(() => {
    if (!experiment || !accepted) return;
    const resolution = resolvedEngineActionAcceptance(accepted, experiment);
    if (!resolution.resolved) return;
    if (resolution.selection) navigate(engineExperimentPath(request.experimentId, resolution.selection));
    setAccepted(undefined);
  }, [experiment, accepted, navigate, request.experimentId]);
  if (workspace.isPending) return <div className="page"><LoadingState label="Loading engine experiment" /></div>;
  if (workspace.isError || !experiment) return <div className="page"><Link to="/composition">Composition workspace</Link><ErrorState title="Engine experiment unavailable" error={workspace.error ?? new Error("The engine experiment workspace is unavailable.")} retry={() => { void workspace.refetch(); }} /></div>;
  return <div className="page engine-experiment-route">
    <Link to="/composition">Composition workspace</Link>
    {reviewNotice ? <Callout tone="warning" title="Unconfirmed action acceptance"><p>{reviewNotice}</p></Callout> : null}
    {accepted ? <Callout title="Action accepted"><p>{accepted.job ? "The durable job was accepted. BlueFire is refreshing its saved status." : "The saved workspace transition was accepted and is being refreshed."}</p>{accepted.job ? <Link to={`/runs?job=${encodeURIComponent(accepted.job.job_id)}`}>Open saved job in Runs</Link> : null}<button type="button" className="button button-secondary button-small" onClick={() => { setPollUntil(Date.now() + 60_000); void workspace.refetch(); }}>Refresh action status</button></Callout> : null}
    {cancellation.variables ? <Callout tone={cancellation.isError ? "danger" : cancellation.isSuccess ? "success" : "info"} title={cancellation.isError ? "Cancellation was refused" : cancellation.isSuccess ? "Cancellation requested" : "Requesting cancellation"}><p>{cancellation.isError ? (cancellation.error instanceof Error ? cancellation.error.message : "The saved job could not be cancelled.") : cancellation.isSuccess ? "BlueFire accepted the cancellation request and is refreshing the saved work state." : "BlueFire is asking the saved job to stop and will preserve its recorded evidence."}</p><Link to={`/runs?job=${encodeURIComponent(cancellation.variables.jobId)}`}>Open saved job in Runs</Link><button type="button" className="button button-secondary button-small" onClick={() => { void workspace.refetch(); }}>Refresh saved state</button></Callout> : null}
    <EngineExperimentWorkspace experiment={experiment} selectedAttemptId={selectedAttempt} selectedCheckId={selectedCheck}
      onSelectAttempt={id => select({ kind: "engine_attempt", id })}
      onSelectCheck={id => select({ kind: "controller_check", id })}
      onCancelAttempt={cancelAttempt}
      cancellingAttemptId={!cancellation.isError && cancellation.variables?.kind === "engine_attempt" ? cancellation.variables.id : null}
      onPrimaryAction={action => {
        if (action === "review_evidence") { const selection = engineReviewSelection(experiment); if (selection) select(selection); }
        else if (action === "open_comparison") {
          const comparison = document.querySelector<HTMLElement>(".engine-retest-comparison");
          comparison?.setAttribute("tabindex", "-1"); comparison?.focus(); comparison?.scrollIntoView({ block: "start" });
        }
        else if (Object.hasOwn(engineActionLabels, action)) {
          const selected = action as PreparedActionKind;
          if (uncertainAction && uncertainAction !== selected) {
            setReviewNotice(`Acceptance of ${engineActionLabels[uncertainAction].toLowerCase()} is unconfirmed. Recover that exact prepared request before reviewing another action.`);
            setReviewAction(uncertainAction); setReviewOpen(true);
          } else {
            setReviewNotice(undefined); setReviewAction(selected); setReviewOpen(true);
          }
        }
      }}
      runHref={id => `/runs/${encodeURIComponent(id)}`} />
    <EngineActionReview key={`${request.experimentId}:${reviewAction ?? "none"}`} open={reviewOpen} actionKind={reviewAction} onClose={() => setReviewOpen(false)} onUncertainChange={action => { setUncertainAction(action); if (!action) setReviewNotice(undefined); }} experiment={experiment} onAccepted={receipt => { setAccepted(receipt); setReviewOpen(false); setPollUntil(Date.now() + 60_000); void workspace.refetch(); }} />
  </div>;
}
