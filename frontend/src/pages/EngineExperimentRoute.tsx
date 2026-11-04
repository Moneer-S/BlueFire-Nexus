import { useQuery } from "@tanstack/react-query";
import { useMemo } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { EngineExperimentWorkspace } from "../components/EngineExperimentWorkspace";
import { ErrorState, LoadingState } from "../components/Primitives";
import { engineExperimentApi, engineExperimentId, engineExperimentPath } from "../lib/engine-experiment-api";
import { engineExperimentSelection } from "../lib/engine-assistance";
import { usePublishEngineExperimentSelection } from "../state/AssistanceContext";
import { useRememberDefensiveWork } from "../state/activeDefensiveWork";
import { CompositionPage } from "./Composition";

const ATTEMPT_ID = /^engine-attempt-[0-9a-f]{32}$/;
const CHECK_ID = /^controller-check-[0-9a-f]{32}$/;

export type EngineExperimentRouteSelection = { kind: "engine_attempt" | "controller_check"; id: string } | null;
export type EngineExperimentRouteRequest = { experimentId: string; selection: EngineExperimentRouteSelection };

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
  return parsed.request ? <EngineExperimentRoute request={parsed.request} /> : <CompositionPage />;
}

function EngineExperimentRoute({ request }: { request: EngineExperimentRouteRequest }) {
  const navigate = useNavigate();
  const workspace = useQuery({ queryKey: ["engine-experiment-workspace", request.experimentId, request.selection?.kind ?? null, request.selection?.id ?? null], queryFn: () => engineExperimentApi.workspace(request.experimentId, request.selection), retry: false, refetchInterval: state => {
    const projection = state.state.data?.projection;
    return projection && ([...projection.attempts].some(item => ["queued", "preflight", "running", "stopping"].includes(item.state)) || projection.checks.some(item => item.state === "reserved")) ? 1500 : false;
  } });
  const experiment = workspace.data;
  const selectedAttempt = request.selection?.kind === "engine_attempt" ? request.selection.id : null;
  const selectedCheck = request.selection?.kind === "controller_check" ? request.selection.id : null;
  const assistantSelection = useMemo(() => experiment ? engineExperimentSelection(experiment, selectedAttempt, selectedCheck) : undefined, [experiment, selectedAttempt, selectedCheck]);
  usePublishEngineExperimentSelection(assistantSelection, experiment?.objective.title);
  useRememberDefensiveWork("engine", experiment?.experiment_id);
  const select = (selection: EngineExperimentRouteSelection) => navigate(engineExperimentPath(request.experimentId, selection));
  if (workspace.isPending) return <div className="page"><LoadingState label="Loading engine experiment" /></div>;
  if (workspace.isError || !experiment) return <div className="page"><Link to="/composition">Composition workspace</Link><ErrorState title="Engine experiment unavailable" error={workspace.error ?? new Error("The engine experiment workspace is unavailable.")} retry={() => { void workspace.refetch(); }} /></div>;
  return <div className="page engine-experiment-route">
    <Link to="/composition">Composition workspace</Link>
    <EngineExperimentWorkspace experiment={experiment} selectedAttemptId={selectedAttempt} selectedCheckId={selectedCheck}
      onSelectAttempt={id => select({ kind: "engine_attempt", id })}
      onSelectCheck={id => select({ kind: "controller_check", id })}
      runHref={id => `/runs/${encodeURIComponent(id)}`} />
  </div>;
}
