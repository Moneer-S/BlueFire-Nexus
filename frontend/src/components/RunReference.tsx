import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api } from "../lib/api";
import { runLabel } from "../lib/runPresentation";
import type { RunRecord } from "../types";
import { CopyRunId } from "./RunNameControl";
import { formatDate, sentence } from "./Primitives";
import "./RunReference.css";

function matchesRun(value: RunRecord | undefined, runId: string): value is RunRecord {
  return Boolean(value && value.run_id === runId
    && (value.schema_version === undefined || value.schema_version === "bluefire.run-result.v1")
    && (value.mode === "simulate" || value.mode === "execute")
    && typeof value.finalized_at === "string" && Array.isArray(value.steps));
}

/** Presentation-only lookup: it cannot replace an evidence binding or gate work. */
export function RunReference({ runId, label, onNavigate }: { runId: string; label?: string; onNavigate?: () => void }) {
  const query = useQuery({ queryKey: ["run", runId], queryFn: async () => {
    const run = await api.runDetail(runId);
    if (!matchesRun(run, runId)) throw new Error("The run details do not match this reference.");
    return run;
  }, retry: false });
  // Check cached data too: a prior response for another ID must never label this link.
  const run = matchesRun(query.data, runId) ? query.data : undefined;
  const name = runLabel({ run_id: runId, presentation: run?.presentation,
    scenario_title: typeof run?.scenario?.title === "string" ? run.scenario.title : typeof run?.scenario_title === "string" ? run.scenario_title : undefined });
  const time = run?.created_at || run?.finalized_at;
  const profile = typeof run?.runner_profile_id === "string" ? run.runner_profile_id : typeof run?.profile?.id === "string" ? run.profile.id : undefined;
  return <div className="run-reference">
    {label ? <small>{label}</small> : null}
    <Link onClick={onNavigate} to={`/runs/${encodeURIComponent(runId)}`} aria-label={label ? `${label}: ${name}` : name}>{name}</Link>
    {run ? <small>{sentence(run.mode)}{time && Number.isFinite(Date.parse(time)) ? <> · <time dateTime={time}>{formatDate(time)}</time></> : null}{profile ? <> · Profile: {profile}</> : null}</small> : query.isError ? <small>Run details unavailable</small> : null}
    <details><summary>Run identity</summary><CopyRunId key={runId} runId={runId}/></details>
  </div>;
}
