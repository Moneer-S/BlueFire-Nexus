// The recorded runs on the Runs screen: what the service keeps, newest first,
// each opening in the live view, and one control to import a recording file.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowRight, FileUp, Radio, RotateCcw } from "lucide-react";
import { useRef, useState, type ChangeEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api, ApiError, type RecordingSummary } from "../lib/api";
import { newestFirst, originWords, recordedRaceWords, recordedRunPath, recordedScoreWords, recordedWhere, recordingKindWords } from "../lib/recorded-runs";
import { Button, ErrorState, LoadingState, Panel } from "./Primitives";

/** The problems a refused import names, in the service's own words. */
function refusalProblems(error: unknown): string[] {
  if (!(error instanceof ApiError) || !error.details || typeof error.details !== "object") return [];
  const problems = (error.details as { problems?: unknown }).problems;
  return Array.isArray(problems) ? problems.filter((item): item is string => typeof item === "string") : [];
}

type ImportProblem = { message: string; problems: string[] };

function readText(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(typeof reader.result === "string" ? reader.result : "");
    reader.onerror = () => reject(reader.error ?? new Error("the file could not be read"));
    reader.readAsText(file);
  });
}

export function RecordedRuns() {
  const recordings = useQuery({ queryKey: ["recordings"], queryFn: api.recordings });
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const input = useRef<HTMLInputElement | null>(null);
  const [problem, setProblem] = useState<ImportProblem | null>(null);
  const importing = useMutation({
    mutationFn: (recording: unknown) => api.importRecording(recording),
    onSuccess: async (result) => {
      setProblem(null);
      // A recording imported again under its id, a running one that grew or finished, is not shown from the cache.
      queryClient.removeQueries({ queryKey: ["recording", result.summary.id] });
      await queryClient.invalidateQueries({ queryKey: ["recordings"] });
      navigate(recordedRunPath(result.summary.id));
    },
    onError: (error) => {
      setProblem({ message: error instanceof Error ? error.message : "The import failed.", problems: refusalProblems(error) });
      // An answer that was lost or could not be read may follow an import that was kept, so the list is asked again.
      void queryClient.invalidateQueries({ queryKey: ["recordings"] });
    },
  });
  const chooseFile = async (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.currentTarget.files?.[0];
    event.currentTarget.value = "";
    if (!file) return;
    setProblem(null);
    let value: unknown;
    try {
      value = JSON.parse(await readText(file));
    } catch (error) {
      setProblem({ message: `${file.name} is not a JSON file, so it was not sent: ${error instanceof Error ? error.message : "it could not be read"}.`, problems: [] });
      return;
    }
    importing.mutate(value);
  };
  const list = recordings.data ? newestFirst(recordings.data.recordings) : undefined;
  const unreadable = recordings.data?.unreadable_count ?? 0;
  const omitted = recordings.data?.omitted_count ?? 0;

  return <Panel className="recorded-runs" aria-labelledby="recorded-runs-heading">
    <header className="panel-header">
      <div>
        <h2 id="recorded-runs-heading">Recorded runs</h2>
        <p>Real runs, recorded step by step with what the sensors saw and which rules fired. Open one to watch it.</p>
      </div>
      <div className="recorded-runs-actions">
        <Button size="small" variant="ghost" aria-label="Refresh recorded runs" onClick={() => { void recordings.refetch(); }} disabled={recordings.isFetching}><RotateCcw aria-hidden="true" />Refresh</Button>
        <Button size="small" onClick={() => input.current?.click()} disabled={importing.isPending}><FileUp aria-hidden="true" />{importing.isPending ? "Importing" : "Import a recording"}</Button>
        <input ref={input} className="sr-only" type="file" accept=".json,application/json" aria-label="Recording file to import" tabIndex={-1} onChange={(event) => { void chooseFile(event); }} />
      </div>
    </header>
    {problem ? <div className="recorded-runs-refusal" role="alert">
      <strong>The recording was not imported</strong>
      {problem.problems.length > 1 ? <><p>The service found these problems:</p><ul>{problem.problems.map((item, index) => <li key={index}>{item}</li>)}</ul></> : <p>{problem.message}</p>}
      <Button size="small" variant="ghost" onClick={() => setProblem(null)}>Dismiss</Button>
    </div> : null}
    {recordings.isError ? <ErrorState title="Recorded runs unavailable" error={recordings.error} retry={() => { void recordings.refetch(); }} /> : null}
    {unreadable > 0 ? <p className="workspace-note" role="status">{unreadable} imported {unreadable === 1 ? "recording no longer follows" : "recordings no longer follow"} the recording format and {unreadable === 1 ? "is" : "are"} not listed.</p> : null}
    {omitted > 0 ? <p className="workspace-note" role="status">{omitted} more imported {omitted === 1 ? "recording is" : "recordings are"} kept but not listed: the list reads the first 200.</p> : null}
    {recordings.isPending ? <LoadingState label="Loading recorded runs" />
      : list?.length ? <ul className="recorded-run-list">{list.map((summary) => <RecordedRunItem key={summary.id} summary={summary} />)}</ul>
      : recordings.isSuccess ? <div className="inline-empty"><span>No recorded runs yet. Import a recording file made by the lab.</span></div> : null}
  </Panel>;
}

/** A thin bar of the score: alerted, seen and unseen, as parts of the tests that took effect. */
function ScoreBar({ summary }: { summary: RecordingSummary }) {
  const { alerted, seen, unseen, took_effect: total } = summary.score;
  if (total <= 0) return null;
  const part = (value: number) => `${(100 * value) / total}%`;
  return <span className="recorded-run-bar-chart" aria-hidden="true">
    <i className="is-alerted" style={{ width: part(alerted) }} />
    <i className="is-seen" style={{ width: part(seen) }} />
    <i className="is-unseen" style={{ width: part(unseen) }} />
  </span>;
}

function RecordedRunItem({ summary }: { summary: RecordingSummary }) {
  const race = recordedRaceWords(summary);
  return <li className={`recorded-run-item${summary.running ? " is-running" : ""}`}>
    <span className="recorded-run-symbol" aria-hidden="true"><Radio /></span>
    <div className="recorded-run-main">
      <Link className="recorded-run-link" to={recordedRunPath(summary.id)}>{summary.title}</Link>
      <p className="recorded-run-meta">
        <span>{recordingKindWords(summary.kind)}</span>
        <span>{recordedWhere(summary)}</span>
        <span className={`recorded-run-origin is-${summary.origin.kind}`}>{originWords(summary.origin)}</span>
        {summary.running ? <span className="recorded-run-live"><i aria-hidden="true" />Still running</span> : null}
      </p>
      <p className="recorded-run-score">
        <ScoreBar summary={summary} />
        <span>{recordedScoreWords(summary)}</span>
        {race ? <span className="recorded-run-race">{race}</span> : null}
      </p>
    </div>
    <span className="recorded-run-open" aria-hidden="true">{summary.running ? "Watch" : "Play"}<ArrowRight /></span>
  </li>;
}
