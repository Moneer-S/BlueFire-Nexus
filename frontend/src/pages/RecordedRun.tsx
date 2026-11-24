// One recorded run inside the app: loads the recording the service keeps, reads
// it, and plays it in the live view. The address holds the moment, so a link
// opens the same step in the same mode.

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useLocation, useParams, useSearchParams } from "react-router-dom";
import { api, type RecordingList, type RecordingSummary } from "../lib/api";
import { addressShows, momentFromSearch, momentSearch, namesMissingStep, originWords, recordingKindWords, withSummary } from "../lib/recorded-runs";
import { LiveView, type LiveMoment, type LiveViewProps } from "../live/LiveView";
import { LiveViewBoundary } from "../live/LiveViewBoundary";
import { RecordingError, readRecording, type Recording } from "../live/recording";
import { ErrorState, LoadingState } from "../components/Primitives";
import "./RecordedRun.css";

/** How often a recording that is still running is asked for again. */
const RUNNING_POLL_MS = 4_000;
/** The address follows the viewer after this pause, so dragging the scrubber does not rewrite it on every move. */
const ADDRESS_SETTLE_MS = 300;

/**
 * Reads the recording to play. An imported file's CI run address is only what
 * the file says, so the live view is not given it: it would link that run as
 * the one that made the recording. The bar above says the file names it.
 */
function read(value: unknown, summary: RecordingSummary): { recording: Recording } | { problem: string } {
  try {
    // The app follows a recording that is still running, which the replay page refuses.
    const recording = readRecording(value, { running: true });
    if (summary.origin.kind !== "imported" || recording.source.run_url === undefined) return { recording };
    const source = { ...recording.source };
    delete source.run_url;
    return { recording: { ...recording, source } };
  } catch (error) {
    if (error instanceof RecordingError) return { problem: error.message };
    return { problem: `The recording could not be checked: ${error instanceof Error ? error.message : "an unknown failure"}.` };
  }
}

export function RecordedRunPage() {
  const { recordingId = "", file } = useParams<{ recordingId: string; file?: string }>();
  // A different recording, or another file of it, is a fresh page, with its own moment.
  return <RecordedRun key={`${recordingId}/${file ?? ""}`} recordingId={recordingId} file={file} />;
}

/**
 * One recording: the first file kept for its id, or, with `file`, the kept file
 * with that SHA-256: a run evaluated more than once keeps one per evaluation,
 * and the same recording sent in other bytes is kept beside the first.
 */
function RecordedRun({ recordingId, file }: { recordingId: string; file?: string }) {
  const entry = useQuery({
    queryKey: file ? ["recording-file", recordingId, file] : ["recording", recordingId],
    queryFn: () => (file ? api.recordingFile(recordingId, file) : api.recording(recordingId)),
    retry: false,
    refetchInterval: (query) => (query.state.data?.summary.running ? RUNNING_POLL_MS : false),
  });
  const data = entry.data;
  const reading = useMemo(() => (data ? read(data.recording, data.summary) : null), [data]);
  const queryClient = useQueryClient();
  // The list shows the first file of each id, so only that file's answer is put in it.
  const summary = file ? undefined : data?.summary;
  // The list of recorded runs, kept from the last visit to Runs, can hold an
  // older version of this run, from before it grew or finished: this page's
  // answer is newer, so the list shows it too.
  useEffect(() => {
    if (!summary) return;
    const list = queryClient.getQueryData<RecordingList>(["recordings"]);
    if (!list) return;
    const updated = withSummary(list, summary);
    // The rest of the list is as old as it was: it is asked again as often as before.
    if (updated) queryClient.setQueryData<RecordingList>(["recordings"], updated, { updatedAt: queryClient.getQueryState(["recordings"])?.dataUpdatedAt });
    else void queryClient.invalidateQueries({ queryKey: ["recordings"] });
  }, [queryClient, summary]);

  if (entry.isPending) return <div className="recorded-run is-message"><LoadingState label="Loading the recording" /></div>;
  if (!data) {
    return <div className="recorded-run is-message">
      <RecordedRunBar />
      <div className="recorded-run-message"><ErrorState title="This recording could not be loaded" error={entry.error} retry={() => { void entry.refetch(); }} /></div>
    </div>;
  }
  return <div className="recorded-run">
    <RecordedRunBar summary={data.summary} pollError={entry.isError && data.summary.running ? entry.error : null} />
    {reading && "recording" in reading
      ? <RecordedRunView recording={reading.recording} />
      : <CannotPlay message={reading?.problem ?? "The recording could not be read."} />}
  </div>;
}

function CannotPlay({ message }: { message: string }) {
  return <div className="recorded-run-message" role="alert">
    <div>
      <h1>This recording cannot be played</h1>
      <p>{message}</p>
      <Link to="/runs">Back to Runs</Link>
    </div>
  </div>;
}

/**
 * The quiet line above the live view: back to Runs, what the recording is, and
 * where it comes from. The live view's own header says when and where it was
 * recorded and links the CI run, so this line does not repeat them.
 */
function RecordedRunBar({ summary, pollError }: { summary?: RecordingSummary; pollError?: unknown }) {
  return <header className="recorded-run-bar">
    <nav className="recorded-run-line" aria-label="Recorded run">
      <Link className="recorded-run-back" to="/runs"><ArrowLeft aria-hidden="true" />Runs</Link>
      {summary ? <p className="recorded-run-facts">
        <span className="recorded-run-title">{summary.title}</span>
        <span>{recordingKindWords(summary.kind)}</span>
        <span className={`recorded-run-origin is-${summary.origin.kind}`}>{originWords(summary.origin)}</span>
        {summary.running ? <span className="recorded-run-running" role="status"><i aria-hidden="true" />Still running: new steps appear as they arrive</span> : null}
      </p> : null}
    </nav>
    {summary?.origin.kind === "imported" ? <p className="recorded-run-note">
      {summary.origin.note}
      {summary.source.run_url ? <> The file names this CI run, which BlueFire cannot confirm: <span className="recorded-run-claimed">{summary.source.run_url}</span></> : null}
    </p> : null}
    {pollError ? <p className="recorded-run-note is-problem" role="status">Could not ask the service for more of this run: {pollError instanceof Error ? pollError.message : "the request failed"}. Trying again.</p> : null}
  </header>;
}

function RecordedRunView({ recording }: { recording: Recording }) {
  const { pathname } = useLocation();
  const [searchParams, setSearchParams] = useSearchParams();
  const [initial, setInitial] = useState<NonNullable<LiveViewProps["initial"]>>(() => momentFromSearch(searchParams));
  const [mount, setMount] = useState(0);
  const [fixing, setFixing] = useState<string | null>(null);
  const latest = useRef<LiveMoment | null>(null);
  const pending = useRef<number | undefined>(undefined);
  const note = useRef<HTMLParagraphElement | null>(null);
  // The address this page last wrote, or opened with. Any other is a moment someone asked for.
  const written = useRef(searchParams.toString());
  const address = searchParams.toString();
  // Where the view opened, as an address, when the address named a step the recording does not hold.
  // Until the viewer moves from there, the address keeps naming that step, as the line under the title
  // does: it does not take the place the view fell back to for the one that was asked for.
  const opened = useRef<{ search: string; left: boolean } | null>(null);
  const missing = namesMissingStep(recording, initial);

  // The address follows the viewer, replacing itself, so moving through a run adds nothing to the browser's history.
  // Only while the address is still this run's: once someone has gone to another page, writing it would take them back.
  const onMoment = useCallback((moment: LiveMoment) => {
    latest.current = moment;
    window.clearTimeout(pending.current);
    const next = momentSearch(moment).toString();
    if (missing && !opened.current?.left) {
      opened.current ??= { search: next, left: false };
      if (next === opened.current.search) return;
      opened.current.left = true;
    }
    pending.current = window.setTimeout(() => {
      if (next === written.current || !addressShows(pathname)) return;
      written.current = next;
      setSearchParams(next, { replace: true, preventScrollReset: true });
    }, ADDRESS_SETTLE_MS);
  }, [missing, pathname, setSearchParams]);
  useEffect(() => () => window.clearTimeout(pending.current), []);

  // A link to another moment of this run, or the browser's Back, opens the view there.
  useEffect(() => {
    if (address === written.current) return;
    window.clearTimeout(pending.current);
    written.current = address;
    opened.current = null;
    setFixing(null);
    setInitial(momentFromSearch(new URLSearchParams(address)));
    setMount((value) => value + 1);
  }, [address]);

  // "Fix this" opens the step's detail, whose hint says where the gap is. Making the change in BlueFire comes later.
  const onFix = useCallback((stepId: string) => {
    const now = latest.current;
    setFixing(stepId);
    if (now?.mode === "analyse" && now.select === stepId) return;
    opened.current = null;
    setInitial({ step: stepId, paused: true, mode: "analyse", select: stepId });
    setMount((value) => value + 1);
  }, []);
  useEffect(() => {
    if (fixing !== null) note.current?.focus();
  }, [fixing, mount]);
  const fixingTitle = fixing === null ? undefined : recording.steps.find((step) => step.id === fixing)?.title;

  return <>
    {fixing !== null ? <div className="recorded-run-fix">
      <p ref={note} tabIndex={-1} role="status">
        Fix this{fixingTitle ? <>, <strong>{fixingTitle}</strong></> : null}: the hint in the step's detail says where the gap is. BlueFire cannot make the change for you yet.
      </p>
      <button type="button" onClick={() => setFixing(null)}>Dismiss</button>
    </div> : null}
    <div className="recorded-run-view">
      <LiveViewBoundary fallback={(message) => <CannotPlay message={message} />}>
        <LiveView key={mount} recording={recording} initial={initial} onFix={onFix} onMoment={onMoment} />
      </LiveViewBoundary>
    </div>
  </>;
}
