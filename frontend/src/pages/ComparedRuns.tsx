// One pair of recorded runs, before against after, drawn from the delta that
// `bluefire-lab compare` wrote and nothing else: the declared change, what it
// moved and at what price, the control, and what was refused. No difference is
// worked out here. The two recordings are fetched only to open a step's detail
// for both sides, next to each other.

import { useQuery } from "@tanstack/react-query";
import { ArrowLeft, ArrowRight } from "lucide-react";
import { useEffect, useMemo, useRef } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { api, type Delta, type DeltaLimit, type DeltaSide, type DeltaStep, type DeltaSummary } from "../lib/api";
import { originWords, recordedRunPath } from "../lib/recorded-runs";
import { changeWords, chipField, codeSpans, controlWords, creditsWords, isCredited, isDigest, limitOf, movedSteps, raceWords, recordsParts, resultWords, runnerDifferences, setupLede, setupWords, shortValue, sideWhere, variationWords, verdictParts } from "../lib/recording-pairs";
import { stepRows } from "../live/analyse";
import { outcomeClass, outcomeWords, plural, runLink, sensorColours, testNumbers } from "../live/format";
import { runFacts } from "../live/moment";
import { buildTimeline } from "../live/playback";
import { readRecording, RecordingError, type Recording } from "../live/recording";
import { StepDetail } from "../live/StepDetail";
import { ErrorState, LoadingState } from "../components/Primitives";
import "../live/live.css";
import "./RecordedRun.css";
import "./ComparedRuns.css";

type Side = "before" | "after";
const SIDES: readonly Side[] = ["before", "after"];

export function ComparedRunsPage() {
  const { deltaId = "" } = useParams<{ deltaId: string }>();
  return <ComparedRuns key={deltaId} deltaId={deltaId} />;
}

function ComparedRuns({ deltaId }: { deltaId: string }) {
  const entry = useQuery({ queryKey: ["recording-delta", deltaId], queryFn: () => api.recordingDelta(deltaId), retry: false });
  if (entry.isPending) return <div className="compared is-message"><LoadingState label="Loading the compared runs" /></div>;
  if (!entry.data) {
    return <div className="compared is-message">
      <ComparedBar />
      <div className="compared-message"><ErrorState title="These compared runs could not be loaded" error={entry.error} retry={() => { void entry.refetch(); }} /></div>
    </div>;
  }
  return <div className="compared">
    <ComparedBar summary={entry.data.summary} />
    <PairView delta={entry.data.delta} summary={entry.data.summary} />
  </div>;
}

/** The quiet line under the app's header: back to Runs, what this page is, and where the pair comes from. */
function ComparedBar({ summary }: { summary?: DeltaSummary }) {
  // A shipped pair of two runs side by side names the one CI run that made both and compared them.
  const pairRun = summary?.origin.kind === "shipped" && summary.origin.run_url ? runLink({ run_url: summary.origin.run_url }) : null;
  return <header className="recorded-run-bar">
    <nav className="recorded-run-line" aria-label="Compared runs">
      <Link className="recorded-run-back" to="/runs"><ArrowLeft aria-hidden="true" />Runs</Link>
      {summary ? <p className="recorded-run-facts">
        <span className="recorded-run-title">Before against after</span>
        <span>{changeWords(summary.declared_change)}</span>
        <span className={`recorded-run-origin is-${summary.origin.kind}`}>{originWords(summary.origin)}</span>
        {pairRun ? <span>Both runs and this comparison made in CI <a href={pairRun} target="_blank" rel="noreferrer">{pairRun.replace(/^.*\/runs\//, "run ")}</a></span> : null}
      </p> : null}
    </nav>
    {summary && summary.origin.kind !== "shipped" ? <p className="recorded-run-note">{summary.origin.note}</p> : null}
  </header>;
}

function PairView({ delta, summary }: { delta: Delta; summary: DeltaSummary }) {
  const [params, setParams] = useSearchParams();
  const open = params.get("step");
  const moved = movedSteps(delta);
  const byId = useMemo(() => new Map(delta.steps.map((step) => [step.id, step])), [delta]);
  const unexplained = delta.unexplained.map((id) => byId.get(id)).filter((step): step is DeltaStep => step !== undefined);
  const race = raceWords(delta.race);
  const choose = (stepId: string | null) => {
    const next = new URLSearchParams(params);
    if (stepId === null) next.delete("step");
    else next.set("step", stepId);
    // A step's detail is a place of its own: Back closes it.
    setParams(next, { preventScrollReset: true });
  };
  const line = (step: DeltaStep) => <StepLine key={step.id} delta={delta} step={step} open={open === step.id} onToggle={() => choose(open === step.id ? null : step.id)} />;

  return <div className="lv compared-view">
    <div className="cmp-page">
      <Claim delta={delta} />
      <section className="cmp-runs" aria-label="The two runs">
        {SIDES.map((side) => <RunCard key={side} side={side} facts={delta[side]} summary={summary} />)}
        {sharedNote(summary) ? <p className="cmp-run-note cmp-runs-note">Both recordings: {sharedNote(summary)}</p> : null}
      </section>

      <section className="cmp-sec" aria-labelledby="cmp-moved">
        <h2 id="cmp-moved">{!delta.comparable ? "Steps that differ, with no verdict" : delta.declared_change === null ? "Steps credited to a change" : "What the change moved"}<span>{plural(moved.length, "step")} of {plural(delta.counts.paired, "paired step")}{delta.limit ? ", each credited by the change's own mark only" : ""}</span></h2>
        {moved.length ? <ol className="cmp-steps">{moved.map(line)}</ol>
          : <p className="cmp-empty">{delta.declared_change === null ? "Nothing was declared as changed, so no step is credited to a change." : "No step moved in what this change can move."}</p>}
      </section>

      <section className="cmp-sec" aria-labelledby="cmp-control">
        <h2 id="cmp-control">The control<span>what this change cannot move</span></h2>
        <p className="cmp-control">{controlWords(delta)}</p>
        {delta.control.varied.length ? <p className="cmp-control">It varied on {plural(delta.control.varied.length, "step")}: that is {variationWords(delta)}, not an effect.</p> : null}
        {unexplained.length ? <>
          {delta.limit
            ? <h3>Not attributable to the change<span>the two runners differed, and could have moved these</span></h3>
            : <h3>Changed without a cause</h3>}
          <ol className="cmp-steps">{unexplained.map(line)}</ol>
        </> : null}
        {delta.new.length || delta.gone.length ? <>
          <h3>New and gone<span>listed, not counted</span></h3>
          <ListedSteps label="Only in the after run" steps={delta.new} />
          <ListedSteps label="Only in the before run" steps={delta.gone} />
        </> : null}
      </section>

      <p className={`cmp-race${race.quiet ? " is-quiet" : ""}`}>{race.text}</p>
      <p className="cmp-claim-foot">All of this rests on {delta.claim}.</p>
    </div>
  </div>;
}

/** The lab's words, with its `code spans` drawn as code: text through React, never HTML. */
function LabText({ text }: { text: string }) {
  return <>{codeSpans(text).map((part, index) => (part.code ? <code key={index}>{part.text}</code> : part.text))}</>;
}

/** A digest shortened to its start, whole on hover or focus, and whole for a screen reader. */
function Value({ value }: { value: string | null }) {
  if (!isDigest(value)) return <code className="cmp-value">{shortValue(value)}</code>;
  return <code className="cmp-value cmp-digest" tabIndex={0} title={value}>
    <span className="is-short" aria-hidden="true">{shortValue(value)}</span>
    <span className="is-whole">{value}</span>
  </code>;
}

function Claim({ delta }: { delta: Delta }) {
  const declared = delta.declared_change;
  const change = declared === null ? undefined : delta.differences.find((item) => item.what === declared);
  const code = delta.lab_code;
  const known = delta.differences.filter((item) => item.before !== null || item.after !== null);
  const limit = delta.comparable ? limitOf(delta) : null;
  return <header className={`cmp-claim${delta.comparable ? "" : " is-refused"}${limit ? " is-limited" : ""}`}>
    <p className="cmp-kicker">Before against after<span>{delta.claim}</span>{limit ? <span className="is-limit">limited verdict</span> : null}</p>
    {delta.comparable ? <>
      <h1>{declared === null ? "Nothing declared as changed" : <>{limit ? "Declared change" : "One change"}: {setupWords(declared)}</>}</h1>
      {change ? <p className="cmp-change">
        <span className="cmp-side-word">Before</span><Value value={change.before} />
        <ArrowRight className="cmp-arrow" aria-hidden="true" />
        <span className="cmp-side-word">After</span><Value value={change.after} />
      </p> : null}
      <p className="cmp-lede">{setupLede(delta)}</p>
      {limit ? <LimitBox delta={delta} limit={limit} /> : null}
    </> : <>
      <h1>No verdict</h1>
      <p className="cmp-lede">{declared === null ? "Nothing was declared as changed." : <>Declared change: {setupWords(declared)}.</>} The comparison was refused, and still lists what differed:</p>
      <ul className="cmp-reasons">{delta.refused_because.map((reason, index) => <li key={index}><LabText text={reason} /></li>)}</ul>
    </>}
    {!delta.comparable && known.length ? <table className="cmp-table">
      <caption className="lv-sr">What differed between the two runs</caption>
      <thead><tr><th scope="col">What differed</th><th scope="col">Before</th><th scope="col">After</th></tr></thead>
      <tbody>{known.map((item) => <tr key={item.what} className={item.what === declared ? "is-declared" : undefined}>
        <th scope="row">{setupWords(item.what)}{item.what === declared ? <span className="cmp-declared">declared</span> : null}</th>
        <td><Value value={item.before} /></td>
        <td><Value value={item.after} /></td>
      </tr>)}</tbody>
    </table> : null}
    {!code.same ? <p className="cmp-note">
      The lab's code {code.before || code.after ? <>differed (<code>{code.before ? code.before.slice(0, 8) : "not recorded"}</code> before, <code>{code.after ? code.after.slice(0, 8) : "not recorded"}</code> after)</> : "is not recorded in either run"}. The comparison does not check what a change of it did, so a step that differs may also come from it.
    </p> : null}
    {delta.same_in_both.length ? <div className="cmp-same">
      <span className="cmp-side-word">Recorded as the same in both</span>
      <ul>{delta.same_in_both.map((name) => <li key={name}>{setupWords(name)}</li>)}</ul>
    </div> : null}
  </header>;
}

/**
 * A limited verdict, as prominent as the claim: why (the two runners differed,
 * and in what, with both values), and what is credited, in the delta's words.
 */
function LimitBox({ delta, limit }: { delta: Delta; limit: DeltaLimit }) {
  const credits = creditsWords(limit);
  return <section className="cmp-limit" aria-labelledby="cmp-limit-heading">
    <h2 id="cmp-limit-heading">A limited verdict: {limit.why}</h2>
    <table className="cmp-table">
      <caption className="lv-sr">What differed between the two runners</caption>
      <thead><tr><th scope="col">The runners</th><th scope="col">Before</th><th scope="col">After</th></tr></thead>
      <tbody>{runnerDifferences(delta).map((item) => <tr key={item.what}>
        <th scope="row">{setupWords(item.what)}</th>
        <td><Value value={item.before} /></td>
        <td><Value value={item.after} /></td>
      </tr>)}</tbody>
    </table>
    <p className="cmp-limit-credits">
      <strong>Credited: {credits.lead}</strong>{credits.rest ? <>: <LabText text={credits.rest} /></> : null}.
      {" "}Every other step that differs is not attributable, since the runners' difference could have moved it. No price is known: each run counted its ordinary activity on a runner of its own.
    </p>
    <p className="cmp-limit-count">{plural(limit.credited, "step")} credited by the mark, {limit.not_attributable} not attributable.</p>
  </section>;
}

/** The note of an imported recording, shown once under both runs when both have the same one. */
function importedNote(summary: DeltaSummary, side: Side): string | null {
  const origin = summary.recordings[side].origin;
  return origin.kind === "imported" ? origin.note : null;
}

function sharedNote(summary: DeltaSummary): string | null {
  const before = importedNote(summary, "before");
  return before !== null && before === importedNote(summary, "after") ? before : null;
}

function RunCard({ side, facts, summary }: { side: Side; facts: DeltaSide; summary: DeltaSummary }) {
  const note = sharedNote(summary) === null ? importedNote(summary, side) : null;
  const recording = summary.recordings[side];
  const shipped = recording.origin.kind === "shipped";
  // Only a shipped recording's CI run is linked as the run that made it; an imported file's is only what the file says.
  const link = shipped ? runLink({ run_url: facts.run_url }) : null;
  return <article className="cmp-run" aria-labelledby={`cmp-run-${side}`}>
    <header>
      <h2 id={`cmp-run-${side}`}>{side === "before" ? "Before" : "After"}</h2>
      <span className={`recorded-run-origin is-${recording.origin.kind}`}>{originWords(recording.origin)}</span>
    </header>
    <p className="cmp-run-title">{recording.title}</p>
    <dl className="cmp-run-facts">
      <div><dt>Where and when</dt><dd>{sideWhere(facts)}</dd></div>
      <div><dt>Lab's commit</dt><dd>{facts.commit ? <code>{facts.commit.slice(0, 8)}</code> : "not recorded"}</dd></div>
      {facts.defense_commit ? <div><dt>Rules and sensor settings</dt><dd>from commit <code>{facts.defense_commit.slice(0, 8)}</code>{facts.defense_commit === facts.commit ? " (the lab's commit)" : null}</dd></div> : null}
      <div><dt>CI run</dt><dd>{link ? <a href={link} target="_blank" rel="noreferrer">{link.replace(/^.*\/runs\//, "run ")}</a>
        : facts.run_url ? <span className="cmp-claimed" title="The file names this CI run, which BlueFire cannot confirm">{facts.run_url} <small>(named by the file, not confirmed)</small></span>
        : "not recorded"}</dd></div>
    </dl>
    {note ? <p className="cmp-run-note">{note}</p> : null}
    <Link className="cmp-open" to={recordedRunPath(facts.id)}>Open<span className="lv-sr"> the {side} run</span><ArrowRight aria-hidden="true" /></Link>
  </article>;
}

function ListedSteps({ label, steps }: { label: string; steps: Delta["new"] }) {
  if (steps.length === 0) return null;
  return <div className="cmp-listed">
    <span className="cmp-side-word">{label}</span>
    <ul>{steps.map((step) => <li key={step.id}><span className="lv-tech">{step.technique}</span> {step.title}{step.role !== "test" ? <span className="lv-role-tag">{step.role}</span> : null}</li>)}</ul>
  </div>;
}

function Chip({ value }: { value: DeltaStep["before"]["outcome"] }) {
  return <span className={`lv-word is-${outcomeClass(value)}`}>{outcomeWords(value)}</span>;
}

function StepLine({ delta, step, open, onToggle }: { delta: Delta; step: DeltaStep; open: boolean; onToggle: () => void }) {
  const field = chipField(delta);
  const parts = verdictParts(step);
  const result = step.result.replace(/\s+/g, "-");
  // Only a result the delta credits to the change is drawn as a move; any other difference is shown flat, before and after.
  const credited = isCredited(step.result);
  const detail = `cmp-detail-${step.id.replace(/[^A-Za-z0-9_-]/g, "-")}`;
  return <li className={`cmp-step is-${result}${open ? " is-open" : ""}`}>
    <div className="cmp-step-line">
      <button type="button" className="cmp-step-title" aria-expanded={open} aria-controls={detail} onClick={onToggle}>
        <b>{step.title}</b>
        <span className="lv-tech">{step.technique}</span>
        {step.role !== "test" ? <span className="lv-role-tag">{step.role}</span> : null}
      </button>
      {credited ? <span className="cmp-move">
        <span className="lv-sr">Before </span><Chip value={step.before[field]} />
        <ArrowRight className="cmp-arrow" aria-hidden="true" />
        <span className="lv-sr">, after </span><Chip value={step.after[field]} />
        {field === "outcome_with_lab_rules" ? <small>with the lab's rules</small> : null}
      </span> : <span className="cmp-move is-flat">
        <span className="cmp-side-word">Before</span><Chip value={step.before[field]} />
        <span className="cmp-side-word">After</span><Chip value={step.after[field]} />
        {field === "outcome_with_lab_rules" ? <small>with the lab's rules</small> : null}
      </span>}
    </div>
    <p className="cmp-verdict">
      <span className={`cmp-result is-${result}`}>{resultWords(step.result)}</span>
      {step.mark ? <> <span className="cmp-result is-mark">by the change's own mark<span className="lv-sr">, on two runners that differed</span></span></> : null}
      <span className="lv-sr">: </span>
      <LabText text={parts.before} />
      {parts.price ? <span className={`cmp-price${parts.price.startsWith("price not known") ? " is-unknown" : ""}`}><LabText text={parts.price} /></span> : null}
      <LabText text={parts.after} />
    </p>
    {step.underneath.length ? <ul className={`cmp-under${step.result === "better" ? " is-better" : ""}`} aria-label="What changed underneath">{step.underneath.map((item) => <li key={item}>{item}</li>)}</ul> : null}
    {step.records ? <Records records={step.records} /> : null}
    {step.paired_by !== "id" ? <p className="cmp-paired">Paired by {step.paired_by}.</p> : null}
    {open ? <PairDetail id={detail} delta={delta} step={step} onClose={onToggle} /> : null}
  </li>;
}

/** What the declared sensor recorded of a step in one run only, with the first lines the delta gives. */
function Records({ records }: { records: NonNullable<DeltaStep["records"]> }) {
  const parts = recordsParts(records);
  if (parts.length === 0) return null;
  return <div className="cmp-records">
    <p className="cmp-side-word">What sensor {records.sensor} recorded of it in one run only</p>
    {parts.map((part) => <div key={part.label} className="cmp-records-part">
      <span className="cmp-records-label">{part.label}, {plural(part.count, "event")}</span>
      <ul>{part.lines.map((text, index) => <li key={index}><code>{text}</code></li>)}</ul>
      {part.more > 0 ? <p className="cmp-records-more">and {plural(part.more, "more event")}, not listed in the comparison</p> : null}
    </div>)}
  </div>;
}

/** The step's detail in each recording, before and after next to each other, from the live view. */
function PairDetail({ id, delta, step, onClose }: { id: string; delta: Delta; step: DeltaStep; onClose: () => void }) {
  const heading = useRef<HTMLHeadingElement | null>(null);
  useEffect(() => {
    heading.current?.focus({ preventScroll: false });
  }, []);
  return <section className="cmp-detail" id={id} aria-labelledby={`${id}-heading`}>
    <div className="cmp-detail-head">
      <h3 id={`${id}-heading`} ref={heading} tabIndex={-1}>{step.title}, before and after</h3>
      <button type="button" className="lv-button is-close" onClick={onClose} aria-label="Close the step's detail">Close</button>
    </div>
    <div className="cmp-detail-sides">
      {SIDES.map((side) => <SideDetail key={side} side={side} recordingId={delta[side].id} stepId={side === "before" ? (step.before_id ?? step.id) : step.id} />)}
    </div>
  </section>;
}

function read(value: unknown): { recording: Recording } | { problem: string } {
  try {
    return { recording: readRecording(value) };
  } catch (error) {
    return { problem: error instanceof RecordingError ? error.message : "The recording could not be read." };
  }
}

function SideDetail({ side, recordingId, stepId }: { side: Side; recordingId: string; stepId: string }) {
  const navigate = useNavigate();
  const entry = useQuery({ queryKey: ["recording", recordingId], queryFn: () => api.recording(recordingId), retry: false });
  const reading = useMemo(() => (entry.data ? read(entry.data.recording) : null), [entry.data]);
  const recording = reading && "recording" in reading ? reading.recording : null;
  const view = useMemo(() => {
    if (!recording) return null;
    const timeline = buildTimeline(recording);
    const row = stepRows(recording, timeline).find((item) => item.step.id === stepId);
    if (!row) return null;
    const numbers = testNumbers(recording);
    return { row, colours: sensorColours(recording.network.sensors), number: numbers.get(stepId), tests: numbers.size, origin: runFacts(recording, timeline).start };
  }, [recording, stepId]);
  const label = side === "before" ? "Before" : "After";

  let body;
  if (entry.isPending) body = <p className="cmp-empty">Loading the {side} recording.</p>;
  else if (!entry.data) body = <p className="cmp-empty" role="status">The {side} recording could not be loaded: {entry.error instanceof Error ? entry.error.message : "the request failed"}.</p>;
  else if (!recording) body = <p className="cmp-empty" role="status">{reading && "problem" in reading ? reading.problem : "The recording could not be read."}</p>;
  else if (!view) body = <p className="cmp-empty" role="status">The {side} recording has no step {stepId}.</p>;
  else body = <StepDetail
    recording={recording}
    row={view.row}
    colours={view.colours}
    testNumber={view.number}
    testsTotal={view.tests}
    origin={view.origin}
    onSelect={(other) => navigate(`${recordedRunPath(recordingId)}?mode=analyse&select=${encodeURIComponent(other)}`)}
    takeFocus={false}
  />;
  return <div className={`cmp-detail-side is-${side}`}>
    <p className="cmp-side-word">{label}</p>
    <div className="lv-an-detail">{body}</div>
  </div>;
}
