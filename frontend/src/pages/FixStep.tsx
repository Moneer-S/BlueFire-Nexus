// The place where a defender starts fixing one step of a recorded run. It leads
// with where to start and what has already been tried, then gives what the step
// left behind, the rules that matched it, a draft, where a model will help one
// day, and how a rerun is made. Everything on it is
// read from the step's recording and the comparisons the service keeps. The
// change itself is a file in the repository, run by its CI: this page makes
// nothing, runs nothing and sends nothing.

import { useQueries, useQuery } from "@tanstack/react-query";
import { ArrowLeft, ArrowRight } from "lucide-react";
import { useEffect, useId, useMemo, useRef, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { api, type RecordingSummary } from "../lib/api";
import { activeProviderKind, backPath, browserStorage, candidates, draftKey, hasStableIds, keepDraft, labRulesCommit, modelWords, notAccepted, otherRunsOf, readDraft, sensorsOf, startWith, stepMoment, tieOf, triedFor, type FileHere, type RuleMatch, type SensorFacts, type StartWith, type Tie, type Tried } from "../lib/fix-step";
import { originWords, recordedRunPath, RUNNING_POLL_MS } from "../lib/recorded-runs";
import { chipField, codeSpans, isOneRun, pairChangeWords, priceLead, resultWords, verdictParts } from "../lib/recording-pairs";
import { stepRows, type StepRow } from "../live/analyse";
import { clockTime, comparedStep, count, outcomeClass, outcomeWords, plural, roleWords, sensorColours, stepLabel } from "../live/format";
import type { StyleVars } from "../live/motion";
import { buildTimeline } from "../live/playback";
import { readRecording, RecordingError, timeOf, type Recording, type RecordingEvent, type Step } from "../live/recording";
import { ErrorState, LoadingState } from "../components/Primitives";
import "../live/live.css";
import "./RecordedRun.css";
import "./ComparedRuns.css";
import "./FixStep.css";

export function FixStepPage() {
  const { recordingId = "", file, stepId = "" } = useParams<{ recordingId: string; file?: string; stepId: string }>();
  return <FixStep key={`${recordingId}/${file ?? ""}/${stepId}`} recordingId={recordingId} file={file} stepId={stepId} />;
}

function read(value: unknown): { recording: Recording } | { problem: string } {
  try {
    return { recording: readRecording(value, { running: true }) };
  } catch (error) {
    return { problem: error instanceof RecordingError ? error.message : "The recording could not be read." };
  }
}

function FixStep({ recordingId, file, stepId }: { recordingId: string; file?: string; stepId: string }) {
  const [search] = useSearchParams();
  const back = backPath(recordingId, file, stepId, search);
  const entry = useQuery({
    queryKey: file ? ["recording-file", recordingId, file] : ["recording", recordingId],
    queryFn: () => (file ? api.recordingFile(recordingId, file) : api.recording(recordingId)),
    retry: false,
    // As on the run's own page: a recording that is still running is asked for again until it has finished.
    refetchInterval: (query) => (query.state.data?.summary.running ? RUNNING_POLL_MS : false),
  });
  const data = entry.data;
  const reading = useMemo(() => (data ? read(data.recording) : null), [data]);
  const recording = reading && "recording" in reading ? reading.recording : null;
  const row = useMemo(() => (recording ? stepRows(recording, buildTimeline(recording)).find((item) => item.step.id === stepId) ?? null : null), [recording, stepId]);

  if (entry.isPending) return <div className="fx is-message"><LoadingState label="Loading the recording" /></div>;
  if (!data) {
    return <div className="fx is-message">
      <FixBar back={back} />
      <div className="recorded-run-message"><ErrorState title="This recording could not be loaded" error={entry.error} retry={() => { void entry.refetch(); }} /></div>
    </div>;
  }
  const problem = reading && "problem" in reading ? reading.problem : !row ? `This recording has no step ${JSON.stringify(stepId)}.` : null;
  // The file a comparison names: the one in the address, or the first file of the id, which the service names once it is finished.
  const sha256 = file ?? ("sha256" in data && typeof data.sha256 === "string" ? data.sha256 : undefined);
  return <div className="fx">
    <FixBar back={back} summary={data.summary} />
    {problem || !recording || !row
      ? <div className="recorded-run-message" role="alert"><div><h1>This step cannot be shown</h1><p>{problem}</p><Link to={back}>Back to the run</Link></div></div>
      : <FixView recording={recording} row={row} recordingId={recordingId} file={file} sha256={sha256} list={{ kind: data.summary.kind, title: data.summary.title }} />}
  </div>;
}

/** The quiet line under the app's header: back to the moment the reader came from, and which run this step is of. */
function FixBar({ back, summary }: { back: string; summary?: RecordingSummary }) {
  return <header className="recorded-run-bar">
    <nav className="recorded-run-line" aria-label="Fixing a step">
      <Link className="recorded-run-back" to={back}><ArrowLeft aria-hidden="true" />Back to the run</Link>
      {summary ? <p className="recorded-run-facts">
        <span className="recorded-run-title">Fix this</span>
        <span>{summary.title}</span>
        <span className={`recorded-run-origin is-${summary.origin.kind}`}>{originWords(summary.origin)}</span>
      </p> : null}
    </nav>
    {summary?.origin.kind === "imported" ? <p className="recorded-run-note">{summary.origin.note}</p> : null}
  </header>;
}

function FixView({ recording, row, recordingId, file, sha256, list }: { recording: Recording; row: StepRow; recordingId: string; file?: string; sha256?: string; list: { kind: string; title: string } }) {
  const step = row.step;
  const { kind: listKind, title: listTitle } = list;
  const here = useMemo<FileHere>(() => ({ id: recordingId, ...(sha256 ? { sha256 } : {}), stable: hasStableIds(recording), list: { kind: listKind, title: listTitle } }), [recordingId, sha256, recording, listKind, listTitle]);
  const tie = useMemo(() => tieOf(recording, step), [recording, step]);
  const heading = useRef<HTMLHeadingElement | null>(null);
  useEffect(() => {
    heading.current?.focus({ preventScroll: true });
  }, []);
  const start = startWith(recording, step, row.matches);
  const colours = sensorColours(recording.network.sensors);
  const sensors = sensorsOf(recording, row);
  const compared = comparedStep(recording, step);
  const label = stepLabel(recording, step);
  const role = step.role === "test" ? label : compared ? `${roleWords(step.role)} of ${stepLabel(recording, compared)}` : `${roleWords(step.role)}, ${label}`;
  const labWord = step.outcome_with_lab_rules !== undefined && step.outcome_with_lab_rules !== step.outcome ? step.outcome_with_lab_rules : null;

  return <div className="lv fx-view">
    <div className="cmp-page fx-page">
      <header className="cmp-claim fx-step">
        <p className="cmp-kicker">Fix this<span>{role}</span><span className="fx-tech">{step.technique.id}{step.technique.name ? ` ${step.technique.name}` : ""}</span></p>
        <h1 ref={heading} tabIndex={-1}>{step.title}</h1>
        {step.plain ? <p className="fx-plain">{step.plain}</p> : null}
        <p className="fx-outcome">
          <span className={`lv-word is-${outcomeClass(step.outcome)}`}>{step.outcome}</span>
          <span className="fx-happened">{step.happened.answer}<small>{step.happened.basis}</small></span>
          {labWord ? <span className="fx-labword">with the lab's rules: <b>{labWord}</b>, not in the score</span> : null}
        </p>
      </header>

      <WhereToStart row={row} start={start} />
      <AlreadyTried here={here} stepId={step.id} tie={tie} noun={noun(step)} />
      <Recorded recording={recording} row={row} sensors={sensors} colours={colours} start={start} runPath={recordedRunPath(recordingId, file)} />
      <Matched recording={recording} start={start} />
      {start.kind === "rule" ? here.sha256 ? <Draft storageKey={draftKey(here.id, here.sha256, step.id)} />
        : <section className="cmp-sec fx-draft" aria-labelledby="fx-draft"><h2 id="fx-draft">A draft</h2><p className="cmp-empty">This recording is still running. A draft is kept for one finished recording file, so it can be written once the run has finished.</p></section>
        : null}
      <ModelPlace />
      <RunAgain />
    </div>
  </div>;
}

/** The lab's words, with its `code spans` drawn as code: text through React, never HTML. */
function LabText({ text }: { text: string }) {
  return <>{codeSpans(text).map((part, index) => (part.code ? <code key={index}>{part.text}</code> : part.text))}</>;
}

/** A step of role test is a test; any other step is a step. */
function noun(step: Step): string {
  return step.role === "test" ? "test" : "step";
}

/** How many other runs of the technique show before "Show all". */
const FIRST_OTHERS = 3;

/** What the recording holds of the step, by sensor; how the recording knows, behind one line; and for a step with no event, the other runs of its technique. */
function Recorded({ recording, row, sensors, colours, start, runPath }: { recording: Recording; row: StepRow; sensors: SensorFacts[]; colours: Map<string, string>; start: StartWith; runPath: string }) {
  const step = row.step;
  const recorded = row.recorded;
  const kept = row.events.length;
  const others = start.kind === "sensor" ? otherRunsOf(recording, step) : [];
  const defense = recording.source.defense_commit;
  const [allOthers, setAllOthers] = useState(false);
  return <section className="cmp-sec" aria-labelledby="fx-recorded">
    <h2 id="fx-recorded">What was recorded<span>{recorded !== null && recorded > kept ? `${count(recorded)} events, ${count(kept)} of them kept in the recording` : recorded === null ? "the engine could not tie events to this step" : plural(kept, "event")}</span></h2>
    <div className="fx-sensors">
      {sensors.map((sensor) => <article key={sensor.id} className={`fx-sensor${sensor.events.length ? " has-events" : ""}`} aria-label={`Sensor ${sensor.name}`} style={{ "--rgb": colours.get(sensor.id) ?? "123,202,255" } as StyleVars}>
        <header>
          <i className="lv-dot" />
          <h3>{sensor.name}</h3>
          {sensor.version ? <span className="fx-version">{sensor.version}</span> : null}
          <span className={`fx-count${sensor.events.length === 0 && start.kind === "sensor" ? " is-gap" : ""}`}>{plural(sensor.events.length, "event")} of this step</span>
        </header>
        <p className="fx-records">Records {sensor.records}.</p>
        {sensor.watches ? <details className="fx-watches">
          <summary>What its rules watched: {sensor.watches.map((watch, index) => <span key={watch.key}>{index ? ", " : ""}<code>{watch.key || "(no key)"}</code> {plural(watch.rules.length, "rule")}</span>)}</summary>
          <ul>{sensor.watches.map((watch) => <li key={watch.key}><code className="fx-key">{watch.key || "(no key)"}</code><ul>{watch.rules.map((rule) => <li key={rule}><code>{rule}</code></li>)}</ul></li>)}</ul>
        </details> : null}
        {sensor.events.length ? <EventTable recording={recording} events={sensor.events} /> : null}
      </article>)}
    </div>
    <details className="fx-know">
      <summary>How we know</summary>
      <dl>
        <div><dt>What the recording says</dt><dd><q>{step.visibility.basis}</q></dd></div>
        {start.kind === "sensor" && start.launcher ? <div><dt>The launcher</dt><dd>The shell the lab starts each test from. An attacker would not leave it behind, so it never counts, and a rule on it would alert on the lab, not on the attack.</dd></div> : null}
        {sensors.map((sensor) => <div key={sensor.id}>
          <dt>Settings of {sensor.name}</dt>
          <dd>{sensor.settings
            ? <>SHA-256 <code>{sensor.settings}</code> as it loaded them{defense ? <>, from commit <code>{defense.slice(0, 8)}</code></> : null}</>
            : "This recording does not say which settings it loaded."}</dd>
        </div>)}
      </dl>
    </details>
    {start.kind === "sensor" ? <div className="fx-others">
      <h3>Other tests of the same technique in this run<span>{step.technique.id} · {others.length ? plural(others.length, "step") : "none"}</span></h3>
      {others.length ? <ul>{(allOthers ? others : others.slice(0, FIRST_OTHERS)).map(({ step: other, recorded: events }) => <li key={other.id}>
        <Link to={`${runPath}?${stepMoment(other.id).toString()}`} className="fx-other">
          <span className="fx-other-label">{stepLabel(recording, other)}</span>
          <span className="fx-other-title">{other.title}{other.role !== "test" ? <span className="lv-role-tag">{other.role}</span> : null}</span>
          <span className={`lv-ow is-${outcomeClass(other.outcome)}`}>{outcomeWords(other.outcome)}</span>
          <span className="fx-other-events">{events === null ? "events not tied" : plural(events, "event")}</span>
        </Link>
      </li>)}</ul> : null}
      {!allOthers && others.length > FIRST_OTHERS ? <button type="button" className="lv-link-button fx-more" onClick={() => setAllOthers(true)}>Show all {count(others.length)}</button> : null}
    </div> : null}
  </section>;
}

/** The step's events of one sensor, in time order: time, kind, text, and for auditd its audit key and the command. */
function EventTable({ recording, events }: { recording: Recording; events: RecordingEvent[] }) {
  const [all, setAll] = useState(false);
  const shown = all ? events : events.slice(0, 40);
  return <>
    <table className="fx-events">
      <caption className="lv-sr">The events this sensor recorded of the step</caption>
      <thead><tr><th scope="col">Time (UTC)</th><th scope="col">Kind</th><th scope="col">What it recorded</th><th scope="col">Tied by</th></tr></thead>
      <tbody>{shown.map((event) => {
        const key = event.fields?.key;
        const command = event.fields?.command;
        return <tr key={event.id}>
          <td className="fx-time">{clockTime(timeOf(event.time))}</td>
          <td className="fx-kind">{event.kind}</td>
          <td className="fx-text">
            <code>{event.text || event.image || ""}</code>
            {typeof key === "string" || typeof command === "string" ? <small>
              {typeof key === "string" ? <>audit key <code>{key}</code></> : null}
              {typeof command === "string" ? <> by <code>{command}</code></> : null}
            </small> : null}
          </td>
          <td className="fx-tied">{event.tied_by}</td>
        </tr>;
      })}</tbody>
    </table>
    {events.length > shown.length ? <button type="button" className="lv-link-button fx-more" onClick={() => setAll(true)}>Show all {count(events.length)} events of {recording.network.sensors.find((item) => item.id === events[0]?.sensor)?.name ?? "this sensor"}</button> : null}
  </>;
}

/** Where a fix starts, in a sentence or two, decided by what the recording holds: a sensor, a rule, or nothing to fix. */
function WhereToStart({ row, start }: { row: StepRow; start: StartWith }) {
  const what = noun(row.step);
  return <section className="cmp-sec fx-start" aria-labelledby="fx-start">
    <h2 id="fx-start">Where to start</h2>
    {start.kind === "sensor" ? <>
      <p className="fx-lead"><b>Nothing of this {what} was recorded. Start with a sensor's settings:</b> a rule can only match what a sensor records.</p>
      <p className="fx-why">A sensor's settings are files under <code>lab/sensors/</code> in the repository.</p>
    </> : start.kind === "rule" ? <>
      <p className="fx-lead"><b>A sensor recorded this {what}, but no rule raised an alert. Start with a rule</b> that matches what the sensor recorded.</p>
      <p className="fx-why">A rule is a file under <code>lab/rules/linux/</code> in the repository.</p>
    </> : start.kind === "lab alerted" ? <>
      <p className="fx-lead"><b>One of the lab's own rules raised an alert on it: it is caught.</b> The score counts published rules only, and none of those alerted, so the score leaves it out.</p>
      <p className="fx-why">The lab's own rules are the files under <code>lab/rules/linux/</code> in the repository.</p>
    </> : start.kind === "alerted" ? <>
      <p className="fx-lead"><b>A published rule raised an alert on it.</b> There is nothing to fix here.</p>
    </> : <p className="fx-lead">{start.why}</p>}
  </section>;
}

/** The rules that matched the step, as the recording has them, with what the run did not accept. */
function Matched({ recording, start }: { recording: Recording; start: StartWith }) {
  if (start.kind === "sensor" || start.kind === "nothing") return null;
  const declined = notAccepted(recording);
  const labCommit = labRulesCommit(recording);
  return <section className="cmp-sec fx-matched" aria-labelledby="fx-matched">
    <h2 id="fx-matched">Rules that matched it</h2>
    {start.kind === "rule" ? <>
      <RuleGroup title="Published rules that matched, below alert level" empty="No published rule matched it, at any level." matches={start.review} />
      <RuleGroup title="The lab's own rules that matched" empty={recording.network.detectors.some((detector) => detector.id === "lab") ? "None of the lab's own rules matched it." : "This run did not try the lab's own rules."} matches={start.lab} />
      {start.launcher.length ? <RuleGroup title="Matched only the line that starts the test, which never counts" matches={start.launcher} /> : null}
    </> : start.kind === "lab alerted" ? <>
      <RuleGroup title="The rule that raised the alert" matches={start.alerted} />
      {labCommit ? <p className="fx-why">The run loaded it from commit <code>{labCommit.slice(0, 8)}</code>.</p> : null}
      {start.review.length ? <RuleGroup title="Published rules that matched, below alert level" matches={start.review} /> : null}
    </> : <>
      <RuleGroup title="The rule that raised the alert" matches={start.alerted} />
      {start.lab.length ? <RuleGroup title="The lab's own rules that matched" matches={start.lab} /> : null}
    </>}
    {(start.kind === "rule" || start.kind === "lab alerted") && declined.length ? <p className="fx-declined">
      Rules this run did not accept, so their matches are left out: {declined.map((verdict, index) => <span key={verdict.rule}>{index ? "; " : ""}<b>{verdict.title}</b>{verdict.reason ? <> ({verdict.reason})</> : null}</span>)}.
    </p> : null}
  </section>;
}

function RuleGroup({ title, empty, matches }: { title: string; empty?: string; matches: RuleMatch[] }) {
  if (matches.length === 0) return empty ? <div className="fx-rules"><h3>{title}</h3><p className="cmp-empty">{empty}</p></div> : null;
  return <div className="fx-rules">
    <h3>{title}</h3>
    <ul>{matches.map((match) => <li key={`${match.rule.origin}:${match.rule.id}`}><RuleCard match={match} /></li>)}</ul>
  </div>;
}

function matchChip(match: RuleMatch): { words: string; className: string } {
  const [first] = match.alerts;
  if (first?.launcher_only === true) return { words: "launcher line", className: "is-launcher" };
  if (match.rule.origin === "lab") return { words: first?.counts ? `would alert · ${match.rule.level}` : `lab · ${match.rule.level}`, className: "is-lab" };
  return { words: first?.counts ? `alert · ${match.rule.level}` : `review · ${match.rule.level}`, className: first?.counts ? "is-alert" : "is-review" };
}

function RuleCard({ match }: { match: RuleMatch }) {
  const chip = matchChip(match);
  const events = new Set(match.alerts.flatMap((alert) => alert.events)).size;
  const verdict = match.verdict;
  return <article className="fx-rule" aria-label={match.rule.title}>
    <p className="fx-rule-line">
      <span className={`lv-mchip ${chip.className}`}>{chip.words}</span>
      <b>{match.rule.title}</b>
      <span className="fx-rule-meta">
        {match.rule.origin === "lab" ? "the lab's own" : "published"}
        {" · "}{events ? `on ${plural(events, "event")}` : "on no event"}
        {match.ordinary !== undefined && match.ordinary !== null ? <> · {match.ordinary === 0 ? "nothing" : plural(match.ordinary, "event")} in ordinary activity</> : null}
      </span>
    </p>
    {match.rule.origin === "lab" ? verdict ? <>
      <p className="fx-rule-judged">
        <span className={`cmp-judged ${verdict.accepted ? "is-accepted" : "is-not-accepted"}`}>{verdict.accepted ? "accepted" : "not accepted"}</span>
        {verdict.reason ? <span className="cmp-judged-why"><LabText text={verdict.reason} /></span> : null}
        {verdict.file ? <code className="cmp-rule-file">{verdict.file}</code> : null}
      </p>
      {verdict.lines ? <figure className="cmp-rule-text">
        <figcaption>The rule's text, as this recording carries it</figcaption>
        <pre tabIndex={0} aria-label={`The text of the rule ${match.rule.title}`}>{verdict.lines.join("\n")}</pre>
      </figure> : <p className="cmp-empty">This recording does not carry the rule's text.</p>}
    </> : <p className="cmp-empty">This recording does not say how the run judged this rule.</p> : null}
  </article>;
}

/** A plain text area for a rule, never filled in by the app, kept in this browser only. */
function Draft({ storageKey }: { storageKey: string }) {
  const id = useId();
  const [text, setText] = useState(() => readDraft(browserStorage(), storageKey));
  const [kept, setKept] = useState(true);
  return <section className="cmp-sec fx-draft" aria-labelledby={`${id}-heading`}>
    <h2 id={`${id}-heading`}>A draft</h2>
    <label className="fx-draft-label" htmlFor={id}>Your rule</label>
    <textarea
      id={id}
      className="fx-draft-text"
      value={text}
      rows={10}
      spellCheck={false}
      autoComplete="off"
      aria-describedby={`${id}-kept ${id}-file`}
      onChange={(event) => {
        setText(event.target.value);
        setKept(keepDraft(browserStorage(), storageKey, event.target.value));
      }}
    />
    <p className="fx-kept" id={`${id}-kept`}>Kept in this browser only. The file in the repository is what runs.</p>
    {!kept ? <p className="fx-kept is-problem" role="status">This browser could not keep the latest change, so what was typed since may go when the page closes.</p> : null}
    <p className="fx-file" id={`${id}-file`}>Save it as a Sigma rule, a <code>.yml</code> file, in the folder of its kind under <code>lab/rules/linux/</code>: <code>process_creation/</code>, <code>file_event/</code> or <code>network_connection/</code> for Sysmon, <code>auditd/</code> for auditd. A run accepts it only if it alerts on every rerun of a test with changed arguments and on nothing in ordinary activity. Once the run accepts it, a rule at level high or critical raises an alert.</p>
  </section>;
}

/** The model's place: one of two fixed texts by the configured provider's kind, read from the configuration and nothing else. */
function ModelPlace() {
  const catalog = useQuery({ queryKey: ["catalog"], queryFn: api.catalog });
  const words = catalog.data ? modelWords(activeProviderKind(catalog.data))
    : catalog.isError ? "The model connection could not be read from the configuration. Nothing was sent."
    : null;
  return <aside className="fx-model" aria-label="The model's place">
    <p>{words ?? "Reading the model connection from the configuration."}</p>
    <Link to="/settings#model-connection">Model connection settings<ArrowRight aria-hidden="true" /></Link>
  </aside>;
}

/** What a rerun is here: a file in the repository, a pull request, and the lab's comparison of the two runs. */
function RunAgain() {
  return <section className="cmp-sec fx-again" aria-labelledby="fx-again">
    <h2 id="fx-again">Running it again</h2>
    <ol>
      <li>Make the change as a file in the repository: a rule under <code>lab/rules/linux/</code>, or a sensor's settings under <code>lab/sensors/</code>.</li>
      <li>Open a pull request. Its CI runs the list before and after the change: for a sensor's settings, two runs side by side; for a rule, one run judged with the old rules and with the new.</li>
      <li>The lab compares the two. Import the comparison with its two recordings here to see before against after.</li>
    </ol>
    <p className="fx-note">This app runs no test and opens no pull request.</p>
  </section>;
}

/** Each kept comparison that moved this step, with its before and after, its price and the links of the loop. */
function AlreadyTried({ here, stepId, tie, noun: what }: { here: FileHere; stepId: string; tie: Tie | null; noun: string }) {
  const list = useQuery({ queryKey: ["recording-deltas"], queryFn: api.recordingDeltas });
  const wanted = useMemo(() => (list.data ? candidates(here, tie, list.data.deltas) : []), [list.data, here, tie]);
  const loaded = useQueries({ queries: wanted.map((pair) => ({ queryKey: ["recording-delta", pair.id], queryFn: () => api.recordingDelta(pair.id), retry: false })) });
  const comparisons = loaded.flatMap((query) => (query.data ? [query.data] : []));
  const pending = list.isPending || loaded.some((query) => query.isPending);
  const failed = list.isError || loaded.some((query) => query.isError);
  const tried = triedFor(here, stepId, tie, comparisons);

  return <section className="cmp-sec fx-tried" aria-labelledby="fx-tried">
    <h2 id="fx-tried">What was already tried<span>{pending ? "reading the comparisons" : plural(tried.length, "comparison")}</span></h2>
    {here.sha256 === undefined ? <p className="cmp-empty">This recording is still running: a comparison names a finished file.</p> : null}
    {tried.length ? <ol className="cmp-steps">{tried.map((item) => <TriedLine key={item.summary.id} item={item} />)}</ol>
      : pending ? null
      : <p className="cmp-empty">No comparison has moved this {what} yet.</p>}
    {tie === null ? <p className="fx-note">This recording is older than the ids that tie a {what} like this one across runs, so only comparisons of this very run are looked at.</p> : null}
    {failed ? <p className="fx-note is-problem" role="status">Some comparisons could not be read from the service, so this list may be short.</p> : null}
  </section>;
}

/** Where this run stands in a comparison, in plain words, and for another run how the step was tied to it. */
function WhereWords({ item, oneRun }: { item: Tried; oneRun: boolean }) {
  if (item.where !== "another run") return <>{oneRun ? `This run, with the rules from ${item.where} the change.` : `This run is the one ${item.where} the change.`}</>;
  const tie = item.tie;
  return tie?.by === "published test"
    ? <>Another run of the same list, not this one, with the same published test as the list runs it. <small className="fx-tie">Published test <code title={tie.guid}>{tie.guid.slice(0, 8)}</code></small></>
    : <>Another run of the same list, not this one, with the same published test. <small className="fx-tie">Step <code>{item.step.id}</code></small></>;
}

function TriedLine({ item }: { item: Tried }) {
  const { summary, delta, step } = item;
  const field = chipField(delta);
  const parts = verdictParts(step);
  const price = parts.price ? priceLead(parts.price) : null;
  const result = step.result.replace(/\s+/g, "-");
  const oneRun = isOneRun(delta);
  return <li className={`cmp-step is-${result}`}>
    <div className="cmp-step-line">
      <p className="fx-tried-what">
        <Link to={item.pair}>{pairChangeWords(summary)}</Link>
        <span className="fx-tried-how">{oneRun ? "one run evaluated with two rule sets" : "a pair of runs"}</span>
        <span className={`recorded-run-origin is-${summary.origin.kind}`}>{originWords(summary.origin)}</span>
      </p>
      <span className="cmp-move">
        <span className="lv-sr">Before </span><span className={`lv-word is-${outcomeClass(step.before[field])}`}>{outcomeWords(step.before[field])}</span>
        <ArrowRight className="cmp-arrow" aria-hidden="true" />
        <span className="lv-sr">, after </span><span className={`lv-word is-${outcomeClass(step.after[field])}`}>{outcomeWords(step.after[field])}</span>
        {field === "outcome_with_lab_rules" ? <small>with the lab's rules</small> : null}
      </span>
    </div>
    <p className="fx-where"><WhereWords item={item} oneRun={oneRun} /></p>
    <p className="cmp-verdict fx-tried-verdict">
      <span className={`cmp-result is-${result}`}>{resultWords(step.result)}</span>
      {/* The price's lead on the line; the lab's whole verdict, with what the price quotes, one click away. */}
      {price ? <span className={`cmp-price${price.lead.startsWith("price not known") ? " is-unknown" : ""}`}><LabText text={price.lead} /></span> : null}
    </p>
    <details className="fx-quoted">
      <summary>The comparison's own words</summary>
      <p><LabText text={step.verdict} /></p>
    </details>
    <p className="cmp-opens">
      <Link className="cmp-open" to={item.pair}>Open the comparison at this step<ArrowRight aria-hidden="true" /></Link>
      {item.after ? <Link className="cmp-open" to={item.after}>{oneRun ? "Open the same step with the rules after" : "Open the same step in the after run"}<ArrowRight aria-hidden="true" /></Link> : null}
    </p>
  </li>;
}
