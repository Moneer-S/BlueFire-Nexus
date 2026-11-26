// One step in analyse mode: the plain sentence, how it went and what that
// rests on, its times, the published test, the command, the rules that
// matched, its events as a log, and the other runs of the same technique.

import { useEffect, useRef, useState } from "react";
import type { Alert, Recording, RecordingEvent, Step } from "./recording";
import { alertMoment, timeOf } from "./recording";
import type { StepRow } from "./analyse";
import { fixHint, ordinaryMatches, otherRuns } from "./analyse";
import { capital, clockTime, comparedStep, count, elapsed, eventMarks, howItWent, ordinaryAlertEvents, outcomeClass, outcomeWords, plural, seenWords, sensorLabel, sensorShortName, sensorWord, sentence, span, stepLabel, stepShortName, titleInSentence, unitWord, unseenWords } from "./format";
import type { MatchKind } from "./format";
import { FreeText } from "./FreeText";
import { refusalOf } from "./EventLog";
import type { StyleVars } from "./motion";

interface StepDetailProps {
  recording: Recording;
  row: StepRow;
  colours: Map<string, string>;
  testNumber: number | undefined;
  testsTotal: number;
  /** Real time (ms) of the run's start, the origin of "into the run" (`RunFacts.start`). */
  origin: number;
  /** What that origin is, in words (`RunFacts.startWords`). */
  originWords?: string;
  onSelect: (stepId: string) => void;
  /** Left out where the step is shown outside its run's playback: there is no "Watch from here". */
  onWatch?: (stepId: string) => void;
  onFix?: (stepId: string) => void;
  /** Left out where the step's place has its own way to close it: there is no "Whole run". */
  onClose?: () => void;
  /** True when the step was just chosen by the viewer: the detail then takes keyboard focus, so its actions are the next stops. */
  takeFocus: boolean;
}

/** Events shown before "Show all": a long log is still one scroll away. */
const FIRST_EVENTS = 120;

/**
 * "first alert 12 ms after the start", or, when a sensor stamped it a moment
 * before the step's start marker, says so: sensors keep their own clocks.
 */
function afterStart(what: string, ms: number): string {
  if (ms >= 1) return `${what} ${span(ms)} after the start`;
  if (ms <= -1) return `${what} ${span(-ms)} before the step's start marker (each sensor stamps its own records)`;
  return `${what} at the start`;
}

function chip(alert: Alert): { words: string; className: string; title?: string } {
  if (alert.launcher_only === true) return { words: "launcher line", className: "is-launcher" };
  if (alert.counts && alert.rule.origin === "lab") return { words: `lab alert · ${alert.rule.level}`, className: "is-lab", title: "One of the lab's own rules alerted. The score does not count it." };
  if (alert.counts) return { words: `alert · ${alert.rule.level}`, className: "is-alert" };
  if (alert.rule.origin === "lab") return { words: `lab · ${alert.rule.level}`, className: "is-lab" };
  if (alert.rule.level === "informational") return { words: "informational", className: "is-review", title: "An informational match: nobody reviews it." };
  return { words: `review · ${alert.rule.level}`, className: "is-review" };
}

/**
 * For a match raised live after its step ended: "Raised 2.9 s after the step
 * ended." Null for any other. `ended` is the step's end as playback reads it,
 * so exactly the matches the watch view brings as late arrivals say so here.
 */
function raisedAfter(alert: Alert, ended: number | null): string | null {
  if (alert.raised === undefined || ended === null) return null;
  const late = timeOf(alert.raised) - ended;
  return late > 0 ? `Raised ${span(late)} after the step ended.` : null;
}

function MatchGroup({ recording, title, alerts, ended }: { recording: Recording; title: string; alerts: Alert[]; ended: number | null }) {
  if (alerts.length === 0) return null;
  return (
    <div className="lv-dt-group">
      <h5>{title}</h5>
      {alerts.map((alert) => {
        const look = chip(alert);
        const ordinary = alert.counts && alert.rule.origin === "pinned" ? ordinaryAlertEvents(recording, alert.rule.title) : 0;
        // How noisy a rule for review is on ordinary activity: what a defender weighs before raising it to alert.
        const noise = !alert.counts && alert.rule.origin === "pinned" && alert.launcher_only !== true ? ordinaryMatches(recording, alert.rule.title) : null;
        const late = raisedAfter(alert, ended);
        return (
          <div key={alert.id} className={`lv-dt-match${alert.launcher_only === true ? " is-dim" : ""}`}>
            <span className={`lv-mchip ${look.className}`} title={look.title}>
              {look.words}
            </span>
            <span className="lv-dt-rule" title={alert.rule.id}>
              {alert.rule.title}
            </span>
            <span className="lv-dt-mmeta">
              {alert.events.length > 0 ? plural(alert.events.length, "event") : "no event"} &middot; {clockTime(alertMoment(alert))}
              {noise !== null ? (
                <span className="lv-dt-noise" title="Events of ordinary activity, outside every step, that this rule matched">
                  {" "}
                  &middot; {noise === 0 ? "none" : count(noise)} in ordinary activity
                </span>
              ) : null}
            </span>
            {late ? <span className="lv-dt-mnote">{late}</span> : null}
            {ordinary > 0 ? <span className="lv-dt-mnote">The same rule also alerted on {plural(ordinary, "event")} of ordinary activity, outside every step: one false alert.</span> : null}
          </div>
        );
      })}
    </div>
  );
}

/** The source's own words for a refused start, for someone writing a rule on it: "execve success=no exit=-13 key=process-start". */
function rawFields(event: RecordingEvent): string {
  const fields = event.fields ?? {};
  const parts = [event.kind];
  for (const name of ["success", "exit", "key"]) {
    const value = fields[name];
    if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") parts.push(`${name}=${String(value)}`);
  }
  return parts.join(" ");
}

/** What each sensor of the step's host, and any other that recorded the step, recorded of it; for a step nobody saw, also what each one watches. */
function SensorCounts({ recording, row, colours }: { recording: Recording; row: StepRow; colours: Map<string, string> }) {
  const sensors = recording.network.sensors.filter((sensor) => sensor.host === row.step.host || (row.bySensor.get(sensor.id) ?? 0) > 0);
  if (sensors.length === 0) return null;
  const silent = row.step.outcome === "unseen";
  return (
    <ul className="lv-dt-sensors">
      {sensors.map((sensor) => {
        const count = row.bySensor.get(sensor.id) ?? 0;
        return (
          <li key={sensor.id} style={{ "--rgb": colours.get(sensor.id) ?? "123,202,255" } as StyleVars}>
            <i className="lv-dot" />
            <span>{sensorLabel(recording, sensor)}</span>
            <b className={count === 0 && silent ? "is-gap" : ""}>{plural(count, "event")}</b>
            {silent ? <small>records {sensor.records}</small> : null}
          </li>
        );
      })}
    </ul>
  );
}

function Verdict({ step, row }: { step: Step; row: StepRow }) {
  const m = row.matches;
  const first = m.alert[0];
  if (step.outcome === "alerted" && first) {
    return (
      <>
        <b>{titleInSentence(first.rule.title)}</b> ({first.rule.level}) matched an event of this step.
      </>
    );
  }
  if (step.outcome === "seen") return <>{seenWords(row.recorded ?? row.events.length, [...m.review, ...m.labAlert, ...m.launcher])}</>;
  if (step.outcome === "unseen") {
    return (
      <>
        It <em className="lv-red">took effect</em>, and {unseenWords(step)}.
      </>
    );
  }
  if (step.outcome === "stopped" && step.defense) {
    return (
      <>
        Hardening change: <b>{step.defense.title}</b>.
      </>
    );
  }
  return <>{sentence(step.happened.basis)}.</>;
}

function EventLines({ recording, events, marks, colours, refusal }: { recording: Recording; events: RecordingEvent[]; marks: Map<string, { kind: MatchKind; word: string }>; colours: Map<string, string>; refusal: RecordingEvent | undefined }) {
  const [all, setAll] = useState(false);
  const shown = all ? events : events.slice(0, FIRST_EVENTS);
  return (
    <>
      <div className="lv-dt-log" role="list">
        {shown.map((event) => {
          const mark = marks.get(event.id);
          const refused = event === refusal;
          const text = event.text || event.image || "";
          const sensor = recording.network.sensors.find((item) => item.id === event.sensor);
          return (
            <div key={event.id} role="listitem" className={`lv-dt-line${mark ? ` is-${mark.kind}` : ""}${refused ? " is-refused" : ""}`} style={{ "--rgb": colours.get(event.sensor) ?? "123,202,255" } as StyleVars}>
              <span className="lv-dt-time">{clockTime(timeOf(event.time))}</span>
              <span className="lv-dt-sensor" title={sensor?.name ?? event.sensor}>
                <i className="lv-dot" />
                {sensor ? sensorWord(sensor.name) : event.sensor}
              </span>
              <span className="lv-dt-kind">{event.kind}</span>
              <span className="lv-dt-text" title={text}>
                {text}
              </span>
              <span className="lv-dt-mark" title={`Tied to the step by ${event.tied_by}`}>
                {refused ? "refused" : mark ? mark.word : event.tied_by}
              </span>
            </div>
          );
        })}
      </div>
      {events.length > shown.length ? (
        <button type="button" className="lv-link-button lv-dt-more" onClick={() => setAll(true)}>
          Show all {count(events.length)} events
        </button>
      ) : null}
    </>
  );
}

export function StepDetail({ recording, row, colours, testNumber, testsTotal, origin, originWords = "the start of the run", onSelect, onWatch, onFix, onClose, takeFocus }: StepDetailProps) {
  const article = useRef<HTMLElement | null>(null);
  // The detail is mounted again for every step, so this runs once per chosen step.
  useEffect(() => {
    if (takeFocus) article.current?.focus({ preventScroll: true });
  }, [takeFocus]);
  const step = row.step;
  const m = row.matches;
  const compared = comparedStep(recording, step);
  const others = otherRuns(recording, step);
  const hint = fixHint(recording, step, m);
  const marks = eventMarks([...m.alert, ...m.labAlert, ...m.review, ...m.labReview]);
  const refusal = step.outcome === "stopped" ? refusalOf(row.events) : undefined;
  const refusalSensor = refusal ? recording.network.sensors.find((item) => item.id === refusal.sensor) : undefined;
  const started = step.started === undefined ? null : timeOf(step.started);
  const ended = step.ended === undefined ? null : timeOf(step.ended);
  // The step's first alert, the first playback fires and the one its verdict names, at its moment: when it was raised, where the rules ran live.
  const firstAlert = m.alert[0] ? alertMoment(m.alert[0]) : Number.NaN;
  const firstLabAlert = m.labAlert[0] ? alertMoment(m.labAlert[0]) : Number.NaN;
  const host = recording.network.hosts.find((item) => item.id === step.host);
  const from = step.from === undefined ? undefined : recording.network.hosts.find((item) => item.id === step.from);
  const labWord = step.outcome_with_lab_rules !== undefined && step.outcome_with_lab_rules !== step.outcome ? step.outcome_with_lab_rules : null;
  const unit = unitWord(recording);
  const role = step.role === "test" && testNumber !== undefined ? `${capital(unit)} ${testNumber} of ${testsTotal}` : capital(stepLabel(recording, step));
  // On an attack path the head already says the step's place among the steps: a second line would repeat it.
  const place = unit === "step" && step.role === "test" && testsTotal === recording.steps.length ? null : `${row.index + 1} of ${plural(recording.steps.length, "step")}`;
  const anyMatch = m.alert.length + m.labAlert.length + m.review.length + m.labReview.length + m.launcher.length > 0;
  const recorded = row.recorded;

  const otherBlock =
    others.length > 0 ? (
      <section className="lv-dt-sec">
        <h4>
          Other runs of {step.technique.id} <span>{others.length}</span>
        </h4>
        <div className="lv-dt-others">
          {others.map((other) => (
            <button key={other.id} type="button" onClick={() => onSelect(other.id)}>
              {/* Its name says its role, and for a rerun the test it reruns. */}
              <span className="lv-dt-on">{stepShortName(recording, other)}</span>
              <span className="lv-dt-ot">{other.title}</span>
              <span className={`lv-ow is-${outcomeClass(other.outcome)}`}>{outcomeWords(other.outcome)}</span>
              {/* The outcome counts the published rules; where the lab's own rules alerted, the list says that too, as the step's own line does. */}
              {other.outcome_with_lab_rules === "alerted" && other.outcome !== "alerted" ? (
                <span className="lv-ow is-lab" title="One of the lab's own rules alerted on it, which the score does not count">
                  lab alert
                </span>
              ) : null}
            </button>
          ))}
        </div>
      </section>
    ) : null;
  // For a step nobody saw, the other runs of its technique are where a fix starts: they come first.
  const othersFirst = step.outcome === "unseen";

  return (
    <article className="lv-dt" aria-label={capital(stepLabel(recording, step))} ref={article} tabIndex={-1}>
      <div className="lv-dt-top">
        <div className="lv-dt-kicker">
          <span className={`lv-dt-role${step.role === "test" ? "" : " is-quiet"}`}>{role}</span>
          {place === null ? null : <span>{place}</span>}
          <span className="lv-dt-id" title={`The step's id in the recording. A link to it ends ?step=${encodeURIComponent(step.id)}`}>
            id <span className="lv-mono">{step.id}</span>
          </span>
        </div>
        {onWatch || onClose ? (
          <div className="lv-dt-actions">
            {onWatch ? (
              <button type="button" className="lv-button is-watch" onClick={() => onWatch(step.id)}>
                <svg viewBox="0 0 12 12" aria-hidden="true">
                  <path d="M3 1.5v9l7.5-4.5z" />
                </svg>
                Watch from here
              </button>
            ) : null}
            {onClose ? (
              <button type="button" className="lv-button is-close" onClick={onClose} title="Close the step and show the whole run">
                Whole run
              </button>
            ) : null}
          </div>
        ) : null}
      </div>
      <h3 className="lv-dt-title">{step.title}</h3>
      <div className="lv-dt-kicker lv-dt-techline">
        <span className="lv-tech">{step.technique.id}</span>
        {step.technique.name ? <span className="lv-dt-tname">{step.technique.name}</span> : null}
        {step.technique.tactic ? <span>{step.technique.tactic}</span> : null}
      </div>
      {step.plain ? (
        <p className="lv-dt-plain">
          <FreeText text={step.plain} />
        </p>
      ) : null}

      <div className={`lv-dt-verdict is-${outcomeClass(step.outcome)}`}>
        <span className={`lv-word is-${outcomeClass(step.outcome)}`}>{step.outcome}</span>
        <span className="lv-dt-why">
          <Verdict step={step} row={row} />
          {labWord ? (
            <span className="lv-dt-labnote">
              {" "}
              {m.labAlert[0] ? (
                <>
                  One of the lab&apos;s own rules alerted, which the score does not count: <b>{titleInSentence(m.labAlert[0].rule.title)}</b>.
                </>
              ) : (
                <>
                  With the lab&apos;s own rules, which the score does not count: <b>{outcomeWords(labWord)}</b>.
                </>
              )}
            </span>
          ) : null}
        </span>
        {hint && onFix ? (
          <button type="button" className="lv-fix" onClick={() => onFix(step.id)} aria-describedby={`lv-dt-hint-${step.id}`}>
            <svg viewBox="0 0 16 16" aria-hidden="true">
              <path d="M3 8h9M8.5 4.5 12 8l-3.5 3.5" />
            </svg>
            Fix this
          </button>
        ) : null}
        {hint ? (
          <p className="lv-dt-hint" id={`lv-dt-hint-${step.id}`} role="status">
            {hint}
          </p>
        ) : null}
      </div>

      {compared ? (
        <div className="lv-dt-compare">
          <div className={step.role === "hardened" ? "is-with" : ""}>
            <span>{step.role === "hardened" ? "With the change" : "This run"}</span>
            <span>
              <b>{howItWent(step)}</b>
              {refusal ? (
                <>
                  {": "}
                  {refusalSensor ? sensorShortName(refusalSensor.name) : refusal.sensor} recorded <code>{refusal.text}</code>
                  <small className="lv-mono">{rawFields(refusal)}</small>
                </>
              ) : null}
            </span>
          </div>
          <div>
            <span>{step.role === "hardened" ? "Without it" : "The first run"}</span>
            <span>
              <button type="button" className="lv-link-button" onClick={() => onSelect(compared.id)}>
                {stepLabel(recording, compared)}
              </button>
              {": "}
              <b>{howItWent(compared)}</b>
            </span>
          </div>
        </div>
      ) : null}
      {step.role === "hardened" && step.defense ? (
        <section className="lv-dt-change">
          <h4>
            The change <span className="lv-dt-change-title">{step.defense.title}</span>
          </h4>
          <p>
            <b>Why a defender would deploy it.</b> {step.defense.why}
          </p>
        </section>
      ) : null}

      <dl className="lv-dt-grid">
        <div>
          <dt>Happened</dt>
          <dd>
            {step.happened.answer}
            <small>{step.happened.basis}</small>
          </dd>
        </div>
        <div>
          <dt>Seen</dt>
          <dd>
            {/* The outcome in the words the chip and the score use; the recording's own account of it under them. */}
            {step.outcome === "stopped" ? step.visibility.answer : outcomeWords(step.outcome)}
            <small>{step.visibility.basis}</small>
          </dd>
        </div>
        <div>
          <dt>When</dt>
          <dd>
            {started !== null ? (
              <>
                {clockTime(started)}
                {ended !== null ? <> to {clockTime(ended)}</> : null} UTC
                <small>
                  {ended !== null ? `${span(ended - started)}, ` : ""}
                  <span title={`Counted from ${originWords}, ${clockTime(origin)} UTC`}>{elapsed((started - origin) / 1000)} into the run</span>
                  {Number.isFinite(firstAlert) ? `, ${afterStart("first alert", firstAlert - started)}` : ""}
                  {!Number.isFinite(firstAlert) && Number.isFinite(firstLabAlert) && step.first_alert_with_lab_rules ? `, ${afterStart("a lab rule's first alert", firstLabAlert - started)}` : ""}
                </small>
              </>
            ) : (
              "not recorded"
            )}
          </dd>
        </div>
        <div>
          <dt>Where</dt>
          <dd>
            {host ? host.name : step.host}
            {from ? <> from {from.name}</> : null}
            <small>
              {host ? host.role : ""}
              {step.test ? `${host ? ". " : ""}${step.test.project}, run by ${step.test.executor}${step.test.elevated ? " as root" : ""}` : ""}
            </small>
          </dd>
        </div>
      </dl>

      {step.command ? (
        <section className="lv-dt-sec">
          <h4>
            Command {step.test ? <span className="lv-mono" title="The published test's id">{step.test.guid}</span> : null}
          </h4>
          <pre className="lv-dt-pre">
            <FreeText text={step.command} />
          </pre>
        </section>
      ) : null}

      {othersFirst ? otherBlock : null}

      <section className="lv-dt-sec">
        <h4>
          Rules that matched <span>only high or critical is an alert</span>
        </h4>
        {anyMatch ? (
          <>
            <MatchGroup recording={recording} title="Published rules at alert level: in the score" alerts={m.alert} ended={row.end} />
            <MatchGroup recording={recording} title="Lab alerts: the lab's own rules at alert level, not in the score" alerts={m.labAlert} ended={row.end} />
            <MatchGroup recording={recording} title="Published rules below alert level: for review" alerts={m.review.filter((alert) => alert.rule.level !== "informational")} ended={row.end} />
            <MatchGroup recording={recording} title="Published rules at informational level: nobody reviews them" alerts={m.review.filter((alert) => alert.rule.level === "informational")} ended={row.end} />
            <MatchGroup recording={recording} title="The lab's own rules below alert level" alerts={m.labReview} ended={row.end} />
            <MatchGroup recording={recording} title="Matched only the launcher line, which never counts" alerts={m.launcher} ended={row.end} />
          </>
        ) : (
          <p className="lv-dt-empty">No rule matched.</p>
        )}
      </section>

      <section className="lv-dt-sec">
        <h4>
          What the sensors recorded <span>{recorded !== null && recorded > row.events.length ? `${count(recorded)} events, ${count(row.events.length)} of them kept here` : plural(recorded ?? row.events.length, "event")}</span>
        </h4>
        <SensorCounts recording={recording} row={row} colours={colours} />
      </section>

      {othersFirst ? null : otherBlock}

      {step.output ? (
        <details className="lv-dt-sec lv-dt-output">
          <summary>What it printed</summary>
          <pre className="lv-dt-pre">
            <FreeText text={step.output} />
          </pre>
        </details>
      ) : null}

      <section className="lv-dt-sec">
        <h4>
          Events{" "}
          <span>
            {recorded !== null && recorded > row.events.length ? `${count(recorded)} recorded; the first ones and every matched one kept, ${count(row.events.length)} in all` : plural(row.events.length, "event")}
          </span>
        </h4>
        {row.events.length > 0 ? (
          <EventLines key={step.id} recording={recording} events={row.events} marks={marks} colours={colours} refusal={refusal} />
        ) : (
          <p className="lv-dt-empty">{recorded === null ? "The engine could not tie events to this step." : "No event is tied to this step."}</p>
        )}
      </section>
    </article>
  );
}
