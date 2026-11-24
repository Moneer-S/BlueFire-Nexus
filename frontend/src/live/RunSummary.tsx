// The whole run in analyse mode, while no step is chosen: the score, the first
// alert, the ordinary activity and its false alerts, the notes of the
// recording, and where the recording comes from.

import { useMemo } from "react";
import type { Recording } from "./recording";
import type { Timeline } from "./playback";
import type { RunFacts } from "./moment";
import { firstAlertClock } from "./moment";
import { capital, day, elapsed, falseAlertsOf, plural, runLink, stepLabel } from "./format";
import { seenBreakdown } from "./analyse";

interface RunSummaryProps {
  recording: Recording;
  timeline: Timeline;
  facts: RunFacts;
  onSelect: (stepId: string) => void;
}

const ALERT_LEVELS = new Set(["high", "critical"]);

export function RunSummary({ recording, timeline, facts, onSelect }: RunSummaryProps) {
  const score = recording.score;
  const source = recording.source;
  const first = timeline.firstAlert;
  const other = facts.otherFirst;
  const ordinary = recording.ordinary;
  const matches = ordinary ? [...ordinary.matches].sort((a, b) => Number(ALERT_LEVELS.has(b.level)) - Number(ALERT_LEVELS.has(a.level)) || b.count - a.count) : [];
  const runUrl = runLink(source);
  const lab = score.alerted_with_lab_rules;
  // The rule of the flagged alert itself: the counting published match that fires first.
  const firstRule = first?.alert.rule.title;
  const firstClock = first ? firstAlertClock(recording, facts, first) : null;
  const firstFalse = firstRule ? falseAlertsOf(recording, firstRule) : 0;
  const seen = useMemo(() => seenBreakdown(recording), [recording]);
  const unseen = useMemo(() => recording.steps.filter((step) => step.role === "test" && step.outcome === "unseen"), [recording]);
  const hardened = useMemo(() => {
    const steps = recording.steps.filter((step) => step.role === "hardened");
    return { total: steps.length, stopped: steps.filter((step) => step.outcome === "stopped").length, notStopped: steps.filter((step) => step.outcome !== "stopped") };
  }, [recording]);

  return (
    <article className="lv-dt lv-sum" aria-label="The whole run">
      <div className="lv-dt-kicker">
        <span className="lv-dt-role">The whole run</span>
        <span>{recording.kind}</span>
      </div>
      <h3 className="lv-sum-head">
        <em>{score.alerted}</em> of {plural(score.steps, "test")} alerted
      </h3>
      <p className="lv-sum-lead">
        {[`${score.seen} ${score.seen === 1 ? "was" : "were"} recorded with no alert`, score.unseen > 0 ? `${score.unseen} left nothing a sensor recorded` : "", score.took_effect < score.steps ? `${score.steps - score.took_effect} did not take effect` : ""].filter(Boolean).join(", ")}
        {hardened.total > 0 ? `; ${hardened.stopped} of ${plural(hardened.total, "hardened rerun")} ${hardened.stopped === 1 ? "was" : "were"} stopped` : ""}.
      </p>
      {unseen.length > 0 ? (
        <p className="lv-sum-gap">
          {unseen.length === 1 ? "The test nobody saw:" : `${unseen.length} tests nobody saw:`}{" "}
          {unseen.map((step, index) => (
            <span key={step.id}>
              {index > 0 ? ", " : ""}
              <button type="button" className="lv-link-button" onClick={() => onSelect(step.id)}>
                {step.title}
              </button>
            </span>
          ))}
          . Open it to start fixing.
        </p>
      ) : null}
      <p className="lv-dt-plain lv-sum-quiet">{recording.attacker.description}</p>

      {/* The score itself is in the header and the headline; this panel says what lies behind it. */}
      <dl className="lv-dt-facts">
        <dt>Tests</dt>
        <dd>
          {score.steps}, of which {score.took_effect} took effect
        </dd>
        {seen.total > 0 ? (
          <>
            <dt>Seen, no alert</dt>
            <dd>
              {[seen.review > 0 ? `${seen.review} with a published rule for review` : "", seen.launcher > 0 ? `${seen.launcher} matched on the launcher line only` : "", seen.none > 0 ? `${seen.none} matched by no published rule` : ""].filter(Boolean).join(", ")}
            </dd>
          </>
        ) : null}
        {lab !== undefined ? (
          <>
            <dt>Lab rules</dt>
            <dd className="lv-sum-lab" title="Rules written in this repository. They are shown apart and never counted in the score.">
              with them, {lab} of {score.steps} tests would alert <small>not scored</small>
            </dd>
          </>
        ) : null}
        {hardened.total > 0 ? (
          <>
            <dt>Hardened reruns</dt>
            <dd>
              {hardened.stopped} of {hardened.total} stopped by their change
              {hardened.notStopped.length > 0 ? (
                <small>
                  Not stopped:{" "}
                  {hardened.notStopped.map((item, index) => (
                    <span key={item.id}>
                      {index > 0 ? ", " : ""}
                      <button type="button" className="lv-link-button" onClick={() => onSelect(item.id)}>
                        {stepLabel(recording, item)}
                      </button>
                    </span>
                  ))}
                </small>
              ) : null}
            </dd>
          </>
        ) : null}
        <dt>First alert</dt>
        <dd>
          {first ? (
            <>
              {firstClock ? `${elapsed(firstClock.seconds)} ${firstClock.words}, on ` : "On "}
              <button type="button" className="lv-link-button" onClick={() => onSelect(first.step.id)}>
                {stepLabel(recording, first.step)}
              </button>
              {firstRule ? <>, by {firstRule}</> : null}
              <small>
                {capital(plural(first.testsBefore, "other test"))} had started when it fired.
                {firstFalse > 0 ? ` The same rule also alerted on ${plural(firstFalse, "event")} of ordinary activity.` : ""}
                {other ? ` The ${other.step.role}, ${stepLabel(recording, other.step)}, alerted at ${elapsed((other.real - facts.start) / 1000)} into the run${other.step.role === "canary" ? ", as expected: it is built to be caught" : ""}.` : ""}
              </small>
            </>
          ) : (
            "no test raised an alert"
          )}
        </dd>
        {recording.kind === "attack path" && recording.attacker.goal !== null ? (
          <>
            <dt>Goal</dt>
            <dd>
              {recording.attacker.goal}
              <small>{score.goal_seconds !== undefined ? `Reached ${elapsed(score.goal_seconds)} after the first step.` : "The recording does not say it was reached."}</small>
            </dd>
          </>
        ) : null}
        <dt>Length</dt>
        <dd>
          {elapsed((facts.end - facts.start) / 1000, 0)} from the first step to the last
        </dd>
      </dl>

      {recording.notes.length > 0 ? (
        <details className="lv-dt-sec lv-dt-output">
          <summary>
            What to know when reading the score <span>{plural(recording.notes.length, "note")}</span>
          </summary>
          <ul className="lv-sum-notes">
            {recording.notes.map((note) => (
              <li key={note}>{note}</li>
            ))}
          </ul>
        </details>
      ) : null}

      {ordinary ? (
        <section className="lv-dt-sec">
          <h4>
            Ordinary activity{" "}
            <span>
              {plural(ordinary.events, "event")}
              {score.false_alerts !== undefined ? `, ${plural(score.false_alerts, "false alert")}` : ""}
            </span>
          </h4>
          <p className="lv-sum-quiet">What the published rules said about the run&apos;s own administration and the host&apos;s background work, outside every step.</p>
          {matches.length > 0 ? (
            <div className="lv-sum-ord">
              {matches.map((match) => {
                const alerting = ALERT_LEVELS.has(match.level);
                return (
                  <div key={`${match.rule}:${match.level}`} className={alerting ? "is-false" : ""}>
                    <span className="lv-sum-level">{match.level}</span>
                    <span className="lv-sum-rule" title={match.rule}>
                      {match.rule}
                    </span>
                    <span className="lv-sum-count">{alerting ? `false alert, ${plural(match.count, "event")}` : plural(match.count, "event")}</span>
                  </div>
                );
              })}
            </div>
          ) : (
            <p className="lv-dt-empty">No published rule matched it.</p>
          )}
        </section>
      ) : null}

      <section className="lv-dt-sec lv-sum-source">
        <h4>Where this recording comes from</h4>
        <p className="lv-sum-quiet">
          {source.engine} on a {source.environment}, {day(source.started)}, {source.finished ? `${source.started.slice(11, 19)} to ${source.finished.slice(11, 19)} UTC.` : `from ${source.started.slice(11, 19)} UTC, still running.`}
          {source.repository ? (
            <>
              {" "}
              Code: {source.repository}
              {source.commit ? <span className="lv-mono"> {source.commit.slice(0, 12)}</span> : null}.
            </>
          ) : null}
          {runUrl ? (
            <>
              {" "}
              <a href={runUrl} target="_blank" rel="noreferrer noopener">
                The run that made it (github.com)
              </a>
              .
            </>
          ) : null}
        </p>
        {source.tools.length > 0 ? (
          <dl className="lv-sum-tools">
            {source.tools.map((tool) => (
              <div key={`${tool.name}:${tool.role}`}>
                <dt>
                  {tool.name} <span>{tool.role}</span>
                </dt>
                <dd title={tool.version}>{tool.version}</dd>
              </div>
            ))}
          </dl>
        ) : null}
      </section>
      <p className="lv-sum-quiet lv-sum-pick">Choose a step in the lanes or the table to see what the sensors recorded and which rules matched.</p>
    </article>
  );
}
