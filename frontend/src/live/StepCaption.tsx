// The step, told as one plain sentence low on the screen, with its score word
// once the outcome is known.

import { memo, useLayoutEffect, useRef } from "react";
import type { Alert, Outcome, Recording, Step } from "./recording";
import { capital, comparedStep, falseAlertsOf, howItWent, outcomeClass, outcomeWords, plural, roleWords, sensorShortName, sentence, stepLabel } from "./format";
import type { StepMoment } from "./moment";
import { refusalOf } from "./EventLog";
import { fixHint, groupMatches } from "./analyse";

interface StepCaptionProps {
  recording: Recording;
  moment: StepMoment | null;
  /** How many events the recording holds for the step. */
  total: number;
  /** Starts fixing the step: in the app, its fixer; on the single page, the step's detail. */
  onFix: (stepId: string) => void;
  /** True while playback runs fast: then only outcomes are announced, so announcements do not pile up. */
  quiet: boolean;
  /** Called when the caption held keyboard focus and the element that had it went away or was hidden. */
  onLoseFocus: () => void;
  /** The latest late arrival on screen, in one sentence: a match of an earlier step raised after that step ended. */
  late: string | null;
}

/**
 * The line over the sentence: the technique, the test's name and the step's
 * number. A step that is not a test says first what it is. The test's count
 * is not repeated here: the attacker's counter at the top says it.
 */
function Kicker({ recording, step }: { recording: Recording; step: Step }) {
  const compared = comparedStep(recording, step);
  const role = compared ? `${roleWords(step.role)} of ${stepLabel(recording, compared)}` : roleWords(step.role);
  const hint = step.role === "canary" ? "a step the defenses are known to catch" : step.role === "control" ? "a step that must raise no alert" : "";
  return (
    <div className="lv-kicker">
      {step.role === "test" ? null : (
        <>
          <span className="lv-role">{role}</span>
          {hint ? <span className="lv-kicker-hint">{hint}</span> : null}
          <i className="lv-sep" />
        </>
      )}
      <span className="lv-tech" title={[step.technique.name, step.technique.tactic ? `tactic: ${step.technique.tactic}` : ""].filter(Boolean).join(", ") || undefined}>
        {step.technique.id}
      </span>
      <span className="lv-title">{step.title}</span>
      <span className="lv-step-chip" title={`Its place in the run: ${recording.steps.indexOf(step) + 1} of ${recording.steps.length} steps`}>
        {stepLabel(recording, step)}
      </span>
    </div>
  );
}

/**
 * A step whose alert was raised live after it ended, told as it stood at its
 * end: no alert by then. It stays when that alert fires and the verdict turns
 * to alerted; the late line beside it names the alert. Null for any other.
 */
function noAlertYet(step: Step, stood: Outcome, total: number): string | null {
  if (stood === step.outcome) return null;
  return stood === "seen" ? `${plural(step.visibility.events ?? total, "event")} recorded, no alert by the end of the step.` : "No sensor recorded it, and no alert by the end of the step.";
}

/** How many published rules matched the step below alert level, of the matches `heard` so far. */
function reviewRules(heard: readonly Alert[]): number {
  return new Set(heard.filter((alert) => !alert.counts && alert.launcher_only !== true && alert.rule.origin === "pinned").map((alert) => alert.rule.id)).size;
}

/**
 * Why the step went as it did, from the matches `heard` so far. `first` is
 * the alert it is told by: the step's first counting alert in playback's
 * firing order, once it has fired.
 */
function why(step: Step, stood: Outcome, first: Alert | null, heard: readonly Alert[], total: number) {
  const yet = noAlertYet(step, stood, total);
  if (yet !== null) return <>{yet}</>;
  if (step.outcome === "alerted") {
    return first ? (
      <>
        <b>{first.rule.title}</b> ({first.rule.level}) matched an event of this step.
      </>
    ) : (
      <>{sentence(step.visibility.basis)}.</>
    );
  }
  if (step.outcome === "seen") {
    const review = reviewRules(heard);
    const events = step.visibility.events ?? total;
    return (
      <>
        {plural(events, "event")} recorded, {review > 0 ? `${plural(review, "rule")} matched for review` : "no rule matched"}, none at alert level.
      </>
    );
  }
  if (step.outcome === "unseen") return <>No sensor recorded it.</>;
  if (step.outcome === "stopped" && step.defense) {
    return (
      <>
        Hardening change: <b>{step.defense.title}</b>.
      </>
    );
  }
  return <>{sentence(step.happened.basis)}.</>;
}

/** The same reason as `why`, as plain text for a screen reader. */
function whyText(step: Step, stood: Outcome, first: Alert | null, heard: readonly Alert[], total: number): string {
  const yet = noAlertYet(step, stood, total);
  if (yet !== null) return yet;
  if (step.outcome === "alerted") {
    return first ? `${first.rule.title} (${first.rule.level}) matched an event of this step.` : `${sentence(step.visibility.basis)}.`;
  }
  if (step.outcome === "seen") {
    const review = reviewRules(heard);
    return `${plural(step.visibility.events ?? total, "event")} recorded, ${review > 0 ? `${plural(review, "rule")} matched for review` : "no rule matched"}, none at alert level.`;
  }
  if (step.outcome === "unseen") return "No sensor recorded it.";
  if (step.outcome === "stopped" && step.defense) return `Hardening change: ${step.defense.title}.`;
  return `${sentence(step.happened.basis)}.`;
}

/**
 * A rerun set against the run it repeats, as a before and after: "with the
 * change" and "without it", or "this run" and "first arguments".
 */
function Compare({ recording, step, moment }: { recording: Recording; step: Step; moment: StepMoment }) {
  const before = comparedStep(recording, step);
  if (!before) return null;
  const hardened = step.role === "hardened";
  const refusal = hardened && step.outcome === "stopped" ? refusalOf(moment.events) : undefined;
  const sensor = refusal ? recording.network.sensors.find((item) => item.id === refusal.sensor) : undefined;
  return (
    <div className="lv-pair">
      <div className={`lv-pair-side${step.outcome === "stopped" ? " is-stopped" : ""}`}>
        <span className="lv-pair-head">{hardened ? "With the change" : "This run"}</span>
        <span className="lv-pair-body">
          {refusal ? (
            <>
              <code title={sensor ? `Recorded by ${sensor.name}` : undefined}>{refusal.text}</code>
              <small>{sensor ? `recorded by ${sensorShortName(sensor.name)}` : ""}</small>
            </>
          ) : (
            howItWent(step)
          )}
        </span>
      </div>
      <div className="lv-pair-side">
        <span className="lv-pair-head">
          {hardened ? "Without it" : "First arguments"} &middot; {stepLabel(recording, before)}
        </span>
        <span className="lv-pair-body">{howItWent(before)}</span>
      </div>
    </div>
  );
}

function StepCaptionView({ recording, moment, total, onFix, quiet, onLoseFocus, late }: StepCaptionProps) {
  const box = useRef<HTMLElement | null>(null);
  // Whether keyboard focus is inside the caption. A focused element that is
  // removed or hidden fires no blur, so this stays true until focus is put back.
  const inside = useRef(false);
  const stepId = moment?.step.id;
  const revealed = moment?.revealed ?? false;
  useLayoutEffect(() => {
    if (!inside.current) return;
    const active = document.activeElement;
    if (!revealed || !active || !box.current?.contains(active)) {
      inside.current = false;
      onLoseFocus();
    }
  }, [stepId, revealed, onLoseFocus]);

  const step = moment?.step;
  const outcome = moment?.outcome;
  // One live region for the whole life of the caption: a region that is added already filled is often not read.
  const announcement = !moment || !step || !outcome ? "" : revealed ? `${capital(outcomeWords(outcome))}: ${whyText(step, moment.stood, moment.named, moment.heard, total)}` : quiet ? "" : `${capital(stepLabel(recording, step))}: ${step.plain ?? step.title}`;
  const live = (
    <div className="lv-sr" aria-live="polite" aria-atomic="true">
      {announcement}
    </div>
  );
  // A late arrival is said on a line of its own, which never replaces the step's sentence.
  const lateLine = (
    <div className="lv-late" aria-live="polite" aria-atomic="true">
      {late}
    </div>
  );
  if (!moment || !step || !outcome) {
    return (
      <section className="lv-caption">
        {live}
        {lateLine}
      </section>
    );
  }
  // Like the sentence, the hint speaks only of the matches that have fired by now.
  const hint = fixHint(recording, step, groupMatches(moment.heard));
  const long = (step.plain ?? step.title).length > 60;
  const fixable = hint !== null;
  // The alerts the caption names, picked once in playback's firing order, so the sentence, its notes and its spoken text agree.
  const labAlert = step.outcome !== "alerted" && step.outcome_with_lab_rules === "alerted" ? moment.namedLab : null;
  const first = outcome === "alerted" ? moment.named : null;
  const falseAlerts = first ? falseAlertsOf(recording, first.rule.title) : 0;
  return (
    <section
      className="lv-caption"
      aria-label="The step"
      ref={box}
      onFocus={() => {
        inside.current = true;
      }}
      onBlur={(event) => {
        if (!event.currentTarget.contains(event.relatedTarget)) inside.current = false;
      }}
    >
      {live}
      {lateLine}
      {/* Only the told step rises in again; the verdict below keeps its elements, so a focused button is not lost. */}
      <div className="lv-caption-in" key={step.id}>
        <Kicker recording={recording} step={step} />
        <div className={`lv-plain${long ? " is-long" : ""}`}>{step.plain ?? step.title}</div>
      </div>
      <div className="lv-caption-out">
        <div className={`lv-verdict${moment.revealed ? "" : " is-hidden"}`}>
          <span className={`lv-word is-${outcomeClass(outcome)}`}>{outcome}</span>
          <span className="lv-why">{why(step, moment.stood, moment.named, moment.heard, total)}</span>
          {fixable ? (
            <button
              type="button"
              className="lv-fix"
              onClick={() => onFix(step.id)}
              aria-describedby={`lv-fix-hint-${step.id}`}
              tabIndex={moment.revealed ? 0 : -1}
            >
              <svg viewBox="0 0 16 16" aria-hidden="true">
                <path d="M3 8h9M8.5 4.5 12 8l-3.5 3.5" />
              </svg>
              Fix this
            </button>
          ) : null}
        </div>
        <div className={`lv-after${moment.revealed ? "" : " is-hidden"}`}>
          {first && falseAlerts > 0 ? (
            <div className="lv-falsenote">
              The same rule also alerted on {plural(falseAlerts, "event")} of ordinary activity, outside every step.
            </div>
          ) : null}
          {labAlert ? (
            <div className="lv-labnote">
              A rule written in this repository would alert: <b>{labAlert.rule.title}</b>. It is not in the score.
            </div>
          ) : null}
          <Compare recording={recording} step={step} moment={moment} />
          {hint ? (
            <div className="lv-fix-hint" id={`lv-fix-hint-${step.id}`} role="status">
              {hint}
            </div>
          ) : null}
        </div>
      </div>
    </section>
  );
}

/**
 * The caption changes when the step, its telling or its events do, not on
 * every animation frame. Events only grow inside a step, so their count says
 * when they changed.
 */
export const StepCaption = memo(
  StepCaptionView,
  (a, b) =>
    a.recording === b.recording &&
    a.total === b.total &&
    a.onFix === b.onFix &&
    a.quiet === b.quiet &&
    a.onLoseFocus === b.onLoseFocus &&
    a.late === b.late &&
    a.moment?.step.id === b.moment?.step.id &&
    a.moment?.revealed === b.moment?.revealed &&
    a.moment?.outcome === b.moment?.outcome &&
    a.moment?.heard === b.moment?.heard &&
    a.moment?.events.length === b.moment?.events.length,
);
