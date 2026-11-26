// The race, on the recording's real clock: how far the attacker has got, and
// where the defense's first alert came, with one sentence that says who is winning.

import { useLayoutEffect, useRef, useState } from "react";
import type { ReactNode, RefObject } from "react";
import type { Recording } from "./recording";
import { rulesRanAfterTheRun, timeOf } from "./recording";
import type { FirstAlert, Frame, ScoreSoFar, Timeline } from "./playback";
import { capital, clockTime, elapsed, ordinaryAlertEvents, plainMarks, plural, span, stepLabel, unitWord } from "./format";
import { firstAlertClock, firstAlertOnScreen } from "./moment";
import type { RunFacts } from "./moment";

interface RaceLineProps {
  recording: Recording;
  timeline: Timeline;
  frame: Frame;
  facts: RunFacts;
  score: ScoreSoFar;
  /** True once the current step's outcome is told. */
  revealed: boolean;
  /** True once the current step's clock has reached its recorded end. */
  ended: boolean;
}

/**
 * True once the screen tells that the attacker reached the goal: the clock has
 * passed it, and the run's first alert, when it was raised before the goal,
 * has been told (`told`, the first alert as the screen tells it), also when
 * that alert fires on screen only after the clock has passed the goal. The
 * goal never comes first on screen when the alert came first in the
 * recording, and once told it is not taken back.
 */
export function goalReached(frame: Frame, facts: RunFacts, told: FirstAlert | null): boolean {
  if (facts.goal === null || frame.real < facts.goal) return false;
  const first = facts.firstAlert;
  return told !== null || first === null || first.real > facts.goal;
}

/** The attacker's goal as the end of a sentence: its own words without a closing full stop. */
export function goalWords(goal: string): string {
  return goal.trim().replace(/[.\s]+$/, "");
}

/**
 * One sentence that says who is winning so far. For an attack path it is the
 * race between the first alert and the goal, both on the recording's real
 * clock: the goal falls `score.goal_seconds` after the first step's recorded start.
 */
export function whoIsWinning(recording: Recording, frame: Frame, score: ScoreSoFar, facts: RunFacts, firstAlert: FirstAlert | null = frame.race.firstAlert): string {
  const { race } = frame;
  if (frame.segment === null) return "Nothing has run yet.";
  if (recording.kind === "attack path") {
    const first = firstAlert;
    const goalReal = facts.goal;
    if (goalReal !== null && goalReached(frame, facts, first)) {
      // The goal is named where it is claimed: the format refuses a goal time without a goal.
      // Quoted after "its goal", so the sentence stays in the past tense whatever tense the goal's own words take.
      const goal = recording.attacker.goal === null ? "" : `, “${plainMarks(goalWords(recording.attacker.goal))}”,`;
      // Both facts, the attacker's first: it got what it came for, whether a step was stopped on the way, and when the first alert came.
      const stopped = recording.steps.filter((item) => item.outcome === "stopped" && (item.ended === undefined || timeOf(item.ended) <= goalReal)).length;
      const stops = stopped === 0 ? "no step stopped" : `${plural(stopped, "step")} stopped`;
      const reached = goal ? `The attacker reached its goal${goal}` : "The attacker reached the goal";
      if (!first) return `${reached} with no alert and ${stops}.`;
      const gap = span(Math.abs(goalReal - first.real));
      return first.real <= goalReal ? `${reached} ${gap} after the first alert, with ${stops}.` : `${reached} ${gap} before the first alert.`;
    }
    if (first) {
      const clock = firstAlertClock(recording, facts, first);
      const where = stepLabel(recording, first.step);
      return clock ? `The defense raised its first alert on ${where}, ${elapsed(clock.seconds)} ${clock.words}.` : `The defense raised its first alert on ${where}.`;
    }
    return frame.ended ? "No alert on any step." : "No alert yet.";
  }
  const decided = score.alerted + score.seen + score.unseen;
  if (decided === 0) {
    if (race.testsRun === 0) return "No test has run yet.";
    if (race.testsRun === 1 && score.testsDone === 0) return "The first test is running.";
    return `${score.testsDone} of ${plural(race.testsTotal, "test")} ${score.testsDone === 1 ? "has" : "have"} run; none ${frame.ended ? "was" : "is yet"} alerted, seen or unseen.`;
  }
  // Once every test has run and the reruns play, the tests' count is final: no "so far".
  const final = frame.ended || (score.testsDone === race.testsTotal && frame.segment.step.role !== "test");
  const soFar = final ? "" : " so far";
  const through = score.seen + score.unseen;
  if (through === 0) return `Every test${soFar} raised an alert: ${score.alerted} of ${decided}.`;
  // Only the count fits here: the caption, the map and analyse mode say what the recording holds of an unseen test.
  const unseen = score.unseen > 0 ? `, ${score.unseen} unseen` : "";
  return `${through} of ${plural(decided, "test")}${soFar} got through without an alert${unseen}.`;
}

/**
 * While hardened reruns play: how many of those that have reached their recorded end their change stopped, of all the
 * hardened reruns of the recording, the count the score box gives. `ended` says whether the current step's clock has
 * reached its end, the moment the host's badge and the log say it was stopped. Null at any other step.
 */
export function rerunsSoFar(timeline: Timeline, frame: Frame, ended: boolean): { stopped: number; total: number } | null {
  const current = frame.segment;
  if (!current || current.step.role !== "hardened") return null;
  const hardened = timeline.segments.filter((segment) => segment.step.role === "hardened");
  const over = hardened.filter((segment) => segment.end <= frame.time || (segment === current && ended));
  return { stopped: over.filter((segment) => segment.step.outcome === "stopped").length, total: hardened.length };
}

/** Pixels kept free between two labels on the track. */
const LABEL_GAP = 12;
/** Pixels a label that opens to the left of its flag reaches past the flag. */
const PAST_FLAG = 10;

/** A flag's label: where its flag stands and how wide its words are, in pixels from the track's left. */
export interface FlagLabel {
  x: number;
  width: number;
}

/** Where the race line's labels go on a track, in pixels from its left. */
export interface FlagPlaces {
  /** The left edge of the first alert's label. */
  alert: number | null;
  /** The left edge of the goal's label. */
  goal: number | null;
  /** True when the goal's label stands a row above the first alert's, because on one row the two would touch. */
  raised: boolean;
  /** The right edge of the words that stand in for the first alert until it comes. */
  waitEnd: number;
  /** Whether "00:00" at the start of the track stays clear of each label. */
  startClearOfAlert: boolean;
  startClearOfGoal: boolean;
}

/** A label opens to the right of its flag, unless it would pass the end of the track: then it opens to its left. */
function natural(label: FlagLabel, track: number): number {
  if (label.x + label.width <= track) return label.x;
  return Math.max(0, Math.min(label.x + PAST_FLAG, track) - label.width);
}

function touch(left: number, width: number, otherLeft: number, otherWidth: number): boolean {
  return left < otherLeft + otherWidth + LABEL_GAP && otherLeft < left + width + LABEL_GAP;
}

/**
 * Places the labels of the first alert and the goal so that both can be read
 * at any width: each opens to the right of its flag, or to its left near the
 * end of the track. Two that would touch go one to each side when there is
 * room, and else the goal's stands a row higher. The words that wait for the
 * first alert stand at the end of the track, or just before the goal's label.
 * `wait` and `start` are the widths of those words and of "00:00".
 */
export function placeFlags(track: number, alert: FlagLabel | null, goal: FlagLabel | null, wait: number, start: number): FlagPlaces {
  if (track <= 0) {
    // Not measured yet: every label opens to the right of its flag.
    return { alert: alert?.x ?? null, goal: goal?.x ?? null, raised: false, waitEnd: track, startClearOfAlert: true, startClearOfGoal: true };
  }
  let alertLeft = alert ? natural(alert, track) : null;
  let goalLeft = goal ? natural(goal, track) : null;
  let raised = false;
  if (alert && goal && alertLeft !== null && goalLeft !== null && touch(alertLeft, alert.width, goalLeft, goal.width)) {
    const alertFirst = alert.x <= goal.x;
    const [early, late] = alertFirst ? [alert, goal] : [goal, alert];
    const earlyLeft = early.x + PAST_FLAG - early.width;
    if (earlyLeft >= 0 && late.x + late.width <= track && early.x + PAST_FLAG + LABEL_GAP <= late.x) {
      alertLeft = alertFirst ? earlyLeft : late.x;
      goalLeft = alertFirst ? late.x : earlyLeft;
    } else {
      raised = true;
    }
  }
  const sameRowGoal = goal && goalLeft !== null && !raised ? goalLeft : null;
  const waitEnd = sameRowGoal !== null && goal && touch(track - wait, wait, sameRowGoal, goal.width) ? Math.max(wait, sameRowGoal - LABEL_GAP) : track;
  return {
    alert: alertLeft,
    goal: goalLeft,
    raised,
    waitEnd,
    startClearOfAlert: alertLeft === null || alertLeft >= start + LABEL_GAP,
    startClearOfGoal: sameRowGoal === null || sameRowGoal >= start + LABEL_GAP,
  };
}

interface Widths {
  track: number;
  alert: number;
  goal: number;
  waiting: number;
  none: number;
  start: number;
}

const UNMEASURED: Widths = { track: 0, alert: 0, goal: 0, waiting: 0, none: 0, start: 0 };

/** The widths of the track and of each label's words, measured on hidden copies and kept up to date as they change. */
function useWidths(): [RefObject<HTMLDivElement | null>, RefObject<HTMLDivElement | null>, Widths] {
  const track = useRef<HTMLDivElement | null>(null);
  const ruler = useRef<HTMLDivElement | null>(null);
  const [widths, setWidths] = useState<Widths>(UNMEASURED);
  useLayoutEffect(() => {
    const trackElement = track.current;
    const rulerElement = ruler.current;
    if (!trackElement || !rulerElement) return undefined;
    const of = (name: keyof Widths) => rulerElement.querySelector(`[data-measure="${name}"]`)?.getBoundingClientRect().width ?? 0;
    const measure = () => {
      const next: Widths = { track: trackElement.clientWidth, alert: of("alert"), goal: of("goal"), waiting: of("waiting"), none: of("none"), start: of("start") };
      setWidths((old) => ((Object.keys(next) as (keyof Widths)[]).every((key) => Math.abs(old[key] - next[key]) < 0.5) ? old : next));
    };
    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(trackElement);
    for (const item of rulerElement.querySelectorAll("[data-measure]")) observer.observe(item);
    return () => observer.disconnect();
  }, []);
  return [track, ruler, widths];
}

export function RaceLine({ recording, timeline, frame, facts, score, revealed, ended }: RaceLineProps) {
  const length = Math.max(1, facts.end - facts.start);
  const fraction = (real: number) => Math.min(1, Math.max(0, (real - facts.start) / length));
  const at = (real: number) => `${(fraction(real) * 100).toFixed(3)}%`;
  const head = at(frame.real);
  const first = timeline.firstAlert;
  const reached = firstAlertOnScreen(frame.race.firstAlert, frame.time, frame.segment, revealed);
  const goal = recording.score.goal_seconds;
  const goalReal = facts.goal;
  const other = facts.otherFirst && frame.time >= facts.otherFirst.at ? facts.otherFirst : null;
  const testList = recording.kind === "test list";
  const segmentsBegun = timeline.segments.filter((segment) => segment.start <= frame.time).length;
  // While a step that is not a test plays, the counter also says how many of those have run.
  const others = timeline.segments.filter((segment) => segment.step.role !== "test");
  const otherTotal = others.length;
  const otherBegun = others.filter((segment) => segment.start <= frame.time).length;
  const otherNow = testList && frame.segment !== null && frame.segment.step.role !== "test" && otherBegun > 0;
  const otherRoles = [...new Set(others.map((segment) => segment.step.role))].join(", ");
  const reruns = rerunsSoFar(timeline, frame, ended);
  const otherNote = other ? `${capital(stepLabel(recording, other.step))} alerted at ${elapsed((other.real - facts.start) / 1000)} into the run${other.step.role === "canary" ? ", as expected: it is built to be caught" : ""}.` : undefined;
  // The flagged alert itself: the counting published match that fires first.
  const firstRule = first?.alert.rule.title;
  const firstFalse = firstRule ? ordinaryAlertEvents(recording, firstRule) : 0;
  const firstClock = first ? firstAlertClock(recording, facts, first) : null;
  const winning = whoIsWinning(recording, frame, score, facts, reached);
  // Rules that ran after the run have no time of their own: said once, here, where the first alert's time is shown.
  const eventTime = rulesRanAfterTheRun(recording);
  const eventTimeWords = "The rules ran after the run, so an alert's time is the time of the event it matched.";
  // The count of tests that got through leads the sentence, in the attacker's colour.
  const lead = winning.includes("got through") ? (/^\d[\d,]* of [\d,]+ tests?/.exec(winning)?.[0] ?? "") : "";

  // The labels' places depend on the run and the width only, not on the moment, so they never move while it plays.
  const [trackRef, rulerRef, widths] = useWidths();
  const alertWords: ReactNode = first ? (
    <>
      {firstClock ? <b>{elapsed(firstClock.seconds)}</b> : null} first alert &middot; {stepLabel(recording, first.step)}
      {eventTime ? <small className="lv-flag-note"> (the time of the event it matched)</small> : null}
    </>
  ) : null;
  const goalLabel: ReactNode =
    goalReal === null ? null : (
      <>
        <b>{elapsed(goal ?? 0)}</b> goal reached
      </>
    );
  const waiting = testList ? "first alert on a test: not yet" : "first alert: not yet";
  const none = testList ? "no test raised an alert" : "no alert";
  const alertX = first ? fraction(first.real) * widths.track : 0;
  const goalX = goalReal === null ? 0 : fraction(goalReal) * widths.track;
  const places = placeFlags(widths.track, first ? { x: alertX, width: widths.alert } : null, goalReal === null ? null : { x: goalX, width: widths.goal }, frame.ended ? widths.none : widths.waiting, widths.start);
  const alertShown = first !== null && reached !== null;
  const goalShown = goalReal !== null && goalReached(frame, facts, reached);
  const startLabel = !(alertShown && !places.startClearOfAlert) && !(goalShown && !places.startClearOfGoal);

  return (
    <section className={`lv-race${places.raised ? " is-stacked" : ""}`} aria-label="The race">
      <div className="lv-race-side">
        <span className="lv-race-key">
          <i />
          Attacker
        </span>
        <span className="lv-race-value">
          {testList ? frame.race.testsRun : segmentsBegun}
          <small>of {testList ? plural(frame.race.testsTotal, "test") : plural(timeline.segments.length, "step")}</small>
        </span>
        <span className="lv-race-more" title={`Steps that are not tests (${otherRoles}), which are not in the score of tests`}>
          {otherNow ? `${otherBegun} of ${plural(otherTotal, "other step")}` : ""}
        </span>
      </div>
      <div className="lv-race-body">
        <div className="lv-track" ref={trackRef}>
          <div className="lv-flag-ruler" ref={rulerRef} aria-hidden="true">
            <span className="lv-track-start" data-measure="start">
              00:00
            </span>
            <div className="lv-flag">
              <span data-measure="alert">{alertWords}</span>
            </div>
            <div className="lv-flag is-goal">
              <span data-measure="goal">{goalLabel}</span>
            </div>
            <div className="lv-flag-wait">
              <span data-measure="waiting">{waiting}</span>
            </div>
            <div className="lv-flag-wait">
              <span data-measure="none">{none}</span>
            </div>
          </div>
          {startLabel ? (
            <span className="lv-track-start" title={`Times count from ${facts.startWords}, ${clockTime(facts.start)} UTC`}>
              00:00
            </span>
          ) : null}
          <div className="lv-rail" />
          <div className="lv-fill" style={{ width: head }} />
          {other ? <div className="lv-pin" style={{ left: at(other.real) }} title={otherNote} /> : null}
          <div className="lv-head-dot" style={{ left: head }} title="The playhead" />
          {first && alertShown ? (
            <div
              className="lv-flag"
              style={{ left: at(first.real) }}
              title={[firstClock ? `${elapsed(firstClock.seconds)} ${firstClock.words}.` : "", eventTime ? eventTimeWords : "", first.testsBefore === 0 ? `It fired before any other ${unitWord(recording)} had started.` : `${capital(plural(first.testsBefore, `other ${unitWord(recording)}`))} had started when it fired.`, firstRule ? `Rule: ${firstRule}.` : "", firstFalse > 0 ? `Its rule also alerted on ${plural(firstFalse, "event")} of ordinary activity, outside every step.` : "", otherNote].filter(Boolean).join(" ")}
            >
              <span style={{ left: `${(places.alert ?? alertX) - alertX}px` }}>{alertWords}</span>
              <i />
            </div>
          ) : timeline.segments.length === 0 ? null : (
            <div className="lv-flag-wait" style={goalShown ? { right: `${widths.track - places.waitEnd}px` } : undefined}>
              {frame.ended ? none : waiting}
            </div>
          )}
          {goalShown && goalReal !== null ? (
            <div className={`lv-flag is-goal${places.raised ? " is-raised" : ""}`} style={{ left: at(goalReal) }} title={recording.attacker.goal === null ? undefined : `The attacker's goal: ${plainMarks(recording.attacker.goal)}`}>
              <span style={{ left: `${(places.goal ?? goalX) - goalX}px` }}>{goalLabel}</span>
              <i />
            </div>
          ) : null}
        </div>
        <div className="lv-race-notes">
          <span className="lv-winning" title={reruns ? `${winning} Hardened reruns: ${reruns.stopped} of ${reruns.total} stopped so far.` : winning}>
            {lead ? <em>{lead}</em> : null}
            {winning.slice(lead.length)}
            {reruns ? (
              <span className="lv-phase">
                {" "}
                Hardened reruns: <b>{reruns.stopped}</b> of {reruns.total} stopped so far.
              </span>
            ) : null}
          </span>
          {/* Once the goal is told, its time stands on the track and the sentence that names the goal needs the whole line. */}
          {goalShown ? null : (
            <span className="lv-race-end" title={`From ${facts.startWords} to the end of the last step${recording.source.finished ? "" : " so far"}, ${clockTime(facts.end)} UTC`}>
              {elapsed(length / 1000, 0)} {recording.source.finished ? "from the first step to the last" : "so far"}
            </span>
          )}
        </div>
      </div>
    </section>
  );
}
