// What the watch view needs about the current step at one moment: pure.

import { alertMoment, countsAsAlert, countsForScore, timeOf } from "./recording";
import type { Alert, Outcome, Recording, RecordingEvent, Step } from "./recording";
import type { Fire, FirstAlert, Frame, ScoreSoFar, Segment, Timeline } from "./playback";
import { landing, maxOf, outcomeAt, outcomeAtEnd, PLAYBACK_RULE, stepEnd, stepMatchesFiredBy } from "./playback";
import { matchKind, span, stepLabel, strongerKind } from "./format";
import type { MatchKind } from "./format";

/** Screen seconds a recorded event takes to travel from its host to the rule engines. */
export const TRAVEL = PLAYBACK_RULE.travel;
/** The share of the travel spent between the host and its sensor. */
export const TO_SENSOR = 0.26;

export interface StepMoment {
  segment: Segment;
  step: Step;
  /** Screen time. */
  now: number;
  /** True once the step's real window has started to play. */
  running: boolean;
  /** Screen time at which the step's outcome is told. */
  revealAt: number;
  revealed: boolean;
  /**
   * The outcome the step is told with now, the one the score counts. It
   * differs from the step's own only for a step whose first alert was raised
   * live after it ended: until that alert fires, in the silence after the
   * step, it is told as seen or unseen with no alert yet.
   */
  outcome: Outcome;
  /** The step's outcome as it stood when the step ended, which its own sentence tells. */
  stood: Outcome;
  /** Late arrivals of earlier steps (or of this one, in the silence after it) that have fired while it is on screen. */
  late: Fire[];
  /** The step's events that have arrived, in arrival order. */
  events: RecordingEvent[];
  /** The step's matches that have fired, in firing order. */
  fired: Alert[];
  /** Every match of the step, fired or not. Only for drawing the lights of its events: nothing said on screen reads it. */
  all: readonly Alert[];
  /**
   * The step's matches that have fired by now, its late arrivals too, in
   * firing order: every sentence, count, hint and spoken text about the
   * step's matches reads this, so a match is told only once it has fired.
   */
  heard: readonly Alert[];
  /**
   * The step's first counting match of a published rule in playback's firing
   * order, once it has fired: the alert the step's sentence names, the same
   * one the score and the first alert's flag count from. Null before then.
   */
  named: Alert | null;
  /** The same for a rule written in this repository at alert level, which is never in the score. */
  namedLab: Alert | null;
  /** The fired matches whose light has reached its rule engine, with that moment. */
  landed: { alert: Alert; at: number }[];
  /** For each event of the step, the strongest match on it by each detector. */
  matchByDetector: Map<string, Map<string, MatchKind>>;
  /** For each event of the step, its strongest match. */
  matchOf: Map<string, MatchKind>;
}

/** The matches of a step, keyed by event: what each detector made of each event. */
export function stepMatches(alerts: readonly Alert[]): { byDetector: Map<string, Map<string, MatchKind>>; strongest: Map<string, MatchKind> } {
  const byDetector = new Map<string, Map<string, MatchKind>>();
  const strongest = new Map<string, MatchKind>();
  for (const alert of alerts) {
    const kind = matchKind(alert);
    for (const id of alert.events) {
      const own = byDetector.get(id) ?? new Map<string, MatchKind>();
      own.set(alert.detector, strongerKind(own.get(alert.detector) ?? null, kind));
      byDetector.set(id, own);
      strongest.set(id, strongerKind(strongest.get(id) ?? null, kind));
    }
  }
  return { byDetector, strongest };
}

function firstCountingFire(timeline: Timeline, stepId: string): { alert: Alert; at: number } | undefined {
  return timeline.byStep.get(stepId)?.firstCounting ?? undefined;
}

const REVEALS = new WeakMap<Segment, number>();

/**
 * The screen time at which a step's outcome is told. An alerted step is told
 * when the light of its first alert that counts reaches the rule engine. Any
 * other step is told once the rule engines have judged what was recorded: a
 * little before the middle of its body, or when its last match lands, and
 * always a moment before the step ends. The step holds after its body for as
 * long as that takes, so each light lands while the step is on screen.
 */
export function revealTime(timeline: Timeline, segment: Segment): number {
  const known = REVEALS.get(segment);
  if (known !== undefined) return known;
  const value = workOutReveal(timeline, segment);
  REVEALS.set(segment, value);
  return value;
}

function workOutReveal(timeline: Timeline, segment: Segment): number {
  const middle = segment.bodyStart + (segment.bodyEnd - segment.bodyStart) * 0.42;
  if (segment.step.outcome === "alerted") {
    const fire = timeline.byStep.get(segment.step.id)?.firstCounting;
    // An alert raised after the step ended is not waited for: the step is told
    // as it stood. One that still fires inside the step's own stretch, before
    // the step leaves the screen, is waited for, so the step is never told as
    // seen first and then taken back.
    if (fire && (!fire.late || fire.at <= segment.end)) return Math.max(landing(fire), segment.bodyStart);
  }
  // The step's own fires, which leave out its late arrivals.
  const fires = timeline.byStep.get(segment.step.id)?.fires ?? [];
  const last = Math.max(middle, maxOf(fires.map(landing)));
  return Math.max(segment.bodyStart, Math.min(last, segment.end - PLAYBACK_RULE.told));
}

/**
 * The score as the screen tells it: the playback's score so far, with the
 * current step counted from the moment its outcome is told, so the numbers
 * and the step's own words never disagree.
 */
export function scoreOnScreen(timeline: Timeline, frame: Frame, moment: StepMoment | null): ScoreSoFar {
  const score = { ...frame.score };
  if (!moment || frame.ended || moment.now >= moment.segment.end) return score;
  const step = moment.step;
  const test = step.role === "test" && step.happened.answer === "took effect";
  if (step.outcome === "alerted" && test) {
    const fire = firstCountingFire(timeline, step.id);
    const counted = fire !== undefined && moment.now >= fire.at;
    if (counted && !moment.revealed) score.alerted -= 1;
    if (!counted && moment.revealed && moment.outcome === "alerted") score.alerted += 1;
  }
  if (!moment.revealed) return score;
  if (step.outcome === "stopped") score.stopped += 1;
  if (test && moment.outcome === "seen") score.seen += 1;
  if (test && moment.outcome === "unseen") score.unseen += 1;
  return score;
}

/**
 * The first alert on a test as the screen tells it: from its fire time, but
 * while its own step plays, not before that step's outcome is told, so the
 * flag, the timeline's mark and the score never disagree.
 */
export function firstAlertOnScreen(first: FirstAlert | null, time: number, segment: Segment | null | undefined, revealed: boolean): FirstAlert | null {
  if (!first || time < first.at) return null;
  return segment?.step.id === first.step.id && !revealed ? null : first;
}

const LATE_WORDS: Record<MatchKind, string> = {
  alert: "Alert",
  lab: "A rule written in this repository would alert",
  review: "Match for review",
  launcher: "Launcher line match, never counted,",
};

/**
 * A late arrival in one plain sentence, from the recording's own times:
 * "Alert on test 3, Discover Private SSH Keys: <rule>, raised 14.2 s after that step ended."
 */
export function lateWords(recording: Recording, timeline: Timeline, fire: Fire): string {
  const segment = timeline.segments.find((item) => item.step.id === fire.alert.step);
  const where = segment ? `${stepLabel(recording, segment.step)}, ${segment.step.title}` : fire.alert.step;
  const kind = matchKind(fire.alert);
  const what = kind === "review" && fire.alert.rule.level === "informational" ? "Informational match" : LATE_WORDS[kind];
  return `${what} on ${where}: ${fire.alert.rule.title}, ${raisedAfterEnd(timeline, fire, "that step")}.`;
}

/** "raised 14.2 s after that step ended", from the step's end as every part of the view reads it. */
function raisedAfterEnd(timeline: Timeline, fire: Fire, which: string): string {
  const segment = timeline.segments.find((item) => item.step.id === fire.alert.step);
  const ended = segment ? stepEnd(segment) : Number.NaN;
  return Number.isFinite(ended) ? `raised ${span(alertMoment(fire.alert) - ended)} after ${which} ended` : `raised after ${which} ended`;
}

/**
 * The line under the step for the late arrivals on screen: every one fired
 * within the time it takes to read one, so when several fire at once each is
 * named, and never fewer than the score counts. One arrival is told by
 * `lateWords`; several by their count and each rule with its step.
 */
export function lateLine(recording: Recording, timeline: Timeline, late: readonly Fire[]): string | null {
  const last = late[late.length - 1];
  if (!last) return null;
  const together = late.filter((fire) => fire.at > last.at - PLAYBACK_RULE.read);
  if (together.length === 1) return lateWords(recording, timeline, last);
  const step = (fire: Fire) => recording.steps.find((item) => item.id === fire.alert.step);
  const what = together.every((fire) => matchKind(fire.alert) === "alert") ? "alerts" : "matches";
  const named = together.map((fire) => {
    const owner = step(fire);
    return `${fire.alert.rule.title} on ${owner ? stepLabel(recording, owner) : fire.alert.step}, ${raisedAfterEnd(timeline, fire, "it")}`;
  });
  return `${together.length} ${what} raised late: ${named.join("; ")}.`;
}

export function momentOf(timeline: Timeline, frame: Frame, all: readonly Alert[], matches: ReturnType<typeof stepMatches>): StepMoment | null {
  const segment = frame.segment;
  if (!segment) return null;
  const now = frame.time;
  const revealAt = revealTime(timeline, segment);
  const landed: { alert: Alert; at: number }[] = [];
  for (const alert of frame.alerts) {
    const at = landing({ alert, at: timeline.fire.get(alert.id) ?? segment.bodyStart, late: false });
    if (at <= now || frame.ended) landed.push({ alert, at });
  }
  const heard = stepMatchesFiredBy(timeline, segment.step.id, now);
  return {
    segment,
    step: segment.step,
    now,
    running: now >= segment.bodyStart,
    revealAt,
    revealed: now >= revealAt || frame.ended,
    outcome: outcomeAt(timeline, segment, now),
    stood: outcomeAtEnd(timeline, segment),
    late: frame.late,
    events: frame.events,
    fired: frame.alerts,
    all,
    heard,
    named: heard.find(countsForScore) ?? null,
    namedLab: heard.find((alert) => countsAsAlert(alert) && alert.rule.origin === "lab") ?? null,
    landed,
    matchByDetector: matches.byDetector,
    matchOf: matches.strongest,
  };
}

/**
 * The time to the first alert on a test, the same wherever it is shown. For
 * an attack path it counts from the start of the first test step to the
 * moment the alert fires, like the format's `score.first_alert_seconds`; null
 * when that start was not recorded. For a test list it
 * counts into the run from the first step, like the clock and the race track.
 */
export function firstAlertClock(recording: Recording, facts: RunFacts, first: FirstAlert): { seconds: number; words: string } | null {
  if (recording.kind === "attack path") return first.secondsFromFirstTest === null ? null : { seconds: first.secondsFromFirstTest, words: "after the first test step" };
  return { seconds: (first.real - facts.start) / 1000, words: "into the run" };
}

/** The recording's own facts about the run that the watch view shows in several places. */
export interface RunFacts {
  /**
   * Real time (ms) at which the run starts, the origin of "into the run" and
   * of the race track: for an attack path its first step's recorded start, the
   * one moment its race counts from; for a test list the start of the first
   * step's window, its start or an event stamped a little before it.
   */
  start: number;
  /** What `start` is, in words for a tooltip: "the first step's recorded start". */
  startWords: string;
  /** Real time (ms) of the last step's end. */
  end: number;
  /**
   * Real time (ms) at which an attack path reaches its goal: `score.goal_seconds`
   * after its first step's recorded start, as the format counts it. Null
   * without a goal time.
   */
  goal: number | null;
  /**
   * The run's first alert on a test, whenever it fires on screen. The race
   * holds the goal back until this alert is told when it was raised before
   * the goal. Null when no test alerted.
   */
  firstAlert: FirstAlert | null;
  /** The first alert that counts on a step that is not a test, such as a canary. */
  otherFirst: { step: Step; at: number; real: number } | null;
}

export function runFacts(recording: Recording, timeline: Timeline): RunFacts {
  const first = timeline.segments[0];
  const last = timeline.segments[timeline.segments.length - 1];
  // An attack path begins with a test that has a start, and its race counts
  // from that one moment: the first alert, the goal, the track and the clock.
  const raceStart = recording.kind === "attack path" && first?.step.started !== undefined ? timeOf(first.step.started) : null;
  const start = raceStart ?? (first ? first.realStart : timeOf(recording.source.started));
  // A running recording has no end yet: without steps its run has only begun.
  const end = last ? last.realEnd : timeOf(recording.source.finished ?? recording.source.started);
  const seconds = recording.kind === "attack path" ? recording.score.goal_seconds : undefined;
  const goal = seconds === undefined || raceStart === null ? null : raceStart + seconds * 1000;
  const roles = new Map(recording.steps.map((step) => [step.id, step]));
  const found = timeline.fires.find(({ alert }) => countsForScore(alert) && roles.get(alert.step)?.role !== "test");
  const step = found ? roles.get(found.alert.step) : undefined;
  const otherFirst = found && step ? { step, at: found.at, real: alertMoment(found.alert) } : null;
  const startWords = raceStart !== null ? "the first step's recorded start" : "the first recorded event of the first step";
  return { start, startWords, end, goal, firstAlert: timeline.firstAlert, otherFirst };
}
