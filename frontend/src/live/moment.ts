// What the watch view needs about the current step at one moment: pure.

import { countsForScore } from "./recording";
import type { Alert, Recording, RecordingEvent, Step } from "./recording";
import type { FirstAlert, Frame, ScoreSoFar, Segment, Timeline } from "./playback";
import { maxOf } from "./playback";
import { matchKind, strongerKind } from "./format";
import type { MatchKind } from "./format";

/** Screen seconds a recorded event takes to travel from its host to the rule engines. */
export const TRAVEL = 0.9;
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
  /** The step's events that have arrived, in arrival order. */
  events: RecordingEvent[];
  /** The step's matches that have fired, in firing order. */
  fired: Alert[];
  /** Every match of the step, fired or not. */
  all: readonly Alert[];
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

/** The screen time at which a match's light reaches its rule engine. A match on the launcher line has no light. */
function landing(fire: { alert: Alert; at: number }): number {
  return fire.at + (fire.alert.events.length > 0 ? TRAVEL : 0);
}

/**
 * The screen time at which a step's outcome is told. An alerted step is told
 * when the light of its first alert that counts reaches the rule engine. Any
 * other step is told once the rule engines have judged what was recorded: a
 * little before the middle of its body, or when its last match lands, and
 * always a moment before the step ends.
 */
export function revealTime(timeline: Timeline, segment: Segment): number {
  const known = REVEALS.get(segment);
  if (known !== undefined) return known;
  const value = workOutReveal(timeline, segment);
  REVEALS.set(segment, value);
  return value;
}

function workOutReveal(timeline: Timeline, segment: Segment): number {
  const middle = segment.bodyStart + (segment.end - segment.bodyStart) * 0.42;
  if (segment.step.outcome === "alerted") {
    const fire = firstCountingFire(timeline, segment.step.id);
    if (fire) return Math.max(landing(fire), segment.bodyStart);
  }
  const fires = timeline.byStep.get(segment.step.id)?.fires ?? [];
  const last = Math.max(middle, maxOf(fires.map(landing)));
  return Math.max(segment.bodyStart, Math.min(last, segment.end - 0.25));
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
    if (!counted && moment.revealed) score.alerted += 1;
  }
  if (!moment.revealed) return score;
  if (step.outcome === "stopped") score.stopped += 1;
  if (test && step.outcome === "seen") score.seen += 1;
  if (test && step.outcome === "unseen") score.unseen += 1;
  return score;
}

export function momentOf(timeline: Timeline, frame: Frame, all: readonly Alert[], matches: ReturnType<typeof stepMatches>): StepMoment | null {
  const segment = frame.segment;
  if (!segment) return null;
  const now = frame.time;
  const revealAt = revealTime(timeline, segment);
  const landed: { alert: Alert; at: number }[] = [];
  for (const alert of frame.alerts) {
    const at = landing({ alert, at: timeline.fire.get(alert.id) ?? segment.bodyStart });
    if (at <= now || frame.ended) landed.push({ alert, at });
  }
  return {
    segment,
    step: segment.step,
    now,
    running: now >= segment.bodyStart,
    revealAt,
    revealed: now >= revealAt || frame.ended,
    events: frame.events,
    fired: frame.alerts,
    all,
    landed,
    matchByDetector: matches.byDetector,
    matchOf: matches.strongest,
  };
}

/**
 * The time to the first alert on a test, the same wherever it is shown. For
 * an attack path it counts from the start of the first test step (the
 * recording's own `score.first_alert_seconds` when it has it), like the
 * format's score; null when that start was not recorded. For a test list it
 * counts into the run from the first step, like the clock and the race track.
 */
export function firstAlertClock(recording: Recording, facts: RunFacts, first: FirstAlert): { seconds: number; words: string } | null {
  if (recording.kind === "attack path") return first.secondsFromFirstTest === null ? null : { seconds: first.secondsFromFirstTest, words: "after the first test step" };
  return { seconds: (first.real - facts.start) / 1000, words: "into the run" };
}

/** The recording's own facts about the run that the watch view shows in several places. */
export interface RunFacts {
  /** Real time (ms) of the first step's start, the origin of "into the run". */
  start: number;
  /** Real time (ms) of the last step's end. */
  end: number;
  /** The first alert that counts on a step that is not a test, such as a canary. */
  otherFirst: { step: Step; at: number; real: number } | null;
}

export function runFacts(recording: Recording, timeline: Timeline): RunFacts {
  const first = timeline.segments[0];
  const last = timeline.segments[timeline.segments.length - 1];
  const start = first ? first.realStart : Date.parse(recording.source.started);
  const end = last ? last.realEnd : Date.parse(recording.source.finished ?? recording.source.started);
  const roles = new Map(recording.steps.map((step) => [step.id, step]));
  const found = timeline.fires.find(({ alert }) => countsForScore(alert) && roles.get(alert.step)?.role !== "test");
  const step = found ? roles.get(found.alert.step) : undefined;
  const otherFirst = found && step ? { step, at: found.at, real: Date.parse(found.alert.raised ?? found.alert.time) } : null;
  return { start, end, otherFirst };
}
