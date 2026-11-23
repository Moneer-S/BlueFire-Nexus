// The playback model of the live view: pure functions, no React, no clock.
//
// Screen time is in seconds from the start of playback at normal speed. Real
// time is milliseconds since 1970, the recording's own clock.
//
// The rule: every step gets a segment on screen made of a short lead (the step
// is told before anything arrives) and a body that plays the step's real
// window. The body's length is the step's real duration passed through a
// curve that stretches short steps and squeezes long ones into a comfortable
// range: MIN_BODY + (MAX_BODY - MIN_BODY) * d / (d + HALF), with d in seconds.
// A step of 0.1 s gets about 1.8 s, one of 8 s about 6.8 s, one of a minute
// about 10.8 s, and no step gets more than 12 s. Inside the body, real time
// runs linearly, so events keep their order and spacing. When the light of a
// match fired in the body would reach its rule engine too late to be told, the
// step holds after its body, its clock stopped, until a moment after it lands.
// Every silence between two steps, whatever its real length, becomes one short
// beat.

import { countsAsAlert, countsForScore, timeOf } from "./recording";
import type { Alert, Recording, RecordingEvent, Step } from "./recording";

export const PLAYBACK_RULE = {
  /** Seconds a step is shown before its real window starts to play. */
  lead: 0.4,
  /** Shortest body of a step, in seconds of screen time. */
  minBody: 1.6,
  /** The body length that very long steps approach and never reach. */
  maxBody: 12,
  /** Real seconds at which a step gets half of the range between the two. */
  half: 8,
  /** Screen seconds of every silence between two steps. */
  beat: 0.5,
  /** Screen seconds a recorded event takes to travel from its host to the rule engines. */
  travel: 0.9,
  /** Screen seconds a step's outcome is told, at least, before the step ends. */
  told: 0.25,
} as const;

/** The screen time at which a match's light reaches its rule engine. A match on the launcher line has no light. */
export function landing(fire: Fire): number {
  return fire.at + (fire.alert.events.length > 0 ? PLAYBACK_RULE.travel : 0);
}

/** Screen seconds of a step's body for a real duration in seconds. */
export function bodySeconds(realSeconds: number): number {
  const { minBody, maxBody, half } = PLAYBACK_RULE;
  const d = Number.isFinite(realSeconds) && realSeconds > 0 ? realSeconds : 0;
  return minBody + ((maxBody - minBody) * d) / (d + half);
}

export interface Segment {
  step: Step;
  /** The step's place in `recording.steps`. */
  index: number;
  /** Screen time where the segment begins. */
  start: number;
  /** Screen time where the lead ends and the real window starts to play. */
  bodyStart: number;
  /** Screen time where the real window has played. */
  bodyEnd: number;
  /** Screen time where the segment ends: the body's end, or later when the step holds for a match's light to land. */
  end: number;
  /** The real window the body plays, in ms. It holds the step's events and matches. */
  realStart: number;
  realEnd: number;
  /** False when the recording has no start for the step, so its window is taken from its events or its place. */
  timed: boolean;
}

/** A silence between two steps, shortened to one beat. */
export interface Gap {
  /** Index of the segment before it. */
  after: number;
  start: number;
  end: number;
  realStart: number;
  realEnd: number;
}

export interface Arrival {
  event: RecordingEvent;
  at: number;
}

export interface Fire {
  alert: Alert;
  at: number;
}

/** What one step brings to the screen, worked out once. */
export interface StepPlay {
  /** The step's events, in arrival order. */
  arrivals: Arrival[];
  /** The step's matches of any level and origin, in firing order. */
  fires: Fire[];
  /** The step's first counting match of a published rule, if any. */
  firstCounting: Fire | null;
  /** The step's first counting match of either origin, if any. */
  firstCountingWithLabRules: Fire | null;
}

export interface Timeline {
  recording: Recording;
  segments: Segment[];
  gaps: Gap[];
  /** Screen seconds of the whole playback at normal speed. */
  duration: number;
  /** Screen time at which each event arrives, by event id. */
  arrival: Map<string, number>;
  /** Screen time at which each match fires, by alert id. */
  fire: Map<string, number>;
  /** Every event with its arrival, in arrival order. */
  arrivals: Arrival[];
  /** Every match with its firing time, in firing order. */
  fires: Fire[];
  /** Each step's own arrivals and fires, by step id. Every step has an entry. */
  byStep: Map<string, StepPlay>;
  /** The segments of steps of role `test`, in run order. */
  tests: Segment[];
  /** True when any step carries `outcome_with_lab_rules`. */
  withLabRules: boolean;
  /** The first counting match of a published rule on a step of role `test`, if any. */
  firstAlert: FirstAlert | null;
  /** The same when the accepted rules written in this repository count too. */
  firstAlertWithLabRules: FirstAlert | null;
}

export interface FirstAlert {
  step: Step;
  alert: Alert;
  /** Screen time at which it fires. */
  at: number;
  /** Its real time, in ms: `raised` when present, else the time of the matched activity. */
  real: number;
  /**
   * The other steps of role `test` that had begun when it fired: the tests the
   * attacker started before the defense knew. Its own step is not counted.
   */
  testsBefore: number;
  /**
   * Real seconds from the start of the first step of role `test`: the
   * recording's own `score.first_alert_seconds` for an attack path that has
   * it. Null when the first test has no recorded start.
   */
  secondsFromFirstTest: number | null;
}

/** The smallest of many numbers, without spreading them into call arguments, which fails past about 100,000. */
export function minOf(values: Iterable<number>, empty = Number.POSITIVE_INFINITY): number {
  let low = Number.POSITIVE_INFINITY;
  for (const value of values) if (value < low) low = value;
  return low === Number.POSITIVE_INFINITY ? empty : low;
}

/** The largest of many numbers; see `minOf`. */
export function maxOf(values: Iterable<number>, empty = Number.NEGATIVE_INFINITY): number {
  let high = Number.NEGATIVE_INFINITY;
  for (const value of values) if (value > high) high = value;
  return high === Number.NEGATIVE_INFINITY ? empty : high;
}

/** How many items of a list sorted by `at` have `at <= t`: a binary search. */
function countUpTo(items: readonly { at: number }[], t: number): number {
  let low = 0;
  let high = items.length;
  while (low < high) {
    const middle = (low + high) >> 1;
    const item = items[middle];
    if (item && item.at <= t) low = middle + 1;
    else high = middle;
  }
  return low;
}

/** How many segments of a list in run order have begun by screen time `t`. */
function countBegun(segments: readonly Segment[], t: number): number {
  let low = 0;
  let high = segments.length;
  while (low < high) {
    const middle = (low + high) >> 1;
    const item = segments[middle];
    if (item && item.start <= t) low = middle + 1;
    else high = middle;
  }
  return low;
}

// The last cut of each list, so the same frame contents keep the same array
// from one animation frame to the next and a view can compare them cheaply.
const EVENT_CUTS = new WeakMap<readonly Arrival[], { count: number; items: RecordingEvent[] }>();
const ALERT_CUTS = new WeakMap<readonly Fire[], { count: number; items: Alert[] }>();

function cutEvents(list: readonly Arrival[], count: number): RecordingEvent[] {
  const last = EVENT_CUTS.get(list);
  if (last && last.count === count) return last.items;
  const items = list.slice(0, count).map(({ event }) => event);
  EVENT_CUTS.set(list, { count, items });
  return items;
}

function cutAlerts(list: readonly Fire[], count: number): Alert[] {
  const last = ALERT_CUTS.get(list);
  if (last && last.count === count) return last.items;
  const items = list.slice(0, count).map(({ alert }) => alert);
  ALERT_CUTS.set(list, { count, items });
  return items;
}

interface StepFacts {
  events: RecordingEvent[];
  alerts: Alert[];
}

function stepFacts(recording: Recording): Map<string, StepFacts> {
  const facts = new Map<string, StepFacts>(recording.steps.map((step) => [step.id, { events: [], alerts: [] }]));
  for (const event of recording.events) facts.get(event.step)?.events.push(event);
  for (const alert of recording.alerts) facts.get(alert.step)?.alerts.push(alert);
  return facts;
}

function finite(values: number[]): number[] {
  return values.filter((value) => Number.isFinite(value));
}

function placeInBody(segment: Segment, real: number): number {
  const body = segment.bodyEnd - segment.bodyStart;
  const span = segment.realEnd - segment.realStart;
  if (span <= 0) return segment.bodyStart;
  const clamped = Math.min(segment.realEnd, Math.max(segment.realStart, real));
  return segment.bodyStart + (body * (clamped - segment.realStart)) / span;
}

function alertReal(alert: Alert): number {
  return timeOf(alert.raised ?? alert.time);
}

/** Lays the steps out on screen, each holding after its body for the seconds `holds` gives it. */
function layOut(recording: Recording, facts: Map<string, StepFacts>, holds: ReadonlyMap<string, number>): { segments: Segment[]; gaps: Gap[]; duration: number } {
  const segments: Segment[] = [];
  const gaps: Gap[] = [];
  let screen = 0;
  let previousEnd = timeOf(recording.source.started);

  recording.steps.forEach((step, index) => {
    const own = facts.get(step.id) ?? { events: [], alerts: [] };
    const recorded = finite([...own.events.map((event) => timeOf(event.time)), ...own.alerts.map((alert) => timeOf(alert.time))]);
    const started = step.started === undefined ? Number.NaN : timeOf(step.started);
    const ended = step.ended === undefined ? Number.NaN : timeOf(step.ended);
    const timed = Number.isFinite(started);
    const low = minOf(recorded, Number.NaN);
    const high = maxOf(recorded, Number.NaN);
    const starts = finite([started, low]);
    const ends = finite([ended, started, high]);
    let realStart = starts.length > 0 ? minOf(starts) : previousEnd;
    let realEnd = ends.length > 0 ? maxOf(ends) : realStart;
    if (!Number.isFinite(previousEnd)) previousEnd = realStart;
    if (realStart < previousEnd) realStart = previousEnd;
    if (realEnd < realStart) realEnd = realStart;

    if (index > 0) {
      const before = segments[index - 1];
      if (before) gaps.push({ after: index - 1, start: screen, end: screen + PLAYBACK_RULE.beat, realStart: before.realEnd, realEnd: realStart });
      screen += PLAYBACK_RULE.beat;
    }
    const bodyStart = screen + PLAYBACK_RULE.lead;
    const bodyEnd = bodyStart + bodySeconds((realEnd - realStart) / 1000);
    const end = bodyEnd + (holds.get(step.id) ?? 0);
    segments.push({ step, index, start: screen, bodyStart, bodyEnd, end, realStart, realEnd, timed });
    screen = end;
    previousEnd = realEnd;
  });
  return { segments, gaps, duration: screen };
}

/** When each event arrives and each match fires on a laid-out screen, both in time order. */
function placeAll(recording: Recording, laid: { segments: Segment[]; duration: number }): { arrivals: Arrival[]; fires: Fire[] } {
  const segmentOf = new Map(laid.segments.map((segment) => [segment.step.id, segment]));
  const arrival = new Map<string, number>();
  const arrivals: Arrival[] = [];
  const fires: Fire[] = [];
  for (const event of recording.events) {
    const segment = segmentOf.get(event.step);
    if (!segment) continue;
    const at = placeInBody(segment, timeOf(event.time));
    arrival.set(event.id, at);
    arrivals.push({ event, at });
  }
  for (const alert of recording.alerts) {
    const segment = segmentOf.get(alert.step);
    if (!segment) continue;
    const base = alert.raised === undefined ? placeInBody(segment, timeOf(alert.time)) : realToScreen(laid, timeOf(alert.raised));
    // A match fires once every event it names has arrived.
    let at = Math.max(base, segment.bodyStart);
    for (const id of alert.events) at = Math.max(at, arrival.get(id) ?? segment.bodyStart);
    fires.push({ alert, at });
  }
  arrivals.sort((a, b) => a.at - b.at);
  fires.sort((a, b) => a.at - b.at);
  return { arrivals, fires };
}

/**
 * How long each step holds after its body so that the light of every match
 * fired by its end lands a moment before the step ends. A match raised live
 * after its step ended fires later on screen and is told from then.
 */
function holdsFor(segments: readonly Segment[], fires: readonly Fire[]): Map<string, number> {
  const segmentOf = new Map(segments.map((segment) => [segment.step.id, segment]));
  const holds = new Map<string, number>();
  for (const fire of fires) {
    const segment = segmentOf.get(fire.alert.step);
    if (!segment || fire.at > segment.end) continue;
    const need = landing(fire) + PLAYBACK_RULE.told - segment.end;
    if (need > (holds.get(segment.step.id) ?? 0)) holds.set(segment.step.id, need);
  }
  return holds;
}

/** Builds the compressed timeline of a recording. */
export function buildTimeline(recording: Recording): Timeline {
  const facts = stepFacts(recording);
  let laid = layOut(recording, facts, new Map());
  let placed = placeAll(recording, laid);
  // A hold moves only later steps, and a match keeps its place inside its own body.
  const holds = holdsFor(laid.segments, placed.fires);
  if (holds.size > 0) {
    laid = layOut(recording, facts, holds);
    placed = placeAll(recording, laid);
  }
  const { segments, gaps, duration } = laid;

  const byStep = new Map<string, StepPlay>(recording.steps.map((step) => [step.id, { arrivals: [], fires: [], firstCounting: null, firstCountingWithLabRules: null }]));
  const timeline: Timeline = {
    recording,
    segments,
    gaps,
    duration,
    arrival: new Map(placed.arrivals.map(({ event, at }) => [event.id, at])),
    fire: new Map(placed.fires.map(({ alert, at }) => [alert.id, at])),
    arrivals: placed.arrivals,
    fires: placed.fires,
    byStep,
    tests: segments.filter((segment) => segment.step.role === "test"),
    withLabRules: recording.steps.some((step) => step.outcome_with_lab_rules !== undefined),
    firstAlert: null,
    firstAlertWithLabRules: null,
  };
  const segmentOf = new Map(segments.map((segment) => [segment.step.id, segment]));
  for (const arrival of timeline.arrivals) byStep.get(arrival.event.step)?.arrivals.push(arrival);
  for (const fire of timeline.fires) {
    const own = byStep.get(fire.alert.step);
    if (!own) continue;
    own.fires.push(fire);
    if (own.firstCounting === null && countsForScore(fire.alert)) own.firstCounting = fire;
    if (own.firstCountingWithLabRules === null && countsAsAlert(fire.alert)) own.firstCountingWithLabRules = fire;
  }

  // The first test is the first step of role `test`, whatever its start: a
  // time is never measured from a later step.
  const firstTest = timeline.tests[0];
  const firstTestReal = firstTest?.step.started === undefined ? null : timeOf(firstTest.step.started);
  const ownSeconds = recording.kind === "attack path" ? recording.score.first_alert_seconds : undefined;
  const first = (counts: (alert: Alert) => boolean, own: number | undefined): FirstAlert | null => {
    const found = timeline.fires.find(({ alert }) => counts(alert) && segmentOf.get(alert.step)?.step.role === "test");
    if (!found) return null;
    const segment = segmentOf.get(found.alert.step);
    if (!segment) return null;
    const real = alertReal(found.alert);
    return {
      step: segment.step,
      alert: found.alert,
      at: found.at,
      real,
      testsBefore: timeline.tests.filter((other) => other.start < found.at && other.index !== segment.index).length,
      secondsFromFirstTest: own ?? (firstTestReal === null ? null : (real - firstTestReal) / 1000),
    };
  };
  timeline.firstAlert = first(countsForScore, ownSeconds);
  timeline.firstAlertWithLabRules = first(countsAsAlert, undefined);
  return timeline;
}

function clampScreen(timeline: Timeline, screen: number): number {
  if (Number.isNaN(screen)) return 0;
  return Math.min(timeline.duration, Math.max(0, screen));
}

/** The index of the segment shown at screen time `screen`: the last one that has begun. -1 for an empty recording. */
export function segmentIndexAt(timeline: Timeline, screen: number): number {
  const t = clampScreen(timeline, screen);
  let low = 0;
  let high = timeline.segments.length - 1;
  let found = -1;
  while (low <= high) {
    const middle = (low + high) >> 1;
    const segment = timeline.segments[middle];
    if (segment && segment.start <= t) {
      found = middle;
      low = middle + 1;
    } else {
      high = middle - 1;
    }
  }
  return found;
}

/** The real time (ms) shown at screen time `screen`. During a lead the clock waits at the step's start, and during a hold at its end. */
export function screenToReal(timeline: Timeline, screen: number): number {
  const t = clampScreen(timeline, screen);
  const segment = timeline.segments[segmentIndexAt(timeline, t)];
  if (!segment) return timeOf(timeline.recording.source.started);
  if (t <= segment.bodyStart) return segment.realStart;
  if (t <= segment.bodyEnd) {
    const body = segment.bodyEnd - segment.bodyStart;
    return segment.realStart + ((segment.realEnd - segment.realStart) * (t - segment.bodyStart)) / body;
  }
  if (t <= segment.end) return segment.realEnd;
  const next = timeline.segments[segment.index + 1];
  if (!next) return segment.realEnd;
  const beat = next.start - segment.end;
  if (beat <= 0) return next.realStart;
  return segment.realEnd + ((next.realStart - segment.realEnd) * (t - segment.end)) / beat;
}

/** The screen time at which real time `real` (ms) plays. A time inside a silence falls inside its beat. */
export function realToScreen(timeline: Pick<Timeline, "segments" | "duration">, real: number): number {
  const segments = timeline.segments;
  const first = segments[0];
  if (!first || real <= first.realStart) return first ? first.bodyStart : 0;
  // Real windows never go back in time, so the first segment that ends at or after `real` is found by halving.
  let low = 0;
  let high = segments.length;
  while (low < high) {
    const middle = (low + high) >> 1;
    const item = segments[middle];
    if (item && item.realEnd < real) low = middle + 1;
    else high = middle;
  }
  const segment = segments[low];
  if (!segment) return timeline.duration;
  if (real >= segment.realStart) return placeInBody(segment, real);
  const before = segments[segment.index - 1];
  if (!before) return segment.bodyStart;
  const silence = segment.realStart - before.realEnd;
  const beat = segment.start - before.end;
  return silence <= 0 ? segment.start : before.end + (beat * (real - before.realEnd)) / silence;
}

/** The screen time of a step at position `at` inside its segment (0 its start, 1 its end). Null when no step has that id. */
export function seekStep(timeline: Timeline, stepId: string, at = 0.6): number | null {
  const segment = timeline.segments.find((item) => item.step.id === stepId);
  if (!segment) return null;
  const position = Number.isFinite(at) ? Math.min(1, Math.max(0, at)) : 0;
  return segment.start + (segment.end - segment.start) * position;
}

/**
 * The scrubber gives every step one even slot, so the strip reads as a rhythm
 * of steps whatever their length. A slot runs from its step's start to the next
 * step's start; inside it, screen time runs linearly. Positions are 0 to 1.
 */
export function evenPosition(timeline: Timeline, screen: number): number {
  const count = timeline.segments.length;
  const t = clampScreen(timeline, screen);
  const index = segmentIndexAt(timeline, t);
  const segment = timeline.segments[index];
  if (count === 0 || !segment) return 0;
  const end = timeline.segments[index + 1]?.start ?? timeline.duration;
  const fraction = end > segment.start ? Math.min(1, Math.max(0, (t - segment.start) / (end - segment.start))) : 0;
  return (index + fraction) / count;
}

/** The screen time at an even position of the scrubber: the inverse of `evenPosition`. */
export function evenTime(timeline: Timeline, position: number): number {
  const count = timeline.segments.length;
  if (count === 0) return 0;
  const place = (Number.isFinite(position) ? Math.min(1, Math.max(0, position)) : 0) * count;
  const index = Math.min(count - 1, Math.floor(place));
  const segment = timeline.segments[index];
  if (!segment) return 0;
  const end = timeline.segments[index + 1]?.start ?? timeline.duration;
  return segment.start + (end - segment.start) * Math.min(1, place - index);
}

export interface ScoreSoFar {
  /** Steps of role `test` whose segment has ended. */
  testsDone: number;
  /** Of steps of role `test` that took effect: alerted from the first counting alert of a published rule, seen and unseen once the step has ended. */
  alerted: number;
  seen: number;
  unseen: number;
  /** The same count of alerted tests when the accepted rules written in this repository count too. Null when the run did not evaluate such rules. */
  alertedWithLabRules: number | null;
  /** Steps of any role with outcome `stopped` that have ended. */
  stopped: number;
}

export interface RaceSoFar {
  /** Steps of role `test` that have begun. */
  testsRun: number;
  /** Steps of role `test` in the recording. */
  testsTotal: number;
  /** The first alert on a test, once playback has reached it. */
  firstAlert: FirstAlert | null;
  firstAlertWithLabRules: FirstAlert | null;
}

export interface Frame {
  /** The screen time, held inside the playback. */
  time: number;
  /** The real clock time shown, in ms. */
  real: number;
  /** The current segment: the last one that has begun. Null for a recording without steps. */
  segment: Segment | null;
  step: Step | null;
  /** How far through its segment playback is, from 0 to 1. */
  progress: number;
  /** True while the step is told and its real window has not started playing. */
  inLead: boolean;
  /** The silence playback is in after the current step, if any. */
  gap: Gap | null;
  /** The current step's events that have arrived, in arrival order. */
  events: RecordingEvent[];
  /** The current step's matches (of any level and origin) that have fired, in firing order. */
  alerts: Alert[];
  score: ScoreSoFar;
  race: RaceSoFar;
  /** True at the end of playback. */
  ended: boolean;
}

/** The score so far at screen time `screen`: one pass over the steps that have begun, with each step's first alert looked up. */
export function scoreAt(timeline: Timeline, screen: number): ScoreSoFar {
  const t = clampScreen(timeline, screen);
  const score: ScoreSoFar = { testsDone: 0, alerted: 0, seen: 0, unseen: 0, alertedWithLabRules: timeline.withLabRules ? 0 : null, stopped: 0 };
  for (const segment of timeline.segments) {
    if (segment.start > t) break;
    const step = segment.step;
    const done = t >= segment.end;
    if (done && step.outcome === "stopped") score.stopped += 1;
    if (step.role !== "test") continue;
    if (done) score.testsDone += 1;
    if (step.happened.answer !== "took effect") continue;
    const own = timeline.byStep.get(step.id);
    // An alerted test counts from its first counting alert; one raised live
    // after the step ended counts only from then.
    if (step.outcome === "alerted" && t >= (own?.firstCounting?.at ?? segment.end)) score.alerted += 1;
    else if (done && step.outcome === "seen") score.seen += 1;
    else if (done && step.outcome === "unseen") score.unseen += 1;
    if (score.alertedWithLabRules !== null && step.outcome_with_lab_rules === "alerted") {
      if (t >= (own?.firstCountingWithLabRules?.at ?? segment.end)) score.alertedWithLabRules += 1;
    }
  }
  return score;
}

/** The race so far at screen time `screen`. */
export function raceAt(timeline: Timeline, screen: number): RaceSoFar {
  const t = clampScreen(timeline, screen);
  const tests = timeline.tests;
  return {
    testsRun: countBegun(tests, t),
    testsTotal: tests.length,
    firstAlert: timeline.firstAlert && timeline.firstAlert.at <= t ? timeline.firstAlert : null,
    firstAlertWithLabRules: timeline.firstAlertWithLabRules && timeline.firstAlertWithLabRules.at <= t ? timeline.firstAlertWithLabRules : null,
  };
}

/** What is on screen at screen time `screen`. */
export function frameAt(timeline: Timeline, screen: number): Frame {
  const t = clampScreen(timeline, screen);
  const segment = timeline.segments[segmentIndexAt(timeline, t)] ?? null;
  const length = segment ? segment.end - segment.start : 0;
  const progress = segment ? (length > 0 ? Math.min(1, (t - segment.start) / length) : 1) : 0;
  const next = segment && t > segment.end ? timeline.gaps[segment.index] : undefined;
  const gap = next && segment && next.after === segment.index ? next : null;
  const own = segment ? timeline.byStep.get(segment.step.id) : undefined;
  return {
    time: t,
    real: screenToReal(timeline, t),
    segment,
    step: segment ? segment.step : null,
    progress,
    inLead: segment !== null && t < segment.bodyStart,
    gap,
    events: own ? cutEvents(own.arrivals, countUpTo(own.arrivals, t)) : [],
    alerts: own ? cutAlerts(own.fires, countUpTo(own.fires, t)) : [],
    score: scoreAt(timeline, t),
    race: raceAt(timeline, t),
    ended: t >= timeline.duration,
  };
}
