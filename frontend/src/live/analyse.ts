// What analyse mode needs about every step, worked out once: pure, no React.

import type { Alert, Outcome, Recording, RecordingEvent, Step, StepRole } from "./recording";
import { alertsByStep, countsAsAlert, countsForScore, eventsByStep } from "./recording";
import { plural, stepLabel } from "./format";
import { stepEnd, stepMatchesInFiringOrder } from "./playback";
import type { Timeline } from "./playback";

/** The matches of one step, published and lab rules apart, alert and review apart, the launcher line named. */
export interface MatchGroups {
  /** Published rules at alert level: they make the score. */
  alert: Alert[];
  /** Published rules below alert level. */
  review: Alert[];
  /** Rules written in this repository at alert level: never in the score. */
  labAlert: Alert[];
  /** Rules written in this repository below alert level. */
  labReview: Alert[];
  /** Matches of the one shell command that carried the test: they never count. */
  launcher: Alert[];
}

export function groupMatches(alerts: readonly Alert[]): MatchGroups {
  const groups: MatchGroups = { alert: [], review: [], labAlert: [], labReview: [], launcher: [] };
  for (const alert of alerts) {
    if (alert.launcher_only === true) groups.launcher.push(alert);
    else if (countsForScore(alert)) groups.alert.push(alert);
    else if (countsAsAlert(alert)) groups.labAlert.push(alert);
    else if (alert.rule.origin === "lab") groups.labReview.push(alert);
    else groups.review.push(alert);
  }
  return groups;
}

/** One row of the table of every step. */
export interface StepRow {
  step: Step;
  /** The step's place in `recording.steps`. */
  index: number;
  /** The events the recording keeps for the step. */
  events: RecordingEvent[];
  /** Kept events by sensor id. */
  bySensor: Map<string, number>;
  /** Events the sensors recorded for the step, which can be more than the recording keeps. Null when the engine could not tie events to it. */
  recorded: number | null;
  matches: MatchGroups;
  /** When the step ended, as playback and the watch view read it (`stepEnd`): a match raised live after it is late. Null for a step with no time. */
  end: number | null;
}

/** Every step's row. Its matches are in the order playback fires them, so a step's first alert here is the one the watch view names. */
export function stepRows(recording: Recording, timeline: Timeline): StepRow[] {
  const events = eventsByStep(recording);
  return recording.steps.map((step, index) => {
    const own = events.get(step.id) ?? [];
    const bySensor = new Map<string, number>();
    for (const event of own) bySensor.set(event.sensor, (bySensor.get(event.sensor) ?? 0) + 1);
    const segment = timeline.segments[index];
    return {
      step,
      index,
      events: own,
      bySensor,
      recorded: step.visibility.events ?? null,
      matches: groupMatches(stepMatchesInFiringOrder(timeline, step.id)),
      end: segment && segment.step.id === step.id ? stepEnd(segment) : null,
    };
  });
}

/** What needs work first: the step nobody saw, then the ones that alerted, then the long list seen with no alert. */
export const OUTCOME_ORDER: readonly Outcome[] = ["unseen", "alerted", "seen", "stopped", "no effect", "inconclusive"];
export const ROLE_ORDER: readonly StepRole[] = ["test", "canary", "control", "hardened", "variant"];

export type SortKey = "order" | "outcome" | "title" | "technique" | "events" | "matches";

function matchWeight(row: StepRow): number {
  const m = row.matches;
  return m.alert.length * 1e6 + m.labAlert.length * 1e4 + (m.review.length + m.labReview.length) * 1e2 + m.launcher.length;
}

function sortValue(row: StepRow, key: SortKey): number | string {
  switch (key) {
    case "order":
      return row.step.order;
    case "outcome":
      return OUTCOME_ORDER.indexOf(row.step.outcome);
    case "title":
      return row.step.title.toLowerCase();
    case "technique":
      return row.step.technique.id;
    case "events":
      return row.recorded ?? row.events.length;
    case "matches":
      return matchWeight(row);
  }
}

/** The rows of one role (or every role) and one outcome (or every outcome), sorted; ties keep the run's order. */
export function tableRows(rows: readonly StepRow[], filter: { role: StepRole | "all"; outcome: Outcome | null }, sort: { key: SortKey; ascending: boolean }): StepRow[] {
  const chosen = rows.filter((row) => (filter.role === "all" || row.step.role === filter.role) && (filter.outcome === null || row.step.outcome === filter.outcome));
  const direction = sort.ascending ? 1 : -1;
  return chosen.sort((a, b) => {
    const x = sortValue(a, sort.key);
    const y = sortValue(b, sort.key);
    if (x < y) return -direction;
    if (x > y) return direction;
    return a.index - b.index;
  });
}

/** A run of consecutive steps of the same role, such as "60 tests" or "12 hardened reruns". */
export interface RoleRun {
  role: StepRole;
  first: number;
  last: number;
  count: number;
}

export function roleRuns(steps: readonly Step[]): RoleRun[] {
  const runs: RoleRun[] = [];
  steps.forEach((step, index) => {
    const last = runs[runs.length - 1];
    if (last && last.role === step.role) {
      last.last = index;
      last.count += 1;
    } else {
      runs.push({ role: step.role, first: index, last: index, count: 1 });
    }
  });
  return runs;
}

const ROLE_PLURAL: Record<StepRole, [string, string]> = {
  test: ["test", "tests"],
  canary: ["canary", "canaries"],
  control: ["control", "controls"],
  hardened: ["hardened rerun", "hardened reruns"],
  variant: ["variant", "variants"],
};

export function roleCount(role: StepRole, count: number): string {
  const [one, many] = ROLE_PLURAL[role];
  return plural(count, one, many);
}

/** The other runs of the same technique: tests first, then the rest, each in run order. */
export function otherRuns(recording: Recording, step: Step): Step[] {
  return recording.steps
    .filter((other) => other.id !== step.id && other.technique.id === step.technique.id)
    .sort((a, b) => (a.role === "test" ? 0 : 1) - (b.role === "test" ? 0 : 1) || a.order - b.order);
}

/**
 * The tests seen with no alert, split by what the published rules made of
 * them: a match for review, a match on the launcher line only, or nothing.
 * The last are the furthest from an alert.
 */
export function seenBreakdown(recording: Recording): { total: number; review: number; launcher: number; none: number } {
  const alerts = alertsByStep(recording);
  const result = { total: 0, review: 0, launcher: 0, none: 0 };
  for (const step of recording.steps) {
    if (step.role !== "test" || step.outcome !== "seen") continue;
    const groups = groupMatches(alerts.get(step.id) ?? []);
    result.total += 1;
    if (groups.review.length > 0) result.review += 1;
    else if (groups.launcher.some((alert) => alert.rule.origin === "pinned")) result.launcher += 1;
    else result.none += 1;
  }
  return result;
}

const LEVEL_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, informational: 0 };

/** How many events of ordinary activity a published rule matched, or null when the recording says nothing of ordinary activity. */
export function ordinaryMatches(recording: Recording, ruleTitle: string): number | null {
  if (!recording.ordinary) return null;
  return recording.ordinary.matches.filter((match) => match.rule === ruleTitle).reduce((sum, match) => sum + match.count, 0);
}

/**
 * Where the gap is, for a step that got through without an alert. Null when
 * there is nothing to fix. For a step nobody saw, the hint names the other
 * runs of the same technique that a sensor did record. When published rules
 * already matched a seen step below alert level, it names the one to start
 * from: the highest level, and of those the quietest on ordinary activity.
 */
export function fixHint(recording: Recording, step: Step, matches?: MatchGroups): string | null {
  if (step.role === "canary" || step.role === "control") return null;
  if (step.outcome === "unseen") {
    // The runs that alerted first: they show which telemetry already catches the technique.
    const recorded = otherRuns(recording, step)
      .filter((other) => other.outcome === "alerted" || other.outcome === "seen")
      .sort((a, b) => Number(b.outcome === "alerted") - Number(a.outcome === "alerted") || a.order - b.order);
    if (recorded.length === 0) return "No sensor recorded it: start with a sensor.";
    const named = recorded.slice(0, 3).map((other) => `${stepLabel(recording, other)} ${other.outcome === "seen" ? "seen" : "alerted"}`);
    const more = recorded.length > 3 ? ` and ${recorded.length - 3} more` : "";
    return `Start with a sensor: other runs of ${step.technique.id} were recorded (${named.join(", ")}${more}).`;
  }
  if (step.outcome !== "seen") return null;
  const rules = new Map<string, Alert>();
  for (const alert of matches?.review ?? []) if (!rules.has(alert.rule.id)) rules.set(alert.rule.id, alert);
  const quiet = (alert: Alert) => ordinaryMatches(recording, alert.rule.title) ?? 0;
  const top = [...rules.values()].sort((a, b) => (LEVEL_RANK[b.rule.level] ?? 0) - (LEVEL_RANK[a.rule.level] ?? 0) || quiet(a) - quiet(b))[0];
  if (!top) return "Recorded, no rule at alert level: start with a rule.";
  const ordinary = ordinaryMatches(recording, top.rule.title);
  const noise = ordinary === null ? "" : ordinary === 0 ? ", and nothing in ordinary activity" : `, and ${plural(ordinary, "ordinary event")}`;
  return `Start with a rule: ${top.rule.title} (${top.rule.level}) matched it below alert level${noise}.`;
}
