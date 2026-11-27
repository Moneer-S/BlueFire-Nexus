// One run judged by several defenses. Each defense is a validated view of the
// same recording; this module derives those views and the comparison shown by
// the live view. It is pure and imports nothing from the rest of the app.

import type { Defense, Network, Outcome, Recording } from "./recording";
import { defensesOf, judgedBy } from "./recording";
import { buildTimeline, frameAt, outcomeAt } from "./playback";
import type { Timeline } from "./playback";
import { firstAlertClock, firstAlertOnScreen, momentOf, runFacts, scoreOnScreen, stepMatches } from "./moment";
import type { RunFacts } from "./moment";
import { span, stepLabel } from "./format";
import { hintStage, markQuietSensors } from "./networkLayout";

export interface Judged {
  defense: Defense;
  index: number;
  view: Recording;
  timeline: Timeline;
  facts: RunFacts;
  stage: Network;
  made: string;
  when: string;
}

/** Every defense of a recording judged by two or more. */
export function judgeAll(recording: Recording): Judged[] {
  const defenses = defensesOf(recording);
  if (defenses.length < 2) return [];
  const engines = defenses.map((defense) => new Set(defense.detectors).size);
  const list = defenses.map((defense) => defense.name);
  return defenses.map((defense, index) => {
    const view = judgedBy(recording, defense.id);
    const timeline = buildTimeline(view);
    const stage: Network = { ...recording.network, detectors: view.network.detectors };
    markQuietSensors(stage);
    hintStage(stage, { engines, list });
    const after = view.network.detectors.length > 0 && view.network.detectors.every((detector) => detector.when === "after the run");
    const when = view.network.detectors.length === 0 ? "Recorded the events; no rule set ran" : after ? "Judged the recorded events after the run" : "Judged the events as they arrived";
    return {
      defense,
      index,
      view,
      timeline,
      facts: runFacts(view, timeline),
      stage,
      made: madeOf(view.network),
      when,
    };
  });
}

/** The same step and real clock in another defense's timeline. */
export function sameMoment(from: Timeline, to: Timeline, time: number): number {
  const frame = frameAt(from, time);
  const source = frame.segment;
  if (!source) return 0;
  if (frame.ended) return to.duration;
  const target = to.segments[source.index];
  if (!target) return 0;
  const share = (value: number, low: number, high: number): number => (high > low ? Math.min(1, Math.max(0, (value - low) / (high - low))) : 1);
  if (frame.time <= source.bodyStart) return target.start + (target.bodyStart - target.start) * share(frame.time, source.start, source.bodyStart);
  if (frame.time <= source.bodyEnd) {
    const realLength = target.realEnd - target.realStart;
    return realLength > 0 ? target.bodyStart + (target.bodyEnd - target.bodyStart) * Math.min(1, Math.max(0, (frame.real - target.realStart) / realLength)) : target.bodyStart;
  }
  if (frame.time <= source.end) return target.bodyEnd + (target.end - target.bodyEnd) * share(frame.time, source.bodyEnd, source.end);
  const sourceGap = frame.gap;
  const targetGap = to.gaps.find((gap) => gap.after === source.index);
  if (!sourceGap || !targetGap) return target.end;
  return targetGap.start + (targetGap.end - targetGap.start) * Math.min(0.999, share(frame.time, sourceGap.start, sourceGap.end));
}

export interface Tally {
  id: string;
  name: string;
  key: number;
  alerted: number;
  seen: number;
  unseen: number;
  steps: (Outcome | "running" | null)[];
  firstAlert: { seconds: number | null; step: string; real: number } | null;
  falseAlerts: number | null | undefined;
  final: boolean;
  goalSeconds: number | undefined;
  made: string;
  when: string;
}

const NO_MATCHES = stepMatches([]);

/** A defense's sensors and rule sets in one sentence for its accessible name. */
function madeOf(network: Network): string {
  const hostName = (id: string): string => network.hosts.find((host) => host.id === id)?.name ?? id;
  const groups = new Map<string, string[]>();
  for (const sensor of network.sensors) groups.set(sensor.name, [...(groups.get(sensor.name) ?? []), hostName(sensor.host)]);
  const list = (items: string[]): string => (items.length > 1 ? `${items.slice(0, -1).join(", ")} and ${items[items.length - 1] ?? ""}` : (items[0] ?? ""));
  const sensors = [...groups].map(([name, hosts]) => `${name} on ${list(hosts)}`).join("; ");
  const rules = network.detectors.map((detector) => `${detector.name} (${detector.when === "live" ? "live" : "after the run"})`).join("; ");
  return `Records with ${sensors}. Rule sets: ${rules || "none"}.`;
}

/** What a defense had concluded by a moment, or of the whole run in Analyse. */
export function tallyOf(judged: Judged, time: number, analyse: boolean): Tally {
  const { view, timeline, facts, defense } = judged;
  const base = {
    id: defense.id,
    name: defense.name,
    key: judged.index + 1,
    goalSeconds: view.score.goal_seconds,
    made: judged.made,
    when: judged.when,
  };
  const counted = view.ordinary !== undefined && view.score.false_alerts !== undefined;
  const clock = (first: NonNullable<Timeline["firstAlert"]>) => ({
    seconds: firstAlertClock(view, facts, first)?.seconds ?? null,
    step: stepLabel(view, first.step),
    real: first.real,
  });
  if (analyse) {
    const outcomes = view.steps.map((step) => step.outcome);
    const first = timeline.firstAlert;
    return {
      ...base,
      alerted: outcomes.filter((outcome) => outcome === "alerted").length,
      seen: outcomes.filter((outcome) => outcome === "seen").length,
      unseen: outcomes.filter((outcome) => outcome === "unseen").length,
      steps: outcomes,
      firstAlert: first ? clock(first) : null,
      falseAlerts: counted ? view.score.false_alerts : undefined,
      final: true,
    };
  }
  const frame = frameAt(timeline, time);
  const moment = momentOf(timeline, frame, NO_MATCHES);
  const score = scoreOnScreen(timeline, frame, moment);
  const current = frame.segment?.index ?? -1;
  const revealed = moment?.revealed ?? false;
  const first = firstAlertOnScreen(frame.race.firstAlert, frame.time, frame.segment, revealed);
  return {
    ...base,
    alerted: score.alerted,
    seen: score.seen,
    unseen: score.unseen,
    steps: timeline.segments.map((segment, index) => (frame.ended || index < current || (index === current && revealed) ? outcomeAt(timeline, segment, frame.time) : index === current ? "running" : null)),
    firstAlert: first ? clock(first) : null,
    falseAlerts: counted ? (frame.ended ? view.score.false_alerts : null) : undefined,
    final: frame.ended,
  };
}

/** A defense's first alert set against the goal, in the product's plain words. */
export function firstAlertWords(tally: Tally, elapsedOf: (seconds: number) => string, goalTold: boolean): { when: string; against: string } {
  const first = tally.firstAlert;
  const goal = goalTold ? tally.goalSeconds : undefined;
  if (!first) return { when: tally.final ? "no alert" : "no alert yet", against: goal !== undefined && tally.final ? "the goal was reached with none" : "" };
  const when = first.seconds === null ? `on ${first.step}` : `${elapsedOf(first.seconds)} on ${first.step}`;
  if (goal === undefined || first.seconds === null) return { when, against: "" };
  const gap = span(Math.abs(goal - first.seconds) * 1000);
  return { when, against: first.seconds <= goal ? `${gap} before the goal` : `${gap} after the goal` };
}
