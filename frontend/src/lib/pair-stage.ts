// What one recording holds of one step, as the two stages of a pair's page draw
// it: the host, its sensors with the events each recorded of the step, and the
// rule engines with what each matched. Read from the recording and nothing else:
// the two stages are two readings set side by side, never a difference worked
// out between them.

import { countsAsAlert, countsForScore, type Alert, type Outcome, type Recording, type RecordingEvent, type Step } from "../live/recording";
import { capital, isLabDetector, launcherRules, outcomeWords, plural, sensorColours, sensorShortName } from "../live/format";

/** What a rule engine made of the step: an alert of a published rule, an alert of the lab's own rules, a match below alert level, or nothing. */
export type EngineState = "alert" | "lab" | "review" | "none";

export interface StageSensor {
  id: string;
  name: string;
  rgb: string;
  events: number;
}

export interface StageMatch {
  id: string;
  rule: string;
  title: string;
  level: string;
  state: Exclude<EngineState, "none">;
}

export interface StageEngine {
  id: string;
  name: string;
  lab: boolean;
  state: EngineState;
  matches: StageMatch[];
  /** How many published rules of the engine matched only the launcher line: not drawn, and named in words. */
  launcher: number;
}

export interface StageSide {
  step: Step;
  host: string;
  outcome: Outcome;
  sensors: StageSensor[];
  engines: StageEngine[];
  events: RecordingEvent[];
  alerts: Alert[];
  /** How many published rules matched only the step's launcher line, which never counts. */
  launcher: number;
}

const RANK: Record<EngineState, number> = { none: 0, review: 1, lab: 2, alert: 3 };

function matchState(alert: Alert): Exclude<EngineState, "none"> {
  if (countsForScore(alert)) return "alert";
  if (countsAsAlert(alert)) return "lab";
  return "review";
}

/** An engine's name on a stage: the lab's own rules, or the published ones. */
function engineName(recording: Recording, id: string, name: string): string {
  if (isLabDetector(recording, id)) return "The lab's rules";
  if (id === "pinned") return "Published rules";
  const cut = name.indexOf(" with ");
  return cut > 0 ? name.slice(0, cut) : name;
}

/** The step as one recording holds it, with what was drawn of it; null when the recording has no such step. */
export function stageSide(recording: Recording, stepId: string): StageSide | null {
  const step = recording.steps.find((item) => item.id === stepId);
  if (!step) return null;
  const events = recording.events.filter((event) => event.step === stepId);
  // A match on the launcher line alone is not drawn on a stage: it says nothing of what the test did. The words name it.
  const own = recording.alerts.filter((alert) => alert.step === stepId);
  const alerts = own.filter((alert) => alert.launcher_only !== true);
  const colours = sensorColours(recording.network.sensors);
  const sensors = recording.network.sensors
    .filter((sensor) => sensor.host === step.host)
    .map((sensor) => ({ id: sensor.id, name: sensorShortName(sensor.name), rgb: colours.get(sensor.id) ?? "123,202,255", events: events.filter((event) => event.sensor === sensor.id).length }));
  const engines = recording.network.detectors.map((detector) => {
    const matches = alerts.filter((alert) => alert.detector === detector.id).map((alert) => ({ id: alert.id, rule: alert.rule.id, title: alert.rule.title, level: alert.rule.level, state: matchState(alert) }));
    const state = matches.reduce<EngineState>((best, match) => (RANK[match.state] > RANK[best] ? match.state : best), "none");
    const launcher = launcherRules(own.filter((alert) => alert.detector === detector.id));
    return { id: detector.id, name: engineName(recording, detector.id, detector.name), lab: isLabDetector(recording, detector.id), state, matches, launcher };
  });
  const host = recording.network.hosts.find((item) => item.id === step.host)?.name ?? step.host;
  return { step, host, outcome: step.outcome_with_lab_rules ?? step.outcome, sensors, engines, events, alerts, launcher: launcherRules(own) };
}

/** The sensors and engines that read the same on both stages, drawn dim: the same number of events, the same rules matched. */
export function sameOnBoth(before: StageSide, after: StageSide): { sensors: Set<string>; engines: Set<string> } {
  const sensors = new Set<string>();
  const engines = new Set<string>();
  for (const sensor of after.sensors) {
    const was = before.sensors.find((item) => item.id === sensor.id);
    if (was && was.events === sensor.events) sensors.add(sensor.id);
  }
  const rules = (engine: StageEngine) => engine.matches.map((match) => `${match.rule}:${match.state}`).sort().join(",");
  for (const engine of after.engines) {
    const was = before.engines.find((item) => item.id === engine.id);
    if (was && was.state === engine.state && was.launcher === engine.launcher && rules(was) === rules(engine)) engines.add(engine.id);
  }
  return { sensors, engines };
}

/**
 * What a stage says under its drawing, in one or two short sentences, from
 * the recording's own fields. `newRules` are the rules the change brought in.
 */
export function stageSentence(side: StageSide, newRules: ReadonlySet<string> = new Set()): string {
  const outcome = side.outcome;
  if (outcome === "unseen") return `${capital(side.step.visibility.basis)}.`;
  if (outcome === "stopped") return `Stopped: ${side.step.happened.basis}.`;
  const recorded = side.sensors.filter((sensor) => sensor.events > 0).map((sensor) => `${sensor.name} recorded ${plural(sensor.events, "event")}`);
  // A sensor's name keeps its own case: "auditd recorded 1 event."
  const lead = recorded.length ? `${recorded.join(", ")}.` : "";
  const matches = side.engines.flatMap((engine) => engine.matches);
  if (outcome === "alerted") {
    const alert = matches.find((match) => match.state === "alert") ?? matches.find((match) => match.state === "lab");
    if (!alert) return lead;
    if (alert.state === "alert") return `${lead} A published rule raised an alert: ${alert.title} (${alert.level}).`.trim();
    const who = newRules.has(alert.rule) ? "The new rule" : "One of the lab's own rules";
    return `${lead} ${who} alerted, which the score does not count: ${alert.title} (${alert.level}).`.trim();
  }
  if (outcome === "seen") {
    const review = matches.find((match) => match.state === "review");
    // As the step's sentence in the live view words it.
    if (!review && side.launcher > 0) return `${lead} ${capital(plural(side.launcher, "rule"))} matched only the launcher line, which never counts.`.trim();
    if (!review) return `${lead} No rule matched it.`.trim();
    return `${lead} No alert: ${review.title} matched at level ${review.level}, below the alert level.`.trim();
  }
  return `${capital(outcomeWords(outcome))}.`;
}
