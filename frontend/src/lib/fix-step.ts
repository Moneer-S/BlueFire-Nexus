// What the page for fixing a step decides, from the step's recording and the
// comparisons the service keeps, and nothing else: where to start, what the
// recording holds of the step and of its sensors, what was already tried, and
// the fixed words of the model's place. Nothing here guesses a rule or reads
// the repository: the change itself is a file there, run by its CI.

import type { MatchGroups, StepRow } from "../live/analyse";
import { ordinaryMatches, otherRuns } from "../live/analyse";
import { sensorLabel, sensorShortName } from "../live/format";
import type { Alert, Recording, RecordingEvent, Rule, RuleVerdict, Step } from "../live/recording";
import type { CatalogResponse } from "../types";
import type { Delta, DeltaSide, DeltaStep, DeltaSummary } from "./api";
import { momentSearch, pairsInOrder, recordedRunPath } from "./recorded-runs";
import { movedSteps, pairPath } from "./recording-pairs";

/** The page for fixing one step of a recording: of its first file, or of the file with `sha256`. */
export function fixPath(recordingId: string, file: string | undefined, stepId: string): string {
  return `${recordedRunPath(recordingId, file)}/fix/${encodeURIComponent(stepId)}`;
}

/** The moment that opens a step in analyse mode, paused at its start, where its detail offers "Fix this". */
export function stepMoment(stepId: string): URLSearchParams {
  return momentSearch({ step: stepId, at: 0, paused: true, mode: "analyse", select: stepId });
}

/**
 * Back to the moment the reader came from: the fix page's address carries it.
 * Opened from a link with none, back to the step's detail in analyse mode.
 */
export function backPath(recordingId: string, file: string | undefined, stepId: string, search: URLSearchParams): string {
  const moment = search.toString() ? search : stepMoment(stepId);
  return `${recordedRunPath(recordingId, file)}?${moment.toString()}`;
}

/** One rule that matched the step, with every match of it, and what the recording says of it. */
export interface RuleMatch {
  rule: Rule;
  alerts: Alert[];
  /** For a rule of the lab's own: how this run judged it, when the recording says so. */
  verdict?: RuleVerdict;
  /** For a published rule: how many events of ordinary activity it matched, or null when the recording does not say. */
  ordinary?: number | null;
}

/** Matches grouped by rule, in the order their first match comes. */
function byRule(recording: Recording, alerts: readonly Alert[]): RuleMatch[] {
  const verdicts = labVerdicts(recording);
  const found = new Map<string, RuleMatch>();
  for (const alert of alerts) {
    const key = `${alert.rule.origin}:${alert.rule.id}`;
    const entry = found.get(key);
    if (entry) {
      entry.alerts.push(alert);
      continue;
    }
    const verdict = alert.rule.origin === "lab" ? verdicts.find((item) => item.rule === alert.rule.id) : undefined;
    found.set(key, {
      rule: alert.rule,
      alerts: [alert],
      ...(verdict ? { verdict } : {}),
      ...(alert.rule.origin === "pinned" ? { ordinary: ordinaryMatches(recording, alert.rule.title) } : {}),
    });
  }
  return [...found.values()];
}

/** How the run judged each rule of the lab's own, as its detector `lab` says. Empty when the recording does not say. */
export function labVerdicts(recording: Recording): RuleVerdict[] {
  return recording.network.detectors.find((detector) => detector.id === "lab")?.verdicts ?? [];
}

/**
 * How the run judged the lab's own rules, in the one note the lab writes of
 * them ("The run accepted 8 of the 9 rules written in this repository. ..."),
 * for a recording whose detector `lab` carries no verdicts: an older one says
 * it only there. Returned whole, never taken apart; null when the recording
 * carries verdicts or holds no such note.
 */
export function labRulesNote(recording: Recording): string | null {
  if (labVerdicts(recording).length > 0) return null;
  return recording.notes.find((note) => note.startsWith("The run accepted ")) ?? null;
}

/** The commit the run loaded the lab's own rules from: the detector `lab`'s own, or the defense's, or null when the recording names neither. */
export function labRulesCommit(recording: Recording): string | null {
  return recording.network.detectors.find((detector) => detector.id === "lab")?.commit ?? recording.source.defense_commit ?? null;
}

/**
 * Where the defense of a recording's run is set, which decides where a fix is
 * made. A range runs its defense on a host of its own network, its manager, and
 * is built from a spec under `lab/range/`; the lab's one host has no such host,
 * and its sensors' settings and rules are files under `lab/sensors/` and
 * `lab/rules/linux/`.
 */
export type DefenseHome =
  | { kind: "lab" }
  | {
      kind: "range";
      /** The name of the host that runs the range's rules. */
      manager: string;
      /** The sensors' names, each once, without their versions: "Wazuh agent". */
      sensors: string[];
      /** The rules that ran, in the recording's words, or null when it names none. */
      rules: string | null;
    };

export function defenseHome(recording: Recording): DefenseHome {
  const manager = recording.network.hosts.find((host) => host.kind === "defense");
  if (!manager) return { kind: "lab" };
  return {
    kind: "range",
    manager: manager.name,
    sensors: [...new Set(recording.network.sensors.map((sensor) => sensorShortName(sensor.name)))],
    rules: recording.network.detectors.find((detector) => detector.id === "pinned")?.name ?? null,
  };
}

/** The rules of the lab's own that this run did not accept: their matches are not in the recording. */
export function notAccepted(recording: Recording): RuleVerdict[] {
  return labVerdicts(recording).filter((verdict) => !verdict.accepted);
}

/**
 * Where a fix starts, by what the recording holds of the step and nothing else:
 * - `sensor`: nothing of the step itself was recorded, so no rule can help
 *   before a sensor's settings change;
 * - `rule`: it was recorded and nothing alerted: a rule is the next move, and
 *   these are the rules that matched it below alert level;
 * - `lab alerted`: no published rule alerted, and a rule of the lab's own did;
 * - `alerted`: a published rule alerted;
 * - `nothing`: there is no gap to fix, and why.
 * Each kind that names rules names every rule that matched the step: the one
 * that alerted, the lab's own rules besides it, the published ones below alert level,
 * and those that matched only the launcher line.
 */
export type StartWith =
  | { kind: "sensor"; basis: string; launcher: boolean }
  | { kind: "rule"; review: RuleMatch[]; lab: RuleMatch[]; launcher: RuleMatch[] }
  | { kind: "lab alerted"; alerted: RuleMatch[]; lab: RuleMatch[]; review: RuleMatch[]; launcher: RuleMatch[] }
  | { kind: "alerted"; alerted: RuleMatch[]; lab: RuleMatch[]; review: RuleMatch[]; launcher: RuleMatch[] }
  | { kind: "nothing"; why: string };

export function startWith(recording: Recording, step: Step, matches: MatchGroups): StartWith {
  if (step.role === "canary") return { kind: "nothing", why: "A canary is a step the defenses are known to catch, run to show that the sensors and rules work. It is not a gap to fix." };
  if (step.role === "control") return { kind: "nothing", why: "A control is a step that must raise no alert. It is not a gap to fix." };
  if (step.outcome === "unseen") {
    // The recording's own words for why nothing counts as recorded; the launcher, when it says so, is the lab's own harness.
    return { kind: "sensor", basis: step.visibility.basis, launcher: /\blauncher\b/.test(step.visibility.basis) };
  }
  const below = { review: byRule(recording, matches.review), launcher: byRule(recording, matches.launcher) };
  if (step.outcome === "alerted") return { kind: "alerted", alerted: byRule(recording, matches.alert), lab: byRule(recording, [...matches.labAlert, ...matches.labReview]), ...below };
  if (step.outcome === "seen" && step.outcome_with_lab_rules === "alerted") {
    return { kind: "lab alerted", alerted: byRule(recording, matches.labAlert), lab: byRule(recording, matches.labReview), ...below };
  }
  if (step.outcome === "seen") {
    return { kind: "rule", ...below, lab: byRule(recording, matches.labReview) };
  }
  if (step.outcome === "stopped") return { kind: "nothing", why: `The defense stopped it: ${step.happened.basis}.` };
  if (step.outcome === "no effect") return { kind: "nothing", why: `It did not take effect: ${step.happened.basis}.` };
  return { kind: "nothing", why: `The recording cannot say how it went: ${step.visibility.basis}.` };
}

/** A sensor that watched or recorded the step: what the recording says of it and of its settings, and what it recorded of the step. */
export interface SensorFacts {
  id: string;
  /** Its name without its version, and its host when another sensor shares the name: "Wazuh agent on web". */
  name: string;
  version: string | null;
  records: string;
  /** The SHA-256 of its settings as it loaded them, from `source.setup`, or null when the recording does not say. */
  settings: string | null;
  /** On auditd: what its rules watched under each audit key, or null when the recording does not say. */
  watches: { key: string; rules: string[] }[] | null;
  events: RecordingEvent[];
}

/**
 * The sensors that watched the step's host or recorded any of its events, in
 * the recording's order, each with the step's events it recorded. In a range a
 * step can be recorded by the agent of the host it ran from, not of its target.
 */
export function sensorsOf(recording: Recording, row: Pick<StepRow, "step" | "events">): SensorFacts[] {
  const settings = recording.source.setup?.sensors;
  return recording.network.sensors
    .filter((sensor) => sensor.host === row.step.host || row.events.some((event) => event.sensor === sensor.id))
    .map((sensor) => {
      const name = sensorShortName(sensor.name);
      const tool = recording.source.tools.find((item) => item.role === "sensor" && item.name === name);
      const rest = sensor.name.slice(name.length).trim();
      const digest = typeof settings === "object" ? settings[sensor.id] : undefined;
      return {
        id: sensor.id,
        name: sensorLabel(recording, sensor),
        version: tool?.version ?? (rest || null),
        records: sensor.records,
        settings: digest ?? null,
        watches: sensor.audit_watches ? Object.entries(sensor.audit_watches).map(([key, rules]) => ({ key, rules })) : null,
        events: row.events.filter((event) => event.sensor === sensor.id),
      };
    });
}

/** The other runs of the step's technique in this recording, tests first, each with what a sensor recorded of it. */
export function otherRunsOf(recording: Recording, step: Step): { step: Step; recorded: number | null }[] {
  return otherRuns(recording, step).map((other) => ({ step: other, recorded: other.visibility.events ?? null }));
}

/** True when the recording's step ids are stable: the same published test, arguments and role has the same id in every run of the list. */
export function hasStableIds(recording: Recording): boolean {
  return recording.source.setup !== undefined;
}

/** The file a page is of: the recording's id and, once it is finished, its file's SHA-256, and the list it ran. */
export interface FileHere {
  id: string;
  sha256?: string;
  /** Whether its step ids are stable, so that a comparison of other runs can name the same test. */
  stable: boolean;
  /** The list the run ran, as its list entry names it: a comparison of other runs counts only when both its runs ran the same one. */
  list?: { kind: string; title: string };
}

/**
 * How a comparison of other runs can name this step, or null when none can:
 * - `stable id`: the recording gives its steps stable ids, so the step's own id;
 * - `published test`: an older recording, whose ids are its own run's. A step
 *   of role `test` that is the only one of its published test in the run is
 *   named, in a recording with stable ids, by its role and the first 8
 *   characters of the test's GUID, when it runs as the list gives it, with no
 *   input arguments. That is the id this gives, and how the lab itself pairs
 *   an older recording's steps: by role and test. A rerun with changed
 *   arguments or with a hardening change has another role and is never tied.
 */
export type Tie = { by: "stable id"; id: string } | { by: "published test"; id: string; guid: string };

export function tieOf(recording: Recording, step: Step): Tie | null {
  if (hasStableIds(recording)) return { by: "stable id", id: step.id };
  const guid = step.test?.guid;
  if (step.role !== "test" || !guid) return null;
  const prefix = guid.slice(0, 8);
  const same = recording.steps.filter((other) => other.role === "test" && other.test?.guid.slice(0, 8) === prefix);
  return same.length === 1 ? { by: "published test", id: `test:${prefix}`, guid } : null;
}

function isFile(side: DeltaSide, here: FileHere): boolean {
  return here.sha256 !== undefined && side.id === here.id && side.sha256 === here.sha256;
}

/** Whether both runs of a comparison ran the list this file ran. */
function sameList(pair: DeltaSummary, here: FileHere): boolean {
  const list = here.list;
  return list !== undefined && [pair.recordings.before, pair.recordings.after].every((side) => side.kind === list.kind && side.title === list.title);
}

/**
 * The comparisons worth loading whole for a step: those of which this file is a
 * side, and, when the step can be tied to other runs of the same list, those
 * that list it among what they moved, or list as many as a list holds and may
 * hold it beyond.
 */
export function candidates(here: FileHere, tie: Tie | null, pairs: readonly DeltaSummary[]): DeltaSummary[] {
  return pairs.filter((pair) => {
    if (isFile(pair.before, here) || isFile(pair.after, here)) return true;
    if (!tie || !sameList(pair, here)) return false;
    const moved = pair.moved ?? [];
    return moved.length >= 20 || moved.some((step) => step.id === tie.id);
  });
}

/** A comparison that moved the step: where this recording stands in it, the step as the delta has it, and the links of the walk. */
export interface Tried {
  summary: DeltaSummary;
  delta: Delta;
  step: DeltaStep;
  /** This recording is the comparison's before or after; or the comparison is of other runs of the same list, tied as `tie` says. */
  where: "before" | "after" | "another run";
  /** For another run: how the step was tied to it. */
  tie?: Tie;
  /** The pair's page at the step. */
  pair: string;
  /** When this recording is the before: the same step in the after recording, in analyse mode. */
  after: string | null;
}

/**
 * What was already tried for a step: each kept comparison that names it among
 * the steps it moved, in the order the pairs happened, this recording's own
 * first. A comparison of other runs counts only when both its runs ran the same
 * list as this one and it paired the step by stable ids, and the step is tied
 * to it as `tieOf` says: by its own stable id, or, in an older recording, as the
 * published test run as the list gives it.
 */
export function triedFor(here: FileHere, stepId: string, tie: Tie | null, comparisons: readonly { summary: DeltaSummary; delta: Delta }[]): Tried[] {
  const order = pairsInOrder(comparisons.map((item) => item.summary)).map((summary) => summary.id);
  const found: Tried[] = [];
  for (const { summary, delta } of comparisons) {
    const moved = movedSteps(delta);
    const side = isFile(delta.after, here) ? "after" : isFile(delta.before, here) ? "before" : null;
    const step = side === "before" ? moved.find((item) => (item.before_id ?? item.id) === stepId)
      : side === "after" ? moved.find((item) => item.id === stepId)
      : tie && sameList(summary, here) ? moved.find((item) => item.id === tie.id && item.paired_by === "id" && (tie.by === "stable id" || item.role === "test"))
      : undefined;
    if (!step) continue;
    const pair = `${pairPath(summary.id)}?${new URLSearchParams({ step: step.id }).toString()}`;
    const after = side === "before" ? `${recordedRunPath(delta.after.id, delta.after.sha256)}?${stepMoment(step.id).toString()}` : null;
    found.push({ summary, delta, step, where: side ?? "another run", ...(side === null && tie ? { tie } : {}), pair, after });
  }
  const rank = (item: Tried) => (item.where === "another run" ? 1 : 0);
  return found.sort((a, b) => rank(a) - rank(b) || order.indexOf(a.summary.id) - order.indexOf(b.summary.id));
}

/** The kind of the model connection the service would use, from its configuration, or null when none is configured. */
export function activeProviderKind(catalog: Pick<CatalogResponse, "ai"> | undefined): string | null {
  const active = catalog?.ai.active_provider;
  if (!active) return null;
  return catalog?.ai.providers?.find((provider) => provider.provider_id === active)?.kind ?? null;
}

/** The model's place, in one of two fixed texts by the configured provider's kind: nothing is asked of a model either way. */
export function modelWords(kind: string | null): string {
  return kind === null || kind === "deterministic"
    ? "No model is connected. Nothing was sent."
    : "A model is configured, but BlueFire does not ask models for rules yet. Nothing was sent.";
}

/** Where this browser keeps a draft, one per finished recording file and step. */
export function draftKey(recordingId: string, sha256: string, stepId: string): string {
  return `bluefire.fix-draft.v1:${recordingId}:${sha256}:${stepId}`;
}

/** The draft this browser keeps under `key`, or "" when it keeps none or cannot be read. Never anything the app wrote. */
export function readDraft(storage: Pick<Storage, "getItem"> | null, key: string): string {
  try {
    return storage?.getItem(key) ?? "";
  } catch {
    return "";
  }
}

/** Keeps a draft in this browser, or forgets it when it is empty. False when the browser could not keep this change. */
export function keepDraft(storage: Pick<Storage, "setItem" | "removeItem"> | null, key: string, text: string): boolean {
  if (!storage) return false;
  try {
    if (text === "") storage.removeItem(key);
    else storage.setItem(key, text);
    return true;
  } catch {
    return false;
  }
}

/** This browser's storage, or null where it is blocked. */
export function browserStorage(): Storage | null {
  try {
    return window.localStorage;
  } catch {
    return null;
  }
}
