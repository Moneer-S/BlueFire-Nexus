// The recording format `bluefire.recording/1`, as docs/RECORDING.md defines it,
// a reader that refuses anything else with a plain message, and small helpers.
// This file imports nothing from the rest of the app.

export const RECORDING_SCHEMA = "bluefire.recording/1";

/**
 * The most of each column of the network map that it draws readably. The
 * service (`bluefire/recordings.py`) refuses the same, so that it keeps no
 * recording this page cannot show, and docs/RECORDING.md says them.
 */
export const MAX_HOSTS = 12;
export const MAX_DEFENSE_HOSTS = 3;
export const MAX_LINKS = 16;
export const MAX_SENSORS = 16;
export const MAX_SENSORS_ON_A_HOST = 4;
export const MAX_DETECTORS = 4;
/**
 * A recording with defenses holds one run judged by each of them. A defense
 * has at most `MAX_DETECTORS` rule sets, which the map draws at once, and the
 * network holds those of all.
 */
export const MAX_DEFENSES = 8;
export const MAX_DETECTORS_WITH_DEFENSES = 8;

/** An ISO 8601 time in UTC, such as `2026-11-17T17:07:23.834Z`. */
export type Time = string;

export type RecordingKind = "test list" | "attack path";
export type ToolRole = "tests" | "executor" | "sensor" | "rules" | "rule engine";
export type HostKind = "host" | "attacker" | "internet" | "defense";
export type DetectorWhen = "live" | "after the run";
export type StepRole = "test" | "canary" | "control" | "hardened" | "variant";
export type HappenedAnswer = "took effect" | "attempted without effect" | "blocked" | "not attempted" | "inconclusive";
export type VisibilityAnswer = "alert" | "telemetry only" | "no telemetry" | "inconclusive" | "not applicable";
export type Outcome = "stopped" | "no effect" | "alerted" | "seen" | "unseen" | "inconclusive";
export type TiedBy = "session" | "launcher" | "account" | "systemd" | "address" | "content" | "window";
export type RuleLevel = "informational" | "low" | "medium" | "high" | "critical";
export type RuleOrigin = "pinned" | "lab";

export interface Tool {
  name: string;
  version: string;
  role: ToolRole;
}

export interface Source {
  engine: string;
  environment: string;
  started: Time;
  /** Absent while the run is still going: the engine sends the recording again as it grows. */
  finished?: Time;
  repository?: string;
  commit?: string;
  /** The commit the sensors' settings, and the lab's rules unless the detector `lab` names its own, were loaded from. */
  defense_commit?: string;
  run_url?: string;
  tools: Tool[];
  /** What a comparison of two runs needs to know was the same. A recording with it has stable step ids. */
  setup?: Record<string, string | Record<string, string>>;
}

export interface Host {
  id: string;
  name: string;
  role: string;
  kind: HostKind;
  os?: string;
  addresses?: string[];
}

export interface Link {
  from: string;
  to: string;
  label: string;
}

export interface Sensor {
  id: string;
  name: string;
  host: string;
  records: string;
  /** On auditd: what its rules watch under each audit key, as the run loaded them. */
  audit_watches?: Record<string, string[]>;
}

export interface Detector {
  id: string;
  name: string;
  rules: number;
  when: DetectorWhen;
  /** The commit of the repository the lab's own rules came from, when the detector `lab` names it. */
  commit?: string;
  /** For the detector `lab`: how the run judged each rule written in the repository, and the rule itself where it is given. */
  verdicts?: RuleVerdict[];
}

/** How a run judged one rule of the lab's own, and, optionally, the rule's file and its text line by line. */
export interface RuleVerdict {
  rule: string;
  title: string;
  digest?: string;
  accepted: boolean;
  reason?: string;
  file?: string;
  lines?: string[];
}

export interface Network {
  hosts: Host[];
  links?: Link[];
  sensors: Sensor[];
  detectors: Detector[];
}

export interface Attacker {
  kind: "scripted" | "agent";
  description: string;
  goal: string | null;
}

export interface Technique {
  id: string;
  name?: string;
  tactic?: string;
}

export interface PublishedTest {
  project: string;
  guid: string;
  executor: string;
  elevated: boolean;
}

export interface Happened {
  answer: HappenedAnswer;
  basis: string;
}

export interface Visibility {
  answer: VisibilityAnswer;
  basis: string;
  events?: number;
  kept?: number;
}

/** The hardening change a `hardened` step ran with. */
export interface HardeningChange {
  title: string;
  why: string;
}

/**
 * What a defense made of a step: the keys of a step that depend on who judges
 * the run. A recording with defenses holds them once for each defense, and
 * the step's own are the first defense's.
 */
export interface StepVerdict {
  visibility: Visibility;
  outcome: Outcome;
  outcome_with_lab_rules?: Outcome;
  first_event?: Time;
  first_alert?: Time;
  first_alert_with_lab_rules?: Time;
}

export interface Step extends StepVerdict {
  id: string;
  order: number;
  role: StepRole;
  title: string;
  plain?: string;
  technique: Technique;
  test?: PublishedTest;
  host: string;
  from?: string;
  started?: Time;
  ended?: Time;
  command?: string;
  output?: string;
  happened: Happened;
  compared_with?: string;
  defense?: HardeningChange;
}

export interface RecordingEvent {
  id: string;
  time: Time;
  host: string;
  sensor: string;
  kind: string;
  text: string;
  step: string;
  tied_by: TiedBy;
  user?: string;
  image?: string;
  fields?: Record<string, string | number | boolean | null | string[]>;
}

export interface Rule {
  id: string;
  title: string;
  level: RuleLevel;
  origin: RuleOrigin;
}

export interface Alert {
  id: string;
  time: Time;
  raised?: Time;
  host: string;
  detector: string;
  rule: Rule;
  counts: boolean;
  step: string;
  events: string[];
  launcher_only?: boolean;
}

export interface OrdinaryMatch {
  rule: string;
  level: RuleLevel;
  count: number;
}

export interface Ordinary {
  events: number;
  matches: OrdinaryMatch[];
}

export interface Score {
  steps: number;
  took_effect: number;
  alerted: number;
  seen: number;
  unseen: number;
  alerted_with_lab_rules?: number;
  stopped: number;
  first_alert_seconds?: number;
  goal_seconds?: number;
  false_alerts?: number;
}

/**
 * A defense: the sensors it records with, the rule sets it runs, and what it
 * made of the run. Its view of the recording holds only the events of its
 * sensors and the alerts of its rule sets on those events; `judgedBy` gives it.
 */
export interface Defense {
  id: string;
  name: string;
  /** Ids of the network's sensors, at least one. */
  sensors: string[];
  /** Ids of the network's detectors, at most `MAX_DETECTORS`; none for a defense that only records. */
  detectors: string[];
  /** Its verdict on every step, by the step's id. */
  steps: Record<string, StepVerdict>;
  ordinary?: Ordinary;
  score: Score;
}

export interface Recording {
  schema: typeof RECORDING_SCHEMA;
  id: string;
  title: string;
  kind: RecordingKind;
  source: Source;
  network: Network;
  attacker: Attacker;
  steps: Step[];
  events: RecordingEvent[];
  alerts: Alert[];
  ordinary?: Ordinary;
  score: Score;
  /**
   * The defenses that judged the run, in a recording that names them. The
   * steps' verdicts, `ordinary` and `score` above are then the first one's,
   * and `events` and `alerts` hold those of every defense.
   */
  defenses?: Defense[];
  notes: string[];
}

/** Thrown by `readRecording`; its message is a plain sentence a person can act on. */
export class RecordingError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RecordingError";
  }
}

const KINDS: readonly RecordingKind[] = ["test list", "attack path"];
const TOOL_ROLES: readonly ToolRole[] = ["tests", "executor", "sensor", "rules", "rule engine"];
const ATTACKER_KINDS: readonly Attacker["kind"][] = ["scripted", "agent"];
const HOST_KINDS: readonly HostKind[] = ["host", "attacker", "internet", "defense"];
const WHENS: readonly DetectorWhen[] = ["live", "after the run"];
const ROLES: readonly StepRole[] = ["test", "canary", "control", "hardened", "variant"];
const HAPPENED: readonly HappenedAnswer[] = ["took effect", "attempted without effect", "blocked", "not attempted", "inconclusive"];
const VISIBILITY: readonly VisibilityAnswer[] = ["alert", "telemetry only", "no telemetry", "inconclusive", "not applicable"];
const OUTCOMES: readonly Outcome[] = ["stopped", "no effect", "alerted", "seen", "unseen", "inconclusive"];
const TIES: readonly TiedBy[] = ["session", "launcher", "account", "systemd", "address", "content", "window"];
const LEVELS: readonly RuleLevel[] = ["informational", "low", "medium", "high", "critical"];
const ORIGINS: readonly RuleOrigin[] = ["pinned", "lab"];

type Fields = Record<string, unknown>;

function isObject(value: unknown): value is Fields {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function fail(message: string): never {
  throw new RecordingError(message);
}

function object(value: unknown, where: string): Fields {
  if (!isObject(value)) fail(`${where} is not an object.`);
  return value;
}

function array(value: unknown, where: string): unknown[] {
  if (!Array.isArray(value)) fail(`${where} is not a list.`);
  return value;
}

function text(value: unknown, where: string): string {
  if (typeof value !== "string") fail(`${where} is not text.`);
  return value;
}

function optionalText(value: unknown, where: string): void {
  if (value !== undefined) text(value, where);
}

function textList(value: unknown, where: string): void {
  array(value, where).forEach((item, index) => text(item, `Item ${index + 1} of ${where.charAt(0).toLowerCase()}${where.slice(1)}`));
}

/** A finite number. Null, NaN and text are refused. */
function number(value: unknown, where: string): number {
  if (typeof value !== "number" || !Number.isFinite(value)) fail(`${where} is not a number.`);
  return value;
}

function optionalNumber(value: unknown, where: string): void {
  if (value !== undefined) number(value, where);
}

function bool(value: unknown, where: string): void {
  if (typeof value !== "boolean") fail(`${where} is not true or false.`);
}

function oneOf<T extends string>(value: unknown, allowed: readonly T[], where: string): T {
  const found = allowed.find((item) => item === value);
  if (found === undefined) fail(`${where} is ${JSON.stringify(value)}, which is not one of: ${allowed.join(", ")}.`);
  return found;
}

/** Times are ISO 8601 in UTC with a Z, so a recording plays the same in every time zone, with up to six digits after the second. */
const UTC_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z$/;

function time(value: unknown, where: string): void {
  const raw = text(value, where);
  if (!UTC_TIME.test(raw)) fail(`${where} is not a UTC time such as 2026-11-17T17:07:23.834Z: ${JSON.stringify(raw)}.`);
  if (Number.isNaN(timeOf(raw))) fail(`${where} is not a time: ${JSON.stringify(raw)}.`);
}

/** The furthest from zero a number in an event's fields may be: the largest whole number a browser holds exactly. */
const MAX_FIELD_NUMBER = 2 ** 53;

/** The values a source field of an event may hold: text, a number no further than 2^53 from zero, true or false, null, or a list of text. */
function fieldValue(value: unknown): boolean {
  if (value === null || typeof value === "string" || typeof value === "boolean") return true;
  // However the number is written, 1e300 or 9007199254740993: past 2^53 a browser holds another number.
  if (typeof value === "number") return Number.isFinite(value) && Math.abs(value) <= MAX_FIELD_NUMBER;
  return Array.isArray(value) && value.every((item) => typeof item === "string");
}

function optionalTime(value: unknown, where: string): void {
  if (value !== undefined) time(value, where);
}

/** A list of the network, refused when it holds more than the map draws: `limit` of them. */
function atMost(items: unknown[], limit: number, what: string): unknown[] {
  if (items.length > limit) fail(`The network has ${items.length} ${what}; the map draws at most ${limit}.`);
  return items;
}

function uniqueIds(items: Fields[], what: string): Set<string> {
  const ids = new Set<string>();
  items.forEach((item, index) => {
    const id = text(item.id, `The id of ${what} ${index + 1}`);
    if (ids.has(id)) fail(`Two ${what}s have the id ${JSON.stringify(id)}.`);
    ids.add(id);
  });
  return ids;
}

function known(ids: Set<string>, value: unknown, where: string, what: string): void {
  const id = text(value, where);
  if (!ids.has(id)) fail(`${where} names the ${what} ${JSON.stringify(id)}, which is not in the recording.`);
}

/**
 * Checks that `value` is a recording of `bluefire.recording/1` and returns it typed.
 * Refuses anything else with a `RecordingError` whose message says what is wrong.
 * A recording that is still running, with no end time yet, is read only with
 * `running`: the app follows one as it grows, and a replay page is of a finished run.
 */
export function readRecording(value: unknown, options: { running?: boolean } = {}): Recording {
  if (value === null || value === undefined) fail("There is no recording here.");
  const top = object(value, "The recording");
  if (top.schema !== RECORDING_SCHEMA) {
    fail(`This is not a recording this page can play: its schema is ${JSON.stringify(top.schema ?? null)}, not ${JSON.stringify(RECORDING_SCHEMA)}.`);
  }
  text(top.id, "The recording's id");
  text(top.title, "The recording's title");
  oneOf(top.kind, KINDS, "The recording's kind");

  const source = object(top.source, "The recording's source");
  text(source.engine, "The source's engine");
  text(source.environment, "The source's environment");
  time(source.started, "The source's start");
  // The service keeps a recording that is still running, and makes a page of a finished one only.
  // The app's own view follows a running one as it grows, and asks for it with `running`.
  if (source.finished === undefined && options.running !== true) fail("This recording is still running: it has no end time yet, and a replay is made of a finished run.");
  optionalTime(source.finished, "The source's end");
  optionalText(source.repository, "The source's repository");
  optionalText(source.commit, "The source's commit");
  optionalText(source.defense_commit, "The commit the source's defense came from");
  optionalText(source.run_url, "The address of the run that made the recording");
  if (source.setup !== undefined) {
    for (const [key, value] of Object.entries(object(source.setup, "The source's setup"))) {
      if (typeof value === "string") continue;
      for (const [id, item] of Object.entries(object(value, `The setup's ${key}`))) text(item, `The setup's ${key} of ${JSON.stringify(id)}`);
    }
  }
  array(source.tools, "The source's tools").forEach((item, index) => {
    const tool = object(item, `Tool ${index + 1}`);
    text(tool.name, `The name of tool ${index + 1}`);
    text(tool.version, `The version of tool ${index + 1}`);
    oneOf(tool.role, TOOL_ROLES, `The role of tool ${index + 1}`);
  });

  const network = object(top.network, "The recording's network");
  const hosts = atMost(array(network.hosts, "The network's hosts"), MAX_HOSTS, "hosts").map((item, index) => object(item, `Host ${index + 1}`));
  const hostIds = uniqueIds(hosts, "host");
  hosts.forEach((host, index) => {
    text(host.name, `The name of host ${index + 1}`);
    text(host.role, `The role of host ${index + 1}`);
    oneOf(host.kind, HOST_KINDS, `The kind of host ${index + 1}`);
    optionalText(host.os, `The system of host ${index + 1}`);
    if (host.addresses !== undefined) textList(host.addresses, `The addresses of host ${index + 1}`);
  });
  const defenseHosts = hosts.filter((host) => host.kind === "defense").length;
  if (defenseHosts > MAX_DEFENSE_HOSTS) fail(`The network has ${defenseHosts} defense hosts; the map draws at most ${MAX_DEFENSE_HOSTS}.`);
  if (network.links !== undefined) {
    const seen = new Set<string>();
    atMost(array(network.links, "The network's links"), MAX_LINKS, "links").forEach((item, index) => {
      const link = object(item, `Link ${index + 1}`);
      known(hostIds, link.from, `Link ${index + 1}`, "host");
      known(hostIds, link.to, `Link ${index + 1}`, "host");
      const label = text(link.label, `The label of link ${index + 1}`);
      if (link.from === link.to) fail(`Link ${index + 1} joins a host to itself; a link runs between two hosts.`);
      const key = JSON.stringify([link.from, link.to, label]);
      if (seen.has(key)) fail(`Link ${index + 1} repeats a link with the same hosts and label.`);
      seen.add(key);
    });
  }
  const sensors = atMost(array(network.sensors, "The network's sensors"), MAX_SENSORS, "sensors").map((item, index) => object(item, `Sensor ${index + 1}`));
  const sensorIds = uniqueIds(sensors, "sensor");
  const onHost = new Map<unknown, number>();
  sensors.forEach((sensor, index) => {
    text(sensor.name, `The name of sensor ${index + 1}`);
    known(hostIds, sensor.host, `Sensor ${JSON.stringify(sensor.id)}`, "host");
    text(sensor.records, `What sensor ${index + 1} records`);
    if (sensor.audit_watches !== undefined) {
      for (const [key, rules] of Object.entries(object(sensor.audit_watches, `What sensor ${index + 1} watches`))) textList(rules, `What sensor ${index + 1} watches under the key ${JSON.stringify(key)}`);
    }
    const count = (onHost.get(sensor.host) ?? 0) + 1;
    if (count > MAX_SENSORS_ON_A_HOST) fail(`The host ${JSON.stringify(sensor.host)} has more than ${MAX_SENSORS_ON_A_HOST} sensors; the map draws at most ${MAX_SENSORS_ON_A_HOST} on one host.`);
    onHost.set(sensor.host, count);
  });
  // Without defenses the map draws every detector at once; with them it draws one defense's, and each defense has its own limit.
  const allDetectors = array(network.detectors, "The network's detectors");
  if (top.defenses !== undefined && allDetectors.length > MAX_DETECTORS_WITH_DEFENSES) fail(`The network has ${allDetectors.length} detectors; a recording with defenses holds at most ${MAX_DETECTORS_WITH_DEFENSES}.`);
  const detectors = (top.defenses === undefined ? atMost(allDetectors, MAX_DETECTORS, "detectors") : allDetectors).map((item, index) => object(item, `Detector ${index + 1}`));
  const detectorIds = uniqueIds(detectors, "detector");
  detectors.forEach((detector, index) => {
    text(detector.name, `The name of detector ${index + 1}`);
    number(detector.rules, `The number of rules of detector ${index + 1}`);
    oneOf(detector.when, WHENS, `When detector ${JSON.stringify(detector.id)} ran`);
    optionalText(detector.commit, `The commit of detector ${index + 1}`);
    if (detector.verdicts !== undefined) {
      array(detector.verdicts, `The verdicts of detector ${index + 1}`).forEach((item, at) => {
        const where = `verdict ${at + 1} of detector ${index + 1}`;
        const verdict = object(item, `The ${where}`);
        text(verdict.rule, `The rule of ${where}`);
        text(verdict.title, `The title of ${where}`);
        optionalText(verdict.digest, `The digest of ${where}`);
        bool(verdict.accepted, `Whether ${where} accepted its rule`);
        optionalText(verdict.reason, `The reason of ${where}`);
        optionalText(verdict.file, `The file of ${where}`);
        if (verdict.lines !== undefined) textList(verdict.lines, `The lines of ${where}`);
      });
    }
  });

  const attacker = object(top.attacker, "The recording's attacker");
  oneOf(attacker.kind, ATTACKER_KINDS, "The attacker's kind");
  text(attacker.description, "The attacker's description");
  if (attacker.goal !== null) text(attacker.goal, "The attacker's goal");

  const steps = array(top.steps, "The recording's steps").map((item, index) => object(item, `Step ${index + 1}`));
  const stepIds = uniqueIds(steps, "step");
  steps.forEach((step) => {
    const name = `Step ${JSON.stringify(step.id)}`;
    number(step.order, `The order of ${name}`);
    oneOf(step.role, ROLES, `The role of ${name}`);
    text(step.title, `The title of ${name}`);
    optionalText(step.plain, `The plain sentence of ${name}`);
    const technique = object(step.technique, `The technique of ${name}`);
    text(technique.id, `The technique id of ${name}`);
    optionalText(technique.name, `The technique name of ${name}`);
    optionalText(technique.tactic, `The tactic of ${name}`);
    if (step.test !== undefined) {
      const test = object(step.test, `The published test of ${name}`);
      text(test.project, `The project of the test of ${name}`);
      text(test.guid, `The id of the test of ${name}`);
      text(test.executor, `The executor of the test of ${name}`);
      bool(test.elevated, `Whether the test of ${name} ran as root`);
    }
    known(hostIds, step.host, name, "host");
    if (step.from !== undefined) known(hostIds, step.from, `Where ${name} came from`, "host");
    optionalTime(step.started, `The start of ${name}`);
    optionalTime(step.ended, `The end of ${name}`);
    optionalText(step.command, `The command of ${name}`);
    optionalText(step.output, `The output of ${name}`);
    const happened = object(step.happened, `What happened in ${name}`);
    oneOf(happened.answer, HAPPENED, `What happened in ${name}`);
    text(happened.basis, `The basis of what happened in ${name}`);
    verdictShape(step, name);
    if (step.compared_with !== undefined) known(stepIds, step.compared_with, `What ${name} is compared with`, "step");
    if (step.defense !== undefined) {
      const defense = object(step.defense, `The hardening change of ${name}`);
      text(defense.title, `The title of the hardening change of ${name}`);
      text(defense.why, `Why the hardening change of ${name} is deployed`);
    }
  });

  const events = array(top.events, "The recording's events").map((item, index) => object(item, `Event ${index + 1}`));
  const eventIds = uniqueIds(events, "event");
  events.forEach((event) => {
    const name = `Event ${JSON.stringify(event.id)}`;
    time(event.time, `The time of ${name}`);
    known(hostIds, event.host, name, "host");
    known(sensorIds, event.sensor, name, "sensor");
    text(event.kind, `The kind of ${name}`);
    text(event.text, `The text of ${name}`);
    known(stepIds, event.step, name, "step");
    oneOf(event.tied_by, TIES, `How ${name} is tied to its step`);
    optionalText(event.user, `The user of ${name}`);
    optionalText(event.image, `The program of ${name}`);
    if (event.fields !== undefined) {
      for (const [key, field] of Object.entries(object(event.fields, `The fields of ${name}`))) {
        if (!fieldValue(field)) fail(`The field ${JSON.stringify(key)} of ${name} is not text, a number no further than 2^53 from zero, true or false, null or a list of text.`);
      }
    }
  });

  const alerts = array(top.alerts, "The recording's alerts").map((item, index) => object(item, `Alert ${index + 1}`));
  uniqueIds(alerts, "alert");
  alerts.forEach((alert) => {
    const name = `Alert ${JSON.stringify(alert.id)}`;
    time(alert.time, `The time of ${name}`);
    optionalTime(alert.raised, `When ${name} was raised`);
    known(hostIds, alert.host, name, "host");
    known(detectorIds, alert.detector, name, "detector");
    const rule = object(alert.rule, `The rule of ${name}`);
    text(rule.id, `The rule id of ${name}`);
    text(rule.title, `The rule title of ${name}`);
    oneOf(rule.level, LEVELS, `The rule level of ${name}`);
    oneOf(rule.origin, ORIGINS, `The rule origin of ${name}`);
    bool(alert.counts, `Whether ${name} counts`);
    known(stepIds, alert.step, name, "step");
    array(alert.events, `The events of ${name}`).forEach((id) => known(eventIds, id, name, "event"));
    if (alert.launcher_only !== undefined) bool(alert.launcher_only, `Whether ${name} matched only the launcher`);
  });

  ordinaryAndScore(top);
  if (top.defenses !== undefined) defensesShape(top.defenses, sensorIds, detectorIds, stepIds);
  array(top.notes, "The recording's notes").forEach((note, index) => text(note, `Note ${index + 1}`));

  const recording = value as Recording;
  noControls(recording);
  if (recording.defenses === undefined) agree(recording);
  else agreeForEach(recording, recording.defenses);
  return recording;
}

/** A defense's id, as a recording's own: letters, digits, `-` and `_`, at most 64. */
const DEFENSE_ID = /^[A-Za-z0-9_-]{1,64}$/;

/**
 * The defenses of a recording that names them: from 1 to `MAX_DEFENSES`, each
 * with an id of its own and a name, sensors and detectors that the network
 * has, a verdict on every step and on nothing else, and its ordinary activity
 * and score.
 */
function defensesShape(value: unknown, sensorIds: Set<string>, detectorIds: Set<string>, stepIds: Set<string>): void {
  const list = array(value, "The recording's defenses");
  if (list.length < 1 || list.length > MAX_DEFENSES) fail(`The recording has ${list.length} defenses; one with defenses has from 1 to ${MAX_DEFENSES}.`);
  const defenses = list.map((item, index) => object(item, `Defense ${index + 1}`));
  uniqueIds(defenses, "defense");
  defenses.forEach((defense, index) => {
    const id = JSON.stringify(defense.id);
    if (!DEFENSE_ID.test(text(defense.id, `The id of defense ${index + 1}`))) fail(`The id of defense ${index + 1}, ${id}, is not 1 to 64 letters, digits, "-" or "_".`);
    text(defense.name, `The name of the defense ${id}`);
    const sensors = array(defense.sensors, `The sensors of the defense ${id}`);
    textList(sensors, `The sensors of the defense ${id}`);
    sensors.forEach((item) => known(sensorIds, item, `The defense ${id}`, "sensor"));
    if (sensors.length === 0) fail(`The defense ${id} has no sensor; a defense records with at least one.`);
    const detectors = array(defense.detectors, `The detectors of the defense ${id}`);
    textList(detectors, `The detectors of the defense ${id}`);
    detectors.forEach((item) => known(detectorIds, item, `The defense ${id}`, "detector"));
    const distinct = new Set(detectors).size;
    if (distinct > MAX_DETECTORS) fail(`The defense ${id} has ${distinct} detectors; the map draws at most ${MAX_DETECTORS}.`);
    const verdicts = object(defense.steps, `The steps of the defense ${id}`);
    for (const step of Object.keys(verdicts)) known(stepIds, step, `The defense ${id}`, "step");
    for (const step of stepIds) {
      if (!Object.hasOwn(verdicts, step)) fail(`The defense ${id} has no verdict on Step ${JSON.stringify(step)}; a defense judges every step.`);
      verdictShape(object(verdicts[step], `The verdict of the defense ${id} on Step ${JSON.stringify(step)}`), `Step ${JSON.stringify(step)} for the defense ${id}`);
    }
    ordinaryAndScore(defense, ` of the defense ${id}`);
  });
}

/** What a defense made of a step: those keys of the step itself, or a defense's verdict on the step. */
function verdictShape(holder: Fields, name: string): void {
  const visibility = object(holder.visibility, `The visibility of ${name}`);
  oneOf(visibility.answer, VISIBILITY, `The visibility of ${name}`);
  text(visibility.basis, `The basis of the visibility of ${name}`);
  optionalNumber(visibility.events, `The events counted for ${name}`);
  optionalNumber(visibility.kept, `The events kept for ${name}`);
  oneOf(holder.outcome, OUTCOMES, `The outcome of ${name}`);
  if (holder.outcome_with_lab_rules !== undefined) oneOf(holder.outcome_with_lab_rules, OUTCOMES, `The outcome with lab rules of ${name}`);
  optionalTime(holder.first_event, `The first event of ${name}`);
  optionalTime(holder.first_alert, `The first alert of ${name}`);
  optionalTime(holder.first_alert_with_lab_rules, `The first alert with lab rules of ${name}`);
}

/** The ordinary activity and the score: the recording's own, or those of a defense, which `of` names. */
function ordinaryAndScore(holder: Fields, of = ""): void {
  if (holder.ordinary !== undefined) {
    const ordinary = object(holder.ordinary, of ? `The ordinary activity${of}` : "The recording's ordinary activity");
    number(ordinary.events, `The events of ordinary activity${of}`);
    array(ordinary.matches, `The matches on ordinary activity${of}`).forEach((item, index) => {
      const match = object(item, `Match ${index + 1} on ordinary activity${of}`);
      text(match.rule, `The rule of match ${index + 1} on ordinary activity${of}`);
      oneOf(match.level, LEVELS, `The level of match ${index + 1} on ordinary activity${of}`);
      number(match.count, `The count of match ${index + 1} on ordinary activity${of}`);
    });
  }
  const score = object(holder.score, of ? `The score${of}` : "The recording's score");
  const named = (key: string) => (of ? `The ${key} in the score${of}` : `The score's ${key}`);
  for (const key of ["steps", "took_effect", "alerted", "seen", "unseen", "stopped"]) number(score[key], named(key));
  for (const key of ["alerted_with_lab_rules", "first_alert_seconds", "goal_seconds", "false_alerts"]) optionalNumber(score[key], named(key));
}

/**
 * Control characters as docs/RECORDING.md means them: C0, DEL and C1, the
 * direction marks, embeddings, overrides and isolates, and the line and
 * paragraph separators. The service's import refuses the same.
 */
function isControl(code: number): boolean {
  return code <= 0x1f || (code >= 0x7f && code <= 0x9f) || code === 0x61c || code === 0x200e || code === 0x200f || code === 0x2028 || code === 0x2029 || (code >= 0x202a && code <= 0x202e) || (code >= 0x2066 && code <= 0x2069);
}

function holdsControl(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) if (isControl(value.charCodeAt(index))) return true;
  return false;
}

/** The only texts that may hold them: what a step ran and printed, and sentences. Paths as the service writes them. */
const FREE_TEXT = /^(?:notes\[\d+\]|attacker\.(?:description|goal)|steps\[\d+\]\.(?:command|output|plain))$/;

/** Refuses a NUL in any text, and a control character in any key or in any text the format does not let hold one. */
function noControls(recording: Recording): void {
  const stack: { item: unknown; where: string }[] = [{ item: recording, where: "" }];
  while (stack.length > 0) {
    const next = stack.pop();
    if (!next) break;
    const { item, where } = next;
    if (typeof item === "string") {
      // No text holds a NUL, a free one neither.
      if (item.includes("\u0000")) fail(`The text at ${where} holds a NUL character.`);
      if (!FREE_TEXT.test(where) && holdsControl(item)) fail(`The text at ${where} holds a control character, a direction mark or a line separator; only a step's command, output and plain sentence, the attacker's description and goal, and the notes may.`);
    } else if (Array.isArray(item)) {
      item.forEach((child, index) => stack.push({ item: child, where: `${where}[${index}]` }));
    } else if (isObject(item)) {
      for (const [key, child] of Object.entries(item)) {
        if (holdsControl(key)) fail(`A key at ${where || "the top of the recording"} holds a control character.`);
        stack.push({ item: child, where: where ? `${where}.${key}` : key });
      }
    }
  }
}

/** A GitHub repository as `owner/name`. */
const REPOSITORY = /^[A-Za-z0-9-]+\/[A-Za-z0-9._-]+$/;
const RERUNS: readonly StepRole[] = ["hardened", "variant"];

/**
 * The parts of a well-formed recording that must agree for the page to show
 * them truthfully, each refused with the field named, as the service refuses
 * them on import.
 */
function agree(recording: Recording): void {
  const { steps, events, alerts, source, attacker, score, ordinary } = recording;
  const name = (step: Step) => `Step ${JSON.stringify(step.id)}`;
  if (source.repository !== undefined && source.repository.trim() !== "" && !REPOSITORY.test(source.repository)) fail(`The source's repository, ${JSON.stringify(source.repository)}, is not a GitHub repository as owner/name.`);

  if (recording.kind === "test list" && attacker.goal !== null) fail("The attacker's goal is set, but a test list has no goal: it is null.");
  if (recording.kind === "attack path") {
    if (score.goal_seconds !== undefined && attacker.goal === null) fail("The score's goal_seconds is set, but the attacker has no goal.");
    const first = steps[0];
    if (first && first.role !== "test") fail(`The first step of an attack path, ${name(first)}, has the role ${first.role}: an attack path begins with a step of role test, and its race counts from that step's started.`);
    if (first && first.started === undefined) fail(`The first step of an attack path, ${name(first)}, has no started: its race counts from that step's start.`);
    if (!first && score.goal_seconds !== undefined) fail("The score's goal_seconds is set, but the recording has no step to reach the goal at.");
  }

  // Ordinary activity: each rule listed once, with no more events than there were.
  if (score.false_alerts !== undefined && ordinary === undefined) fail("The score's false_alerts is set, but the recording has no ordinary activity to count it from.");
  if (ordinary) {
    const listed = new Set<string>();
    ordinary.matches.forEach((match, index) => {
      if (listed.has(match.rule)) fail(`Match ${index + 1} on ordinary activity names the rule ${JSON.stringify(match.rule)} again; each rule is listed once.`);
      listed.add(match.rule);
      if (match.count > ordinary.events) fail(`The count of match ${index + 1} on ordinary activity, ${match.count}, is more than the ${ordinary.events} events of ordinary activity.`);
    });
  }

  // A rerun names an earlier step that is not a rerun itself.
  const place = new Map(steps.map((step, index) => [step.id, index]));
  steps.forEach((step, index) => {
    if (step.compared_with === undefined) return;
    const at = place.get(step.compared_with) ?? -1;
    const other = steps[at];
    if (!RERUNS.includes(step.role)) fail(`${name(step)} has compared_with, but it is of role ${step.role}; only a hardened or variant step repeats another.`);
    if (step.compared_with === step.id) fail(`${name(step)} names itself in compared_with; a rerun is compared with the step it repeats.`);
    if (at > index) fail(`${name(step)} names a later step in compared_with; a rerun repeats a step run before it.`);
    if (other && RERUNS.includes(other.role)) fail(`${name(step)} names a ${other.role} step in compared_with; a rerun is compared with a step that is neither.`);
  });

  // Steps run forward, one after another: the stretch of the run each one
  // plays, from its start or earliest event or alert to its end or latest one,
  // follows the stretch of the step before it.
  const stamps = new Map<string, number[]>(steps.map((step) => [step.id, []]));
  for (const item of [...events, ...alerts]) stamps.get(item.step)?.push(timeOf(item.time));
  let lastStart: { step: Step; at: number } | null = null;
  let lastEnd: { step: Step; at: number } | null = null;
  let lastWindow: { step: Step; at: number } | null = null;
  for (const step of steps) {
    const started = step.started === undefined ? null : timeOf(step.started);
    const ended = step.ended === undefined ? null : timeOf(step.ended);
    const own = stamps.get(step.id) ?? [];
    if (started !== null && ended !== null && ended < started) fail(`${name(step)} ends before it starts: its ended, ${step.ended ?? ""}, is earlier than its started, ${step.started ?? ""}.`);
    if (started !== null && lastStart && started < lastStart.at) fail(`${name(step)} starts before ${name(lastStart.step)}, the step before it: its started is earlier, and steps run forward in their order.`);
    if (started !== null && lastEnd && started < lastEnd.at) fail(`${name(step)} starts before ${name(lastEnd.step)}, the step before it, has ended: its started is earlier than that step's end, and steps do not overlap.`);
    const starts = [...(started === null ? [] : [started]), ...own];
    const ends = [...(ended === null ? [] : [ended]), ...(started === null ? [] : [started]), ...own];
    const first = starts.length > 0 ? minimum(starts) : ends.length > 0 ? minimum(ends) : null;
    if (first !== null && lastWindow && first < lastWindow.at) fail(`${name(step)} begins before ${name(lastWindow.step)}, the step before it, ends: a step's start, events and alerts come after the end, events and alerts of the step before it.`);
    if (started !== null) lastStart = { step, at: started };
    if (started !== null || ended !== null) lastEnd = { step, at: Math.max(ended ?? Number.NEGATIVE_INFINITY, started ?? Number.NEGATIVE_INFINITY) };
    if (ends.length > 0) lastWindow = { step, at: maximum(ends) };
  }

  // An alert comes after the first event it names, at its moment, on the host of those events. An
  // after-run correlation ends with its terminal event; earlier evidence may belong to earlier steps.
  const eventTime = new Map(events.map((event) => [event.id, timeOf(event.time)]));
  const eventHost = new Map(events.map((event) => [event.id, event.host]));
  const eventStep = new Map(events.map((event) => [event.id, event.step]));
  const eventUser = new Map(events.map((event) => [event.id, event.user]));
  const detectorWhen = new Map(recording.network.detectors.map((detector) => [detector.id, detector.when]));
  for (const alert of alerts) {
    if (alert.events.length === 0) continue;
    if (alert.events.some((id) => eventHost.get(id) !== alert.host)) fail(`Alert ${JSON.stringify(alert.id)} is on the host ${JSON.stringify(alert.host)}, but an event it matched is on another host: an alert is on the host of its events.`);
    const times = alert.events.map((id) => eventTime.get(id) ?? Number.POSITIVE_INFINITY);
    const crossStep = alert.events.some((id) => eventStep.get(id) !== alert.step);
    const correlation = detectorWhen.get(alert.detector) === "after the run" && crossStep;
    if (correlation) {
      const terminalId = alert.events[alert.events.length - 1] ?? "";
      const terminal = eventTime.get(terminalId) ?? Number.POSITIVE_INFINITY;
      if (eventStep.get(terminalId) !== alert.step) fail(`Alert ${JSON.stringify(alert.id)} does not end with a terminal event of its step ${JSON.stringify(alert.step)}.`);
      if (timeOf(alert.time) !== terminal) fail(`Alert ${JSON.stringify(alert.id)} has the time ${alert.time}, not the time of its terminal event.`);
      if (maximum(times) > terminal) fail(`Alert ${JSON.stringify(alert.id)} names evidence after its terminal event.`);
      const users = new Set(alert.events.map((id) => eventUser.get(id)).filter((user): user is string => user !== undefined && user !== ""));
      if (users.size > 1) fail(`Alert ${JSON.stringify(alert.id)} names events of different observed users.`);
    } else if (crossStep) {
      fail(`Alert ${JSON.stringify(alert.id)} names an event of another step.`);
    }
    const earliest = minimum(times);
    if (alertMoment(alert) < earliest) fail(`Alert ${JSON.stringify(alert.id)} is earlier than the earliest event it matched: its ${alert.raised === undefined ? "time" : "raised"}, ${alert.raised ?? alert.time}, comes before that event.`);
  }
}

function minimum(values: readonly number[]): number {
  let low = Number.POSITIVE_INFINITY;
  for (const value of values) if (value < low) low = value;
  return low;
}

function maximum(values: readonly number[]): number {
  let high = Number.NEGATIVE_INFINITY;
  for (const value of values) if (value > high) high = value;
  return high;
}

/** Whether two values of a recording are the same, whatever the order of an object's keys. */
function same(a: unknown, b: unknown): boolean {
  if (Array.isArray(a) || Array.isArray(b)) return Array.isArray(a) && Array.isArray(b) && a.length === b.length && a.every((item, index) => same(item, b[index]));
  if (!isObject(a) || !isObject(b)) return a === b;
  const keys = Object.keys(a);
  return keys.length === Object.keys(b).length && keys.every((key) => Object.hasOwn(b, key) && same(a[key], b[key]));
}

/**
 * What must hold of a recording with defenses, as the service checks it on
 * import: every event and every alert is in the view of at least one defense,
 * the top level holds the verdicts of the first defense, and the view of each
 * defense agrees with itself as a recording without defenses does.
 */
function agreeForEach(recording: Recording, defenses: readonly Defense[]): void {
  const views = defenses.map((defense) => ({ id: JSON.stringify(defense.id), view: viewOf(recording, defense) }));
  const held = new Set(views.flatMap(({ view }) => view.events.map((event) => event.id)));
  for (const event of recording.events) {
    if (!held.has(event.id)) fail(`Event ${JSON.stringify(event.id)} is of the sensor ${JSON.stringify(event.sensor)}, which no defense has: every event of a recording with defenses is of a sensor that one of them has.`);
  }
  const judged = new Set(views.flatMap(({ view }) => view.alerts.map((alert) => alert.id)));
  const run = new Set(defenses.flatMap((defense) => defense.detectors));
  for (const alert of recording.alerts) {
    if (judged.has(alert.id)) continue;
    if (run.has(alert.detector)) fail(`Alert ${JSON.stringify(alert.id)} is in no defense's view: no defense has its detector, ${JSON.stringify(alert.detector)}, and the sensor of every event it names.`);
    fail(`Alert ${JSON.stringify(alert.id)} is of the detector ${JSON.stringify(alert.detector)}, which no defense has: every alert of a recording with defenses is of a rule set that one of them has.`);
  }

  const [first] = views;
  if (first) {
    const whose = `the first defense's, ${first.id}: the top level of a recording with defenses holds the verdicts of its first defense.`;
    recording.steps.forEach((step, index) => {
      const judgedStep = first.view.steps[index];
      const key = VERDICT_KEYS.find((item) => !same(step[item], judgedStep?.[item]));
      if (key) fail(`The ${key} of Step ${JSON.stringify(step.id)} differs from ${whose}`);
    });
    if (!same(recording.ordinary, first.view.ordinary)) fail(`The recording's ordinary differs from ${whose}`);
    if (!same(recording.score, first.view.score)) fail(`The recording's score differs from ${whose}`);
  }

  for (const { id, view } of views) {
    try {
      agree(view);
    } catch (error) {
      if (error instanceof RecordingError) fail(`For the defense ${id}: ${error.message}`);
      throw error;
    }
  }
}

/** The keys of a step that say what a defense made of it. Every other key is the step's own, whoever judges it. */
const VERDICT_KEYS: readonly (keyof StepVerdict)[] = ["visibility", "outcome", "outcome_with_lab_rules", "first_event", "first_alert", "first_alert_with_lab_rules"];

/** Gives `target` one key of a verdict as `source` has it, or takes the key away when `source` has none. */
function carry<K extends keyof StepVerdict>(target: StepVerdict, source: StepVerdict, key: K): void {
  if (source[key] === undefined) delete target[key];
  else target[key] = source[key];
}

/** The view of one defense of the recording, as `judgedBy` describes it. */
function viewOf(recording: Recording, defense: Defense): Recording {
  const sensors = new Set(defense.sensors);
  const detectors = new Set(defense.detectors);
  const events = recording.events.filter((event) => sensors.has(event.sensor));
  const held = new Set(events.map((event) => event.id));
  const view: Recording = {
    ...recording,
    network: { ...recording.network, sensors: recording.network.sensors.filter((sensor) => sensors.has(sensor.id)), detectors: recording.network.detectors.filter((detector) => detectors.has(detector.id)) },
    steps: recording.steps.map((step) => {
      const verdict = Object.hasOwn(defense.steps, step.id) ? defense.steps[step.id] : undefined;
      if (!verdict) fail(`The defense ${JSON.stringify(defense.id)} has no verdict on Step ${JSON.stringify(step.id)}; a defense judges every step.`);
      const judged: Step = { ...step };
      for (const key of VERDICT_KEYS) carry(judged, verdict, key);
      return judged;
    }),
    events,
    alerts: recording.alerts.filter((alert) => detectors.has(alert.detector) && alert.events.every((id) => held.has(id))),
    score: defense.score,
  };
  delete view.defenses;
  if (defense.ordinary === undefined) delete view.ordinary;
  else view.ordinary = defense.ordinary;
  return view;
}

/** The defenses of a recording, in its order: the first is the one a reader shows first. None for a recording that names none. */
export function defensesOf(recording: Recording): Defense[] {
  return recording.defenses ?? [];
}

/**
 * The view of one defense: the recording as that defense judged the run. It is
 * itself a recording without defenses, so whatever plays or reads a recording
 * takes it. It holds only the events of the defense's sensors and the alerts
 * of its detectors that rest on those events, only those sensors and detectors
 * in its network, each step with the defense's verdict in place of the step's
 * own, and the defense's ordinary activity and score. What a step did is the
 * same in every view.
 */
export function judgedBy(recording: Recording, defenseId: string): Recording {
  const defense = defensesOf(recording).find((item) => item.id === defenseId);
  if (!defense) fail(`This recording has no defense ${JSON.stringify(defenseId)}.`);
  return viewOf(recording, defense);
}

/**
 * What the app and the replay page play of a recording: the view of its first
 * defense, or the recording itself when it names none.
 */
export function firstView(recording: Recording): Recording {
  const [first] = defensesOf(recording);
  return first ? viewOf(recording, first) : recording;
}

/**
 * Milliseconds since 1970 of a recording time, with the digits past the
 * millisecond kept as a fraction of one, so the page orders and compares
 * times as finely as the service, to the microsecond.
 */
export function timeOf(value: Time): number {
  const found = /^(.*\.\d{3})(\d+)Z$/.exec(value);
  if (!found) return Date.parse(value);
  const [, head = "", rest = ""] = found;
  return Date.parse(`${head}Z`) + Number(`0.${rest}`);
}

function groupByStep<T extends { step: string }>(recording: Recording, items: readonly T[]): Map<string, T[]> {
  const groups = new Map<string, T[]>(recording.steps.map((step) => [step.id, []]));
  for (const item of items) {
    const group = groups.get(item.step);
    if (group) group.push(item);
    else groups.set(item.step, [item]);
  }
  return groups;
}

/** Every step's events, in the recording's time order. Every step has an entry. */
export function eventsByStep(recording: Recording): Map<string, RecordingEvent[]> {
  return groupByStep(recording, recording.events);
}

/**
 * Every step's rule matches, in the recording's order: the order of their
 * activity, not of when a live rule engine raised them. For counting only:
 * to pick, list or name a step's matches, read them in firing order from
 * `stepMatchesInFiringOrder` in `playback.ts`. Every step has an entry.
 */
export function alertsByStep(recording: Recording): Map<string, Alert[]> {
  return groupByStep(recording, recording.alerts);
}

/** True when the match counts as an alert of its origin: high or critical, and not on the launcher line alone. */
export function countsAsAlert(alert: Alert): boolean {
  return alert.counts && alert.launcher_only !== true;
}

/** True when the match counts toward `outcome` and `first_alert`: a counting match of a published rule. */
export function countsForScore(alert: Alert): boolean {
  return countsAsAlert(alert) && alert.rule.origin === "pinned";
}

/**
 * The moment of an alert, in ms: when it was raised where its detector ran
 * live, else the time of its activity (rules that ran after the run have no
 * other moment). Playback fires it then, and the race counts it from then.
 */
export function alertMoment(alert: Alert): number {
  return timeOf(alert.raised ?? alert.time);
}

/** True when every detector of the recording ran after the run, so an alert's time is its event's time. */
export function rulesRanAfterTheRun(recording: Recording): boolean {
  return recording.network.detectors.length > 0 && recording.network.detectors.every((detector) => detector.when === "after the run");
}
