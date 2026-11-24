// The recording format `bluefire.recording/1`, as docs/RECORDING.md defines it,
// a reader that refuses anything else with a plain message, and small helpers.
// This file imports nothing from the rest of the app.

export const RECORDING_SCHEMA = "bluefire.recording/1";

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
export type TiedBy = "session" | "launcher" | "account" | "systemd" | "window";
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
  finished: Time;
  repository?: string;
  commit?: string;
  run_url?: string;
  tools: Tool[];
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
}

export interface Detector {
  id: string;
  name: string;
  rules: number;
  when: DetectorWhen;
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

export interface Defense {
  title: string;
  why: string;
}

export interface Step {
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
  visibility: Visibility;
  outcome: Outcome;
  outcome_with_lab_rules?: Outcome;
  first_event?: Time;
  first_alert?: Time;
  first_alert_with_lab_rules?: Time;
  compared_with?: string;
  defense?: Defense;
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
const TIES: readonly TiedBy[] = ["session", "launcher", "account", "systemd", "window"];
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

/** The values a source field of an event may hold: text, a number, true or false, null, or a list of text. */
function fieldValue(value: unknown): boolean {
  if (value === null || typeof value === "string" || typeof value === "boolean") return true;
  if (typeof value === "number") return Number.isFinite(value);
  return Array.isArray(value) && value.every((item) => typeof item === "string");
}

function optionalTime(value: unknown, where: string): void {
  if (value !== undefined) time(value, where);
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
 */
export function readRecording(value: unknown): Recording {
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
  if (source.finished === undefined) fail("This recording is still running: it has no end time yet, and a replay is made of a finished run.");
  time(source.finished, "The source's end");
  optionalText(source.repository, "The source's repository");
  optionalText(source.commit, "The source's commit");
  optionalText(source.run_url, "The address of the run that made the recording");
  array(source.tools, "The source's tools").forEach((item, index) => {
    const tool = object(item, `Tool ${index + 1}`);
    text(tool.name, `The name of tool ${index + 1}`);
    text(tool.version, `The version of tool ${index + 1}`);
    oneOf(tool.role, TOOL_ROLES, `The role of tool ${index + 1}`);
  });

  const network = object(top.network, "The recording's network");
  const hosts = array(network.hosts, "The network's hosts").map((item, index) => object(item, `Host ${index + 1}`));
  const hostIds = uniqueIds(hosts, "host");
  hosts.forEach((host, index) => {
    text(host.name, `The name of host ${index + 1}`);
    text(host.role, `The role of host ${index + 1}`);
    oneOf(host.kind, HOST_KINDS, `The kind of host ${index + 1}`);
    optionalText(host.os, `The system of host ${index + 1}`);
    if (host.addresses !== undefined) textList(host.addresses, `The addresses of host ${index + 1}`);
  });
  if (network.links !== undefined) {
    array(network.links, "The network's links").forEach((item, index) => {
      const link = object(item, `Link ${index + 1}`);
      known(hostIds, link.from, `Link ${index + 1}`, "host");
      known(hostIds, link.to, `Link ${index + 1}`, "host");
      text(link.label, `The label of link ${index + 1}`);
    });
  }
  const sensors = array(network.sensors, "The network's sensors").map((item, index) => object(item, `Sensor ${index + 1}`));
  const sensorIds = uniqueIds(sensors, "sensor");
  sensors.forEach((sensor, index) => {
    text(sensor.name, `The name of sensor ${index + 1}`);
    known(hostIds, sensor.host, `Sensor ${JSON.stringify(sensor.id)}`, "host");
    text(sensor.records, `What sensor ${index + 1} records`);
  });
  const detectors = array(network.detectors, "The network's detectors").map((item, index) => object(item, `Detector ${index + 1}`));
  const detectorIds = uniqueIds(detectors, "detector");
  detectors.forEach((detector, index) => {
    text(detector.name, `The name of detector ${index + 1}`);
    number(detector.rules, `The number of rules of detector ${index + 1}`);
    oneOf(detector.when, WHENS, `When detector ${JSON.stringify(detector.id)} ran`);
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
    const visibility = object(step.visibility, `The visibility of ${name}`);
    oneOf(visibility.answer, VISIBILITY, `The visibility of ${name}`);
    text(visibility.basis, `The basis of the visibility of ${name}`);
    optionalNumber(visibility.events, `The events counted for ${name}`);
    optionalNumber(visibility.kept, `The events kept for ${name}`);
    oneOf(step.outcome, OUTCOMES, `The outcome of ${name}`);
    if (step.outcome_with_lab_rules !== undefined) oneOf(step.outcome_with_lab_rules, OUTCOMES, `The outcome with lab rules of ${name}`);
    optionalTime(step.first_event, `The first event of ${name}`);
    optionalTime(step.first_alert, `The first alert of ${name}`);
    optionalTime(step.first_alert_with_lab_rules, `The first alert with lab rules of ${name}`);
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
        if (!fieldValue(field)) fail(`The field ${JSON.stringify(key)} of ${name} is not text, a number, true or false, null or a list of text.`);
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

  if (top.ordinary !== undefined) {
    const ordinary = object(top.ordinary, "The recording's ordinary activity");
    number(ordinary.events, "The events of ordinary activity");
    array(ordinary.matches, "The matches on ordinary activity").forEach((item, index) => {
      const match = object(item, `Match ${index + 1} on ordinary activity`);
      text(match.rule, `The rule of match ${index + 1} on ordinary activity`);
      oneOf(match.level, LEVELS, `The level of match ${index + 1} on ordinary activity`);
      number(match.count, `The count of match ${index + 1} on ordinary activity`);
    });
  }
  const score = object(top.score, "The recording's score");
  for (const key of ["steps", "took_effect", "alerted", "seen", "unseen", "stopped"]) number(score[key], `The score's ${key}`);
  for (const key of ["alerted_with_lab_rules", "first_alert_seconds", "goal_seconds", "false_alerts"]) optionalNumber(score[key], `The score's ${key}`);
  array(top.notes, "The recording's notes").forEach((note, index) => text(note, `Note ${index + 1}`));

  return value as Recording;
}

/** Milliseconds since 1970 of a recording time. */
export function timeOf(value: Time): number {
  // A browser reads at most milliseconds the same everywhere, so digits past
  // the third are cut, which keeps every time in its order.
  return Date.parse(value.replace(/(\.\d{3})\d+Z$/, "$1Z"));
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
