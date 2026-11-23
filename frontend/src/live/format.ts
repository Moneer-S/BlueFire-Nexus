// Small pure helpers for the words and numbers the live view shows.

import { countsAsAlert, countsForScore } from "./recording";
import type { Alert, Outcome, Recording, Sensor, Source, Step, StepRole } from "./recording";

// Made once: building an Intl formatter on every call is slow, and these run on every frame.
const COUNT = new Intl.NumberFormat("en-US");
const DAY = new Intl.DateTimeFormat("en-GB", { day: "numeric", month: "short", year: "numeric", timeZone: "UTC" });

/** A count with thousands marked: 1,931. */
export function count(value: number): string {
  return COUNT.format(value);
}

/** "1 event", "3 events"; `many` for an irregular plural. */
export function plural(value: number, one: string, many = `${one}s`): string {
  return `${COUNT.format(value)} ${value === 1 ? one : many}`;
}

/** Upper-cases the first letter. */
export function capital(text: string): string {
  return text.charAt(0).toUpperCase() + text.slice(1);
}

const PLACES = new WeakMap<Recording, Map<string, { place: number; test: number | null }>>();

function placesOf(recording: Recording): Map<string, { place: number; test: number | null }> {
  let places = PLACES.get(recording);
  if (!places) {
    places = new Map();
    let tests = 0;
    recording.steps.forEach((step, index) => {
      if (step.role === "test") tests += 1;
      places?.set(step.id, { place: index + 1, test: step.role === "test" ? tests : null });
    });
    PLACES.set(recording, places);
  }
  return places;
}

/**
 * How a step is named to the viewer: "test 12" for a test, by its place among
 * the tests, and "step 3" for any other step, by its place in the run. A
 * step's `order` is not used: it skips positions that were not steps.
 */
export function stepLabel(recording: Recording, step: Step): string {
  const found = placesOf(recording).get(step.id);
  if (!found) return "step";
  return found.test !== null ? `test ${found.test}` : `step ${found.place}`;
}

/** A step's place among all the steps of the run, from 1: "step 3". */
export function stepPlace(recording: Recording, step: Step): string {
  const found = placesOf(recording).get(step.id);
  return found ? `step ${found.place}` : "step";
}

const RUN_PATH = /^\/[^/]+\/[^/]+\/actions\/runs\/\d+(\/.*)?$/;

/**
 * The address of the CI run that made the recording, only when it is a GitHub
 * Actions run over https, of the recording's own repository when it names one.
 * Null for anything else, so a recording cannot dress another site up as its run.
 */
export function runLink(source: Pick<Source, "repository"> & { run_url?: unknown }): string | null {
  const raw = source.run_url;
  if (typeof raw !== "string") return null;
  let address: URL;
  try {
    address = new URL(raw);
  } catch {
    return null;
  }
  if (address.protocol !== "https:" || address.host !== "github.com" || address.username !== "" || address.password !== "") return null;
  if (!RUN_PATH.test(address.pathname)) return null;
  if (source.repository !== undefined && !address.pathname.startsWith(`/${source.repository}/`)) return null;
  return address.href;
}

/** A time of day on the recording's clock, in UTC to the millisecond: 17:29:55.495. */
export function clockTime(ms: number): string {
  if (!Number.isFinite(ms)) return "";
  return new Date(ms).toISOString().slice(11, 23);
}

/** Seconds as minutes and seconds: 04:05.4, or 00:00.138 under a second when `fine`. */
export function elapsed(seconds: number, decimals = 1): string {
  const safe = Number.isFinite(seconds) ? Math.max(0, seconds) : 0;
  // Round first, so 239.95 s reads 04:00.0 and never 03:60.0.
  const factor = 10 ** decimals;
  const rounded = Math.round(safe * factor) / factor;
  const minutes = Math.floor(rounded / 60);
  const rest = rounded - minutes * 60;
  const text = rest.toFixed(decimals);
  const width = decimals > 0 ? 3 + decimals : 2;
  return `${String(minutes).padStart(2, "0")}:${text.padStart(width, "0")}`;
}

/** A length of time in words: 144 ms, 4.2 s, 1 min 5 s. */
export function span(ms: number): string {
  const safe = Number.isFinite(ms) ? Math.max(0, ms) : 0;
  if (safe < 1000) return `${Math.round(safe)} ms`;
  const seconds = safe / 1000;
  if (seconds < 59.5) return `${seconds < 9.95 ? seconds.toFixed(1) : Math.round(seconds)} s`;
  const whole = Math.round(seconds);
  const minutes = Math.floor(whole / 60);
  const rest = whole % 60;
  return rest > 0 ? `${minutes} min ${rest} s` : `${minutes} min`;
}

/** A date such as 23 Nov 2026, in UTC. */
export function day(iso: string): string {
  const ms = Date.parse(iso);
  if (Number.isNaN(ms)) return "";
  return DAY.format(ms);
}

/** A sensor's name without its version: "Sysmon for Linux 1.6.0" becomes "Sysmon for Linux". */
export function sensorShortName(name: string): string {
  return name.replace(/(\s+\d\S*)+$/, "").trim() || name;
}

/** The first word of a sensor's short name, for tight places: "Sysmon", "auditd". */
export function sensorWord(name: string): string {
  const short = sensorShortName(name);
  return short.split(/\s+/)[0] ?? short;
}

/** A detector's name split at " with ": the rule set and its engine. */
export function detectorParts(name: string): { main: string; engine: string } {
  const cut = name.indexOf(" with ");
  return cut > 0 ? { main: name.slice(0, cut), engine: name.slice(cut + 6) } : { main: name, engine: "" };
}

/** A CSS-friendly word for an outcome: "no effect" becomes "noeffect". */
export function outcomeClass(outcome: Outcome): string {
  return outcome.replace(/\s+/g, "");
}

/** The words shown for an outcome where it stands alone. */
export function outcomeWords(outcome: Outcome): string {
  return outcome === "seen" ? "seen, no alert" : outcome;
}

const ROLE_WORDS: Record<StepRole, string> = {
  test: "Test",
  canary: "Canary",
  control: "Control",
  hardened: "Hardened rerun",
  variant: "Variant",
};

export function roleWords(role: StepRole): string {
  return ROLE_WORDS[role];
}

/** Cuts long text in the middle and keeps its end from a slash, so a file name survives. */
export function middleCut(text: string, room: number): string {
  if (text.length <= room || room < 8) return text;
  const space = room - 1;
  let tail = "";
  for (let index = text.length - 1; index > 0; index -= 1) {
    if (text[index] === "/" && text.length - index <= space * 0.6) tail = text.slice(index);
  }
  if (!tail) tail = text.slice(text.length - Math.floor(space * 0.45));
  return `${text.slice(0, space - tail.length)}…${tail}`;
}

/** Upper-cases the first letter and drops a final full stop. */
export function sentence(text: string): string {
  const trimmed = text.trim().replace(/\.$/, "");
  return trimmed ? trimmed.charAt(0).toUpperCase() + trimmed.slice(1) : "";
}

/** How a match shows: an alert that counts, a lab rule that would alert, a match for review, or the launcher line. */
export type MatchKind = "alert" | "lab" | "review" | "launcher";

export function matchKind(alert: Alert): MatchKind {
  if (alert.launcher_only === true) return "launcher";
  if (countsForScore(alert)) return "alert";
  if (countsAsAlert(alert)) return "lab";
  return "review";
}

const KIND_RANK: Record<MatchKind, number> = { alert: 3, lab: 2, review: 1, launcher: 0 };

/** The stronger of two kinds of match. */
export function strongerKind(a: MatchKind | null, b: MatchKind): MatchKind {
  return a === null || KIND_RANK[b] > KIND_RANK[a] ? b : a;
}

export function kindRank(kind: MatchKind): number {
  return KIND_RANK[kind];
}

/** True when a detector holds the rules written in this repository, which are never scored. */
export function isLabDetector(recording: Recording, detectorId: string): boolean {
  if (detectorId === "lab") return true;
  const own = recording.alerts.filter((alert) => alert.detector === detectorId);
  return own.length > 0 && own.every((alert) => alert.rule.origin === "lab");
}

/** Colours of sensors, as RGB triples, given by the sensor's kind so the same tool keeps its colour on every host. */
const SENSOR_RGB = ["123,202,255", "226,236,246", "62,226,220", "158,180,255"];

export function sensorColours(sensors: readonly Sensor[]): Map<string, string> {
  const kinds: string[] = [];
  const colours = new Map<string, string>();
  for (const sensor of sensors) {
    const kind = sensorShortName(sensor.name);
    if (!kinds.includes(kind)) kinds.push(kind);
    colours.set(sensor.id, SENSOR_RGB[kinds.indexOf(kind) % SENSOR_RGB.length] ?? "123,202,255");
  }
  return colours;
}

/** Each test step's number among the tests: 1 for the first step of role `test`. Other roles have no entry. */
export function testNumbers(recording: Recording): Map<string, number> {
  const numbers = new Map<string, number>();
  let count = 0;
  for (const step of recording.steps) {
    if (step.role === "test") {
      count += 1;
      numbers.set(step.id, count);
    }
  }
  return numbers;
}

/**
 * How many events of ordinary activity, outside every step, a published rule
 * of this title alerted on: each such match is a false alert. 0 when the
 * recording says nothing of ordinary activity or the rule did not alert there.
 */
export function falseAlertsOf(recording: Recording, ruleTitle: string): number {
  const matches = recording.ordinary?.matches ?? [];
  return matches.filter((match) => match.rule === ruleTitle && (match.level === "high" || match.level === "critical")).reduce((sum, match) => sum + match.count, 0);
}

/** 1st, 2nd, 3rd, 4th, 11th, 21st. */
export function ordinal(value: number): string {
  const tens = value % 100;
  const ones = value % 10;
  const suffix = tens >= 11 && tens <= 13 ? "th" : ones === 1 ? "st" : ones === 2 ? "nd" : ones === 3 ? "rd" : "th";
  return `${COUNT.format(value)}${suffix}`;
}

/**
 * Where a step stands among the steps of its own role: "Test 39 of 60",
 * "Hardened rerun 10 of 12", or just "Control" when it is the only one.
 */
export function placeInRole(recording: Recording, step: Step): string {
  const same = recording.steps.filter((other) => other.role === step.role);
  const index = same.findIndex((other) => other.id === step.id);
  const name = roleWords(step.role);
  return same.length > 1 && index >= 0 ? `${name} ${index + 1} of ${same.length}` : name;
}


/** The step a hardened or variant step repeats, if the recording has it. */
export function comparedStep(recording: Recording, step: Step): Step | undefined {
  if (step.compared_with === undefined) return undefined;
  return recording.steps.find((other) => other.id === step.compared_with);
}

/** "took effect, seen, no alert": how a step went, in a few words. */
export function howItWent(step: Step): string {
  const parts: string[] = [step.outcome === "stopped" ? "stopped" : step.happened.answer];
  if (step.outcome !== "stopped" && step.outcome !== "no effect") parts.push(outcomeWords(step.outcome));
  return parts.join(", ");
}
