// Small pure helpers for the words and numbers the live view shows.

import { countsAsAlert, countsForScore, timeOf } from "./recording";
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

/**
 * What one step of a recording is called, the one place the word is decided:
 * on an attack path each step is a step of the path ("step 9", "11 steps"),
 * though it runs a published test, which keeps its own title; in a list of
 * tests on one host each test is a test ("test 39", "60 tests"). Every part of
 * the view that names or counts the steps asks this.
 */
export function unitWord(recording: Pick<Recording, "kind">): "step" | "test" {
  return recording.kind === "attack path" ? "step" : "test";
}

/** A step's name in a sentence, and the short form a table cell or an axis label has room for. */
interface StepName {
  name: string;
  short: string;
}

const NAMES = new WeakMap<Recording, Map<string, StepName>>();

/** What a role is called in a step's name: in a sentence, and in the short form. */
const NAME_WORDS: Record<StepRole, [string, string]> = {
  test: ["test", "test"],
  canary: ["canary", "canary"],
  control: ["control", "control"],
  hardened: ["hardened rerun", "rerun"],
  variant: ["variant", "variant"],
};

function namesOf(recording: Recording): Map<string, StepName> {
  const cached = NAMES.get(recording);
  if (cached) return cached;
  const names = new Map<string, StepName>();
  const known = new Set(recording.steps.map((step) => step.id));
  // A rerun of a step the recording holds is named by that step; any other step by its count among its role.
  const group = (step: Step) => (step.compared_with !== undefined && known.has(step.compared_with) ? `${step.role}>${step.compared_with}` : step.role);
  const totals = new Map<string, number>();
  for (const step of recording.steps) totals.set(group(step), (totals.get(group(step)) ?? 0) + 1);
  const counts = new Map<string, number>();
  for (const step of recording.steps) {
    const key = group(step);
    const count = (counts.get(key) ?? 0) + 1;
    counts.set(key, count);
    const total = totals.get(key) ?? 1;
    const [word, shortWord] = NAME_WORDS[step.role];
    // A rerun repeats a step before it, which is named already.
    const of = step.compared_with === undefined ? undefined : names.get(step.compared_with);
    if (step.role === "test") names.set(step.id, { name: `${unitWord(recording)} ${count}`, short: `${unitWord(recording)} ${count}` });
    else if (of) {
      const which = total > 1 ? ` ${count}` : "";
      names.set(step.id, { name: `${word}${which} of ${of.name}`, short: `${shortWord}${which} of ${of.short}` });
    } else if (total === 1) names.set(step.id, { name: `the ${word}`, short: word });
    else names.set(step.id, { name: `${word} ${count}`, short: `${word} ${count}` });
  }
  NAMES.set(recording, names);
  return names;
}

/**
 * How a step is named to the viewer, the same everywhere: a test is "test 12",
 * its count among the tests in run order, as the score counts them; any other
 * step is named by its role, and a rerun by the step it repeats: "canary 1",
 * "the control", "hardened rerun of test 12", "variant 2 of test 39". A place
 * in the list of steps is never a name; the address takes the step's `id`.
 */
export function stepLabel(recording: Recording, step: Step): string {
  return namesOf(recording).get(step.id)?.name ?? "a step";
}

/** The short form of a step's name, for a table cell or an axis label: "test 12", "canary", "rerun of test 12". */
export function stepShortName(recording: Recording, step: Step): string {
  return namesOf(recording).get(step.id)?.short ?? "step";
}

/**
 * What the recording says of a step nobody saw, as the end of a sentence: its
 * own `visibility.basis`, "nothing of the test was recorded besides its
 * launcher's start", so a recording of another engine is told in its words.
 */
export function unseenWords(step: Step): string {
  const basis = step.visibility.basis.trim().replace(/\.$/, "");
  if (!basis) return "nothing of it was recorded";
  // Lower-cased to sit inside a sentence, unless it starts with a name or an acronym: "EDR saw nothing".
  return /^\p{Lu}\p{Ll}/u.test(basis) ? basis.charAt(0).toLowerCase() + basis.slice(1) : basis;
}

/** The one basis every unseen test of the recording shares, or null when they differ or there is none. */
export function sharedUnseenWords(recording: Recording): string | null {
  const words = new Set(recording.steps.filter((step) => step.role === "test" && step.outcome === "unseen").map(unseenWords));
  return words.size === 1 ? ([...words][0] ?? null) : null;
}

/**
 * True when the recording says, in the lab's words, that the one record of a
 * step is its launcher's start: the lab's harness starting the test's command,
 * which never counts. Any other basis is told in its own words.
 */
export function onlyItsLaunch(step: Step): boolean {
  return /\bbesides its launcher's start\b/i.test(step.visibility.basis);
}

/** The direction marks, embeddings, overrides and isolates, which free text may hold. */
const DIRECTION = /[\u061C\u200E\u200F\u202A-\u202E\u2066-\u2069]/g;

/** A direction character as its code: "U+202E". */
export function markCode(mark: string): string {
  return `U+${(mark.codePointAt(0) ?? 0).toString(16).toUpperCase().padStart(4, "0")}`;
}

/**
 * Free text with each direction character written as its code, so it cannot
 * reorder what is shown: for a tooltip, a spoken sentence or the page's title.
 * Visible text goes through `FreeText`, which shows the code in a tag.
 */
export function plainMarks(text: string): string {
  return text.replace(DIRECTION, (mark) => `[${markCode(mark)}]`);
}

/** Free text cut at its direction characters: text, and each mark on its own. */
export function markParts(text: string): { text: string; mark: boolean }[] {
  const parts: { text: string; mark: boolean }[] = [];
  let from = 0;
  for (const found of text.matchAll(DIRECTION)) {
    const at = found.index;
    if (at > from) parts.push({ text: text.slice(from, at), mark: false });
    parts.push({ text: found[0], mark: true });
    from = at + found[0].length;
  }
  if (from < text.length) parts.push({ text: text.slice(from), mark: false });
  return parts;
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
  const ms = timeOf(iso);
  if (Number.isNaN(ms)) return "";
  return DAY.format(ms);
}

/** Where a run ran, after "on": "on a GitHub-hosted runner", but "on containers on a developer machine": no article before a plural. */
export function onEnvironment(environment: string): string {
  const first = environment.trim().split(/\s+/)[0] ?? "";
  if (/^(a|an|the)$/i.test(first) || /[^s]s$/i.test(first)) return `on ${environment}`;
  return `on ${/^[aeiou]/i.test(first) ? "an" : "a"} ${environment}`;
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

/**
 * A sensor's name for a label, without its version: its short name (`name`),
 * its first word where room is tight (`word`), or for a table's column, its
 * first word (`column`). When another sensor of the recording has the same
 * short name, such as a Wazuh agent on each host of a range, the label names
 * its host too: "Wazuh agent on web", "Wazuh on web", and in a column, where
 * only a word fits, the host alone: "web".
 */
export function sensorLabel(recording: Pick<Recording, "network">, sensor: Sensor, room: "name" | "word" | "column" = "name"): string {
  const short = sensorShortName(sensor.name);
  const shared = recording.network.sensors.some((other) => other.id !== sensor.id && sensorShortName(other.name) === short);
  // A sensor told apart by its host keeps its kind with its name ("Wazuh agent on web"), so it never reads as the engine of the same name.
  const name = room === "name" || shared ? short : sensorWord(sensor.name);
  const host = shared ? recording.network.hosts.find((item) => item.id === sensor.host)?.name : undefined;
  if (!host) return name;
  return room === "column" ? host : `${name} on ${host}`;
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

/** How a match shows: an alert that counts, a lab alert, a match for review, or the launcher line. */
export type MatchKind = "alert" | "lab" | "review" | "launcher";

export function matchKind(alert: Alert): MatchKind {
  if (alert.launcher_only === true) return "launcher";
  if (countsForScore(alert)) return "alert";
  if (countsAsAlert(alert)) return "lab";
  return "review";
}

const KIND_RANK: Record<MatchKind, number> = { alert: 3, lab: 2, review: 1, launcher: 0 };

/** A match of an ad hoc lab rule at alert level is a "lab alert", on every screen: the score does not count it. */
export const MARK_WORDS: Readonly<Record<MatchKind, string>> = { alert: "alert", lab: "lab alert", review: "review", launcher: "" };

/**
 * When a live alert was raised against the end of the step it matched, in the
 * one wording every part of the view uses: "raised 922 ms after the step
 * ended". Null when it was raised by the step's end, or when the recording
 * gives no time for either.
 */
export function raisedAfterStep(alert: Alert, step: Step | undefined, which = "the step"): string | null {
  if (alert.raised === undefined || step?.ended === undefined) return null;
  const after = timeOf(alert.raised) - timeOf(step.ended);
  return Number.isFinite(after) && after > 0 ? `raised ${span(after)} after ${which} ended` : null;
}

/**
 * The mark some matches give a line: the strongest kind among them, and its
 * word, which is "informational" where every match below alert level is
 * informational, since nobody reviews those. Null when only the launcher line matched.
 */
export function markOf(alerts: readonly Alert[]): { kind: MatchKind; word: string } | null {
  let kind: MatchKind | null = null;
  let reviewed = false;
  for (const alert of alerts) {
    const own = matchKind(alert);
    if (own === "launcher") continue;
    kind = strongerKind(kind, own);
    if (own === "review" && alert.rule.level !== "informational") reviewed = true;
  }
  if (kind === null) return null;
  return { kind, word: kind === "review" && !reviewed ? "informational" : MARK_WORDS[kind] };
}

/** Each event's mark, from the matches that name it. */
export function eventMarks(alerts: Iterable<Alert>): Map<string, { kind: MatchKind; word: string }> {
  const byEvent = new Map<string, Alert[]>();
  for (const alert of alerts) {
    for (const id of alert.events) {
      const list = byEvent.get(id);
      if (list) list.push(alert);
      else byEvent.set(id, [alert]);
    }
  }
  const marks = new Map<string, { kind: MatchKind; word: string }>();
  for (const [id, list] of byEvent) {
    const mark = markOf(list);
    if (mark) marks.set(id, mark);
  }
  return marks;
}

/** The stronger of two kinds of match. */
export function strongerKind(a: MatchKind | null, b: MatchKind): MatchKind {
  return a === null || KIND_RANK[b] > KIND_RANK[a] ? b : a;
}

export function kindRank(kind: MatchKind): number {
  return KIND_RANK[kind];
}

/** True when a detector holds ad hoc local rules, which are never scored. */
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
 * How many events of ordinary activity, outside every step, a rule in the
 * scored defense with this title alerted on. These are events, not false alerts: a rule that
 * alerted there is one false alert, however many events it matched, as the
 * score counts. 0 when the recording says nothing of ordinary activity or the
 * rule did not alert there.
 */
export function ordinaryAlertEvents(recording: Recording, ruleTitle: string): number {
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
 * The rules in the scored defense that matched a step below alert level, of `alerts`, by
 * distinct rule: those for review, and those at informational level, which
 * nobody reviews and which are counted apart.
 */
export function belowAlert(alerts: readonly Alert[]): { review: number; info: number } {
  const review = new Set<string>();
  const info = new Set<string>();
  for (const alert of alerts) {
    if (alert.counts || alert.launcher_only === true || alert.rule.origin !== "pinned") continue;
    (alert.rule.level === "informational" ? info : review).add(alert.rule.id);
  }
  return { review: review.size, info: info.size };
}

/** "3 rules matched for review", "1 informational rule matched", or "no rule matched": `belowAlert` in words. */
export function belowAlertWords(alerts: readonly Alert[]): string {
  const { review, info } = belowAlert(alerts);
  const parts = [review > 0 ? `${plural(review, "rule")} matched for review` : "", info > 0 ? `${plural(info, "informational rule")} matched` : ""].filter(Boolean);
  return parts.length > 0 ? parts.join(", ") : "no rule matched";
}

/** A rule's title for the middle of a sentence: without the full stop many rule titles end with. */
export function titleInSentence(title: string): string {
  return title.replace(/\.$/, "");
}

/** How many rules in the scored defense, by distinct rule, matched only the line that started the step, which never counts. */
export function launcherRules(alerts: readonly Alert[]): number {
  return new Set(alerts.filter((alert) => alert.launcher_only === true && alert.rule.origin === "pinned").map((alert) => alert.rule.id)).size;
}

/**
 * A seen step in one sentence: "24 events recorded, 1 rule matched for
 * review, none at alert level." Where an ad hoc lab rule alerted, the last
 * words say they speak of the rules in the scored defense; where no rule
 * matched, they are left out. Where the only scored-defense match was on the launcher line,
 * the sentence says so: "1 rule matched only the launcher line, which never counts."
 */
export function seenWords(events: number, alerts: readonly Alert[]): string {
  const { review, info } = belowAlert(alerts);
  const lab = alerts.some((alert) => matchKind(alert) === "lab");
  const matched = review + info > 0;
  const launcher = launcherRules(alerts);
  if (!matched && launcher > 0) return `${plural(events, "event")} recorded, ${plural(launcher, "rule")}${lab ? " in this defense" : ""} matched only the launcher line, which never counts.`;
  if (!matched) return `${plural(events, "event")} recorded, ${lab ? "no rule in this defense matched" : "no rule matched"}.`;
  return `${plural(events, "event")} recorded, ${belowAlertWords(alerts)}, ${lab ? "none of the rules in this defense at alert level" : "none at alert level"}.`;
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
