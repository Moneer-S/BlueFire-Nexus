// Words and addresses for a pair of recorded runs: a delta that
// `bluefire-lab compare` wrote, as the Runs screen lists it and its page shows
// it. Nothing here compares two recordings: every verdict, count and reason is
// the delta's own, and these functions only put its names into words.

import { count, day, plural } from "../live/format";
import type { Recording, RecordingEvent } from "../live/recording";
import type { Delta, DeltaField, DeltaJudged, DeltaLabRule, DeltaLimit, DeltaMoved, DeltaResult, DeltaSide, DeltaStep, DeltaSummary, RaceTimes } from "./api";

/** The declared change of the lab's own rules, the one a single run can be evaluated twice for. */
export const LAB_RULES = "detectors:lab";

/** How a rule of the lab's own differs, as the lead of a title. */
const RULE_CHANGE: Record<DeltaLabRule["change"], string> = {
  new: "A new rule",
  gone: "A rule taken out",
  changed: "A changed rule",
  moved: "A rule moved to another file",
};

/** The words for one rule's change: "A new rule". */
export function ruleChangeWords(change: DeltaLabRule["change"]): string {
  return RULE_CHANGE[change];
}

/**
 * What changed, in the words a list and a page lead with: for a change of the
 * lab's rules that the delta names one by one, the rule ("A new rule: Shell
 * History File Truncated In Place"); otherwise the declared change.
 */
export function pairChangeWords(pair: Pick<Delta, "declared_change" | "lab_rules">): string {
  const rules = pair.declared_change === LAB_RULES ? pair.lab_rules ?? [] : [];
  const [only] = rules;
  if (rules.length === 1 && only) return `${ruleChangeWords(only.change)}: ${only.title}`;
  if (rules.length > 1) return `${count(rules.length)} of the lab's rules changed`;
  return changeWords(pair.declared_change);
}

/** True when the delta is one run whose telemetry was evaluated with two sets of the lab's rules. */
export function isOneRun(pair: Pick<Delta, "one_run">): boolean {
  return pair.one_run === true;
}

/** How one evaluation judged a rule: "not there", or accepted or not, with the lab's reason. */
export function judgedWords(judged: DeltaJudged | null): { word: string; reason: string | null } {
  if (judged === null) return { word: "not there", reason: null };
  return { word: judged.accepted ? "accepted" : "not accepted", reason: judged.reason ?? null };
}

/** The field a pair's moves are told in: the outcome with the lab's rules for a change of them, else the published rules'. */
function movedField(declared: string | null): "outcome" | "outcome_with_lab_rules" {
  return declared === LAB_RULES ? "outcome_with_lab_rules" : "outcome";
}

function listWords(items: readonly string[]): string {
  if (items.length <= 1) return items[0] ?? "";
  return `${items.slice(0, -1).join(", ")} and ${items[items.length - 1] ?? ""}`;
}

/**
 * What a pair moved, in one line for a list, from the steps its delta credits
 * to the change: "Clear Bash history (echo): unseen to seen", or "Clear Bash
 * history (echo) and Clear Bash history (cat dev/null), each also with changed
 * input arguments: seen to alerted with the lab's rules". Null when it moved
 * nothing, or the list does not say.
 */
export function movedWords(pair: Pick<DeltaSummary, "declared_change" | "moved">): string | null {
  const moved = pair.moved ?? [];
  if (moved.length === 0) return null;
  const field = movedField(pair.declared_change);
  const tests = [...new Set(moved.filter((step) => step.role === "test").map((step) => step.title))];
  const others = moved.filter((step) => step.role !== "test");
  // A run with changed input arguments of a test is a variant of it, under the test's title.
  const variantsOfEach = others.length === tests.length && others.every((step) => step.role === "variant" && tests.includes(step.title));
  const named = tests.length === 0 ? plural(moved.length, "step") : tests.length <= 3 ? listWords(tests) : plural(tests.length, "test");
  const rest = tests.length === 0 || others.length === 0 ? ""
    : variantsOfEach ? `, ${tests.length === 1 ? "also" : "each also"} with changed input arguments`
    : `, and ${plural(others.length, "other step")}`;
  const moves = [...new Set(moved.map((step) => `${step.before[field]} to ${step.after[field]}`))];
  const how = moves.length === 1 ? `${moves[0] ?? ""}${field === "outcome_with_lab_rules" ? " with the lab's rules" : ""}` : "moved";
  return `${named}${rest}: ${how}`;
}

/** The text of a rule of the lab's own as a recording carries it, with its file, or null when it does not. */
export function ruleText(recording: Recording, rule: string): { lines: string[]; file: string | null } | null {
  const lab = recording.network.detectors.find((detector) => detector.id === "lab");
  const verdict = lab?.verdicts?.find((item) => item.rule === rule);
  if (!verdict?.lines) return null;
  return { lines: verdict.lines, file: verdict.file ?? null };
}

/** The alerts of these rules of the lab's own on one step of a recording, each with the events it rests on. */
export function ruleAlerts(recording: Recording, rules: ReadonlySet<string>, stepId: string): { id: string; title: string; level: string; events: RecordingEvent[] }[] {
  const events = new Map(recording.events.map((event) => [event.id, event]));
  return recording.alerts
    .filter((alert) => alert.step === stepId && alert.rule.origin === "lab" && rules.has(alert.rule.id) && alert.launcher_only !== true)
    .map((alert) => ({
      id: alert.id,
      title: alert.rule.title,
      level: alert.rule.level,
      events: alert.events.map((id) => events.get(id)).filter((event): event is RecordingEvent => event !== undefined),
    }));
}

/**
 * A price cut at its first parenthesis: the lab's lead, and what it quotes in
 * the parenthesis, so that a price every moved step shares is said once in
 * full and each step carries its lead.
 */
export function priceLead(price: string): { lead: string; quoted: string | null } {
  const at = price.indexOf(" (");
  if (at < 0 || !price.endsWith(")")) return { lead: price, quoted: null };
  return { lead: price.slice(0, at), quoted: price.slice(at + 2, -1) };
}

/** The one price every moved step of a delta shares, or null when they differ or have none. */
export function sharedPrice(steps: readonly Pick<DeltaStep, "price">[]): string | null {
  const prices = new Set(steps.flatMap((step) => (step.price ? [step.price] : [])));
  const [only] = prices;
  return prices.size === 1 && only ? only : null;
}

/** The setup's groups in words, as the lab's `delta.md` names them. */
const GROUPS: Record<string, string> = {
  atomic_commit: "the tests' commit",
  images: "the image of host",
  kernels: "the kernel of host",
  sensors: "the settings of sensor",
  detectors: "the rules of detector",
  tools: "the version of",
};

/** A name of the setup in words: `sensors:auditd` is "the settings of sensor auditd". */
export function setupWords(name: string): string {
  const cut = name.indexOf(":");
  if (cut < 0) return GROUPS[name] ?? name;
  const group = name.slice(0, cut);
  const member = name.slice(cut + 1);
  const words = GROUPS[group];
  return words ? `${words} ${member}` : `${group} ${member}`;
}

/** The declared change in words, or that nothing was declared. */
export function changeWords(declared: string | null): string {
  return declared === null ? "Nothing declared as changed" : capitalFirst(setupWords(declared));
}

function capitalFirst(text: string): string {
  return text.charAt(0).toUpperCase() + text.slice(1);
}

const HEX_DIGEST = /^[0-9a-f]{64}$/;

/** A SHA-256 shown by its first 12 digits; anything else as it is. Null is "not recorded". */
export function shortValue(value: string | null): string {
  if (value === null) return "not recorded";
  return HEX_DIGEST.test(value) ? `${value.slice(0, 12)}…` : value;
}

/** True when a value is a digest that is shown shortened. */
export function isDigest(value: string | null): value is string {
  return value !== null && HEX_DIGEST.test(value);
}

const FIELD_WORDS: Record<DeltaField, string> = {
  happened: "what happened",
  recorded: "whether a sensor recorded the step",
  outcome: "the outcome by the published rules",
  outcome_with_lab_rules: "the outcome with the lab's rules",
};

/** "what happened, whether a sensor recorded the step and the outcome by the published rules". */
export function fieldsWords(fields: readonly DeltaField[]): string {
  const words = fields.map((field) => FIELD_WORDS[field]);
  if (words.length <= 1) return words[0] ?? "nothing";
  return `${words.slice(0, -1).join(", ")} and ${words[words.length - 1] ?? ""}`;
}

/**
 * What a difference in the control is, by whether the lab's own code was the
 * same in both runs and, under a limit, with the runners' difference beside it,
 * as the lab's `delta.md` says it.
 */
export function variationWords(delta: Pick<Delta, "lab_code" | "limit">): string {
  const variation = delta.lab_code.same ? "run variation" : "run variation or a change of the lab's code";
  return delta.limit ? `${variation} or the runners' difference` : variation;
}

/** The delta's limit, or null when its verdict is like with like (or there is none). */
export function limitOf(delta: Pick<Delta, "limit">): DeltaLimit | null {
  return delta.limit ?? null;
}

/** The rows of `differences` that the limit names: what differed between the two runners, with both values. */
export function runnerDifferences(delta: Pick<Delta, "limit" | "differences">): Delta["differences"] {
  const limit = limitOf(delta);
  if (!limit) return [];
  return limit.differences.map((name) => delta.differences.find((row) => row.what === name) ?? { what: name, before: null, after: null });
}

/**
 * What the limit credits, in the delta's own words: its `credits` with the
 * lead "only a step that carries the change's own mark: " cut, so that the
 * page can say the lead once in its own heading.
 */
export function creditsWords(limit: DeltaLimit): { lead: string; rest: string } {
  const cut = limit.credits.indexOf(": ");
  return cut < 0 ? { lead: limit.credits, rest: "" } : { lead: limit.credits.slice(0, cut), rest: limit.credits.slice(cut + 2) };
}

/** The sentence under the claim: the setup the two runs shared, as far as the delta says. */
export function setupLede(delta: Pick<Delta, "declared_change" | "runners" | "limit" | "lab_code" | "one_run">): string {
  if (isOneRun(delta)) {
    return "One run, evaluated twice: the list ran once, on one runner, and its telemetry was read with the lab's rules as they were before the change and after it. Not a pair of runs, so no second runner and no run variation: its steps, events, published rules' alerts and ordinary activity are the same in both evaluations, as the lab and BlueFire checked.";
  }
  if (delta.declared_change === null) return `The same steps, made with the same setup. Nothing was declared as changed, so a step that differs is ${variationWords(delta)}, not an effect.`;
  // The limit's own box, right below, says in what the runners differed.
  if (limitOf(delta)) return "The same steps, made side by side in one CI run on two fresh runners.";
  if (delta.runners === 2) return "The same steps, made with the same setup apart from this change, side by side in one CI run, each on a fresh runner of its own.";
  return "The same steps, made with the same setup apart from this change.";
}

/** What a sensor recorded of a step in one run only, each side that holds something, with how many lines are shown. */
export function recordsParts(records: NonNullable<DeltaStep["records"]>): { label: string; count: number; lines: string[]; more: number }[] {
  return ([["new", "after"], ["gone", "before"]] as const)
    .map(([key, run]) => ({ part: records[key], run }))
    .filter(({ part }) => part.count > 0)
    .map(({ part, run }) => ({ label: `Only in the ${run} run`, count: part.count, lines: part.lines, more: Math.max(0, part.count - part.lines.length) }));
}

/**
 * Under a limit, the audit keys of a step's events that the delta says can
 * carry no mark of the change's own, each with why not in the lab's words:
 * a key only one run's events carry is not by that the change's own.
 */
export function noMarkKeys(delta: Pick<Delta, "limit" | "audit_keys">, step: Pick<DeltaStep, "id" | "before_id">): { key: string; run: "before" | "after"; why: string }[] {
  if (!limitOf(delta) || !delta.audit_keys) return [];
  const found: { key: string; run: "before" | "after"; why: string }[] = [];
  for (const [run, keys, stepId] of [["after", delta.audit_keys.only_after, step.id], ["before", delta.audit_keys.only_before, step.before_id ?? step.id]] as const) {
    for (const [key, entry] of Object.entries(keys)) {
      if (entry.mark === false && typeof entry.no_mark === "string" && entry.steps.includes(stepId)) found.push({ key, run, why: entry.no_mark });
    }
  }
  return found;
}

/**
 * The control in one sentence: "What happened, which this change cannot move,
 * was the same on 91 of 91 paired steps." With nothing declared every field is
 * the control.
 */
export function controlWords(delta: Pick<Delta, "control" | "declared_change">): string {
  const { fields, same, of } = delta.control;
  const why = delta.declared_change === null ? "every field, since nothing was declared" : "which this change cannot move";
  return `${capitalFirst(fieldsWords(fields))}, ${why}: the same on ${count(same)} of ${plural(of, "paired step")}.`;
}

/**
 * One line of a pair's result for a list: "1 better, 0 worse, 0 changed
 * without a cause, of 91 steps", or "No verdict: <the first reason>".
 */
export function pairResultWords(summary: Pick<DeltaSummary, "comparable" | "refused_because" | "counts" | "limit">): string {
  if (!summary.comparable) {
    const first = summary.refused_because[0];
    const more = summary.refused_because.length - 1;
    return `No verdict: ${first ?? "the comparison was refused"}${more > 0 ? ` (and ${plural(more, "more reason")})` : ""}`;
  }
  const c = summary.counts;
  const parts = [`${count(c.better)} better`, `${count(c.worse)} worse`];
  if (c.changed > 0) parts.push(`${count(c.changed)} changed`);
  if (summary.limit) {
    // Under a limit a step is credited only by the change's own mark, and any other that differs may be the runners'.
    const rest = c["without cause"] > 0 ? [`${count(c["without cause"])} changed without a cause`] : [];
    return `Limited verdict, the runners differed: ${parts.join(", ")}, ${count(c.by_mark ?? 0)} of them by the change's own mark alone; ${[`${count(c["not attributable"])} not attributable`, ...rest].join(", ")}; of ${plural(c.paired, "paired step")}`;
  }
  parts.push(`${count(c["without cause"] + c["not attributable"])} changed without a cause`);
  return `${parts.join(", ")}, of ${plural(c.paired, "paired step")}`;
}

/** "GitHub-hosted runner, 23 Nov 2026": where and when one side ran, as far as the delta says. */
export function sideWhere(side: DeltaSide): string {
  const parts = [side.environment, side.started ? day(side.started) : undefined].filter((part): part is string => Boolean(part));
  return parts.length ? parts.join(", ") : "not recorded";
}

/** A result the delta credits to the declared change; any other step that differs is not a gain or a loss. */
export function isCredited(result: DeltaResult): boolean {
  return result === "better" || result === "worse" || result === "changed";
}

/** How the verdict of a step credited by the change's own mark goes on after its result. */
export const MARK_LEAD = "by the change's own mark, on two runners that differed";

/** A step's result as its tag says it, in the words its verdict starts with. */
export function resultWords(result: DeltaResult): string {
  return result === "without cause" ? "changed without a cause" : result;
}

/**
 * The verdict cut around its price, so the price can be drawn on the same line
 * but apart: the delta's own words, never rewritten. The result the verdict
 * starts with is left to the step's tag; a price the verdict does not hold is
 * put after it, so a gain is never drawn without its price.
 */
export function verdictParts(step: Pick<DeltaStep, "verdict" | "price" | "result" | "mark">): { before: string; price: string | null; after: string } {
  // A step credited by the change's own mark says so in a tag of its own, so its lead goes with the result's.
  const lead = step.mark ? `${resultWords(step.result)} ${MARK_LEAD}: ` : `${resultWords(step.result)}: `;
  const verdict = step.verdict.startsWith(lead) ? step.verdict.slice(lead.length) : step.verdict;
  if (!step.price) return { before: verdict, price: null, after: "" };
  const at = verdict.indexOf(step.price);
  if (at < 0) return { before: `${verdict}; `, price: step.price, after: "" };
  return { before: verdict.slice(0, at), price: step.price, after: verdict.slice(at + step.price.length) };
}

/** The lab's text with its `code spans` cut out, to be drawn as code: still text, never HTML. */
export function codeSpans(text: string): { text: string; code: boolean }[] {
  return text.split("`").map((part, index) => ({ text: part, code: index % 2 === 1 })).filter((part) => part.text !== "");
}

/** The race in one line, only when the delta has one with numbers; otherwise, quietly, why there is none. */
export function raceWords(race: Delta["race"]): { quiet: boolean; text: string } {
  if ("why" in race) return { quiet: true, text: `No race: ${race.why}.` };
  const side = (label: string, times: RaceTimes) => {
    const parts: string[] = [];
    if (times.first_alert_seconds !== undefined) parts.push(`first alert after ${times.first_alert_seconds} s`);
    if (times.goal_seconds !== undefined) parts.push(`the goal after ${times.goal_seconds} s`);
    return parts.length ? `${label}: ${parts.join(", ")}` : null;
  };
  const before = side("Before", race.before), after = side("After", race.after);
  if (before === null && after === null) return { quiet: true, text: "No race: neither run recorded a first alert or the goal." };
  return { quiet: false, text: `${before ?? "Before: not recorded"}. ${after ?? "After: not recorded"}.` };
}

/** The path of a pair's page inside the app. */
export function pairPath(id: string): string {
  return `/runs/compared/${encodeURIComponent(id)}`;
}

/**
 * The field every mark of a pair is drawn in, on its page, on the Runs screen
 * and on the Overview: what the published rules and the lab's own rules made
 * of a step together. A step that only the lab's rules alert on is drawn in the
 * live view's violet, so the one field never hides whose rule it was.
 */
export const MARK_FIELD = "outcome_with_lab_rules";

type MarkSide = Pick<DeltaStep["before"], "outcome" | "outcome_with_lab_rules">;
type MovedLike = Pick<DeltaMoved, "role" | "title" | "before" | "after">;

/** True when only the lab's own rules alerted on the step: the published rules did not. */
export function alertedByLabOnly(side: MarkSide): boolean {
  return side[MARK_FIELD] === "alerted" && side.outcome !== "alerted";
}

const NUMBER_WORDS = ["No", "One", "Two", "Three", "Four", "Five", "Six", "Seven", "Eight", "Nine", "Ten", "Eleven", "Twelve"];

/** "One", "Four", or 13 and above in figures: a count as a headline says it. */
export function numberWord(value: number): string {
  return NUMBER_WORDS[value] ?? count(value);
}

/** How many steps the delta credits to the change. */
export function creditedCount(counts: Pick<DeltaSummary["counts"], "better" | "worse" | "changed">): number {
  return counts.better + counts.worse + counts.changed;
}

const FROM_WORDS: Partial<Record<DeltaStep["before"]["outcome"], [string, string]>> = {
  unseen: ["that nobody saw", "that nobody saw"],
  seen: ["that was seen with no alert", "that were seen with no alert"],
  alerted: ["that raised an alert", "that raised an alert"],
  stopped: ["that was stopped", "that were stopped"],
};
const TO_WORDS: Partial<Record<DeltaStep["before"]["outcome"], [string, string]>> = {
  unseen: ["is now unseen", "are now unseen"],
  seen: ["is now seen", "are now seen"],
  alerted: ["now raises an alert", "now raise an alert"],
  stopped: ["is now stopped", "are now stopped"],
};

/**
 * What the change did, in one sentence, from the steps the delta credits to
 * it: "One test that nobody saw is now seen." The count is the delta's own; the
 * listed steps give the words, only when the list holds every credited step
 * (a list entry is cut at 20) and every one moved the same way.
 */
export function pairHeadline(pair: Pick<DeltaSummary, "comparable" | "declared_change" | "counts">, moved: readonly MovedLike[]): string {
  if (!pair.comparable) return "No verdict.";
  if (pair.declared_change === null) return "Nothing was declared as changed.";
  const total = creditedCount(pair.counts);
  if (total === 0) return "No step moved.";
  const many = total === 1 ? 0 : 1;
  const tests = moved.length === total && moved.every((step) => step.role === "test");
  const noun = tests ? (total === 1 ? "test" : "tests") : total === 1 ? "step" : "steps";
  const [first] = moved;
  const from = first?.before[MARK_FIELD];
  const to = first?.after[MARK_FIELD];
  const alike = first !== undefined && moved.every((step) => step.before[MARK_FIELD] === from && step.after[MARK_FIELD] === to);
  const fromWords = from === undefined ? undefined : FROM_WORDS[from]?.[many];
  const toWords = to === undefined ? undefined : TO_WORDS[to]?.[many];
  if (moved.length !== total || !alike || !fromWords || !toWords) return `${numberWord(total)} ${noun} moved.`;
  return `${numberWord(total)} ${noun} ${fromWords} ${toWords}.`;
}

/**
 * The short name of a turn of the loop, the same wherever it is shown: "New
 * auditd settings", "A new rule", or the declared change in words.
 */
export function turnName(pair: Pick<Delta, "declared_change" | "lab_rules">): string {
  const declared = pair.declared_change;
  if (declared === null) return "Nothing declared";
  if (declared.startsWith("sensors:")) return `New ${declared.slice("sensors:".length)} settings`;
  const rules = declared === LAB_RULES ? pair.lab_rules ?? [] : [];
  const [only] = rules;
  if (rules.length === 1 && only) return ruleChangeWords(only.change);
  if (rules.length > 1) return `${count(rules.length)} of the lab's rules changed`;
  return changeWords(declared);
}

/** How the comparison was made, in the lab's terms, small: "Two runs side by side, 24 Nov 2026". */
export function methodWords(pair: Pick<Delta, "before" | "after" | "runners" | "one_run">): string {
  const dates = [pair.before.started, pair.after.started].map((started) => (started ? day(started) : "not recorded"));
  if (isOneRun(pair)) return `One run evaluated with two rule sets, ${dates[0] ?? ""}`;
  if (pair.runners === 2) return `Two runs side by side, ${dates[1] === dates[0] ? dates[0] ?? "" : `${dates[0] ?? ""} and ${dates[1] ?? ""}`}`;
  return `Before ${dates[0] ?? ""}, after ${dates[1] ?? ""}`;
}

/** The basis of every verdict of a pair and when it was made, as one sentence a careful reader finds without opening anything. */
export function basisWords(pair: Pick<Delta, "claim" | "runners" | "one_run" | "before" | "after">): string {
  const [first = "", second = ""] = [pair.before.started, pair.after.started].map((started) => (started ? day(started) : "not recorded"));
  if (isOneRun(pair)) return `One run, its telemetry read with two rule sets, ${first}.`;
  if (pair.runners === 2) return `One pair of runs, made side by side in one CI run, ${second === first ? first : `${first} and ${second}`}.`;
  return `It rests on ${pair.claim}: before ${first}, after ${second}.`;
}

const COUNTED_PRICE = /^price: published rules that alerted on ordinary activity: (\d+) before, (\d+) after(;|$)/;

/**
 * A price in the page's plain words, short enough for a card: what the
 * delta's price says of the published rules that alerted on ordinary activity,
 * or that it is not counted or not known and why. A price the lab words in
 * any other way is shown as its lead, as it is.
 */
export function priceWords(price: string): string {
  const counted = COUNTED_PRICE.exec(price);
  if (counted) {
    const before = Number(counted[1]), after = Number(counted[2]);
    if (before === after) return `${count(before)} published ${before === 1 ? "rule alerts" : "rules alert"} on ordinary activity, before and after`;
    return `Published rules alerting on ordinary activity: ${count(before)} before, ${count(after)} after`;
  }
  if (price.startsWith("price not counted")) return "Not counted: the lab keeps its own rules' matches on ordinary activity out of the recording";
  if (price.startsWith("price not known")) return "Not known: each run counted its ordinary activity on a runner of its own, and the runners differed";
  return capitalFirst(priceLead(price).lead);
}

/**
 * A price for a list, in plain words, when every listed step has the same
 * price; null when there is none to say.
 */
export function listedPrice(moved: readonly Pick<DeltaMoved, "price">[]): { words: string; shared: boolean } | null {
  const price = sharedPrice(moved);
  if (price) return { words: priceWords(price), shared: true };
  const any = moved.find((step) => step.price !== undefined)?.price;
  return any ? { words: "Each step has a price of its own, said on the page", shared: false } : null;
}

/**
 * The titles of steps as one phrase, a family said once: "Clear Bash history
 * (echo) and (cat dev/null)".
 */
export function titlesWords(steps: readonly Pick<DeltaMoved, "title">[]): string {
  const titles = [...new Set(steps.map((step) => step.title))];
  const [first] = titles;
  if (!first) return "";
  const cut = first.indexOf(" (");
  const stem = cut > 0 ? first.slice(0, cut) : "";
  if (titles.length > 1 && stem && titles.every((title) => title.startsWith(`${stem} (`))) {
    return `${stem} ${listWords(titles.map((title) => title.slice(stem.length + 1)))}`;
  }
  return listWords(titles);
}
