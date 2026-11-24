// Words and addresses for a pair of recorded runs: a delta that
// `bluefire-lab compare` wrote, as the Runs screen lists it and its page shows
// it. Nothing here compares two recordings: every verdict, count and reason is
// the delta's own, and these functions only put its names into words.

import { count, day, plural } from "../live/format";
import type { Delta, DeltaField, DeltaResult, DeltaSide, DeltaStep, DeltaSummary, RaceTimes } from "./api";

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

/** What a difference in the control is, by whether the lab's own code was the same in both runs. */
export function variationWords(delta: Pick<Delta, "lab_code">): string {
  return delta.lab_code.same ? "run variation" : "run variation or a change of the lab's code";
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
export function pairResultWords(summary: Pick<DeltaSummary, "comparable" | "refused_because" | "counts">): string {
  if (!summary.comparable) {
    const first = summary.refused_because[0];
    const more = summary.refused_because.length - 1;
    return `No verdict: ${first ?? "the comparison was refused"}${more > 0 ? ` (and ${plural(more, "more reason")})` : ""}`;
  }
  const c = summary.counts;
  const parts = [`${count(c.better)} better`, `${count(c.worse)} worse`];
  if (c.changed > 0) parts.push(`${count(c.changed)} changed`);
  parts.push(`${count(c["without cause"] + c["not attributable"])} changed without a cause`);
  return `${parts.join(", ")}, of ${plural(c.paired, "paired step")}`;
}

/** "GitHub-hosted runner, 23 Nov 2026": where and when one side ran, as far as the delta says. */
export function sideWhere(side: DeltaSide): string {
  const parts = [side.environment, side.started ? day(side.started) : undefined].filter((part): part is string => Boolean(part));
  return parts.length ? parts.join(", ") : "not recorded";
}

/** The steps the change moved: a verdict the delta gives, or, with no verdict, every step that differs. */
export function movedSteps(delta: Pick<Delta, "steps">): DeltaStep[] {
  return delta.steps.filter((step) => step.result === "better" || step.result === "worse" || step.result === "changed" || step.result === "no verdict");
}

/** The field whose outcome the step's chips show: the published rules', unless the change is judged only with the lab's rules. */
export function chipField(delta: Pick<Delta, "judged">): "outcome" | "outcome_with_lab_rules" {
  return delta.judged.length > 0 && !delta.judged.includes("outcome") && delta.judged.includes("outcome_with_lab_rules") ? "outcome_with_lab_rules" : "outcome";
}

/** A result the delta credits to the declared change; any other step that differs is not a gain or a loss. */
export function isCredited(result: DeltaResult): boolean {
  return result === "better" || result === "worse" || result === "changed";
}

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
export function verdictParts(step: Pick<DeltaStep, "verdict" | "price" | "result">): { before: string; price: string | null; after: string } {
  const lead = `${resultWords(step.result)}: `;
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
