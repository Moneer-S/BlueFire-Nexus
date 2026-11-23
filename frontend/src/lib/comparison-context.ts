import { sourceRunParam } from "./run-handoffs";

export const MAX_COMPARISON_RUNS = 32;
const contextKeys = ["compare_context", "compare_run", "compare_baseline", "compare_revised"];

export interface ComparisonSelection {
  runIds: string[];
  baselineId: string;
  revisedId: string;
}

export interface ComparisonContext extends ComparisonSelection {
  explicit: boolean;
  invalid: boolean;
}

function validId(value: string): boolean {
  return value.length > 0 && value.length <= 200 && value.trim() === value
    && !Array.from(value).some(character => character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127);
}

function validSelection(selection: ComparisonSelection): boolean {
  return selection.runIds.length <= MAX_COMPARISON_RUNS
    && selection.runIds.every(validId)
    && new Set(selection.runIds).size === selection.runIds.length
    && (!selection.baselineId || validId(selection.baselineId))
    && (!selection.revisedId || validId(selection.revisedId))
    && (!selection.revisedId || Boolean(selection.baselineId))
    && (!selection.baselineId || selection.runIds.length >= 2)
    && (!selection.revisedId || selection.revisedId !== selection.baselineId);
}

// This is navigation context only. Restoring it never compares, evaluates or runs.
export function readComparisonContext(params: URLSearchParams): ComparisonContext {
  const explicit = contextKeys.some(key => params.has(key));
  if (!explicit) {
    return { runIds: [...new Set([sourceRunParam(params, "source"), sourceRunParam(params, "replay")].filter(Boolean))], baselineId: "", revisedId: "", explicit: false, invalid: false };
  }
  const selection = { runIds: params.getAll("compare_run"), baselineId: params.get("compare_baseline") ?? "", revisedId: params.get("compare_revised") ?? "" };
  const invalid = params.get("compare_context") !== "1"
    || ["compare_context", "compare_baseline", "compare_revised"].some(key => params.getAll(key).length > 1)
    || ["compare_baseline", "compare_revised"].some(key => params.has(key) && !params.get(key))
    || !validSelection(selection);
  return invalid ? { runIds: [], baselineId: "", revisedId: "", explicit: true, invalid: true } : { ...selection, explicit: true, invalid: false };
}

export function clearComparisonContext(params: URLSearchParams): URLSearchParams {
  const next = new URLSearchParams(params);
  contextKeys.forEach(key => next.delete(key));
  return next;
}

export function writeComparisonContext(params: URLSearchParams, selection: ComparisonSelection): URLSearchParams {
  if (!validSelection(selection)) throw new Error("Invalid comparison selection.");
  const next = clearComparisonContext(params);
  next.set("compare_context", "1");
  selection.runIds.forEach(id => next.append("compare_run", id));
  if (selection.baselineId) next.set("compare_baseline", selection.baselineId);
  if (selection.revisedId) next.set("compare_revised", selection.revisedId);
  return next;
}
