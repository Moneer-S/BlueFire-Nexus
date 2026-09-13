import type { RunPresentation, RunRecord } from "../types";
import { displayTitle } from "./display-title";

type NamedRun = Pick<RunRecord, "scenario" | "scenario_title" | "objective" | "scenario_id" | "presentation"> & { run_id?: string };

export function isRunPresentation(value: unknown, runId: string): value is RunPresentation {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const item = value as Partial<RunPresentation>;
  return item.schema_version === "bluefire.run-presentation.v1" && item.run_id === runId
    && (item.display_name === null || (typeof item.display_name === "string"
      && item.display_name === item.display_name.trim() && [...item.display_name].length >= 1
      && [...item.display_name].length <= 120 && !/[\p{Cc}\p{Cf}\p{Cs}\p{Cn}\p{Zl}\p{Zp}]/u.test(item.display_name)))
    && typeof item.default_name === "string" && Boolean(item.default_name.trim())
    && (item.updated_at === null || (typeof item.updated_at === "string" && Number.isFinite(Date.parse(item.updated_at))));
}

// Keep editor values exact; the readable label is a separate projection.
export function runNameValue(run: NamedRun): string {
  if (run.run_id && isRunPresentation(run.presentation, run.run_id)) {
    return run.presentation.display_name ?? run.presentation.default_name;
  }
  return run.scenario?.title?.trim() || run.scenario_title?.trim() || "Run";
}

export function runLabel(run: NamedRun): string {
  return displayTitle(runNameValue(run));
}

export function runMatchesSearch(run: NamedRun, query: string): boolean {
  const search = query.trim().toLocaleLowerCase();
  return !search || runLabel(run).toLocaleLowerCase().includes(displayTitle(search))
    || (run.run_id?.toLocaleLowerCase().includes(search) ?? false);
}
