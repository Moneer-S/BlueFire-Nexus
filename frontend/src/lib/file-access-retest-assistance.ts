import { request } from "./api";
import type { AssistanceContext } from "./assistance";
import type { CompositionAttempt, CompositionObjective } from "./composition";
import { FILE_ACCESS_PACK } from "./composition";
import { checkedFileAccessRetestLinkage, type FileAccessRetestLinkage } from "./file-access-linkage";
import { sameJson } from "./replay-review";

export interface FileAccessRetestAssistanceSelection {
  kind: "file_access_retest_comparison";
  objective_owner_id: string;
  attempt_id: string;
  control_owner_id: string;
  linkage_digest: string;
}

export interface FileAccessRetestAssistanceSummary {
  schema_version: "bluefire.file-access-retest-assistance-summary.v1";
  proof_scope: "historical_saved_linkage_only";
  baseline: { source: "verified_saved_baseline_operation"; control_revision: number; mode: "0640"; non_owner: "allowed"; owner: "allowed"; record_count: number };
  change: { source: "reviewed_saved_hardening_operation"; control_revision: number; mode: "0600" };
  retest: {
    source: "saved_composed_attempt"; state: "verified" | "unknown";
    non_owner_decision: "allowed" | "permission_denied" | "unknown" | null;
    owner_decision: "allowed" | "unknown" | null; record_count: number | null;
    run_cleanup: "complete" | "incomplete" | null; request_cleanup: "verified_closed" | null;
    objective_established: boolean | null;
  };
  comparison: { state: "established" | "not_established" | "unknown"; non_owner_change: "allowed_to_denied" | "still_allowed" | "unknown"; owner_preserved: boolean | null; content_preserved: boolean | null; cleanup_verified: boolean | null };
}

export interface FileAccessRetestAssistanceContext extends AssistanceContext {
  selected: FileAccessRetestAssistanceSelection;
  analysis_only: true;
  capabilities: [];
  reference_summary: FileAccessRetestAssistanceSummary;
}

export const fileAccessRetestAssistanceLimitations = [
  "This explains one exact saved Linux baseline, reviewed hardening, and selected composed retest; it does not read files, change permissions, rerun work, or recover an attempt.",
  "Baseline and retest are recorded reads of the same originally enrolled generated resource; they are not independent telemetry or a general host-access claim.",
  "The reviewed mode change alone does not prove denied access. Only a verified fresh retest can establish its recorded objective.",
  "Unknown or incomplete retest evidence remains unknown; a verified false objective is not successful prevention.",
  "The historical linkage is rechecked before explanation. Later control revisions cannot replace this selected comparison; changed or unavailable evidence refuses a new explanation.",
] as const;

const object = (value: unknown): value is Record<string, unknown> => Boolean(value) && typeof value === "object" && !Array.isArray(value);
const exact = (value: unknown, keys: string[]): value is Record<string, unknown> => object(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const digest = (value: unknown): value is string => typeof value === "string" && /^sha256:[0-9a-f]{64}$/.test(value);
const job = (value: unknown): value is string => typeof value === "string" && /^job-[0-9a-f]{32}$/.test(value);
const revision = (value: unknown): value is number => Number.isSafeInteger(value) && Number(value) > 0 && Number(value) <= 2_147_483_647;
const count = (value: unknown): value is number => Number.isSafeInteger(value) && Number(value) >= 1 && Number(value) <= 100;
const nullableBoolean = (value: unknown) => value === null || typeof value === "boolean";
const oneOf = (value: unknown, choices: readonly string[]): value is string => typeof value === "string" && choices.includes(value);

export function validFileAccessRetestAssistanceSelection(value: unknown): value is FileAccessRetestAssistanceSelection {
  return exact(value, ["kind", "objective_owner_id", "attempt_id", "control_owner_id", "linkage_digest"])
    && value.kind === "file_access_retest_comparison" && job(value.objective_owner_id) && job(value.control_owner_id)
    && typeof value.attempt_id === "string" && /^attempt-[0-9a-f]{32}$/.test(value.attempt_id) && digest(value.linkage_digest);
}

export function fileAccessRetestSelection(linkage: FileAccessRetestLinkage, objective: CompositionObjective, attempt: CompositionAttempt): FileAccessRetestAssistanceSelection {
  const checked = checkedFileAccessRetestLinkage(linkage, objective, attempt);
  return { kind: "file_access_retest_comparison", objective_owner_id: checked.objective_owner_id, attempt_id: checked.attempt_id, control_owner_id: checked.control_owner_id, linkage_digest: checked.linkage_digest };
}

export function fileAccessRetestComparisonPath(selected: FileAccessRetestAssistanceSelection): string {
  if (!validFileAccessRetestAssistanceSelection(selected)) throw new Error("Select one exact saved file-access comparison.");
  return `/composition?${new URLSearchParams({ control: selected.control_owner_id, objective: selected.objective_owner_id, pack: FILE_ACCESS_PACK, attempt: selected.attempt_id })}`;
}

function validSummary(value: unknown): value is FileAccessRetestAssistanceSummary {
  if (!exact(value, ["schema_version", "proof_scope", "baseline", "change", "retest", "comparison"])
    || value.schema_version !== "bluefire.file-access-retest-assistance-summary.v1" || value.proof_scope !== "historical_saved_linkage_only") return false;
  const { baseline, change, retest, comparison } = value;
  if (!exact(baseline, ["source", "control_revision", "mode", "non_owner", "owner", "record_count"])
    || baseline.source !== "verified_saved_baseline_operation" || !revision(baseline.control_revision) || baseline.mode !== "0640"
    || baseline.non_owner !== "allowed" || baseline.owner !== "allowed" || !count(baseline.record_count)
    || !exact(change, ["source", "control_revision", "mode"]) || change.source !== "reviewed_saved_hardening_operation"
    || !revision(change.control_revision) || change.control_revision <= baseline.control_revision || change.mode !== "0600"
    || !exact(retest, ["source", "state", "non_owner_decision", "owner_decision", "record_count", "run_cleanup", "request_cleanup", "objective_established"])
    || retest.source !== "saved_composed_attempt"
    || !exact(comparison, ["state", "non_owner_change", "owner_preserved", "content_preserved", "cleanup_verified"])
    || ![comparison.owner_preserved, comparison.content_preserved, comparison.cleanup_verified].every(nullableBoolean)) return false;
  if (retest.state === "unknown") return [retest.non_owner_decision, retest.owner_decision, retest.record_count, retest.run_cleanup, retest.request_cleanup, retest.objective_established].every(item => item === null)
    && comparison.state === "unknown" && comparison.non_owner_change === "unknown"
    && [comparison.owner_preserved, comparison.content_preserved, comparison.cleanup_verified].every(item => item === null);
  if (retest.state !== "verified" || !oneOf(retest.non_owner_decision, ["allowed", "permission_denied", "unknown"])
    || !oneOf(retest.owner_decision, ["allowed", "unknown"]) || !count(retest.record_count)
    || !oneOf(retest.run_cleanup, ["complete", "incomplete"]) || retest.request_cleanup !== "verified_closed" || typeof retest.objective_established !== "boolean") return false;
  if (comparison.state !== (retest.objective_established ? "established" : "not_established")
    || comparison.non_owner_change !== ({ allowed: "still_allowed", permission_denied: "allowed_to_denied", unknown: "unknown" } as Record<string, string>)[retest.non_owner_decision]
    || comparison.owner_preserved !== (retest.owner_decision === "allowed" ? true : null)
    || (comparison.content_preserved === null) !== (retest.owner_decision === "unknown")
    || comparison.content_preserved === true && retest.record_count !== baseline.record_count
    || comparison.cleanup_verified !== (retest.run_cleanup === "complete")) return false;
  return !retest.objective_established || retest.non_owner_decision === "permission_denied" && retest.owner_decision === "allowed"
    && comparison.content_preserved === true && comparison.cleanup_verified === true;
}

export function checkedFileAccessRetestAssistanceContext(value: unknown, selected: FileAccessRetestAssistanceSelection): FileAccessRetestAssistanceContext {
  if (!validFileAccessRetestAssistanceSelection(selected) || !exact(value, ["schema_version", "selected", "context_digest", "analysis_only", "capabilities", "reference_summary", "limitations"])
    || value.schema_version !== "bluefire.assistance-context.v1" || !sameJson(value.selected, selected) || !digest(value.context_digest)
    || value.analysis_only !== true || !Array.isArray(value.capabilities) || value.capabilities.length !== 0
    || !sameJson(value.limitations, fileAccessRetestAssistanceLimitations) || !validSummary(value.reference_summary)
    || new TextEncoder().encode(JSON.stringify(value.reference_summary)).length > 8192) throw new Error("The selected file-access comparison explanation changed or is unavailable.");
  return value as unknown as FileAccessRetestAssistanceContext;
}

export async function fileAccessRetestAssistanceContext(selected: FileAccessRetestAssistanceSelection): Promise<FileAccessRetestAssistanceContext> {
  if (!validFileAccessRetestAssistanceSelection(selected)) throw new Error("Select one exact saved file-access comparison.");
  const response: unknown = await request(`/composition/objectives/${encodeURIComponent(selected.objective_owner_id)}/file-access-linkage/${encodeURIComponent(selected.attempt_id)}/assistant-context`);
  return checkedFileAccessRetestAssistanceContext(response, selected);
}
