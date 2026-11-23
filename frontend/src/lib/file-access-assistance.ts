import { request } from "./api";
import type { AssistanceContext } from "./assistance";
import { fileAccessControlIdValid } from "./file-access";
import { sameJson } from "./replay-review";

export interface FileAccessAssistanceSelection {
  kind: "file_access_control";
  control_owner_id: string;
  control_revision: number;
  control_digest: string;
}

type FileAccessFreshResult =
  | { recorded: false }
  | {
      recorded: true;
      operation: "baseline" | "rollback" | "harden";
      non_owner: "allowed" | "data_access_denied";
      owner: "allowed";
      source: "verified_saved_task_observation" | "verified_saved_paired_read";
      independent_observation: false;
    };

export interface FileAccessAssistanceSummary {
  schema_version: "bluefire.file-access-assistance-summary.v1";
  platform: "linux" | "macos" | "windows";
  control_status: "created" | "baseline_verified" | "hardened" | "rolled_back" | "reset" | "uncertain" | "recovery_required" | "setup_verified";
  baseline: { recorded: false } | { recorded: true; non_owner: "allowed"; owner: "allowed" };
  protection: {
    kind: "posix_mode" | "windows_metadata";
    value: "0640" | "0600" | "reader_readable" | "metadata_only" | "unknown" | "not_recorded";
    effective_access_proven: false;
  };
  fresh_result: FileAccessFreshResult;
  latest_operation: null | {
    operation: "create" | "baseline" | "harden" | "rollback" | "reset";
    state: string;
    outcome: "not_recorded" | "complete" | "settled_partial" | "refused_no_effect" | "unknown";
    record_digest: string;
  };
  task_access: { usage_state: "pending" | "settled" | "none" | "unresolved" };
  readiness: "not_assessed";
}

export interface FileAccessAssistanceContext extends AssistanceContext {
  selected: FileAccessAssistanceSelection;
  analysis_only: true;
  capabilities: [];
  reference_summary: FileAccessAssistanceSummary;
}

export const fileAccessAssistanceLimitations = [
  "This explains one exact saved file-access control revision; it is not an execution or recovery plan.",
  "Saved baseline reads, protection metadata and verified fresh task observations are separate evidence; a mode or policy change alone does not prove denied access.",
  "Task-access settlement is not current endpoint readiness. Readiness is not assessed and no native channel or enrollment is contacted by this context.",
  "Recorded reads concern only the originally enrolled generated resource and principals; they are not independent detection telemetry or a general host-access claim.",
  "Missing or unresolved evidence remains unreported. No file read, permission change, recovery, run or grant is available from this context.",
] as const;

const object = (value: unknown): value is Record<string, unknown> => Boolean(value) && typeof value === "object" && !Array.isArray(value);
const exact = (value: unknown, keys: string[]): value is Record<string, unknown> => object(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const digest = (value: unknown): value is string => typeof value === "string" && /^sha256:[0-9a-f]{64}$/.test(value);
const operationStates = ["queued", "planning", "running", "awaiting_approval", "cancelling", "completed", "failed", "cancelled", "interrupted"] as const;

export function validFileAccessAssistanceSelection(value: unknown): value is FileAccessAssistanceSelection {
  return exact(value, ["kind", "control_owner_id", "control_revision", "control_digest"])
    && value.kind === "file_access_control" && typeof value.control_owner_id === "string" && fileAccessControlIdValid(value.control_owner_id)
    && Number.isSafeInteger(value.control_revision) && Number(value.control_revision) > 0 && Number(value.control_revision) <= 2_147_483_647
    && digest(value.control_digest);
}

function validSummary(value: unknown): value is FileAccessAssistanceSummary {
  if (!exact(value, ["schema_version", "platform", "control_status", "baseline", "protection", "fresh_result", "latest_operation", "task_access", "readiness"])) return false;
  if (value.schema_version !== "bluefire.file-access-assistance-summary.v1"
    || !["linux", "macos", "windows"].includes(String(value.platform))
    || !["created", "baseline_verified", "hardened", "rolled_back", "reset", "uncertain", "recovery_required", "setup_verified"].includes(String(value.control_status))
    || value.readiness !== "not_assessed") return false;
  if (value.platform === "windows" && !["setup_verified", "uncertain", "baseline_verified", "hardened"].includes(String(value.control_status))
    || value.platform === "macos" && !["created", "baseline_verified", "hardened", "rolled_back", "uncertain"].includes(String(value.control_status))) return false;
  const baselineValid = exact(value.baseline, ["recorded"]) && value.baseline.recorded === false
    || exact(value.baseline, ["recorded", "non_owner", "owner"]) && value.baseline.recorded === true && value.baseline.non_owner === "allowed" && value.baseline.owner === "allowed";
  if (!baselineValid || !exact(value.protection, ["kind", "value", "effective_access_proven"]) || value.protection.effective_access_proven !== false) return false;
  if (value.platform === "windows") {
    if (value.protection.kind !== "windows_metadata" || !["reader_readable", "metadata_only", "unknown", "not_recorded"].includes(String(value.protection.value))) return false;
  } else if (value.protection.kind !== "posix_mode" || !["0640", "0600", "not_recorded"].includes(String(value.protection.value))) return false;
  const freshValid = exact(value.fresh_result, ["recorded"]) && value.fresh_result.recorded === false
    || exact(value.fresh_result, ["recorded", "operation", "non_owner", "owner", "source", "independent_observation"])
      && value.fresh_result.recorded === true
      && ["baseline", "rollback", "harden"].includes(String(value.fresh_result.operation))
      && ["allowed", "data_access_denied"].includes(String(value.fresh_result.non_owner))
      && value.fresh_result.owner === "allowed"
      && ["verified_saved_task_observation", "verified_saved_paired_read"].includes(String(value.fresh_result.source))
      && value.fresh_result.independent_observation === false
      && (value.fresh_result.source === "verified_saved_task_observation"
        ? value.platform === "linux" && ["baseline", "rollback"].includes(String(value.fresh_result.operation)) && value.fresh_result.non_owner === "allowed"
        : value.platform === "windows" && value.fresh_result.operation === "harden" && value.fresh_result.non_owner === "data_access_denied");
  if (!freshValid) return false;
  const operationValid = value.latest_operation === null || exact(value.latest_operation, ["operation", "state", "outcome", "record_digest"])
    && ["create", "baseline", "harden", "rollback", "reset"].includes(String(value.latest_operation.operation))
    && typeof value.latest_operation.state === "string" && operationStates.includes(value.latest_operation.state as typeof operationStates[number])
    && ["not_recorded", "complete", "settled_partial", "refused_no_effect", "unknown"].includes(String(value.latest_operation.outcome))
    && digest(value.latest_operation.record_digest);
  return operationValid && exact(value.task_access, ["usage_state"])
    && (value.platform === "windows" ? ["none", "settled", "unresolved"].includes(String(value.task_access.usage_state)) : ["pending", "settled"].includes(String(value.task_access.usage_state)));
}

export function checkedFileAccessAssistanceContext(value: unknown, selected: FileAccessAssistanceSelection): FileAccessAssistanceContext {
  if (!validFileAccessAssistanceSelection(selected)
    || !exact(value, ["schema_version", "selected", "context_digest", "analysis_only", "capabilities", "reference_summary", "limitations"])
    || value.schema_version !== "bluefire.assistance-context.v1" || !sameJson(value.selected, selected)
    || !digest(value.context_digest) || value.analysis_only !== true || !Array.isArray(value.capabilities) || value.capabilities.length !== 0
    || !Array.isArray(value.limitations) || !sameJson(value.limitations, fileAccessAssistanceLimitations)
    || !validSummary(value.reference_summary) || new TextEncoder().encode(JSON.stringify(value.reference_summary)).length > 8192) {
    throw new Error("The saved file-access explanation context changed or is unavailable.");
  }
  return value as unknown as FileAccessAssistanceContext;
}

export async function fileAccessAssistanceContext(selected: FileAccessAssistanceSelection): Promise<FileAccessAssistanceContext> {
  if (!validFileAccessAssistanceSelection(selected)) throw new Error("Select one exact saved file-access control.");
  const response: unknown = await request(`/file-access/controls/${encodeURIComponent(selected.control_owner_id)}/assistant-context`);
  return checkedFileAccessAssistanceContext(response, selected);
}
