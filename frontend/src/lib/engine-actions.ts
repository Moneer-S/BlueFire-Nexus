import type { EngineExperiment } from "./engine-experiment";

export const engineActionLabels = {
  start_baseline: "Start baseline exploration", start_adaptive_search: "Start fresh adaptive search",
  review_defense: "Review defensive change", apply_defense: "Apply defensive change",
  reconcile_defense: "Reconcile defensive change", repeat_mechanism: "Retest original mechanism",
  run_legitimate_use: "Run legitimate-use check", retain_defense: "Retain defensive change",
  rollback_defense: "Roll back defensive change", reconcile_rollback: "Reconcile rollback",
} as const;
export type PreparedActionKind = keyof typeof engineActionLabels;
export interface PreparedEngineAction {
  schema_version: "bluefire.engine-prepared-action.v1";
  preparation_id: string; protected_request_ref: string; experiment_id: string; revision: number;
  experiment_digest: string; workspace_digest: string; action_kind: PreparedActionKind;
  preparation_kind: "engine_attempt" | "controller_job" | "controller_transition";
  effect: { kind: string; summary: string; changes_target: boolean; uses_external_engine: boolean };
  requires_approval: boolean;
  approval: { required: boolean; state: "not_required" | "pending" | "approved" | "consumed" | "claimed" | "withdrawn"; review_binding_digest: string | null; expires_at: string | null };
  submission: { submission_id: string; intent_digest: string } | null;
  limits: { wall_clock_seconds: number | null; action_limit: number | null; artifact_byte_limit: number | null; cost_limit_microunits: number | null; target_scope_digest: string | null; maximum_tier: string | null };
  prepared_at: string; expires_at: string; effects_started_at_preparation: false;
}
export interface EngineActionAcceptance {
  schema_version: "bluefire.engine-action-acceptance.v1"; receipt_id: string; preparation_id: string;
  protected_request_ref: string; experiment_id: string; action_kind: PreparedActionKind; accepted_at: string;
  job: { job_id: string; kind: string } | null; transition: { revision: number; digest: string } | null;
}
const fail = (): never => { throw new Error("The engine action review is invalid or changed. Reload the workspace before continuing."); };
const row = (v: unknown, keys: string[]): Record<string, unknown> => {
  if (!v || typeof v !== "object" || Array.isArray(v) || Object.keys(v).sort().join("|") !== [...keys].sort().join("|")) return fail();
  return v as Record<string, unknown>;
};
const digest = (v: unknown) => typeof v === "string" && /^sha256:[0-9a-f]{64}$/.test(v);
const integer = (v: unknown, min: number, max: number) => typeof v === "number" && Number.isSafeInteger(v) && v >= min && v <= max;
const time = (v: unknown) => typeof v === "string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$/.test(v) && Number.isFinite(Date.parse(v)) && new Date(Date.parse(v)).toISOString().slice(0, 19) === v.slice(0, 19);
const contracts: Record<PreparedActionKind, [string, string, boolean, boolean]> = {
  start_baseline: ["engine_attempt", "external_engine_attempt", false, true], start_adaptive_search: ["engine_attempt", "external_engine_attempt", false, true],
  review_defense: ["controller_transition", "defense_review", false, false], retain_defense: ["controller_transition", "defense_disposition", false, false],
  apply_defense: ["controller_job", "defensive_change", true, false], rollback_defense: ["controller_job", "defensive_change", true, false],
  reconcile_defense: ["controller_job", "defensive_change", false, false], reconcile_rollback: ["controller_job", "defensive_change", false, false],
  repeat_mechanism: ["controller_job", "controller_check", false, false], run_legitimate_use: ["controller_job", "controller_check", false, false],
};
export function checkedPreparedEngineAction(value: unknown, workspace: EngineExperiment): PreparedEngineAction {
  const v = row(value, ["schema_version", "preparation_id", "protected_request_ref", "experiment_id", "revision", "experiment_digest", "workspace_digest", "action_kind", "preparation_kind", "effect", "requires_approval", "approval", "submission", "limits", "prepared_at", "expires_at", "effects_started_at_preparation"]);
  const effect = row(v.effect, ["kind", "summary", "changes_target", "uses_external_engine"]);
  const approval = row(v.approval, ["required", "state", "review_binding_digest", "expires_at"]);
  const limits = row(v.limits, ["wall_clock_seconds", "action_limit", "artifact_byte_limit", "cost_limit_microunits", "target_scope_digest", "maximum_tier"]);
  const contract = typeof v.action_kind === "string" && Object.hasOwn(contracts, v.action_kind) ? contracts[v.action_kind as PreparedActionKind] : undefined;
  const action = workspace.actions.find(item => item.primary && item.enabled);
  if (!contract || v.schema_version !== "bluefire.engine-prepared-action.v1" || v.effects_started_at_preparation !== false
    || v.experiment_id !== workspace.experiment_id || v.revision !== workspace.revision || v.experiment_digest !== workspace.experiment_digest || v.workspace_digest !== workspace.workspace_digest
    || v.action_kind !== action?.kind || !digest(v.preparation_id) || !digest(v.protected_request_ref)
    || v.preparation_kind !== contract[0] || effect.kind !== contract[1] || effect.changes_target !== contract[2] || effect.uses_external_engine !== contract[3]
    || typeof effect.summary !== "string" || !effect.summary.trim() || effect.summary.length > 240 || [...effect.summary].some(character => character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127)
    || v.requires_approval !== contract[3] || approval.required !== contract[3]
    || !time(v.prepared_at) || !time(v.expires_at) || Date.parse(v.expires_at as string) <= Date.parse(v.prepared_at as string) || Date.parse(v.expires_at as string) - Date.parse(v.prepared_at as string) > 7_800_000) return fail();
  if (contract[3]) {
    if (!["pending", "approved", "consumed", "claimed", "withdrawn"].includes(String(approval.state)) || !digest(approval.review_binding_digest) || approval.expires_at !== v.expires_at
      || !integer(limits.wall_clock_seconds, 1, 7200) || !integer(limits.action_limit, 1, 512) || !integer(limits.artifact_byte_limit, 1, 64 * 1024 * 1024) || !integer(limits.cost_limit_microunits, 0, 10_000_000_000)
      || !digest(limits.target_scope_digest) || !["safe", "controlled", "restricted"].includes(String(limits.maximum_tier))
      || ["wall_clock_seconds", "action_limit", "artifact_byte_limit", "cost_limit_microunits"].some(key => limits[key] !== workspace.authorization[key as keyof typeof workspace.authorization])) return fail();
  } else if (approval.state !== "not_required" || approval.review_binding_digest !== null || approval.expires_at !== null || Object.values(limits).some(item => item !== null)) return fail();
  if (contract[0] === "controller_transition") { if (v.submission !== null) return fail(); }
  else { const submission = row(v.submission, ["submission_id", "intent_digest"]); if (typeof submission.submission_id !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(submission.submission_id) || !digest(submission.intent_digest)) return fail(); }
  return value as PreparedEngineAction;
}
export function checkedEngineActionAcceptance(value: unknown, prepared: PreparedEngineAction): EngineActionAcceptance {
  const v = row(value, ["schema_version", "receipt_id", "preparation_id", "protected_request_ref", "experiment_id", "action_kind", "accepted_at", "job", "transition"]);
  if (v.schema_version !== "bluefire.engine-action-acceptance.v1" || !digest(v.receipt_id) || !time(v.accepted_at)
    || ["preparation_id", "protected_request_ref", "experiment_id", "action_kind"].some(key => v[key] !== prepared[key as keyof PreparedEngineAction])) return fail();
  if (prepared.preparation_kind === "controller_transition") {
    const t = row(v.transition, ["revision", "digest"]);
    if (v.job !== null || t.revision !== prepared.revision + 1 || !digest(t.digest)) return fail();
  } else {
    const job = row(v.job, ["job_id", "kind"]);
    const expected = prepared.preparation_kind === "engine_attempt" ? "engine-attempt" : ["repeat_mechanism", "run_legitimate_use"].includes(prepared.action_kind) ? "engine-controller-check" : "engine-controller-operation";
    if (v.transition !== null || typeof job.job_id !== "string" || !/^job-[0-9a-f]{32}$/.test(job.job_id) || job.kind !== expected) return fail();
  }
  return value as EngineActionAcceptance;
}
