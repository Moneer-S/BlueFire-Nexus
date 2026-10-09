import { DEMO_MODE, request } from "./api";

export const s3Phases = ["inspect", "baseline", "apply", "retest", "reconcile", "rollback"] as const;
export type S3Phase = typeof s3Phases[number];
export const phaseName: Record<S3Phase, string> = { inspect: "Inspect policy", baseline: "Baseline reads", apply: "Apply reviewed change", retest: "Fresh access checks", reconcile: "Inspect current policy", rollback: "Restore reviewed policy" };
export interface S3Environment { environment_id: string; display_name: string; scope: { bucket: string; region: string; account_id: string; expires_at: string; roles: Record<string, unknown>; objects: unknown[]; limits: Record<string, number> }; baseline_policy: unknown; exclusive_writer_digest: string | null }
export interface S3EnvironmentRow { environment: S3Environment; available: boolean; problem: string | null; context_digest: string }
export interface S3Environments { schema_version: "bluefire.s3-environments.v1"; environments: S3EnvironmentRow[]; problem: string | null }
export interface S3Fact { reader: "probe" | "legitimate"; purpose: string; result: string }
export interface S3Outcome { state: string; cleanup: "verified" | "unknown"; complete: boolean; facts: S3Fact[]; policy_observation: string | null; provenance: "synthetic" | "runner_reported"; independent_observations: 0; audit: "not_collected"; resource_disposition: "retained" }
export interface S3Operation { phase: S3Phase; operation_job_id: string; review_digest: string; run_ids: string[]; outcome: S3Outcome; outcome_digest: string }
export interface S3Exercise { schema_version: "bluefire.s3-exercise.v1"; workflow_job_id: string; context_digest: string; environment: S3Environment; revision: number; policy_state: string; stopped: boolean; operations: S3Operation[]; active_job: { job_id: string; state: string; request: { s3_access: { workflow_job_id: string; phase: S3Phase; review: { review_digest: string } } } } | null; allowed_phases: S3Phase[]; saved_result_recovery_available: boolean; remaining: Record<string, number>; problem: string | null; audit: "not_collected"; resource_disposition: "retained"; independent_observations: 0; live_outcome_verified: false }
export interface S3List { schema_version: "bluefire.s3-exercise-list.v1"; exercises: Array<{ workflow_job_id: string; name: string; bucket: string; policy_state: string; updated_at: string }>; truncated: boolean }
export interface S3Review { schema_version: "bluefire.s3-stage-review.v1"; workflow_job_id: string; phase: S3Phase; revision: number; review_digest: string; reserved: Record<string, number>; remaining: Record<string, number>; required_remaining: Record<string, number>; policy_change: { before: unknown; after: unknown } | null; prior_run_ids: string[] }
export type S3Pending = { kind: "create"; owner: string; request: { submission_id: string; environment_id: string; context_digest: string } } | { kind: "stage"; owner: string; operation: string; request: { submission_id: string; phase: S3Phase; review_digest: string; reviewed_by: string } };
const pendingKey = "bluefire.s3.pending.v1";
const stopKey = "bluefire.s3.pending-stops.v1";
export const validS3Job = (value: unknown): value is string => typeof value === "string" && /^job-[0-9a-f]{32}$/.test(value);
export const validS3Run = (value: unknown): value is string => typeof value === "string" && /^run-\d{8}T\d{6}Z-[0-9a-f]{16}$/.test(value);
const hash = (value: unknown) => typeof value === "string" && /^sha256:[0-9a-f]{64}$/.test(value);
const invalid = () => new Error("This saved S3 response is incomplete or belongs to different work.");
const record = (value: unknown): value is Record<string, unknown> => Boolean(value) && typeof value === "object" && !Array.isArray(value);
const boundedText = (value: unknown, maximum: number): value is string => typeof value === "string" && value.length > 0 && value.length <= maximum && Array.from(value).every(char => char.charCodeAt(0) >= 32 && char.charCodeAt(0) !== 127);
const reference = (value: unknown) => typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(value);
const nullableProblem = (value: unknown) => value === null || boundedText(value, 2000);
const integer = (value: unknown) => typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
const budgetKeys = ["api_calls", "business_attempts", "sessions", "policy_changes", "rollbacks"] as const;
const budget = (value: unknown) => record(value) && Object.keys(value).length === budgetKeys.length && budgetKeys.every(key => integer(value[key]));
const policyStates = ["baseline", "hardened", "uncertain", "drift"];
const outcomeStates = ["observed", "failed", "uncertain", "drift", "baseline_failed", "denied_with_legitimate_reads", "defense_not_confirmed"];
const jobStates = ["queued", "planning", "awaiting_approval", "running", "paused", "cancelling", "completed", "failed", "cancelled", "interrupted"];
const exactKeys = (value: unknown, keys: string[]) => record(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const unique = (values: unknown[]) => new Set(values).size === values.length;
export const s3JobId = (submission: string) => `job-${submission.replaceAll("-", "")}`;

function validEnvironment(value: S3Environment) {
  return value && reference(value.environment_id) && boundedText(value.display_name, 100)
    && value.scope && boundedText(value.scope.bucket, 63) && boundedText(value.scope.region, 32)
    && typeof value.scope.account_id === "string" && /^\d{12}$/.test(value.scope.account_id) && boundedText(value.scope.expires_at, 40)
    && Number.isFinite(Date.parse(value.scope.expires_at)) && record(value.scope.roles)
    && Array.isArray(value.scope.objects) && value.scope.objects.length <= 2
    && record(value.scope.limits) && budgetKeys.every(key => integer(value.scope.limits[key]))
    && record(value.baseline_policy) && (value.exclusive_writer_digest === null || hash(value.exclusive_writer_digest));
}

export function checkedEnvironments(value: S3Environments): S3Environments {
  if (value?.schema_version !== "bluefire.s3-environments.v1" || !Array.isArray(value.environments)
    || value.environments.length > 32 || !nullableProblem(value.problem)
    || value.environments.some(row => !row || !validEnvironment(row.environment) || typeof row.available !== "boolean"
      || !nullableProblem(row.problem) || (row.available && row.problem !== null) || !hash(row.context_digest))
    || !unique(value.environments.map(row => row.environment.environment_id))) throw invalid();
  return value;
}

export function checkedList(value: S3List): S3List {
  if (value?.schema_version !== "bluefire.s3-exercise-list.v1" || typeof value.truncated !== "boolean"
    || !Array.isArray(value.exercises) || value.exercises.length > 100
    || value.exercises.some(row => !row || !validS3Job(row.workflow_job_id) || !boundedText(row.name, 100)
      || !boundedText(row.bucket, 63) || !policyStates.includes(row.policy_state) || !boundedText(row.updated_at, 40))
    || !unique(value.exercises.map(row => row.workflow_job_id))) throw invalid();
  return value;
}

export function checkedExercise(value: S3Exercise, expected: string): S3Exercise {
  if (value?.schema_version !== "bluefire.s3-exercise.v1" || value.workflow_job_id !== expected || !validS3Job(expected)
    || !hash(value.context_digest) || !integer(value.revision) || !validEnvironment(value.environment) || !policyStates.includes(value.policy_state)
    || typeof value.stopped !== "boolean" || typeof value.saved_result_recovery_available !== "boolean"
    || !budget(value.remaining) || !nullableProblem(value.problem) || !Array.isArray(value.operations)
    || value.operations.length > 150 || !Array.isArray(value.allowed_phases) || !unique(value.allowed_phases)
    || value.allowed_phases.some(p => !s3Phases.includes(p)) || value.independent_observations !== 0
    || value.live_outcome_verified !== false || value.audit !== "not_collected" || value.resource_disposition !== "retained") throw invalid();
  if ((value.stopped && value.allowed_phases.some(phase => !["rollback", "reconcile"].includes(phase)))
    || (value.problem !== null && value.allowed_phases.length > 0)) throw invalid();
  const ids = new Set<string>();
  const runs = new Set<string>();
  for (const row of value.operations) {
    if (!row || !validS3Job(row.operation_job_id) || row.operation_job_id === expected || ids.has(row.operation_job_id)
      || !s3Phases.includes(row.phase) || !hash(row.review_digest) || !hash(row.outcome_digest)
      || !Array.isArray(row.run_ids) || !row.run_ids.every(validS3Run) || !unique(row.run_ids)
      || row.run_ids.some(id => runs.has(id)) || row.run_ids.length > (["baseline", "retest"].includes(row.phase) ? 2 : 1)
      || !row.outcome || !outcomeStates.includes(row.outcome.state) || typeof row.outcome.complete !== "boolean"
      || !["synthetic", "runner_reported"].includes(row.outcome.provenance)
      || !["verified", "unknown"].includes(row.outcome.cleanup) || !Array.isArray(row.outcome.facts)
      || row.outcome.facts.length > 3 || row.outcome.facts.some(fact => !fact || !["probe", "legitimate"].includes(fact.reader)
        || !["primary", "health"].includes(fact.purpose) || !["read", "service_denied"].includes(fact.result)
        || (fact.reader === "probe" && fact.purpose !== "primary"))
      || !unique(row.outcome.facts.map(fact => `${fact.reader}:${fact.purpose}`))
      || (row.outcome.policy_observation !== null && !["matched_before", "matched_after", "drift"].includes(row.outcome.policy_observation))
      || row.outcome.independent_observations !== 0 || row.outcome.audit !== "not_collected"
      || row.outcome.resource_disposition !== "retained") throw invalid();
    ids.add(row.operation_job_id);
    row.run_ids.forEach(id => runs.add(id));
  }
  const active = value.active_job;
  if (active !== null && (!active || !validS3Job(active.job_id) || active.job_id === expected || ids.has(active.job_id)
    || !jobStates.includes(active.state) || active.request?.s3_access?.workflow_job_id !== expected
    || !s3Phases.includes(active.request.s3_access.phase) || !hash(active.request.s3_access.review?.review_digest))) throw invalid();
  if ((active && value.allowed_phases.length > 0) || (value.saved_result_recovery_available
    && (!active || !["completed", "failed", "cancelled", "interrupted"].includes(active.state)))) throw invalid();
  const last = value.operations.at(-1);
  if (last && last.outcome.cleanup !== "verified" && value.allowed_phases.length > 0) throw invalid();
  return value;
}

export function checkedReview(value: S3Review, owner: string, phase: S3Phase): S3Review {
  if (value?.schema_version !== "bluefire.s3-stage-review.v1" || !validS3Job(owner) || !s3Phases.includes(phase)
    || value.workflow_job_id !== owner || value.phase !== phase || !hash(value.review_digest) || !integer(value.revision)
    || !budget(value.remaining) || !budget(value.reserved) || !budget(value.required_remaining)
    || budgetKeys.some(key => value.required_remaining[key]! < value.reserved[key]! || value.required_remaining[key]! > value.remaining[key]!)
    || !Array.isArray(value.prior_run_ids)
    || value.prior_run_ids.length > 300 || !value.prior_run_ids.every(validS3Run) || !unique(value.prior_run_ids)
    || (["apply", "reconcile", "rollback"].includes(phase)
      ? !value.policy_change || !record(value.policy_change.before) || !record(value.policy_change.after)
      : value.policy_change !== null)) throw invalid();
  return value;
}

function validatePending(value: S3Pending): S3Pending {
  const id = value?.request?.submission_id;
  if (typeof id !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(id) || !validS3Job(value.owner)) throw invalid();
  if (value.kind === "create") {
    if (!exactKeys(value, ["kind", "owner", "request"]) || !exactKeys(value.request, ["submission_id", "environment_id", "context_digest"])
      || value.owner !== s3JobId(id) || !reference(value.request.environment_id) || !hash(value.request.context_digest)) throw invalid();
  } else if (value.kind !== "stage" || !exactKeys(value, ["kind", "owner", "operation", "request"])
    || !exactKeys(value.request, ["submission_id", "phase", "review_digest", "reviewed_by"])
    || value.operation !== s3JobId(id) || value.operation === value.owner || !s3Phases.includes(value.request.phase)
    || !hash(value.request.review_digest) || !boundedText(value.request.reviewed_by, 100) || !value.request.reviewed_by.trim()) throw invalid();
  return value;
}
export function readS3Pending(): S3Pending | null { const raw = localStorage.getItem(pendingKey); if (raw && raw.length > 4096) throw invalid(); return raw ? validatePending(JSON.parse(raw) as S3Pending) : null; }
export function storeS3Pending(value: S3Pending) { localStorage.setItem(pendingKey, JSON.stringify(validatePending(value))); }
export function clearS3Pending(value: S3Pending) { if (JSON.stringify(readS3Pending()) !== JSON.stringify(value)) throw invalid(); localStorage.removeItem(pendingKey); }
export function readS3Stops(): string[] { const raw = localStorage.getItem(stopKey) ?? "[]"; if (raw.length > 4096) throw invalid(); const value: unknown = JSON.parse(raw); if (!Array.isArray(value) || value.length > 100 || !value.every(validS3Job) || !unique(value)) throw invalid(); return value; }
export function storeS3Stop(owner: string) { if (!validS3Job(owner)) throw invalid(); const values = [...new Set([...readS3Stops(), owner])]; if (values.length > 100) throw invalid(); localStorage.setItem(stopKey, JSON.stringify(values)); }
export function clearS3Stop(owner: string) { localStorage.setItem(stopKey, JSON.stringify(readS3Stops().filter(id => id !== owner))); }
export function confirmsS3Pending(value: S3Exercise, pending: S3Pending) {
  if (value.workflow_job_id !== pending.owner) return false;
  if (pending.kind === "create") return value.environment.environment_id === pending.request.environment_id && value.context_digest === pending.request.context_digest;
  const operation = value.operations.find(row => row.operation_job_id === pending.operation);
  return Boolean(operation && operation.phase === pending.request.phase && operation.review_digest === pending.request.review_digest) || Boolean(value.active_job?.job_id === pending.operation && value.active_job.request.s3_access.phase === pending.request.phase && value.active_job.request.s3_access.review.review_digest === pending.request.review_digest);
}
const root = "/s3-access";
const write = <T>(path: string, body: unknown) => request<T>(path, { method: "POST", body: JSON.stringify(body) });
function live<T>(callback: () => Promise<T>): Promise<T> { return DEMO_MODE ? Promise.reject(new Error("S3 access requires an enrolled local service; demo mode has no cloud authority.")) : callback(); }
function ownerPath(owner: string) { if (!validS3Job(owner)) throw invalid(); return `${root}/exercises/${owner}`; }
export const s3Api = {
  environments: () => live(async () => checkedEnvironments(await request<S3Environments>(`${root}/environments`))),
  list: () => live(async () => checkedList(await request<S3List>(`${root}/exercises`))),
  read: (owner: string) => live(async () => checkedExercise(await request<S3Exercise>(ownerPath(owner)), owner)),
  review: (owner: string, phase: S3Phase) => live(async () => { if (!s3Phases.includes(phase)) throw invalid(); return checkedReview(await write<S3Review>(`${ownerPath(owner)}/review`, { phase }), owner, phase); }),
  send: (value: S3Pending) => live(async () => { validatePending(value); return checkedExercise(await write<S3Exercise>(value.kind === "create" ? `${root}/exercises` : `${ownerPath(value.owner)}/operations`, value.request), value.owner); }),
  control: (owner: string, action: "stop" | "recover") => live(async () => { if (!["stop", "recover"].includes(action)) throw invalid(); return checkedExercise(await write<S3Exercise>(`${ownerPath(owner)}/${action}`, {}), owner); }),
};
