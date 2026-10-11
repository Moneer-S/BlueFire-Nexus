import { request } from "./api";

export const adPhases = ["inspect", "baseline", "harden", "retest", "rollback", "audit"] as const;
export type AdPhase = typeof adPhases[number];
export const adPhaseLabels: Record<AdPhase, string> = { inspect: "Inspect share", baseline: "Baseline reads", harden: "Remove probe access", retest: "Fresh read checks", rollback: "Restore share access", audit: "Collect audit" };
export const adSteps: Record<AdPhase, string[]> = { inspect: ["inspect_member"], baseline: ["read_probe_primary", "read_legitimate_primary", "read_legitimate_health"], harden: ["harden_share"], retest: ["read_probe_primary", "read_legitimate_primary", "read_legitimate_health"], rollback: ["rollback_share"], audit: ["collect_audit"] };
export interface AdBudget { business_attempts: number; sessions: number; share_changes: number; rollbacks: number }
export interface AdEnvironment {
  id: string; provenance: "synthetic_fixture" | "runner_reported"; scopeId: string; domain: string; member: string; client: string; share: string;
  createdAt: string; expiresAt: string; businessSeconds: number; auditSeconds: number;
  principals: { probe: string; legitimate: string; controller: string };
  files: { purpose: "primary" | "health"; name: string; bytes: number; digest: string }[];
}
export interface AdReadiness { available: boolean; member: boolean; client: boolean; channel: boolean; problem: string | null }
export interface AdEnvironments { nativeAvailable: boolean; environments: { environment: AdEnvironment; readiness: AdReadiness; available: boolean }[] }
export interface AdAce { sid: string; right: "Read" | "Full"; digest: string }
export interface AdDescriptor { digest: string; owner: string; group: string; control: number; aces: AdAce[] }
export interface AdChange { before: AdDescriptor; after: AdDescriptor; removed: AdAce; beforeDigest: string; afterDigest: string }
export interface AdRead { reader: "probe" | "legitimate"; purpose: "primary" | "health"; state: string; bytes: number; digest: string | null; localContext: string | null; cleanup: "verified" | "unknown" }
export interface AdExecution { provenance: "synthetic_fixture" | "runner_reported"; dispatch: "not_started" | "attempted" | "unknown"; cleanup: "verified" | "unknown"; read: AdRead | null; audit: { events: number; truncated: boolean; digest: string } | null; change: AdChange | null }
export interface AdOperation { id: string; phase: AdPhase; runId: string; state: "complete" | "partial" | "not_started" | "unknown"; expectation: "matched" | "not_met" | "incomplete" | null; distinctContexts: boolean | null; cleanup: "verified" | "unknown"; digest: string; executions: AdExecution[] }
export interface AdWorkflow { id: string; environment: AdEnvironment; revision: number; stopped: boolean; pending: string | null; policy: "baseline" | "hardened" | "unknown"; operations: AdOperation[]; allowed: AdPhase[]; remaining: AdBudget; integration: "unavailable" | "injected_adapter" | "configured_admission" }
export interface AdReview { workflow: string; revision: number; phase: AdPhase; digest: string; steps: string[]; budget: AdBudget; change: AdChange | null; policy: string }
export interface AdSubmission { submission_id: string; phase: AdPhase; review_digest: string; reviewed_by: string }
export type AdPending = { kind: "create"; id: string; body: { submission_id: string; environment_id: string } } | { kind: "submit"; id: string; workflow: string; body: AdSubmission };

const bad = () => new Error("The AD response is incomplete or differs from the selected saved work.");
const object = (value: unknown): Record<string, unknown> => { if (!value || typeof value !== "object" || Array.isArray(value)) throw bad(); return value as Record<string, unknown>; };
const text = (value: unknown, max = 512): string => { if (typeof value !== "string" || !value.length || value.length > max || Array.from(value).some(character => character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127)) throw bad(); return value; };
const bool = (value: unknown): boolean => { if (typeof value !== "boolean") throw bad(); return value; };
const integer = (value: unknown, max = 1_048_576): number => { if (!Number.isSafeInteger(value) || Number(value) < 0 || Number(value) > max) throw bad(); return Number(value); };
const list = (value: unknown, max: number): unknown[] => { if (!Array.isArray(value) || value.length > max) throw bad(); return value; };
const oneOf = <T extends string>(value: unknown, choices: readonly T[]): T => { if (!choices.includes(value as T)) throw bad(); return value as T; };
const nullableBool = (value: unknown): boolean | null => value === null ? null : bool(value);
const digest = (value: unknown): string => { if (typeof value !== "string" || !/^sha256:[a-f0-9]{64}$/.test(value)) throw bad(); return value; };
const sid = (value: unknown): string => { if (typeof value !== "string" || !/^S-1-\d+(?:-\d+){1,15}$/.test(value) || value.length > 184) throw bad(); return value; };
const stamp = (value: unknown): string => { const result = text(value, 40); if (!Number.isFinite(Date.parse(result))) throw bad(); return result; };
export const adJobValid = (value: string): boolean => /^job-[a-f0-9]{32}$/.test(value);
export const adJobId = (submission: string): string => `job-${submission.replaceAll("-", "")}`;
const job = (value: unknown): string => { if (typeof value !== "string" || !adJobValid(value)) throw bad(); return value; };
const environmentId = (value: unknown): string => { if (typeof value !== "string" || !/^ad-env-[a-f0-9]{32}$/.test(value)) throw bad(); return value; };
const noClaims = (row: Record<string, unknown>) => { for (const key of ["authenticated_remote_reader", "independent_observation", "effective_access_claim"]) if (row[key] !== false) throw bad(); };

function environment(value: unknown): AdEnvironment {
  const row = object(value), scope = object(row.scope), hosts = object(scope.hosts), principals = object(scope.principals), limits = object(scope.limits);
  if (scope.schema_version !== "bluefire.ad-smb-scope.v1" || typeof scope.scope_id !== "string" || !/^[a-f0-9]{32}$/.test(scope.scope_id)) throw bad();
  const files = list(scope.files, 2).map(value => { const file = object(value); return { purpose: oneOf(file.purpose, ["primary", "health"]), name: text(file.name, 32), bytes: integer(file.size_bytes, 65536), digest: digest(file.sha256) }; });
  if (files.length !== 2 || files[0]?.purpose !== "primary" || files[0]?.name !== "records.jsonl" || files[1]?.purpose !== "health" || files[1]?.name !== "health.jsonl") throw bad();
  return { id: environmentId(row.environment_id), provenance: oneOf(row.provenance, ["synthetic_fixture", "runner_reported"]), scopeId: scope.scope_id, domain: text(object(scope.domain).dns, 253), member: text(object(hosts.member).fqdn, 253), client: text(object(hosts.client).fqdn, 253), share: text(object(scope.share).unc), createdAt: stamp(scope.created_at), expiresAt: stamp(scope.expires_at), businessSeconds: integer(limits.business_seconds, 1800), auditSeconds: integer(limits.audit_seconds, 600), principals: { probe: sid(object(principals.probe).sid), legitimate: sid(object(principals.legitimate).sid), controller: sid(object(principals.controller).sid) }, files };
}
export function checkedAdEnvironments(value: unknown): AdEnvironments {
  const row = object(value);
  const environments = list(row.environments, 16).map(value => { const entry = object(value), ready = object(entry.readiness); const readiness = { available: bool(ready.available), member: bool(ready.member_observation), client: bool(ready.client_read_admission), channel: bool(ready.secret_channel_available), problem: ready.problem === null ? null : oneOf(ready.problem, ["native_admission_unavailable", "enrollment_unavailable", "changed"]) }; if (readiness.available && (!readiness.member || !readiness.client || !readiness.channel || readiness.problem !== null)) throw bad(); const available = bool(entry.available); if (available && !readiness.available) throw bad(); return { environment: environment(entry.environment), readiness, available }; });
  if (new Set(environments.map(entry => entry.environment.id)).size !== environments.length) throw bad();
  const nativeAvailable = bool(row.native_execution_available);
  if (nativeAvailable !== environments.some(entry => entry.available && entry.environment.provenance === "runner_reported")) throw bad();
  return { nativeAvailable, environments };
}
function budget(value: unknown): AdBudget { const row = object(value); return { business_attempts: integer(row.business_attempts, 6), sessions: integer(row.sessions, 6), share_changes: integer(row.share_changes, 1), rollbacks: integer(row.rollbacks, 1) }; }
function ace(value: unknown): AdAce { const row = object(value); if (row.ace_type !== "access_allowed" || row.flags !== 0) throw bad(); return { sid: sid(row.trustee_sid), right: oneOf(row.smb_right, ["Read", "Full"]), digest: digest(row.raw_ace_digest) }; }
function descriptor(value: unknown): AdDescriptor { const row = object(value), dacl = object(row.dacl); if (row.revision !== 1 || row.sacl !== null || dacl.revision !== 2 || ![0x8004, 0x9004].includes(Number(row.control))) throw bad(); return { digest: digest(row.sha256), owner: sid(row.owner_sid), group: sid(row.group_sid), control: integer(row.control, 65535), aces: list(dacl.aces, 3).map(ace) }; }
function structuralChange(value: AdChange): AdChange {
  const { before, after, removed } = value;
  const retained = before.aces.filter(entry => entry.digest !== removed.digest);
  if (before.aces.length !== 3 || after.aces.length !== 2 || removed.right !== "Read" || before.digest === after.digest || before.owner !== after.owner || before.group !== after.group || before.control !== after.control || !before.aces.some(entry => JSON.stringify(entry) === JSON.stringify(removed)) || JSON.stringify(retained) !== JSON.stringify(after.aces) || new Set(before.aces.map(entry => entry.sid)).size !== 3) throw bad();
  return value;
}
function change(value: unknown): AdChange { const row = object(value); if (row.schema_version !== "bluefire.ad-smb-acl-change.v1" || row.native_projection_verified !== false || row.effective_access_claim !== false) throw bad(); return structuralChange({ before: descriptor(object(row.before).descriptor), after: descriptor(row.after_descriptor), removed: ace(row.removed_ace), beforeDigest: digest(row.before_digest), afterDigest: digest(row.after_digest) }); }
function execution(value: unknown): AdExecution {
  const row = object(value), observation = row.observation === null ? null : object(row.observation);
  const result: AdExecution = { provenance: oneOf(row.provenance, ["synthetic_fixture", "runner_reported"]), dispatch: oneOf(row.dispatch, ["not_started", "attempted", "unknown"]), cleanup: oneOf(row.cleanup, ["verified", "unknown"]), read: null, audit: null, change: null };
  if (row.schema_version !== "bluefire.ad-smb-execution.v1") throw bad();
  digest(row.request_digest);
  if (!observation) return result;
  if (result.dispatch !== "attempted") throw bad();
  if ("reader" in observation) {
    noClaims(observation);
    if (observation.fresh_server_logon !== false || observation.server_session_closed !== null) throw bad();
    const localContext = observation.local_authentication_id === null ? null : text(observation.local_authentication_id, 16);
    if (localContext !== null && !/^[0-9a-f]{16}$/.test(localContext)) throw bad();
    result.read = { reader: oneOf(observation.reader, ["probe", "legitimate"]), purpose: oneOf(observation.purpose, ["primary", "health"]), state: oneOf(observation.state, ["bytes_matched", "open_access_denied", "unknown", "deadline", "cancelled", "not_started"]), bytes: integer(observation.bytes_read, 65537), digest: observation.sha256 === null ? null : digest(observation.sha256), localContext, cleanup: oneOf(observation.local_cleanup, ["verified", "unknown"]) };
  } else if ("events" in observation) {
    if (observation.authenticated_source !== false || observation.independent_observation !== false || observation.effective_access_claim !== false) throw bad();
    result.audit = { events: integer(observation.events, 1000), truncated: bool(observation.truncated), digest: digest(observation.source_digest) };
  } else if ("after_descriptor" in observation) {
    // Retain only the operator-facing structural diff, never binary descriptor or protected task data.
    const before = descriptor(object(observation.snapshot).descriptor), after = descriptor(observation.after_descriptor);
    const removed = before.aces.filter(entry => !after.aces.some(other => other.digest === entry.digest));
    const removedAce = removed[0];
    if (removed.length !== 1 || !removedAce) throw bad();
    result.change = structuralChange({ before, after, removed: removedAce, beforeDigest: before.digest, afterDigest: after.digest });
  }
  return result;
}
function operation(value: unknown): AdOperation {
  const row = object(value), outcome = object(row.outcome);
  noClaims(outcome);
  const phase = oneOf(row.phase, adPhases), executions = list(row.executions, adSteps[phase].length).map(execution);
  const runId = text(row.run_id, 160); if (!/^run-[A-Za-z0-9_-]+$/.test(runId)) throw bad();
  const state = oneOf(outcome.state, ["complete", "partial", "not_started", "unknown"]);
  if (state === "complete" && executions.length !== adSteps[phase].length) throw bad();
  if (phase === "baseline" || phase === "retest") for (const [index, entry] of executions.entries()) {
    if (entry.read && (entry.read.reader !== (index === 0 ? "probe" : "legitimate") || entry.read.purpose !== (index === 2 ? "health" : "primary"))) throw bad();
  }
  return { id: job(row.job_id), phase, runId, state, expectation: outcome.read_expectation === null ? null : oneOf(outcome.read_expectation, ["matched", "not_met", "incomplete"] as const), distinctContexts: nullableBool(outcome.distinct_local_contexts), cleanup: oneOf(outcome.cleanup, ["verified", "unknown"]), digest: digest(outcome.evidence_digest), executions };
}
export function checkedAdWorkflow(value: unknown, expected?: string): AdWorkflow {
  const envelope = object(value), row = object(envelope.workflow), progress = object(row.progress);
  const id = job(row.job_id); if ((expected && id !== expected) || row.kind !== "ad_smb.exercise" || envelope.effective_access_claim !== false) throw bad();
  const operations = list(progress.operations, 6).map(operation), allowed = list(envelope.allowed_phases, 6).map(value => oneOf(value, adPhases));
  if (new Set(operations.map(row => row.id)).size !== operations.length || new Set(allowed).size !== allowed.length) throw bad();
  const pending = progress.pending_operation === null ? null : job(progress.pending_operation);
  if (pending && (allowed.length || operations.some(row => row.id === pending))) throw bad();
  const selected = environment(object(row.request).environment);
  if (operations.some(row => row.executions.some(entry => entry.change && entry.change.removed.sid !== selected.principals.probe))) throw bad();
  return { id, environment: selected, revision: integer(progress.revision, 1000), stopped: bool(progress.stopped), pending, policy: oneOf(progress.policy_state, ["baseline", "hardened", "unknown"]), operations, allowed, remaining: budget(envelope.remaining), integration: oneOf(envelope.execution_integration, ["unavailable", "injected_adapter", "configured_admission"]) };
}
export function checkedAdList(value: unknown): AdWorkflow[] { const rows = list(object(value).workflows, 4096).map(value => checkedAdWorkflow(value)); if (new Set(rows.map(row => row.id)).size !== rows.length) throw bad(); return rows; }
export function checkedAdReview(value: unknown, workflow: AdWorkflow, phase: AdPhase): AdReview {
  const row = object(value);
  if (row.schema_version !== "bluefire.ad-smb-review.v1" || row.workflow_job_id !== workflow.id || row.revision !== workflow.revision || row.phase !== phase || !workflow.allowed.includes(phase) || row.policy_state !== workflow.policy || JSON.stringify(row.steps) !== JSON.stringify(adSteps[phase])) throw bad();
  const reservation = budget(row.budget), selectedChange = row.change === null ? null : change(row.change);
  const reads = phase === "baseline" || phase === "retest" ? 3 : 0;
  if (reservation.business_attempts !== reads || reservation.sessions !== reads || reservation.share_changes !== Number(phase === "harden") || reservation.rollbacks !== Number(phase === "rollback") || Boolean(selectedChange) !== ["harden", "retest", "rollback"].includes(phase) || (selectedChange && selectedChange.removed.sid !== workflow.environment.principals.probe)) throw bad();
  return { workflow: workflow.id, revision: workflow.revision, phase, digest: digest(row.review_digest), steps: [...adSteps[phase]], budget: reservation, change: selectedChange, policy: workflow.policy };
}
export function adPhaseCurrent(workflow: AdWorkflow, phase: AdPhase, now = Date.now()): boolean {
  const env = workflow.environment, start = Date.parse(env.createdAt), end = Date.parse(env.expiresAt);
  const deadline = phase === "rollback" ? end : Math.min(end, start + (env.businessSeconds + (phase === "audit" ? env.auditSeconds : 0)) * 1000);
  return start <= now && now < deadline;
}
export function adConfirmed(value: unknown, pending: AdPending): boolean {
  const row = object(value), saved = object(row.request), submitted = object(saved.submitted_request);
  if (row.job_id !== pending.id || row.kind !== (pending.kind === "create" ? "ad_smb.exercise" : "ad_smb.operation")) return false;
  if (pending.kind === "create") return submitted.environment_id === pending.body.environment_id && Object.keys(submitted).length === 1;
  return Object.keys(submitted).length === 4 && submitted.workflow_job_id === pending.workflow && submitted.phase === pending.body.phase && submitted.review_digest === pending.body.review_digest && submitted.reviewed_by === pending.body.reviewed_by;
}
const pendingKey = "bluefire.ad-smb.pending.v1";
function checkedPending(value: unknown): AdPending {
  const row = object(value), body = object(row.body), kind = oneOf(row.kind, ["create", "submit"]);
  const submission = text(body.submission_id, 36);
  if (!/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/.test(submission) || adJobId(submission) !== job(row.id)) throw bad();
  if (Object.keys(row).sort().join() !== (kind === "create" ? "body,id,kind" : "body,id,kind,workflow")) throw bad();
  if (kind === "create") { if (Object.keys(body).sort().join() !== "environment_id,submission_id") throw bad(); return { kind, id: row.id as string, body: { submission_id: submission, environment_id: environmentId(body.environment_id) } }; }
  if (Object.keys(body).sort().join() !== "phase,review_digest,reviewed_by,submission_id" || typeof body.reviewed_by !== "string" || !/^[A-Za-z0-9][A-Za-z0-9_. -]{0,99}$/.test(body.reviewed_by)) throw bad();
  return { kind, id: row.id as string, workflow: job(row.workflow), body: { submission_id: submission, phase: oneOf(body.phase, adPhases), review_digest: digest(body.review_digest), reviewed_by: body.reviewed_by } };
}
export function readAdPending(): AdPending | undefined { const raw = localStorage.getItem(pendingKey); if (raw === null) return; if (raw.length > 8192) throw bad(); return checkedPending(JSON.parse(raw)); }
export function storeAdPending(value: AdPending): void { const saved = checkedPending(value), previous = readAdPending(); if (previous && JSON.stringify(previous) !== JSON.stringify(saved)) throw new Error("Confirm the original AD request before saving another."); const raw = JSON.stringify(saved); localStorage.setItem(pendingKey, raw); if (localStorage.getItem(pendingKey) !== raw) throw new Error("The original request could not be retained. Nothing was sent."); }
export function clearAdPending(value: AdPending): void { if (JSON.stringify(readAdPending()) !== JSON.stringify(checkedPending(value))) throw new Error("The retained AD request changed in another tab."); localStorage.removeItem(pendingKey); }
const post = (path: string, body: unknown) => request<unknown>(`/ad-smb/${path}`, { method: "POST", body: JSON.stringify(body) });
export const adSmbApi = {
  environments: () => request<unknown>("/ad-smb/environments"), list: () => request<unknown>("/ad-smb/workflows"),
  workflow: (id: string) => request<unknown>(`/ad-smb/workflows/${encodeURIComponent(id)}`),
  job: (id: string) => request<unknown>(`/jobs/${encodeURIComponent(id)}`),
  create: (body: { submission_id: string; environment_id: string }) => post("workflows", body),
  review: (id: string, phase: AdPhase) => post(`workflows/${encodeURIComponent(id)}/review`, { phase }),
  submit: (id: string, body: AdSubmission) => post(`workflows/${encodeURIComponent(id)}/operations`, body),
  stop: (id: string) => post(`workflows/${encodeURIComponent(id)}/stop`, {}),
  recover: (id: string) => post(`workflows/${encodeURIComponent(id)}/recover`, {}),
};
