export const fixturePhases = ["prepare", "reconcile_fixtures", "cleanup"] as const;
export type FixtureState = "not_prepared" | "owned" | "partial" | "uncertain" | "drift" | "absent";
export type ResourceDisposition = "not_prepared" | "retained" | "cleanup_required" | "removed";
export interface FixtureEnrollment { schema_version: "bluefire.s3-fixture-enrollment.v2"; scope_digest: string; generation_digest: string; exclusive_writer_digest: string; bucket_shape: "never_versioned_no_object_lock" }
export interface FixtureReceipt { purpose: "primary" | "health"; key: string; state: Exclude<FixtureState, "partial">; etag: string | null; sha256: string; size_bytes: number; intent_id: string; request_ids: string[]; provenance: "not_observed" | "synthetic" | "runner_reported" }
export interface PolicyRetention { policy_state: string; review_digest: string; operation_job_id: string }
export interface FixtureReview { authority_digest: string; intent_id: string; objects: Array<{ purpose: "primary" | "health"; key: string; sha256: string; size_bytes: number; payload_preview: string; expected_etag: string | null }>; policy_disposition: "retain_current"; policy_state: string }

const record = (v: unknown): v is Record<string, unknown> => Boolean(v) && typeof v === "object" && !Array.isArray(v);
const exact = (v: unknown, keys: string[]): v is Record<string, unknown> => record(v) && Object.keys(v).length === keys.length && keys.every(key => Object.hasOwn(v, key));
const hash = (v: unknown) => typeof v === "string" && /^sha256:[0-9a-f]{64}$/.test(v);
const intent = (v: unknown) => typeof v === "string" && /^[0-9a-f]{64}$/.test(v);
const key = (v: unknown) => typeof v === "string" && /^bluefire\/s3-[0-9a-f]{32}\/(?:records|health)\.jsonl$/.test(v);
const size = (v: unknown): v is number => typeof v === "number" && Number.isSafeInteger(v) && v > 0 && v <= 65536;
const etag = (v: unknown) => v === null || (typeof v === "string" && /^"[A-Za-z0-9._+-]{1,128}"$/.test(v));
const policies = ["baseline", "hardened", "uncertain", "drift"];
export const isFixturePhase = (v: string) => (fixturePhases as readonly string[]).includes(v);

export function validFixtureEnrollment(v: unknown): v is FixtureEnrollment {
  return exact(v, ["schema_version", "scope_digest", "generation_digest", "exclusive_writer_digest", "bucket_shape"])
    && v.schema_version === "bluefire.s3-fixture-enrollment.v2" && hash(v.scope_digest)
    && hash(v.generation_digest) && hash(v.exclusive_writer_digest) && v.bucket_shape === "never_versioned_no_object_lock";
}

export function validFixtureProjection(v: { fixture_state?: FixtureState; fixtures?: FixtureReceipt[]; policy_retention?: PolicyRetention | null; resource_disposition: ResourceDisposition; environment: { scope: { objects: unknown[] } } }): boolean {
  if (!Array.isArray(v.fixtures) || v.fixtures.length !== 2 || v.environment.scope.objects.length !== 2) return false;
  if (v.fixtures.some((row, index) => {
    const scoped = v.environment.scope.objects[index];
    return !exact(row, ["purpose", "key", "state", "etag", "sha256", "size_bytes", "intent_id", "request_ids", "provenance"])
      || !record(scoped) || row.purpose !== (index === 0 ? "primary" : "health") || row.purpose !== scoped.purpose
      || !key(row.key) || row.key !== scoped.key || !hash(row.sha256) || row.sha256 !== scoped.sha256
      || !size(row.size_bytes) || row.size_bytes !== scoped.size_bytes || !intent(row.intent_id) || !etag(row.etag)
      || !["not_prepared", "owned", "absent", "uncertain", "drift"].includes(row.state)
      || !["not_observed", "synthetic", "runner_reported"].includes(row.provenance)
      || !Array.isArray(row.request_ids) || row.request_ids.length > 14
      || row.request_ids.some(id => typeof id !== "string" || !/^[A-Za-z0-9][A-Za-z0-9+/=_:.-]{0,127}$/.test(id))
      || (row.state === "owned" && (row.etag === null || row.provenance === "not_observed"))
      || (row.state === "not_prepared" && (row.etag !== null || row.request_ids.length > 0 || row.provenance !== "not_observed"));
  })) return false;
  if (v.fixtures[0]!.intent_id !== v.fixtures[1]!.intent_id || v.fixtures.reduce((total, row) => total + row.size_bytes, 0) > 65536) return false;
  const states = v.fixtures.map(row => row.state);
  const state: FixtureState = states.includes("uncertain") ? "uncertain" : states.includes("drift") ? "drift"
    : states.every(s => s === "owned") ? "owned" : states.every(s => s === "absent") ? "absent"
      : states.every(s => s === "not_prepared") ? "not_prepared" : "partial";
  const disposition: ResourceDisposition = state === "not_prepared" ? "not_prepared" : state === "owned" ? "retained" : state === "absent" ? "removed" : "cleanup_required";
  const retention = v.policy_retention;
  return v.fixture_state === state && v.resource_disposition === disposition && (retention === null
    || (exact(retention, ["policy_state", "review_digest", "operation_job_id"]) && policies.includes(retention.policy_state as string)
      && hash(retention.review_digest) && typeof retention.operation_job_id === "string" && /^job-[0-9a-f]{32}$/.test(retention.operation_job_id)));
}

export function validFixtureReview(v: unknown): v is FixtureReview {
  if (!exact(v, ["authority_digest", "intent_id", "objects", "policy_disposition", "policy_state"])
    || !hash(v.authority_digest) || !intent(v.intent_id) || v.policy_disposition !== "retain_current"
    || !policies.includes(v.policy_state as string) || !Array.isArray(v.objects) || v.objects.length !== 2) return false;
  return v.objects.every((row, index) => exact(row, ["purpose", "key", "sha256", "size_bytes", "payload_preview", "expected_etag"])
    && row.purpose === (index === 0 ? "primary" : "health") && key(row.key) && hash(row.sha256) && size(row.size_bytes)
    && typeof row.payload_preview === "string" && new TextEncoder().encode(row.payload_preview).length === row.size_bytes
    && etag(row.expected_etag)) && v.objects.reduce((total: number, row: { size_bytes: number }) => total + row.size_bytes, 0) <= 65536;
}
