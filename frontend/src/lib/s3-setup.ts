import { DEMO_MODE, request } from "./api";

export interface S3SetupProfile { profile_id: string; profile_digest: string }
export interface S3SetupProfiles { schema_version: "bluefire.s3-onboarding.v1"; profiles: S3SetupProfile[]; truncated: boolean }
export const configurationStates = ["unsupported_host", "method_unavailable", "missing", "incomplete", "invalid", "profile_missing", "profile_changed", "configured"] as const;
export type S3ConfigurationState = typeof configurationStates[number];
export interface S3SetupEnvironment { environment_id: string; runtime_state: "verified" | "unavailable"; access_reference_state: "absent" | "current" | "expired"; scope_state: "current" | "not_current"; fixture_generation: 1 | 2 }
export interface S3SetupStatus { schema_version: "bluefire.s3-setup-status.v1"; profile_id: string; configuration_state: S3ConfigurationState; revision_digest: string | null; environments: S3SetupEnvironment[]; context_digest: string }
export interface S3SetupCheck { schema_version: "bluefire.s3-onboarding-check.v1"; profile_id: string; profile_digest: string; host_state: "authenticated" | "unavailable"; setup: S3SetupStatus | null; context_digest: string }
export const MAX_S3_DRAFT_BYTES = 128 * 1024;
export interface S3SetupDraftRequest extends S3SetupProfile { configuration_json: string }
export interface S3SetupDraftEnvironment { environment_id: string; display_name: string; account_id: string; region: string; bucket: string; expires_at: string; fixture_generation: 1 | 2 }
export interface S3SetupDraftReview extends S3SetupProfile { schema_version: "bluefire.s3-onboarding-draft-review.v1"; validation_scope: "structural_only"; source_sha256: string; configuration_digest: string; environments: S3SetupDraftEnvironment[] }
const hash = (value: unknown) => typeof value === "string" && /^sha256:[0-9a-f]{64}$/.test(value);
const identifier = (value: unknown) => typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(value);
const exact = (value: unknown, keys: string[]) => value !== null && typeof value === "object" && !Array.isArray(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const invalid = () => new Error("S3 setup changed or returned an incomplete response. Check the selected connection again.");
const profile = (value: S3SetupProfile) => exact(value, ["profile_id", "profile_digest"]) && identifier(value.profile_id) && hash(value.profile_digest);

export function checkedSetupProfiles(value: S3SetupProfiles): S3SetupProfiles {
  if (!exact(value, ["schema_version", "profiles", "truncated"]) || value.schema_version !== "bluefire.s3-onboarding.v1" || typeof value.truncated !== "boolean" || !Array.isArray(value.profiles) || value.profiles.length > 64 || !value.profiles.every(profile) || new Set(value.profiles.map(row => row.profile_id)).size !== value.profiles.length) throw invalid();
  return value;
}

export function checkedSetup(value: S3SetupCheck, selected: S3SetupProfile): S3SetupCheck {
  if (!profile(selected) || !exact(value, ["schema_version", "profile_id", "profile_digest", "host_state", "setup", "context_digest"]) || value.schema_version !== "bluefire.s3-onboarding-check.v1" || value.profile_id !== selected.profile_id || value.profile_digest !== selected.profile_digest || !hash(value.context_digest) || !["authenticated", "unavailable"].includes(value.host_state)) throw invalid();
  if (value.host_state === "unavailable") { if (value.setup !== null) throw invalid(); return value; }
  const setup = value.setup;
  if (!setup || !exact(setup, ["schema_version", "profile_id", "configuration_state", "revision_digest", "environments", "context_digest"]) || setup.schema_version !== "bluefire.s3-setup-status.v1" || setup.profile_id !== selected.profile_id || !configurationStates.includes(setup.configuration_state) || !hash(setup.context_digest) || !Array.isArray(setup.environments) || setup.environments.length > 8 || Boolean(setup.environments.length) !== (setup.configuration_state === "configured") || (["configured", "profile_missing", "profile_changed"].includes(setup.configuration_state) ? !hash(setup.revision_digest) : setup.revision_digest !== null)) throw invalid();
  if (new Set(setup.environments.map(row => row?.environment_id)).size !== setup.environments.length || setup.environments.some(row => !exact(row, ["environment_id", "runtime_state", "access_reference_state", "scope_state", "fixture_generation"]) || !identifier(row.environment_id) || !["verified", "unavailable"].includes(row.runtime_state) || !["absent", "current", "expired"].includes(row.access_reference_state) || !["current", "not_current"].includes(row.scope_state) || ![1, 2].includes(row.fixture_generation))) throw invalid();
  return value;
}

function installed() { if (DEMO_MODE) throw new Error("S3 setup requires the installed local service."); }
export async function draftSourceDigest(source: string): Promise<string> {
  if (typeof source !== "string" || !source.trim() || source.length > MAX_S3_DRAFT_BYTES) throw new Error("The nonsecret configuration must be JSON text of at most 128 KiB.");
  const bytes = new TextEncoder().encode(source);
  if (bytes.length > MAX_S3_DRAFT_BYTES) throw new Error("The nonsecret configuration exceeds 128 KiB.");
  const value = await crypto.subtle.digest("SHA-256", bytes);
  return `sha256:${Array.from(new Uint8Array(value), byte => byte.toString(16).padStart(2, "0")).join("")}`;
}

export function checkedDraftReview(value: S3SetupDraftReview, selected: S3SetupProfile, sourceDigest: string): S3SetupDraftReview {
  if (!profile(selected) || !exact(value, ["schema_version", "profile_id", "profile_digest", "validation_scope", "source_sha256", "configuration_digest", "environments"]) || value.schema_version !== "bluefire.s3-onboarding-draft-review.v1" || value.validation_scope !== "structural_only" || value.profile_id !== selected.profile_id || value.profile_digest !== selected.profile_digest || !hash(sourceDigest) || value.source_sha256 !== sourceDigest || !hash(value.configuration_digest) || !Array.isArray(value.environments) || !value.environments.length || value.environments.length > 8) throw invalid();
  if (value.environments.some(row => !exact(row, ["environment_id", "display_name", "account_id", "region", "bucket", "expires_at", "fixture_generation"]) || !identifier(row.environment_id) || typeof row.display_name !== "string" || !row.display_name || row.display_name.length > 100 || typeof row.account_id !== "string" || !/^[0-9]{12}$/.test(row.account_id) || typeof row.region !== "string" || !/^[a-z]{2}-[a-z]+-[1-9][0-9]?$/.test(row.region) || typeof row.bucket !== "string" || !/^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/.test(row.bucket) || typeof row.expires_at !== "string" || row.expires_at.length > 40 || !Number.isFinite(Date.parse(row.expires_at)) || ![1, 2].includes(row.fixture_generation)) || new Set(value.environments.map(row => row.environment_id)).size !== value.environments.length) throw invalid();
  return value;
}

export const s3SetupApi = {
  profiles: async () => { installed(); return checkedSetupProfiles(await request<S3SetupProfiles>("/s3-access/setup")); },
  check: async (selected: S3SetupProfile) => { installed(); if (!profile(selected)) throw invalid(); return checkedSetup(await request<S3SetupCheck>("/s3-access/setup/check", { method: "POST", body: JSON.stringify(selected) }), selected); },
  reviewDraft: async (input: S3SetupDraftRequest) => {
    installed();
    const selected = { profile_id: input.profile_id, profile_digest: input.profile_digest };
    if (!profile(selected) || !exact(input, ["profile_id", "profile_digest", "configuration_json"])) throw invalid();
    const sourceDigest = await draftSourceDigest(input.configuration_json);
    return checkedDraftReview(await request<S3SetupDraftReview>("/s3-access/setup/review", { method: "POST", body: JSON.stringify(input) }), selected, sourceDigest);
  },
};
