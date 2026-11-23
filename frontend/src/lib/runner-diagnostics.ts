import { ApiError } from "./api";

export function runnerDiagnosticsPath(profileId?: string) {
  return profileId ? `/runners?profile=${encodeURIComponent(profileId)}` : "/runners";
}

/** Lifecycle errors already contain path-free refusal reasons from the service. */
export function runnerLifecycleFailure(error: unknown): string[] {
  if (!(error instanceof ApiError) || !error.code.startsWith("runner_") || !Array.isArray(error.details)) return [];
  return error.details.filter((item): item is string => typeof item === "string" && item.length > 0 && item.length <= 1600).slice(0, 8);
}
