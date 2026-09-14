import { collectionObservationSteps, collectionObserverSelection } from "./collection-observation";
import { hasAdaptiveApprovalReview } from "./approvalReview";
import type { CatalogResponse, PreflightReport, RunConfiguration, Scenario } from "../types";

export function configurationForMode(config: RunConfiguration, mode: RunConfiguration["mode"], catalog: CatalogResponse, scenario: Scenario): RunConfiguration {
  if (config.mode === mode) return config;
  const profile = catalog.runner_profiles.find((item) => item.mode === mode && (mode !== "execute" || item.id === "sandbox-execute.v1"));
  return { ...config, mode, profileId: profile?.id ?? "", collectors: collectionObserverSelection(config, mode === "execute" && collectionObservationSteps(scenario).length > 0), approved: false, approvedBy: "" };
}

export function hasExecutePlanReview(preflight?: PreflightReport, scenario?: Scenario) {
  const binding = preflight?.approval_binding;
  return Boolean(preflight?.plan && binding && [binding.state_digest, binding.plan_digest, binding.target_scope_digest, binding.profile_id, binding.maximum_tier].every(value => typeof value === "string" && value.length > 0)
    && typeof preflight.approval_envelope?.envelope_digest === "string" && preflight.approval_envelope.envelope_digest.length > 0 && Array.isArray(preflight.approval_envelope.steps)
    && hasAdaptiveApprovalReview(preflight, Boolean(scenario?.adaptive_execution))
    && (preflight.ready || preflight.status === "approval_required"));
}
