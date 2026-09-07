import { collectionObservationSteps, collectionObserverSelection } from "./collection-observation";
import type { CatalogResponse, PreflightReport, RunConfiguration, Scenario } from "../types";

export function configurationForMode(config: RunConfiguration, mode: RunConfiguration["mode"], catalog: CatalogResponse, scenario: Scenario): RunConfiguration {
  if (config.mode === mode) return config;
  const profile = catalog.runner_profiles.find((item) => item.mode === mode && (mode !== "execute" || item.id === "sandbox-execute.v1"));
  return { ...config, mode, profileId: profile?.id ?? "", collectors: collectionObserverSelection(config, mode === "execute" && collectionObservationSteps(scenario).length > 0), approved: false, approvedBy: "" };
}

export function hasLocalExecuteReview(preflight?: PreflightReport) {
  return Boolean(preflight?.approval_binding && preflight.approval_envelope && (preflight.ready || preflight.status === "approval_required"));
}
