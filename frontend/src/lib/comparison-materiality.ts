import type { ComparisonDelta } from "../types";

export function hasMaterialDelta(delta: ComparisonDelta): boolean {
  if (typeof delta.material_changed === "boolean") return delta.material_changed;
  const evidence = delta.evidence_detail_delta;
  const structuralChange = Boolean(
    delta.material_configuration_changed || delta.catalog_authority_changed ||
    delta.objective_changed || delta.first_blocked_changed || delta.cleanup_changed ||
    delta.autonomy_changed || delta.ai_provider_changed || delta.target_scope_changed ||
    delta.first_path_divergence !== null && delta.first_path_divergence !== undefined && delta.first_path_divergence >= 0 ||
    Object.values(delta.evidence_delta ?? {}).some(Boolean) ||
    evidence?.observed_artifacts_added?.length || evidence?.observed_artifacts_removed?.length ||
    evidence?.observed_artifacts_changed?.length || evidence?.evidence_gaps_added?.length ||
    evidence?.evidence_gaps_removed?.length || Object.values(evidence?.producer_delta ?? {}).some(Boolean) ||
    Object.values(delta.detection_delta ?? {}).some(Boolean) || Object.values(delta.outcome_delta ?? {}).some(Boolean) ||
    delta.detection_match_delta || delta.benign_match_delta || delta.ai_proposal_delta ||
    delta.telemetry_added?.length || delta.telemetry_removed?.length ||
    delta.controls_added?.length || delta.controls_removed?.length ||
    Object.values(delta.dimensions ?? {}).some((dimension) => dimension.changed === true)
  );
  if (structuralChange) return true;
  // Older responses can classify ancestry alone as "mixed". Preserve their
  // substantive assessment signals, while lineage and elapsed time stay descriptive.
  const signals = delta.signals?.filter((signal) => signal !== "replay_variant_changed") ?? [];
  if (signals.length > 0) return true;
  if (delta.assessment === "mixed" && delta.signals?.length) return false;
  return Boolean(delta.assessment && delta.assessment !== "no_material_change");
}
