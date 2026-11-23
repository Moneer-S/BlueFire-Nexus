import { describe, expect, it } from "vitest";
import { hasMaterialDelta } from "../src/lib/comparison-materiality";
import type { ComparisonDelta } from "../src/types";

const lineageOnly: ComparisonDelta = {
  from_run_id: "run-original", to_run_id: "run-replay", first_path_divergence: null,
  replay_lineage_changed: true, duration_delta_ms: 321,
  replay_lineage_delta: { changed: true, to_variant_types: ["exact"] },
};

describe("comparison materiality", () => {
  it("keeps lineage and duration descriptive for canonical and older responses", () => {
    expect(hasMaterialDelta({ ...lineageOnly, material_changed: false, assessment: "no_material_change" })).toBe(false);
    expect(hasMaterialDelta(lineageOnly)).toBe(false);
    expect(hasMaterialDelta({ ...lineageOnly, assessment: "mixed", signals: ["replay_variant_changed"] })).toBe(false);
  });

  it.each<Partial<ComparisonDelta>>([
    { first_path_divergence: 0 }, { controls_added: ["control_blocked"] },
    { evidence_delta: { observed: -1 } }, { evidence_detail_delta: { observed_artifacts_changed: [{ sha256: "changed" }] } },
    { detection_delta: { rendered: -1, parsed: 1 } }, { cleanup_changed: true },
    { material_configuration_changed: true }, { catalog_authority_changed: true },
    { dimensions: { implementation: { changed: true, profile_changed: true } } },
    { material_changed: true, material_changes: ["configuration"] },
    { assessment: "mixed" },
  ])("retains substantive change %j alongside replay ancestry", (change) => {
    expect(hasMaterialDelta({ ...lineageOnly, ...change })).toBe(true);
  });
});
