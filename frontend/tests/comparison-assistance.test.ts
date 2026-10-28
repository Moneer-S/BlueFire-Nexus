import { afterEach, expect, it, vi } from "vitest";
import { request } from "../src/lib/api";
import { checkedComparisonAssistanceContext, comparisonAssistanceContext, comparisonAssistanceLimitations, validComparisonAssistanceSelection, type ComparisonAssistanceContext, type ComparisonAssistanceSelection } from "../src/lib/comparison-assistance";
import { clearAssistanceReceipt, readAssistanceReceipt, storeAssistanceReceipt, type ComparisonAssistanceRequest } from "../src/lib/assistance";

vi.mock("../src/lib/api", () => ({ request: vi.fn() }));
const hash = "a".repeat(64);
const selection: ComparisonAssistanceSelection = { kind: "comparison_snapshot", snapshot_id: `run-comparison-${hash}`, snapshot_digest: `sha256:${hash}` };
const counts = { evidence_records: null, observed_artifacts: null, evidence_gaps: null };
function context(): ComparisonAssistanceContext {
  return {
    schema_version: "bluefire.assistance-context.v1", selected: selection, context_digest: `sha256:${"b".repeat(64)}`,
    analysis_only: true, capabilities: [], limitations: [...comparisonAssistanceLimitations],
    reference_summary: {
      schema_version: "bluefire.comparison-assistance-summary.v1",
      saved_comparison: {
        run_count: 2, baseline_position: 1,
        runs: [1, 2].map(position => ({ position, mode: "simulate", objective_reached: null, recorded_attempts: null, repeated_step_ids: null,
          first_stop: { recorded: false }, observations: counts,
          detection: { total_matches: null, observed_matches: null, fixture_matches: null, benign_matches: null },
          cleanup: { source: "not_recorded", authoritative: false, state: "unknown", success: null } })),
        changes: [{ compared_position: 2, objective_relation: "unreported", material_changed: null, material_changes: null, first_divergence_position: null, divergence_kind: "unreported", observations: { added: null, removed: null, changed: null } }],
        legitimate_use: { state: "not_recorded" },
      },
      source_integrity: { status: "verified", runs: [{ position: 1, status: "verified" }, { position: 2, status: "verified" }] },
    },
  };
}
afterEach(() => vi.restoreAllMocks());

it("accepts only the exact saved snapshot binding and analysis-only minimized context", () => {
  const response = context();
  expect(validComparisonAssistanceSelection(selection)).toBe(true);
  expect(checkedComparisonAssistanceContext(response, selection)).toBe(response);
  expect(validComparisonAssistanceSelection({ ...selection, snapshot_digest: `sha256:${"c".repeat(64)}` })).toBe(false);
  expect(validComparisonAssistanceSelection({ ...selection, snapshot_id: `run-comparison-${"A".repeat(64)}` })).toBe(false);
  expect(() => checkedComparisonAssistanceContext({ ...response, selected: { ...selection, snapshot_digest: `sha256:${"c".repeat(64)}` } }, selection)).toThrow();
  expect(() => checkedComparisonAssistanceContext({ ...response, capabilities: [{ id: "run.saved_graph_and_inspect" }] }, selection)).toThrow();
  expect(() => checkedComparisonAssistanceContext({ ...response, analysis_only: false }, selection)).toThrow();
  expect(() => checkedComparisonAssistanceContext({ ...response, limitations: [] }, selection)).toThrow();
  expect(() => checkedComparisonAssistanceContext({ ...response, extra: "not in contract" }, selection)).toThrow();
});

it("rejects malformed positions, unbounded counts, invalid provenance and inconsistent source integrity", () => {
  const response = context();
  const summary = response.reference_summary;
  expect(() => checkedComparisonAssistanceContext({ ...response, reference_summary: { ...summary, saved_comparison: { ...summary.saved_comparison, runs: [{ ...summary.saved_comparison.runs[0], position: 2 }, summary.saved_comparison.runs[1]] } } }, selection)).toThrow();
  expect(() => checkedComparisonAssistanceContext({ ...response, reference_summary: { ...summary, saved_comparison: { ...summary.saved_comparison, runs: [{ ...summary.saved_comparison.runs[0], recorded_attempts: 2_147_483_648 }, summary.saved_comparison.runs[1]] } } }, selection)).toThrow();
  expect(() => checkedComparisonAssistanceContext({ ...response, reference_summary: { ...summary, source_integrity: { status: "verified", runs: [{ position: 1, status: "missing" }, { position: 2, status: "verified" }] } } }, selection)).toThrow();
  expect(() => checkedComparisonAssistanceContext({ ...response, reference_summary: { ...summary, saved_comparison: { ...summary.saved_comparison, changes: [{ ...summary.saved_comparison.changes[0], objective_relation: "same_recorded_result", unknown: true }] } } }, selection)).toThrow();
  expect(() => checkedComparisonAssistanceContext({ ...response, reference_summary: { ...summary, saved_comparison: { ...summary.saved_comparison, changes: [{ ...summary.saved_comparison.changes[0], material_changed: true, material_changes: [] }] } } }, selection)).toThrow();
});

it("checks saved S3 result rows and refuses unsupported access claims", () => {
  const response = context();
  const legitimate_use = {
    state: "saved_s3_read_results", comparison_state: "paired", change_state: "changed",
    rows: [["probe", "primary"], ["legitimate", "primary"], ["legitimate", "health"]].map(([reader, purpose]) => ({
      reader, purpose,
      baseline: { state: "read", provenance: "synthetic", cleanup: "verified" },
      retest: { state: reader === "probe" ? "service_denied" : "read", provenance: "synthetic", cleanup: "verified" }, changed: reader === "probe",
    })),
    gaps: [], proof_scope: "saved_read_results_only", effective_access_claim: false, defensive_effectiveness_claim: false,
  };
  const withS3 = { ...response, reference_summary: { ...response.reference_summary, saved_comparison: { ...response.reference_summary.saved_comparison, legitimate_use } } };
  expect(checkedComparisonAssistanceContext(withS3, selection)).toBe(withS3);
  expect(() => checkedComparisonAssistanceContext({ ...withS3, reference_summary: { ...withS3.reference_summary, saved_comparison: { ...withS3.reference_summary.saved_comparison, legitimate_use: { ...legitimate_use, effective_access_claim: true } } } }, selection)).toThrow();
  expect(() => checkedComparisonAssistanceContext({ ...withS3, reference_summary: { ...withS3.reference_summary, saved_comparison: { ...withS3.reference_summary.saved_comparison, legitimate_use: { ...legitimate_use, rows: legitimate_use.rows.map((row, index) => index ? row : { ...row, changed: false }) } } } }, selection)).toThrow();
});

it("derives exact S3 phase gaps and rejects paired or clean claims over incomplete evidence", () => {
  const response = context();
  const rows = [
    { reader: "probe", purpose: "primary", baseline: { state: "read", provenance: "synthetic", cleanup: "verified" }, retest: { state: "service_denied", provenance: "synthetic", cleanup: "unknown" }, changed: null },
    { reader: "legitimate", purpose: "primary", baseline: { state: "read", provenance: "synthetic", cleanup: "verified" }, retest: { state: "not_recorded", provenance: null, cleanup: null }, changed: null },
    { reader: "legitimate", purpose: "health", baseline: { state: "read", provenance: "synthetic", cleanup: "verified" }, retest: { state: "not_recorded", provenance: null, cleanup: null }, changed: null },
  ];
  const legitimate_use = {
    state: "saved_s3_read_results", comparison_state: "partial", change_state: "unknown", rows,
    gaps: ["retest_selection_incomplete", "retest_observations_incomplete", "cleanup_unresolved"],
    proof_scope: "saved_read_results_only", effective_access_claim: false, defensive_effectiveness_claim: false,
  };
  const withPartial = { ...response, reference_summary: { ...response.reference_summary, saved_comparison: { ...response.reference_summary.saved_comparison, legitimate_use } } };
  expect(checkedComparisonAssistanceContext(withPartial, selection)).toBe(withPartial);
  expect(() => checkedComparisonAssistanceContext({ ...withPartial, reference_summary: { ...withPartial.reference_summary, saved_comparison: { ...withPartial.reference_summary.saved_comparison, legitimate_use: { ...legitimate_use, comparison_state: "paired", change_state: "unchanged", gaps: [], rows: rows.map(row => ({ ...row, changed: false })) } } } }, selection)).toThrow();
  expect(() => checkedComparisonAssistanceContext({ ...withPartial, reference_summary: { ...withPartial.reference_summary, saved_comparison: { ...withPartial.reference_summary.saved_comparison, legitimate_use: { ...legitimate_use, gaps: ["cleanup_unresolved"] } } } }, selection)).toThrow();
  expect(() => checkedComparisonAssistanceContext({ ...withPartial, reference_summary: { ...withPartial.reference_summary, saved_comparison: { ...withPartial.reference_summary.saved_comparison, legitimate_use: { ...legitimate_use, rows: rows.map((row, index) => index === 1 ? { ...row, health: "invalid" } : row) } } } }, selection)).toThrow();
});

it("fetches only the encoded exact snapshot context route and validates the response", async () => {
  vi.mocked(request).mockResolvedValue(context());
  await expect(comparisonAssistanceContext(selection)).resolves.toMatchObject({ selected: selection, capabilities: [] });
  expect(request).toHaveBeenCalledWith(`/comparison-snapshots/${encodeURIComponent(selection.snapshot_id)}/assistant-context`);
  vi.mocked(request).mockResolvedValue({ ...context(), selected: { ...selection, snapshot_digest: `sha256:${"c".repeat(64)}` } });
  await expect(comparisonAssistanceContext(selection)).rejects.toThrow(/context changed/);
  await expect(comparisonAssistanceContext({ ...selection, snapshot_id: "not-a-snapshot" })).rejects.toThrow(/exact saved comparison/);
});

it("retains the exact saved comparison selection in the durable request receipt", () => {
  const submitted: ComparisonAssistanceRequest = {
    submission_id: "123e4567-e89b-42d3-a456-426614174000", context_digest: `sha256:${"b".repeat(64)}`,
    selection, message: "Explain the saved comparison", autonomy: "assist", provider_id: "provider-test",
  };
  expect(storeAssistanceReceipt(submitted)).toBe(true);
  expect(readAssistanceReceipt()).toEqual(submitted);
  expect(clearAssistanceReceipt(submitted)).toBe(true);
});
