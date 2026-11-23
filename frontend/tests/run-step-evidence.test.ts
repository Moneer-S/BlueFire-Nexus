import { describe, expect, it } from "vitest";
import type { EvidenceRecord, RunRecord, RunStep } from "../src/types";
import { resolveRunStepEvidence } from "../src/lib/run-step-evidence";

const runId = "run-20261025T120000Z-0123456789abcdef";
const stepId = "collect";

function step(evidence_ids?: string[]): RunStep {
  return { step_id: stepId, status: "success", evidence_ids };
}

function run(records?: EvidenceRecord[]): RunRecord {
  return { run_id: runId, mode: "execute", status: "completed", steps: [], ...(records ? { evidence: { records } } : {}) };
}

function evidence(evidence_id: string, provenance: EvidenceRecord["provenance"], extra: Partial<EvidenceRecord> = {}): EvidenceRecord {
  return { evidence_id, provenance, content: { marker: evidence_id }, ...extra };
}

describe("resolveRunStepEvidence", () => {
  it("resolves exact canonical identities in reference order without filtering provenance or mutating records", () => {
    const observed = evidence("evidence-observed", "observed", { run_id: runId, step_id: stepId });
    const synthetic = evidence("evidence-synthetic", "synthetic", { run_id: runId, step_id: stepId });
    const executed = evidence("evidence-executed", "executed", { run_id: runId, step_id: stepId });
    const records = [observed, synthetic, executed];
    const before = structuredClone(records);

    expect(resolveRunStepEvidence(run(records), step(["evidence-executed", "evidence-observed", "evidence-synthetic", "evidence-executed"]))).toEqual({
      records: [executed, observed, synthetic], unresolvedIds: [], distinctReferenceCount: 3,
    });
    expect(records).toEqual(before);
  });

  it("allows legacy id only when the canonical evidence_id is absent", () => {
    const legacy = { id: "legacy-evidence", provenance: "unknown" } satisfies EvidenceRecord;
    const conflictingLegacy = { id: "not-the-canonical-id", evidence_id: "canonical-evidence", provenance: "observed" } satisfies EvidenceRecord;
    expect(resolveRunStepEvidence(run([legacy, conflictingLegacy]), step(["legacy-evidence", "not-the-canonical-id", "canonical-evidence"]))).toEqual({
      records: [legacy, conflictingLegacy], unresolvedIds: ["not-the-canonical-id"], distinctReferenceCount: 3,
    });
  });

  it("leaves absent references and missing run evidence unresolved without inventing links", () => {
    expect(resolveRunStepEvidence(run([]), step())).toEqual({ records: [], unresolvedIds: [], distinctReferenceCount: 0 });
    expect(resolveRunStepEvidence(run(), step(["missing-a", "missing-b"]))).toEqual({
      records: [], unresolvedIds: ["missing-a", "missing-b"], distinctReferenceCount: 2,
    });
    const unrelated = evidence("other-evidence", "observed", { step_id: stepId });
    expect(resolveRunStepEvidence(run([unrelated]), step(["missing-a"]))).toEqual({
      records: [], unresolvedIds: ["missing-a"], distinctReferenceCount: 1,
    });
  });

  it.each([
    ["run_id", { run_id: "another-run" }],
    ["step_id", { step_id: "another-step" }],
  ] as const)("keeps an explicit conflicting %s unresolved", (_field, attribution) => {
    const record = evidence("evidence-conflict", "executed", attribution);
    expect(resolveRunStepEvidence(run([record]), step(["evidence-conflict"]))).toEqual({
      records: [], unresolvedIds: ["evidence-conflict"], distinctReferenceCount: 1,
    });
  });

  it("allows legacy records with no run or step attribution when explicitly referenced", () => {
    const record = evidence("evidence-legacy", "synthetic");
    expect(resolveRunStepEvidence(run([record]), step(["evidence-legacy"]))).toEqual({
      records: [record], unresolvedIds: [], distinctReferenceCount: 1,
    });
  });

  it("treats duplicate matching identities as ambiguous instead of selecting either record", () => {
    const first = evidence("duplicate-id", "observed", { content: { marker: "first" } });
    const second = evidence("duplicate-id", "executed", { content: { marker: "second" } });
    expect(resolveRunStepEvidence(run([first, second]), step(["duplicate-id"]))).toEqual({
      records: [], unresolvedIds: ["duplicate-id"], distinctReferenceCount: 1,
    });
    const canonical = evidence("duplicate-id", "observed");
    const legacy = { id: "duplicate-id", provenance: "synthetic" } satisfies EvidenceRecord;
    expect(resolveRunStepEvidence(run([canonical, legacy]), step(["duplicate-id"])).unresolvedIds).toEqual(["duplicate-id"]);
  });
});
