import { expect, it } from "vitest";
import { createHash } from "node:crypto";
import {
  buildDetectionEvaluationPlan, evaluationReportMatches, evaluationSource, evaluationTarget,
  missingRevisedEvaluationRuns,
} from "../src/lib/detection-evaluation-plan";
import type { DetectionResource, DetectionRunEvaluation, RunRecord } from "../src/types";

const digest = `sha256:${"a".repeat(64)}`;
const manifest = (runId: string) => ({
  schema_version: "1.0", run_id: runId, bundle_hash: digest,
  files: { "evidence.json": { hash: digest, size_bytes: 123 } },
});
function manifestDigest(runId: string): string {
  const identity = JSON.stringify({ bundle_hash: digest, files: { "evidence.json": { hash: digest, size_bytes: 123 } }, run_id: runId, schema_version: "1.0" });
  return `sha256:${createHash("sha256").update(identity, "utf8").digest("hex")}`;
}
const manifestDigests = Object.fromEntries(["attack", "benign", "heldout"].map(id => [id, manifestDigest(id)]));

function resource(id: string, revision: number, root = "root"): DetectionResource {
  return {
    kind: "detections", id, status: "parsed", digest,
    created_at: "2026-09-06T12:00:00Z", updated_at: "2026-09-06T12:00:00Z",
    document: {
      candidate_id: id, title: `Rule ${revision}`, state: "parsed", revision, revision_root_id: root,
      definition_digest: digest, target_language: "sqlite", rule_source: "SELECT fixture_id FROM logs",
      parser_backend: { name: "SQLite", version: "3.45.1" },
      validation: { query_sha256: digest, source_sha256: digest },
    },
  };
}

function source(runId: string): RunRecord {
  return {
    run_id: runId, mode: "execute", status: "completed", created_at: "2026-09-06T12:00:00Z",
    finalized_at: "2026-09-06T12:01:00Z", steps: [], manifest: manifest(runId),
  };
}

function report(candidateId: string, runId: string, state: DetectionRunEvaluation["result"]["state"] = "matched"): DetectionRunEvaluation {
  return {
    schema_version: "bluefire.detection-run-evaluation.v1", evaluation_id: `${candidateId}-${runId}`,
    question: "", case_role: "unknown", case_role_basis: "operator_declared", created_at: "2026-09-06T12:02:00Z", limitations: [],
    candidate: {
      candidate_id: candidateId, revision_root_id: "root", revision: candidateId === "original" ? 1 : 2,
      definition_digest: digest, query_sha256: digest, source_sha256: digest, target_language: "sqlite",
      parser_backend: { name: "SQLite", version: "3.45.1" },
    },
    source: { run_id: runId, manifest_digest: manifestDigest(runId), evidence_digest: digest, observed_count: 1, evidence_count: 1, excluded_provenance_counts: {} },
    result: { state, match_count: state === "matched" ? 1 : state === "not_matched" ? 0 : null, evaluated_evidence_ids: [], matched_evidence_ids: [], gap_count: 0, gap_evidence_ids: [], mapped_fields: [], available_fields: [], unsupported_fields: [], missing_fields: [], diagnostic_codes: [] },
    backend: { name: "SQLite", executed: state === "matched" || state === "not_matched", version: "3.45.1" },
    classification: {
      activity_label: "unknown", activity_basis: "operator_declared", source_lineage: "unknown", lineage_basis: "unavailable",
      replay_source_run_id: null, evaluation_use: "unspecified", requested_use: "unspecified", use_basis: "unknown",
      development_reasons: [], development_history_complete: true, independence_verified: false,
    },
  };
}

const selection = { runIds: ["attack", "benign", "heldout"], baselineId: "original", revisedId: "revised" };
const resources = [resource("original", 1), resource("revised", 2)];

it("plans only missing revised cases in selected order, regardless of report order or outcome", () => {
  const retained = [report("revised", "heldout", "backend_error")];
  expect(missingRevisedEvaluationRuns(selection.runIds, retained)).toEqual(["attack", "benign"]);
  const plan = buildDetectionEvaluationPlan({ ...selection, resources, reports: retained, sources: selection.runIds.map(source), manifestDigests });
  expect(plan.runIds).toEqual(selection.runIds);
  expect(plan.cases.map(item => item.runId)).toEqual(["attack", "benign"]);
  expect(plan.cases.map(item => [item.activity, item.evaluationUse, item.question])).toEqual([
    ["unknown", "unspecified", ""], ["unknown", "unspecified", ""],
  ]);
});

it("treats every retained state, including insufficient evidence, as already evaluated", () => {
  const retained = [report("revised", "benign", "insufficient_evidence"), report("revised", "attack", "backend_error")];
  expect(missingRevisedEvaluationRuns(selection.runIds, retained)).toEqual(["heldout"]);
});

it.each([
  ["empty selection", []],
  ["duplicate IDs", ["attack", "attack"]],
  ["trimmed ID", [" attack"]],
  ["control character", ["attack\n"]],
  ["too many IDs", Array.from({ length: 33 }, (_, index) => `run-${index}`)],
] as const)("rejects %s before making a plan", (_label, runIds) => {
  expect(() => missingRevisedEvaluationRuns([...runIds], [])).toThrow();
});

it.each(["ambiguous baseline", "ambiguous revised", "unrelated lineage", "report identity mismatch"])("blocks %s", scenario => {
  const chosen = scenario === "unrelated lineage" ? [resources[0]!, resource("revised", 2, "other-root")] : [...resources];
  if (scenario === "ambiguous baseline") chosen.push(resource("original", 1));
  if (scenario === "ambiguous revised") chosen.push(resource("revised", 2));
  const reports = scenario === "report identity mismatch" ? [report("wrong-candidate", "heldout")] : [];
  expect(() => buildDetectionEvaluationPlan({ ...selection, resources: chosen, reports, sources: selection.runIds.map(source), manifestDigests })).toThrow();
});

it.each(["missing", "duplicate", "demo", "unfinalized", "wrong manifest ID", "bad bundle digest"])("refuses %s source identity", scenario => {
  const twoRunSelection = { ...selection, runIds: ["attack", "benign"] };
  const run = source("attack");
  if (scenario === "demo") run.is_demo = true;
  if (scenario === "unfinalized") delete run.finalized_at;
  if (scenario === "wrong manifest ID") run.manifest = manifest("other-run");
  if (scenario === "bad bundle digest") run.manifest = { ...manifest("attack"), bundle_hash: "bad" };
  const twoRunDigests = { attack: manifestDigest("attack"), benign: manifestDigest("benign") };
  if (scenario === "missing") expect(() => buildDetectionEvaluationPlan({ ...twoRunSelection, resources, reports: [], sources: [source("benign")], manifestDigests: twoRunDigests })).toThrow();
  else if (scenario === "duplicate") expect(() => buildDetectionEvaluationPlan({ ...twoRunSelection, resources, reports: [], sources: [run, run, source("benign")], manifestDigests: twoRunDigests })).toThrow();
  else expect(evaluationSource(run, "attack")).toBeUndefined();
});

it("retains explicit per-case classifications and question without inferring independence", () => {
  const plan = buildDetectionEvaluationPlan({
    ...selection, resources, reports: [], sources: selection.runIds.map(source), manifestDigests,
    inputs: { attack: { question: "Did the revised query find the staged item?", activity: "attack", evaluationUse: "development" }, benign: { question: "", activity: "benign", evaluationUse: "unspecified" } },
  });
  expect(plan.cases.map(({ runId, question, activity, evaluationUse }) => ({ runId, question, activity, evaluationUse }))).toEqual([
    { runId: "attack", question: "Did the revised query find the staged item?", activity: "attack", evaluationUse: "development" },
    { runId: "benign", question: "", activity: "benign", evaluationUse: "unspecified" },
    { runId: "heldout", question: "", activity: "unknown", evaluationUse: "unspecified" },
  ]);
});

it.each([
  ["oversized question", { question: "q".repeat(1001), activity: "unknown", evaluationUse: "unspecified" }],
  ["control character", { question: "line\nbreak", activity: "unknown", evaluationUse: "unspecified" }],
  ["invalid activity", { question: "", activity: "replay", evaluationUse: "unspecified" }],
  ["invalid data use", { question: "", activity: "unknown", evaluationUse: "independent-ish" }],
] as const)("refuses %s during plan construction", (_label, input) => {
  expect(() => buildDetectionEvaluationPlan({ ...selection, resources, reports: [], sources: selection.runIds.map(source), manifestDigests, inputs: { attack: input as never } })).toThrow();
});

it("validates a returned report against the frozen target, case, evidence and operator inputs", () => {
  const plan = buildDetectionEvaluationPlan({ ...selection, resources, reports: [], sources: selection.runIds.map(source), manifestDigests, inputs: { attack: { question: "Check this case", activity: "attack", evaluationUse: "development" } } });
  const reportValue = report("revised", "attack");
  reportValue.question = "Check this case";
  reportValue.case_role = "attack";
  reportValue.classification = {
    activity_label: "attack", activity_basis: "operator_declared", source_lineage: "unknown", lineage_basis: "unavailable",
    replay_source_run_id: null, evaluation_use: "development", requested_use: "development", use_basis: "operator_declared",
    development_reasons: [], development_history_complete: true, independence_verified: false,
  };
  expect(evaluationReportMatches(reportValue, plan.target, plan.cases[0]!)).toBe(true);
  expect(evaluationReportMatches({ ...reportValue, source: { ...reportValue.source, run_id: "benign" } }, plan.target, plan.cases[0]!)).toBe(false);
  expect(evaluationReportMatches({ ...reportValue, source: { ...reportValue.source, manifest_digest: `sha256:${"f".repeat(64)}` } }, plan.target, plan.cases[0]!)).toBe(false);
  expect(evaluationReportMatches({ ...reportValue, candidate: { ...reportValue.candidate, revision: 1 } }, plan.target, plan.cases[0]!)).toBe(false);
  expect(evaluationReportMatches({ ...reportValue, classification: { ...reportValue.classification!, requested_use: "independent" } }, plan.target, plan.cases[0]!)).toBe(false);
  const independentPlan = buildDetectionEvaluationPlan({ ...selection, resources, reports: [], sources: selection.runIds.map(source), manifestDigests,
    inputs: { attack: { question: "", activity: "unknown", evaluationUse: "independent" } } });
  const developmentOverride = { ...report("revised", "attack"), classification: {
    activity_label: "unknown" as const, activity_basis: "operator_declared" as const, source_lineage: "unknown" as const,
    lineage_basis: "unavailable" as const, replay_source_run_id: null, requested_use: "independent" as const,
    evaluation_use: "development" as const, use_basis: "recorded_development" as const,
    development_reasons: ["A source record links this data to rule development."], development_history_complete: true,
    independence_verified: false as const,
  } };
  expect(evaluationReportMatches(developmentOverride, independentPlan.target, independentPlan.cases[0]!)).toBe(true);
});

it("extracts only a validated saved evaluation target", () => {
  const target = evaluationTarget(resources[1]!);
  expect(target).toMatchObject({ id: "revised", rootId: "root", revision: 2, definitionDigest: digest, language: "sqlite" });
  expect(evaluationTarget({ ...resources[1]!, id: "different" })).toBeUndefined();
  expect(evaluationTarget({ ...resources[1]!, document: { ...resources[1]!.document, state: "hypothesis" } })).toBeUndefined();
});

it("matches a fixed canonical SHA-256 manifest vector", () => {
  const vectorRunId = "unicode-ü-run";
  const vectorManifest = {
    schema_version: "1.0", run_id: vectorRunId, bundle_hash: digest,
    files: {
      "2": { hash: `sha256:${"2".repeat(64)}`, size_bytes: 2 },
      "10": { hash: `sha256:${"1".repeat(64)}`, size_bytes: 10 },
      "evidence.json": { hash: `sha256:${"e".repeat(64)}`, size_bytes: 123 },
    },
  };
  const expectedCanonical = `{"bundle_hash":"${digest}","files":{"10":{"hash":"sha256:${"1".repeat(64)}","size_bytes":10},"2":{"hash":"sha256:${"2".repeat(64)}","size_bytes":2},"evidence.json":{"hash":"sha256:${"e".repeat(64)}","size_bytes":123}},"run_id":"${vectorRunId}","schema_version":"1.0"}`;
  const binding = evaluationSource({ run_id: vectorRunId, mode: "execute", status: "completed", finalized_at: "2026-09-06", steps: [], manifest: vectorManifest }, vectorRunId);
  expect(binding?.manifestIdentity).toBe(expectedCanonical);
  expect(createHash("sha256").update(expectedCanonical, "utf8").digest("hex")).toBe("39eadde111ab04fcdd49fed88270d9a6f3ba2dfdb6bda956871f0e939bbdee83"); // pragma: allowlist secret -- independently verified SHA-256 of the authored canonical manifest above
});
