import { MAX_COMPARISON_RUNS, writeComparisonContext } from "./comparison-context";
import { runLabel } from "./run-presentation";
import type { DetectionResource, DetectionRunEvaluation, RunRecord } from "../types";

export interface EvaluationTarget {
  id: string;
  rootId: string;
  revision: number;
  definitionDigest: string;
  language: string;
  querySha256: string | null;
  sourceSha256: string | null;
  parserBackend: Record<string, string>;
}

export interface EvaluationSource { runId: string; label: string; manifestIdentity: string }
export interface EvaluationCaseInputs {
  question: string;
  activity: "unknown" | "attack" | "benign";
  evaluationUse: "unspecified" | "development" | "independent";
}
export interface EvaluationPlanCase extends EvaluationCaseInputs { source: EvaluationSource & { manifestDigest: string }; runId: string }
export interface DetectionEvaluationPlan {
  runIds: string[];
  baseline: EvaluationTarget;
  target: EvaluationTarget;
  title: string;
  cases: EvaluationPlanCase[];
}
export interface EvaluationPlanOptions {
  runIds: string[];
  baselineId: string;
  revisedId: string;
  resources: DetectionResource[];
  reports: DetectionRunEvaluation[];
  sources: RunRecord[];
  manifestDigests: Record<string, string>;
  inputs?: Record<string, EvaluationCaseInputs>;
}

const digest = (value: unknown): value is string => typeof value === "string" && /^sha256:[0-9a-f]{64}$/.test(value);
const record = (value: unknown): value is Record<string, unknown> => Boolean(value) && typeof value === "object" && !Array.isArray(value);
const fail = (message: string): never => { throw new Error(message); };

// A stable comparison of supplied identity fields, not a cryptographic digest.
function stable(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
  if (record(value)) return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${stable(value[key])}`).join(",")}}`;
  return JSON.stringify(value) ?? "undefined";
}

export function evaluationTarget(resource: DetectionResource): EvaluationTarget | undefined {
  const candidate = resource.document;
  const language = candidate.target_language ?? candidate.language ?? "";
  const revision = candidate.revision ?? 1;
  if (!resource.id || candidate.candidate_id !== resource.id || resource.status !== candidate.state || !digest(resource.digest) || !digest(candidate.definition_digest)
    || !Number.isSafeInteger(revision) || revision < 1
    || !["internal", "sqlite", "sigma"].includes(language)
    || !["parsed", "fixture_exercised", "observed_exercised", "benign_evaluated"].includes(candidate.state)) return undefined;
  const query = candidate.validation?.query_sha256 ?? null;
  const source = candidate.validation?.source_sha256 ?? null;
  if ((query !== null && !digest(query)) || (source !== null && !digest(source))) return undefined;
  const backend = candidate.parser_backend ?? {};
  if (!record(backend) || Object.values(backend).some(value => typeof value !== "string")) return undefined;
  return { id: resource.id, rootId: candidate.revision_root_id ?? resource.id, revision,
    definitionDigest: candidate.definition_digest, language, querySha256: query, sourceSha256: source,
    parserBackend: Object.fromEntries(Object.entries(backend).sort()) as Record<string, string> };
}

export function sameEvaluationTarget(left: EvaluationTarget, right: EvaluationTarget): boolean {
  return stable(left) === stable(right);
}

export function missingRevisedEvaluationRuns(runIds: string[], reports: DetectionRunEvaluation[]): string[] {
  if (!runIds.length || runIds.length > MAX_COMPARISON_RUNS) fail("Choose between one and 32 runs.");
  // Reuse the navigation contract for bounded, unique ordered IDs.
  writeComparisonContext(new URLSearchParams(), { runIds, baselineId: "", revisedId: "" });
  const evaluated = new Set(reports.map(report => report.source.run_id));
  return runIds.filter(id => !evaluated.has(id));
}

export function evaluationSource(run: RunRecord, runId: string): EvaluationSource | undefined {
  const manifest = run.manifest;
  if (run.run_id !== runId || run.is_demo || !run.finalized_at || !record(manifest)
    || manifest.run_id !== runId || !digest(manifest.bundle_hash) || !record(manifest.files)) return undefined;
  // These are the manifest's actual server fields. Keeping their types bounded
  // makes this serialization identical to Python's canonical JSON; evidence
  // content (whose floating-point representation may differ) is not rehashed.
  if (manifest.schema_version !== "1.0" || !record(manifest.files["evidence.json"])
    || Object.keys(manifest).sort().join(",") !== "bundle_hash,files,run_id,schema_version"
    || Object.entries(manifest.files).some(([name, file]) => !/^[A-Za-z0-9_.-]+$/.test(name) || !record(file)
      || Object.keys(file).sort().join(",") !== "hash,size_bytes" || !digest(file.hash)
      || typeof file.size_bytes !== "number" || !Number.isSafeInteger(file.size_bytes) || file.size_bytes < 0)) return undefined;
  const manifestIdentity = stable(manifest);
  if (new TextEncoder().encode(manifestIdentity).length > 128 * 1024) return undefined;
  return { runId, label: runLabel(run), manifestIdentity };
}

function reportTargetMatches(report: DetectionRunEvaluation, target: EvaluationTarget): boolean {
  const candidate = report.candidate;
  return candidate.candidate_id === target.id && candidate.revision_root_id === target.rootId
    && candidate.revision === target.revision && candidate.definition_digest === target.definitionDigest
    && candidate.target_language === target.language && candidate.query_sha256 === target.querySha256
    && candidate.source_sha256 === target.sourceSha256 && stable(candidate.parser_backend) === stable(target.parserBackend);
}

export function evaluationPlanTargets({ baselineId, revisedId, resources, reports }: Pick<EvaluationPlanOptions, "baselineId" | "revisedId" | "resources" | "reports">): Pick<DetectionEvaluationPlan, "baseline" | "target" | "title"> {
  const original = resources.filter(resource => resource.id === baselineId);
  const revisions = resources.filter(resource => resource.id === revisedId);
  const baseline = original.length === 1 ? evaluationTarget(original[0]!) : undefined;
  const target = revisions.length === 1 ? evaluationTarget(revisions[0]!) : undefined;
  if (!baseline || !target || baseline.id === target.id || baseline.rootId !== target.rootId) return fail("The selected saved revisions are unavailable or do not share one lineage.");
  if (reports.some(report => !reportTargetMatches(report, target))) fail("Retained results do not match the selected revised rule.");
  return { baseline, target, title: revisions[0]!.document.title ?? "Revised rule" };
}

export function buildDetectionEvaluationPlan(options: EvaluationPlanOptions): DetectionEvaluationPlan {
  const { runIds, baselineId, revisedId, reports, sources, manifestDigests, inputs = {} } = options;
  writeComparisonContext(new URLSearchParams(), { runIds, baselineId, revisedId });
  const { baseline, target, title } = evaluationPlanTargets(options);
  const cases = missingRevisedEvaluationRuns(runIds, reports).map(runId => {
    const matches = sources.filter(source => source.run_id === runId);
    const source = matches.length === 1 ? evaluationSource(matches[0]!, runId) : undefined;
    if (!source) return fail("A selected source is unavailable, ambiguous or not a finalized run.");
    const manifestDigest = manifestDigests[runId];
    if (!digest(manifestDigest)) return fail("The reviewed source manifest has no verified digest.");
    const values = inputs[runId] ?? { question: "", activity: "unknown", evaluationUse: "unspecified" };
    if (typeof values.question !== "string" || values.question.trim().length > 1000
      || Array.from(values.question).some(character => character.charCodeAt(0) < 32)
      || !["unknown", "attack", "benign"].includes(values.activity)
      || !["unspecified", "development", "independent"].includes(values.evaluationUse)) fail("Review each question and classification before starting. Questions allow up to 1,000 printable characters.");
    return { runId, source: { ...source, manifestDigest }, question: values.question.trim(), activity: values.activity, evaluationUse: values.evaluationUse };
  });
  return { runIds: [...runIds], baseline, target, title, cases };
}

export function evaluationReportMatches(report: DetectionRunEvaluation, target: EvaluationTarget, item: EvaluationPlanCase): boolean {
  return Boolean(report && report.candidate && report.source && report.result && report.backend)
    && reportTargetMatches(report, target) && report.source.run_id === item.runId
    && report.source.manifest_digest === item.source.manifestDigest && digest(report.source.evidence_digest)
    && typeof report.evaluation_id === "string" && Boolean(report.evaluation_id)
    && ["matched", "not_matched", "insufficient_evidence", "backend_error"].includes(report.result.state)
    && typeof report.backend.executed === "boolean" && typeof report.result.gap_count === "number"
    && (report.result.match_count === null || (Number.isSafeInteger(report.result.match_count) && report.result.match_count >= 0))
    && Array.isArray(report.result.missing_fields)
    && report.case_role === item.activity
    && report.classification?.activity_label === item.activity
    && report.classification.requested_use === item.evaluationUse
    && (!item.question || report.question === item.question);
}
