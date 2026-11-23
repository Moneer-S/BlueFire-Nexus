import type { DetectionCandidate, DetectionResource } from "../types";

function record(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

function ids(value: unknown): string[] | undefined {
  return Array.isArray(value) && value.length <= 128
    && value.every(item => typeof item === "string" && item.length > 0 && item.length <= 200)
    && new Set(value).size === value.length ? value as string[] : undefined;
}

function sameIds(before: string[], after: string[]) {
  return before.length === after.length && before.every(id => after.includes(id));
}

function validCount(value: unknown, total: number): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && value <= total;
}

const parserNames: Record<string, string> = {
  internal: "bluefire-structured-matcher", sqlite: "SQLite bounded executor", sigma: "pySigma", yara: "YARA-Python",
};
const digest = (value: unknown): value is string => typeof value === "string" && /^sha256:[0-9a-f]{64}$/.test(value);

function parserResult(candidate: DetectionCandidate) {
  const validation = record(candidate.validation);
  const parser = record(candidate.parser_backend);
  const history = Array.isArray(candidate.lifecycle_history) ? candidate.lifecycle_history.map(record) : [];
  const lastParse = history.filter(row => row.action === "parse").at(-1);
  if (lastParse?.outcome === "rejected") return "Failed";
  const language = candidate.target_language ?? candidate.language ?? "internal";
  if (language === "spl" && validation.syntax_checked === true && validation.authoritative_backend_validated === false) return "Structural only";
  return ["parsed", "fixture_exercised", "observed_exercised", "benign_evaluated", "rejected"].includes(candidate.state) && parserNames[language]
    && parser.name === parserNames[language]
    && typeof parser.version === "string" && parser.version.length > 0 ? "Parsed" : "Unavailable";
}

function fixtureResult(candidate: DetectionCandidate, benign: boolean): string {
  const validation = record(candidate.validation);
  const population = ids(benign ? candidate.benign_fixture_ids : candidate.malicious_fixture_ids);
  if (!population?.length || validation.source_rule_executed !== true || parserResult(candidate) !== "Parsed") return "Unavailable";
  const language = candidate.target_language ?? candidate.language ?? "internal";
  if (language === "internal") {
    const history = Array.isArray(candidate.lifecycle_history) ? candidate.lifecycle_history.map(record) : [];
    const action = benign ? "evaluate_benign" : "exercise_fixtures";
    if (!history.some(row => row.action === action)) return "Unavailable";
    if (validation[benign ? "benign_fixture_backend" : "fixture_backend"] !== parserNames.internal) return "Unavailable";
    // The positive aggregate may also contain observed matches; never divide that
    // mixed population by a fixture denominator or re-run the matcher to infer it.
    if (!benign && (candidate.state === "observed_exercised" || candidate.observed_evidence_ids?.length || history.some(row => row.action === "exercise_observed") || validation.observed_exercise !== undefined)) return "Unavailable";
    const count = benign ? candidate.benign_match_count : candidate.match_count;
    return validCount(count, population.length) ? `${count} / ${population.length} matched` : "Unavailable";
  }
  const sourceBound = language === "yara"
    ? digest(validation.source_sha256) && validation.executed_source_sha256 === validation.source_sha256
    : ["sqlite", "sigma"].includes(language) && digest(validation.query_sha256) && validation.executed_query_sha256 === validation.query_sha256;
  const evaluated = ids(validation[benign ? "benign_evaluated_fixture_ids" : "evaluated_fixture_ids"]);
  const matched = ids(validation[benign ? "benign_matched_fixture_ids" : "matched_fixture_ids"]);
  if (!sourceBound || !evaluated || !matched || !sameIds(evaluated, population) || !matched.every(id => evaluated.includes(id))) return "Unavailable";
  return `${matched.length} / ${evaluated.length} matched`;
}

/** Summarize this saved revision's retained checks; never current draft or run results. */
export function recordedDetectionSummary(resource: DetectionResource | undefined, selectedId: string) {
  const candidate = resource?.document;
  const unavailable = { revision: undefined, parser: "Unavailable", malicious: "Unavailable", benign: "Unavailable" };
  if (!resource || resource.id !== selectedId || !candidate || candidate.candidate_id !== selectedId
    || !Number.isSafeInteger(candidate.revision) || candidate.revision! < 1 || !digest(candidate.definition_digest)) return unavailable;
  return { revision: candidate.revision, parser: parserResult(candidate), malicious: fixtureResult(candidate, false), benign: fixtureResult(candidate, true) };
}
