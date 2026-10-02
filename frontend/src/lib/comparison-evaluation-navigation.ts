import { readComparisonContext, writeComparisonContext, type ComparisonSelection } from "./comparison-context";
import { detectionEvaluationHandoff, registeredDetectionEvaluationLink } from "./run-handoffs";

export function readComparisonEvaluationNavigation(params: URLSearchParams): {
  runId: string;
  candidateId: string;
  comparison: ComparisonSelection;
  returnPath: string;
} | undefined {
  const handoff = detectionEvaluationHandoff(params);
  const context = readComparisonContext(params);
  if (!handoff || !context.explicit || context.invalid || !context.baselineId || !context.revisedId
    || !context.runIds.includes(handoff.runId)
    || (handoff.candidateId !== context.baselineId && handoff.candidateId !== context.revisedId)) return undefined;
  const comparison = { runIds: context.runIds, baselineId: context.baselineId, revisedId: context.revisedId };
  // Only validated comparison choices cross back. No caller-supplied destination
  // or execution/approval parameters can become part of the return URL.
  return { ...handoff, comparison, returnPath: `/compare?${writeComparisonContext(new URLSearchParams(), comparison)}` };
}

export function comparisonEvaluationLink(runId: string, candidateId: string, comparison: ComparisonSelection): string | undefined {
  const handoff = registeredDetectionEvaluationLink(runId, candidateId);
  if (!handoff) return undefined;
  let params: URLSearchParams;
  try {
    params = writeComparisonContext(new URLSearchParams(handoff.slice(handoff.indexOf("?") + 1)), comparison);
  } catch { return undefined; }
  return readComparisonEvaluationNavigation(params) ? `/detection-lab?${params}` : undefined;
}
