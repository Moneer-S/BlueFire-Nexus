import { readComparisonContext, writeComparisonContext, type ComparisonSelection } from "./comparison-context";
import { detectionEvaluationHandoff, registeredDetectionEvaluationLink } from "./run-handoffs";

function validSnapshotId(value: string): boolean {
  return /^run-comparison-[0-9a-f]{64}$/.test(value);
}

export function readComparisonEvaluationNavigation(params: URLSearchParams): {
  runId: string;
  candidateId: string;
  comparison: ComparisonSelection;
  snapshotId?: string;
  returnPath: string;
} | undefined {
  const handoff = detectionEvaluationHandoff(params);
  const context = readComparisonContext(params);
  const snapshots = params.getAll("snapshot");
  if (snapshots.length > 1 || (snapshots.length === 1 && !validSnapshotId(snapshots[0]!))) return undefined;
  const snapshotId = snapshots[0];
  if (!handoff || !context.explicit || context.invalid || !context.baselineId || !context.revisedId
    || !context.runIds.includes(handoff.runId)
    || (handoff.candidateId !== context.baselineId && handoff.candidateId !== context.revisedId)) return undefined;
  const comparison = { runIds: context.runIds, baselineId: context.baselineId, revisedId: context.revisedId };
  // Only validated comparison choices and snapshot identity cross back. The
  // comparison page reloads the snapshot and checks its recorded run order.
  // No caller-supplied destination
  // or execution/approval parameters can become part of the return URL.
  const returnParams = writeComparisonContext(new URLSearchParams(), comparison);
  if (snapshotId) returnParams.set("snapshot", snapshotId);
  return { ...handoff, comparison, ...(snapshotId ? { snapshotId } : {}), returnPath: `/compare?${returnParams}` };
}

export function comparisonEvaluationLink(runId: string, candidateId: string, comparison: ComparisonSelection, snapshotId?: string): string | undefined {
  const handoff = registeredDetectionEvaluationLink(runId, candidateId);
  if (!handoff || (snapshotId !== undefined && !validSnapshotId(snapshotId))) return undefined;
  let params: URLSearchParams;
  try {
    params = writeComparisonContext(new URLSearchParams(handoff.slice(handoff.indexOf("?") + 1)), comparison);
    if (snapshotId) params.set("snapshot", snapshotId);
  } catch { return undefined; }
  return readComparisonEvaluationNavigation(params) ? `/detection-lab?${params}` : undefined;
}
