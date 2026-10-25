import type { ComparisonResponse, RunStep } from "../types";

type Summary = ComparisonResponse["summaries"][number];
export interface RecordedComparisonLabel {
  name: string;
  method?: string;
  record?: Pick<RunStep, "step_id" | "behavior_id" | "action_id" | "simulation_id">;
}
export interface RecordedPathDifference {
  baselineRunId: string;
  comparedRunId: string;
  index: number;
  kind: "method" | "path";
  detail: string;
}
type Labels = ReadonlyMap<string, { path: readonly RecordedComparisonLabel[] }>;

function methodChanged(before?: RecordedComparisonLabel["record"], after?: RecordedComparisonLabel["record"]) {
  if (!before || !after || before.step_id !== after.step_id) return false;
  return (["behavior_id", "action_id", "simulation_id"] as const).some(key =>
    typeof before[key] === "string" && Boolean(before[key]) && typeof after[key] === "string" && Boolean(after[key]) && before[key] !== after[key]);
}

function methodLabel(label?: RecordedComparisonLabel) {
  return label?.method && !["Method details unavailable", "Method unavailable in this catalog"].includes(label.method) ? label.method : label?.name;
}

function firstDifference(baseline: Summary, compared: Summary, labels: Labels): RecordedPathDifference | undefined {
  const before = labels.get(baseline.run_id)?.path ?? [], after = labels.get(compared.run_id)?.path ?? [];
  for (let index = 0; index < Math.max(baseline.path.length, compared.path.length); index += 1) {
    const differentPath = baseline.path[index] !== compared.path[index];
    const differentMethod = !differentPath && before[index]?.record?.step_id === baseline.path[index]
      && after[index]?.record?.step_id === compared.path[index] && methodChanged(before[index]?.record, after[index]?.record);
    if (!differentPath && !differentMethod) continue;
    const from = differentMethod ? methodLabel(before[index]) : before[index]?.name;
    const to = differentMethod ? methodLabel(after[index]) : after[index]?.name;
    const detail = from && to && from !== to ? `At recorded position ${index + 1}: ${from} → ${to}.`
      : differentPath ? `The recorded paths first differ at position ${index + 1}.`
        : `A recorded method changes at position ${index + 1}; its exact identities are in run context.`;
    return { baselineRunId: baseline.run_id, comparedRunId: compared.run_id, index, kind: differentMethod ? "method" : "path", detail };
  }
  return undefined;
}

/** Describe existing recorded facts; do not infer prevention, causation or a retest. */
export function comparisonConclusion(comparison: ComparisonResponse, labels: Labels) {
  const baseline = comparison.summaries.find(run => run.run_id === comparison.baseline_run_id) ?? comparison.summaries[0];
  const compared = comparison.summaries.filter(run => run !== baseline);
  const differences = baseline ? compared.flatMap(run => {
    const difference = firstDifference(baseline, run, labels);
    return difference ? [difference] : [];
  }) : [];
  const result = (title: string, detail: string) => ({ title, detail, differences });
  if (comparison.s3_access !== undefined) return result("Review the saved read outcomes", "S3 saved read results are shown separately below.");
  if (!baseline || !compared.length) return result("Recorded comparison incomplete", "A complete baseline and compared-run pair was not recorded.");
  if (compared.length > 1) {
    const achieved = comparison.summaries.filter(run => run.objective_reached === true).length;
    const unmet = comparison.summaries.filter(run => run.objective_reached === false).length;
    const unknown = comparison.summaries.length - achieved - unmet;
    const knownDifferences = compared.filter(run => differences.some(difference => difference.comparedRunId === run.run_id)
      || comparison.deltas.some(delta => delta.from_run_id === baseline.run_id && delta.to_run_id === run.run_id
        && typeof delta.first_path_divergence === "number" && Number.isInteger(delta.first_path_divergence) && delta.first_path_divergence >= 0));
    const unavailableDetails = knownDifferences.filter(run => !differences.some(difference => difference.comparedRunId === run.run_id)).length;
    return result(`Recorded results across ${comparison.summaries.length} runs`,
      `Recorded objectives: ${achieved} achieved, ${unmet} not reached, ${unknown} unreported.${knownDifferences.length ? ` ${knownDifferences.length} compared ${knownDifferences.length === 1 ? "run has" : "runs have"} a recorded path or method difference from baseline.` : ""}${unavailableDetails ? ` Details are unavailable for ${unavailableDetails} of those differences.` : ""}`);
  }
  const candidate = compared[0]!;
  const difference = differences[0];
  const delta = comparison.deltas.find(item => item.from_run_id === baseline.run_id && item.to_run_id === candidate.run_id);
  const reportedDifference = typeof delta?.first_path_divergence === "number" && Number.isInteger(delta.first_path_divergence) && delta.first_path_divergence >= 0;
  const unavailableDifference = !difference && reportedDifference;
  const change = difference?.detail ? `${difference.detail} ` : unavailableDifference ? "The saved comparison records a path or method difference; its details are unavailable. " : "";
  const simulated = baseline.mode === "simulate" && candidate.mode === "simulate";
  const sameMode = baseline.mode !== undefined && baseline.mode === candidate.mode;
  if (!sameMode) return result("Run modes differ or are unreported", `${change}Review each run's recorded objective and observations in its own mode.`);
  const knownObjectives = typeof baseline.objective_reached === "boolean" && typeof candidate.objective_reached === "boolean";
  if (!knownObjectives) return result(unavailableDifference ? "Recorded path or method difference" : difference?.kind === "method" ? "Different method, objective result unreported"
    : difference ? "Different paths, objective result unreported" : "Objective result not fully reported",
  `${change}Both objective results are needed to compare recorded completion.`);
  if (baseline.objective_reached !== candidate.objective_reached) return result(simulated ? "Different simulated objective results" : "Different recorded objective results",
    `${change}Baseline: objective ${baseline.objective_reached ? "achieved" : "not reached"}; compared run: objective ${candidate.objective_reached ? "achieved" : "not reached"}.`);
  const achieved = baseline.objective_reached === true;
  if (difference) {
    const setupChanged = delta?.target_scope_changed === true || delta?.dimensions?.scope?.changed === true
      || Boolean(baseline.profile_id && candidate.profile_id && baseline.profile_id !== candidate.profile_id);
    const subject = difference.kind === "method" ? "Different method" : "Different paths";
    const title = `${subject}${setupChanged ? " and setup" : ""}, ${simulated ? "simulated " : "recorded "}objectives ${achieved ? "achieved" : "not reached"}`;
    return result(title, difference.detail);
  }
  if (unavailableDifference) return result("Recorded path or method difference", `Details are unavailable. ${simulated
    ? achieved ? "Both simulations achieved their recorded objectives." : "Neither simulation reached its recorded objective."
    : achieved ? "Both runs record achieved objectives." : "Both runs record unmet objectives."}`);
  const evidence = delta?.evidence_detail_delta;
  const observationsChanged = Boolean(evidence?.observed_artifacts_added?.length || evidence?.observed_artifacts_removed?.length || evidence?.observed_artifacts_changed?.length);
  if (observationsChanged) return result(`${simulated ? "Simulated" : "Recorded"} objectives ${achieved ? "achieved" : "not reached"}, observations differ`,
    "The saved comparison records changes in independently observed artifacts. Review those observations separately from the objective result.");
  return result(achieved ? simulated ? "Both simulations achieved their recorded objectives" : "Both runs record achieved objectives"
    : simulated ? "Neither simulation reached its recorded objective" : "Both runs record unmet objectives",
  "Review the recorded observations and cleanup alongside the objective result.");
}
