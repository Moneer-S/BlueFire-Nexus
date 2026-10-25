import { api } from "./api";
import { adSmbApi, adJobValid, checkedAdWorkflow, adPhaseLabels, type AdWorkflow } from "./ad-smb";
import { checkedFileAccessControl, fileAccessApi, fileAccessControlIdValid, fileAccessOperationLabels, type FileAccessControl, type FileAccessSubmission } from "./file-access";
import { checkedReceiverTest, phaseTitle, policyTitle, receiverJobValid, receiverOutcome } from "./receiver-defense";
import type { ReceiverDefenseEnvelope } from "./receiver-defense-types";
import { phaseName, s3Api, validS3Job, type S3Exercise } from "./s3-access";
import { objectives } from "./objectives";
import { workFamilies, type WorkFamily } from "./saved-defensive-work";
import { savedExperimentPath } from "./receiver-navigation";

export type ActiveWorkReference = { family: WorkFamily; id: string };
export type ActiveWorkResult = { label: string; value: string; tone?: "positive" | "caution" | "neutral" };
export type ActiveWorkSummary = {
  reference: ActiveWorkReference;
  title: string;
  objective: string;
  environment: string;
  phase: string;
  recordedState: string;
  change: string;
  results: ActiveWorkResult[];
  href: string;
  links: Array<{ label: string; href: string }>;
};

const notRecorded = "Not recorded";
const purposeId: Record<WorkFamily, string> = {
  handoff: "data-handoff",
  file: "file-access",
  domain: "ad-access",
  cloud: "s3-access",
};

function purpose(reference: ActiveWorkReference): string {
  return objectives.find(item => item.id === purposeId[reference.family])?.question ?? notRecorded;
}

function isActiveWorkReference(value: unknown): value is ActiveWorkReference {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const reference = value as Record<string, unknown>;
  if (Object.keys(reference).sort().join(",") !== "family,id" || typeof reference.id !== "string") return false;
  if (reference.family === "handoff") return receiverJobValid(reference.id);
  if (reference.family === "file") return fileAccessControlIdValid(reference.id);
  if (reference.family === "domain") return adJobValid(reference.id);
  if (reference.family === "cloud") return validS3Job(reference.id);
  return false;
}

export function parseActiveWorkReference(value: unknown): ActiveWorkReference | undefined {
  return isActiveWorkReference(value) ? { family: value.family, id: value.id } : undefined;
}

export function activeWorkHref(reference: ActiveWorkReference): string {
  if (!isActiveWorkReference(reference)) throw new Error("This saved work reference is invalid.");
  const family = workFamilies.find(item => item.id === reference.family)!;
  const queryKey = { handoff: "receiver_job", file: "control", domain: "workflow", cloud: "exercise" }[reference.family];
  const query = new URLSearchParams({ goal: purposeId[reference.family], [queryKey]: reference.id });
  return `${family.href}${family.href.includes("?") ? "&" : "?"}${query.toString()}`;
}

function result(label: string, value: unknown, tone?: ActiveWorkResult["tone"]): ActiveWorkResult {
  return { label, value: typeof value === "string" && value.length ? value : notRecorded, ...(tone ? { tone } : {}) };
}

function humanize(value: string): string {
  return value.replaceAll("_", " ").replace(/^./, character => character.toUpperCase());
}

function provenanceLabel(values: string[]): string {
  const kinds = new Set(values);
  if (!kinds.size) return notRecorded;
  const labels = [
    ...(kinds.has("synthetic") || kinds.has("synthetic_fixture") ? ["Synthetic fixture"] : []),
    ...(kinds.has("runner_reported") ? ["Runner-reported"] : []),
    ...(kinds.has("observed") ? ["Observed evidence"] : []),
    ...(kinds.has("executed") ? ["Executed evidence"] : []),
    ...(kinds.has("control_blocked") ? ["Control-blocked evidence"] : []),
    ...(kinds.has("counterfactual") ? ["Counterfactual evidence"] : []),
    ...(kinds.has("unknown") ? ["Unknown provenance"] : []),
    ...[...kinds].filter(kind => !["synthetic", "synthetic_fixture", "runner_reported", "observed", "executed", "control_blocked", "counterfactual", "unknown"].includes(kind)),
  ];
  return labels.join("; ");
}

function runLinks(entries: Array<{ id: string; label: string }>): ActiveWorkSummary["links"] {
  const seen = new Set<string>();
  return entries.filter(entry => {
    if (!entry.id || seen.has(entry.id)) return false;
    seen.add(entry.id);
    return true;
  }).map(entry => ({ label: entry.label, href: `/runs/${encodeURIComponent(entry.id)}` }));
}

function handoffSummary(reference: ActiveWorkReference, value: ReceiverDefenseEnvelope): ActiveWorkSummary {
  const current = value.next_action.phase ? value.phases.find(phase => phase.phase === value.next_action.phase) : undefined;
  const latestOutcome = [...value.phases].reverse().find(phase => phase.result);
  const shownOutcomes = value.phases.filter(phase => phase.result).slice(-3);
  const policy = value.control?.desired_policy_id ?? latestOutcome?.result?.policy_id;
  const runProvenance = [...new Set(shownOutcomes.flatMap(phase => phase.result?.run.evidence?.records?.map(item => item.provenance) ?? []))];
  const hasOwnedDecision = shownOutcomes.some(phase => phase.result?.receiver_observation.schema_version === "bluefire.owned-receiver-observation.v1"
    && phase.result.receiver_observation.state === "verified" && ["accepted", "policy_refused"].includes(phase.result.decision));
  const evidenceSource = [
    ...(hasOwnedDecision ? ["Owned loopback receiver decision"] : []),
    ...(runProvenance.length ? [`Run evidence: ${provenanceLabel(runProvenance)}`] : []),
  ].join("; ") || notRecorded;
  const results: ActiveWorkResult[] = [
    ...(shownOutcomes.length ? shownOutcomes.map(phase => result(phaseTitle[phase.phase] ?? phase.phase, receiverOutcome(phase)))
      : [result("Phase outcomes", notRecorded)]),
    result("Evidence source", evidenceSource),
  ].slice(0, 4);
  const phase = current ? phaseTitle[current.phase] : latestOutcome ? phaseTitle[latestOutcome.phase] : notRecorded;
  const links = value.context ? [{
    label: "Open saved experiment",
    href: savedExperimentPath({ scenario_id: value.context.selection.scenario_id, version: value.context.selection.version, digest: value.context.selection.digest }),
  }, ...runLinks(value.phases.filter(row => row.result).slice(-2).map(row => ({ id: row.result!.run_id, label: `${phaseTitle[row.phase] ?? row.phase} run evidence` })))] : [];
  return {
    reference, title: `Controlled data handoff${value.context?.scenario_title ? ` · ${value.context.scenario_title}` : ""}`, objective: purpose(reference),
    environment: value.context?.handoff ? "Loopback receiver" : notRecorded,
    phase, recordedState: value.status,
    change: policy && Object.hasOwn(policyTitle, policy)
      ? value.control
        ? `Desired policy: ${policyTitle[policy as keyof typeof policyTitle]} · ${humanize(value.control.status)}`
        : latestOutcome ? `Latest recorded phase policy: ${policyTitle[policy as keyof typeof policyTitle]}` : notRecorded
      : notRecorded,
    results, href: activeWorkHref(reference), links,
  };
}

function fileSummary(reference: ActiveWorkReference, value: FileAccessControl): ActiveWorkSummary {
  const operations = value.operations;
  const lastOperation = operations.at(-1);
  const request = lastOperation?.progress.submitted_request as FileAccessSubmission | undefined;
  const resource = value.resource;
  const platform = value.platform === "windows" ? "Windows" : value.platform === "macos" ? "macOS" : "Linux";
  const environment = value.platform === "windows" ? "Protected Windows setup" : `${platform} generated application file`;
  const protection = resource && "mode" in resource && resource.mode ? `mode ${resource.mode}`
    : resource && "protection" in resource && resource.protection ? `protection ${resource.protection}` : undefined;
  const results: ActiveWorkResult[] = [
    result("File protection", protection ?? notRecorded),
    result("Baseline record", value.baseline ? "Present" : notRecorded),
    result("Task usage", "task_usage_state" in value ? value.task_usage_state : "usage_state" in value ? value.usage_state : notRecorded),
    result("Latest saved operation", lastOperation?.state),
  ].slice(0, 4);
  return { reference, title: `Excess file access · ${platform} generated file`, objective: purpose(reference), environment,
    phase: request?.review?.operation && Object.hasOwn(fileAccessOperationLabels, request.review.operation)
      ? fileAccessOperationLabels[request.review.operation] : notRecorded, recordedState: value.status,
    change: protection ? `File ${protection}` : notRecorded, results, href: activeWorkHref(reference), links: [] };
}

function domainSummary(reference: ActiveWorkReference, value: AdWorkflow): ActiveWorkSummary {
  const lastOperation = value.operations.at(-1);
  const executions = lastOperation?.executions ?? [];
  const provenance = provenanceLabel(executions.map(execution => execution.provenance));
  const reads = executions.flatMap(execution => execution.read ? [`${execution.read.reader} ${execution.read.purpose}: ${execution.read.state}`] : []);
  const results: ActiveWorkResult[] = [
    result("Latest operation", lastOperation ? `${humanize(lastOperation.state)}${lastOperation.expectation ? ` · expectation ${humanize(lastOperation.expectation)}` : ""}` : notRecorded),
    result("Execution source", provenance),
    result("Cleanup", lastOperation ? humanize(lastOperation.cleanup) : notRecorded),
    result("Recorded reads", reads.length ? reads.map(read => read.replace(/: [a-z_]+$/, match => `: ${humanize(match.slice(2))}`)).join("; ") : notRecorded),
  ];
  const operationLinks = lastOperation ? runLinks([{ id: lastOperation.runId, label: "Open saved domain run" }]) : [];
  const titleContext = `${value.environment.domain} · ${value.environment.member}`;
  return { reference, title: `Excess domain access · ${titleContext}`, objective: purpose(reference),
    environment: `${value.environment.domain} · ${value.environment.share}`, phase: lastOperation ? adPhaseLabels[lastOperation.phase] : notRecorded,
    recordedState: value.pending ? "Operation pending" : value.stopped ? "Stopped" : value.policy,
    change: `Recorded policy: ${humanize(value.policy)}`, results, href: activeWorkHref(reference), links: operationLinks };
}

function cloudSummary(reference: ActiveWorkReference, value: S3Exercise): ActiveWorkSummary {
  const latest = value.operations.at(-1);
  const results: ActiveWorkResult[] = [
    result("Latest operation", latest ? `${humanize(latest.outcome.state)} · ${latest.outcome.complete ? "Complete" : "Incomplete"}` : notRecorded),
    result("Result source", latest ? provenanceLabel([latest.outcome.provenance]) : notRecorded),
    result("Cleanup and resources", latest ? `Worker cleanup: ${humanize(latest.outcome.cleanup)}; resources: ${humanize(latest.outcome.resource_disposition)}` : notRecorded),
    result("Recorded reads and independent observations", latest?.outcome.facts.length
      ? `${latest.outcome.facts.map(fact => `${fact.reader} ${fact.purpose}: ${fact.result}`).join("; ")} · ${value.independent_observations} independent observations`
      : `${value.independent_observations} independent observations`),
  ];
  const relevantOperations = [
    value.operations.find(operation => operation.phase === "baseline"),
    [...value.operations].reverse().find(operation => operation.phase === "retest"),
    latest,
  ].filter((operation, index, all): operation is NonNullable<typeof operation> => operation !== undefined
    && all.findIndex(candidate => candidate && (candidate.operation_job_id || candidate.phase) === (operation.operation_job_id || operation.phase)) === index);
  const operationLinks = runLinks(relevantOperations.flatMap(operation => operation.run_ids.slice(0, 1).map(id => ({ id, label: `${phaseName[operation.phase]} run evidence` }))));
  const activePhase = value.active_job?.request.s3_access.phase;
  return { reference, title: `Excess S3 access · ${value.environment.display_name}`, objective: purpose(reference),
    environment: `${value.environment.scope.bucket} · ${value.environment.scope.region}`,
    phase: activePhase ? phaseName[activePhase] : latest ? phaseName[latest.phase] : notRecorded,
    recordedState: value.stopped ? "Stopped" : value.policy_state,
    change: `Recorded policy: ${humanize(value.policy_state)}`, results, href: activeWorkHref(reference), links: operationLinks };
}

/** Fetch and summarize one selected retained control by its direct read endpoint. */
export async function loadActiveWork(reference: ActiveWorkReference): Promise<ActiveWorkSummary> {
  const selected = parseActiveWorkReference(reference);
  if (!selected) throw new Error("Choose a valid saved work item first.");
  if (selected.family === "handoff") {
    const record = checkedReceiverTest(await api.receiverTest(selected.id), selected.id);
    return handoffSummary(selected, record);
  }
  if (selected.family === "file") {
    const record = checkedFileAccessControl(await fileAccessApi.control(selected.id), selected.id);
    return fileSummary(selected, record);
  }
  if (selected.family === "domain") {
    const record = checkedAdWorkflow(await adSmbApi.workflow(selected.id), selected.id);
    return domainSummary(selected, record);
  }
  const record = await s3Api.read(selected.id);
  return cloudSummary(selected, record);
}
