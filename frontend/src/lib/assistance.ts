import { validSavedGraphSelection, type SavedGraphSelection, type RunInspectedResult } from "./run-assistance";
import type { DetectionCaseRole, RunJob } from "../types";
import type { MethodSource } from "./method-comparison";
import { sameJson } from "./replay-review";

export type AssistanceCapability = "detection.revise_and_evaluate" | "method.compare_same_detector" | "graph.propose_and_validate" | "run.saved_graph_and_inspect";
export interface GraphSelection { kind: "graph"; base_scenario: null | { scenario_id: string; version: number; digest: string } }
export interface AssistanceContext {
  schema_version: "bluefire.assistance-context.v1";
  context_digest: string;
  selected: GraphSelection | SavedGraphSelection | {
    run_id: string; candidate_id: string; candidate_resource_digest: string;
    title: string; definition_digest: string; target_language: string; source_binding: MethodSource;
  };
  capabilities: Array<{ id: AssistanceCapability; title: string; available: boolean; supported_autonomy: Array<"assist" | "auto">; reason: string; native_path: string }>;
  limitations: string[];
}
export interface DetectionAssistanceRequest {
  submission_id: string; context_digest: string; run_id: string; candidate_id: string;
  candidate_resource_digest: string; message: string; case_role: DetectionCaseRole;
  autonomy: "off" | "assist" | "auto"; provider_id?: string;
}
export interface GraphAssistanceRequest {
  submission_id: string; context_digest: string; selection: GraphSelection; message: string;
  autonomy: "off" | "assist" | "auto"; provider_id?: string;
}
export interface SavedGraphAssistanceRequest extends Omit<GraphAssistanceRequest, "selection"> { selection: SavedGraphSelection }
export type AssistanceRequest = DetectionAssistanceRequest | GraphAssistanceRequest | SavedGraphAssistanceRequest;
export const isSavedGraphRequest = (value: AssistanceRequest): value is SavedGraphAssistanceRequest => "selection" in value && value.selection?.kind === "saved_graph";
export const isSavedGraphSelection = (value: AssistanceContext["selected"]): value is SavedGraphSelection => "kind" in value && value.kind === "saved_graph";
export const isGraphRequest = (value: AssistanceRequest): value is GraphAssistanceRequest => "selection" in value && value.selection?.kind === "graph";
export const isGraphSelection = (value: AssistanceContext["selected"]): value is GraphSelection => "kind" in value && value.kind === "graph";
export type AssistanceStatus = "planning" | "off" | "working" | "awaiting_review" | "awaiting_execute_approval" | "ready_to_continue" | "completed" | "blocked" | "cancelling" | "cancelled";
export interface AssistanceEnvelope {
  job: RunJob;
  turn: {
    schema_version: "bluefire.assistance-turn.v1"; status: AssistanceStatus; message: string; context_digest: string;
    can_start_new_turn: boolean;
    selected: GraphSelection | SavedGraphSelection | Pick<DetectionAssistanceRequest, "run_id" | "candidate_id" | "candidate_resource_digest">;
    plan: Array<{ step_id: string; capability_id: AssistanceCapability; title: string; detector_ref: "selected" | "revised" | "none"; reason: string }>;
    active_child: null | { job_id: string; kind: string; state: string; step_id: string; native_path: string };
    next_action: null | { kind: "review_run" | "review_graph" | "review_detection" | "review_method" | "review_execute" | "continue" | "new_turn"; label: string; native_path: string | null };
    results: Array<RunInspectedResult | { kind: "detection_revision" | "method_comparison"; step_id: string; candidate_id: string; evaluation_ids: string[]; run_ids: string[]; comparison_id: string | null; native_path: string } | { kind: "graph_saved"; step_id: string; proposal_job_id: string; scenario_id: string; version: number; digest: string; operator_modified: boolean; native_path: string; execution_state: "not_run" }>;
    continuation: null | { job_id: string; submission_id: string; state: string; context_digest: string };
    recovery?: null | {
      code: "runner_readiness_required" | "native_review_required" | "detection_review_required" | "source_review_required";
      message: string; profile_id: string | null;
      action: { label: string; native_path: string };
    };
    limitations: string[];
  };
}
export const assistanceJobId = (submission: string) => `job-${submission.replaceAll("-", "")}`;
export const assistanceActive = (status: AssistanceStatus) => !["off", "completed", "blocked", "cancelled"].includes(status);
export function assistancePath(value: unknown): string | undefined {
  if (typeof value !== "string" || [...value].some((character) => character === "\\" || character.charCodeAt(0) <= 32)) return;
  if (!/^\/(?:builder|detection-lab|compare|runs|runners)(?:\?|\/|$)/.test(value)) return;
  const parsed = new URL(value, "https://bluefire.invalid");
  return parsed.origin === "https://bluefire.invalid" ? `${parsed.pathname}${parsed.search}${parsed.hash}` : undefined;
}
const storageKey = "bluefire.assistance.receipt.v1";
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const digest = /^sha256:[0-9a-f]{64}$/;
const bounded = (value: unknown, limit = 200): value is string => typeof value === "string" && value.trim().length > 0 && value.length <= limit && [...value].every((character) => character.charCodeAt(0) >= 32 || "\t\n\r".includes(character));
export function readAssistanceReceipt(): AssistanceRequest | undefined {
  try {
    const raw = sessionStorage.getItem(storageKey);
    if (!raw || raw.length > 9000) return;
    const value = JSON.parse(raw) as AssistanceRequest;
    if (!value || !uuid.test(value.submission_id) || !digest.test(value.context_digest) || !bounded(value.message, 1000)
      || !["off", "assist", "auto"].includes(value.autonomy)
      || (value.provider_id !== undefined && !bounded(value.provider_id))) return;
    if (isSavedGraphRequest(value)) {
      if (!validSavedGraphSelection(value.selection)) return;
    } else if (isGraphRequest(value)) {
      const base = value.selection.base_scenario;
      if (base !== null && (!base || !bounded(base.scenario_id) || !Number.isSafeInteger(base.version) || base.version < 1 || !digest.test(base.digest))) return;
    } else if ("selection" in value || !digest.test(value.candidate_resource_digest) || !bounded(value.run_id) || !bounded(value.candidate_id)
      || !["attack", "benign", "replay", "heldout"].includes(value.case_role)) return;
    return value;
  } catch { return; }
}
export function storeAssistanceReceipt(value: AssistanceRequest): boolean {
  try {
    if (sessionStorage.getItem(storageKey) !== null && !sameJson(readAssistanceReceipt(), value)) return false;
    sessionStorage.setItem(storageKey, JSON.stringify(value));
    return sameJson(readAssistanceReceipt(), value);
  } catch { return false; }
}
export function clearAssistanceReceipt(value: AssistanceRequest): boolean {
  try {
    if (!sameJson(readAssistanceReceipt(), value)) return false;
    sessionStorage.removeItem(storageKey);
    return sessionStorage.getItem(storageKey) === null;
  } catch { return false; }
}
export function matchesAssistanceReceipt(value: AssistanceEnvelope, receipt: AssistanceRequest): boolean {
  return value.job?.kind === "assistance.turn" && value.job.job_id === assistanceJobId(receipt.submission_id)
    && sameJson(value.job.request?.submitted_request, receipt) && value.turn?.schema_version === "bluefire.assistance-turn.v1"
    && value.turn.context_digest === receipt.context_digest && sameJson(value.turn.selected, "selection" in receipt ? receipt.selection
      : { run_id: receipt.run_id, candidate_id: receipt.candidate_id, candidate_resource_digest: receipt.candidate_resource_digest });
}

export interface AssistanceRecovery { job_id: string; submission_id: string; context_digest: string }
const recoveryKey = "bluefire.assistance.recovery.v1";
export function readAssistanceRecovery(): AssistanceRecovery | undefined {
  try {
    const raw = sessionStorage.getItem(recoveryKey);
    if (!raw || raw.length > 1000) return;
    const value = JSON.parse(raw) as AssistanceRecovery;
    return value && /^job-[0-9a-f]{32}$/.test(value.job_id) && uuid.test(value.submission_id) && digest.test(value.context_digest) ? value : undefined;
  } catch { return; }
}
export function storeAssistanceRecovery(value: AssistanceRecovery): boolean {
  try {
    const existing = readAssistanceRecovery();
    if (existing && !sameJson(existing, value)) return false;
    sessionStorage.setItem(recoveryKey, JSON.stringify(value));
    return sameJson(readAssistanceRecovery(), value);
  } catch { return false; }
}
export function clearAssistanceRecovery(value: AssistanceRecovery): boolean {
  try {
    if (!sameJson(readAssistanceRecovery(), value)) return false;
    sessionStorage.removeItem(recoveryKey);
    return sessionStorage.getItem(recoveryKey) === null;
  } catch { return false; }
}
