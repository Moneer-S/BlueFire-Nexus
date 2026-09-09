import { validSavedRunSelection, type SavedRunSelection, type RunInspectedResult } from "./run-assistance";
import { validRunDetectionSelection, type RunDetectionSelection, type DetectionCreatedResult } from "./detection-creation";
import { parseScenarioDocument } from "./scenario";
import type { DetectionCaseRole, RunJob, Scenario } from "../types";
import type { MethodSource } from "./method-comparison";
import { sameJson } from "./replay-review";
import { checkedReceiverAssistance, isReceiverSelection, validReceiverAssistanceSelection, type ReceiverAssistanceSelection, type ReceiverAssistanceProgress, type ReceiverAssistanceResult } from "./receiver-assistance";

export type AssistanceCapability = "detection.create_and_evaluate" | "detection.revise_and_evaluate" | "method.compare_same_detector" | "graph.propose_and_validate" | "run.saved_graph_and_inspect" | "receiver.test_and_compare" | "receiver.inspect_and_plan_next";
export interface GraphStepSelection { scenario: Scenario; step_id: string; dirty: boolean }
export interface GraphSelection { edit_step?: GraphStepSelection; kind: "graph"; base_scenario: null | { scenario_id: string; version: number; digest: string } }
export interface AssistanceContext {
  schema_version: "bluefire.assistance-context.v1";
  context_digest: string;
  selected: GraphSelection | SavedRunSelection | RunDetectionSelection | ReceiverAssistanceSelection | {
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
export interface SavedGraphAssistanceRequest extends Omit<GraphAssistanceRequest, "selection"> { selection: SavedRunSelection }
export interface RunDetectionAssistanceRequest extends Omit<GraphAssistanceRequest, "selection"> { selection: RunDetectionSelection }
export interface ReceiverAssistanceRequest extends Omit<GraphAssistanceRequest, "selection"> { selection: ReceiverAssistanceSelection }
export type AssistanceRequest = DetectionAssistanceRequest | GraphAssistanceRequest | SavedGraphAssistanceRequest | RunDetectionAssistanceRequest | ReceiverAssistanceRequest;
export const isReceiverRequest = (value: AssistanceRequest): value is ReceiverAssistanceRequest => "selection" in value && isReceiverSelection(value.selection);
export const isRunDetectionRequest = (value: AssistanceRequest): value is RunDetectionAssistanceRequest => "selection" in value && value.selection?.kind === "run_detection";
export const isRunDetectionSelection = (value: AssistanceContext["selected"]): value is RunDetectionSelection => "kind" in value && value.kind === "run_detection";
export const isSavedGraphRequest = (value: AssistanceRequest): value is SavedGraphAssistanceRequest => "selection" in value && (value.selection?.kind === "saved_graph" || value.selection?.kind === "saved_scenario");
export const isSavedRunSelection = (value: AssistanceContext["selected"]): value is SavedRunSelection => "kind" in value && (value.kind === "saved_graph" || value.kind === "saved_scenario");
export const isGraphRequest = (value: AssistanceRequest): value is GraphAssistanceRequest => "selection" in value && value.selection?.kind === "graph";
export const isGraphSelection = (value: AssistanceContext["selected"]): value is GraphSelection => "kind" in value && value.kind === "graph";
export type AssistanceStatus = "planning" | "off" | "working" | "awaiting_review" | "awaiting_execute_approval" | "ready_to_continue" | "completed" | "blocked" | "cancelling" | "cancelled";
export interface AssistanceEnvelope {
  job: RunJob;
  turn: {
    schema_version: "bluefire.assistance-turn.v1"; status: AssistanceStatus; message: string; context_digest: string;
    can_start_new_turn: boolean;
    selected: GraphSelection | SavedRunSelection | RunDetectionSelection | ReceiverAssistanceSelection | Pick<DetectionAssistanceRequest, "run_id" | "candidate_id" | "candidate_resource_digest">;
    plan: Array<{ step_id: string; capability_id: AssistanceCapability; title: string; detector_ref: "selected" | "revised" | "none"; reason: string }>;
    active_child: null | { job_id: string; kind: string; state: string; step_id: string; native_path: string };
    receiver_test?: ReceiverAssistanceProgress;
    next_action: null | { kind: "review_run" | "review_graph" | "review_detection" | "review_detection_create" | "review_method" | "review_execute" | "approve_execute" | "review_receiver" | "open_results" | "wait" | "continue" | "new_turn"; label?: string; native_path: string | null };
    results: Array<ReceiverAssistanceResult | RunInspectedResult | DetectionCreatedResult | { kind: "detection_revision" | "method_comparison"; step_id: string; candidate_id: string; evaluation_ids: string[]; run_ids: string[]; comparison_id: string | null; native_path: string } | { kind: "graph_saved"; step_id: string; proposal_job_id: string; scenario_id: string; version: number; digest: string; operator_modified: boolean; native_path: string; execution_state: "not_run" }>;
    continuation: null | { job_id: string; submission_id: string; state: string; context_digest: string };
    recovery?: null | {
      code: "runner_readiness_required" | "native_review_required" | "detection_review_required" | "source_review_required" | "receiver_review_required";
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
function readStoredRequest(key: string): AssistanceRequest | undefined {
  try {
    const raw = sessionStorage.getItem(key);
    if (!raw || raw.length > 100000) return;
    const value = JSON.parse(raw) as AssistanceRequest;
    if (!value || !uuid.test(value.submission_id) || !digest.test(value.context_digest) || !bounded(value.message, 1000)
      || !["off", "assist", "auto"].includes(value.autonomy)
      || (value.provider_id !== undefined && !bounded(value.provider_id))) return;
    if (isReceiverRequest(value)) {
      if (!validReceiverAssistanceSelection(value.selection)) return;
    } else if (isRunDetectionRequest(value)) {
      if (!validRunDetectionSelection(value.selection)) return;
    } else if (isSavedGraphRequest(value)) {
      if (!validSavedRunSelection(value.selection)) return;
    } else if (isGraphRequest(value)) {
      if (!validGraphSelection(value.selection)) return;
    } else if ("selection" in value || !digest.test(value.candidate_resource_digest) || !bounded(value.run_id) || !bounded(value.candidate_id)
      || !["attack", "benign", "replay", "heldout"].includes(value.case_role)) return;
    return value;
  } catch { return; }
}
export function readAssistanceReceipt(): AssistanceRequest | undefined { return readStoredRequest(storageKey); }
const historyKey = "bluefire.assistance.history.v1";
const viewedKey = "bluefire.assistance.viewed.v1";
export function readAssistanceHistory(): AssistanceRequest[] {
  try {
    const raw = sessionStorage.getItem(historyKey);
    if (!raw || raw.length > 4000) return [];
    const ids: unknown = JSON.parse(raw);
    if (!Array.isArray(ids) || ids.length > 20) return [];
    return ids.flatMap(id => {
      if (typeof id !== "string" || !uuid.test(id)) return [];
      const request = readStoredRequest(`${historyKey}.${id}`);
      return request && request.submission_id === id ? [request] : [];
    });
  } catch { return []; }
}
export function rememberAssistanceRequest(request: AssistanceRequest): boolean {
  try {
    const key = `${historyKey}.${request.submission_id}`;
    const existing = readStoredRequest(key);
    if (existing && !sameJson(existing, request)) return false;
    sessionStorage.setItem(key, JSON.stringify(request));
    if (!sameJson(readStoredRequest(key), request)) return false;
    const ids = [request.submission_id, ...readAssistanceHistory().map(item => item.submission_id).filter(id => id !== request.submission_id)].slice(0, 20);
    sessionStorage.setItem(historyKey, JSON.stringify(ids));
    return readAssistanceHistory().some(item => sameJson(item, request));
  } catch { return false; }
}
export function viewAssistanceRequest(request?: AssistanceRequest) {
  try { sessionStorage.setItem(viewedKey, request?.submission_id ?? "selection"); } catch { /* Active ownership remains separately retained. */ }
}
export function readViewedAssistanceRequest(): AssistanceRequest | undefined {
  try {
    const id = sessionStorage.getItem(viewedKey);
    if (id === "selection") return;
    return readAssistanceHistory().find(item => item.submission_id === id) ?? readAssistanceReceipt();
  } catch { return readAssistanceReceipt(); }
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
  try { checkedReceiverAssistance(value); } catch { return false; }
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

export function validGraphSelection(value: GraphSelection): boolean {
  try {
    if (!value || value.kind !== "graph") return false;
    const base = value.base_scenario;
    if (base !== null && (!base || !bounded(base.scenario_id) || !Number.isSafeInteger(base.version) || base.version < 1 || !digest.test(base.digest))) return false;
    if (value.edit_step !== undefined) {
      const edit = value.edit_step;
      if (!edit || typeof edit.dirty !== "boolean" || !bounded(edit.step_id) || (edit.dirty && base !== null) || JSON.stringify(edit.scenario).length > 65536) return false;
      const scenario = parseScenarioDocument(edit.scenario);
      if (scenario.steps.length > 128 || scenario.edges.length > 256 || !scenario.steps.some(step => step.id === edit.step_id)) return false;
    }
    return true;
  } catch { return false; }
}
