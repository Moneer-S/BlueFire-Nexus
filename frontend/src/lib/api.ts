import { retainedObservations, type RetainedRunRecord } from "./retained-run-record";
import type { NativeToolActionId } from "./native-tool-setup";
import type { AssistanceRunEnvelope, RunPreparationDecision, SavedRunSelection } from "./run-assistance";
import type { AILiveAuthorization, AILiveAuthorizationList, AILiveAuthorizationRequest, PublicAIProviderConfig, NativeToolCandidateInspection } from "../types";
import type { RunnerUpgradeReview } from "./runner-upgrade";
import type { ReceiverContext, ReceiverContextRequest, ReceiverControlDecision, ReceiverDecision, ReceiverDefenseEnvelope, ReceiverPhase, ReceiverTestList } from "./receiver-defense-types";
import type { RunDetectionSelection, DetectionCreationSource, DetectionCreationEnvelope, DetectionCreationDecision, DetectionCreationValidation } from "./detection-creation";
import type { AIProviderCheck, ActiveJobList, AIGraphDraftResult, AIProposalDecisionResult, AIProposalReview, AIProposalReviewList, ActionPackageCatalogIdentity, ActionPackageInstallation, ActionPackageInventory, ActionPackagePublisherEnrollment, ActionPackagePublisherTrust, AutonomyLevel, CatalogResponse, ComparisonResponse, SavedComparisonSnapshot, SavedComparisonSummary, DetectionCloneRequest, DetectionComparisonResponse, DetectionLabHealth, DetectionResource, DetectionResourceEnvelope, DetectionRunImportResponse, DetectionRunEvaluation, DetectionCaseRole, DetectionTuneRequest, JobApprovalResult, JobRetryResult, ManagedResource, ManagedResourceList, ManagedResourceRoute, ManagedSetting, PreflightReport, RunnerLifecycleStatus, RunnerProbe, RunConfiguration, RunEventPage, RunJob, RunJobSubmission, RunPresentation, RunRecord, RuntimeResourceResult, Scenario, ScenarioVersion } from "../types";
import { approvalDeadline, hasAdaptiveApprovalReview, requiresAdaptiveReview, storedRunApprovalPreflight } from "./approvalReview";
import { isRunPresentation } from "./runPresentation";
import { sameJson } from "./replay-review";
import type { DetectionAIDecision, DetectionAIRequest } from "./detection-ai";
import type { MethodContext, MethodDecision, MethodRequest } from "./method-comparison";
import type { AssistanceContext, AssistanceEnvelope, AssistanceRequest, GraphSelection } from "./assistance";
import type { GraphDecision, GraphEnvelope, GraphValidation } from "./graph-assistance";
import { compareDemoRuns, demoCatalog, demoRuns, demoScenario } from "./demo";
import { browserApiFetch, exchangeBrowserCapability } from "./browser-session";
import type { HappenedAnswer, Outcome, RecordingKind, Score as RecordingScore } from "../live/recording";

const API_ROOT = "/api/v1";
const BROWSER_BOOTSTRAP_FRAGMENT_KEY = "bluefire-session";
const BROWSER_CAPABILITY = /^[A-Za-z0-9_-]{64}$/;
// Server configuration permits six 300-second attempts, 5.75 seconds of retry
// backoff, and 10 seconds for normalization. A static bound avoids aborting
// against stale catalog metadata.
const AI_DRAFT_REQUEST_TIMEOUT_MS = 1_815_750;
const RUNNER_TRUST_MUTATION_TIMEOUT_MS = 135_000;
// Replay remains synchronous, and a browser disconnect does not cancel server-side
// effects. Cover the server's five-second admission window, full 24-hour profile
// budget, and 60-second completion margin without trusting stale catalog metadata.
const SYNCHRONOUS_REPLAY_TIMEOUT_MS = 5_000 + (24 * 60 * 60 * 1000) + 60_000;
export const DEMO_MODE = import.meta.env.VITE_DEMO_MODE === "true";
export const BROWSER_SESSION_RELAUNCH_MESSAGE = "This browser session is unavailable. Connect with a fresh one-time code from the BlueFire launcher.";
const EMPTY_ACTION_PACKAGE_CATALOG_DIGEST = `sha256:${"0".repeat(64)}`;

export interface ReviewedT1082IntakeResult {
  schema_version: "bluefire.reviewed-source-intake-result.v1";
  destination_id: string;
  artifact: {
    media_type: string;
    sha256: string;
    size_bytes: number;
    state_ref: string;
  };
  intake: {
    intake_id: string;
    record_sha256: string;
    output_sha256: string;
    execution_material_imported: false;
  };
  operation_receipt: {
    media_type: string;
    sha256: string;
    size_bytes: number;
    state_ref: string;
    record: {
      schema_version: "bluefire.reviewed-source-intake-operation-receipt.v1";
      destination_id: string;
      operator_id: string;
      runner_profile_id: string;
      completed_at: string;
    } & Record<string, unknown>;
  };
  package_activation: {
    schema_version: "bluefire.reviewed-source-intake-activation.v1";
    operation: "installed_and_activated" | "resumed_activation" | "already_active_revalidated";
    package: {
      package_id: string;
      version: string;
      package_digest: string;
      content_digest: string;
      publisher_id: string;
      key_id: string;
      status: string;
    };
    catalog_delta: {
      changed: boolean;
      generation_before: number;
      generation_after: number;
      catalog_digest_before: string;
      catalog_digest_after: string;
      behavior_ids_added: string[];
      action_ids_added: string[];
    };
    availability: {
      behavior_id: string;
      behavior_available: boolean;
      action_id: string;
      action_available: boolean;
    };
    runner: {
      profile_id: string;
      identity_digest: string;
      inventory_digest: string;
      activation_revalidated: true;
    };
    persistence: {
      installed_now: boolean;
      activated_now: boolean;
      durable_product_store: true;
      signing_key_lifecycle: string;
      private_signing_key_persisted: false;
    };
  };
}

export class ApiError extends Error {
  constructor(message: string, public readonly code = "request_failed", public readonly details?: unknown, public readonly status?: number) {
    super(message);
    this.name = "ApiError";
  }
}

export function hasBrowserBootstrapFragment(): boolean {
  return window.location.hash.startsWith(`#${BROWSER_BOOTSTRAP_FRAGMENT_KEY}=`);
}

function consumeBrowserBootstrapFragment(returnHash: string): string | null {
  const prefix = `#${BROWSER_BOOTSTRAP_FRAGMENT_KEY}=`;
  if (!window.location.hash.startsWith(prefix)) return null;

  const capability = window.location.hash.slice(prefix.length);
  // A fragment is browser-local and is never sent in an HTTP request. Remove it
  // before the first fetch, including malformed and failed bootstrap attempts.
  window.history.replaceState(window.history.state, "", `${window.location.pathname}${window.location.search}${returnHash.startsWith("#/") ? returnHash : ""}`);
  if (!BROWSER_CAPABILITY.test(capability)) throw new Error("invalid browser bootstrap fragment");
  return capability;
}

export async function establishBrowserSession(returnHash = "", connectionCode?: string): Promise<void> {
  if (DEMO_MODE) return;
  try {
    const fragment = consumeBrowserBootstrapFragment(returnHash);
    const capability = connectionCode ?? fragment;
    if (capability !== null) {
      try { await exchangeBrowserCapability(capability); return; }
      catch {
        // A replayed launch link may still belong to this tab's valid session.
        if (connectionCode !== undefined) throw new Error("connection code refused");
      }
    }
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), 15_000);
    try {
      const response = await browserApiFetch(`${API_ROOT}/session`, {
        method: "GET", headers: { Accept: "application/json" }, signal: controller.signal,
      });
      if (response.status !== 204) throw new Error("browser session refused");
    } finally { window.clearTimeout(timeout); }
  } catch {
    throw new ApiError(BROWSER_SESSION_RELAUNCH_MESSAGE, "browser_session_unavailable", undefined, 401);
  }
}

export async function request<T>(path: string, options: RequestInit = {}, timeoutMs = 20_000): Promise<T> {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await browserApiFetch(`${API_ROOT}${path}`, {
      ...options,
      signal: controller.signal,
      headers: { Accept: "application/json", ...(options.body ? { "Content-Type": "application/json" } : {}), ...options.headers },
    });
    const payload = await response.json().catch(() => null) as any;
    if (!response.ok) throw new ApiError(payload?.error?.message ?? `Request failed (${response.status})`, payload?.error?.code, payload?.error?.details, response.status);
    return payload as T;
  } catch (error) {
    if (error instanceof ApiError) throw error;
    if (error instanceof DOMException && error.name === "AbortError") throw new ApiError("The local service did not respond before the timeout.", "request_timeout");
    throw new ApiError(error instanceof Error ? error.message : "The local service is unavailable.", "service_unavailable");
  } finally {
    window.clearTimeout(timeout);
  }
}

type CanonicalRunList = {
  schema_version?: string;
  runs: RunRecord[];
  unavailable_run_count: number;
};

/** How the service says where a recording comes from, with its note in plain words. */
export type RecordingOrigin =
  | { kind: "shipped"; run_url: string; note: string }
  | { kind: "imported"; note: string };

/** One entry of `GET /api/v1/recordings`: what a list shows of a recording without loading it whole. */
export interface RecordingSummary {
  id: string;
  title: string;
  kind: RecordingKind;
  source: { engine: string; environment: string; started: string; finished?: string; run_url?: string; commit?: string };
  score: RecordingScore;
  counts: { steps: number; events: number; alerts: number };
  origin: RecordingOrigin;
  /** True while the recording has no end time: its engine is still sending it. */
  running: boolean;
}

export interface RecordingList {
  recordings: RecordingSummary[];
  /** Imported files that no longer follow the format, left out of the list. */
  unreadable_count: number;
  /** Imported files after the first 200, not read. */
  omitted_count: number;
}

/** One whole recording with its list entry. The recording is checked by the live view's reader before it is played. */
export interface RecordingEntry {
  summary: RecordingSummary;
  recording: unknown;
  /** The SHA-256 of the file, by which a comparison names it. Given once the recording is finished. */
  sha256?: string;
}

export interface RecordingImport {
  created: boolean;
  replaced: boolean;
  /**
   * True when the answer names a file kept beside the first file of its id, not that first file:
   * another evaluation of the same run, or the same recording in other bytes (the lab's file and
   * the copy of a recording sent as an object). Either is opened by its SHA-256.
   */
  anotherEvaluation?: boolean;
  /** The SHA-256 of the kept file, by which an id that holds more than one file names each of them. */
  sha256?: string;
  summary: RecordingSummary;
}

/** A recording id as the service accepts it. */
const RECORDING_ID = /^[A-Za-z0-9_-]{1,64}$/;
/** A kept file of a recording, named by its SHA-256. */
const FILE_DIGEST = /^[0-9a-f]{64}$/;

/** How one evaluation judged a rule of the lab's own: accepted or not, why, and the rule's file. */
export interface DeltaJudged {
  accepted: boolean;
  reason?: string;
  file?: string;
}

/** A rule of the lab's own that differs between the two evaluations, as the delta lists it. */
export interface DeltaLabRule {
  rule: string;
  title: string;
  change: "new" | "gone" | "changed" | "moved";
  before: DeltaJudged | null;
  after: DeltaJudged | null;
}

/** A step the change is credited with, as a list of pairs shows it without loading the delta. */
export interface DeltaMoved {
  id: string;
  role: string;
  title: string;
  technique: string;
  result: DeltaResult;
  before: DeltaStepSide;
  after: DeltaStepSide;
  /** The step's price as the delta words it, when it has one. */
  price?: string;
}

/** The fields of a step that a delta compares. */
export type DeltaField = "happened" | "recorded" | "outcome" | "outcome_with_lab_rules";
export type DeltaResult = "same" | "better" | "worse" | "changed" | "not attributable" | "without cause" | "no verdict";

/** One recording of a delta: its file's SHA-256 and id, and from its `source` what it has. */
export interface DeltaSide {
  sha256: string;
  id: string;
  run_url?: string;
  environment?: string;
  commit?: string;
  /** The commit the lab's own rules and the sensors' settings were loaded from, when it is not `commit`'s. */
  defense_commit?: string;
  /** The commit the lab's own rules came from, when the recording names it: it wins over `defense_commit` for them. */
  lab_rules_commit?: string;
  started?: string;
}

export interface DeltaStepSide {
  happened: HappenedAnswer;
  recorded: "recorded" | "no telemetry" | "not known";
  outcome: Outcome;
  outcome_with_lab_rules: Outcome;
}

export interface DeltaStep {
  id: string;
  before_id?: string;
  role: string;
  title: string;
  technique: string;
  paired_by: "id" | "role, test and order";
  before: DeltaStepSide;
  after: DeltaStepSide;
  changed: DeltaField[];
  underneath: string[];
  /** Under a sensor change: what that sensor recorded of the step in one run only, each with its first lines. */
  records?: { sensor: string; new: DeltaRecords; gone: DeltaRecords };
  /** Under a limit, on a step credited by the change's own mark: the run whose events carry it, their audit keys and their number. */
  mark?: { run: "before" | "after"; keys: string[]; events: number };
  result: DeltaResult;
  verdict: string;
  price?: string;
  procedures?: { better: number; of: number };
}

export interface DeltaRecords {
  count: number;
  lines: string[];
}

/**
 * An audit key that only one run's events carry: its events and their steps,
 * and under a limit whether its events can carry the change's own mark, with
 * why not in the lab's words when they cannot.
 */
export interface DeltaAuditKey {
  events: number;
  steps: string[];
  mark?: boolean;
  no_mark?: string;
}

/**
 * Why a verdict is limited, when the two runners differed: the names of the
 * setup that differed for it, which steps the change is credited on, in words,
 * and how many were credited by the mark and how many are not attributable.
 */
export interface DeltaLimit {
  why: string;
  differences: string[];
  credits: string;
  credited: number;
  not_attributable: number;
}

export interface DeltaListed {
  id: string;
  role: string;
  title: string;
  technique: string;
}

/** Every result with its number, and `by_mark`: of those, the steps credited by the change's own mark alone (left out by an older delta). */
export type DeltaCounts = Record<DeltaResult | "paired" | "new" | "gone", number> & { by_mark?: number };

/**
 * A comparison of two recordings, `bluefire.delta/1`, as `bluefire-lab compare`
 * wrote it (docs/RECORDING.md, "A delta"). The service checks its shape and
 * that its recordings are kept; the app only draws what it says.
 */
export interface Delta {
  schema: "bluefire.delta/1";
  claim: string;
  before: DeltaSide;
  after: DeltaSide;
  declared_change: string | null;
  /** 2 when the runs were made side by side in one CI run, each on a fresh runner; absent or null otherwise. */
  runners?: 2 | null;
  /** True when the two recordings are one run, its telemetry evaluated with two sets of the lab's rules. */
  one_run?: boolean;
  /** For a change of the lab's rules: each rule that differs, with how each evaluation judged it. */
  lab_rules?: DeltaLabRule[] | null;
  comparable: boolean;
  /** Set when the verdict is limited: the two runners differed, and only a step with the change's own mark is credited. */
  limit?: DeltaLimit | null;
  refused_because: string[];
  /** `declared` is true on the declared change and on a name that is part of it. */
  differences: { what: string; before: string | null; after: string | null; declared?: true }[];
  same_in_both: string[];
  lab_code: { before: string | null; after: string | null; same: boolean };
  judged: DeltaField[];
  control: { fields: DeltaField[]; same: number; of: number; varied: string[] };
  counts: DeltaCounts;
  unexplained: string[];
  steps: DeltaStep[];
  new: DeltaListed[];
  gone: DeltaListed[];
  race: { why: string } | { before: RaceTimes; after: RaceTimes };
  /** Only when the declared change is `sensors:auditd`: the audit keys that one run's events carry and the other's never do. */
  audit_keys?: { only_before: Record<string, DeltaAuditKey>; only_after: Record<string, DeltaAuditKey> } | null;
}

export interface RaceTimes {
  first_alert_seconds?: number;
  goal_seconds?: number;
}

/** One entry of `GET /api/v1/recordings/deltas`: what a list shows of a pair without loading it whole. */
export interface DeltaSummary {
  id: string;
  claim: string;
  declared_change: string | null;
  runners?: 2 | null;
  one_run?: boolean;
  lab_rules?: DeltaLabRule[] | null;
  comparable: boolean;
  limit?: DeltaLimit | null;
  refused_because: string[];
  counts: DeltaCounts;
  /** The steps the change is credited with, at most 20, for a list. */
  moved?: DeltaMoved[];
  before: DeltaSide;
  after: DeltaSide;
  /** The list entries of the two recordings, as the service keeps them. */
  recordings: { before: RecordingSummary; after: RecordingSummary };
  /** Shipped only when the delta and both its recordings are; otherwise imported, the pair's weaker side. */
  origin: DeltaOrigin;
}

/**
 * Where a pair comes from. A shipped pair of two runs made side by side in one
 * CI run names that run, which made both recordings and the comparison.
 */
export type DeltaOrigin = { kind: "shipped"; run_url?: string; note: string } | { kind: "imported"; note: string };

export interface DeltaList {
  deltas: DeltaSummary[];
  unreadable_count: number;
  omitted_count: number;
}

export interface DeltaEntry {
  summary: DeltaSummary;
  delta: Delta;
}

const DELTA_ID = /^[0-9a-f]{16}$/;

function isDeltaSide(value: unknown): value is DeltaSide {
  const side = jsonObject(value);
  return side !== null && typeof side.sha256 === "string" && typeof side.id === "string";
}

/** No limit, or one in the shape the page reads: a limited verdict is never read as a plain one. */
function isLimitOrNone(value: unknown): boolean {
  if (value === undefined || value === null) return true;
  const limit = jsonObject(value);
  return limit !== null && typeof limit.why === "string" && typeof limit.credits === "string"
    && Array.isArray(limit.differences) && limit.differences.every((item) => typeof item === "string")
    && typeof limit.credited === "number" && typeof limit.not_attributable === "number";
}

function isJudgedOrNone(value: unknown): boolean {
  if (value === null) return true;
  const judged = jsonObject(value);
  return judged !== null && typeof judged.accepted === "boolean"
    && (judged.reason === undefined || typeof judged.reason === "string")
    && (judged.file === undefined || typeof judged.file === "string");
}

/** No list of the lab's rules, or one in the shape the page reads. */
function isLabRulesOrNone(value: unknown): boolean {
  if (value === undefined || value === null) return true;
  return Array.isArray(value) && value.every((item) => {
    const row = jsonObject(item);
    return row !== null && typeof row.rule === "string" && typeof row.title === "string"
      && (row.change === "new" || row.change === "gone" || row.change === "changed" || row.change === "moved")
      && isJudgedOrNone(row.before) && isJudgedOrNone(row.after);
  });
}

function isStepSide(value: unknown): boolean {
  const side = jsonObject(value);
  return side !== null && typeof side.outcome === "string" && typeof side.outcome_with_lab_rules === "string";
}

function isMovedOrNone(value: unknown): boolean {
  if (value === undefined) return true;
  return Array.isArray(value) && value.every((item) => {
    const step = jsonObject(item);
    return step !== null && typeof step.id === "string" && typeof step.title === "string" && typeof step.role === "string"
      && typeof step.technique === "string" && typeof step.result === "string" && isStepSide(step.before) && isStepSide(step.after)
      && (step.price === undefined || typeof step.price === "string");
  });
}

function isDeltaSummary(value: unknown): value is DeltaSummary {
  const entry = jsonObject(value);
  if (!entry) return false;
  const recordings = jsonObject(entry.recordings), counts = jsonObject(entry.counts), origin = jsonObject(entry.origin);
  return typeof entry.id === "string" && DELTA_ID.test(entry.id)
    && (entry.one_run === undefined || typeof entry.one_run === "boolean") && isLabRulesOrNone(entry.lab_rules) && isMovedOrNone(entry.moved)
    && typeof entry.comparable === "boolean" && isLimitOrNone(entry.limit)
    && (entry.declared_change === null || typeof entry.declared_change === "string")
    && Array.isArray(entry.refused_because) && entry.refused_because.every((item) => typeof item === "string")
    && counts !== null && Object.values(counts).every((item) => typeof item === "number")
    && isDeltaSide(entry.before) && isDeltaSide(entry.after)
    && recordings !== null && isRecordingSummary(recordings.before) && isRecordingSummary(recordings.after)
    && origin !== null && typeof origin.note === "string" && typeof origin.kind === "string";
}

/** The shape the page reads of a delta; the service checked it in full on import. */
function isDelta(value: unknown): value is Delta {
  const delta = jsonObject(value);
  if (!delta) return false;
  const control = jsonObject(delta.control), race = jsonObject(delta.race), code = jsonObject(delta.lab_code);
  return delta.schema === "bluefire.delta/1"
    && typeof delta.claim === "string"
    && isDeltaSide(delta.before) && isDeltaSide(delta.after)
    && Array.isArray(delta.steps) && Array.isArray(delta.differences) && Array.isArray(delta.same_in_both)
    && Array.isArray(delta.new) && Array.isArray(delta.gone) && Array.isArray(delta.unexplained)
    && Array.isArray(delta.refused_because) && typeof delta.comparable === "boolean" && isLimitOrNone(delta.limit)
    && (delta.one_run === undefined || typeof delta.one_run === "boolean") && isLabRulesOrNone(delta.lab_rules)
    && control !== null && Array.isArray(control.fields) && Array.isArray(control.varied)
    && code !== null && typeof code.same === "boolean"
    && race !== null && (typeof race.why === "string" || (jsonObject(race.before) !== null && jsonObject(race.after) !== null));
}

/** A delta in the shape the page reads, or an error when it is not one. */
export function readDelta(value: unknown): Delta {
  if (!isDelta(value)) throw new ApiError("The comparison could not be read.", "invalid_delta");
  return value;
}

function deltaList(payload: unknown): DeltaList {
  const envelope = jsonObject(payload);
  if (!envelope || envelope.schema_version !== "bluefire.delta-list.v1" || !Array.isArray(envelope.deltas)) throw new ApiError("The list of compared runs was invalid.", "invalid_delta_list");
  const deltas = envelope.deltas.filter(isDeltaSummary);
  const unreadable = typeof envelope.unreadable_count === "number" ? envelope.unreadable_count : 0;
  return {
    deltas,
    unreadable_count: unreadable + envelope.deltas.length - deltas.length,
    omitted_count: typeof envelope.omitted_count === "number" ? envelope.omitted_count : 0,
  };
}

/** A file's bytes in base64, as the recording import sends them. */
function base64(bytes: Uint8Array): string {
  let text = "";
  for (let start = 0; start < bytes.length; start += 0x8000) text += String.fromCharCode(...bytes.subarray(start, start + 0x8000));
  return btoa(text);
}

function jsonObject(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
}

/** A list entry of a recording in the shape the interface reads, as the service's list route gives it. */
export function isRecordingSummary(value: unknown): value is RecordingSummary {
  const entry = jsonObject(value);
  if (!entry) return false;
  const source = jsonObject(entry.source), score = jsonObject(entry.score), counts = jsonObject(entry.counts), origin = jsonObject(entry.origin);
  const numbers = (holder: Record<string, unknown> | null, keys: string[]) => holder !== null && keys.every((key) => typeof holder[key] === "number" && Number.isFinite(holder[key]));
  return typeof entry.id === "string" && RECORDING_ID.test(entry.id)
    && typeof entry.title === "string"
    && (entry.kind === "test list" || entry.kind === "attack path")
    && typeof entry.running === "boolean"
    && source !== null && typeof source.environment === "string" && typeof source.engine === "string" && typeof source.started === "string"
    && numbers(score, ["steps", "took_effect", "alerted", "seen", "unseen", "stopped"])
    && numbers(counts, ["steps", "events", "alerts"])
    && origin !== null && typeof origin.note === "string"
    && (origin.kind === "imported" || (origin.kind === "shipped" && typeof origin.run_url === "string"));
}

function recordingList(payload: unknown): RecordingList {
  const envelope = jsonObject(payload);
  if (!envelope || envelope.schema_version !== "bluefire.recording-list.v1" || !Array.isArray(envelope.recordings)) throw new ApiError("The list of recordings was invalid.", "invalid_recording_list");
  const recordings = envelope.recordings.filter(isRecordingSummary);
  const unreadable = typeof envelope.unreadable_count === "number" ? envelope.unreadable_count : 0;
  return {
    recordings,
    // An entry this interface cannot read counts as unreadable too, so it is never silently dropped.
    unreadable_count: unreadable + envelope.recordings.length - recordings.length,
    omitted_count: typeof envelope.omitted_count === "number" ? envelope.omitted_count : 0,
  };
}

function isFinalizedRunRecord(value: unknown): value is RunRecord {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const run = value as Partial<RunRecord>;
  return typeof run.run_id === "string"
    && (run.mode === "simulate" || run.mode === "execute")
    && typeof run.status === "string"
    && typeof run.finalized_at === "string"
    && Array.isArray(run.steps);
}

function canonicalRunList(payload: unknown): CanonicalRunList {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) throw new ApiError("Run history response was invalid.", "invalid_run_history");
  const envelope = payload as { schema_version?: unknown; runs?: unknown };
  if (!Array.isArray(envelope.runs)) throw new ApiError("Run history response was invalid.", "invalid_run_history");
  const runs = envelope.runs.filter(isFinalizedRunRecord);
  return {
    ...(typeof envelope.schema_version === "string" ? { schema_version: envelope.schema_version } : {}),
    runs,
    unavailable_run_count: envelope.runs.length - runs.length,
  };
}

function graphDocument(scenario: Scenario) {
  return {
    scenario: { ...scenario, layout: undefined },
    layout: { schema_version: "bluefire.layout.v1", nodes: Object.entries(scenario.layout ?? {}).map(([id, position]) => ({ id, ...position })) },
  };
}

export function buildRunPayload(scenario: Scenario, config: RunConfiguration) {
  return {
    ...graphDocument(scenario), mode: config.mode, autonomy: config.autonomy,
    ai_provider_id: config.provider || null, runner_profile_id: config.profileId || null,
    target_scope: { scope_refs: config.scopeRefs },
    ...(config.mode === "execute" ? { collectors: [...config.collectors] } : {}),
    ...(config.mode === "execute" && Object.keys(config.actionImplementations).length ? { action_implementations: { ...config.actionImplementations } } : {}),
  };
}

const demoJobs = new Map<string, RunJob>();
const demoSettings = new Map<string, ManagedSetting>();
const demoScenarioVersions = new Map<string, ScenarioVersion>();
const demoResources = new Map<string, ManagedResource>();

export interface ReplayPreparation {
  schema_version: "bluefire.replay-preparation.v1";
  preparation_id: string;
  preparation_context: Record<string, unknown>;
  binding: { source: { run_id: string }; replay_request: Record<string, unknown>; [key: string]: unknown };
  replay_request: Record<string, unknown>;
  replay_extent: "full" | "from_step";
  scenario: Scenario;
  lineage: Record<string, unknown>;
  preflight: PreflightReport;
  approval_created: false;
  effects_started: false;
}

export interface ReplayJobSubmission extends RunJobSubmission {
  schema_version: "bluefire.replay-job-submission.v1";
  preparation: ReplayPreparation;
  preflight: PreflightReport;
}

export interface ReplaySubmissionResolution {
  schema_version: "bluefire.replay-submission-resolution.v1";
  outcome: "closed" | "existing";
  source_run_id: string;
  submission_id: string;
  intent_digest: string;
  submitted_request: Record<string, unknown>;
  job: RunJob;
}

export function replaySubmittedRequest(preparation: ReplayPreparation): Record<string, unknown> {
  return { ...preparation.replay_request, preparation_id: preparation.preparation_id, preparation_context: preparation.preparation_context };
}

export interface ReplayPayloadOptions {
  strategy: "exact" | "from_node" | "swap" | "parameters" | "setup";
  fromStep?: string;
  swapStep?: string;
  swapBehavior?: string;
  profile?: string;
  autonomy?: AutonomyLevel | "preserve";
  provider?: string;
  defenseChange?: string;
  parameterOverrides?: Record<string, Record<string, unknown>>;
  targetScope?: string[];
  approval?: { confirmed: true; approved_by: string };
  actionImplementations?: Record<string, string>;
}

export function buildReplayPayload(options: ReplayPayloadOptions): Record<string, unknown> {
  const executionReview = {
    ...(options.targetScope ? { target_scope: { scope_refs: options.targetScope } } : {}),
    ...(options.approval ? { approval: options.approval } : {}),
    ...(options.strategy !== "exact" && options.actionImplementations && Object.keys(options.actionImplementations).length ? { action_implementations: options.actionImplementations } : {}),
  };
  if (options.strategy === "exact") return { exact: true, ...executionReview };
  return {
    exact: false,
    from_step_id: options.strategy === "from_node" ? options.fromStep || null : null,
    swap_step_id: options.strategy === "swap" ? options.swapStep || null : null,
    swap_behavior_id: options.strategy === "swap" ? options.swapBehavior || null : null,
    runner_profile_id: options.profile || null,
    autonomy: options.autonomy && options.autonomy !== "preserve" ? options.autonomy : null,
    ai_provider_id: options.provider || null,
    defense_change: options.defenseChange || null,
    parameter_overrides: options.strategy === "parameters" ? options.parameterOverrides ?? {} : null,
    ...executionReview,
  };
}

export interface BuildInfo {
  schema_version: "bluefire.build-info.v1";
  product: { name: string; version: string };
  source: { revision: string | null; provenance: "git_archive" | "unavailable" };
  build: { metadata_status: "embedded" | "unavailable" | "invalid"; digest: string | null };
  ui: { digest: string | null; files: { name: string; sha256: string; size: number }[]; matches_build: boolean | null };
}

export const api = {
  async buildInfo(): Promise<BuildInfo> { return request("/build-info"); },
  /** Lightweight authenticated liveness only; never establishes or renews a session. */
  async serviceConnection(signal?: AbortSignal): Promise<{ checkedAt: number }> {
    if (DEMO_MODE) throw new ApiError("Demo mode does not connect to a local service.", "demo_service_unavailable");
    const controller = new AbortController();
    const abort = () => controller.abort();
    signal?.addEventListener("abort", abort, { once: true });
    if (signal?.aborted) abort();
    const timer = window.setTimeout(abort, 5_000);
    try {
      const response = await browserApiFetch(`${API_ROOT}/session`, {
        method: "GET",
        headers: { Accept: "application/json" }, signal: controller.signal,
      });
      if (controller.signal.aborted) throw new ApiError("The local service check did not complete.", "request_timeout");
      if (response.status === 401 || response.status === 403) throw new ApiError(BROWSER_SESSION_RELAUNCH_MESSAGE, "browser_session_unavailable", undefined, response.status);
      if (response.status !== 204) throw new ApiError("The local service did not confirm this browser session.", "service_unavailable", undefined, response.status);
      return { checkedAt: Date.now() };
    } catch (error) {
      if (error instanceof ApiError) throw error;
      throw new ApiError("The local service could not be reached. Cached work remains available.", "service_unavailable");
    } finally {
      window.clearTimeout(timer);
      signal?.removeEventListener("abort", abort);
    }
  },
  async receiverTests(cursor?: string): Promise<ReceiverTestList> {
    if (DEMO_MODE) return { schema_version: "bluefire.receiver-defense-list.v1", jobs: [], truncated: false, next_cursor: null };
    return request(`/receiver-defense/jobs${cursor ? `?cursor=${encodeURIComponent(cursor)}` : ""}`);
  },
  async receiverContext(body: ReceiverContextRequest): Promise<ReceiverContext> {
    if (DEMO_MODE) throw new Error("Receiver control tests require the installed product and an owned Linux lab.");
    return request("/receiver-defense/context", { method: "POST", body: JSON.stringify(body) });
  },
  async createReceiverTest(body: ReceiverContextRequest & { submission_id: string; context_digest: string }): Promise<ReceiverDefenseEnvelope> {
    if (DEMO_MODE) throw new Error("Receiver control tests require the installed product.");
    return request("/receiver-defense/jobs", { method: "POST", body: JSON.stringify(body) });
  },
  async receiverTest(id: string): Promise<ReceiverDefenseEnvelope> {
    if (DEMO_MODE) throw new Error("Receiver control tests require the installed product.");
    return request(`/receiver-defense/jobs/${encodeURIComponent(id)}`);
  },
  async prepareReceiver(id: string, body: { submission_id: string; phase: ReceiverPhase; reviewed_by: string }): Promise<ReceiverDefenseEnvelope> {
    if (DEMO_MODE) throw new Error("Demo mode cannot prepare a receiver.");
    return request(`/receiver-defense/jobs/${encodeURIComponent(id)}/prepare`, { method: "POST", body: JSON.stringify(body) });
  },
  async reviewReceiver(id: string, body: ReceiverDecision): Promise<ReceiverDefenseEnvelope> {
    if (DEMO_MODE) throw new Error("Demo mode cannot accept a receiver run review.");
    return request(`/receiver-defense/jobs/${encodeURIComponent(id)}/review`, { method: "POST", body: JSON.stringify(body) });
  },
  async rollbackReceiverControl(id: string, body: ReceiverControlDecision): Promise<ReceiverDefenseEnvelope> {
    if (DEMO_MODE) throw new Error("Demo mode cannot roll back a retained receiver policy.");
    return request(`/receiver-defense/jobs/${encodeURIComponent(id)}/control`, { method: "POST", body: JSON.stringify(body) });
  },
  async detectionCreationSource(runId: string): Promise<DetectionCreationSource> {
    if (DEMO_MODE) throw new ApiError("Detection creation requires a saved run in the connected local service.", "demo_assistance_refused", undefined, 409);
    return request("/assistance/detection-source", { method: "POST", body: JSON.stringify({ run_id: runId }) });
  },
  async detectionCreation(jobId: string): Promise<DetectionCreationEnvelope> {
    if (DEMO_MODE) throw new ApiError("Saved detection work requires the connected local service.", "demo_assistance_refused", undefined, 409);
    return request(`/ai/detection-create-jobs/${encodeURIComponent(jobId)}`);
  },
  async validateDetectionCreation(jobId: string, body: { proposal_digest: string; title: string; source: string }): Promise<DetectionCreationValidation> {
    if (DEMO_MODE) throw new ApiError("Source validation requires the connected local service.", "demo_assistance_refused", undefined, 409);
    return request(`/ai/detection-create-jobs/${encodeURIComponent(jobId)}/validate`, { method: "POST", body: JSON.stringify(body) });
  },
  async reviewDetectionCreation(jobId: string, body: DetectionCreationDecision): Promise<DetectionCreationEnvelope> {
    if (DEMO_MODE) throw new ApiError("Rule review requires the connected local service.", "demo_assistance_refused", undefined, 409);
    return request(`/ai/detection-create-jobs/${encodeURIComponent(jobId)}/review`, { method: "POST", body: JSON.stringify(body) });
  },
  async assistanceDetectionContext(selection: RunDetectionSelection): Promise<AssistanceContext> {
    if (DEMO_MODE) throw new ApiError("Detection creation requires the connected local service.", "demo_assistance_refused", undefined, 409);
    const { kind: _kind, ...body } = selection;
    void _kind;
    return request("/assistance/detection-context", { method: "POST", body: JSON.stringify(body) });
  },
  async assistanceReceiverContext(selection: import("./receiver-assistance").ReceiverAssistanceSelection): Promise<import("./receiver-assistance").ReceiverAssistanceContext> {
    if (DEMO_MODE) throw new ApiError("Receiver assistance requires the connected local service.", "demo_assistance_refused", undefined, 409);
    return request("/assistance/receiver-context", { method: "POST", body: JSON.stringify({ selection }) });
  },
  async assistanceRunContext(selection: SavedRunSelection): Promise<AssistanceContext> {
    if (DEMO_MODE) throw new ApiError("Run assistance requires the connected local service.", "demo_assistance_refused", undefined, 409);
    return request("/assistance/run-context", { method: "POST", body: JSON.stringify({ selection }) });
  },
  async assistanceRun(jobId: string): Promise<AssistanceRunEnvelope> {
    if (DEMO_MODE) throw new ApiError("Run assistance requires the connected local service.", "demo_assistance_refused", undefined, 409);
    return request(`/assistance/run-jobs/${encodeURIComponent(jobId)}`);
  },
  async reviewAssistanceRun(jobId: string, body: RunPreparationDecision & { decision: "accept" | "reject" }): Promise<AssistanceRunEnvelope> {
    if (DEMO_MODE) throw new ApiError("Run review requires the connected local service.", "demo_assistance_refused", undefined, 409);
    return request(`/assistance/run-jobs/${encodeURIComponent(jobId)}/review`, { method: "POST", body: JSON.stringify(body) });
  },
  async assistanceGraphContext(base: GraphSelection["base_scenario"]): Promise<AssistanceContext> {
    if (DEMO_MODE) throw new ApiError("Graph assistance requires the connected local service.", "demo_assistance_refused", undefined, 409);
    const query = base ? `?${new URLSearchParams({ scenario_id: base.scenario_id, version: String(base.version), digest: base.digest })}` : "";
    return request(`/assistance/graph-context${query}`);
  },
  async assistanceGraphEditContext(selection: GraphSelection): Promise<AssistanceContext> {
    if (DEMO_MODE) throw new ApiError("Graph assistance requires the connected local service.", "demo_assistance_refused", undefined, 409);
    return request("/assistance/graph-context", { method: "POST", body: JSON.stringify(selection) });
  },
  async graphProposal(jobId: string): Promise<GraphEnvelope> {
    if (DEMO_MODE) throw new ApiError("Saved graph proposals require the connected local service.", "demo_assistance_refused", undefined, 409);
    return request(`/ai/graph-jobs/${encodeURIComponent(jobId)}`);
  },
  async validateGraphProposal(jobId: string, body: { proposal_digest: string; scenario: Scenario }): Promise<GraphValidation> {
    if (DEMO_MODE) throw new ApiError("Graph review requires the connected local service.", "demo_assistance_refused", undefined, 409);
    return request(`/ai/graph-jobs/${encodeURIComponent(jobId)}/validate`, { method: "POST", body: JSON.stringify(body) });
  },
  async reviewGraphProposal(jobId: string, body: GraphDecision): Promise<GraphEnvelope> {
    if (DEMO_MODE) throw new ApiError("Graph review requires the connected local service.", "demo_assistance_refused", undefined, 409);
    return request(`/ai/graph-jobs/${encodeURIComponent(jobId)}/review`, { method: "POST", body: JSON.stringify(body) });
  },
  async immutableScenarioVersion(id: string, version: number): Promise<{ schema_version: string; scenario: ScenarioVersion }> {
    if (DEMO_MODE) throw new ApiError("Saved proposal versions require the connected local service.", "demo_assistance_refused", undefined, 409);
    return request(`/scenario-versions/${encodeURIComponent(id)}/versions/${version}`);
  },
  async assistanceContext(runId: string, candidateId: string): Promise<AssistanceContext> {
    if (DEMO_MODE) throw new ApiError("Contextual assistance requires saved observations in the connected local service.", "demo_assistance_refused", undefined, 409);
    return request(`/assistance/context?${new URLSearchParams({ run_id: runId, candidate_id: candidateId })}`);
  },
  async submitAssistance(body: AssistanceRequest): Promise<AssistanceEnvelope> {
    if (DEMO_MODE) throw new ApiError("The demo cannot submit assistant work.", "demo_assistance_refused", undefined, 409);
    return request("/assistance/turns", { method: "POST", body: JSON.stringify(body) });
  },
  async assistanceTurn(jobId: string): Promise<AssistanceEnvelope> {
    if (DEMO_MODE) throw new ApiError("Saved assistant work requires the connected local service.", "demo_assistance_refused", undefined, 409);
    return request(`/assistance/turns/${encodeURIComponent(jobId)}`);
  },
  async continueAssistance(jobId: string, body: { submission_id: string; context_digest: string }): Promise<AssistanceEnvelope> {
    if (DEMO_MODE) throw new ApiError("The demo cannot continue assistant work.", "demo_assistance_refused", undefined, 409);
    return request(`/assistance/turns/${encodeURIComponent(jobId)}/continue`, { method: "POST", body: JSON.stringify(body) });
  },
  async aiAuthorizations(): Promise<AILiveAuthorizationList> {
    if (DEMO_MODE) return { schema_version: "bluefire.ai-live-authorizations.v1", context: { kind: "direct", binding_digest: null, expires_at_ms: null, provider: null }, authorizations: [] };
    return request("/ai/authorizations");
  },
  async authorizeAI(body: AILiveAuthorizationRequest): Promise<{ authorization: AILiveAuthorization }> {
    if (DEMO_MODE) throw new ApiError("Live model authorization requires the installed local service.", "demo_authorization_refused", undefined, 409);
    return request("/ai/authorizations", { method: "POST", body: JSON.stringify(body) });
  },
  async revokeAIAuthorization(id: string): Promise<{ authorization: AILiveAuthorization }> {
    if (DEMO_MODE) throw new ApiError("Live model authorization requires the installed local service.", "demo_authorization_refused", undefined, 409);
    return request(`/ai/authorizations/${encodeURIComponent(id)}/revoke`, { method: "POST", body: "{}" });
  },
  async checkAIProvider(provider: Record<string, unknown> | PublicAIProviderConfig, connect: boolean): Promise<AIProviderCheck> {
    if (DEMO_MODE) return { schema_version: "bluefire.ai-provider-check.v1", provider_id: String(provider.id), api_style: String(provider.kind), model: String(provider.model), credential_state: "unavailable", connectivity: "not_tested", structured_output: "not_tested", attempts: 0, used_fallback: false, code: "demo_no_network", message: "Demo mode cannot resolve server credentials or test provider connections. No request was sent." };
    return request("/ai/providers/check", { method: "POST", body: JSON.stringify({ provider, connect }) }, 12_000);
  },
  async aiDraft(objective: string, providerId?: string | null, maxNodes = 8, maxEdges = 16): Promise<AIGraphDraftResult> {
    if (DEMO_MODE) {
      const count = Math.max(1, Math.min(maxNodes, demoScenario.steps.length)); const steps = structuredClone(demoScenario.steps.slice(0, count)); const ids = new Set(steps.map((step) => step.id)); const edges = structuredClone(demoScenario.edges.filter((edge) => ids.has(edge.from_step) && ids.has(edge.to_step)).slice(0, maxEdges));
      return { schema_version: "bluefire.ai-graph-draft-result.v1", draft_id: `ai-draft-demo-${Date.now()}`, saved: false, scenario: { ...structuredClone(demoScenario), title: objective.slice(0, 80), purpose: objective, start: steps[0]!.id, steps, edges, layout: undefined }, rationale: "Sanitized demo control-plane draft using registered behavior contracts.", assumptions: ["Demo mode did not call an external model.", "Operator review is required before saving or running."], audit: { schema_version: "bluefire.ai-graph-draft-audit.v1", unsaved: true, provider: { requested_provider_id: providerId ?? null, effective_provider_id: "deterministic-offline.v1", model: "deterministic-planner.v1", attempts: 1, used_fallback: true, fallback_reason: "demo_mode", usage: null }, bounds: { max_nodes: maxNodes, max_edges: maxEdges }, selected_behavior_ids: steps.map((step) => step.behavior_id) } };
    }
    return request("/ai/drafts", { method: "POST", body: JSON.stringify({ objective, ...(providerId ? { provider_id: providerId } : {}), max_nodes: maxNodes, max_edges: maxEdges }) }, AI_DRAFT_REQUEST_TIMEOUT_MS);
  },
  async catalog(): Promise<CatalogResponse> { return DEMO_MODE ? structuredClone(demoCatalog) : request("/catalog"); },
  async intakeReviewedT1082(destinationId: string, runnerProfileId: string, operatorId: string): Promise<ReviewedT1082IntakeResult> {
    if (DEMO_MODE) throw new ApiError("Demo mode cannot activate reviewed source content.", "demo_source_intake_refused", undefined, 409);
    return request("/research-intakes/mitre-attack-t1082-v19-2", {
      method: "POST",
      body: JSON.stringify({ destination_id: destinationId, runner_profile_id: runnerProfileId, operator_id: operatorId }),
    }, RUNNER_TRUST_MUTATION_TIMEOUT_MS);
  },
  async actionPackages(): Promise<ActionPackageInventory> {
    if (DEMO_MODE) return {
      schema_version: "bluefire.action-package-inventory.v1",
      packages: [],
      publishers: [],
      catalog: { schema_version: "bluefire.action-catalog-authority.v1", generation: 0, catalog_digest: EMPTY_ACTION_PACKAGE_CATALOG_DIGEST, packages: [], action_bindings: [] },
      activation_events: [],
      execution_boundary: "demo-no-execution",
    };
    return request("/action-packages");
  },
  async installActionPackage(envelopeJson: string, installedBy: string): Promise<{ schema_version: string; package: ActionPackageInstallation; catalog_changed: false; activation_required: true }> {
    if (DEMO_MODE) throw new ApiError("Demo mode cannot install signed action packages.", "demo_action_package_refused", undefined, 409);
    let envelope: unknown;
    try {
      envelope = JSON.parse(envelopeJson) as unknown;
    } catch {
      throw new ApiError("The signed package envelope must be valid JSON.", "invalid_action_package_envelope");
    }
    if (!envelope || typeof envelope !== "object" || Array.isArray(envelope)) {
      throw new ApiError("The signed package envelope must be a JSON object.", "invalid_action_package_envelope");
    }
    // Keep the parsed envelope's original numeric tokens intact. Re-serializing
    // through JavaScript would round signed 64-bit integers outside Number's
    // safe range before the control plane can perform canonical verification.
    const body = `{"envelope":${envelopeJson},"installed_by":${JSON.stringify(installedBy)}}`;
    return request("/action-packages", { method: "POST", body });
  },
  async trustActionPackagePublisher(enrollment: ActionPackagePublisherEnrollment): Promise<{ schema_version: string; publisher: ActionPackagePublisherTrust }> {
    if (DEMO_MODE) throw new ApiError("Demo mode cannot enroll publisher trust.", "demo_action_package_refused", undefined, 409);
    return request("/action-package-publishers", { method: "POST", body: JSON.stringify(enrollment) });
  },
  async transitionActionPackagePublisher(publisherId: string, keyId: string, action: "suspend" | "revoke", actor: string, reason: string): Promise<{ schema_version: string; publisher: ActionPackagePublisherTrust; catalog?: Record<string, unknown>; active_packages_deactivated?: true }> {
    if (DEMO_MODE) throw new ApiError("Demo mode cannot change publisher trust.", "demo_action_package_refused", undefined, 409);
    return request(`/action-package-publishers/${encodeURIComponent(publisherId)}/keys/${encodeURIComponent(keyId)}/${action}`, { method: "POST", body: JSON.stringify({ actor, reason }) });
  },
  async activateActionPackage(packageId: string, version: string, runnerProfileId: string, activatedBy: string, reason: string): Promise<{ schema_version: string; operation: string; package: ActionPackageInstallation; catalog: Record<string, unknown> }> {
    if (DEMO_MODE) throw new ApiError("Demo mode cannot activate action packages.", "demo_action_package_refused", undefined, 409);
    return request(`/action-packages/${encodeURIComponent(packageId)}/versions/${encodeURIComponent(version)}/activate`, { method: "POST", body: JSON.stringify({ runner_profile_id: runnerProfileId, activated_by: activatedBy, reason }) }, 60_000);
  },
  async deactivateActionPackage(packageId: string, version: string, identity: ActionPackageCatalogIdentity, deactivatedBy: string, reason: string): Promise<{ schema_version: string; package: ActionPackageInstallation; catalog: Record<string, unknown> }> {
    if (DEMO_MODE) throw new ApiError("Demo mode cannot deactivate action packages.", "demo_action_package_refused", undefined, 409);
    return request(`/action-packages/${encodeURIComponent(packageId)}/versions/${encodeURIComponent(version)}/deactivate`, { method: "POST", body: JSON.stringify({ ...identity, deactivated_by: deactivatedBy, reason }) });
  },
  async removeActionPackage(packageId: string, version: string, identity: ActionPackageCatalogIdentity, removedBy: string, reason: string): Promise<{ schema_version: string; package: ActionPackageInstallation; catalog: Record<string, unknown>; historical_audit_bytes_retained: true }> {
    if (DEMO_MODE) throw new ApiError("Demo mode cannot remove action packages.", "demo_action_package_refused", undefined, 409);
    return request(`/action-packages/${encodeURIComponent(packageId)}/versions/${encodeURIComponent(version)}/remove`, { method: "POST", body: JSON.stringify({ ...identity, removed_by: removedBy, reason }) });
  },
  async scenarios(): Promise<{ scenarios: Scenario[] }> { return DEMO_MODE ? { scenarios: [structuredClone(demoScenario)] } : request("/scenarios"); },
  async settings(): Promise<{ schema_version: string; settings: ManagedSetting[] }> {
    return DEMO_MODE ? { schema_version: "bluefire.setting-list.v1", settings: structuredClone([...demoSettings.values()]) } : request("/settings");
  },
  async saveSetting<T>(key: string, value: T): Promise<{ schema_version: string; setting: ManagedSetting<T> }> {
    if (DEMO_MODE) {
      const setting = { key, value: structuredClone(value), updated_at: new Date().toISOString() };
      demoSettings.set(key, setting);
      return { schema_version: "bluefire.setting.v1", setting };
    }
    return request(`/settings/${encodeURIComponent(key)}`, { method: "POST", body: JSON.stringify({ value }) });
  },
  async scenarioVersions(): Promise<{ schema_version: string; scenarios: ScenarioVersion[] }> {
    return DEMO_MODE ? { schema_version: "bluefire.scenario-version-list.v1", scenarios: structuredClone([...demoScenarioVersions.values()]) } : request("/scenario-versions");
  },
  async scenarioVersionHistory(id: string): Promise<{ schema_version: string; scenarios: ScenarioVersion[] }> {
    if (DEMO_MODE) throw new ApiError("Complete saved history requires the connected local service.", "demo_history_unavailable", undefined, 409);
    return request(`/scenario-versions/${encodeURIComponent(id)}/versions`);
  },
  async saveScenarioVersion(scenario: Scenario): Promise<{ schema_version: string; scenario: ScenarioVersion }> {
    const { layout: _layout, ...canonicalScenario } = scenario;
    void _layout;
    if (DEMO_MODE) {
      const previous = demoScenarioVersions.get(scenario.id);
      const saved: ScenarioVersion = { scenario_id: scenario.id, title: scenario.title, version: (previous?.version ?? 0) + 1, digest: `demo-${scenario.id}-${Date.now()}`, created_at: previous?.created_at ?? new Date().toISOString(), updated_at: new Date().toISOString(), document: structuredClone(canonicalScenario) as Scenario };
      demoScenarioVersions.set(scenario.id, saved);
      return { schema_version: "bluefire.scenario-version.v1", scenario: structuredClone(saved) };
    }
    return request("/scenario-versions", { method: "POST", body: JSON.stringify({ scenario: canonicalScenario }) });
  },
  async resources<T extends Record<string, unknown> = Record<string, unknown>>(kind: ManagedResourceRoute): Promise<ManagedResourceList<T>> {
    if (DEMO_MODE) {
      const resources = structuredClone([...demoResources.values()].filter((item) => item.kind === kind)) as Array<ManagedResource<T>>;
      const inventory = kind === "plugins" ? { schema_version: "bluefire.plugin-inventory.v1", lifecycle: "declarative-manifest-only", manifest_count: resources.length, active_manifest_ids: resources.filter((item) => item.status === "active").map((item) => item.id), health: { state: "ready", message: "Sanitized demo metadata inventory." }, executable_loading: false as const, dynamic_actions: false as const, python_entry_points: false as const } : undefined;
      return { schema_version: "bluefire.resource-list.v1", kind, resources, inventory };
    }
    return request(`/resources/${kind}`);
  },
  async saveResource<T extends Record<string, unknown>>(kind: ManagedResourceRoute, id: string, document: T, status = "draft"): Promise<{ schema_version: string; resource: ManagedResource<T> }> {
    if (DEMO_MODE) {
      const key = `${kind}:${id}`; const previous = demoResources.get(key); const now = new Date().toISOString();
      const pluginStatus = kind === "plugins"
        ? previous?.status === "inactive" ? "inactive"
          : document.enabled !== true ? "disabled"
            : document.trust === "untrusted" ? "review_required" : "ready"
        : status;
      const resource: ManagedResource<T> = { kind, id, document: structuredClone(document), status: pluginStatus, digest: `demo-${id}-${Date.now()}`, created_at: previous?.created_at ?? now, updated_at: now };
      demoResources.set(key, resource);
      return { schema_version: "bluefire.resource.v1", resource: structuredClone(resource) };
    }
    const body = kind === "plugins" ? { document } : { document, status };
    return request(`/resources/${kind}/${encodeURIComponent(id)}`, { method: "POST", body: JSON.stringify(body) });
  },
  async inspectNativeToolCandidate(profileId: string, installationLocation: string, toolVersion: string, actionId: NativeToolActionId = "sandbox.permission.chmod.v1"): Promise<NativeToolCandidateInspection> {
    if (DEMO_MODE) throw new ApiError("Demo mode cannot inspect a local native tool.", "demo_native_tool_inspection_refused", undefined, 409);
    return request(`/resources/runner-profiles/${encodeURIComponent(profileId)}/inspect-native-tool`, {
      method: "POST",
      body: JSON.stringify({ schema_version: "bluefire.native-tool-candidate.v1", action_id: actionId, installation_location: installationLocation, tool_version: toolVersion }),
    });
  },
  async activateResource(kind: "runner-profiles" | "model-providers" | "plugins", id: string): Promise<RuntimeResourceResult> {
    if (DEMO_MODE) return demoRuntimeResource(kind, id, "active");
    return request(`/resources/${kind}/${encodeURIComponent(id)}/activate`, { method: "POST", body: JSON.stringify({}) });
  },
  async deactivateResource(kind: "runner-profiles" | "model-providers" | "plugins", id: string): Promise<RuntimeResourceResult> {
    if (DEMO_MODE) return demoRuntimeResource(kind, id, "inactive");
    return request(`/resources/${kind}/${encodeURIComponent(id)}/deactivate`, { method: "POST", body: JSON.stringify({}) });
  },
  async probeRunnerProfile(id: string): Promise<RunnerProbe> {
    if (DEMO_MODE) return { schema_version: "bluefire.runner-probe.v1", profile_id: id, version: null, platform: null, actions: [], health: { state: "unavailable", message: "Demo mode never probes a local runner." } };
    return request(`/resources/runner-profiles/${encodeURIComponent(id)}/probe`, { method: "POST", body: JSON.stringify({}) });
  },
  async runnerStatus(profileId?: string): Promise<RunnerLifecycleStatus> {
    if (DEMO_MODE) return { schema_version: "bluefire.runner-lifecycle-status.v1", state: "unavailable", runner_id: "bluefire-rust-runner.v1", profile_id: null, loopback_only: true, enrollment: "absent", process: "absent", runner: null, health: null };
    return request(`/runner${profileId ? `?profile_id=${encodeURIComponent(profileId)}` : ""}`);
  },
  async reviewRunnerUpgrade(profileId?: string): Promise<RunnerUpgradeReview> {
    if (DEMO_MODE) throw new ApiError("Demo mode cannot review a local runner upgrade.", "demo_runner_lifecycle_refused", undefined, 409);
    return request("/runner/upgrade-review", { method: "POST", body: JSON.stringify(profileId ? { profile_id: profileId } : {}) }, 120_000);
  },
  async bootstrapRunner(profileId?: string, allowUpgrade = false, upgradeReviewDigest?: string): Promise<RunnerLifecycleStatus> {
    if (DEMO_MODE) throw new ApiError("Demo mode cannot bootstrap a local runner.", "demo_runner_lifecycle_refused", undefined, 409);
    if (upgradeReviewDigest !== undefined && !allowUpgrade) throw new ApiError("An upgrade review requires an explicit upgrade request.", "runner_bootstrap_invalid", undefined, 400);
    return request("/runner/bootstrap", { method: "POST", body: JSON.stringify({ ...(profileId ? { profile_id: profileId } : {}), ...(allowUpgrade ? { allow_upgrade: true } : {}), ...(upgradeReviewDigest !== undefined ? { upgrade_review_digest: upgradeReviewDigest } : {}) }) }, 120_000);
  },
  async startRunner(profileId?: string): Promise<RunnerLifecycleStatus> {
    if (DEMO_MODE) throw new ApiError("Demo mode cannot start a local runner.", "demo_runner_lifecycle_refused", undefined, 409);
    return request("/runner/start", { method: "POST", body: JSON.stringify(profileId ? { profile_id: profileId } : {}) }, 45_000);
  },
  async stopRunner(profileId?: string): Promise<RunnerLifecycleStatus> {
    if (DEMO_MODE) throw new ApiError("Demo mode cannot stop a local runner.", "demo_runner_lifecycle_refused", undefined, 409);
    return request("/runner/stop", { method: "POST", body: JSON.stringify(profileId ? { profile_id: profileId } : {}) }, 45_000);
  },
  async revokeRunner(): Promise<RunnerLifecycleStatus> {
    if (DEMO_MODE) throw new ApiError("Demo mode cannot revoke local runner trust.", "demo_runner_lifecycle_refused", undefined, 409);
    return request("/runner/revoke", { method: "POST", body: JSON.stringify({}) }, RUNNER_TRUST_MUTATION_TIMEOUT_MS);
  },
  async removeRunner(confirmRunnerId: string): Promise<RunnerLifecycleStatus> {
    if (DEMO_MODE) throw new ApiError("Demo mode cannot remove local runner trust.", "demo_runner_lifecycle_refused", undefined, 409);
    return request("/runner/remove", { method: "POST", body: JSON.stringify({ confirm_runner_id: confirmRunnerId }) }, RUNNER_TRUST_MUTATION_TIMEOUT_MS);
  },
  async detectionHealth(): Promise<DetectionLabHealth> {
    if (DEMO_MODE) return { schema_version: "bluefire.detection-lab-health.v1", ready: true, persistence_ready: true, candidate_resources: [...demoResources.values()].filter((item) => item.kind === "detections").length, invalid_candidate_resources: 0, languages: { internal: { ready: true, authoritative: true, backend: "demo-structured-matcher", version: "fixture" }, sigma: { ready: false, authoritative: false, backend: "pySigma", version: null }, yara: { ready: false, authoritative: false, backend: "YARA-Python", version: null }, spl: { ready: true, authoritative: false, backend: "structural-only", version: "fixture", lifecycle_ceiling: "hypothesis" } }, limits: { source_bytes: 262144, fixture_bytes: 1048576, fixtures_per_action: 128, evidence_per_action: 128, notes_per_action: 128 } };
    return request("/detection-lab/health");
  },
  async detections(): Promise<{ schema_version: string; candidates: DetectionResource[] }> {
    if (DEMO_MODE) return { schema_version: "bluefire.detection-list.v1", candidates: structuredClone([...demoResources.values()].filter((item) => item.kind === "detections")) as DetectionResource[] };
    return request("/detections");
  },
  async detection(candidateId: string): Promise<DetectionResourceEnvelope> {
    if (DEMO_MODE) {
      const resource = demoResources.get(`detections:${candidateId}`) as DetectionResource | undefined;
      if (!resource) throw new ApiError("Demo detection candidate was not found.", "detection_not_found", undefined, 404);
      return { schema_version: "bluefire.detection-resource.v1", candidate: structuredClone(resource) };
    }
    return request(`/detections/${encodeURIComponent(candidateId)}`);
  },
  async upsertDetection(document: Record<string, unknown>): Promise<DetectionResourceEnvelope> {
    if (DEMO_MODE) {
      const identity = `detection-demo-${Date.now()}`; const now = new Date().toISOString();
      const resource = { kind: "detections", id: identity, status: "hypothesis", digest: `demo-${identity}`, created_at: now, updated_at: now, document: { ...structuredClone(document), candidate_id: identity, state: "hypothesis", lifecycle_history: [{ sequence: 1, action: "hypothesis_upsert", current_state: "hypothesis", outcome: "created", timestamp: now }] } } as DetectionResource;
      demoResources.set(`detections:${identity}`, resource);
      return { schema_version: "bluefire.detection-resource.v1", candidate: structuredClone(resource) };
    }
    return request("/detections", { method: "POST", body: JSON.stringify(document) });
  },
  async detectionAction(candidateId: string, action: "parse" | "exercise-fixtures" | "exercise-observed" | "evaluate-benign" | "reject", body: Record<string, unknown>): Promise<DetectionResourceEnvelope> {
    if (DEMO_MODE) throw new ApiError("Demo candidates do not run parser, fixture, evidence, or rejection lifecycle actions.", "demo_detection_action_refused", undefined, 409);
    return request(`/detections/${encodeURIComponent(candidateId)}/${action}`, { method: "POST", body: JSON.stringify(body) });
  },
  async cloneDetection(candidateId: string, body: DetectionCloneRequest): Promise<DetectionResourceEnvelope> {
    if (DEMO_MODE) throw new ApiError("Demo candidates cannot create durable immutable revisions.", "demo_detection_revision_refused", undefined, 409);
    return request(`/detections/${encodeURIComponent(candidateId)}/clone`, { method: "POST", body: JSON.stringify(body) });
  },
  async tuneDetection(candidateId: string, body: DetectionTuneRequest): Promise<DetectionResourceEnvelope> {
    if (DEMO_MODE) throw new ApiError("Demo candidates cannot create durable immutable revisions.", "demo_detection_revision_refused", undefined, 409);
    return request(`/detections/${encodeURIComponent(candidateId)}/tune`, { method: "POST", body: JSON.stringify(body) });
  },
  async reviseDetectionSource(candidateId: string, body: { source: string; reason: string; title?: string }): Promise<DetectionResourceEnvelope> {
    if (DEMO_MODE) throw new ApiError("Demo candidates cannot create durable immutable revisions.", "demo_detection_revision_refused", undefined, 409);
    return request(`/detections/${encodeURIComponent(candidateId)}/revise-source`, { method: "POST", body: JSON.stringify(body) });
  },
  async compareDetections(baselineCandidateId: string, candidateId: string): Promise<DetectionComparisonResponse> {
    if (DEMO_MODE) throw new ApiError("Demo candidates cannot produce durable revision comparisons.", "demo_detection_comparison_refused", undefined, 409);
    return request(`/detections/${encodeURIComponent(baselineCandidateId)}/compare`, { method: "POST", body: JSON.stringify({ candidate_id: candidateId }) });
  },
  async evaluateDetectionRun(candidateId: string, body: { run_id: string; question: string; case_role: DetectionCaseRole; activity_label?: "attack" | "benign" | "unknown"; evaluation_use?: "development" | "independent" | "unspecified" }): Promise<{ evaluation: DetectionRunEvaluation }> {
    if (DEMO_MODE) throw new ApiError("Demo mode cannot retain immutable detector evaluations.", "demo_detection_evaluation_refused", undefined, 409);
    return request(`/detections/${encodeURIComponent(candidateId)}/evaluate-run`, { method: "POST", body: JSON.stringify(body) });
  },
  async detectionRunEvaluations(candidateId: string): Promise<{ evaluations: DetectionRunEvaluation[] }> {
    if (DEMO_MODE) return { evaluations: [] };
    return request(`/detections/${encodeURIComponent(candidateId)}/evaluations`);
  },
  async suggestDetectionRevision(candidateId: string, body: DetectionAIRequest): Promise<{ job: RunJob }> {
    if (DEMO_MODE) throw new ApiError("Detection assistance requires the connected local service.", "demo_detection_ai_refused", undefined, 409);
    return request(`/detections/${encodeURIComponent(candidateId)}/ai-revision-jobs`, { method: "POST", body: JSON.stringify(body) });
  },
  async decideDetectionRevision(jobId: string, body: DetectionAIDecision): Promise<{ proposal_job: RunJob; application_job: RunJob | null; decision: DetectionAIDecision }> {
    if (DEMO_MODE) throw new ApiError("Demo mode cannot accept detection changes.", "demo_detection_ai_refused", undefined, 409);
    return request(`/jobs/${encodeURIComponent(jobId)}/detection-revision-decisions`, { method: "POST", body: JSON.stringify(body) });
  },
  async detectionFromRun(runId: string, candidateId: string): Promise<DetectionRunImportResponse> {
    if (DEMO_MODE) throw new ApiError("Demo records cannot create durable run-linked hypotheses.", "demo_detection_import_refused", undefined, 409);
    return request("/detections/from-run", { method: "POST", body: JSON.stringify({ run_id: runId, candidate_id: candidateId }) });
  },
  async runs(): Promise<CanonicalRunList> {
    if (DEMO_MODE) return { runs: structuredClone(demoRuns), unavailable_run_count: 0 };
    return canonicalRunList(await request<unknown>("/runs"));
  },
  /** The recordings the service keeps: those shipped with BlueFire first, then the imported ones. */
  async recordings(): Promise<RecordingList> {
    if (DEMO_MODE) {
      // Only the demo build holds the shipped recordings: it lists them from the entries the build
      // worked out, and loads each, a file of its own, only when it is opened.
      const { shippedSummaries } = await import("./demo-recordings");
      return { recordings: shippedSummaries(), unreadable_count: 0, omitted_count: 0 };
    }
    return recordingList(await request<unknown>("/recordings"));
  },
  async recording(recordingId: string): Promise<RecordingEntry> {
    if (!RECORDING_ID.test(recordingId)) throw new ApiError("Recording identifier is invalid.", "invalid_recording_id", undefined, 400);
    if (DEMO_MODE) {
      const { shippedRecording } = await import("./demo-recordings");
      const shipped = await shippedRecording(recordingId);
      if (!shipped) throw new ApiError("Recording was not found.", "recording_not_found", undefined, 404);
      return { summary: shipped.summary, recording: shipped.recording, sha256: shipped.sha256 };
    }
    const envelope = jsonObject(await request<unknown>(`/recordings/${encodeURIComponent(recordingId)}`));
    if (!envelope || envelope.schema_version !== "bluefire.recording-entry.v1" || !isRecordingSummary(envelope.summary) || envelope.summary.id !== recordingId
      || (envelope.sha256 !== undefined && !(typeof envelope.sha256 === "string" && FILE_DIGEST.test(envelope.sha256)))) {
      throw new ApiError("The service returned an invalid recording.", "invalid_recording_entry");
    }
    const sha256 = typeof envelope.sha256 === "string" ? envelope.sha256 : undefined;
    return { summary: envelope.summary, recording: envelope.recording, ...(sha256 ? { sha256 } : {}) };
  },
  /**
   * Imports one recording file, sent as its bytes, untouched, so that the service
   * keeps the file its engine wrote (a comparison of two runs names its
   * recordings by the file's SHA-256) and reads exactly what the command line
   * reads: a duplicate key, a NaN or a byte order mark is refused with the same
   * reason. A refusal is an ApiError whose `details.problems` lists the
   * service's problems in plain words.
   */
  async importRecording(file: Uint8Array): Promise<RecordingImport> {
    if (DEMO_MODE) throw new ApiError("The demo cannot import recordings. Import one in the installed app.", "demo_recording_import_refused", undefined, 409);
    const envelope = jsonObject(await request<unknown>("/recordings", { method: "POST", body: JSON.stringify({ recording_file: base64(file) }) }, 60_000));
    if (!envelope || typeof envelope.created !== "boolean" || typeof envelope.replaced !== "boolean" || !isRecordingSummary(envelope.summary)) {
      throw new ApiError("The service's answer to the import could not be read. Refresh the list to see whether the recording is there.", "invalid_recording_import");
    }
    const sha256 = typeof envelope.sha256 === "string" && FILE_DIGEST.test(envelope.sha256) ? envelope.sha256 : undefined;
    return { created: envelope.created, replaced: envelope.replaced, anotherEvaluation: envelope.another_evaluation === true, ...(sha256 ? { sha256 } : {}), summary: envelope.summary };
  },
  /**
   * One kept file of a recording, by its id and the SHA-256 of the file: a run
   * evaluated more than once keeps a file for each evaluation under its one id.
   */
  async recordingFile(recordingId: string, sha256: string): Promise<{ summary: RecordingSummary; recording: unknown }> {
    if (!RECORDING_ID.test(recordingId)) throw new ApiError("Recording identifier is invalid.", "invalid_recording_id", undefined, 400);
    if (!FILE_DIGEST.test(sha256)) throw new ApiError("A recording's file is named by its SHA-256, 64 hex digits.", "invalid_recording_file", undefined, 400);
    if (DEMO_MODE) {
      const { shippedFile } = await import("./demo-recordings");
      const shipped = await shippedFile(recordingId, sha256);
      if (!shipped) throw new ApiError("No file with this SHA-256 is kept for this recording.", "recording_file_not_found", undefined, 404);
      return { summary: shipped.summary, recording: shipped.recording };
    }
    const envelope = jsonObject(await request<unknown>(`/recordings/${encodeURIComponent(recordingId)}/files/${sha256}`));
    if (!envelope || envelope.schema_version !== "bluefire.recording-entry.v1" || envelope.sha256 !== sha256 || !isRecordingSummary(envelope.summary) || envelope.summary.id !== recordingId || !("recording" in envelope)) {
      throw new ApiError("The service returned an invalid recording.", "invalid_recording_entry");
    }
    return { summary: envelope.summary, recording: envelope.recording };
  },
  /** The comparisons of two kept recordings, each as `bluefire-lab compare` wrote it. */
  async recordingDeltas(): Promise<DeltaList> {
    if (DEMO_MODE) {
      const { shippedPairs } = await import("./demo-pair");
      return { deltas: (await shippedPairs()).map((pair) => pair.summary), unreadable_count: 0, omitted_count: 0 };
    }
    return deltaList(await request<unknown>("/recordings/deltas"));
  },
  async recordingDelta(deltaId: string): Promise<DeltaEntry> {
    if (!DELTA_ID.test(deltaId)) throw new ApiError("Comparison identifier is invalid.", "invalid_delta_id", undefined, 400);
    if (DEMO_MODE) {
      const { shippedPairs } = await import("./demo-pair");
      const shipped = (await shippedPairs()).find((pair) => pair.summary.id === deltaId);
      if (!shipped) throw new ApiError("Comparison was not found.", "delta_not_found", undefined, 404);
      return shipped;
    }
    const envelope = jsonObject(await request<unknown>(`/recordings/deltas/${encodeURIComponent(deltaId)}`));
    if (!envelope || envelope.schema_version !== "bluefire.delta-entry.v1" || !isDeltaSummary(envelope.summary) || envelope.summary.id !== deltaId || !isDelta(envelope.delta)) {
      throw new ApiError("The service returned an invalid comparison.", "invalid_delta_entry");
    }
    return { summary: envelope.summary, delta: envelope.delta };
  },
  async runBundle(runId: string, signal: AbortSignal): Promise<Blob> {
    if (DEMO_MODE) throw new ApiError("Demo runs do not have a saved bundle.", "demo_bundle_unavailable");
    if (!/^run-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}$/.test(runId)) throw new ApiError("Run identifier is invalid.", "invalid_run_id");
    const controller = new AbortController();
    const abort = () => controller.abort();
    signal.addEventListener("abort", abort, { once: true });
    if (signal.aborted) abort();
    const timeout = window.setTimeout(abort, 30_000);
    try {
      const response = await browserApiFetch(`${API_ROOT}/runs/${runId}/bundle`, {
        signal: controller.signal,
        headers: { Accept: "application/zip" },
      });
      if (!response.ok) {
        const payload = await response.json().catch(() => null);
        throw new ApiError(payload?.error?.message ?? `Export failed (${response.status})`, payload?.error?.code, undefined, response.status);
      }
      if (response.headers.get("Content-Type") !== "application/zip") throw new ApiError("The service returned an invalid bundle response.", "invalid_run_bundle");
      return await response.blob();
    } catch (error) {
      if (controller.signal.aborted) throw new ApiError("Bundle download was cancelled or exceeded 30 seconds. Try again.", "request_aborted");
      throw error;
    } finally {
      window.clearTimeout(timeout);
      signal.removeEventListener("abort", abort);
    }
  },
  async renameRun(runId: string, displayName: string | null): Promise<RunPresentation> {
    if (DEMO_MODE) throw new ApiError("Renaming runs requires the local service.", "demo_only");
    const result = await request<unknown>(`/runs/${encodeURIComponent(runId)}/presentation`, {
      method: "POST", body: JSON.stringify({ display_name: displayName }),
    });
    if (!isRunPresentation(result, runId) || result.display_name !== (displayName === null ? null : displayName.trim())) {
      throw new ApiError("The saved run name could not be confirmed. Refresh this run before trying again.", "run_name_unconfirmed");
    }
    return result;
  },
  async retainedRunDetail(runId: string): Promise<RetainedRunRecord> {
    if (DEMO_MODE) throw new ApiError("Retained observations require the local service.", "demo_only");
    const response = await request<unknown>(`/runs/${encodeURIComponent(runId)}/retained-observations`);
    const observations = retainedObservations(response, runId);
    if (!observations) throw new ApiError("The retained record is invalid or does not match this run.", "invalid_retained_run");
    return structuredClone(observations);
  },
  async runDetail(runId: string): Promise<RunRecord> {
    if (DEMO_MODE) {
      const run = demoRuns.find((item) => item.run_id === runId);
      if (!run) throw new ApiError("Demo run was not found.", "run_not_found", undefined, 404);
      return structuredClone(run);
    }
    const run = await request<unknown>(`/runs/${encodeURIComponent(runId)}`);
    if (!isFinalizedRunRecord(run)) throw new ApiError("Run is not available as a finalized canonical record.", "run_not_finalized", undefined, 409);
    return run;
  },
  async validate(scenario: Scenario): Promise<{ valid: boolean; issues: unknown[] }> {
    if (DEMO_MODE) return { valid: scenario.steps.length > 0 && scenario.steps.some((step) => step.id === scenario.start), issues: [] };
    return request("/scenarios/validate", { method: "POST", body: JSON.stringify(graphDocument(scenario)) });
  },
  async preflight(scenario: Scenario, config: RunConfiguration): Promise<PreflightReport> {
    if (DEMO_MODE) {
      if (config.mode === "execute") return { ready: false, status: "demo_only", runner_profile: config.profileId || null, scope: { scope_refs: config.scopeRefs }, capabilities: [], safety_tier: config.safetyTier, approval: config.approved ? "previewed" : "required", cleanup: { policy: config.cleanupPolicy }, findings: ["Demo mode previews Execute configuration but never dispatches runner effects."] };
      return { ready: true, status: "ready", runner_profile: config.profileId || "sandbox-simulate.v1", scope: { scope_refs: config.scopeRefs }, capabilities: [...new Set(demoCatalog.behaviors.flatMap((item) => item.capabilities))], safety_tier: config.safetyTier, approval: "not_required", cleanup: { policy: config.cleanupPolicy }, findings: ["Seeded Simulate preflight. No external effects will occur."] };
    }
    return request("/runs/preflight", { method: "POST", body: JSON.stringify(buildRunPayload(scenario, config)) });
  },
  async submitRun(scenario: Scenario, config: RunConfiguration): Promise<RunJobSubmission> {
    if (DEMO_MODE) {
      if (config.mode === "execute") throw new ApiError("Demo mode cannot dispatch Execute actions.", "demo_execute_refused", undefined, 409);
      const run = structuredClone(demoRuns[0]!);
      const job: RunJob = { schema_version: "bluefire.job.v1", job_id: `job-demo-${Date.now()}`, kind: "scenario.run", state: "completed", request: {}, progress: { phase: "completed", run_id: run.run_id, completed_steps: run.steps.length }, result_ref: run.run_id, created_at: new Date().toISOString(), updated_at: new Date().toISOString(), is_demo: true };
      demoJobs.set(job.job_id, job);
      return { schema_version: "bluefire.run-job-submission.v1", job, approval_request: null, preflight: null };
    }
    return request("/runs", { method: "POST", body: JSON.stringify(buildRunPayload(scenario, config)) });
  },
  async job(jobId: string): Promise<RunJob> {
    if (DEMO_MODE) {
      const job = demoJobs.get(jobId);
      if (!job) throw new ApiError("Demo job was not found.", "job_not_found", undefined, 404);
      return structuredClone(job);
    }
    return request(`/jobs/${encodeURIComponent(jobId)}`);
  },
  async activeJobs(): Promise<ActiveJobList> {
    if (DEMO_MODE) return { schema_version: "bluefire.active-job-list.v1", jobs: [] };
    return request("/jobs");
  },
  async preflightStoredJobRequest(job: RunJob, options: { forDisplayOnly?: boolean } = {}): Promise<PreflightReport> {
    if (DEMO_MODE) throw new ApiError("Demo jobs do not have restorable Execute approval envelopes.", "demo_execute_refused", undefined, 409);
    if (!["scenario.run", "scenario.replay"].includes(job.kind) || job.state !== "awaiting_approval" || !job.request || Array.isArray(job.request)) {
      throw new ApiError("The durable job does not have a restorable approval review.", "job_preflight_unavailable", undefined, 409);
    }
    if (!options.forDisplayOnly && !(approvalDeadline(job.approval_request?.expires_at) > Date.now())) {
      throw new ApiError("The approval deadline is unavailable or expired. This review can only be displayed; obtain a fresh review before release.", "job_preflight_unavailable", undefined, 409);
    }
    if (job.kind === "scenario.replay") {
      const prepared = job.request.replay_preparation as ReplayPreparation | undefined;
      if (prepared?.schema_version !== "bluefire.replay-preparation.v1" || prepared.binding?.source?.run_id !== job.request.source_run_id || !sameJson(prepared.replay_request, job.request.replay_request) || !sameJson(prepared.binding?.replay_request, job.request.replay_request) || !prepared.preflight?.plan || !prepared.preflight.approval_binding || !prepared.preflight.approval_envelope
        || !hasAdaptiveApprovalReview(prepared.preflight, requiresAdaptiveReview(job)))
        throw new ApiError("The replay's exact saved review is unavailable.", "job_preflight_unavailable", undefined, 409);
      // This is the original review, not a newly compiled plan. Approval itself
      // revalidates the bound source, configuration and live runner readiness.
      return structuredClone(prepared.preflight);
    }
    if (["_run_submission_preflight", "_run_submission_request", "_submission", "receiver_defense", "assistance_run"].some((key) => Object.hasOwn(job.request!, key))) {
      const report = storedRunApprovalPreflight(job, options);
      if (!report) throw new ApiError("The run's exact saved review is unavailable or does not match its pending approval. Keep this job open to inspect or cancel it.", "job_preflight_unavailable", undefined, 409);
      // Native receiver authority is deliberately unavailable to a posted public
      // preflight request. Restore its original review; approveJob revalidates the
      // owned receiver, live readiness and all five immutable binding fields.
      return structuredClone(report);
    }
    return request("/runs/preflight", { method: "POST", body: JSON.stringify(job.request) });
  },
  async runEvents(runId: string, afterSequence = 0, limit = 250): Promise<RunEventPage> {
    if (DEMO_MODE) {
      const run = demoRuns.find((item) => item.run_id === runId);
      if (!run) throw new ApiError("Demo run was not found.", "run_not_found", undefined, 404);
      const events = (run.events ?? []).map((event, index) => ({ ...(event as Record<string, unknown>), sequence: Number((event as Record<string, unknown>).sequence ?? index + 1) })).filter((event) => event.sequence > afterSequence).slice(0, limit);
      return { schema_version: "bluefire.event-page.v1", run_id: runId, after_sequence: afterSequence, next_sequence: events.at(-1)?.sequence ?? afterSequence, has_more: false, items: events };
    }
    return request(`/runs/${encodeURIComponent(runId)}/events?after_sequence=${afterSequence}&limit=${limit}`);
  },
  async approveJob(jobId: string, approvedBy: string): Promise<JobApprovalResult> {
    if (DEMO_MODE) throw new ApiError("Demo mode cannot approve an Execute job.", "demo_execute_refused", undefined, 409);
    return request(`/jobs/${encodeURIComponent(jobId)}/approval`, { method: "POST", body: JSON.stringify({ approved_by: approvedBy }) });
  },
  async retryJob(jobId: string): Promise<JobRetryResult> {
    if (DEMO_MODE) throw new ApiError("Demo jobs are immutable fixtures and cannot be retried.", "demo_retry_refused", undefined, 409);
    return request(`/jobs/${encodeURIComponent(jobId)}/retry`, { method: "POST", body: JSON.stringify({}) });
  },
  async proposalReviews(jobId: string): Promise<AIProposalReviewList> {
    if (DEMO_MODE) return { schema_version: "bluefire.ai-proposal-review-list.v1", job_id: jobId, proposals: [] };
    return request(`/jobs/${encodeURIComponent(jobId)}/proposals`);
  },
  async proposalReview(jobId: string, proposalRecordId: string): Promise<AIProposalReview> {
    if (DEMO_MODE) throw new ApiError("Demo mode has no durable proposal review.", "proposal_not_found", undefined, 404);
    return request(`/jobs/${encodeURIComponent(jobId)}/proposals/${encodeURIComponent(proposalRecordId)}`);
  },
  async decideProposal(jobId: string, review: AIProposalReview, decidedBy: string, decision: "accept" | "reject"): Promise<AIProposalDecisionResult> {
    if (DEMO_MODE) throw new ApiError("Demo mode cannot decide a proposal.", "demo_proposal_refused", undefined, 409);
    return request(`/jobs/${encodeURIComponent(jobId)}/proposals/${encodeURIComponent(review.proposal_record_id)}/${decision}`, { method: "POST", body: JSON.stringify({ decided_by: decidedBy, state_digest: review.state_digest, plan_digest: review.plan_digest, proposal_digest: review.proposal_digest }) });
  },
  async controlJob(jobId: string, action: "pause" | "resume" | "cancel"): Promise<RunJob> {
    if (DEMO_MODE) {
      const job = demoJobs.get(jobId);
      if (!job) throw new ApiError("Demo job was not found.", "job_not_found", undefined, 404);
      return structuredClone(job);
    }
    return request(`/jobs/${encodeURIComponent(jobId)}/${action}`, { method: "POST", body: JSON.stringify({}) });
  },
  async prepareReplay(runId: string, body: Record<string, unknown>): Promise<ReplayPreparation> {
    if (DEMO_MODE) throw new ApiError("Execute replay preparation requires a connected BlueFire service.", "demo_no_execution");
    return request(`/runs/${encodeURIComponent(runId)}/replay-preparations`, { method: "POST", body: JSON.stringify(body) });
  },
  async submitReplay(runId: string, preparation: ReplayPreparation, submissionId: string): Promise<ReplayJobSubmission> {
    return request(`/runs/${encodeURIComponent(runId)}/replay-jobs`, { method: "POST", body: JSON.stringify({
      ...replaySubmittedRequest(preparation), submission_id: submissionId,
    }) });
  },
  async resolveReplaySubmission(runId: string, preparation: ReplayPreparation, submissionId: string): Promise<ReplaySubmissionResolution> {
    return request(`/runs/${encodeURIComponent(runId)}/replay-submission-resolution`, { method: "POST", body: JSON.stringify({
      ...replaySubmittedRequest(preparation), submission_id: submissionId,
    }) });
  },
  async replay(runId: string, body: Record<string, unknown>): Promise<RunRecord> {
    if (DEMO_MODE) return { ...structuredClone(demoRuns[0]!), run_id: `demo-replay-${Date.now()}`, replay: { source_run_id: runId, ...body }, is_demo: true };
    // The endpoint returns only after the configured Execute budget, bounded
    // readiness/control work, persistence, and indexing complete.
    return request(`/runs/${encodeURIComponent(runId)}/replays`, { method: "POST", body: JSON.stringify(body) }, SYNCHRONOUS_REPLAY_TIMEOUT_MS);
  },
  async compare(runIds: string[]): Promise<ComparisonResponse> {
    if (DEMO_MODE) return compareDemoRuns(runIds);
    return request("/comparisons", { method: "POST", body: JSON.stringify({ run_ids: runIds }) });
  },
  async comparisonSnapshots(): Promise<{ snapshots: SavedComparisonSummary[] }> {
    if (DEMO_MODE) return { snapshots: [] };
    return request("/comparison-snapshots");
  },
  async comparisonSnapshot(snapshotId: string): Promise<SavedComparisonSnapshot> {
    if (DEMO_MODE) throw new ApiError("Demo mode has no saved comparison snapshots.", "comparison_snapshot_not_found", undefined, 404);
    return request(`/comparison-snapshots/${encodeURIComponent(snapshotId)}`);
  },
  async methodComparisonContext(runId: string): Promise<MethodContext> {
    if (DEMO_MODE) throw new ApiError("Use a connected run with independent observations to compare methods.", "demo_method_comparison_refused", undefined, 409);
    return request(`/runs/${encodeURIComponent(runId)}/method-comparison-context`);
  },
  async suggestMethodComparison(runId: string, body: MethodRequest): Promise<{ job: RunJob }> {
    if (DEMO_MODE) throw new ApiError("Method assistance requires the connected local service.", "demo_method_comparison_refused", undefined, 409);
    return request(`/runs/${encodeURIComponent(runId)}/ai-method-comparison-jobs`, { method: "POST", body: JSON.stringify(body) });
  },
  async decideMethodComparison(jobId: string, body: MethodDecision): Promise<{ proposal_job: RunJob; replay_job: RunJob | null; decision: MethodDecision }> {
    if (DEMO_MODE) throw new ApiError("Demo mode cannot accept a method comparison.", "demo_method_comparison_refused", undefined, 409);
    return request(`/jobs/${encodeURIComponent(jobId)}/method-comparison-decisions`, { method: "POST", body: JSON.stringify(body) });
  },
  async savedComparison(comparisonId: string): Promise<{ resource: { id: string; digest: string; document: ComparisonResponse } }> {
    if (DEMO_MODE) throw new ApiError("Demo mode has no saved comparison receipts.", "demo_method_comparison_refused", undefined, 409);
    return request(`/resources/comparisons/${encodeURIComponent(comparisonId)}`);
  },
};

function demoRuntimeResource(kind: "runner-profiles" | "model-providers" | "plugins", id: string, status: "active" | "inactive"): RuntimeResourceResult {
  const key = `${kind}:${id}`;
  const current = demoResources.get(key);
  if (!current) throw new ApiError("Demo resource was not found.", "resource_not_found", undefined, 404);
  if (kind === "plugins" && status === "active") {
    const digest = (current.document.integrity as Record<string, unknown> | undefined)?.digest;
    if (current.document.enabled !== true || !["reviewed", "trusted"].includes(String(current.document.trust)) || typeof digest !== "string" || digest === "0".repeat(64)) {
      throw new ApiError("The demo manifest is not eligible for metadata-only activation.", "plugin_activation_refused", undefined, 409);
    }
  }
  const resource = { ...current, status, updated_at: new Date().toISOString() };
  demoResources.set(key, resource);
  const inventory = kind === "plugins" ? { schema_version: "bluefire.plugin-inventory.v1", lifecycle: "declarative-manifest-only", manifest_count: [...demoResources.values()].filter((item) => item.kind === "plugins").length, active_manifest_ids: [...demoResources.values()].filter((item) => item.kind === "plugins" && item.status === "active").map((item) => item.id), health: { state: "ready", message: "Sanitized demo metadata inventory." }, executable_loading: false as const, dynamic_actions: false as const, python_entry_points: false as const } : undefined;
  return { schema_version: kind === "plugins" ? "bluefire.plugin-activation.v1" : "bluefire.resource-activation.v1", resource, inventory, registration: kind === "plugins" ? "metadata_only" : undefined, executable_loading: kind === "plugins" ? false : undefined, dynamic_actions: kind === "plugins" ? false : undefined };
}
