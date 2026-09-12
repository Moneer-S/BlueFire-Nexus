import { EvidenceRecords } from "./EvidenceRecords";
import { RunnerInventoryRecovery } from "./ExecuteRunnerReadiness";
import { RunNameControl, CopyRunId } from "../components/RunNameControl";
import { assistanceRunLink } from "../lib/run-assistance";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Activity, AlertTriangle, CircleStop, Clock3, FileSearch, Gauge, ListTree, Pause, Play, RotateCcw, ShieldCheck, Sparkles, TerminalSquare } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useLocation, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { api, ApiError, DEMO_MODE, type ReplayPreparation } from "../lib/api";
import { comparisonLink, detectionLink } from "../lib/run-handoffs";
import { methodComparisonLink } from "../lib/method-comparison";
import { receiverControlLink } from "../lib/receiver-navigation";
import { configurationForMode, hasExecutePlanReview } from "../lib/run-configuration";
import { RunConfigurationPanel } from "../components/RunConfiguration";
import { ExecuteOnboarding, GUIDED_EXECUTE_PROFILE_ID, GUIDED_EXECUTE_SCENARIO_ID, guidedExecuteConfiguration, isExecuteRunnerReady } from "../components/ExecuteOnboarding";
import { ProposalReviewWorkspace } from "../components/ProposalReview";
import { useProduct } from "../state/ProductContext";
import { useApprovalDeadline } from "../state/useApprovalDeadline";
import type { AIProposalDecisionResult, AIProposalReview, CatalogResponse, PreflightReport, RunConfiguration, RunEventPage, RunJob, RunRecord, RunStep, Scenario } from "../types";
import { Badge, Button, Callout, DataList, ErrorState, Field, LoadingState, PageHeader, Panel, PanelHeader, formatDate, sentence } from "../components/Primitives";

import { CanonicalPlanReview } from "../components/CanonicalPlanReview";
import { AdaptiveDecision, AdaptiveRunPath } from "./AdaptiveRunPath";
import { continuationApprovalPreflight, hasAdaptiveApprovalReview, hasUsableStoredApprovalReview, requiresAdaptiveReview } from "../lib/approvalReview";
import { hasReplayExtent, settlePendingReplay } from "../lib/replay-submission";

import { cleanupSummary, recordedTargetScope, objectiveLabel, runLabel, runLimitationGroups, stepOutcomeLabel } from "../lib/run-presentation";

import { RunExports } from "../components/RunExports";
import { recordedStepLabels, runEventPresentation } from "../lib/run-progress-presentation";

import "../pages/Runs.css";
import { sameJson } from "../lib/replay-review";

const terminalJobStates = new Set<RunJob["state"]>(["cancelled", "completed", "failed", "interrupted"]);
const approvalBindingFields = ["state_digest", "plan_digest", "target_scope_digest", "profile_id", "maximum_tier"] as const;
const activeJobStorageKey = "bluefire.local.active-job-id.v1";
const activeJobInventoryUnavailableNotice = "Active-job inventory is unavailable. New preflight and submission remain disabled until it is restored.";
const durableJobId = /^job-[0-9a-f]{32}$/;

function isMissingJobError(error: unknown): boolean {
  return error instanceof ApiError && error.status === 404 && error.code === "job_not_found";
}

function isRetryableInterruptedJob(job: RunJob | null | undefined): boolean {
  return job?.schema_version === "bluefire.job.v1" && ["scenario.run", "scenario.replay"].includes(job.kind) && job.state === "interrupted" && !job.request?.method_comparison && !job.request?.assistance_run && !job.request?.receiver_defense;
}

function readStoredActiveJobId(): string | null {
  try {
    const jobId = window.localStorage.getItem(activeJobStorageKey);
    if (jobId === null || durableJobId.test(jobId)) return jobId;
    window.localStorage.removeItem(activeJobStorageKey);
  } catch {
    // Active-job restoration is best-effort when browser storage is unavailable.
  }
  return null;
}

function storeActiveJobId(jobId: string): void {
  try {
    window.localStorage.setItem(activeJobStorageKey, jobId);
  } catch {
    // The live in-memory job remains controllable for this mount.
  }
}

function clearStoredActiveJobId(jobId: string): void {
  try {
    if (window.localStorage.getItem(activeJobStorageKey) === jobId) window.localStorage.removeItem(activeJobStorageKey);
  } catch {
    // Storage denial must not interfere with terminal-state handling.
  }
}



function preferNewerJobSnapshot(current: RunJob | undefined, candidate: RunJob): RunJob {
  if (!current || current.job_id !== candidate.job_id) return candidate;
  const currentWithApproval = current.approval_request === undefined && candidate.approval_request !== undefined ? { ...current, approval_request: candidate.approval_request } : current;
  const candidateWithApproval = candidate.approval_request === undefined && current.approval_request !== undefined ? { ...candidate, approval_request: current.approval_request } : candidate;
  const currentTerminal = terminalJobStates.has(current.state);
  const candidateTerminal = terminalJobStates.has(candidate.state);
  if (currentTerminal !== candidateTerminal) return currentTerminal ? currentWithApproval : candidateWithApproval;
  const currentUpdatedAt = Date.parse(current.updated_at ?? "");
  const candidateUpdatedAt = Date.parse(candidate.updated_at ?? "");
  if (Number.isFinite(currentUpdatedAt) && !Number.isFinite(candidateUpdatedAt)) return currentWithApproval;
  if (Number.isFinite(currentUpdatedAt) && Number.isFinite(candidateUpdatedAt)) {
    if (candidateUpdatedAt < currentUpdatedAt) return currentWithApproval;
    if (candidateUpdatedAt === currentUpdatedAt) {
      const canonicalUtc = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?Z$/;
      const currentParts = canonicalUtc.exec(current.updated_at ?? "");
      const candidateParts = canonicalUtc.exec(candidate.updated_at ?? "");
      const currentKey = currentParts ? `${currentParts[1]}.${(currentParts[2] ?? "").padEnd(9, "0")}Z` : undefined;
      const candidateKey = candidateParts ? `${candidateParts[1]}.${(candidateParts[2] ?? "").padEnd(9, "0")}Z` : undefined;
      if (currentKey && candidateKey && candidateKey < currentKey) return currentWithApproval;
    }
  }
  return candidateWithApproval;
}

interface RunPreflightAttempt {
  generation: number;
  scenario: Scenario;
  config: RunConfiguration;
}

export function RunWorkspace({ embedded }: { embedded?: { job: RunJob; releaseEnabled: boolean; controlsEnabled?: boolean; onCancelRequested?: () => void } } = {}) {
  // Inline instances are keyed by the exact phase job. They never adopt another job.
  const [initialBinding] = useState(() => embedded ? structuredClone(embedded.job) : undefined);
  const inlineBinding = useRef(initialBinding);
  const isEmbedded = Boolean(embedded);
  const matchesSelection = useCallback((job: RunJob) => !inlineBinding.current || (job.schema_version === "bluefire.job.v1" && job.job_id === inlineBinding.current.job_id && job.kind === inlineBinding.current.kind && sameJson(job.request, inlineBinding.current.request)), []);
  const persistSelection = useCallback((jobId: string) => { if (!inlineBinding.current) storeActiveJobId(jobId); }, []);
  const clearSelection = useCallback((jobId: string) => { if (!inlineBinding.current) clearStoredActiveJobId(jobId); }, []);
  const { runId: routeRunId } = useParams<{ runId?: string }>();
  const runId = isEmbedded ? undefined : routeRunId;
  const location = useLocation();
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const requestedJob = embedded?.job.job_id ?? searchParams.get("job");
  const linkedJobId = requestedJob && durableJobId.test(requestedJob) ? requestedJob : null;
  const catalog = useQuery({ queryKey: ["catalog"], queryFn: api.catalog, enabled: !isEmbedded });
  const runsQuery = useQuery({ queryKey: ["runs"], queryFn: api.runs, enabled: !isEmbedded });
  const scenariosQuery = useQuery({ queryKey: ["scenarios"], queryFn: api.scenarios, enabled: !isEmbedded });
  const historicalRunQuery = useQuery({ queryKey: ["run", runId], queryFn: () => api.runDetail(runId!), enabled: Boolean(runId) });
  const product = useProduct();
  const { scenario, setScenario, dirty, runConfig, setRunConfig } = product;
  const selectedProfile = catalog.data?.runner_profiles.find((profile) => profile.id === runConfig.profileId);
  const runnerProfileId = selectedProfile?.id;
  const runnerSelection = useMemo(() => ({ profileId: runnerProfileId }), [runnerProfileId]);
  const runnerSelectionRef = useRef<typeof runnerSelection | null>(runnerSelection);
  runnerSelectionRef.current = runnerSelection;
  useEffect(() => () => { runnerSelectionRef.current = null; }, []);
  const runnerLifecycleQuery = useQuery({ queryKey: ["runner-lifecycle", runnerProfileId ?? null], queryFn: () => api.runnerStatus(runnerProfileId), enabled: !isEmbedded && Boolean(runnerProfileId), retry: false });
  const selectedRunner = !runnerLifecycleQuery.error && runnerProfileId && (runnerLifecycleQuery.data?.profile_id === runnerProfileId || (runnerLifecycleQuery.data?.profile_id === null && runnerLifecycleQuery.data.state === "unbootstrapped")) ? runnerLifecycleQuery.data : undefined;

  const [inlineRun, setInlineRun] = useState<RunRecord | null>(null);
  const activeRun = isEmbedded ? inlineRun : product.activeRun;
  const setActiveRun = isEmbedded ? setInlineRun : product.setActiveRun;
  const clearApproval = () => { if (!inlineBinding.current) product.clearApproval(); };
  const queryClient = useQueryClient();
  const [preflight, setPreflight] = useState<PreflightReport>(); const [notice, setNotice] = useState<string>();
  const [activeJob, setActiveJob] = useState<RunJob | null>(null); const [activeJobId, setActiveJobId] = useState<string | null>(() => linkedJobId ?? (isEmbedded ? null : readStoredActiveJobId())); const [jobPreflight, setJobPreflight] = useState<PreflightReport>(); const [approvalRequest, setApprovalRequest] = useState<Record<string, unknown> | null>(null);
  const [knownTerminalJobIds, setKnownTerminalJobIds] = useState<ReadonlySet<string>>(() => new Set(queryClient.getQueriesData<RunJob>({ queryKey: ["job"] }).flatMap(([, job]) => job && terminalJobStates.has(job.state) ? [job.job_id] : [])));
  const cancelRequests = useRef(new Set<string>());
  const [cancelRequestedIds, setCancelRequestedIds] = useState<ReadonlySet<string>>(new Set());
  const [activeProposalReview, setActiveProposalReview] = useState<AIProposalReview>();
  const [jobApprovalConfirmed, setJobApprovalConfirmed] = useState(false); const [jobApprovedBy, setJobApprovedBy] = useState("");
  const [liveEvents, setLiveEvents] = useState<RunEventPage["items"]>([]);
  const preflightGeneration = useRef(0);
  const missingInventoryReconciliation = useRef<string | null>(null);
  const activeJobIdRef = useRef(activeJobId);
  activeJobIdRef.current = activeJobId;
  const activeJobRef = useRef(activeJob);
  activeJobRef.current = activeJob;
  const displayedJobIdRef = useRef(activeJob?.job_id ?? null);
  displayedJobIdRef.current = activeJob?.job_id ?? null;
  const consumedSetupArrival = useRef<string | undefined>(undefined);
  const setupMode = isEmbedded ? null : searchParams.has("setup") ? searchParams.get("setup") : location.hash === "#guided-execute" ? "execute" : null;
  const hasJobLink = isEmbedded || searchParams.has("job");
  const [setupExpanded, setSetupExpanded] = useState(() => !linkedJobId && (searchParams.get("prepare") === "1" || setupMode !== null));
  useEffect(() => { if (!linkedJobId && (searchParams.get("prepare") === "1" || setupMode !== null)) setSetupExpanded(true); }, [linkedJobId, searchParams, setupMode]);
  useEffect(() => {
    // Internal selection already installed this exact job and its fresh review.
    if (!linkedJobId || displayedJobIdRef.current === linkedJobId) return;
    activeJobIdRef.current = linkedJobId; activeJobRef.current = null; displayedJobIdRef.current = null;
    setActiveJobId(linkedJobId); persistSelection(linkedJobId); setActiveJob(null);
    setJobPreflight(undefined); setApprovalRequest(null); setActiveProposalReview(undefined);
    setJobApprovalConfirmed(false); setJobApprovedBy(""); setLiveEvents([]); setActiveRun(null);
  }, [linkedJobId, persistSelection, setActiveRun]);
  const followJobUrl = useCallback((jobId: string) => {
    if (inlineBinding.current || runId || !searchParams.has("job") || searchParams.get("job") === jobId) return;
    setSearchParams((current) => { const next = new URLSearchParams(current); next.set("job", jobId); return next; }, { replace: true });
  }, [runId, searchParams, setSearchParams]);
  const activeJobsQuery = useQuery({ queryKey: ["active-jobs"], queryFn: api.activeJobs, refetchInterval: 750, staleTime: 0 });
  const inventoryAuthoritative = activeJobsQuery.isSuccess && activeJobsQuery.isFetchedAfterMount && Boolean(activeJobsQuery.data);
  const inventoryJobs = useMemo(() => inventoryAuthoritative ? activeJobsQuery.data!.jobs.filter(matchesSelection) : [], [activeJobsQuery.data, inventoryAuthoritative, matchesSelection]);
  const selectableInventoryJobs = useMemo(() => inventoryJobs.filter((job) => !terminalJobStates.has(job.state) && !knownTerminalJobIds.has(job.job_id)), [inventoryJobs, knownTerminalJobIds]);
  const inventoryUnavailable = !inventoryAuthoritative;
  const retryInventoryReady = !isEmbedded && inventoryAuthoritative && inventoryJobs.length === 0;
  const jobActivityBlocksNewIntent = isEmbedded || inventoryUnavailable || inventoryJobs.length > 0 || Boolean(activeJobId) || Boolean(activeJob && !terminalJobStates.has(activeJob.state));
  const alternateInventoryJobAvailable = selectableInventoryJobs.some((job) => job.job_id !== activeJobId);
  const rememberTerminalJob = useCallback((job: RunJob) => {
    if (terminalJobStates.has(job.state)) setKnownTerminalJobIds((current) => current.has(job.job_id) ? current : new Set(current).add(job.job_id));
  }, []);
  const trackActiveJob = useCallback((job: RunJob) => {
    displayedJobIdRef.current = job.job_id;
    activeJobRef.current = job;
    setActiveJob(job);
    followJobUrl(job.job_id);
    if (terminalJobStates.has(job.state)) {
      rememberTerminalJob(job);
      setActiveJobId((current) => { const next = current === job.job_id ? null : current; activeJobIdRef.current = next; return next; });
      if (isRetryableInterruptedJob(job)) persistSelection(job.job_id); else clearSelection(job.job_id);
    } else {
      activeJobIdRef.current = job.job_id;
      setActiveJobId(job.job_id);
      persistSelection(job.job_id);
    }
  }, [clearSelection, followJobUrl, persistSelection, rememberTerminalJob]);
  const selectInventoryJob = useCallback((job: RunJob) => {
    displayedJobIdRef.current = job.job_id;
    activeJobIdRef.current = job.job_id;
    activeJobRef.current = job;
    setActiveJobId(job.job_id);
    persistSelection(job.job_id);
    setActiveJob(job);
    followJobUrl(job.job_id);
    setJobPreflight(undefined);
    setApprovalRequest(null);
    setActiveProposalReview(undefined);
    setJobApprovalConfirmed(false);
    setJobApprovedBy("");
    setLiveEvents([]);
    setActiveRun(null);
  }, [followJobUrl, persistSelection, setActiveRun]);
  const synchronizeJobSnapshot = useCallback(async (job: RunJob): Promise<RunJob> => {
    if (!matchesSelection(job)) throw new ApiError("The job response does not match this phase’s immutable execution request.", "job_identity_mismatch", undefined, 502);
    await queryClient.cancelQueries({ queryKey: ["job", job.job_id], exact: true });
    let snapshot = preferNewerJobSnapshot(queryClient.getQueryData<RunJob>(["job", job.job_id]), job);
    if (activeJobRef.current?.job_id === job.job_id) snapshot = preferNewerJobSnapshot(activeJobRef.current, snapshot);
    if (!matchesSelection(snapshot)) throw new ApiError("The cached job no longer matches this phase’s immutable execution request.", "job_identity_mismatch", undefined, 502);
    rememberTerminalJob(snapshot);
    queryClient.setQueryData(["job", job.job_id], snapshot);
    void queryClient.invalidateQueries({ queryKey: ["job", job.job_id], exact: true });
    return snapshot;
  }, [matchesSelection, queryClient, rememberTerminalJob]);
  const jobQuery = useQuery({ queryKey: ["job", activeJobId], queryFn: async () => { const requestedJobId = activeJobId!; const receivedJob = await api.job(requestedJobId); if (receivedJob.job_id !== requestedJobId || !matchesSelection(receivedJob)) throw new ApiError("The job detail response did not match the requested job.", "job_identity_mismatch", undefined, 502); settlePendingReplay(receivedJob); let job = preferNewerJobSnapshot(queryClient.getQueryData<RunJob>(["job", requestedJobId]), receivedJob); if (activeJobRef.current?.job_id === requestedJobId) job = preferNewerJobSnapshot(activeJobRef.current, job); if (!matchesSelection(job)) throw new ApiError("The cached job no longer matches this phase’s immutable execution request.", "job_identity_mismatch", undefined, 502); rememberTerminalJob(job); return job; }, enabled: Boolean(activeJobId && (!activeJob || (activeJob.job_id === activeJobId && !terminalJobStates.has(activeJob.state)))), refetchInterval: (query) => {
    const state = (query.state.data as RunJob | undefined)?.state;
    if (state && terminalJobStates.has(state)) return false;
    // A definitive missing detail must not race the later React clearing effect.
    // Inventory continues polling; confirmed ownership can resume reconciliation.
    const inventoryOwnsJob = inventoryAuthoritative && inventoryJobs.some((job) => job.job_id === activeJobId);
    return isMissingJobError(query.state.error) && !inventoryOwnsJob ? false : 750;
  }, staleTime: 0 });
  const controllerOwnsActiveJob = Boolean(activeJob && matchesSelection(activeJob) && (!jobQuery.data || matchesSelection(jobQuery.data)) && inventoryAuthoritative && inventoryJobs.some((job) => job.job_id === activeJob.job_id));
  useEffect(() => {
    if (consumedSetupArrival.current === location.key || (setupMode !== "simulate" && setupMode !== "execute")) return;
    // A setup link never changes a selected durable job or historical review.
    // Confirmed jobs consume the arrival so later settlement cannot apply it.
    // A stored ID alone must wait: a definitive 404 can still restore this setup.
    const validatedStoredJob = activeJobId && jobQuery.isFetchedAfterMount && jobQuery.isSuccess && jobQuery.data?.job_id === activeJobId;
    if (runId || hasJobLink || activeJob || validatedStoredJob || selectableInventoryJobs.length) { consumedSetupArrival.current = location.key; return; }
    if (activeJobId || !catalog.data || !inventoryAuthoritative) return;
    consumedSetupArrival.current = location.key;
    const next = configurationForMode(runConfig, setupMode, catalog.data, scenario);
    if (next !== runConfig) {
      setRunConfig(next);
      preflightGeneration.current += 1;
      setPreflight(undefined);
    }
  }, [activeJob, activeJobId, catalog.data, hasJobLink, inventoryAuthoritative, jobQuery.data, jobQuery.isFetchedAfterMount, jobQuery.isSuccess, location.key, runConfig, runId, scenario, selectableInventoryJobs.length, setRunConfig, setupMode]);
  const refetchJob = jobQuery.refetch;
  const ordinaryApprovalNeedsPreflight = Boolean(controllerOwnsActiveJob && activeJob?.state === "awaiting_approval" && !["ai_proposal", "ai_proposal_execute"].includes(String(activeJob.progress.approval_kind ?? "")) && (!hasUsableStoredApprovalReview(jobPreflight) || !hasAdaptiveApprovalReview(jobPreflight, requiresAdaptiveReview(activeJob))));
  const storedJobPreflightQuery = useQuery({ queryKey: ["job-preflight", activeJob?.job_id, activeJob?.request?.approval_request_id], queryFn: async () => ({ jobId: activeJob!.job_id, report: await api.preflightStoredJobRequest(activeJob!, { forDisplayOnly: true }) }), enabled: ordinaryApprovalNeedsPreflight, staleTime: 0 });
  const unusableStoredJobPreflight = Boolean(storedJobPreflightQuery.isSuccess && storedJobPreflightQuery.data?.jobId === activeJob?.job_id && (!hasUsableStoredApprovalReview(storedJobPreflightQuery.data.report) || !hasAdaptiveApprovalReview(storedJobPreflightQuery.data.report, requiresAdaptiveReview(activeJob))));
  const liveRunId = typeof activeJob?.progress.run_id === "string" ? activeJob.progress.run_id : undefined;
  const eventCursor = liveEvents.reduce((maximum, event) => Math.max(maximum, Number(event.sequence) || 0), 0);
  const eventsQuery = useQuery({ queryKey: ["run-events", liveRunId, eventCursor, activeJob?.state], queryFn: () => api.runEvents(liveRunId!, eventCursor), enabled: Boolean(liveRunId), refetchInterval: activeJob && terminalJobStates.has(activeJob.state) ? false : 650 });
  const resultRunId = activeJob && terminalJobStates.has(activeJob.state) ? activeJob.result_ref : undefined;
  const resultQuery = useQuery({ queryKey: ["run", resultRunId], queryFn: () => api.runDetail(resultRunId!), enabled: Boolean(resultRunId && activeRun?.run_id !== resultRunId) });
  useEffect(() => {
    if (!inventoryAuthoritative || activeJobIdRef.current !== activeJobId) return;
    const candidates = selectableInventoryJobs;
    const selected = candidates.find((job) => job.job_id === activeJobId);
    if (selected) {
      missingInventoryReconciliation.current = null;
      if (activeJob?.job_id !== selected.job_id) selectInventoryJob(selected);
      return;
    }
    if (activeJobId && !activeJob) return;
    if (activeJobId && activeJob?.job_id === activeJobId && !terminalJobStates.has(activeJob.state)) {
      if (missingInventoryReconciliation.current !== activeJobId) {
        missingInventoryReconciliation.current = activeJobId;
        void refetchJob({ cancelRefetch: false });
      }
      return;
    }
    if (activeJob && terminalJobStates.has(activeJob.state)) return;
    if (inlineBinding.current) return;
    if (candidates[0]) {
      selectInventoryJob(candidates[0]);
      return;
    }
    if (!activeJobId) return;
    missingInventoryReconciliation.current = null;
    clearSelection(activeJobId);
    setActiveJobId(null);
    if (!activeJob || !terminalJobStates.has(activeJob.state)) {
      setActiveJob(null);
      setJobPreflight(undefined);
      setApprovalRequest(null);
      setActiveProposalReview(undefined);
      setJobApprovalConfirmed(false);
      setJobApprovedBy("");
      setLiveEvents([]);
    }
  }, [activeJob, activeJobId, clearSelection, inventoryAuthoritative, refetchJob, selectableInventoryJobs, selectInventoryJob]);
  useEffect(() => { if (activeJobsQuery.error) setNotice(activeJobInventoryUnavailableNotice); else if (inventoryAuthoritative) setNotice((current) => current === activeJobInventoryUnavailableNotice ? undefined : current); }, [activeJobsQuery.error, inventoryAuthoritative]);
  useEffect(() => {
    if (activeJobIdRef.current !== activeJobId || !jobQuery.isFetchedAfterMount || !jobQuery.isSuccess || !jobQuery.data || jobQuery.data.job_id !== activeJobId) return;
    const receivedJob = jobQuery.data;
    if (!matchesSelection(receivedJob)) { setNotice("The saved job response no longer matches this phase’s immutable execution request."); setJobPreflight(undefined); setApprovalRequest(null); setJobApprovalConfirmed(false); setJobApprovedBy(""); return; }
    const trackedJob = activeJobRef.current?.job_id === receivedJob.job_id ? activeJobRef.current : undefined;
    if (terminalJobStates.has(receivedJob.state)) {
      trackActiveJob(receivedJob);
      setNotice((current) => current === `Stored job ${receivedJob.job_id} is not present in the active controller inventory. Mutable controls remain disabled while ownership is reconciled.` ? undefined : current);
      if (receivedJob.approval_request !== undefined) setApprovalRequest(receivedJob.approval_request);
      return;
    }
    if (!inventoryAuthoritative) return;
    const inventoryJob = inventoryJobs.find((job) => job.job_id === receivedJob.job_id);
    if (!inventoryJob) {
      if (isRetryableInterruptedJob(receivedJob)) {
        trackActiveJob(receivedJob);
        if (receivedJob.approval_request !== undefined) setApprovalRequest(receivedJob.approval_request);
        return;
      }
      setNotice(`Stored job ${receivedJob.job_id} is not present in the active controller inventory. Mutable controls remain disabled while ownership is reconciled.`);
      return;
    }
    setNotice((current) => current === `Stored job ${receivedJob.job_id} is not present in the active controller inventory. Mutable controls remain disabled while ownership is reconciled.` ? undefined : current);
    let snapshot = preferNewerJobSnapshot(inventoryJob, receivedJob);
    if (trackedJob) snapshot = preferNewerJobSnapshot(trackedJob, snapshot);
    if (!matchesSelection(snapshot)) { setNotice("The merged job response no longer matches this phase’s immutable execution request."); setJobPreflight(undefined); setApprovalRequest(null); return; }
    trackActiveJob(snapshot);
    if (snapshot.approval_request !== undefined) setApprovalRequest(snapshot.approval_request);
  }, [activeJobId, linkedJobId, inventoryAuthoritative, inventoryJobs, jobQuery.data, jobQuery.isFetchedAfterMount, jobQuery.isSuccess, matchesSelection, rememberTerminalJob, trackActiveJob]);
  useEffect(() => { if (activeJobIdRef.current === activeJobId && jobQuery.isFetchedAfterMount && jobQuery.error) { const definitivelyMissing = isMissingJobError(jobQuery.error); const inventoryStillOwnsJob = Boolean(activeJobId && inventoryJobs.some((job) => job.job_id === activeJobId)); if (definitivelyMissing && activeJobId && inventoryAuthoritative && !inventoryStillOwnsJob) { clearSelection(activeJobId); setActiveJobId(null); if (activeJob?.job_id === activeJobId) setActiveJob(null); } setNotice(jobQuery.error instanceof Error ? jobQuery.error.message : "Job status could not be refreshed."); } }, [activeJob?.job_id, activeJobId, clearSelection, inventoryAuthoritative, inventoryJobs, jobQuery.error, jobQuery.isFetchedAfterMount]);
  useEffect(() => { if (storedJobPreflightQuery.isFetchedAfterMount && storedJobPreflightQuery.data && storedJobPreflightQuery.data.jobId === activeJob?.job_id) setJobPreflight(hasUsableStoredApprovalReview(storedJobPreflightQuery.data.report) && hasAdaptiveApprovalReview(storedJobPreflightQuery.data.report, requiresAdaptiveReview(activeJob)) ? storedJobPreflightQuery.data.report : undefined); }, [activeJob, storedJobPreflightQuery.data, storedJobPreflightQuery.isFetchedAfterMount]);
  useEffect(() => { if (storedJobPreflightQuery.isFetchedAfterMount && storedJobPreflightQuery.error) setNotice(storedJobPreflightQuery.error instanceof Error ? storedJobPreflightQuery.error.message : "The durable job approval review could not be restored."); }, [storedJobPreflightQuery.error, storedJobPreflightQuery.isFetchedAfterMount]);
  useEffect(() => { setLiveEvents([]); }, [activeJob?.job_id]);
  useEffect(() => { if (eventsQuery.data?.items.length) setLiveEvents((current) => { const merged = new Map(current.map((event) => [event.sequence, event])); for (const event of eventsQuery.data.items) merged.set(event.sequence, event); return [...merged.values()].sort((left, right) => left.sequence - right.sequence); }); }, [eventsQuery.data]);
  useEffect(() => { if (eventsQuery.error) setNotice(eventsQuery.error instanceof Error ? eventsQuery.error.message : "Live event polling failed."); }, [eventsQuery.error]);
  useEffect(() => { if (resultQuery.data && resultQuery.data.run_id === resultRunId && activeJobRef.current?.result_ref === resultRunId) { setActiveRun(resultQuery.data); setNotice(`Run ${sentence(resultQuery.data.status).toLowerCase()}; its recorded result is ready for review.`); queryClient.invalidateQueries({ queryKey: ["runs"] }); } }, [queryClient, resultQuery.data, resultRunId, setActiveRun]);
  useEffect(() => { setJobApprovalConfirmed(false); setJobApprovedBy(""); }, [activeJob?.job_id, activeJob?.progress.approval_kind, activeJob?.progress.approval_request_id, activeJob?.request?.approval_request_id, approvalRequest?.approval_id, approvalRequest?.status, approvalRequest?.state_digest, approvalRequest?.plan_digest, approvalRequest?.target_scope_digest, approvalRequest?.profile_id, approvalRequest?.maximum_tier]);
  useEffect(() => { setJobApprovalConfirmed(false); setJobApprovedBy(""); }, [activeProposalReview?.execute_approval_review?.approval_request_id, activeProposalReview?.execute_approval_review?.preflight.approval_envelope?.envelope_digest]);
  const preflightMutation = useMutation({ mutationFn: async (attempt: RunPreflightAttempt) => ({ generation: attempt.generation, report: await api.preflight(attempt.scenario, attempt.config) }), onSuccess: ({ generation, report }, attempt) => { if (generation !== preflightGeneration.current) return; setPreflight(report); setNotice(attempt.config.mode === "execute" && !hasExecutePlanReview(report, attempt.scenario) ? "The service has not returned a complete, usable Execute plan. Review the findings and check the plan again." : report.ready ? "Preflight resolved the current policy envelope." : report.status === "approval_required" && report.approval_binding && report.approval_envelope ? "Preflight resolved the exact Execute envelope. Review it before creating an approval-gated job." : "Preflight did not authorize this intent."); }, onError: (error, attempt) => { if (attempt.generation !== preflightGeneration.current) return; setPreflight(undefined); setNotice(error instanceof Error ? error.message : "Preflight failed."); }, onSettled: (_result, _error, attempt) => { if (attempt.generation === preflightGeneration.current) clearApproval(); } });
  const requestPreflight = () => { if (jobActivityBlocksNewIntent) { setNotice("Active-job inventory must be available and empty before starting another preflight."); return; } const generation = ++preflightGeneration.current; preflightMutation.mutate({ generation, scenario: structuredClone(scenario), config: structuredClone(runConfig) }); };
  const invalidatePreflight = () => { preflightGeneration.current += 1; setPreflight(undefined); };
  const runMutation = useMutation({ mutationFn: () => api.submitRun(scenario, runConfig), onMutate: () => { setNotice(runConfig.mode === "simulate" ? "Submitting a durable Simulate job." : "Creating a durable Execute job with a separate approval gate."); setActiveRun(null); }, onSuccess: async (submission) => { const snapshot = await synchronizeJobSnapshot({ ...submission.job, approval_request: submission.approval_request ?? submission.job.approval_request }); trackActiveJob(snapshot); setJobPreflight(submission.preflight ?? undefined); setApprovalRequest(snapshot.approval_request ?? null); setNotice(`Job ${snapshot.job_id} was accepted in ${sentence(snapshot.state)} state.`); void queryClient.invalidateQueries({ queryKey: ["active-jobs"] }); void queryClient.invalidateQueries({ queryKey: ["runs"] }); }, onError: (error) => setNotice(error instanceof Error ? error.message : "Job submission was refused."), onSettled: clearApproval });
  const approvalMutation = useMutation({ mutationFn: ({ jobId, approvedBy }: { jobId: string; approvedBy: string }) => api.approveJob(jobId, approvedBy), onSuccess: async (result, variables) => { const snapshot = await synchronizeJobSnapshot({ ...result.job, approval_request: result.approval_request ?? result.job.approval_request }); void queryClient.invalidateQueries({ queryKey: ["active-jobs"] }); if (activeJobIdRef.current !== variables.jobId || snapshot.job_id !== variables.jobId) return; trackActiveJob(snapshot); setApprovalRequest(snapshot.approval_request ?? null); setNotice(`The exact envelope for ${snapshot.job_id} was approved once and released to the job controller.`); }, onError: (error, variables) => { if (activeJobIdRef.current === variables.jobId) setNotice(error instanceof Error ? error.message : "Job approval was refused."); }, onSettled: (_result, _error, variables) => { if (activeJobIdRef.current !== variables.jobId) return; setJobApprovalConfirmed(false); setJobApprovedBy(""); clearApproval(); } });
  const runnerLifecycleMutation = useMutation({
    mutationFn: async ({ action, selection }: { action: "bootstrap" | "start"; selection: typeof runnerSelection }) => {
      if (!selection.profileId || DEMO_MODE) throw new Error("Choose an installed runner profile first.");
      const status = await (action === "bootstrap" ? api.bootstrapRunner(selection.profileId) : api.startRunner(selection.profileId));
      if (status.profile_id !== selection.profileId) throw new Error("Runner setup returned a different profile. Check the selected profile in runner diagnostics.");
      return status;
    },
    onSuccess: (status, { selection }) => {
      queryClient.setQueryData(["runner-lifecycle", selection.profileId], status);
      if (runnerSelectionRef.current !== selection) return;
      setNotice(isExecuteRunnerReady(status) ? "The runner for the selected profile is authenticated and ready for preflight." : "The selected profile's packaged runner and local trust are verified. Start the authenticated host next.");
    },
    onError: (error, { selection }) => { if (runnerSelectionRef.current === selection) setNotice(error instanceof Error ? error.message : "Runner setup for the selected profile was refused."); },
  });
  const controlMutation = useMutation({ onMutate: ({ jobId, action }: { jobId: string; action: "pause" | "resume" | "cancel" }) => { if (action === "cancel") { cancelRequests.current.add(jobId); setCancelRequestedIds(new Set(cancelRequests.current)); setJobApprovalConfirmed(false); setJobApprovedBy(""); embedded?.onCancelRequested?.(); } }, mutationFn: ({ jobId, action }: { jobId: string; action: "pause" | "resume" | "cancel" }) => api.controlJob(jobId, action), onSuccess: async (job, variables) => { const snapshot = await synchronizeJobSnapshot(job); void queryClient.invalidateQueries({ queryKey: ["active-jobs"] }); if (activeJobIdRef.current !== variables.jobId || snapshot.job_id !== variables.jobId) return; trackActiveJob(snapshot); setNotice(`${sentence(variables.action)} was requested for ${snapshot.job_id}; the durable state is ${sentence(snapshot.state)}.`); }, onError: (error, variables) => { if (activeJobIdRef.current === variables.jobId) setNotice(error instanceof Error ? error.message : "Job control request was refused."); } });
  const retryMutation = useMutation({ mutationFn: (jobId: string) => api.retryJob(jobId), onSuccess: async (result, sourceJobId) => { const snapshot = await synchronizeJobSnapshot({ ...result.job, approval_request: result.approval_request ?? result.job.approval_request }); void queryClient.invalidateQueries({ queryKey: ["active-jobs"] }); if (displayedJobIdRef.current !== sourceJobId || result.retry_of_job_id !== sourceJobId) return; clearSelection(sourceJobId); setJobApprovalConfirmed(false); setJobApprovedBy(""); trackActiveJob(snapshot); setJobPreflight(result.preflight ?? undefined); setApprovalRequest(snapshot.approval_request ?? null); setActiveProposalReview(undefined); setNotice(`Replacement job ${snapshot.job_id} was created from interrupted job ${result.retry_of_job_id}. The source remains immutable.`); }, onError: (error, sourceJobId) => { if (displayedJobIdRef.current === sourceJobId) setNotice(error instanceof Error ? error.message : "The interrupted job could not be retried safely."); } });
  const handleProposalDecision = (result: AIProposalDecisionResult, review: AIProposalReview) => { void synchronizeJobSnapshot({ ...result.job, approval_request: result.approval_request ?? result.job.approval_request }).then((snapshot) => { void queryClient.invalidateQueries({ queryKey: ["active-jobs"] }); if (activeJobIdRef.current !== snapshot.job_id) return; trackActiveJob(snapshot); setActiveProposalReview(review); setApprovalRequest(snapshot.approval_request ?? null); if (snapshot.progress.approval_kind === "ai_proposal_execute") setJobPreflight(undefined); setNotice(snapshot.progress.approval_kind === "ai_proposal_execute" ? "The registered proposal was accepted. Execute remains stopped at a new, separately bound one-time approval stage." : `The proposal was ${review.status}; durable job state is ${sentence(snapshot.state)}.`); }); };
  const liveWorkspace = <LiveConsole catalog={catalog.data} run={activeRun} job={activeJob} events={liveEvents} pending={runMutation.isPending || Boolean(resultRunId && resultQuery.isPending) || Boolean(activeJob && !terminalJobStates.has(activeJob.state))} approvalPreflight={jobPreflight} approvalRequest={approvalRequest} proposalReview={activeProposalReview} approvalConfirmed={jobApprovalConfirmed} approvedBy={jobApprovedBy} approvalPending={approvalMutation.isPending} releaseEnabled={!cancelRequestedIds.has(activeJob?.job_id ?? "") && !controlMutation.isPending && (!embedded || embedded.releaseEnabled)} controlActionsEnabled={!cancelRequestedIds.has(activeJob?.job_id ?? "") && (!embedded || embedded.controlsEnabled !== false)} controlPending={controlMutation.isPending || retryMutation.isPending} mutableControlsEnabled={controllerOwnsActiveJob} retryEnabled={retryInventoryReady} onApprovalConfirmed={setJobApprovalConfirmed} onApprovedBy={setJobApprovedBy} onApprove={() => activeJob && controllerOwnsActiveJob && !cancelRequests.current.has(activeJob.job_id) && !controlMutation.isPending && (!embedded || embedded.releaseEnabled) && approvalMutation.mutate({ jobId: activeJob.job_id, approvedBy: jobApprovedBy })} onControl={(action) => activeJob && controllerOwnsActiveJob && (action === "cancel" || (!cancelRequests.current.has(activeJob.job_id) && (!embedded || embedded.controlsEnabled !== false))) && controlMutation.mutate({ jobId: activeJob.job_id, action })} onRetry={() => activeJob && retryInventoryReady && isRetryableInterruptedJob(activeJob) && retryMutation.mutate(activeJob.job_id)} onProposalDecision={handleProposalDecision} onProposalReviewLoaded={setActiveProposalReview} onReview={() => activeRun && navigate(runReviewPath(activeRun.run_id))} />;
  const cancellationNotice = activeJob && cancelRequestedIds.has(activeJob.job_id) && !terminalJobStates.has(activeJob.state) ? <Callout tone="warning" title="Cancellation requested">Release stays disabled while the saved job and cleanup are reconciled. Inspect its status or request Cancel again if the response was unavailable; no execution is repeated.</Callout> : null;
  const exactReviewError = (storedJobPreflightQuery.isError || unusableStoredJobPreflight) && ordinaryApprovalNeedsPreflight ? <Callout tone="danger" title="Exact approval review unavailable"><p>The active job remains controllable, but approval stays disabled until its canonical stored request returns an exact approval-required plan, binding, and envelope.</p><Button size="small" variant="secondary" disabled={storedJobPreflightQuery.isFetching} onClick={() => { void storedJobPreflightQuery.refetch(); }}><RotateCcw/>{storedJobPreflightQuery.isFetching ? "Retrying approval review" : "Retry approval review"}</Button></Callout> : null;
  if (embedded && (!durableJobId.test(embedded.job.job_id) || !matchesSelection(embedded.job))) return <ErrorState error={new Error("This phase no longer matches its exact saved execution job.")} />;
  if (embedded) return <section aria-label="Phase run approval and progress">
    {notice ? <Callout tone={approvalMutation.isError || controlMutation.isError || activeJobsQuery.isError || jobQuery.isError || eventsQuery.isError || resultQuery.isError ? "danger" : "info"} title="Run status">{notice}</Callout> : null}
    {!embedded.releaseEnabled && activeJob?.state === "awaiting_approval" ? <Callout title="Receiver status must be confirmed">Release stays disabled while the receiver test is being reconciled or stopped. The retained plan remains available, and controller-owned cancellation remains available.</Callout> : null}
    {!activeJob && !notice ? <LoadingState label="Loading this phase’s exact run job" /> : null}
    {cancellationNotice}{exactReviewError}{activeJob ? liveWorkspace : null}
    <Link to={`/runs?job=${encodeURIComponent(embedded.job.job_id)}`}>Open this job in Runs</Link>
  </section>;
  if (catalog.isPending || (runId && historicalRunQuery.isPending)) return <LoadingState label={runId ? "Loading canonical run review" : "Loading run controls"} />;
  if (catalog.isError) return <ErrorState error={catalog.error} retry={() => catalog.refetch()} />;
  if (runId && historicalRunQuery.isError) return <div className="page runs-page"><PageHeader eyebrow="Run history" title="Canonical run unavailable" description="The requested run could not be loaded from durable history." actions={<Link className="button button-secondary button-medium" to="/runs">Back to run workspace</Link>} /><ErrorState error={historicalRunQuery.error} retry={() => historicalRunQuery.refetch()} /></div>;
  if (runId && historicalRunQuery.data) return <HistoricalRunReview run={historicalRunQuery.data} catalog={catalog.data} />;
  const configReady = runConfig.mode === "simulate" || Boolean(runConfig.profileId);
  const preflightCanAuthorize = runConfig.mode === "execute" ? hasExecutePlanReview(preflight, scenario) : preflight?.ready === true;
  const canStart = preflightCanAuthorize && configReady && !runMutation.isPending && !jobActivityBlocksNewIntent;
  const guidedProfile = catalog.data.runner_profiles.find((profile) => profile.id === GUIDED_EXECUTE_PROFILE_ID);
  const guidedScenario = scenariosQuery.data?.scenarios.find((item) => item.id === GUIDED_EXECUTE_SCENARIO_ID);
  const scrollToGuideTarget = (id: string) => {
    const target = document.getElementById(id);
    target?.focus({ preventScroll: true });
    target?.scrollIntoView({ behavior: "smooth", block: "start" });
  };
  const selectGuidedScenario = () => {
    if (!guidedProfile || !guidedScenario) return;
    setScenario(structuredClone(guidedScenario), false);
    setRunConfig(guidedExecuteConfiguration(runConfig, guidedProfile));
    invalidatePreflight();
    if (!jobActivityBlocksNewIntent) {
      setActiveJob(null);
      setJobPreflight(undefined);
      setApprovalRequest(null);
      setActiveProposalReview(undefined);
    }
    setActiveRun(null);
    setJobApprovalConfirmed(false);
    setJobApprovedBy("");
    setNotice("The seeded restricted canary is selected with AI Off, exact sandbox scope, independent filesystem observation, and mandatory cleanup.");
  };

  const updateConfiguration = (next: RunConfiguration) => {
    consumedSetupArrival.current = location.key;
    const intentChanged = JSON.stringify({ ...runConfig, approved: false, approvedBy: "" }) !== JSON.stringify({ ...next, approved: false, approvedBy: "" });
    setRunConfig(next);
    if (intentChanged) invalidatePreflight();
  };
  const nextPreflightPrimary = !preflightCanAuthorize && !activeJob && Boolean(scenario.steps.length) && (runConfig.mode === "simulate" || isExecuteRunnerReady(selectedRunner));
  const submissionControls = <div className="run-action-bar"><div>{activeJob ? <Badge tone={statusTone(activeJob.state)} dot>{sentence(activeJob.state)}</Badge> : <Badge tone={preflight?.ready ? "success" : preflight?.status === "approval_required" ? "warning" : preflight ? "danger" : "neutral"} dot>{preflight?.ready ? "Ready" : preflight?.status === "approval_required" ? "Ready to create request" : preflight ? sentence(preflight.status) : "Preflight required"}</Badge>}<span>{runConfig.mode === "simulate" ? "No external behavior effects" : "Review and approve the saved request before execution"}</span></div><Button variant={nextPreflightPrimary ? "primary" : "secondary"} onClick={requestPreflight} disabled={preflightMutation.isPending || !scenario.steps.length || jobActivityBlocksNewIntent}>{preflightMutation.isPending ? <Activity className="spin"/> : <ShieldCheck/>}Run preflight</Button><Button variant={canStart && (runConfig.mode === "simulate" || isExecuteRunnerReady(selectedRunner)) ? "primary" : "secondary"} onClick={() => runMutation.mutate()} disabled={!canStart}>{runMutation.isPending ? <Activity className="spin"/> : <Play/>}{runMutation.isPending ? "Submitting job" : runConfig.mode === "execute" ? "Create approval-gated job" : "Submit Simulate job"}</Button></div>;
  const showLiveWorkspace = Boolean(activeJob || activeRun || activeJobId || runMutation.isPending);
  const focusedPreparation = !linkedJobId && (searchParams.get("prepare") === "1" || setupMode !== null);

  return <div className="page runs-page">
    <PageHeader title={linkedJobId ? "Run details" : "Runs"} actions={<>{focusedPreparation ? <Link className="button button-secondary button-medium" to="/runs">Run history</Link> : null}<Link className="button button-primary button-medium" to="/runs?prepare=1" onClick={() => setSetupExpanded(true)}>Review new run</Link><Link className="button button-secondary button-medium" to="/runs?saved=1">Run saved with Assistant</Link>{activeRun ? <Link className="button button-secondary button-medium" to={runReviewPath(activeRun.run_id)}>Review latest result</Link> : null}</>} />
    {!focusedPreparation && !linkedJobId && !showLiveWorkspace ? <RunHistoryPanel runs={runsQuery.data?.runs} unavailable={runsQuery.data?.unavailable_run_count ?? 0} pending={runsQuery.isPending} error={runsQuery.error} retry={() => runsQuery.refetch()} /> : null}
    {notice ? <Callout tone={runMutation.isError || approvalMutation.isError || runnerLifecycleMutation.isError || controlMutation.isError || activeJobsQuery.isError || jobQuery.isError || eventsQuery.isError || resultQuery.isError ? "danger" : preflight && !preflight.ready ? "warning" : "info"} title="Run status">{notice}</Callout> : null}
    {receiverControlLink(activeJob) ? <Callout title="Part of your receiver control test"><p>Return to the test to inspect the receiver policy, measured outcome and cleanup before the next phase.</p><Link className="button button-secondary button-medium" to={receiverControlLink(activeJob)!}>Return to receiver control test</Link></Callout> : null}
    {assistanceRunLink(activeJob) ? <Callout title="Part of your Assistant experiment"><p>This run belongs to the reviewed saved graph. Its evidence inspection and recovery stay with that operation.</p><Link className="button button-secondary button-medium" to={assistanceRunLink(activeJob)!}>Return to Assistant run and evidence</Link>{activeJob && terminalJobStates.has(activeJob.state) && activeJob.state !== "completed" ? <p>Review this run and its cleanup before starting new work. Evidence recovery does not repeat execution.</p> : null}</Callout> : null}
    {methodComparisonLink(activeJob) ? <Callout title="Part of your method test"><p>This replay belongs to the reviewed comparison workflow. Its saved rule will be evaluated against both runs.</p><Link className="button button-secondary button-medium" to={methodComparisonLink(activeJob)!}>Return to method test and results</Link>{activeJob && terminalJobStates.has(activeJob.state) && activeJob.state !== "completed" ? <p>Inspect the retained result and recover comparison work there. This run will not be replayed by a comparison retry.</p> : null}</Callout> : null}
    <>
      <details className="run-draft-details" open={setupExpanded} onToggle={(event) => setSetupExpanded(event.currentTarget.open)}><summary>Review a new run · {scenario.title}</summary>{runConfig.mode === "execute" ? <ExecuteOnboarding submissionControls={submissionControls} profile={selectedProfile} seededScenario={guidedProfile ? guidedScenario : undefined} selectedScenario={scenario} config={runConfig} runner={selectedRunner} runnerPending={Boolean(runnerProfileId) && runnerLifecycleQuery.isPending} runnerError={runnerLifecycleQuery.error} runnerActionPending={runnerLifecycleMutation.isPending} preflight={preflight} preflightPending={preflightMutation.isPending} preflightDisabled={jobActivityBlocksNewIntent} job={activeJob} approvalReleased={["consumed", "claimed"].includes(String(approvalRequest?.status ?? ""))} run={activeRun} jobSubmissionPending={runMutation.isPending} canCreateJob={canStart} demoMode={DEMO_MODE} onRunnerAction={(action) => runnerLifecycleMutation.mutate({ action, selection: runnerSelection })} onSelectScenario={selectGuidedScenario} onPreflight={requestPreflight} onCreateJob={() => runMutation.mutate()} onReviewEnvelope={() => scrollToGuideTarget("execute-envelope-review")} onReviewApproval={() => scrollToGuideTarget("durable-execute-approval")} /> : null}
      {runConfig.mode === "simulate" ? submissionControls : null}
      <div className="run-layout"><RunConfigurationPanel scenario={scenario} config={runConfig} onChange={updateConfiguration} catalog={catalog.data} preflight={preflight} /><PlanPreview scenarioTitle={scenario.title} stepIds={scenario.steps.map((step) => step.id)} edgeCount={scenario.edges.length} dirty={dirty} config={runConfig} catalog={catalog.data} preflight={preflight} /></div>
      {runConfig.mode === "execute" && preflight && (preflight.ready || preflight.status === "approval_required") && !hasExecutePlanReview(preflight, scenario) ? <Callout tone="danger" title="Complete run review unavailable">Job creation remains disabled until the service returns the complete plan, scope binding, and approval envelope.</Callout> : null}
      {runConfig.mode === "execute" && preflight?.runner_profile === runConfig.profileId ? <RunnerInventoryRecovery profileId={runConfig.profileId} problems={preflight.findings} /> : null}
      {preflight?.plan ? <div className="run-exact-review" id="execute-envelope-review" tabIndex={-1}><CanonicalPlanReview catalog={catalog.data} plan={preflight.plan} cleanup={preflight.cleanup} scope={preflight.scope} binding={preflight.approval_binding} envelope={preflight.approval_envelope} adaptiveAuthorization={preflight.adaptive_authorization} /></div> : null}
      </details>{activeJob?.kind === "scenario.replay" && typeof activeJob.request?.source_run_id === "string" ? <p>Replay of <Link to={runReviewPath(activeJob.request.source_run_id)}>the original run</Link>. Approval and progress belong to this saved replay.</p> : null}{alternateInventoryJobAvailable ? <Panel><PanelHeader eyebrow="Active controller inventory" title="Choose an active durable job" detail="Every controller-owned job remains available after navigation or reload." actions={<Badge tone="warning">{selectableInventoryJobs.length} active</Badge>} /><div className="detail-body"><Field label="Active durable job"><select value={selectableInventoryJobs.some((job) => job.job_id === activeJobId) ? activeJobId ?? "" : ""} onChange={(event) => { const selected = selectableInventoryJobs.find((job) => job.job_id === event.target.value); if (selected) selectInventoryJob(selected); }}><option value="" disabled>Select an active job</option>{selectableInventoryJobs.map((job) => <option key={job.job_id} value={job.job_id}>{sentence(job.state)} · {job.job_id}</option>)}</select></Field></div></Panel> : null}
      {cancellationNotice}{exactReviewError}
      {showLiveWorkspace ? liveWorkspace : null}
      {activeRun && activeJob?.kind === "scenario.replay" && activeJob.result_ref === activeRun.run_id && typeof activeJob.request?.source_run_id === "string" ? <Link className="button button-primary button-medium" to={comparisonLink(activeJob.request.source_run_id, activeRun.run_id)}>Compare with original run</Link> : null}
      {focusedPreparation || linkedJobId || showLiveWorkspace ? <RunHistoryPanel runs={runsQuery.data?.runs} unavailable={runsQuery.data?.unavailable_run_count ?? 0} pending={runsQuery.isPending} error={runsQuery.error} retry={() => runsQuery.refetch()} /> : null}
    </>
  </div>;
}

function HistoricalRunReview({ run, catalog }: { run: RunRecord; catalog: CatalogResponse }) {
  return <div className="page runs-page">
    <PageHeader title={runLabel(run)} description={`${sentence(run.mode)} · ${sentence(run.status)} · ${formatDate(run.finalized_at ?? run.created_at)}`} actions={<><RunNameControl key={run.run_id} run={run}/><Link className="button button-secondary button-medium" to="/runs">Back to run workspace</Link><Link className="button button-secondary button-medium" to={detectionLink(run.run_id)}>Open Detection Lab</Link><Link className={"button button-medium button-" + (typeof run.replay?.source_run_id === "string" ? "secondary" : "primary")} to={comparisonLink(run.run_id)}>Replay & compare</Link>{typeof run.replay?.source_run_id === "string" ? <Link className="button button-primary button-medium" to={comparisonLink(run.replay.source_run_id, run.run_id)}>Compare with original run</Link> : null}</>} />
    <RunReview run={run} catalog={catalog} />
  </div>;
}

function RunHistoryPanel({ runs, unavailable, pending, error, retry }: { runs?: RunRecord[]; unavailable: number; pending: boolean; error: unknown; retry: () => void }) {
  const [search, setSearch] = useState(() => { try { return sessionStorage.getItem("bluefire.runs.search.v1") ?? ""; } catch { return ""; } });
  useEffect(() => { try { sessionStorage.setItem("bluefire.runs.search.v1", search); } catch { /* Search still works without storage. */ } }, [search]);
  const history = (runs ?? []).filter(run => (runLabel(run) + " " + run.run_id).toLowerCase().includes(search.trim().toLowerCase()));
  return <Panel className="run-history-workspace">
    <PanelHeader title="Run history" actions={<Button size="small" variant="ghost" onClick={retry}><RotateCcw/>Refresh</Button>} />
    <div className="history-search"><input aria-label="Search runs" placeholder="Search name or run ID" value={search} onChange={event => setSearch(event.target.value)}/></div>
    {error ? <><ErrorState title="Run history unavailable" error={error} retry={retry}/>{runs ? <p className="workspace-note">Showing previously loaded runs.</p> : null}</> : null}
    {unavailable > 0 ? <p role="status">{unavailable} run {unavailable === 1 ? "record could" : "records could"} not be read. Refresh to try again.</p> : null}
    {pending ? <LoadingState label="Loading run history" /> : history.length ? <div className="table-scroll"><table><thead><tr><th>Run</th><th>Mode</th><th>Created</th><th>Outcome</th></tr></thead><tbody>{history.map(run => <tr key={run.run_id}><td><Link to={runReviewPath(run.run_id)} aria-label={"Review run " + runLabel(run) + " · " + sentence(run.mode) + " · " + formatDate(run.created_at)}><strong>{runLabel(run)}</strong></Link>{run.is_demo ? <Badge tone="violet">Demo</Badge> : null}</td><td>{sentence(run.mode)}</td><td>{formatDate(run.created_at)}</td><td><Badge tone={run.status === "failed" ? "danger" : "neutral"}>{sentence(run.status)}</Badge></td></tr>)}</tbody></table></div> : !error && (search || !unavailable) ? <div className="inline-empty"><span>{search ? "No runs match this search." : "No runs yet."}</span>{search ? <Button variant="ghost" size="small" onClick={() => setSearch("")}>Clear search</Button> : <Link to="/runs?prepare=1">Review new run</Link>}</div> : null}
  </Panel>;
}

function runReviewPath(runId: string) { return `/runs/${encodeURIComponent(runId)}`; }

function PlanPreview({ scenarioTitle, stepIds, edgeCount, dirty, config, catalog, preflight }: { scenarioTitle: string; stepIds: string[]; edgeCount: number; dirty: boolean; config: RunConfiguration; catalog: CatalogResponse; preflight?: PreflightReport }) {
  const profile = catalog.runner_profiles.find((item) => item.id === config.profileId); const warnings = [
    ...(config.mode === "execute" && !config.profileId ? ["Execute requires an explicit runner profile."] : []),
    ...(config.mode === "execute" && !config.approved ? ["Execute approval has not been confirmed."] : []),
    ...(config.autonomy === "auto" && catalog.ai.authority === "proposal_only" ? ["Current API reports proposal-only AI authority; Auto will remain bounded by backend capability."] : []),
  ];
  const awaitsExactApproval = preflight?.status === "approval_required" && Boolean(preflight.approval_binding && preflight.approval_envelope);
  const actionOverrideCount = Object.keys(config.actionImplementations).length;
  const nextMove = preflight ? preflight.ready ? "Submit the Simulate job or keep reviewing canonical plan details." : awaitsExactApproval ? "Review the complete Execute envelope, then create the durable approval-gated job." : "Resolve canonical preflight findings before job submission." : dirty ? "Validate and save in Builder when this draft should become reusable; run preflight to test this browser draft." : "Run preflight to bind the current graph, scope, profile, autonomy, and action choices.";
  return <Panel className="plan-preview"><PanelHeader title="Run plan" detail="Preflight resolves the full experiment, including alternate routes." actions={<Badge tone={config.mode === "execute" ? "warning" : "info"}>{sentence(config.mode)}</Badge>} />
    <div className="preview-hero"><div><strong>{scenarioTitle}</strong><small>{stepIds.length} steps · {edgeCount} routes · {dirty ? "Unsaved draft" : "Saved or packaged experiment"}</small></div><Gauge/></div>
    <p className="run-next-step">{nextMove}</p>
    <details className="run-intent-details"><summary>Browser draft & configuration details</summary><div className="preview-path">{stepIds.map((id, index) => <div key={id}><span>{String(index + 1).padStart(2, "0")}</span><strong>{id}</strong><small>{config.mode === "execute" && config.actionImplementations[id] ? `${config.actionImplementations[id]} · sent for exact binding` : "Control plane resolves implementation"}</small></div>)}</div><DataList items={[{ label: "Autonomy (sent)", value: sentence(config.autonomy) }, { label: "Provider (sent)", value: config.provider }, { label: "Profile (sent)", value: profile?.id ?? "Not selected" }, { label: "Targets (sent)", value: config.scopeRefs.join(", ") || "None" }, { label: "Execute actions (sent)", value: config.mode === "execute" ? Object.entries(config.actionImplementations).map(([step, action]) => `${step}: ${action}`).join(", ") || "Resolve deterministically" : "Omitted for Simulate" }, { label: "Safety tiers (profile)", value: profile?.safety_tiers.map(sentence).join(", ") ?? "Not selected" }, { label: "Cleanup (profile)", value: profile ? sentence(profile.cleanup_policy) : "Not selected" }, { label: "Budget (profile)", value: profile ? `${profile.budgets.max_steps} steps / ${profile.budgets.max_seconds}s / ${Math.round((profile.budgets.max_bytes ?? 0) / 1_048_576)} MiB` : "Not selected" }]} />
    <Callout title="Builder handoff">Run configuration uses the current browser graph exactly as shown. Saving a version makes it reusable, but only preflight can authorize this run intent.</Callout>
    <DataList items={[{ label: "Graph source", value: dirty ? "Unsaved browser draft" : "Saved or packaged graph" }, { label: "Graph shape", value: `${stepIds.length} nodes / ${edgeCount} routes` }, { label: "Action overrides", value: config.mode === "execute" ? `${actionOverrideCount} selected for exact binding` : "Not sent in Simulate" }, { label: "Preflight state", value: preflight ? sentence(preflight.status) : "Not run for this handoff" }, { label: "Next required move", value: nextMove }]} /></details>
    {warnings.length ? <div className="warning-list">{warnings.map((warning) => <div key={warning}><AlertTriangle/>{warning}</div>)}</div> : null}
    {preflight ? <div className={`preflight-result ${preflight.ready ? "ready" : awaitsExactApproval ? "approval-required" : "blocked"}`}><header><strong>{preflight.ready ? "Canonical preflight ready" : awaitsExactApproval ? "Canonical envelope awaits confirmation" : "Canonical preflight blocked"}</strong><Badge tone={preflight.ready ? "success" : awaitsExactApproval ? "warning" : "danger"}>{sentence(preflight.status)}</Badge></header><details className="resolved-preflight-details"><summary>Resolved preflight details</summary><DataList items={[{ label: "Resolved autonomy", value: preflight.autonomy ? sentence(preflight.autonomy) : "Not reported" }, { label: "Resolved profile", value: preflight.runner_profile ?? "None" }, { label: "Scope", value: typeof preflight.scope === "string" ? preflight.scope : JSON.stringify(preflight.scope ?? {}) }, { label: "Safety tier", value: preflight.safety_tier ? sentence(preflight.safety_tier) : "Not reported" }, { label: "Capabilities", value: preflight.capabilities?.join(", ") ?? "Not reported" }, { label: "Approval", value: preflight.approval ?? "Not reported" }, { label: "Cleanup", value: typeof preflight.cleanup === "string" ? preflight.cleanup : JSON.stringify(preflight.cleanup ?? {}) }]} /></details>{preflight.findings?.length ? <ul>{preflight.findings.map((item, index) => <li key={index}>{typeof item === "string" ? item : item.message ?? item.code ?? JSON.stringify(item)}</li>)}</ul> : null}</div> : null}
    {!preflight?.plan ? <p className="run-next-step">Preflight will show the exact steps, effects, observations, and cleanup here.</p> : null}
  </Panel>;
}

function normalizeStatus(status: string) { return status === "success" ? "succeeded" : status === "control_blocked" ? "blocked" : status; }
function statusTone(status: string) { const value = normalizeStatus(status); return value === "succeeded" || value === "completed" || value === "cleaned" ? "success" as const : ["blocked", "partial", "awaiting_approval", "paused", "cancelling", "cancelled"].includes(value) ? "warning" as const : ["failed", "refused", "interrupted"].includes(value) ? "danger" as const : value === "counterfactual" ? "violet" as const : "info" as const; }

interface LiveConsoleProps {
  catalog?: CatalogResponse;
  run: RunRecord | null;
  job: RunJob | null;
  events: RunEventPage["items"];
  pending: boolean;
  approvalPreflight?: PreflightReport;
  approvalRequest: Record<string, unknown> | null;
  proposalReview?: AIProposalReview;
  approvalConfirmed: boolean;
  approvedBy: string;
  approvalPending: boolean;
  releaseEnabled: boolean;
  controlActionsEnabled: boolean;
  controlPending: boolean;
  mutableControlsEnabled: boolean;
  retryEnabled: boolean;
  onApprovalConfirmed: (confirmed: boolean) => void;
  onApprovedBy: (identity: string) => void;
  onApprove: () => void;
  onControl: (action: "pause" | "resume" | "cancel") => void;
  onRetry: () => void;
  onProposalDecision: (result: AIProposalDecisionResult, review: AIProposalReview) => void;
  onProposalReviewLoaded: (review: AIProposalReview | undefined) => void;
  onReview: () => void;
}

function LiveConsole({ catalog, run, job, events, pending, approvalPreflight, approvalRequest, proposalReview, approvalConfirmed, approvedBy, approvalPending, releaseEnabled, controlActionsEnabled, controlPending, mutableControlsEnabled, retryEnabled, onApprovalConfirmed, onApprovedBy, onApprove, onControl, onRetry, onProposalDecision, onProposalReviewLoaded, onReview }: LiveConsoleProps) {
  const [tab, setTab] = useState<"timeline" | "planner" | "policy" | "runner" | "evidence" | "detections">("timeline");
  const steps: RunStep[] = run?.steps ?? [];
  const canPause = controlActionsEnabled && mutableControlsEnabled && job?.state === "running";
  const canResume = controlActionsEnabled && mutableControlsEnabled && job?.state === "paused";
  const canCancel = Boolean(mutableControlsEnabled && job && !terminalJobStates.has(job.state));
  const terminal = Boolean(job && terminalJobStates.has(job.state));
  const emptyTitle = pending && !run ? job?.state === "awaiting_approval" ? "Waiting for your approval" : job ? sentence(job.state) : "Submitting request" : run ? `Run ${sentence(run.status).toLowerCase()}` : terminal ? `Job ${sentence(job!.state).toLowerCase()}` : "Awaiting a run";
  const emptyDetail = pending && !run ? job?.state === "awaiting_approval" ? "Review the saved plan below. The next execution phase is waiting for approval." : job ? "Following the saved operation. Step results appear as they are recorded." : "Waiting for the service to return the saved operation." : run ? "The saved record contains no completed steps. Review its events and limitations for context." : terminal ? typeof job?.progress.run_id === "string" ? "This job has ended. Its recorded events remain available below, but no finalized run record is linked." : "This job ended before a run record was linked." : "Planner, policy, dispatch, evidence, detection, and cleanup events will remain separate.";
  return <Panel className="live-console"><PanelHeader title={run ? runLabel(run) : job ? "Run progress" : pending ? "Submitting run" : "No active run"} detail={run ? `${sentence(run.mode)} · ${sentence(run.status)} · ${run.is_demo ? "sanitized demo" : "canonical local record"}` : job ? `${sentence(job.state)} · Updated ${formatDate(job.updated_at)}` : "Complete preflight, then submit a durable local job."} actions={<div className="run-controls"><Button size="small" variant="ghost" disabled={!canPause || controlPending} onClick={() => onControl("pause")} title={canPause ? "Pause at the next cooperative checkpoint" : "Pause requires a running controller-owned job"}><Pause/>Pause</Button><Button size="small" variant="ghost" disabled={!canResume || controlPending} onClick={() => onControl("resume")} title={canResume ? "Resume the cooperatively paused job" : "Resume requires a paused controller-owned job"}><RotateCcw/>Resume</Button>{isRetryableInterruptedJob(job) ? <Button size="small" variant="secondary" disabled={!retryEnabled || controlPending} onClick={onRetry} title={retryEnabled ? "Create a replacement job with fresh preflight and approval" : "Retry requires a fresh empty active-job inventory"}><RotateCcw/>Retry as replacement</Button> : null}<Button size="small" variant="danger" disabled={!canCancel || controlPending} onClick={() => onControl("cancel")} title={canCancel ? "Request cooperative cancellation" : "Cancel requires a nonterminal controller-owned job"}><CircleStop/>Cancel</Button>{run ? <Button size="small" onClick={onReview}><FileSearch/>Review</Button> : null}</div>} />
    {job ? <details className="job-details"><summary>Job details</summary><DataList items={[{ label: "Job ID", value: <code>{job.job_id}</code> }, { label: "Last update", value: formatDate(job.updated_at) }]} /></details> : null}
    {DEMO_MODE ? <div className="console-banner"><Sparkles/>Demo lifecycle states are presentation fixtures only. No runner was dispatched.</div> : null}
    {job?.state === "awaiting_approval" && job.progress.approval_kind !== "ai_proposal" ? mutableControlsEnabled ? <JobApprovalGate catalog={catalog} job={job} preflight={approvalPreflight} approvalRequest={approvalRequest} proposalReview={proposalReview} confirmed={approvalConfirmed} approvedBy={approvedBy} pending={approvalPending} releaseEnabled={releaseEnabled} onConfirmed={onApprovalConfirmed} onApprovedBy={onApprovedBy} onApprove={onApprove} /> : <Callout tone="warning" title="Controller ownership unavailable">Approval remains disabled until fresh active-job inventory confirms that this controller owns the job.</Callout> : null}
    {job && !terminal && typeof job.progress.proposal_record_id === "string" ? mutableControlsEnabled ? <ProposalReviewWorkspace job={job} onDecision={onProposalDecision} onReviewLoaded={onProposalReviewLoaded}/> : <Callout tone="warning" title="Controller ownership unavailable">Proposal decisions remain disabled until fresh active-job inventory confirms that this controller owns the job.</Callout> : null}
    {job?.error ? <Callout tone="danger" title={job.error.code ?? "Job failed"}>{job.error.message ?? "The durable job ended with a sanitized error record."}</Callout> : null}
    <div className="live-path">{steps.length ? steps.map((step, index) => {
      const labels = recordedStepLabels(step, catalog, run);
      return <article key={`${step.step_id}-${index}`} data-status={normalizeStatus(step.status)}><header><span>{String(index + 1).padStart(2, "0")}</span><Badge tone={statusTone(step.status)} dot>{stepOutcomeLabel(step, run!.mode)}</Badge></header><strong>{labels.name}</strong>{labels.method !== labels.name ? <small>{labels.method}</small> : null}<details><summary>Step details</summary><DataList items={[{ label: "Step ID", value: <code>{step.step_id}</code> }, { label: "Method ID", value: <code>{step.action_id ?? step.simulation_id ?? "Not recorded"}</code> }, { label: "Disposition", value: sentence(step.execution_disposition ?? "not recorded") }]} /></details></article>;
    }) : <div className="console-empty"><Activity/><strong>{emptyTitle}</strong><span>{emptyDetail}</span></div>}</div>
    <div className="console-tabs" role="tablist" aria-label="Run detail views">{(["timeline", "planner", "policy", "runner", "evidence", "detections"] as const).map((item) => <button key={item} role="tab" aria-selected={tab === item} onClick={() => setTab(item)}>{sentence(item)}</button>)}</div>
    <div className="console-detail">{tab === "timeline" ? <Timeline catalog={catalog} run={run} job={job} events={events} pending={pending} /> : tab === "planner" ? <StructuredPanel value={run?.planner_decisions?.length ? run.planner_decisions : run?.plan} empty="No planner decisions are available." /> : tab === "policy" ? <StructuredPanel value={run?.policy} empty="No policy decisions are available." /> : tab === "runner" ? <RunnerDetail catalog={catalog} run={run} /> : tab === "evidence" ? <EvidenceDetail run={run} /> : <DetectionDetail run={run} />}</div>
  </Panel>;
}

function JobApprovalGate({ catalog, job, preflight: ordinaryPreflight, approvalRequest, proposalReview, confirmed, approvedBy, pending, releaseEnabled, onConfirmed, onApprovedBy, onApprove }: { catalog?: CatalogResponse; job: RunJob; preflight?: PreflightReport; approvalRequest: Record<string, unknown> | null; proposalReview?: AIProposalReview; confirmed: boolean; approvedBy: string; pending: boolean; releaseEnabled: boolean; onConfirmed: (confirmed: boolean) => void; onApprovedBy: (identity: string) => void; onApprove: () => void }) {
  const deadline = useApprovalDeadline(approvalRequest?.expires_at);
  const receiverLink = receiverControlLink(job);
  const proposalExecute = job.progress.approval_kind === "ai_proposal_execute";
  const preflight = proposalExecute ? continuationApprovalPreflight(job, proposalReview, approvalRequest, { forDisplayOnly: true }) : ordinaryPreflight;
  const binding = preflight?.approval_binding;
  const envelope = preflight?.approval_envelope;
  const resolutionRecord = proposalReview?.resolution && typeof proposalReview.resolution === "object" ? proposalReview.resolution : undefined;
  const continuation = resolutionRecord?.continuation;
  const continuationRecord = continuation && typeof continuation === "object" ? continuation as Record<string, unknown> : undefined;
  const approvalRequestId = typeof approvalRequest?.approval_id === "string" ? approvalRequest.approval_id : undefined;
  const progressApprovalRequestId = typeof job.progress.approval_request_id === "string" ? job.progress.approval_request_id : undefined;
  const originalApprovalRequestId = typeof job.request?.approval_request_id === "string" ? job.request.approval_request_id : undefined;
  const ordinaryRequestReady = Boolean(approvalRequestId && originalApprovalRequestId === approvalRequestId && (progressApprovalRequestId === undefined || progressApprovalRequestId === approvalRequestId));
  const proposalRequestReady = Boolean(approvalRequestId && progressApprovalRequestId === approvalRequestId && originalApprovalRequestId && originalApprovalRequestId !== approvalRequestId && resolutionRecord?.approval_request_id === approvalRequestId);
  const pendingRequestReady = approvalRequest?.status === "pending" && (proposalExecute ? proposalRequestReady : ordinaryRequestReady);
  const exactBindingMatches = Boolean(binding && approvalBindingFields.every((field) => typeof approvalRequest?.[field] === "string" && approvalRequest[field] === binding[field]));
  const replayPreparation = job.kind === "scenario.replay" ? job.request?.replay_preparation as ReplayPreparation | undefined : undefined;
  const storedReplayRequest = job.kind === "scenario.replay" ? job.request?.replay_request as Record<string, unknown> | undefined : undefined;
  const fromStep = storedReplayRequest?.from_step_id;
  const checkpointReplay = fromStep != null || replayPreparation?.replay_extent === "from_step" || replayPreparation?.replay_request?.from_step_id != null || replayPreparation?.binding?.replay_request?.from_step_id != null;
  const restorationReady = !checkpointReplay || Boolean(fromStep != null && hasReplayExtent(replayPreparation) && replayPreparation?.preflight?.plan?.mode === "execute" &&
    replayPreparation.binding.source.run_id === job.request?.source_run_id && sameJson(replayPreparation.replay_request, storedReplayRequest) && sameJson(replayPreparation.binding.replay_request, storedReplayRequest));
  const exactEnvelopeReady = releaseEnabled && restorationReady && Boolean(hasUsableStoredApprovalReview(preflight) && hasAdaptiveApprovalReview(preflight, requiresAdaptiveReview(job)) && pendingRequestReady && exactBindingMatches && deadline.current);
  return <section className="job-approval-gate" id="durable-execute-approval" tabIndex={-1} aria-label="Durable Execute job approval">
    <header><div><AlertTriangle/><span><strong>{proposalExecute ? "Fresh Execute approval after proposal acceptance" : "Approve this run"}</strong><small>Review the actions, lab scope and cleanup below before releasing this run.</small></span></div><Badge tone="warning" dot>Awaiting approval</Badge></header>
    <p className="job-approval-expiry">Review and approve before {formatDate(typeof approvalRequest?.expires_at === "string" ? approvalRequest.expires_at : undefined)}. The pending actions have not started.</p>
    <details className="job-approval-identities"><summary>Approval record and bound state</summary>
      <DataList items={[{ label: "Durable job", value: <code>{job.job_id}</code> }, { label: "Approval request", value: <code>{String(approvalRequest?.approval_id ?? "Not reported")}</code> }, { label: "Expires", value: formatDate(typeof approvalRequest?.expires_at === "string" ? approvalRequest.expires_at : undefined) }, { label: "Profile / tier", value: proposalExecute ? `${String(approvalRequest?.profile_id ?? "Not reported")} / ${sentence(String(approvalRequest?.maximum_tier ?? "not reported"))}` : binding ? `${binding.profile_id} / ${sentence(binding.maximum_tier)}` : "Not reported" }, { label: "State digest", value: <code>{String(proposalExecute ? approvalRequest?.state_digest ?? "Not reported" : binding?.state_digest ?? "Not reported")}</code> }, { label: "Plan digest", value: <code>{String(proposalExecute ? approvalRequest?.plan_digest ?? "Not reported" : binding?.plan_digest ?? "Not reported")}</code> }, { label: "Scope digest", value: <code>{String(proposalExecute ? approvalRequest?.target_scope_digest ?? "Not reported" : binding?.target_scope_digest ?? "Not reported")}</code> }, { label: proposalExecute ? "Continuation binding digest" : "Envelope digest", value: <code>{String(proposalExecute ? continuationRecord?.execute_approval_binding_digest ?? "Not reported" : envelope?.envelope_digest ?? "Not reported")}</code> }]} />
    </details>
    {checkpointReplay ? restorationReady ? <Callout title="Restore and continue"><p>This approval includes recreating the earlier steps in a fresh workspace, verifying their files against the saved checkpoint, and then continuing from <strong>{sentence(String(fromStep))}</strong>. Cleanup applies to the new workspace.</p><details><summary>Checkpoint and restoration details</summary><pre>{JSON.stringify(replayPreparation?.binding.resolution, null, 2)}</pre></details></Callout> : <Callout tone="danger" title="Checkpoint review unavailable">Approval remains disabled because the saved restart position and restoration binding do not match.</Callout> : null}
    {!pendingRequestReady ? <Callout tone="danger" title="Pending approval binding unavailable">Approval remains disabled until this job reports the same pending approval request ID returned with its immutable envelope.</Callout> : null}
    {!deadline.current ? <Callout tone="warning" title={deadline.valid ? "Approval review expired" : "Approval deadline unavailable"}>{deadline.valid ? "This one-time approval has expired." : "This approval has no valid expiry time."} The saved review remains available, but this job cannot be released. {receiverLink ? <>Cancelling it also stops the entire receiver control test. <Link to={receiverLink}>Open the saved control test</Link> to check retained results and cleanup. Once cleanup is confirmed, choose Set up another control test; the stopped phase cannot resume.</> : <>Cancel it and return to its setup page for a fresh review and approval.</>} No approval is renewed automatically.</Callout> : null}
    {proposalExecute && proposalReview && continuationRecord ? <DataList items={[{ label: "Proposal record", value: <code>{proposalReview.proposal_record_id}</code> }, { label: "Selected behavior", value: <code>{String(continuationRecord.selected_behavior_id ?? "Not reported")}</code> }, { label: "Resume step", value: <code>{String(continuationRecord.resume_from_step_id ?? "Full replay")}</code> }, { label: "Proposal digest", value: <code>{proposalReview.proposal_digest}</code> }]} /> : null}
    {preflight?.plan ? <><CanonicalPlanReview catalog={catalog} plan={preflight.plan} cleanup={preflight.cleanup} scope={preflight.scope} binding={binding} envelope={envelope} adaptiveAuthorization={preflight.adaptive_authorization} />{binding && !exactBindingMatches ? <Callout tone="danger" title="Approval envelope mismatch">Approval remains disabled because the pending request does not exactly match all five preflight binding fields.</Callout> : null}</> : <Callout tone="danger" title="Exact review unavailable">Approval remains disabled until the current pending request has its complete canonical plan and approval envelope.</Callout>}
    <div className="job-approval-controls"><label className="check-row"><input type="checkbox" checked={confirmed} disabled={!exactEnvelopeReady || pending} onChange={(event) => onConfirmed(event.target.checked)}/><span><strong>I approve this exact immutable {proposalExecute ? "proposal continuation" : "job envelope"} once</strong><small>Unchecked by default and never stored in browser persistence</small></span></label><Field label="Operator identity for this job"><input value={approvedBy} disabled={!exactEnvelopeReady || pending} onChange={(event) => onApprovedBy(event.target.value)} autoComplete="off" placeholder="Operator label"/></Field><Button variant="primary" disabled={!exactEnvelopeReady || !confirmed || !approvedBy.trim() || pending} onClick={() => { if (deadline.recheck()) onApprove(); }}>{pending ? <Activity className="spin"/> : <ShieldCheck/>}{pending ? "Applying one-time approval" : "Approve and release job"}</Button><p>The server recomputes the binding, validates the pending capability, consumes it atomically, then releases only this job. Changing configuration elsewhere cannot alter this immutable request.</p></div>
  </section>;
}

function Timeline({ catalog, run, job, events: incrementalEvents, pending }: { catalog?: CatalogResponse; run: RunRecord | null; job: RunJob | null; events: RunEventPage["items"]; pending: boolean }) {
  const events = incrementalEvents.length ? incrementalEvents : run?.events?.length ? run.events : run?.steps.map((step, index) => ({ event_type: "step.completed", data: step, sequence: index + 1 })) ?? (job ? [{ type: job.state, sequence: 1, disposition: job.state === "awaiting_approval" ? "Execution callback has not started" : `Durable job phase ${String(job.progress.phase ?? job.state)}`, timestamp: job.updated_at }] : []);
  if (!events.length && !pending) return <div className="console-empty compact"><Clock3/><span>No audit events are available.</span></div>;
  return <ol className="timeline">{pending && !events.length ? <li><span className="timeline-dot planning"/><div><strong>Planning request submitted</strong><p>Waiting for the service to accept the request. Its saved status will appear here.</p></div><time>Now</time></li> : events.map((event, index) => {
    const view = runEventPresentation(event, catalog, run, job?.request?.mode);
    return <li key={view.sequence ?? index + 1}><span className={`timeline-dot ${normalizeStatus(view.status)}`}/><div><strong>{view.title}</strong><p>{view.detail}</p><details><summary>Event details</summary><DataList items={[{ label: "Event type", value: <code>{view.type}</code> }, ...(view.stepId ? [{ label: "Step ID", value: <code>{view.stepId}</code> }] : []), ...(view.methodId ? [{ label: "Method ID", value: <code>{view.methodId}</code> }] : []), ...(view.behaviorId ? [{ label: "Behavior ID", value: <code>{view.behaviorId}</code> }] : [])]} /></details></div><time>{view.timestamp ? formatDate(view.timestamp) : `#${view.sequence ?? index + 1}`}</time></li>;
  })}</ol>;
}

function StructuredPanel({ value, empty }: { value: unknown; empty: string }) {
  if (value === null || value === undefined || (Array.isArray(value) && !value.length)) return <div className="console-empty compact"><ListTree/><span>{empty}</span></div>;
  const entries = Array.isArray(value) ? value.map((item, index) => [`Record ${index + 1}`, item] as const) : typeof value === "object" ? Object.entries(value as Record<string, unknown>) : [["Value", value] as const];
  return <div className="structured-list">{entries.map(([key, item]) => <article key={key}><strong>{sentence(key)}</strong>{typeof item === "object" ? <pre>{JSON.stringify(item, null, 2)}</pre> : <span>{String(item)}</span>}</article>)}</div>;
}

function RunnerDetail({ run, catalog }: { run: RunRecord | null; catalog?: CatalogResponse }) {
  if (!run) return <div className="console-empty compact"><TerminalSquare/><span>No runner dispatch records are available.</span></div>;
  const executed = run.steps.filter((step) => step.action_id);
  return <div>{executed.length ? <div className="structured-list">{executed.map((step, index) => {
    const labels = recordedStepLabels(step, catalog, run);
    return <article key={`${step.step_id}-${index}`}><strong>{labels.name}</strong>{labels.method !== labels.name ? <span>{labels.method}</span> : null}<span>{stepOutcomeLabel(step, run.mode)}</span><details><summary>Dispatch details</summary><DataList items={[{ label: "Step ID", value: <code>{step.step_id}</code> }, { label: "Action ID", value: <code>{step.action_id}</code> }]} /></details></article>;
  })}</div> : <Callout title="No runner dispatch reported">This run used simulation adapters or lacks runner records. Simulation is not execution.</Callout>}</div>;
}

export function EvidenceDetail({ run }: { run: RunRecord | null }) {
  const records = run?.evidence?.records ?? []; if (!records.length) return <div className="console-empty compact"><FileSearch/><span>No evidence records are available.</span></div>;
  return <EvidenceRecords records={records} />;
}

export function DetectionDetail({ run }: { run: RunRecord | null }) {
  const candidates = run?.detections?.candidates ?? []; if (!candidates.length) return <div className="console-empty compact"><FileSearch/><span>No detection candidates are linked to this run.</span></div>;
  return <div className="record-grid">{candidates.map((item, index) => <article key={item.candidate_id ?? item.id ?? index}><header><Badge tone={item.state === "rejected" ? "danger" : item.state.includes("exercised") || item.state === "benign_evaluated" ? "success" : "info"}>{sentence(item.state)}</Badge><code>{item.target_language ?? item.language ?? "query"}</code></header><strong>{item.title ?? item.candidate_id ?? "Detection candidate"}</strong><p>{item.summary ?? "Lifecycle state reflects only completed validation stages."}</p></article>)}</div>;
}


export function RunReview({ run, catalog }: { run: RunRecord; catalog: CatalogResponse }) {
  const steps = run.steps ?? [];
  const stopped = steps.find((step) => step.execution_disposition !== "counterfactual" && ["blocked", "control_blocked", "refused", "failed", "error", "cancelled"].includes(step.status));
  const evidence = run.evidence?.records;
  const observed = evidence?.filter((record) => record.provenance === "observed");
  const executed = evidence?.filter((record) => record.provenance === "executed");
  const synthetic = evidence?.filter((record) => ["synthetic", "counterfactual"].includes(record.provenance));
  const policyRecords = evidence?.filter((record) => record.provenance === "control_blocked");
  const otherRecords = evidence?.filter((record) => !["observed", "executed", "synthetic", "counterfactual", "control_blocked"].includes(record.provenance));
  const sources = [
    [executed?.length, "runner-reported"], [synthetic?.length, "synthetic or simulated-continuation"],
    [observed?.length, "independently observed"], [policyRecords?.length, "policy or refusal"], [otherRecords?.length, "other or unknown"],
  ].filter(([count]) => typeof count === "number" && count > 0).map(([count, label]) => `${count} ${label}`).join(" · ");
  const detections = run.detections?.candidates;
  const aiProposals = Array.isArray(run.ai_proposals) ? run.ai_proposals : [];
  const outcome = objectiveLabel(run.objective_reached, run.mode);
  const cleanup = cleanupSummary(run.cleanup);
  const needsCleanup = cleanup.startsWith("Needs attention") || cleanup.startsWith("Failed");
  const stepName = (step: RunStep) => catalog.behaviors.find((item) => item.id === step.behavior_id)?.title ?? step.step_id;
  const outcomeDescription = run.objective_reached === true
    ? run.mode === "simulate" ? "The simulated path reached the experiment's objective. This does not establish a real effect or a working defense." : "The run records its objective as achieved. Check independent observations below to assess what was verified."
    : run.objective_reached === false ? "The run did not achieve its objective. An unmet objective alone does not establish that a target control prevented it."
    : "This record does not establish whether the objective was achieved. Review the path and available evidence before drawing a conclusion.";
  return <div className="review-stack run-review">
    <RunExports key={run.run_id} run={run}/>
    {run.is_demo ? <Callout title="Seeded review">This is a sanitized Simulate record. It does not prove runner execution, independent observation, or a real control block.</Callout> : null}
    {run.approval_pause ? <Callout tone="warning" title="Waiting for a reviewed continuation">The planner paused before the next action. Return to its saved job to review the proposed change and, for Execute, approve the next run.</Callout> : null}
    <section className="run-outcome" aria-label="Recorded run outcome">
      <div className="run-outcome-main"><p className="eyebrow">Recorded outcome</p><h2>{outcome}</h2><p>{outcomeDescription}</p>{run.objective ? <div className="run-objective"><strong>Objective</strong><p>{run.objective}</p></div> : null}</div>
      <dl className="run-outcome-facts">
        <div><dt>Independent observations</dt><dd>{observed ? `${observed.length} observed records` : "Not reported"}<small>{observed?.length === 0 ? "No independent confirmation is recorded." : observed ? "Collector observations; inspect their content and limitations." : "The evidence document is unavailable."}</small></dd></div>
        <div><dt>First stopped step</dt><dd>{stopped ? <>{stepName(stopped)}<small>{stepOutcomeLabel(stopped, run.mode)}</small></> : <>None recorded<small>This does not establish that the path completed.</small></>}</dd></div>
        <div className={needsCleanup ? "cleanup-attention" : ""}><dt>Cleanup</dt><dd>{cleanup}<small>{run.mode === "simulate" ? "Simulate does not perform lab effects." : "Recorded cleanup result; inspect any outstanding effects."}</small></dd></div>
      </dl>
    </section>
    {stopped?.error?.message ? <Callout tone="warning" title={stepOutcomeLabel(stopped, run.mode)}>{stopped.error.message}</Callout> : null}
    <section className="run-evidence-summary" aria-label="Evidence and detection summary">
      <div><h3>Evidence sources</h3><p>{evidence ? (sources || "No evidence records") : "Evidence not reported"}</p><small>These sources support different claims. Runner output and simulated records are not independent observations.</small></div>
      <div><h3>Detection work</h3><p>{detections ? `${detections.length} linked candidate${detections.length === 1 ? "" : "s"}` : "Not reported"}</p><small>{detections?.length ? "Review each candidate's validation stage and evaluated inputs before claiming coverage." : "No evaluated detection result is established here. Open Detection Lab to investigate this run."}</small></div>
    </section>
    <AdaptiveRunPath run={run} catalog={catalog}/>
    <section className="run-path-section" aria-label="Recorded step outcomes"><header><h2>Path taken</h2><p>{steps.length} recorded steps · outcomes as reported by this run</p></header>
      {steps.length ? <ol className="run-path-list">{steps.map((step, index) => <li key={`${step.step_id}-${index}`}><span className="run-step-number" aria-hidden="true">{String(index + 1).padStart(2, "0")}</span><div><strong>{stepName(step)}</strong><small>{stepOutcomeLabel(step, run.mode)}</small></div><details><summary>Step details</summary><DataList items={[{ label: "Step", value: step.step_id }, { label: "Method", value: step.action_id ?? step.simulation_id ?? "Not reported" }, { label: "Disposition", value: sentence(step.execution_disposition ?? "not reported") }, { label: "Evidence references", value: step.evidence_ids?.join(", ") || "None recorded" }]} />{step.error?.message ? <p>{step.error.message}</p> : null}</details></li>)}</ol> : <p className="field-note">No step outcomes are recorded.</p>}
    </section>
    <details className="run-review-details"><summary>Inspect evidence records{evidence ? ` (${evidence.length})` : " · not reported"}</summary><EvidenceDetail run={run}/></details>
    <details className="run-review-details"><summary>Inspect detection candidates{detections ? ` (${detections.length})` : " · not reported"}</summary><DetectionDetail run={run}/></details>
    {aiProposals.length ? <details className="run-review-details"><summary>AI decisions ({aiProposals.length})</summary><AIProposalTrail run={run} catalog={catalog} proposals={aiProposals}/></details> : <p className="run-ai-note">No runtime AI proposal records are attached.</p>}
    {runLimitationGroups(run).map((group) => <section className="run-limitations" aria-label={group.title} key={group.title}><h2>{group.title}</h2>{group.description ? <p>{group.description}</p> : null}{group.items.length ? <ul>{group.items.map((item, index) => <li key={index}>{item}</li>)}</ul> : <p>No limitations were attached. This is incomplete metadata, not proof that there are none.</p>}</section>)}
    <details className="run-review-details"><summary>Run identity, environment and technical record</summary><DataList items={[{ label: "Run ID", value: <CopyRunId runId={run.run_id}/> }, { label: "Mode", value: sentence(run.mode) }, { label: "AI mode", value: sentence(run.autonomy ?? run.autonomy_level ?? (run.ai_enabled ? "assist" : "off")) }, { label: "Profile", value: run.runner_profile_id ?? "Not recorded" }, { label: "Targets", value: recordedTargetScope(run) }, { label: "Started", value: formatDate(run.created_at) }, { label: "Finalized", value: formatDate(run.finalized_at) }, { label: "Replay lineage", value: run.replay ? "Replay-linked" : "Original run" }]} /><details><summary>Raw reproducibility metadata</summary><div className="raw-columns"><StructuredPanel value={run.manifest ?? { schema_version: run.schema_version, scenario_id: run.scenario_id, profile_id: run.runner_profile_id }} empty="No manifest metadata."/><pre aria-label="Canonical run technical record">{JSON.stringify({ run_id: run.run_id, schema_version: run.schema_version, scenario_id: run.scenario_id, runner_profile_id: run.runner_profile_id, cleanup: run.cleanup ?? null, replay: run.replay ?? null }, null, 2)}</pre></div></details></details>
  </div>;
}

function AIProposalTrail({ proposals, run, catalog }: { proposals: NonNullable<RunRecord["ai_proposals"]>; run: RunRecord; catalog: CatalogResponse }) {
  if (!proposals.length) return <Panel><PanelHeader eyebrow="AI Auto journey" title="No runtime AI proposals"/><Callout title="Deterministic path">This run did not retain any Assist or Auto proposal records; planner decisions remained deterministic.</Callout></Panel>;
  return <Panel><PanelHeader eyebrow="AI Auto journey" title="Proposal, policy, and application trail" detail="Completed records show exactly what the provider proposed and what deterministic policy permitted, reviewed, or refused." actions={<Badge tone="violet">{proposals.length} proposal{proposals.length === 1 ? "" : "s"}</Badge>}/>
    <div className="record-grid">{proposals.map((record, index) => {
      if (record.schema_version === "bluefire.ai-proposal-record.v4") return <AdaptiveDecision key={String(record.proposal_record_id ?? index)} record={record} run={run} catalog={catalog}/>;
      const proposal = record.proposal ?? undefined;
      const provider = record.provider ?? {};
      const policy = record.proposal_policy_evaluation ?? {};
      return <article key={String(record.proposal_record_id ?? proposal?.proposal_id ?? index)}><header><Badge tone={String(record.application_status ?? "").startsWith("applied") || String(record.application_status ?? "").startsWith("accepted") ? "success" : String(record.application_status ?? "").includes("approval") ? "warning" : "info"}>{sentence(String(record.application_status ?? "recorded"))}</Badge><code>{String(proposal?.proposal_id ?? record.proposal_record_id ?? `proposal-${index + 1}`)}</code></header><strong>{sentence(String(proposal?.proposal_type ?? "proposal"))}</strong><p>{proposal?.rationale ?? "No provider rationale was retained."}</p><DataList items={[{ label: "Provider", value: `${String(provider.effective_provider_id ?? provider.requested_provider_id ?? "Not reported")}${provider.used_fallback ? ` · fallback: ${sentence(String(provider.fallback_reason ?? "used"))}` : ""}` }, { label: "Selected step", value: proposal?.selected_step_id ? <code>{proposal.selected_step_id}</code> : "None" }, { label: "Selected Behavior", value: proposal?.selected_behavior_id ? <code>{proposal.selected_behavior_id}</code> : "None" }, { label: "Selected Action", value: proposal?.selected_action_id ? <code>{proposal.selected_action_id}</code> : "None" }, { label: "Observed outcome", value: sentence(String(record.outcome ?? proposal?.selected_edge?.outcome ?? "not reported")) }, { label: "Policy", value: sentence(String(policy.status ?? "not reported")) }]} />{proposal?.selected_edge ? <p className="field-note">Exact registered edge: <code>{proposal.selected_edge.from_step} / {proposal.selected_edge.outcome} / {proposal.selected_edge.to_step}</code></p> : null}{proposal?.parameter_changes?.length ? <details><summary>Typed primitive parameter changes</summary><pre>{JSON.stringify(proposal.parameter_changes, null, 2)}</pre></details> : null}</article>;
    })}</div>
    <p className="field-note">Auto can execute an alternative only inside an explicitly reviewed method set. Legacy exact-plan changes and Assist proposals require a fresh review. Selection alone does not establish dispatch, successful effects or independent verification.</p>
  </Panel>;
}
