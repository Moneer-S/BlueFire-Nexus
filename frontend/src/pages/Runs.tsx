import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Activity, AlertTriangle, CircleStop, Clock3, FileSearch, Gauge, ListTree, Pause, Play, RotateCcw, ShieldCheck, Sparkles, TerminalSquare } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useLocation, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { api, ApiError, DEMO_MODE } from "../lib/api";
import { comparisonLink, detectionLink } from "../lib/run-handoffs";
import { methodComparisonLink } from "../lib/method-comparison";
import { collectionObservationSteps, collectionObserverSelection, collectionSemanticsCollector } from "../lib/collection-observation";
import { ExecuteOnboarding, GUIDED_EXECUTE_PROFILE_ID, GUIDED_EXECUTE_SCENARIO_ID, guidedExecuteConfiguration, isExecuteRunnerReady } from "../components/ExecuteOnboarding";
import { ProposalReviewWorkspace } from "../components/ProposalReview";
import { useProduct } from "../state/ProductContext";
import type { AIProposalDecisionResult, AIProposalReview, AutonomyLevel, CatalogResponse, PreflightReport, RunConfiguration, RunEventPage, RunJob, RunRecord, RunStep, Scenario } from "../types";
import { Badge, Button, Callout, DataList, ErrorState, Field, LoadingState, PageHeader, Panel, PanelHeader, formatDate, sentence } from "../components/Primitives";

import { CanonicalPlanReview } from "../components/CanonicalPlanReview";
import { continuationApprovalPreflight, hasUsableStoredApprovalReview } from "../lib/approvalReview";
import { settlePendingReplay } from "../lib/replay-submission";

import { objectiveLabel, runLabel, stepOutcomeLabel } from "../lib/run-presentation";

import "./Runs.css";

const terminalJobStates = new Set<RunJob["state"]>(["cancelled", "completed", "failed", "interrupted"]);
const approvalBindingFields = ["state_digest", "plan_digest", "target_scope_digest", "profile_id", "maximum_tier"] as const;
const activeJobStorageKey = "bluefire.local.active-job-id.v1";
const activeJobInventoryUnavailableNotice = "Active-job inventory is unavailable. New preflight and submission remain disabled until it is restored.";
const durableJobId = /^job-[0-9a-f]{32}$/;

function isRetryableInterruptedJob(job: RunJob | null | undefined): boolean {
  return job?.schema_version === "bluefire.job.v1" && ["scenario.run", "scenario.replay"].includes(job.kind) && job.state === "interrupted" && !job.request?.method_comparison;
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

function configurationForMode(config: RunConfiguration, mode: RunConfiguration["mode"], catalog: CatalogResponse, scenario: Scenario): RunConfiguration {
  if (config.mode === mode) return config;
  const profile = catalog.runner_profiles.find((item) => item.mode === mode && (mode !== "execute" || item.id === "sandbox-execute.v1"));
  return { ...config, mode, profileId: profile?.id ?? "", collectors: collectionObserverSelection(config, mode === "execute" && collectionObservationSteps(scenario).length > 0), approved: false, approvedBy: "" };
}

export function RunsPage() {
  const { runId } = useParams<{ runId?: string }>();
  const location = useLocation();
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const requestedJob = searchParams.get("job");
  const linkedJobId = requestedJob && durableJobId.test(requestedJob) ? requestedJob : null;
  const catalog = useQuery({ queryKey: ["catalog"], queryFn: api.catalog });
  const runsQuery = useQuery({ queryKey: ["runs"], queryFn: api.runs });
  const scenariosQuery = useQuery({ queryKey: ["scenarios"], queryFn: api.scenarios });
  const runnerLifecycleQuery = useQuery({ queryKey: ["runner-lifecycle"], queryFn: api.runnerStatus });
  const historicalRunQuery = useQuery({ queryKey: ["run", runId], queryFn: () => api.runDetail(runId!), enabled: Boolean(runId) });
  const { scenario, setScenario, dirty, runConfig, setRunConfig, clearApproval, activeRun, setActiveRun } = useProduct();
  const queryClient = useQueryClient();
  const [preflight, setPreflight] = useState<PreflightReport>(); const [notice, setNotice] = useState<string>();
  const [activeJob, setActiveJob] = useState<RunJob | null>(null); const [activeJobId, setActiveJobId] = useState<string | null>(() => linkedJobId ?? readStoredActiveJobId()); const [jobPreflight, setJobPreflight] = useState<PreflightReport>(); const [approvalRequest, setApprovalRequest] = useState<Record<string, unknown> | null>(null);
  const [knownTerminalJobIds, setKnownTerminalJobIds] = useState<ReadonlySet<string>>(() => new Set(queryClient.getQueriesData<RunJob>({ queryKey: ["job"] }).flatMap(([, job]) => job && terminalJobStates.has(job.state) ? [job.job_id] : [])));
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
  const setupMode = searchParams.has("setup") ? searchParams.get("setup") : location.hash === "#guided-execute" ? "execute" : null;
  const hasJobLink = searchParams.has("job");
  useEffect(() => {
    // Internal selection already installed this exact job and its fresh review.
    if (!linkedJobId || displayedJobIdRef.current === linkedJobId) return;
    activeJobIdRef.current = linkedJobId; activeJobRef.current = null; displayedJobIdRef.current = null;
    setActiveJobId(linkedJobId); storeActiveJobId(linkedJobId); setActiveJob(null);
    setJobPreflight(undefined); setApprovalRequest(null); setActiveProposalReview(undefined);
    setJobApprovalConfirmed(false); setJobApprovedBy(""); setLiveEvents([]); setActiveRun(null);
  }, [linkedJobId, setActiveRun]);
  const followJobUrl = useCallback((jobId: string) => {
    if (runId || !searchParams.has("job") || searchParams.get("job") === jobId) return;
    setSearchParams((current) => { const next = new URLSearchParams(current); next.set("job", jobId); return next; }, { replace: true });
  }, [runId, searchParams, setSearchParams]);
  const activeJobsQuery = useQuery({ queryKey: ["active-jobs"], queryFn: api.activeJobs, refetchInterval: 750, staleTime: 0 });
  const inventoryAuthoritative = activeJobsQuery.isSuccess && activeJobsQuery.isFetchedAfterMount && Boolean(activeJobsQuery.data);
  const inventoryJobs = useMemo(() => inventoryAuthoritative ? activeJobsQuery.data!.jobs : [], [activeJobsQuery.data, inventoryAuthoritative]);
  const selectableInventoryJobs = useMemo(() => inventoryJobs.filter((job) => !terminalJobStates.has(job.state) && !knownTerminalJobIds.has(job.job_id)), [inventoryJobs, knownTerminalJobIds]);
  const inventoryUnavailable = !inventoryAuthoritative;
  const controllerOwnsActiveJob = Boolean(activeJob && inventoryAuthoritative && inventoryJobs.some((job) => job.job_id === activeJob.job_id));
  const retryInventoryReady = inventoryAuthoritative && inventoryJobs.length === 0;
  const jobActivityBlocksNewIntent = inventoryUnavailable || inventoryJobs.length > 0 || Boolean(activeJobId) || Boolean(activeJob && !terminalJobStates.has(activeJob.state));
  const alternateInventoryJobAvailable = selectableInventoryJobs.some((job) => job.job_id !== activeJobId);
  useEffect(() => {
    if (consumedSetupArrival.current === location.key || (setupMode !== "simulate" && setupMode !== "execute")) return;
    // A setup link never changes a selected durable job or historical review.
    // Consume blocked arrivals too, so later job settlement cannot apply them.
    if (runId || hasJobLink || activeJobId || activeJob || selectableInventoryJobs.length) { consumedSetupArrival.current = location.key; return; }
    if (!catalog.data || !inventoryAuthoritative) return;
    consumedSetupArrival.current = location.key;
    const next = configurationForMode(runConfig, setupMode, catalog.data, scenario);
    if (next !== runConfig) {
      setRunConfig(next);
      preflightGeneration.current += 1;
      setPreflight(undefined);
    }
  }, [activeJob, activeJobId, catalog.data, hasJobLink, inventoryAuthoritative, location.key, runConfig, runId, scenario, selectableInventoryJobs.length, setRunConfig, setupMode]);
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
      if (isRetryableInterruptedJob(job)) storeActiveJobId(job.job_id); else clearStoredActiveJobId(job.job_id);
    } else {
      activeJobIdRef.current = job.job_id;
      setActiveJobId(job.job_id);
      storeActiveJobId(job.job_id);
    }
  }, [followJobUrl, rememberTerminalJob]);
  const selectInventoryJob = useCallback((job: RunJob) => {
    displayedJobIdRef.current = job.job_id;
    activeJobIdRef.current = job.job_id;
    activeJobRef.current = job;
    setActiveJobId(job.job_id);
    storeActiveJobId(job.job_id);
    setActiveJob(job);
    followJobUrl(job.job_id);
    setJobPreflight(undefined);
    setApprovalRequest(null);
    setActiveProposalReview(undefined);
    setJobApprovalConfirmed(false);
    setJobApprovedBy("");
    setLiveEvents([]);
    setActiveRun(null);
  }, [followJobUrl, setActiveRun]);
  const synchronizeJobSnapshot = useCallback(async (job: RunJob): Promise<RunJob> => {
    await queryClient.cancelQueries({ queryKey: ["job", job.job_id], exact: true });
    let snapshot = preferNewerJobSnapshot(queryClient.getQueryData<RunJob>(["job", job.job_id]), job);
    if (activeJobRef.current?.job_id === job.job_id) snapshot = preferNewerJobSnapshot(activeJobRef.current, snapshot);
    rememberTerminalJob(snapshot);
    queryClient.setQueryData(["job", job.job_id], snapshot);
    void queryClient.invalidateQueries({ queryKey: ["job", job.job_id], exact: true });
    return snapshot;
  }, [queryClient, rememberTerminalJob]);
  const jobQuery = useQuery({ queryKey: ["job", activeJobId], queryFn: async () => { const requestedJobId = activeJobId!; const receivedJob = await api.job(requestedJobId); if (receivedJob.job_id !== requestedJobId) throw new ApiError("The job detail response did not match the requested job.", "job_identity_mismatch", undefined, 502); settlePendingReplay(receivedJob); let job = preferNewerJobSnapshot(queryClient.getQueryData<RunJob>(["job", requestedJobId]), receivedJob); if (activeJobRef.current?.job_id === requestedJobId) job = preferNewerJobSnapshot(activeJobRef.current, job); rememberTerminalJob(job); return job; }, enabled: Boolean(activeJobId && (!activeJob || (activeJob.job_id === activeJobId && !terminalJobStates.has(activeJob.state)))), refetchInterval: (query) => { const state = (query.state.data as RunJob | undefined)?.state; return state && terminalJobStates.has(state) ? false : 750; }, staleTime: 0 });
  const refetchJob = jobQuery.refetch;
  const ordinaryApprovalNeedsPreflight = Boolean(controllerOwnsActiveJob && activeJob?.state === "awaiting_approval" && !["ai_proposal", "ai_proposal_execute"].includes(String(activeJob.progress.approval_kind ?? "")) && !hasUsableStoredApprovalReview(jobPreflight));
  const storedJobPreflightQuery = useQuery({ queryKey: ["job-preflight", activeJob?.job_id, activeJob?.request?.approval_request_id], queryFn: async () => ({ jobId: activeJob!.job_id, report: await api.preflightStoredJobRequest(activeJob!) }), enabled: ordinaryApprovalNeedsPreflight, staleTime: 0 });
  const unusableStoredJobPreflight = Boolean(storedJobPreflightQuery.isSuccess && storedJobPreflightQuery.data?.jobId === activeJob?.job_id && !hasUsableStoredApprovalReview(storedJobPreflightQuery.data.report));
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
    if (candidates[0]) {
      selectInventoryJob(candidates[0]);
      return;
    }
    if (!activeJobId) return;
    missingInventoryReconciliation.current = null;
    clearStoredActiveJobId(activeJobId);
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
  }, [activeJob, activeJobId, inventoryAuthoritative, refetchJob, selectableInventoryJobs, selectInventoryJob]);
  useEffect(() => { if (activeJobsQuery.error) setNotice(activeJobInventoryUnavailableNotice); else if (inventoryAuthoritative) setNotice((current) => current === activeJobInventoryUnavailableNotice ? undefined : current); }, [activeJobsQuery.error, inventoryAuthoritative]);
  useEffect(() => {
    if (activeJobIdRef.current !== activeJobId || !jobQuery.isFetchedAfterMount || !jobQuery.isSuccess || !jobQuery.data || jobQuery.data.job_id !== activeJobId) return;
    const receivedJob = jobQuery.data;
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
    trackActiveJob(snapshot);
    if (snapshot.approval_request !== undefined) setApprovalRequest(snapshot.approval_request);
  }, [activeJobId, linkedJobId, inventoryAuthoritative, inventoryJobs, jobQuery.data, jobQuery.isFetchedAfterMount, jobQuery.isSuccess, rememberTerminalJob, trackActiveJob]);
  useEffect(() => { if (activeJobIdRef.current === activeJobId && jobQuery.isFetchedAfterMount && jobQuery.error) { const definitivelyMissing = jobQuery.error instanceof ApiError && jobQuery.error.status === 404 && jobQuery.error.code === "job_not_found"; const inventoryStillOwnsJob = Boolean(activeJobId && inventoryJobs.some((job) => job.job_id === activeJobId)); if (definitivelyMissing && activeJobId && inventoryAuthoritative && !inventoryStillOwnsJob) { clearStoredActiveJobId(activeJobId); setActiveJobId(null); if (activeJob?.job_id === activeJobId) setActiveJob(null); } setNotice(jobQuery.error instanceof Error ? jobQuery.error.message : "Job status could not be refreshed."); } }, [activeJob?.job_id, activeJobId, inventoryAuthoritative, inventoryJobs, jobQuery.error, jobQuery.isFetchedAfterMount]);
  useEffect(() => { if (storedJobPreflightQuery.isFetchedAfterMount && storedJobPreflightQuery.data && storedJobPreflightQuery.data.jobId === activeJob?.job_id) setJobPreflight(hasUsableStoredApprovalReview(storedJobPreflightQuery.data.report) ? storedJobPreflightQuery.data.report : undefined); }, [activeJob?.job_id, storedJobPreflightQuery.data, storedJobPreflightQuery.isFetchedAfterMount]);
  useEffect(() => { if (storedJobPreflightQuery.isFetchedAfterMount && storedJobPreflightQuery.error) setNotice(storedJobPreflightQuery.error instanceof Error ? storedJobPreflightQuery.error.message : "The durable job approval review could not be restored."); }, [storedJobPreflightQuery.error, storedJobPreflightQuery.isFetchedAfterMount]);
  useEffect(() => { setLiveEvents([]); }, [activeJob?.job_id]);
  useEffect(() => { if (eventsQuery.data?.items.length) setLiveEvents((current) => { const merged = new Map(current.map((event) => [event.sequence, event])); for (const event of eventsQuery.data.items) merged.set(event.sequence, event); return [...merged.values()].sort((left, right) => left.sequence - right.sequence); }); }, [eventsQuery.data]);
  useEffect(() => { if (eventsQuery.error) setNotice(eventsQuery.error instanceof Error ? eventsQuery.error.message : "Live event polling failed."); }, [eventsQuery.error]);
  useEffect(() => { if (resultQuery.data && resultQuery.data.run_id === resultRunId && activeJobRef.current?.result_ref === resultRunId) { setActiveRun(resultQuery.data); setNotice(`Run ${resultQuery.data.run_id} is ${sentence(resultQuery.data.status).toLowerCase()}; its canonical record is ready for review.`); queryClient.invalidateQueries({ queryKey: ["runs"] }); } }, [queryClient, resultQuery.data, resultRunId, setActiveRun]);
  useEffect(() => { setJobApprovalConfirmed(false); setJobApprovedBy(""); }, [activeJob?.job_id, activeJob?.progress.approval_kind, activeJob?.progress.approval_request_id, activeJob?.request?.approval_request_id, approvalRequest?.approval_id, approvalRequest?.status, approvalRequest?.state_digest, approvalRequest?.plan_digest, approvalRequest?.target_scope_digest, approvalRequest?.profile_id, approvalRequest?.maximum_tier]);
  useEffect(() => { setJobApprovalConfirmed(false); setJobApprovedBy(""); }, [activeProposalReview?.execute_approval_review?.approval_request_id, activeProposalReview?.execute_approval_review?.preflight.approval_envelope?.envelope_digest]);
  const preflightMutation = useMutation({ mutationFn: async (attempt: RunPreflightAttempt) => ({ generation: attempt.generation, report: await api.preflight(attempt.scenario, attempt.config) }), onSuccess: ({ generation, report }) => { if (generation !== preflightGeneration.current) return; setPreflight(report); setNotice(report.ready ? "Preflight resolved the current policy envelope." : report.status === "approval_required" && report.approval_binding && report.approval_envelope ? "Preflight resolved the exact Execute envelope. Review it before creating an approval-gated job." : "Preflight did not authorize this intent."); }, onError: (error, attempt) => { if (attempt.generation !== preflightGeneration.current) return; setPreflight(undefined); setNotice(error instanceof Error ? error.message : "Preflight failed."); }, onSettled: (_result, _error, attempt) => { if (attempt.generation === preflightGeneration.current) clearApproval(); } });
  const requestPreflight = () => { if (jobActivityBlocksNewIntent) { setNotice("Active-job inventory must be available and empty before starting another preflight."); return; } const generation = ++preflightGeneration.current; preflightMutation.mutate({ generation, scenario: structuredClone(scenario), config: structuredClone(runConfig) }); };
  const invalidatePreflight = () => { preflightGeneration.current += 1; setPreflight(undefined); };
  const runMutation = useMutation({ mutationFn: () => api.submitRun(scenario, runConfig), onMutate: () => { setNotice(runConfig.mode === "simulate" ? "Submitting a durable Simulate job." : "Creating a durable Execute job with a separate approval gate."); setActiveRun(null); }, onSuccess: async (submission) => { const snapshot = await synchronizeJobSnapshot({ ...submission.job, approval_request: submission.approval_request ?? submission.job.approval_request }); trackActiveJob(snapshot); setJobPreflight(submission.preflight ?? undefined); setApprovalRequest(snapshot.approval_request ?? null); setNotice(`Job ${snapshot.job_id} was accepted in ${sentence(snapshot.state)} state.`); void queryClient.invalidateQueries({ queryKey: ["active-jobs"] }); void queryClient.invalidateQueries({ queryKey: ["runs"] }); }, onError: (error) => setNotice(error instanceof Error ? error.message : "Job submission was refused."), onSettled: clearApproval });
  const approvalMutation = useMutation({ mutationFn: ({ jobId, approvedBy }: { jobId: string; approvedBy: string }) => api.approveJob(jobId, approvedBy), onSuccess: async (result, variables) => { const snapshot = await synchronizeJobSnapshot({ ...result.job, approval_request: result.approval_request ?? result.job.approval_request }); void queryClient.invalidateQueries({ queryKey: ["active-jobs"] }); if (activeJobIdRef.current !== variables.jobId || snapshot.job_id !== variables.jobId) return; trackActiveJob(snapshot); setApprovalRequest(snapshot.approval_request ?? null); setNotice(`The exact envelope for ${snapshot.job_id} was approved once and released to the job controller.`); }, onError: (error, variables) => { if (activeJobIdRef.current === variables.jobId) setNotice(error instanceof Error ? error.message : "Job approval was refused."); }, onSettled: (_result, _error, variables) => { if (activeJobIdRef.current !== variables.jobId) return; setJobApprovalConfirmed(false); setJobApprovedBy(""); clearApproval(); } });
  const runnerLifecycleMutation = useMutation({ mutationFn: (action: "bootstrap" | "start") => action === "bootstrap" ? api.bootstrapRunner(GUIDED_EXECUTE_PROFILE_ID) : api.startRunner(GUIDED_EXECUTE_PROFILE_ID), onSuccess: (status) => { queryClient.setQueryData(["runner-lifecycle"], status); setNotice(status.state === "ready" ? "The packaged runner is authenticated and ready for the guided Execute path." : "The packaged runner and recoverable local trust are verified. Start the authenticated host next."); }, onError: (error) => setNotice(error instanceof Error ? error.message : "The guided runner action was refused.") });
  const controlMutation = useMutation({ mutationFn: ({ jobId, action }: { jobId: string; action: "pause" | "resume" | "cancel" }) => api.controlJob(jobId, action), onSuccess: async (job, variables) => { const snapshot = await synchronizeJobSnapshot(job); void queryClient.invalidateQueries({ queryKey: ["active-jobs"] }); if (activeJobIdRef.current !== variables.jobId || snapshot.job_id !== variables.jobId) return; trackActiveJob(snapshot); setNotice(`${sentence(variables.action)} was requested for ${snapshot.job_id}; the durable state is ${sentence(snapshot.state)}.`); }, onError: (error, variables) => { if (activeJobIdRef.current === variables.jobId) setNotice(error instanceof Error ? error.message : "Job control request was refused."); } });
  const retryMutation = useMutation({ mutationFn: (jobId: string) => api.retryJob(jobId), onSuccess: async (result, sourceJobId) => { const snapshot = await synchronizeJobSnapshot({ ...result.job, approval_request: result.approval_request ?? result.job.approval_request }); void queryClient.invalidateQueries({ queryKey: ["active-jobs"] }); if (displayedJobIdRef.current !== sourceJobId || result.retry_of_job_id !== sourceJobId) return; clearStoredActiveJobId(sourceJobId); setJobApprovalConfirmed(false); setJobApprovedBy(""); trackActiveJob(snapshot); setJobPreflight(result.preflight ?? undefined); setApprovalRequest(snapshot.approval_request ?? null); setActiveProposalReview(undefined); setNotice(`Replacement job ${snapshot.job_id} was created from interrupted job ${result.retry_of_job_id}. The source remains immutable.`); }, onError: (error, sourceJobId) => { if (displayedJobIdRef.current === sourceJobId) setNotice(error instanceof Error ? error.message : "The interrupted job could not be retried safely."); } });
  const handleProposalDecision = (result: AIProposalDecisionResult, review: AIProposalReview) => { void synchronizeJobSnapshot({ ...result.job, approval_request: result.approval_request ?? result.job.approval_request }).then((snapshot) => { void queryClient.invalidateQueries({ queryKey: ["active-jobs"] }); if (activeJobIdRef.current !== snapshot.job_id) return; trackActiveJob(snapshot); setActiveProposalReview(review); setApprovalRequest(snapshot.approval_request ?? null); if (snapshot.progress.approval_kind === "ai_proposal_execute") setJobPreflight(undefined); setNotice(snapshot.progress.approval_kind === "ai_proposal_execute" ? "The registered proposal was accepted. Execute remains stopped at a new, separately bound one-time approval stage." : `The proposal was ${review.status}; durable job state is ${sentence(snapshot.state)}.`); }); };
  if (catalog.isPending || (runId && historicalRunQuery.isPending)) return <LoadingState label={runId ? "Loading canonical run review" : "Loading run controls"} />;
  if (catalog.isError) return <ErrorState error={catalog.error} retry={() => catalog.refetch()} />;
  if (runId && historicalRunQuery.isError) return <div className="page runs-page"><PageHeader eyebrow="Run history" title="Canonical run unavailable" description="The requested run could not be loaded from durable history." actions={<Link to="/runs"><Button variant="secondary">Back to run workspace</Button></Link>} /><ErrorState error={historicalRunQuery.error} retry={() => historicalRunQuery.refetch()} /></div>;
  if (runId && historicalRunQuery.data) return <HistoricalRunReview run={historicalRunQuery.data} catalog={catalog.data} />;
  const configReady = runConfig.mode === "simulate" || Boolean(runConfig.profileId && runConfig.approved && runConfig.approvedBy.trim());
  const preflightCanAuthorize = Boolean(preflight?.ready || (runConfig.mode === "execute" && preflight?.status === "approval_required" && preflight.approval_binding && preflight.approval_envelope));
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
  const nextPreflightPrimary = !preflightCanAuthorize && !activeJob && Boolean(scenario.steps.length) && (runConfig.mode === "simulate" || isExecuteRunnerReady(runnerLifecycleQuery.data));
  const submissionControls = <div className="run-action-bar"><div>{activeJob ? <Badge tone={statusTone(activeJob.state)} dot>{sentence(activeJob.state)}</Badge> : <Badge tone={preflight?.ready ? "success" : preflight?.status === "approval_required" ? "warning" : preflight ? "danger" : "neutral"} dot>{preflight?.ready ? "Ready" : preflight?.status === "approval_required" ? runConfig.approved ? "Envelope acknowledged locally" : "Envelope ready for review" : preflight ? sentence(preflight.status) : "Preflight required"}</Badge>}<span>{runConfig.mode === "simulate" ? "No external behavior effects" : "Job creation and one-time durable approval remain separate"}</span></div><Button variant={nextPreflightPrimary ? "primary" : "secondary"} onClick={requestPreflight} disabled={preflightMutation.isPending || !scenario.steps.length || jobActivityBlocksNewIntent}>{preflightMutation.isPending ? <Activity className="spin"/> : <ShieldCheck/>}Run preflight</Button><Button variant={canStart && (runConfig.mode === "simulate" || isExecuteRunnerReady(runnerLifecycleQuery.data)) ? "primary" : "secondary"} onClick={() => runMutation.mutate()} disabled={!canStart}>{runMutation.isPending ? <Activity className="spin"/> : <Play/>}{runMutation.isPending ? "Submitting job" : runConfig.mode === "execute" ? "Create approval-gated job" : "Submit Simulate job"}</Button></div>;
  const showLiveWorkspace = Boolean(activeJob || activeRun || activeJobId || runMutation.isPending);

  return <div className="page runs-page">
    <PageHeader eyebrow="Run control" title={linkedJobId ? "Follow this run" : "Review and run"} description={linkedJobId ? "Review its saved plan, follow progress, and inspect the result." : "Choose your environment, run preflight, and review what will happen."} actions={<div className="view-toggle" role="tablist" aria-label="Run workspace views"><button role="tab" aria-selected="true">Configure & live</button><button role="tab" aria-selected="false" onClick={() => activeRun && navigate(runReviewPath(activeRun.run_id))} disabled={!activeRun}>Review latest</button></div>} />
    {notice ? <Callout tone={runMutation.isError || approvalMutation.isError || runnerLifecycleMutation.isError || controlMutation.isError || activeJobsQuery.isError || jobQuery.isError || eventsQuery.isError || resultQuery.isError ? "danger" : preflight && !preflight.ready ? "warning" : "info"} title="Control-plane status">{notice}</Callout> : null}
    {methodComparisonLink(activeJob) ? <Callout title="Part of your method test"><p>This replay belongs to the reviewed comparison workflow. Its saved rule will be evaluated against both runs.</p><Link className="button button-secondary button-medium" to={methodComparisonLink(activeJob)!}>Return to method test and results</Link>{activeJob && terminalJobStates.has(activeJob.state) && activeJob.state !== "completed" ? <p>Inspect the retained result and recover comparison work there. This run will not be replayed by a comparison retry.</p> : null}</Callout> : null}
    <>
      <details className="run-draft-details" open={!linkedJobId}><summary>Experiment setup</summary>{runConfig.mode === "execute" ? <ExecuteOnboarding submissionControls={submissionControls} profile={guidedProfile} seededScenario={guidedScenario} selectedScenario={scenario} config={runConfig} runner={runnerLifecycleQuery.data} runnerPending={runnerLifecycleQuery.isPending} runnerError={runnerLifecycleQuery.error} runnerActionPending={runnerLifecycleMutation.isPending} preflight={preflight} preflightPending={preflightMutation.isPending} preflightDisabled={jobActivityBlocksNewIntent} job={activeJob} approvalReleased={["consumed", "claimed"].includes(String(approvalRequest?.status ?? ""))} run={activeRun} jobSubmissionPending={runMutation.isPending} canCreateJob={canStart} demoMode={DEMO_MODE} onRunnerAction={(action) => runnerLifecycleMutation.mutate(action)} onSelectScenario={selectGuidedScenario} onPreflight={requestPreflight} onCreateJob={() => runMutation.mutate()} onReviewEnvelope={() => scrollToGuideTarget("execute-envelope-review")} onReviewApproval={() => scrollToGuideTarget("durable-execute-approval")} /> : null}
      {runConfig.mode === "simulate" ? submissionControls : null}
      <div className="run-layout"><RunConfigurationPanel scenario={scenario} config={runConfig} onChange={updateConfiguration} catalog={catalog.data} preflight={preflight} /><PlanPreview scenarioTitle={scenario.title} stepIds={scenario.steps.map((step) => step.id)} edgeCount={scenario.edges.length} dirty={dirty} config={runConfig} catalog={catalog.data} preflight={preflight} /></div>
      {preflight?.plan ? <div className="run-exact-review" id="execute-envelope-review" tabIndex={-1}><CanonicalPlanReview plan={preflight.plan} cleanup={preflight.cleanup} scope={preflight.scope} binding={preflight.approval_binding} envelope={preflight.approval_envelope} /></div> : null}
      {runConfig.mode === "execute" && hasLocalExecuteReview(preflight) ? <LocalExecuteReview config={runConfig} onChange={updateConfiguration} preflight={preflight} /> : null}
      </details>{activeJob?.kind === "scenario.replay" && typeof activeJob.request?.source_run_id === "string" ? <p>Replay of <Link to={runReviewPath(activeJob.request.source_run_id)}>the original run</Link>. Approval and progress belong to this saved replay.</p> : null}{alternateInventoryJobAvailable ? <Panel><PanelHeader eyebrow="Active controller inventory" title="Choose an active durable job" detail="Every controller-owned job remains available after navigation or reload." actions={<Badge tone="warning">{selectableInventoryJobs.length} active</Badge>} /><div className="detail-body"><Field label="Active durable job"><select value={selectableInventoryJobs.some((job) => job.job_id === activeJobId) ? activeJobId ?? "" : ""} onChange={(event) => { const selected = selectableInventoryJobs.find((job) => job.job_id === event.target.value); if (selected) selectInventoryJob(selected); }}><option value="" disabled>Select an active job</option>{selectableInventoryJobs.map((job) => <option key={job.job_id} value={job.job_id}>{sentence(job.state)} · {job.job_id}</option>)}</select></Field></div></Panel> : null}
      {(storedJobPreflightQuery.isError || unusableStoredJobPreflight) && ordinaryApprovalNeedsPreflight ? <Callout tone="danger" title="Exact approval review unavailable"><p>The active job remains controllable, but approval stays disabled until its canonical stored request returns an exact approval-required plan, binding, and envelope.</p><Button size="small" variant="secondary" disabled={storedJobPreflightQuery.isFetching} onClick={() => { void storedJobPreflightQuery.refetch(); }}><RotateCcw/>{storedJobPreflightQuery.isFetching ? "Retrying approval review" : "Retry approval review"}</Button></Callout> : null}
      {showLiveWorkspace ? <LiveConsole run={activeRun} job={activeJob} events={liveEvents} pending={runMutation.isPending || Boolean(resultRunId && resultQuery.isPending) || Boolean(activeJob && !terminalJobStates.has(activeJob.state))} config={runConfig} approvalPreflight={jobPreflight} approvalRequest={approvalRequest} proposalReview={activeProposalReview} approvalConfirmed={jobApprovalConfirmed} approvedBy={jobApprovedBy} approvalPending={approvalMutation.isPending} controlPending={controlMutation.isPending || retryMutation.isPending} mutableControlsEnabled={controllerOwnsActiveJob} retryEnabled={retryInventoryReady} onApprovalConfirmed={setJobApprovalConfirmed} onApprovedBy={setJobApprovedBy} onApprove={() => activeJob && controllerOwnsActiveJob && approvalMutation.mutate({ jobId: activeJob.job_id, approvedBy: jobApprovedBy })} onControl={(action) => activeJob && controllerOwnsActiveJob && controlMutation.mutate({ jobId: activeJob.job_id, action })} onRetry={() => activeJob && retryInventoryReady && isRetryableInterruptedJob(activeJob) && retryMutation.mutate(activeJob.job_id)} onProposalDecision={handleProposalDecision} onProposalReviewLoaded={setActiveProposalReview} onReview={() => activeRun && navigate(runReviewPath(activeRun.run_id))} /> : null}
      {activeRun && activeJob?.kind === "scenario.replay" && activeJob.result_ref === activeRun.run_id && typeof activeJob.request?.source_run_id === "string" ? <Link className="button button-primary button-medium" to={comparisonLink(activeJob.request.source_run_id, activeRun.run_id)}>Compare with original run</Link> : null}<RunHistoryPanel runs={runsQuery.data?.runs} pending={runsQuery.isPending} error={runsQuery.error} retry={() => runsQuery.refetch()} />
    </>
  </div>;
}

function HistoricalRunReview({ run, catalog }: { run: RunRecord; catalog: CatalogResponse }) {
  return <div className="page runs-page">
    <PageHeader eyebrow="Run review" title={runLabel(run)} description={`${sentence(run.mode)} · ${sentence(run.status)} · ${formatDate(run.finalized_at ?? run.created_at)}`} actions={<><Link to="/runs"><Button variant="secondary">Back to run workspace</Button></Link><Link to={detectionLink(run.run_id)}><Button variant="secondary">Open Detection Lab</Button></Link><Link to={comparisonLink(run.run_id)}><Button variant={typeof run.replay?.source_run_id === "string" ? "secondary" : "primary"}>Replay & compare</Button></Link>{typeof run.replay?.source_run_id === "string" ? <Link className="button button-primary button-medium" to={comparisonLink(run.replay.source_run_id, run.run_id)}>Compare with original run</Link> : null}</>} />
    <RunReview run={run} catalog={catalog} />
  </div>;
}

function RunHistoryPanel({ runs, pending, error, retry }: { runs?: RunRecord[]; pending: boolean; error: unknown; retry: () => void }) {
  const history = runs ?? [];
  return <Panel>
    <PanelHeader title="Run history" detail="Reopen a result to inspect evidence, test a detection, or prepare a replay." actions={<Button size="small" variant="ghost" onClick={retry}><RotateCcw/>Refresh</Button>} />
    {pending ? <LoadingState label="Loading canonical run history" /> : error ? <ErrorState title="Run history unavailable" error={error} retry={retry} /> : history.length ? <div className="table-scroll"><table><thead><tr><th>Experiment</th><th>Mode</th><th>Created</th><th>Status</th></tr></thead><tbody>{history.map((run) => <tr key={run.run_id}><td><Link to={runReviewPath(run.run_id)} aria-label={`Review canonical run ${runLabel(run)} (${shortId(run.run_id)})`}><strong>{runLabel(run)}</strong><br/><code title={run.run_id}>{shortId(run.run_id)}</code></Link>{run.is_demo ? <Badge tone="violet">Demo</Badge> : null}</td><td><Badge tone={run.mode === "execute" ? "warning" : "info"}>{sentence(run.mode)}</Badge></td><td>{formatDate(run.created_at)}</td><td><Badge tone={run.status === "completed" ? "success" : "neutral"} dot>{sentence(run.status)}</Badge></td></tr>)}</tbody></table></div> : <div className="inline-empty"><span>No runs yet.</span><span>Start with Simulate to explore an experiment without lab effects.</span></div>}
  </Panel>;
}

function runReviewPath(runId: string) { return `/runs/${encodeURIComponent(runId)}`; }
function shortId(value: string) { return value.length > 22 ? `${value.slice(0, 10)}…${value.slice(-8)}` : value; }
function cleanupSummary(cleanup: RunRecord["cleanup"]) {
  if (cleanup === true) return "Complete";
  if (cleanup === false) return "Needs attention";
  if (!cleanup) return "Not recorded";
  const count = cleanup.outstanding_receipt_count ?? cleanup.outstanding_effects;
  const outstanding = typeof count === "number" ? count : undefined;
  if (outstanding !== undefined && outstanding > 0) return `Needs attention · ${outstanding} outstanding effect${outstanding === 1 ? "" : "s"}`;
  if (cleanup.success === false) return "Failed · cleanup needs attention";
  if (cleanup.success === true && outstanding === 0) return "Complete · no outstanding effects";
  if (cleanup.attempted === false) return "Not attempted";
  return typeof cleanup.status === "string" ? sentence(cleanup.status) : "Result not reported";
}

function RunConfigurationPanel({ scenario, config, onChange, catalog, preflight }: { scenario: Scenario; config: RunConfiguration; onChange: (config: RunConfiguration) => void; catalog: CatalogResponse; preflight?: PreflightReport }) {
  const set = <K extends keyof RunConfiguration>(key: K, value: RunConfiguration[K]) => onChange({ ...config, [key]: value });
  const collectionSteps = collectionObservationSteps(scenario);
  const selectMode = (mode: RunConfiguration["mode"]) => onChange(configurationForMode(config, mode, catalog, scenario));
  const profiles = catalog.runner_profiles.filter((profile) => profile.mode === config.mode);
  const selectedProfile = profiles.find((profile) => profile.id === config.profileId);
  const providers = catalog.ai.providers ?? [{ provider_id: catalog.ai.active_provider ?? "deterministic-offline.v1", kind: "deterministic", model: "deterministic-planner.v1", health: { state: catalog.ai.provider_health ?? "not_reported" } }];
  const selectedProvider = providers.find((provider) => provider.provider_id === config.provider) ?? providers[0];
  const providerHealth = selectedProvider?.health?.state ?? catalog.ai.provider_health ?? "not_reported";
  return <Panel className="run-config"><PanelHeader eyebrow="Intent" title="Run configuration" detail="Choose effects and scope. Preflight checks the exact plan before a job can start." />
    <div className="config-body">
      <fieldset><legend>Effect mode</legend><div className="choice-grid two">{(["simulate", "execute"] as const).map((mode) => <label key={mode}><input type="radio" name="run-mode" checked={config.mode === mode} onChange={() => selectMode(mode)}/><span><strong>{sentence(mode)}</strong><small>{mode === "simulate" ? "Synthetic evidence only" : "Approved runner actions"}</small></span></label>)}</div></fieldset>
      <div className="config-grid primary-environment">
        <Field label="Runner profile"><select value={config.profileId} onChange={(event) => set("profileId", event.target.value)}><option value="">Select profile</option>{profiles.map((profile) => <option key={profile.id}>{profile.id}</option>)}</select></Field>
        <Field label="Target scope" hint="Only these exact scope references may be used."><input value={config.scopeRefs.join(", ")} onChange={(event) => set("scopeRefs", event.target.value.split(",").map((item) => item.trim()).filter(Boolean))}/></Field>
      </div>
      <fieldset><legend>AI autonomy</legend><div className="choice-grid three">{(["off", "assist", "auto"] as AutonomyLevel[]).map((level) => <label key={level}><input type="radio" name="autonomy" checked={config.autonomy === level} onChange={() => set("autonomy", level)}/><span><strong>{sentence(level)}</strong><small>{level === "off" ? "Deterministic" : level === "assist" ? "Review proposal" : "Policy-valid Simulate choices"}</small></span></label>)}</div><p className="field-note">Off uses deterministic planning. Assist asks you to review proposals. Auto may apply allowed Simulate choices; Execute always needs separate approval.</p></fieldset>
      <details className="provider-details"><summary>AI provider & environment details</summary>
        <div className="config-grid">
          <Field label="Provider"><select value={selectedProvider?.provider_id ?? config.provider} onChange={(event) => { const provider = providers.find((item) => item.provider_id === event.target.value); onChange({ ...config, provider: event.target.value, model: provider?.model ?? "", endpoint: "" }); }}>{providers.map((provider) => <option value={provider.provider_id} key={provider.provider_id}>{provider.provider_id}</option>)}</select></Field>
          <div className="health-field"><span>Provider health</span><Badge tone={providerHealth === "ready" || providerHealth === "healthy" ? "success" : "warning"} dot>{sentence(providerHealth)}</Badge></div>
        </div>
        <DataList items={[{ label: "Model", value: selectedProvider?.model ?? config.model }, { label: "Endpoint and credentials", value: <Link to="/ai-planner">Configure providers</Link> }, { label: "Selected runner", value: "The profile resolves the active local enrollment. Manage it from Runners." }, { label: "Safety authority", value: selectedProfile?.safety_tiers.map(sentence).join(", ") ?? "Select a profile" }]} />
        <p className="field-note">Provider settings are managed by the local service. AI Off uses deterministic planning regardless of the selected provider.</p>
      </details>
      <details><summary>Policy, approval & budgets</summary><Callout title="Profile-owned enforcement">These values come from the selected canonical profile and are bound into preflight. Unsupported browser overrides are intentionally not shown.</Callout><DataList items={[{ label: "Approval", value: selectedProfile ? selectedProfile.approval_required ? "Required for Execute" : "Not required by profile" : "Select a profile" }, { label: "Cleanup", value: selectedProfile ? sentence(selectedProfile.cleanup_policy) : "Select a profile" }, { label: "Maximum steps", value: selectedProfile?.budgets.max_steps ?? "Select a profile" }, { label: "Maximum seconds", value: selectedProfile?.budgets.max_seconds ?? "Select a profile" }, { label: "Maximum artifacts", value: selectedProfile?.budgets.max_artifacts ?? "Select a profile" }, { label: "Maximum bytes", value: selectedProfile?.budgets.max_bytes ? `${Math.round(selectedProfile.budgets.max_bytes / 1_048_576)} MiB` : "Select a profile" }, { label: "Counterfactuals", value: "Planner-derived and always labeled; no unsupported browser switch" }]} />

        {config.mode === "execute" && !hasLocalExecuteReview(preflight) ? <LocalExecuteReview config={config} onChange={onChange} preflight={preflight} /> : null}
      </details>
      <details open={collectionSteps.length > 0 ? true : undefined}><summary>Observation & detection</summary><Callout title="Canonical records only">Execute binds selected per-run collectors into preflight and approval. Runner output remains executed evidence; observed records must come from a declared collector. Detection Lab validation is managed separately.</Callout><div className="choice-grid two">{["collector.filesystem.sandbox.v1"].map((collector) => <label key={collector}><input type="checkbox" checked={config.collectors.includes(collector)} disabled/><span><strong>{collector}</strong><small>Required Execute collector for declared sandbox artifacts</small></span></label>)}</div>
        <label className="check-row"><input type="checkbox" checked={config.collectors.includes(collectionSemanticsCollector)} disabled={config.mode !== "execute"} onChange={(event) => set("collectors", collectionObserverSelection(config, event.target.checked))}/><span><strong>Collection contents (bounded synthetic records)</strong><small>Independently reads the staged file after each reviewed collection step, hashes the same bytes, and records retained/redacted counts without record values. Other action types are skipped.</small></span></label>{collectionSteps.length > 0 ? <DataList items={collectionSteps.map((step) => ({ label: `After ${step.stepId}`, value: step.path }))}/> : null}<p className="field-note">The server derives the exact path and schedule from the approved native collection method and parameters, including a signed package binding. A compatible replay uses its own approved output path. Missing contents observation leaves a compatible collection experiment incomplete.</p>
        <DataList items={[{ label: "Runner results", value: "Executed evidence, never observed" }, { label: "Independent observation", value: preflight?.collectors?.join(", ") || (config.mode === "execute" ? config.collectors.join(", ") : "Execute only") }, { label: "Unavailable collection", value: "Rejected before Execute or recorded as unknown evidence" }, { label: "Detection lifecycle", value: "Managed in Detection Lab from canonical evidence" }, { label: "Fixture mode", value: "Defined by the chosen scenario, not a browser preference" }]} /></details>
    </div>
  </Panel>;
}

function hasLocalExecuteReview(preflight?: PreflightReport) {
  return Boolean(preflight?.approval_binding && preflight.approval_envelope && (preflight.ready || preflight.status === "approval_required"));
}

function LocalExecuteReview({ config, onChange, preflight }: { config: RunConfiguration; onChange: (config: RunConfiguration) => void; preflight?: PreflightReport }) {
  const set = <K extends keyof RunConfiguration>(key: K, value: RunConfiguration[K]) => onChange({ ...config, [key]: value });
  const approvalBinding = preflight?.approval_binding;
  const approvalEnvelope = preflight?.approval_envelope;
  const approvalReviewReady = hasLocalExecuteReview(preflight);
  return <section className="run-local-review" aria-label="Prepare Execute request">{config.mode === "execute" ? <div className="approval-box"><AlertTriangle/><div><strong>Review before durable job creation</strong><p>Review the canonical primary and alternate contracts and acknowledge the exact digests below. This browser acknowledgement is never sent as an execution capability; the durable job requires a new unchecked, job-bound approval after it is created.</p>{approvalReviewReady && approvalBinding && approvalEnvelope ? <div className="approval-binding-summary" aria-label="Execute approval binding"><DataList items={[{ label: "State digest", value: <code>{approvalBinding.state_digest}</code> }, { label: "Plan digest", value: <code>{approvalBinding.plan_digest}</code> }, { label: "Target scope digest", value: <code>{approvalBinding.target_scope_digest}</code> }, { label: "Envelope digest", value: <code>{approvalEnvelope.envelope_digest}</code> }, { label: "Profile / maximum tier", value: `${approvalBinding.profile_id} / ${sentence(approvalBinding.maximum_tier)}` }]} /></div> : <p className="approval-pending">Run preflight first. Job creation stays disabled until the canonical plan, exact scope, and complete approval envelope are displayed.</p>}<label className="check-row"><input type="checkbox" checked={config.approved} disabled={!approvalReviewReady} onChange={(event) => set("approved", event.target.checked)}/><span><strong>I reviewed this exact displayed Execute envelope</strong><small>Local acknowledgement only; cleared after preflight, intent changes, reload, and job submission</small></span></label><Field label="Prepared operator label" hint="Local preparation only. The durable job approval will request identity again."><input value={config.approvedBy} disabled={!approvalReviewReady} onChange={(event) => set("approvedBy", event.target.value)} autoComplete="off" placeholder="Operator label" required={config.mode === "execute"}/></Field></div></div> : null}</section>;
}

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
    <DataList items={[{ label: "Graph source", value: dirty ? "Unsaved browser draft" : "Saved or packaged graph" }, { label: "Graph shape", value: `${stepIds.length} nodes / ${edgeCount} routes` }, { label: "Action overrides", value: config.mode === "execute" ? `${actionOverrideCount} selected for exact binding` : "Not sent in Simulate" }, { label: "Local Execute review", value: config.mode === "execute" ? config.approved ? "Displayed envelope acknowledged locally" : "Awaiting displayed envelope acknowledgement" : "Not required for Simulate" }, { label: "Preflight state", value: preflight ? sentence(preflight.status) : "Not run for this handoff" }, { label: "Next required move", value: nextMove }]} /></details>
    {warnings.length ? <div className="warning-list">{warnings.map((warning) => <div key={warning}><AlertTriangle/>{warning}</div>)}</div> : null}
    {preflight ? <div className={`preflight-result ${preflight.ready ? "ready" : awaitsExactApproval ? "approval-required" : "blocked"}`}><header><strong>{preflight.ready ? "Canonical preflight ready" : awaitsExactApproval ? "Canonical envelope awaits confirmation" : "Canonical preflight blocked"}</strong><Badge tone={preflight.ready ? "success" : awaitsExactApproval ? "warning" : "danger"}>{sentence(preflight.status)}</Badge></header><details className="resolved-preflight-details"><summary>Resolved preflight details</summary><DataList items={[{ label: "Resolved autonomy", value: preflight.autonomy ? sentence(preflight.autonomy) : "Not reported" }, { label: "Resolved profile", value: preflight.runner_profile ?? "None" }, { label: "Scope", value: typeof preflight.scope === "string" ? preflight.scope : JSON.stringify(preflight.scope ?? {}) }, { label: "Safety tier", value: preflight.safety_tier ? sentence(preflight.safety_tier) : "Not reported" }, { label: "Capabilities", value: preflight.capabilities?.join(", ") ?? "Not reported" }, { label: "Approval", value: preflight.approval ?? "Not reported" }, { label: "Cleanup", value: typeof preflight.cleanup === "string" ? preflight.cleanup : JSON.stringify(preflight.cleanup ?? {}) }]} /></details>{preflight.findings?.length ? <ul>{preflight.findings.map((item, index) => <li key={index}>{typeof item === "string" ? item : item.message ?? item.code ?? JSON.stringify(item)}</li>)}</ul> : null}</div> : null}
    {!preflight?.plan ? <p className="run-next-step">Preflight will show the exact steps, effects, observations, and cleanup here.</p> : null}
  </Panel>;
}

function normalizeStatus(status: string) { return status === "success" ? "succeeded" : status === "control_blocked" ? "blocked" : status; }
function statusTone(status: string) { const value = normalizeStatus(status); return value === "succeeded" || value === "completed" || value === "cleaned" ? "success" as const : ["blocked", "partial", "awaiting_approval", "paused", "cancelling", "cancelled"].includes(value) ? "warning" as const : ["failed", "refused", "interrupted"].includes(value) ? "danger" as const : value === "counterfactual" ? "violet" as const : "info" as const; }

interface LiveConsoleProps {
  run: RunRecord | null;
  job: RunJob | null;
  events: RunEventPage["items"];
  pending: boolean;
  config: RunConfiguration;
  approvalPreflight?: PreflightReport;
  approvalRequest: Record<string, unknown> | null;
  proposalReview?: AIProposalReview;
  approvalConfirmed: boolean;
  approvedBy: string;
  approvalPending: boolean;
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

function LiveConsole({ run, job, events, pending, config, approvalPreflight, approvalRequest, proposalReview, approvalConfirmed, approvedBy, approvalPending, controlPending, mutableControlsEnabled, retryEnabled, onApprovalConfirmed, onApprovedBy, onApprove, onControl, onRetry, onProposalDecision, onProposalReviewLoaded, onReview }: LiveConsoleProps) {
  const [tab, setTab] = useState<"timeline" | "planner" | "policy" | "runner" | "evidence" | "detections">("timeline");
  const jobMode = job?.request?.mode === "execute" ? "execute" : job?.request?.mode === "simulate" ? "simulate" : config.mode;
  const previewSteps: RunStep[] = pending ? [{ step_id: "durable_job", status: job?.state ?? "planning", execution_disposition: job?.state === "awaiting_approval" ? "callback_not_started" : jobMode === "simulate" ? "simulation_job" : "approval_gated_job" }] : [];
  const steps = run?.steps ?? previewSteps;
  const canPause = mutableControlsEnabled && job?.state === "running";
  const canResume = mutableControlsEnabled && job?.state === "paused";
  const canCancel = Boolean(mutableControlsEnabled && job && !terminalJobStates.has(job.state));
  const terminal = Boolean(job && terminalJobStates.has(job.state));
  const emptyTitle = run ? `Run ${sentence(run.status).toLowerCase()}` : terminal ? `Job ${sentence(job!.state).toLowerCase()}` : "Awaiting a run";
  const emptyDetail = run ? "The saved record contains no completed steps. Review its events and limitations for context." : terminal ? typeof job?.progress.run_id === "string" ? "This job has ended. Its recorded events remain available below, but no finalized run record is linked." : "This job ended before a run record was linked." : "Planner, policy, dispatch, evidence, detection, and cleanup events will remain separate.";
  return <Panel className="live-console"><PanelHeader eyebrow="Live orchestration" title={run ? run.run_id : job ? job.job_id : pending ? "Job submission in progress" : "No active job"} detail={run ? `${sentence(run.mode)} · ${sentence(run.status)} · ${run.is_demo ? "sanitized demo" : "canonical local record"}` : job ? `${sentence(job.kind)} · durable ${sentence(job.state)} state · ${events.length} incremental events · updated ${formatDate(job.updated_at)}` : "Complete preflight, then submit a durable local job."} actions={<div className="run-controls"><Button size="small" variant="ghost" disabled={!canPause || controlPending} onClick={() => onControl("pause")} title={canPause ? "Pause at the next cooperative checkpoint" : "Pause requires a running controller-owned job"}><Pause/>Pause</Button><Button size="small" variant="ghost" disabled={!canResume || controlPending} onClick={() => onControl("resume")} title={canResume ? "Resume the cooperatively paused job" : "Resume requires a paused controller-owned job"}><RotateCcw/>Resume</Button>{isRetryableInterruptedJob(job) ? <Button size="small" variant="secondary" disabled={!retryEnabled || controlPending} onClick={onRetry} title={retryEnabled ? "Create a replacement job with fresh preflight and approval" : "Retry requires a fresh empty active-job inventory"}><RotateCcw/>Retry as replacement</Button> : null}<Button size="small" variant="danger" disabled={!canCancel || controlPending} onClick={() => onControl("cancel")} title={canCancel ? "Request cooperative cancellation" : "Cancel requires a nonterminal controller-owned job"}><CircleStop/>Cancel</Button>{run ? <Button size="small" onClick={onReview}><FileSearch/>Review</Button> : null}</div>} />
    {DEMO_MODE ? <div className="console-banner"><Sparkles/>Demo lifecycle states are presentation fixtures only. No runner was dispatched.</div> : null}
    {job?.state === "awaiting_approval" && job.progress.approval_kind !== "ai_proposal" ? mutableControlsEnabled ? <JobApprovalGate job={job} preflight={approvalPreflight} approvalRequest={approvalRequest} proposalReview={proposalReview} confirmed={approvalConfirmed} approvedBy={approvedBy} pending={approvalPending} onConfirmed={onApprovalConfirmed} onApprovedBy={onApprovedBy} onApprove={onApprove} /> : <Callout tone="warning" title="Controller ownership unavailable">Approval remains disabled until fresh active-job inventory confirms that this controller owns the job.</Callout> : null}
    {job && !terminal && typeof job.progress.proposal_record_id === "string" ? mutableControlsEnabled ? <ProposalReviewWorkspace job={job} onDecision={onProposalDecision} onReviewLoaded={onProposalReviewLoaded}/> : <Callout tone="warning" title="Controller ownership unavailable">Proposal decisions remain disabled until fresh active-job inventory confirms that this controller owns the job.</Callout> : null}
    {job?.error ? <Callout tone="danger" title={job.error.code ?? "Job failed"}>{job.error.message ?? "The durable job ended with a sanitized error record."}</Callout> : null}
    <div className="live-path">{steps.length ? steps.map((step, index) => <article key={`${step.step_id}-${index}`} data-status={normalizeStatus(step.status)}><header><span>{String(index + 1).padStart(2, "0")}</span><Badge tone={statusTone(step.status)} dot>{sentence(normalizeStatus(step.status))}</Badge></header><strong>{step.step_id}</strong><small>{step.action_id ?? step.simulation_id ?? sentence(step.execution_disposition ?? "pending")}</small></article>) : <div className="console-empty"><Activity/><strong>{emptyTitle}</strong><span>{emptyDetail}</span></div>}</div>
    <div className="console-tabs" role="tablist" aria-label="Run detail views">{(["timeline", "planner", "policy", "runner", "evidence", "detections"] as const).map((item) => <button key={item} role="tab" aria-selected={tab === item} onClick={() => setTab(item)}>{sentence(item)}</button>)}</div>
    <div className="console-detail">{tab === "timeline" ? <Timeline run={run} job={job} events={events} pending={pending} /> : tab === "planner" ? <StructuredPanel value={run?.planner_decisions?.length ? run.planner_decisions : run?.plan} empty="No planner decisions are available." /> : tab === "policy" ? <StructuredPanel value={run?.policy} empty="No policy decisions are available." /> : tab === "runner" ? <RunnerDetail run={run} /> : tab === "evidence" ? <EvidenceDetail run={run} /> : <DetectionDetail run={run} />}</div>
  </Panel>;
}

function JobApprovalGate({ job, preflight: ordinaryPreflight, approvalRequest, proposalReview, confirmed, approvedBy, pending, onConfirmed, onApprovedBy, onApprove }: { job: RunJob; preflight?: PreflightReport; approvalRequest: Record<string, unknown> | null; proposalReview?: AIProposalReview; confirmed: boolean; approvedBy: string; pending: boolean; onConfirmed: (confirmed: boolean) => void; onApprovedBy: (identity: string) => void; onApprove: () => void }) {
  const proposalExecute = job.progress.approval_kind === "ai_proposal_execute";
  const preflight = proposalExecute ? continuationApprovalPreflight(job, proposalReview, approvalRequest) : ordinaryPreflight;
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
  const exactEnvelopeReady = Boolean(hasUsableStoredApprovalReview(preflight) && pendingRequestReady && exactBindingMatches);
  return <section className="job-approval-gate" id="durable-execute-approval" tabIndex={-1} aria-label="Durable Execute job approval">
    <header><div><AlertTriangle/><span><strong>{proposalExecute ? "Fresh Execute approval after proposal acceptance" : "Explicit one-time Execute approval"}</strong><small>The execution callback has not started. Proposal acceptance and effect authorization are separate decisions.</small></span></div><Badge tone="warning" dot>Awaiting approval</Badge></header>
    <DataList items={[{ label: "Durable job", value: <code>{job.job_id}</code> }, { label: "Approval request", value: <code>{String(approvalRequest?.approval_id ?? "Not reported")}</code> }, { label: "Expires", value: formatDate(typeof approvalRequest?.expires_at === "string" ? approvalRequest.expires_at : undefined) }, { label: "Profile / tier", value: proposalExecute ? `${String(approvalRequest?.profile_id ?? "Not reported")} / ${sentence(String(approvalRequest?.maximum_tier ?? "not reported"))}` : binding ? `${binding.profile_id} / ${sentence(binding.maximum_tier)}` : "Not reported" }, { label: "State digest", value: <code>{String(proposalExecute ? approvalRequest?.state_digest ?? "Not reported" : binding?.state_digest ?? "Not reported")}</code> }, { label: "Plan digest", value: <code>{String(proposalExecute ? approvalRequest?.plan_digest ?? "Not reported" : binding?.plan_digest ?? "Not reported")}</code> }, { label: "Scope digest", value: <code>{String(proposalExecute ? approvalRequest?.target_scope_digest ?? "Not reported" : binding?.target_scope_digest ?? "Not reported")}</code> }, { label: proposalExecute ? "Continuation binding digest" : "Envelope digest", value: <code>{String(proposalExecute ? continuationRecord?.execute_approval_binding_digest ?? "Not reported" : envelope?.envelope_digest ?? "Not reported")}</code> }]} />
    {!pendingRequestReady ? <Callout tone="danger" title="Pending approval binding unavailable">Approval remains disabled until this job reports the same pending approval request ID returned with its immutable envelope.</Callout> : null}
    {proposalExecute && proposalReview && continuationRecord ? <DataList items={[{ label: "Proposal record", value: <code>{proposalReview.proposal_record_id}</code> }, { label: "Selected behavior", value: <code>{String(continuationRecord.selected_behavior_id ?? "Not reported")}</code> }, { label: "Resume step", value: <code>{String(continuationRecord.resume_from_step_id ?? "Full replay")}</code> }, { label: "Proposal digest", value: <code>{proposalReview.proposal_digest}</code> }]} /> : null}
    {preflight?.plan ? <><CanonicalPlanReview plan={preflight.plan} cleanup={preflight.cleanup} scope={preflight.scope} binding={binding} envelope={envelope} />{binding && !exactBindingMatches ? <Callout tone="danger" title="Approval envelope mismatch">Approval remains disabled because the pending request does not exactly match all five preflight binding fields.</Callout> : null}</> : <Callout tone="danger" title="Exact review unavailable">Approval remains disabled until the current pending request has its complete canonical plan and approval envelope.</Callout>}
    <div className="job-approval-controls"><label className="check-row"><input type="checkbox" checked={confirmed} disabled={!exactEnvelopeReady || pending} onChange={(event) => onConfirmed(event.target.checked)}/><span><strong>I approve this exact immutable {proposalExecute ? "proposal continuation" : "job envelope"} once</strong><small>Unchecked by default and never stored in browser persistence</small></span></label><Field label="Operator identity for this job"><input value={approvedBy} disabled={!exactEnvelopeReady || pending} onChange={(event) => onApprovedBy(event.target.value)} autoComplete="off" placeholder="Operator label"/></Field><Button variant="primary" disabled={!exactEnvelopeReady || !confirmed || !approvedBy.trim() || pending} onClick={onApprove}>{pending ? <Activity className="spin"/> : <ShieldCheck/>}{pending ? "Applying one-time approval" : "Approve and release job"}</Button><p>The server recomputes the binding, validates the pending capability, consumes it atomically, then releases only this job. Changing configuration elsewhere cannot alter this immutable request.</p></div>
  </section>;
}

function Timeline({ run, job, events: incrementalEvents, pending }: { run: RunRecord | null; job: RunJob | null; events: RunEventPage["items"]; pending: boolean }) {
  const events = incrementalEvents.length ? incrementalEvents : run?.events?.length ? run.events : run?.steps.map((step, index) => ({ type: normalizeStatus(step.status), step_id: step.step_id, sequence: index + 1, disposition: step.execution_disposition })) ?? (job ? [{ type: job.state, sequence: 1, disposition: job.state === "awaiting_approval" ? "Execution callback has not started" : `Durable job phase ${String(job.progress.phase ?? job.state)}`, timestamp: job.updated_at }] : []);
  if (!events.length && !pending) return <div className="console-empty compact"><Clock3/><span>No audit events are available.</span></div>;
  return <ol className="timeline">{pending && !events.length ? <li><span className="timeline-dot planning"/><div><strong>Planning request submitted</strong><p>The browser is awaiting a canonical control-plane response; it is not inventing progress.</p></div><time>Now</time></li> : events.map((event: any, index) => <li key={Number(event.sequence ?? index + 1)}><span className={`timeline-dot ${normalizeStatus(String(event.type ?? event.event_type ?? event.status ?? "observed"))}`}/><div><strong>{sentence(String(event.type ?? event.event_type ?? event.status ?? "event"))}</strong><p>{event.step_id ? `${event.step_id} · ` : ""}{sentence(String(event.disposition ?? event.message ?? "Canonical record"))}</p></div><time>{event.timestamp ? formatDate(event.timestamp) : `#${event.sequence ?? index + 1}`}</time></li>)}</ol>;
}

function StructuredPanel({ value, empty }: { value: unknown; empty: string }) {
  if (value === null || value === undefined || (Array.isArray(value) && !value.length)) return <div className="console-empty compact"><ListTree/><span>{empty}</span></div>;
  const entries = Array.isArray(value) ? value.map((item, index) => [`Record ${index + 1}`, item] as const) : typeof value === "object" ? Object.entries(value as Record<string, unknown>) : [["Value", value] as const];
  return <div className="structured-list">{entries.map(([key, item]) => <article key={key}><strong>{sentence(key)}</strong>{typeof item === "object" ? <pre>{JSON.stringify(item, null, 2)}</pre> : <span>{String(item)}</span>}</article>)}</div>;
}

function RunnerDetail({ run }: { run: RunRecord | null }) {
  if (!run) return <div className="console-empty compact"><TerminalSquare/><span>No runner dispatch records are available.</span></div>;
  const executed = run.steps.filter((step) => step.action_id); return <div>{executed.length ? <div className="structured-list">{executed.map((step) => <article key={step.step_id}><strong>{step.step_id}</strong><code>{step.action_id}</code><span>{sentence(step.status)}</span></article>)}</div> : <Callout title="No runner dispatch reported">This run used simulation adapters or lacks runner records. Simulation is not execution.</Callout>}</div>;
}

export function EvidenceDetail({ run }: { run: RunRecord | null }) {
  const records = run?.evidence?.records ?? []; if (!records.length) return <div className="console-empty compact"><FileSearch/><span>No evidence records are available.</span></div>;
  return <div className="record-grid">{records.map((record, index) => { const content = record.content ?? record.fields; const contentSummary = content && typeof content.summary === "string" ? content.summary : undefined; return <article key={record.evidence_id ?? record.id ?? index}><header><Badge tone={record.provenance === "observed" ? "success" : record.provenance === "control_blocked" ? "warning" : record.provenance === "counterfactual" ? "violet" : "info"}>{sentence(record.provenance)}</Badge><code>{record.step_id ?? "unattributed"}</code></header><strong>{record.kind ?? record.behavior_id ?? "Evidence record"}</strong><p>{record.summary ?? contentSummary ?? "Canonical structured evidence content."}</p><div className="evidence-meta"><span>Producer <code>{record.producer ?? "Not reported"}</code></span><span>Behavior <code>{record.behavior_id ?? "Not reported"}</code></span><span>Action <code>{record.action_id ?? "None"}</code></span><span>Confidence {typeof record.confidence === "number" ? `${Math.round(record.confidence * 100)}%` : "Not reported"}</span></div>{content ? <details><summary>Show technical evidence content</summary><pre aria-label={`Evidence content ${record.evidence_id ?? record.id ?? index + 1}`}>{JSON.stringify(content, null, 2)}</pre></details> : null}{record.limitations?.length ? <div className="evidence-limitations"><strong>Limitations</strong><ul>{record.limitations.map((item) => <li key={item}>{item}</li>)}</ul></div> : null}</article>; })}</div>;
}

export function DetectionDetail({ run }: { run: RunRecord | null }) {
  const candidates = run?.detections?.candidates ?? []; if (!candidates.length) return <div className="console-empty compact"><FileSearch/><span>No detection candidates are linked to this run.</span></div>;
  return <div className="record-grid">{candidates.map((item, index) => <article key={item.candidate_id ?? item.id ?? index}><header><Badge tone={item.state === "rejected" ? "danger" : item.state.includes("exercised") || item.state === "benign_evaluated" ? "success" : "info"}>{sentence(item.state)}</Badge><code>{item.target_language ?? item.language ?? "query"}</code></header><strong>{item.title ?? item.candidate_id ?? "Detection candidate"}</strong><p>{item.summary ?? "Lifecycle state reflects only completed validation stages."}</p></article>)}</div>;
}

function recordedTargetScope(run: RunRecord & { authorized_target_scope?: unknown }): string {
  for (const scope of [run.authorized_target_scope, run.policy?.authorized_target_scope, run.target_scope]) {
    if (!scope || typeof scope !== "object" || !("scope_refs" in scope) || !Array.isArray(scope.scope_refs)) continue;
    return scope.scope_refs.filter((ref): ref is string => typeof ref === "string" && Boolean(ref.trim())).join(", ") || "None recorded";
  }
  return "Not recorded";
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
    <section className="run-path-section" aria-label="Recorded step outcomes"><header><h2>Path taken</h2><p>{steps.length} recorded steps · outcomes as reported by this run</p></header>
      {steps.length ? <ol className="run-path-list">{steps.map((step, index) => <li key={`${step.step_id}-${index}`}><span className="run-step-number" aria-hidden="true">{String(index + 1).padStart(2, "0")}</span><div><strong>{stepName(step)}</strong><small>{stepOutcomeLabel(step, run.mode)}</small></div><details><summary>Step details</summary><DataList items={[{ label: "Step", value: step.step_id }, { label: "Method", value: step.action_id ?? step.simulation_id ?? "Not reported" }, { label: "Disposition", value: sentence(step.execution_disposition ?? "not reported") }, { label: "Evidence references", value: step.evidence_ids?.join(", ") || "None recorded" }]} />{step.error?.message ? <p>{step.error.message}</p> : null}</details></li>)}</ol> : <p className="field-note">No step outcomes are recorded.</p>}
    </section>
    <details className="run-review-details"><summary>Inspect evidence records{evidence ? ` (${evidence.length})` : " · not reported"}</summary><EvidenceDetail run={run}/></details>
    <details className="run-review-details"><summary>Inspect detection candidates{detections ? ` (${detections.length})` : " · not reported"}</summary><DetectionDetail run={run}/></details>
    {aiProposals.length ? <details className="run-review-details"><summary>AI decisions ({aiProposals.length})</summary><AIProposalTrail proposals={aiProposals}/></details> : <p className="run-ai-note">No runtime AI proposal records are attached.</p>}
    <section className="run-limitations"><h2>Limitations</h2>{run.limitations?.length ? <ul>{run.limitations.map((item) => <li key={item}>{item}</li>)}</ul> : <p>No limitations were attached. This is incomplete metadata, not proof that there are none.</p>}</section>
    <details className="run-review-details"><summary>Run identity, environment and technical record</summary><DataList items={[{ label: "Run ID", value: <code>{run.run_id}</code> }, { label: "Mode", value: sentence(run.mode) }, { label: "AI mode", value: sentence(run.autonomy ?? run.autonomy_level ?? (run.ai_enabled ? "assist" : "off")) }, { label: "Profile", value: run.runner_profile_id ?? "Not recorded" }, { label: "Targets", value: recordedTargetScope(run) }, { label: "Started", value: formatDate(run.created_at) }, { label: "Finalized", value: formatDate(run.finalized_at) }, { label: "Replay lineage", value: run.replay ? "Replay-linked" : "Original run" }]} /><details><summary>Raw reproducibility metadata</summary><div className="raw-columns"><StructuredPanel value={run.manifest ?? { schema_version: run.schema_version, scenario_id: run.scenario_id, profile_id: run.runner_profile_id }} empty="No manifest metadata."/><pre aria-label="Canonical run technical record">{JSON.stringify({ run_id: run.run_id, schema_version: run.schema_version, scenario_id: run.scenario_id, runner_profile_id: run.runner_profile_id, cleanup: run.cleanup ?? null, replay: run.replay ?? null }, null, 2)}</pre></div></details></details>
  </div>;
}

function AIProposalTrail({ proposals }: { proposals: NonNullable<RunRecord["ai_proposals"]> }) {
  if (!proposals.length) return <Panel><PanelHeader eyebrow="AI Auto journey" title="No runtime AI proposals"/><Callout title="Deterministic path">This run did not retain any Assist or Auto proposal records; planner decisions remained deterministic.</Callout></Panel>;
  return <Panel><PanelHeader eyebrow="AI Auto journey" title="Proposal, policy, and application trail" detail="Completed records show exactly what the provider proposed and what deterministic policy permitted, reviewed, or refused." actions={<Badge tone="violet">{proposals.length} proposal{proposals.length === 1 ? "" : "s"}</Badge>}/>
    <div className="record-grid">{proposals.map((record, index) => {
      const proposal = record.proposal ?? undefined;
      const provider = record.provider ?? {};
      const policy = record.proposal_policy_evaluation ?? {};
      return <article key={String(record.proposal_record_id ?? proposal?.proposal_id ?? index)}><header><Badge tone={String(record.application_status ?? "").startsWith("applied") || String(record.application_status ?? "").startsWith("accepted") ? "success" : String(record.application_status ?? "").includes("approval") ? "warning" : "info"}>{sentence(String(record.application_status ?? "recorded"))}</Badge><code>{String(proposal?.proposal_id ?? record.proposal_record_id ?? `proposal-${index + 1}`)}</code></header><strong>{sentence(String(proposal?.proposal_type ?? "proposal"))}</strong><p>{proposal?.rationale ?? "No provider rationale was retained."}</p><DataList items={[{ label: "Provider", value: `${String(provider.effective_provider_id ?? provider.requested_provider_id ?? "Not reported")}${provider.used_fallback ? ` · fallback: ${sentence(String(provider.fallback_reason ?? "used"))}` : ""}` }, { label: "Selected step", value: proposal?.selected_step_id ? <code>{proposal.selected_step_id}</code> : "None" }, { label: "Selected Behavior", value: proposal?.selected_behavior_id ? <code>{proposal.selected_behavior_id}</code> : "None" }, { label: "Selected Action", value: proposal?.selected_action_id ? <code>{proposal.selected_action_id}</code> : "None" }, { label: "Observed outcome", value: sentence(String(record.outcome ?? proposal?.selected_edge?.outcome ?? "not reported")) }, { label: "Policy", value: sentence(String(policy.status ?? "not reported")) }]} />{proposal?.selected_edge ? <p className="field-note">Exact registered edge: <code>{proposal.selected_edge.from_step} / {proposal.selected_edge.outcome} / {proposal.selected_edge.to_step}</code></p> : null}{proposal?.parameter_changes?.length ? <details><summary>Typed primitive parameter changes</summary><pre>{JSON.stringify(proposal.parameter_changes, null, 2)}</pre></details> : null}</article>;
    })}</div>
    <Callout title="Model output stayed proposal-only">Auto can apply only policy-valid Simulate choices from registered Behavior/Action contracts; Execute proposals still require durable review plus a fresh one-time approval before runner effects.</Callout>
  </Panel>;
}
