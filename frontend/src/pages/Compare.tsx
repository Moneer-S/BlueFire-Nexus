import { objectiveLabel, runLabel, runResult, shortRunId } from "../lib/run-presentation";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowUpRight, CheckCircle2, Download, Eye, GitBranch, GitCompareArrows, RotateCcw, Search, ShieldAlert, ShieldCheck } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { api, buildReplayPayload, DEMO_MODE, type ReplayPreparation } from "../lib/api";
import { hasMaterialDelta } from "../lib/comparison-materiality";
import { checkedComparisonResponse } from "../lib/s3-comparison";
import { hasReplayExtent, readPendingReplay, storePendingReplay, clearPendingReplay, settleReplayResolution } from "../lib/replay-submission";
import { sameJson } from "../lib/replay-review";
import { comparisonReport } from "../lib/comparison-report";
import { comparisonConclusion } from "../lib/comparison-conclusion";
import { recordedStepLabels } from "../lib/run-progress-presentation";
import { sourceRunParam } from "../lib/run-handoffs";
import { clearComparisonContext, MAX_COMPARISON_RUNS, readComparisonContext, writeComparisonContext } from "../lib/comparison-context";
import { ReplayParameterEditor } from "../components/ReplayParameterEditor";
import { CanonicalPlanReview } from "../components/CanonicalPlanReview";
import { DetectorEvaluationComparison } from "../components/DetectorEvaluationComparison";
import { MethodComparison } from "../components/MethodComparison";
import { S3AccessComparisonResults } from "../components/S3AccessComparison";
import { ReceiverDefensePage } from "./ReceiverDefense";
import { useAssistancePanel, usePublishComparisonSelection } from "../state/AssistanceContext";
import type { ComparisonAssistanceSelection } from "../lib/comparison-assistance";
import type { AutonomyLevel, CatalogResponse, ComparisonResponse, PreflightReport, RunConfiguration, RunRecord, RunStep, SavedComparisonSnapshot, Scenario } from "../types";
import { Badge, Button, Callout, DataList, EmptyState, ErrorState, Field, IconButton, LoadingState, PageHeader, Panel, PanelHeader, formatDate, sentence } from "../components/Primitives";
import "./Compare.css";

type ReplayStrategy = "exact" | "from_node" | "swap" | "parameters" | "setup";
const defaultParameterJson = "{}";
const EVERY_PLATFORM = ["linux", "macos", "windows"];
// A contract-compatible method can still be unrunnable here: the policy engine refuses a
// step whose action, profile and requested platform do not intersect. Name that restriction
// in the picker so the operator sees it before dispatch instead of after a refused run.
export function platformRestriction(platforms: string[] | undefined): string {
  const supported = (platforms ?? []).filter((item) => EVERY_PLATFORM.includes(item));
  if (!supported.length || supported.length === EVERY_PLATFORM.length) return "";
  return ` · ${supported.map((item) => item === "macos" ? "macOS" : item.charAt(0).toUpperCase() + item.slice(1)).join(" / ")} only`;
}
interface ReplayAttempt { sourceId: string; navigationGeneration: number; payload: Record<string, unknown>; preparation?: ReplayPreparation; submissionId: string; legacy: boolean; publicationStarted?: boolean }
interface ComparisonAttempt { runIds: string[]; generation: number }


interface ReplayPreflightAttempt {
  sourceId: string;
  payload: Record<string, unknown>;
  generation: number;
  scenario: Scenario;
  config: RunConfiguration;
  strategy: ReplayStrategy;
  fromStep: string;
  swapStep: string;
  swapBehavior: string;
  scopeRefs: string[];
  parameterJson: string;
  sourceScenario?: Scenario;
}

export function ComparePage() {
  const [params] = useSearchParams();
  return params.has("receiver_job") || params.get("receiver") === "1" ? <ReceiverDefensePage /> : <ComparisonWorkspace />;
}

function ComparisonWorkspace() {
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();
  const submissionRef = useRef<ReplayAttempt | undefined>(undefined);
  const [restoredSubmission, setRestoredSubmission] = useState(readPendingReplay);
  const linkedSource = sourceRunParam(searchParams, "source");
  const linkedReplay = sourceRunParam(searchParams, "replay");
  const comparisonContext = useMemo(() => readComparisonContext(searchParams), [searchParams]);
  const selected = comparisonContext.runIds;
  const selectionKey = JSON.stringify(selected);
  const snapshotId = searchParams.get("snapshot") ?? "";
  const [keepSavedHistoryOpen, setKeepSavedHistoryOpen] = useState(false);
  const runsQuery = useQuery({ queryKey: ["runs"], queryFn: api.runs }); const catalogQuery = useQuery({ queryKey: ["catalog"], queryFn: api.catalog }); const client = useQueryClient();
  const savedComparisonsQuery = useQuery({ queryKey: ["comparison-snapshots"], queryFn: api.comparisonSnapshots, enabled: !DEMO_MODE });
  const savedSnapshotQuery = useQuery({
    queryKey: ["comparison-snapshot", snapshotId],
    queryFn: async (): Promise<SavedComparisonSnapshot> => {
      const snapshot = await api.comparisonSnapshot(snapshotId);
      if (snapshot.snapshot_id !== snapshotId || snapshot.comparison.baseline_run_id !== snapshot.comparison.run_ids[0]
        || JSON.stringify(snapshot.comparison.summaries.map((run) => run.run_id)) !== JSON.stringify(snapshot.comparison.run_ids))
        throw new Error("The saved comparison does not match its recorded run identities.");
      return { ...snapshot, comparison: checkedComparisonResponse(snapshot.comparison) };
    },
    enabled: Boolean(snapshotId),
  });
  const snapshotSelectionMismatch = Boolean(snapshotId && savedSnapshotQuery.data?.snapshot_id === snapshotId && comparisonContext.explicit
    && (comparisonContext.invalid || JSON.stringify(savedSnapshotQuery.data.comparison.run_ids) !== selectionKey));
  const loadedSnapshot = snapshotId && savedSnapshotQuery.data?.snapshot_id === snapshotId && !snapshotSelectionMismatch ? savedSnapshotQuery.data : undefined;
  const assistantPanel = useAssistancePanel();
  const comparisonAssistantSelection = useMemo<ComparisonAssistanceSelection | undefined>(() =>
    loadedSnapshot && savedSnapshotQuery.isSuccess && !savedSnapshotQuery.isError && !savedSnapshotQuery.isFetching
      ? { kind: "comparison_snapshot", snapshot_id: loadedSnapshot.snapshot_id, snapshot_digest: loadedSnapshot.digest }
      : undefined,
  [loadedSnapshot, savedSnapshotQuery.isSuccess, savedSnapshotQuery.isError, savedSnapshotQuery.isFetching]);
  usePublishComparisonSelection(comparisonAssistantSelection, "Saved comparison");
  const runIdentityCounts = useMemo(() => {
    const counts = new Map<string, number>();
    for (const run of runsQuery.data?.runs ?? []) counts.set(run.run_id, (counts.get(run.run_id) ?? 0) + 1);
    return counts;
  }, [runsQuery.data]);
  const [search, setSearch] = useState(""); const [comparison, setComparison] = useState<ComparisonResponse>(); const [sourceId, setSourceId] = useState(linkedSource); const [strategy, setStrategy] = useState<ReplayStrategy>("exact");
  const [fromStep, setFromStep] = useState(""); const [swapStep, setSwapStep] = useState(""); const [swapBehavior, setSwapBehavior] = useState(""); const [profile, setProfile] = useState(""); const [autonomy, setAutonomy] = useState<"preserve" | AutonomyLevel>("preserve"); const [provider, setProvider] = useState(""); const [defenseChange, setDefenseChange] = useState(""); const [parameterJson, setParameterJson] = useState(defaultParameterJson); const [targetScope, setTargetScope] = useState("");
  const [replayPreflight, setReplayPreflight] = useState<PreflightReport>(); const [localError, setLocalError] = useState<string>();
  const [preparation, setPreparation] = useState<ReplayPreparation>();
  const [parameterDraftValid, setParameterDraftValid] = useState(true);
  const parameterDraftValidRef = useRef(true);
  const preflightGeneration = useRef(0);
  const navigationGeneration = useRef(0);
  const comparisonGeneration = useRef(0);
  const resultsRef = useRef<HTMLDivElement>(null);
  const replayChoiceRef = useRef<HTMLSelectElement>(null);
  const [resolutionNotice, setResolutionNotice] = useState<string>();
  useEffect(() => { if (resolutionNotice) replayChoiceRef.current?.focus(); }, [resolutionNotice]);
  useEffect(() => () => { navigationGeneration.current += 1; preflightGeneration.current += 1; comparisonGeneration.current += 1; }, []);
  useEffect(() => { if (comparison) { resultsRef.current?.focus({ preventScroll: true }); resultsRef.current?.scrollIntoView({ block: "start" }); } }, [comparison]);
  useEffect(() => { comparisonGeneration.current += 1; setComparison(undefined); }, [snapshotId]);
  const detailQuery = useQuery({ queryKey: ["run", sourceId], queryFn: () => api.runDetail(sourceId), enabled: Boolean(sourceId) });
  const compareMutation = useMutation({ mutationFn: async (attempt: ComparisonAttempt) => {
    const result = await api.compare(attempt.runIds);
    if (JSON.stringify(result.summaries.map((run) => run.run_id)) !== JSON.stringify(attempt.runIds)
      || JSON.stringify(result.run_ids) !== JSON.stringify(attempt.runIds)
      || result.baseline_run_id !== attempt.runIds[0]) throw new Error("The returned comparison does not match the selected runs. Refresh the history and compare again.");
    return checkedComparisonResponse(result);
  }, onSuccess: (result, attempt) => {
    if (attempt.generation !== comparisonGeneration.current) return;
    setComparison(result);
    if (result.saved_snapshot?.snapshot_id) {
      setSearchParams((current) => { const next = new URLSearchParams(current); next.set("snapshot", result.saved_snapshot!.snapshot_id); return next; });
      void client.invalidateQueries({ queryKey: ["comparison-snapshots"] });
    }
  } });
  const source = detailQuery.data ?? runsQuery.data?.runs.find((run) => run.run_id === sourceId);
  const changeSelection = (runId: string, checked: boolean) => {
    if (checked && selected.length >= MAX_COMPARISON_RUNS) return;
    comparisonGeneration.current += 1;
    setComparison(undefined);
    const runIds = checked ? [...new Set([...selected, runId])] : selected.filter(id => id !== runId);
    setSearchParams(current => { const next = writeComparisonContext(current, { runIds, baselineId: runIds.length >= 2 ? comparisonContext.baselineId : "", revisedId: runIds.length >= 2 ? comparisonContext.revisedId : "" }); next.delete("snapshot"); return next; });
  };
  useEffect(() => { comparisonGeneration.current += 1; setComparison(undefined); }, [selectionKey]);
  const reviewedSource = useRef<RunRecord | undefined>(undefined);
  const resetReview = () => { preflightGeneration.current += 1; setReplayPreflight(undefined); setPreparation(undefined); setLocalError(undefined); };
  useEffect(() => {
    navigationGeneration.current += 1;
    comparisonGeneration.current += 1;
    setSourceId(linkedSource);
    reviewedSource.current = undefined;
    setRestoredSubmission(readPendingReplay());
    setComparison(undefined);
    preflightGeneration.current += 1;
    setReplayPreflight(undefined); setPreparation(undefined);
  }, [linkedSource, linkedReplay]);
  useEffect(() => {
    setStrategy("exact"); setFromStep(""); setSwapStep(""); setSwapBehavior("");
    setProfile(""); setAutonomy("preserve"); setProvider(""); setTargetScope("");
    setParameterJson(defaultParameterJson); parameterDraftValidRef.current = true; setParameterDraftValid(true); setDefenseChange(""); setLocalError(undefined);
  }, [linkedSource]);
  useEffect(() => {
    const current = detailQuery.data;
    if (!current || current.mode !== "execute") return;
    const evidence = Object.fromEntries(Object.entries(current).filter(([key]) => key !== "presentation"));
    const previous = reviewedSource.current;
    if (previous && sameJson(Object.fromEntries(Object.entries(previous).filter(([key]) => key !== "presentation")), evidence)) return;
    reviewedSource.current = current;
    setTargetScope(executionScope(current).join(", ")); resetReview();
  }, [detailQuery.data]);
  const parameterOverrides = useMemo(() => { if (strategy !== "parameters") return {}; try { return parseParameterOverrides(parameterJson, source?.scenario); } catch { return {}; } }, [parameterJson, source?.scenario, strategy]);
  const parameterError = useMemo(() => {
    if (strategy !== "parameters" || parameterJson.trim() === "{}") return undefined;
    try { parseParameterOverrides(parameterJson, source?.scenario); return undefined; }
    catch (error) { return error instanceof Error ? error.message : "Invalid parameter JSON."; }
  }, [parameterJson, source?.scenario, strategy]);
  const changeParameterValidity = (valid: boolean) => {
    if (parameterDraftValidRef.current !== valid) resetReview();
    parameterDraftValidRef.current = valid; setParameterDraftValid(valid);
  };
  const replayScenario = useMemo(() => source?.scenario ? prepareReplayScenario(source.scenario, strategy, swapStep, swapBehavior, parameterOverrides) : undefined, [parameterOverrides, source?.scenario, strategy, swapBehavior, swapStep]);
  const actionImplementations = resolvedActions(source, strategy === "swap" ? swapStep : undefined);
  const variantReady = strategy === "exact" || (strategy === "setup" ? Boolean(profile || autonomy !== "preserve" || provider || defenseChange.trim()) : strategy === "from_node" ? Boolean(fromStep) : strategy === "swap" ? Boolean(swapStep && swapBehavior) : parameterDraftValid && !parameterError && Object.keys(parameterOverrides).length > 0);
  const effectiveAutonomy = autonomy === "preserve" ? source?.autonomy ?? source?.autonomy_level ?? "off" : autonomy; const effectiveProvider = provider || providerId(source) || catalogQuery.data?.ai.active_provider || "deterministic-offline.v1"; const effectiveProfile = profile || source?.runner_profile_id || ""; const scopeRefs = targetScope.split(",").map((item) => item.trim()).filter(Boolean);
  const replayConfig: RunConfiguration | undefined = replayScenario ? { mode: source?.mode ?? "simulate", autonomy: effectiveAutonomy, provider: effectiveProvider, model: "", endpoint: "", profileId: effectiveProfile, runnerIds: [], scopeRefs, safetyTier: "controlled", approvalPolicy: "profile", approved: false, approvedBy: "", maxSeconds: 120, maxSteps: 25, maxBytes: 10_485_760, collectors: source?.mode === "execute" ? ["collector.filesystem.sandbox.v1"] : [], detectionBackends: [], cleanupPolicy: "always", counterfactual: "disabled", fixtureMode: false, actionImplementations } : undefined;
  const currentReplayPayload = () => buildReplayPayload({ strategy, fromStep, swapStep, swapBehavior, profile, autonomy, provider, defenseChange,
    parameterOverrides: strategy === "parameters" ? parseParameterOverrides(parameterJson, source?.scenario) : undefined,
    targetScope: source?.mode === "execute" ? scopeRefs : undefined,
    actionImplementations: source?.mode === "execute" && strategy !== "exact" && strategy !== "from_node" ? actionImplementations : undefined });
  const preflightMutation = useMutation({ mutationFn: async (attempt: ReplayPreflightAttempt) => {
    assertReplayVariant(attempt.strategy, attempt.fromStep, attempt.swapStep, attempt.swapBehavior);
    if (!attempt.scopeRefs.length) throw new Error("Execute replay requires an exact target scope.");
    if (attempt.strategy === "parameters") parseParameterOverrides(attempt.parameterJson, attempt.sourceScenario);
    const prepared = await api.prepareReplay(attempt.sourceId, attempt.payload);
    if (prepared.schema_version !== "bluefire.replay-preparation.v1" || !hasReplayExtent(prepared) || prepared.binding.source.run_id !== attempt.sourceId ||
      !sameJson(prepared.replay_request, attempt.payload) || !sameJson(prepared.binding.replay_request, attempt.payload) || prepared.effects_started !== false || prepared.approval_created !== false)
      throw new Error("The returned review does not match this replay request. Prepare it again.");
    return { generation: attempt.generation, report: prepared.preflight, preparation: prepared };
  }, onSuccess: ({ generation, report, preparation: prepared }) => {
    if (generation !== preflightGeneration.current) return;
    setReplayPreflight(report); setPreparation(prepared); setLocalError(undefined);
  }, onError: (error, attempt) => {
    if (attempt.generation !== preflightGeneration.current) return;
    setReplayPreflight(undefined); setPreparation(undefined); setLocalError(error instanceof Error ? error.message : "Replay preparation failed.");
  } });
  const requestPreflight = () => {
    if (!replayScenario || !replayConfig || !variantReady || (strategy === "parameters" && !parameterDraftValidRef.current)) return;
    try {
      setResolutionNotice(undefined); resetReview(); const generation = preflightGeneration.current;
      preflightMutation.mutate({ generation, sourceId, payload: structuredClone(currentReplayPayload()), scenario: structuredClone(replayScenario), config: structuredClone(replayConfig), strategy, fromStep, swapStep, swapBehavior, scopeRefs: [...scopeRefs], parameterJson, sourceScenario: source?.scenario ? structuredClone(source.scenario) : undefined });
    } catch (error) { setLocalError(error instanceof Error ? error.message : "Replay preparation failed."); }
  };
  const replayMutation = useMutation({
    mutationFn: async (attempt: ReplayAttempt) => {
      if (attempt.legacy) return { kind: "legacy" as const, run: await api.replay(attempt.sourceId, attempt.payload) };
      const prepared = attempt.preparation ?? await api.prepareReplay(attempt.sourceId, attempt.payload);
      if (prepared.schema_version !== "bluefire.replay-preparation.v1" || !hasReplayExtent(prepared) || prepared.binding?.source?.run_id !== attempt.sourceId || !sameJson(prepared.replay_request, attempt.payload) || !sameJson(prepared.binding.replay_request, attempt.payload) || prepared.effects_started !== false || prepared.approval_created !== false) throw new Error("The prepared replay does not match this submission.");
      attempt.preparation = prepared;
      if (!storePendingReplay({ sourceId: attempt.sourceId, payload: attempt.payload, preparation: prepared, submissionId: attempt.submissionId })) throw new Error("The replay retry receipt could not be saved. Enable browser session storage before submitting this replay.");
      attempt.publicationStarted = true;
      const submission = await api.submitReplay(attempt.sourceId, prepared, attempt.submissionId);
      const expectedJobId = `job-${attempt.submissionId.replaceAll("-", "")}`;
      if (submission.job.job_id !== expectedJobId || submission.job.kind !== "scenario.replay") throw new Error("The submitted job identity did not match this replay. Check its saved status before retrying.");
      return { kind: "job" as const, submission };
    },
    onSuccess: (result, attempt) => {
      void client.invalidateQueries({ queryKey: ["runs"] });
      void client.invalidateQueries({ queryKey: ["active-jobs"] });
      if (result.kind === "job") {
        clearPendingReplay(attempt.submissionId); setRestoredSubmission(undefined);
        client.setQueryData(["job", result.submission.job.job_id], result.submission.job);
        if (attempt.navigationGeneration === navigationGeneration.current) navigate(`/runs?job=${encodeURIComponent(result.submission.job.job_id)}`);
        return;
      }
      const run = result.run;
      client.setQueryData(["run", run.run_id], run);
      if (attempt.navigationGeneration !== navigationGeneration.current) return;
      setComparison(undefined);
      setSearchParams((current) => { const next = clearComparisonContext(current); next.set("source", attempt.sourceId); next.set("replay", run.run_id); return next; });
      setLocalError(undefined); setReplayPreflight(undefined); setPreparation(undefined);
    },
    onError: (error, attempt) => {
      if (attempt.publicationStarted) setRestoredSubmission(readPendingReplay());
      if (attempt.navigationGeneration !== navigationGeneration.current) return;
      setLocalError(error instanceof Error ? error.message : "Replay submission could not be confirmed.");
      if (!attempt.publicationStarted) { clearPendingReplay(attempt.submissionId); setRestoredSubmission(undefined); setReplayPreflight(undefined); setPreparation(undefined); submissionRef.current = undefined; }
    },
  });
  const uncertainSubmission = replayMutation.isError && replayMutation.variables?.publicationStarted && replayMutation.variables.navigationGeneration === navigationGeneration.current ? replayMutation.variables : restoredSubmission ? { ...restoredSubmission, navigationGeneration: navigationGeneration.current, legacy: false, publicationStarted: true } : undefined;
  const resolutionMutation = useMutation({
    mutationFn: async (attempt: ReplayAttempt) => {
      if (!attempt.preparation) throw new Error("The saved replay preparation is unavailable. This submission remains unresolved.");
      const receipt = { sourceId: attempt.sourceId, payload: attempt.payload, preparation: attempt.preparation, submissionId: attempt.submissionId };
      const result = await api.resolveReplaySubmission(attempt.sourceId, attempt.preparation, attempt.submissionId);
      if (!settleReplayResolution(receipt, result)) throw new Error("The service response or saved receipt did not match this submission. Keep this request and check its saved status before trying again.");
      return result;
    },
    onSuccess: (result, attempt) => {
      void client.invalidateQueries({ queryKey: ["active-jobs"] });
      client.setQueryData(["job", result.job.job_id], result.job);
      setRestoredSubmission(readPendingReplay());
      if (attempt.navigationGeneration !== navigationGeneration.current) return;
      submissionRef.current = undefined; replayMutation.reset(); resetReview();
      if (result.outcome === "existing") {
        navigate(`/runs?job=${encodeURIComponent(result.job.job_id)}`);
      } else {
        setResolutionNotice("This submission is closed. Review your settings and prepare a new replay when you are ready.");
      }
    },
    onError: (error, attempt) => {
      if (attempt.navigationGeneration === navigationGeneration.current) setLocalError(error instanceof Error ? error.message : "Submission closure could not be confirmed. The saved request is retained.");
    },
  });
  const requestReplay = () => {
    try {
      setResolutionNotice(undefined);
      if (!detailQuery.isSuccess || !source || source.run_id !== sourceId) throw new Error("Select a source run.");
      assertReplayVariant(strategy, fromStep, swapStep, swapBehavior);
      if (!variantReady || (strategy === "parameters" && !parameterDraftValidRef.current)) throw new Error("Finish the parameter change before running the replay.");
      const execute = source.mode === "execute";
      if (execute && (!scopeRefs.length || !executeReviewReady(replayPreflight))) throw new Error("Execute replay requires its exact prepared review before creating a job.");
      const current = currentReplayPayload();
      if (execute && (!preparation || preparation.binding.source.run_id !== sourceId || !sameJson(preparation.replay_request, current))) throw new Error("Prepare the exact replay before approving it.");
      const payload = current;
      const previous = submissionRef.current;
      const attempt = previous && previous.sourceId === sourceId && previous.navigationGeneration === navigationGeneration.current && sameJson(previous.payload, payload) && previous.preparation?.preparation_id === preparation?.preparation_id
        ? previous : { sourceId, navigationGeneration: navigationGeneration.current, payload: structuredClone(payload), preparation, submissionId: crypto.randomUUID(), legacy: DEMO_MODE };
      submissionRef.current = attempt;
      replayMutation.mutate(attempt);
    } catch (error) { setLocalError(error instanceof Error ? error.message : "Replay was refused."); }
  };
  if (runsQuery.isPending || catalogQuery.isPending) return <LoadingState label="Loading replay history" />;
  if (runsQuery.isError) return <ErrorState error={runsQuery.error} retry={() => runsQuery.refetch()} />;
  if (catalogQuery.isError) return <ErrorState error={catalogQuery.error} retry={() => catalogQuery.refetch()} />;
  const availableRuns = runsQuery.data.runs.filter(run => runIdentityCounts.get(run.run_id) === 1);
  const savedRunNames = new Map(availableRuns.map(run => [run.run_id, runLabel(run)]));
  const savedRunName = (runId: string) => savedRunNames.get(runId) ?? (runIdentityCounts.has(runId) ? "Ambiguous run record" : "Run unavailable");
  const runs = availableRuns.filter((run) => `${run.run_id} ${runLabel(run)} ${run.objective ?? ""} ${run.scenario_id ?? ""}`.toLowerCase().includes(search.toLowerCase())); const sourceSteps = source?.steps ?? []; const selectedSwapBehavior = sourceSteps.find((step) => step.step_id === swapStep)?.behavior_id; const sourceBehavior = catalogQuery.data.behaviors.find((item) => item.id === selectedSwapBehavior); const compatible = catalogQuery.data.behaviors.filter((candidate) => sourceBehavior && candidate.id !== sourceBehavior.id && JSON.stringify(candidate.inputs.map((item) => [item.type, item.required, item.multiple])) === JSON.stringify(sourceBehavior.inputs.map((item) => [item.type, item.required, item.multiple])) && JSON.stringify(candidate.outputs.map((item) => [item.type, item.multiple])) === JSON.stringify(sourceBehavior.outputs.map((item) => [item.type, item.multiple])));
  const execute = source?.mode === "execute"; const reviewReady = executeReviewReady(replayPreflight) && Boolean(preparation) && variantReady;
  const unavailableRuns = selected.filter(id => runIdentityCounts.get(id) !== 1);
  const comparisonReady = !comparisonContext.invalid && !unavailableRuns.length && !runsQuery.isFetching && selected.length >= 2;
  const displayedComparison = loadedSnapshot?.comparison ?? (!snapshotId && comparisonReady && comparison && JSON.stringify(comparison.summaries.map(run => run.run_id)) === selectionKey ? comparison : undefined);
  const emptyWorkspace = runsQuery.data.runs.length === 0 && !runsQuery.data.unavailable_run_count
    && !snapshotId && !sourceId && !selected.length && !comparisonContext.explicit && !comparisonContext.invalid
    && !searchParams.has("method_job") && !uncertainSubmission && !replayMutation.isPending && !resolutionNotice;
  const emptySavedHistory = savedComparisonsQuery.isSuccess && savedComparisonsQuery.data.snapshots.length === 0;
  const openSavedSnapshot = (snapshot: { snapshot_id: string; run_ids: string[] }) => {
    setKeepSavedHistoryOpen(true);
    comparisonGeneration.current += 1;
    setComparison(undefined);
    setSearchParams((current) => {
      const next = writeComparisonContext(current, { runIds: snapshot.run_ids, baselineId: "", revisedId: "" });
      next.set("snapshot", snapshot.snapshot_id);
      return next;
    });
  };
  const snapshotSourcesVerified = Boolean(loadedSnapshot
    && loadedSnapshot.source_integrity.status === "verified"
    && loadedSnapshot.source_integrity.runs.length === loadedSnapshot.comparison.run_ids.length
    && loadedSnapshot.source_integrity.runs.every((run) => run.status === "verified"));
  const detectorEvaluationRunIds = loadedSnapshot?.comparison.run_ids ?? selected;
  // A saved comparison remains readable without its source records. Changed or
  // ambiguous current records must not supply historical method labels.
  const labelRuns = availableRuns.filter(run => !loadedSnapshot || loadedSnapshot.source_integrity.runs
    .filter(source => source.run_id === run.run_id).length === 1
    && loadedSnapshot.source_integrity.runs.some(source => source.run_id === run.run_id && source.status === "verified"));
  return <div className="page compare-page"><PageHeader title="Compare runs" actions={<Button variant="secondary" onClick={() => runsQuery.refetch()}><RotateCcw/>Refresh history</Button>} />
    {emptyWorkspace ? <section className="compare-empty-history" aria-label="No run records"><EmptyState title="No run records" description="Run an experiment to create a result. Simulate is available without a lab." action={<Link className="button button-primary button-medium" to="/getting-started">Start an experiment<ArrowUpRight aria-hidden="true"/></Link>}/></section> : null}
    {!DEMO_MODE ? <div className="saved-comparisons-history"><details className="saved-comparisons-browser" open={(!displayedComparison && (!emptyWorkspace || !emptySavedHistory)) || keepSavedHistoryOpen} onToggle={event => { if (!event.currentTarget.open) setKeepSavedHistoryOpen(false); }}><summary>Saved comparisons</summary><IconButton className="saved-comparisons-reload" label="Reload saved comparisons" onClick={() => { void savedComparisonsQuery.refetch(); if (snapshotId) void savedSnapshotQuery.refetch(); }} disabled={savedComparisonsQuery.isFetching || savedSnapshotQuery.isFetching}><RotateCcw aria-hidden="true"/></IconButton><Panel className="saved-comparisons-panel">
      {savedComparisonsQuery.isError ? <p className="workspace-note">Saved comparison history is unavailable.</p> : savedComparisonsQuery.isPending ? <LoadingState label="Loading saved comparisons"/> : savedComparisonsQuery.data.snapshots.length ? <ul className="saved-comparisons-list">{savedComparisonsQuery.data.snapshots.map((item) => {
        const labels = item.run_ids.map((runId, index) => `${runId === item.baseline_run_id ? "Baseline" : `Compared run ${index}`}: ${savedRunName(runId)}`);
        return <li key={item.snapshot_id}>
          <button className="saved-comparison-link" type="button" data-snapshot-id={item.snapshot_id} aria-label={`Open saved comparison. ${labels.join(". ")}. Saved ${formatDate(item.created_at)}`} aria-current={snapshotId === item.snapshot_id ? "page" : undefined} onClick={() => openSavedSnapshot(item)}>
            <span>{labels.map((label, index) => <strong key={index}>{label}</strong>)}<small>{formatDate(item.created_at)} · {item.run_ids.length} runs</small></span>
          </button>
          <details className="saved-comparison-details"><summary>Record details</summary><dl>
            <dt>Snapshot ID</dt><dd><code>{item.snapshot_id}</code></dd>
            <dt>Baseline run ID</dt><dd><code>{item.baseline_run_id}</code></dd>
            <dt>Recorded run order</dt><dd><ol>{item.run_ids.map((runId, index) => <li key={index}><code>{runId}</code></li>)}</ol></dd>
            <dt>Digest</dt><dd><code>{item.digest}</code></dd>
          </dl></details>
        </li>;
      })}</ul> : <p className="workspace-note">No saved comparisons yet.</p>}
      {snapshotId && savedSnapshotQuery.isError ? <ErrorState title="Saved comparison unavailable" error={savedSnapshotQuery.error} retry={() => void savedSnapshotQuery.refetch()} /> : null}
      {snapshotId && savedSnapshotQuery.isPending ? <LoadingState label="Opening saved comparison"/> : null}
    </Panel></details></div> : null}
    {comparisonContext.invalid ? <Callout tone="warning" title="Comparison selection unavailable"><p>This link has an invalid or oversized selection. Clear it and choose the runs and detector revisions again.</p><Button onClick={() => setSearchParams(current => writeComparisonContext(current, { runIds: [], baselineId: "", revisedId: "" }))}>Clear comparison selection</Button></Callout> : null}
    {snapshotSelectionMismatch ? <Callout tone="warning" title="Saved comparison selection mismatch">The saved comparison's recorded run order does not match this link. Reopen it from Saved comparisons to review the original result.</Callout> : null}
    {!snapshotId && unavailableRuns.length ? <Callout tone="warning" title="Selected runs unavailable"><p>{unavailableRuns.length} selected run record{unavailableRuns.length === 1 ? " is" : "s are"} missing or ambiguous in the available history. Refresh history or remove them before comparing; no other run has been substituted.</p><Button onClick={() => setSearchParams(current => writeComparisonContext(current, { runIds: selected.filter(id => !unavailableRuns.includes(id)), baselineId: "", revisedId: "" }))}>Remove unavailable selections</Button></Callout> : null}
    {!snapshotId && comparisonContext.explicit && !comparisonContext.invalid && !displayedComparison ? <p className="workspace-note">Comparison selection restored. Choose Compare selected to load results.</p> : null}
    {loadedSnapshot && (loadedSnapshot.source_integrity.status !== "verified" || loadedSnapshot.source_integrity.runs.some((run) => run.status !== "verified")) ? <Callout tone="warning" title="Historical result; source integrity unavailable"><p>One or more source run records are now missing, changed, or invalid. This comparison is shown as saved and was not recomputed.</p></Callout> : null}
    {runsQuery.data.unavailable_run_count ? <Callout tone="warning" title="Unavailable run records excluded">{runsQuery.data.unavailable_run_count} in-flight, interrupted, or integrity-failed run record{runsQuery.data.unavailable_run_count === 1 ? " is" : "s are"} unavailable for replay and comparison. Refresh after finalization or recovery completes.</Callout> : null}
    {compareMutation.isError && compareMutation.variables?.generation === comparisonGeneration.current ? <ErrorState title="Comparison unavailable" error={compareMutation.error} /> : displayedComparison ? <div className="comparison-workspace" ref={resultsRef} tabIndex={-1} role="region" aria-label="Comparison results"><ComparisonResult comparison={displayedComparison} names={Object.fromEntries(runsQuery.data.runs.map(run => [run.run_id, runLabel(run)]))} createdAt={Object.fromEntries(runsQuery.data.runs.map(run => [run.run_id, run.created_at]))} catalog={catalogQuery.data} runs={labelRuns} onExplain={comparisonAssistantSelection ? () => assistantPanel?.setOpen(true) : undefined} />{loadedSnapshot ? snapshotSourcesVerified ? <section className="current-detector-evaluations" aria-label="Current detector evaluations"><h2>Current detector evaluations</h2><DetectorEvaluationComparison runIds={detectorEvaluationRunIds} snapshotId={loadedSnapshot.snapshot_id} selection={comparisonContext} onSelectionChange={selection => setSearchParams(current => writeComparisonContext(current, { runIds: detectorEvaluationRunIds, ...selection }))} /></section> : null : <DetectorEvaluationComparison runIds={selected} selection={comparisonContext} onSelectionChange={selection => setSearchParams(current => writeComparisonContext(current, { runIds: selected, ...selection }))} />}</div> : null}
    {!emptyWorkspace ? <details className="compare-setup" open={!displayedComparison}><summary>{displayedComparison ? "Choose different runs or prepare a replay" : "Choose runs and prepare a replay"}</summary>
    <div className="compare-top-grid"><Panel className="history-panel"><PanelHeader title="Choose runs to compare" actions={<Badge>{selected.length} selected</Badge>} /><div className="history-search"><Search/><input aria-label="Search run history" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search name or run ID"/></div><div className="run-select-list">{runs.map((run) => <label key={run.run_id}><input type="checkbox" checked={selected.includes(run.run_id)} disabled={!selected.includes(run.run_id) && selected.length >= MAX_COMPARISON_RUNS} onChange={(event) => changeSelection(run.run_id, event.target.checked)}/><span><strong>{runLabel(source?.run_id === run.run_id ? source : run)}</strong><small><span className={`run-select-mode mode-${run.mode}`}>{sentence(run.mode)}</span> · {formatDate(run.created_at)} · {run.steps.length} steps · <span className="run-select-id">{shortRunId(run.run_id)}</span>{selected.includes(run.run_id) ? ` · ${selected.indexOf(run.run_id) === 0 ? "Comparison baseline" : "Variant " + selected.indexOf(run.run_id)}` : ""}</small></span><span className={`run-select-result tone-${runResult(run).tone}`}>{runResult(run).label}</span></label>)}</div>{!runs.length ? <EmptyState title={availableRuns.length ? "No matching runs" : "No available run records"} description={availableRuns.length ? "Try another name or run ID." : "Refresh history or review the linked record to continue."} /> : null}<footer>{selected.length >= MAX_COMPARISON_RUNS ? <p className="workspace-note">Up to {MAX_COMPARISON_RUNS} runs can be retained in one comparison selection.</p> : null}{selected.length < 2 ? <p className="workspace-note">Select at least two runs. The first selected run is the comparison baseline.</p> : null}<Button variant="primary" onClick={() => compareMutation.mutate({ runIds: [...selected], generation: comparisonGeneration.current })} disabled={!comparisonReady || compareMutation.isPending}><GitCompareArrows/>{compareMutation.isPending ? "Comparing" : "Compare selected"}</Button></footer></Panel>
      <Panel className="replay-panel"><PanelHeader title="Prepare another run" detail="Keep the original result and test the same experiment with a deliberate change." /><div className="replay-body">{resolutionNotice ? <Callout title="Submission closed">{resolutionNotice}</Callout> : null}<fieldset className="replay-form" disabled={Boolean(uncertainSubmission) || replayMutation.isPending}><Field label="Source run"><select value={sourceId} onChange={(event) => { const selectedSource = event.target.value; setSearchParams((current) => { const next = clearComparisonContext(current); if (selectedSource) next.set("source", selectedSource); else next.delete("source"); next.delete("replay"); return next; }); }} disabled={replayMutation.isPending}><option value="">Choose a completed run</option>{sourceId && !runsQuery.data.runs.some((run) => run.run_id === sourceId) ? <option value={sourceId}>{sourceId}</option> : null}{availableRuns.map((run) => <option value={run.run_id} key={run.run_id}>{runLabel(source?.run_id === run.run_id ? source : run)} · {sentence(run.mode)} · {formatDate(run.created_at)}</option>)}</select></Field>{sourceId && detailQuery.isError ? <ErrorState title="Source run unavailable" error={detailQuery.error} retry={() => detailQuery.refetch()} /> : null}{sourceId && detailQuery.isPending ? <LoadingState label="Loading the original experiment"/> : null}<Field label="What will change?"><select ref={replayChoiceRef} value={strategy} onChange={(event) => { setStrategy(event.target.value as ReplayStrategy); parameterDraftValidRef.current = true; setParameterDraftValid(true); resetReview(); }} disabled={!sourceId || replayMutation.isPending}>
          <option value="exact">Nothing: repeat the original run</option><option value="swap">Try another method</option><option value="parameters">Change step parameters</option><option value="setup">Change environment or AI setup</option><option value="from_node">Resume from a step</option>
        </select></Field>
        {strategy === "from_node" ? <Field label="Restart node"><select value={fromStep} onChange={(event) => { setFromStep(event.target.value); resetReview(); }}><option value="">Choose a step</option>{sourceSteps.map((step) => <option key={step.step_id} value={step.step_id}>{catalogQuery.data.behaviors.find((item) => item.id === step.behavior_id)?.title ?? step.step_id}</option>)}</select></Field> : null}
        {strategy === "swap" ? <div className="config-grid"><Field label="Substitute node"><select value={swapStep} onChange={(event) => { setSwapStep(event.target.value); setSwapBehavior(""); resetReview(); }}><option value="">Choose a step</option>{sourceSteps.map((step) => <option key={step.step_id} value={step.step_id}>{catalogQuery.data.behaviors.find((item) => item.id === step.behavior_id)?.title ?? step.step_id}</option>)}</select></Field><Field label="Compatible behavior"><select value={swapBehavior} onChange={(event) => { setSwapBehavior(event.target.value); resetReview(); }} disabled={!swapStep}><option value="">Choose a compatible method</option>{compatible.map((item) => <option value={item.id} key={item.id}>{item.title}{platformRestriction(item.platforms)}</option>)}</select></Field></div> : null}
        {strategy === "setup" ? <fieldset><legend>Run setup</legend><div className="config-grid"><Field label="Profile override"><select value={profile} onChange={(event) => { setProfile(event.target.value); resetReview(); }}><option value="">Preserve original</option>{catalogQuery.data.runner_profiles.map((item) => <option key={item.id}>{item.id}</option>)}</select></Field><Field label="AI autonomy override"><select value={autonomy} onChange={(event) => { setAutonomy(event.target.value as typeof autonomy); resetReview(); }}><option value="preserve">Preserve original</option><option value="off">Off</option><option value="assist">Assist</option><option value="auto">Auto</option></select></Field><Field label="AI provider override"><select value={provider} onChange={(event) => { setProvider(event.target.value); resetReview(); }}><option value="">Preserve original</option>{(catalogQuery.data.ai.providers ?? []).map((item) => <option value={item.provider_id} key={item.provider_id}>{item.provider_id}</option>)}</select></Field></div></fieldset> : strategy !== "exact" ? <details className="replay-settings"><summary>Environment and AI settings</summary><div className="config-grid"><Field label="Profile override"><select value={profile} onChange={(event) => { setProfile(event.target.value); resetReview(); }}><option value="">Preserve original</option>{catalogQuery.data.runner_profiles.map((item) => <option key={item.id}>{item.id}</option>)}</select></Field><Field label="AI autonomy override"><select value={autonomy} onChange={(event) => { setAutonomy(event.target.value as typeof autonomy); resetReview(); }}><option value="preserve">Preserve original</option><option value="off">Off</option><option value="assist">Assist</option><option value="auto">Auto</option></select></Field><Field label="AI provider override"><select value={provider} onChange={(event) => { setProvider(event.target.value); resetReview(); }}><option value="">Preserve original</option>{(catalogQuery.data.ai.providers ?? []).map((item) => <option value={item.provider_id} key={item.provider_id}>{item.provider_id}</option>)}</select></Field></div></details> : null}
        {strategy === "parameters" ? <>
          {source?.scenario ? <ReplayParameterEditor scenario={source.scenario} behaviors={catalogQuery.data.behaviors} value={parameterOverrides} onChange={(next) => { setParameterJson(JSON.stringify(next, null, 2)); resetReview(); }} onValidityChange={changeParameterValidity} disabled={replayMutation.isPending}/> : <Callout title="Original graph unavailable">The original scenario is required to edit its parameters.</Callout>}
          <details className="replay-settings"><summary>Advanced parameter JSON</summary><Field label="Parameter overrides JSON" hint='Object keyed by step, then parameter. All values are validated before a replay.'><textarea rows={8} value={parameterJson} onChange={(event) => { setParameterJson(event.target.value); resetReview(); }} disabled={replayMutation.isPending} spellCheck={false}/></Field></details>
          {parameterError ? <Callout tone="danger" title="Parameter changes need attention">{parameterError}</Callout> : null}
        </> : null}{strategy !== "exact" ? <details className="replay-settings"><summary>Record a defense change</summary><Field label="Declared defense change" hint="Describe a change already applied in your lab. This note does not change a defense."><textarea rows={3} maxLength={500} value={defenseChange} onChange={(event) => { setDefenseChange(event.target.value); resetReview(); }} placeholder="For example: revised the receiver policy to require redacted records"/></Field></details> : null}
        {execute ? <><Callout tone="warning" title="Execute replay is a new effect authorization">Review the complete replay, including the original run, your changes, restored inputs, allowed effects, and cleanup. Preparing a replay does not approve it or start any effects.</Callout><Field label="Exact target scope"><input value={targetScope} onChange={(event) => { setTargetScope(event.target.value); resetReview(); }} placeholder="sandbox.workspace"/></Field><Button variant="secondary" onClick={requestPreflight} disabled={!replayScenario || !variantReady || preflightMutation.isPending || !scopeRefs.length}><ShieldCheck/>{preflightMutation.isPending ? "Preparing review" : "Review Execute replay"}</Button>{replayPreflight ? <ReplayPreflight report={replayPreflight} preparation={preparation}/> : null}<p className="field-note">Continue to Runs to approve this exact review and follow the saved job. No effects start before approval.</p></> : null}
        {!variantReady && sourceId ? <Callout tone="warning" title="Replay variant incomplete">{strategy === "from_node" ? "Choose a restart step." : strategy === "swap" ? "Choose a step and its replacement method." : strategy === "setup" ? "Change an environment or AI setting, or record the defense change made in your lab." : "Change at least one step parameter."}</Callout> : null}{localError ? <Callout tone="danger" title="Replay refused">{localError}</Callout> : replayMutation.isSuccess && replayMutation.data.kind === "legacy" ? <Callout tone="success" title="Replay created"><code>{replayMutation.data.run.run_id}</code> is lineage-linked to <code>{replayMutation.variables?.sourceId}</code>.{linkedSource === replayMutation.variables?.sourceId && linkedReplay === replayMutation.data.run.run_id ? " The source and replay are selected for comparison." : " Your current source selection was preserved."}</Callout> : null}<Button variant="primary" className="button-full" onClick={requestReplay} disabled={!sourceId || !detailQuery.isSuccess || !variantReady || replayMutation.isPending || Boolean(execute && !reviewReady)}>{replayMutation.isPending ? "Submitting replay" : execute ? "Continue to approval" : "Create Simulate replay"}</Button></fieldset>{uncertainSubmission ? <Callout tone="warning" title="Check this submission before starting another replay"><p>The response for original run <code>{uncertainSubmission.sourceId}</code> could not be confirmed. Retrying uses the same saved job identity and reviewed request, including after a reload.</p><details><summary>Saved replay request</summary><pre>{JSON.stringify(uncertainSubmission.payload, null, 2)}</pre></details><Button disabled={replayMutation.isPending || resolutionMutation.isPending} onClick={() => replayMutation.mutate(uncertainSubmission)}>Retry same submission</Button><Link className="button button-secondary button-medium" to={`/runs?job=job-${uncertainSubmission.submissionId.replaceAll("-", "")}`}>View submission status</Link><p>If no job was created, close this request to edit and prepare again. If a job already exists, BlueFire opens that saved job and leaves it unchanged.</p><Button disabled={replayMutation.isPending || resolutionMutation.isPending} onClick={() => resolutionMutation.mutate(uncertainSubmission)}>{resolutionMutation.isPending ? "Checking and closing request" : "Close request and start again"}</Button></Callout> : null}</div></Panel>
    </div>
    </details> : null}
    <details className="comparison-next-steps"><summary>Other tests</summary><div><Link className="button button-ghost button-medium" to="/compare?receiver=1">Test a lab receiver control</Link><Link className="button button-ghost button-medium" to="/file-access">Test effective file access</Link></div></details>
    <MethodComparison sourceId={sourceId} runs={runsQuery.data.runs} catalog={catalogQuery.data} />
  </div>;
}

function ReplayPreflight({ report, preparation }: { report: PreflightReport; preparation?: ReplayPreparation }) {
  if (preparation) return <section aria-label="Prepared Execute replay">
    {preparation.replay_extent === "from_step" ? <Callout title="Restore and continue"><p>The runner recreates the earlier steps in a fresh workspace, verifies their files against the saved checkpoint, then continues from <strong>{String(preparation.replay_request.from_step_id)}</strong>. Earlier effects and cleanup are part of this new approval.</p></Callout> : null}
    {report.plan ? <CanonicalPlanReview plan={report.plan} cleanup={report.cleanup} scope={report.scope} binding={report.approval_binding} envelope={report.approval_envelope} adaptiveAuthorization={report.adaptive_authorization}/> : null}
    <DataList items={[{ label: "Independent observers", value: report.collectors?.length ? report.collectors.join(", ") : "None reported" }]} />
    {report.findings?.length ? <Callout tone={executeReviewReady(report) ? "warning" : "danger"} title={executeReviewReady(report) ? "Review findings" : "Replay is blocked"}><ul>{report.findings.map((item, index) => <li key={index}>{typeof item === "string" ? item : item.message ?? item.code ?? "Finding"}</li>)}</ul></Callout> : null}
    <details><summary>Original run and replay identity</summary><p>Original run: <code>{preparation.binding.source.run_id}</code></p><pre>{JSON.stringify({ preparation_id: preparation.preparation_id, binding: preparation.binding, lineage: preparation.lineage, preflight: report }, null, 2)}</pre></details>
  </section>;
  return <Callout tone="warning" title="Replay review unavailable">Prepare this replay again to review its exact source and restart settings.</Callout>;
}

function executeReviewReady(report?: PreflightReport) { return Boolean(report && report.status === "approval_required" && report.plan && report.approval_binding && report.approval_envelope); }

function assertReplayVariant(strategy: ReplayStrategy, fromStep: string, swapStep: string, swapBehavior: string): void {
  if (strategy === "from_node" && !fromStep) throw new Error("Choose a restart node for a from-node replay.");
  if (strategy === "swap" && (!swapStep || !swapBehavior)) throw new Error("Choose both a source node and compatible behavior for substitution.");
}

function prepareReplayScenario(source: Scenario, strategy: ReplayStrategy, swapStep: string, swapBehavior: string, overrides: Record<string, Record<string, unknown>>): Scenario {
  return { ...source, steps: source.steps.map((step) => ({ ...step, behavior_id: strategy === "swap" && step.id === swapStep && swapBehavior ? swapBehavior : step.behavior_id, parameters: strategy === "parameters" && overrides[step.id] ? { ...step.parameters, ...overrides[step.id] } : { ...step.parameters } })) };
}

export function parseParameterOverrides(value: string, scenario?: Scenario): Record<string, Record<string, unknown>> {
  if (value.length > 100_000) throw new Error("Parameter override JSON is too large."); const parsed: unknown = JSON.parse(value); if (!isPlainObject(parsed)) throw new Error("Parameter overrides must be a JSON object."); const entries = Object.entries(parsed); if (!entries.length || entries.length > 100) throw new Error("Supply between 1 and 100 step override objects."); const knownSteps = new Set(scenario?.steps.map((step) => step.id) ?? []); const result: Record<string, Record<string, unknown>> = {};
  for (const [stepId, parameters] of entries) { if (["__proto__", "prototype", "constructor"].includes(stepId) || !isPlainObject(parameters)) throw new Error("Each step must map to a plain parameter object."); if (scenario && !knownSteps.has(stepId)) throw new Error(`Unknown replay step: ${stepId}`); assertSafeJson(parameters); result[stepId] = parameters; }
  return result;
}

function isPlainObject(value: unknown): value is Record<string, unknown> { return Boolean(value) && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function assertSafeJson(value: unknown): void { if (Array.isArray(value)) { value.forEach(assertSafeJson); return; } if (!value || typeof value !== "object") return; for (const [key, child] of Object.entries(value as Record<string, unknown>)) { if (["__proto__", "prototype", "constructor"].includes(key)) throw new Error("Reserved object keys are not allowed."); assertSafeJson(child); } }
function providerId(source?: RunRecord) { return typeof source?.ai_provider === "string" ? source.ai_provider : source?.ai_provider && typeof source.ai_provider.provider_id === "string" ? source.ai_provider.provider_id : undefined; }
function executionScope(source: RunRecord) { const explicit = source.target_scope?.scope_refs; if (Array.isArray(explicit)) return explicit.filter((item): item is string => typeof item === "string"); const policyScope = source.policy?.authorized_target_scope; if (policyScope && typeof policyScope === "object" && Array.isArray((policyScope as Record<string, unknown>).scope_refs)) return ((policyScope as Record<string, unknown>).scope_refs as unknown[]).filter((item): item is string => typeof item === "string"); const profileScope = source.profile?.scope; return Array.isArray(profileScope) ? profileScope.filter((item): item is string => typeof item === "string") : []; }
function resolvedActions(source?: RunRecord, omittedStep?: string) { const steps = Array.isArray(source?.plan?.steps) ? source.plan.steps : []; return Object.fromEntries(steps.filter((item): item is Record<string, unknown> => Boolean(item) && typeof item === "object" && typeof item.step_id === "string" && typeof item.action_id === "string" && item.step_id !== omittedStep).map((item) => [String(item.step_id), String(item.action_id)])); }

type ComparisonSummary = ComparisonResponse["summaries"][number];

function comparedObjectiveLabel(summary: ComparisonSummary): string {
  return summary.capability_objective?.state === "unverified"
    ? "Unknown (proof unavailable)"
    : objectiveLabel(summary.objective_reached, summary.mode);
}
type RecordedComparisonSummary = ComparisonSummary & { execution_path?: unknown; first_block?: unknown };

function comparisonAttempt(value: unknown, stepId: string, stopped = false): RunStep | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  const record = value as Record<string, unknown>;
  if (record.step_id !== stepId || ![record.behavior_id, record.action_id].every(item => item === undefined || item === null || typeof item === "string" && Boolean(item.trim()))) return undefined;
  if (stopped && ![record.status, record.policy_status].some(item => typeof item === "string" && ["blocked", "control_blocked", "refused"].includes(item))) return undefined;
  // Only recorded identifiers enter the label helper; no attempt outcome is inferred.
  return { step_id: stepId, status: "not_reported", behavior_id: typeof record.behavior_id === "string" ? record.behavior_id : undefined,
    action_id: typeof record.action_id === "string" ? record.action_id : record.action_id === null ? null : undefined };
}

function comparisonSourceSteps(value: unknown): RunStep[] | undefined {
  if (!Array.isArray(value)) return undefined;
  // Validate the entire recorded sequence. Dropping malformed rows could make a
  // different source path appear to match the saved comparison.
  for (const valueStep of value) {
    if (!valueStep || typeof valueStep !== "object" || Array.isArray(valueStep)) return undefined;
    const step = valueStep as Record<string, unknown>;
    if (typeof step.step_id !== "string" || !step.step_id.trim() || typeof step.status !== "string" || !step.status.trim()
      || ![step.behavior_id, step.action_id, step.simulation_id].every(item => item === undefined || item === null || typeof item === "string" && Boolean(item.trim()))) return undefined;
  }
  return value as RunStep[];
}

function comparisonStepPresentation(summary: RecordedComparisonSummary, catalog?: CatalogResponse, source?: RunRecord) {
  const savedPath = summary.execution_path;
  const sourceSteps = savedPath === undefined ? comparisonSourceSteps(source?.steps) : undefined;
  const sourceOutcomes = Object.fromEntries((sourceSteps ?? []).map(step => [step.step_id, step.status]));
  const matchingSource = sourceSteps && source && source.run_id === summary.run_id && (!summary.mode || source.mode === summary.mode)
    && sameJson(sourceSteps?.map(step => step.step_id), summary.path)
    && Object.entries(summary.outcomes).every(([id, status]) => sourceOutcomes[id] === status) ? source : undefined;
  const savedAttempts = Array.isArray(savedPath) ? savedPath : undefined;
  const savedPathMatches = savedAttempts !== undefined && savedAttempts.length === summary.path.length
    && savedAttempts.every((step, index) => comparisonAttempt(step, summary.path[index]!));
  const present = (stepId: string, record?: RunStep) => {
    // A captured scenario describes the original plan, not necessarily an actual
    // attempt's method. Only the recorded attempt supplies label identities.
    const labels = recordedStepLabels(record ?? { step_id: stepId, status: "unknown" }, record ? catalog : undefined);
    const method = labels.method === labels.name || labels.method === `Simulation · ${labels.name}` && summary.mode === "simulate" ? undefined : labels.method;
    return { record, name: labels.name, method };
  };
  const pathCounts = new Map<string, number>();
  for (const id of summary.path) pathCounts.set(id, (pathCounts.get(id) ?? 0) + 1);
  const path = summary.path.map((id, index) => ({ ...(savedPath === undefined
    ? present(id, matchingSource ? sourceSteps?.[index] : undefined)
    : present(id, savedPathMatches ? comparisonAttempt(savedAttempts?.[index], id) : undefined)),
  repeated: pathCounts.get(id)! > 1 }));
  const stoppedId = summary.first_blocked_step;
  const savedBlock = stoppedId ? comparisonAttempt(summary.first_block, stoppedId, true) : undefined;
  const stoppedSource = savedPath === undefined && summary.first_block === undefined && matchingSource ? sourceSteps?.find(step => step.step_id === stoppedId
    && ["blocked", "control_blocked", "refused"].includes(step.status)) : undefined;
  const stoppedPath = summary.first_block === undefined && summary.path.filter(id => id === stoppedId).length === 1
    ? path[summary.path.indexOf(stoppedId!)]?.record : undefined;
  // Saved projections omit simulator IDs. Only an exact matching source can
  // supply those identities; the current catalog cannot establish an attempt.
  const simulationSource = savedPath !== undefined && savedPathMatches && summary.mode === "simulate"
    ? comparisonSourceSteps(source?.steps) : undefined;
  const boundSimulationSource = simulationSource && source?.run_id === summary.run_id && source.mode === summary.mode
    && simulationSource.length === path.length && simulationSource.every((step, index) => {
      const saved = path[index]?.record;
      return saved && step.step_id === saved.step_id && step.behavior_id === saved.behavior_id && step.action_id === saved.action_id
        && step.status === summary.outcomes[step.step_id];
    }) ? simulationSource : undefined;
  const sharedRecords = summary.mode === "simulate" ? savedPath === undefined && matchingSource ? sourceSteps : boundSimulationSource
    : summary.mode === "execute" ? path.map(step => step.record) : undefined;
  const knownStatuses = new Set(["success", "succeeded", "partial", "failed", "error", "blocked", "control_blocked", "refused", "cancelled", "interrupted", "skipped"]);
  const sharedPath = path.length && summary.path.every(id => typeof id === "string" && Boolean(id.trim()))
    && new Set(summary.path).size === path.length && Object.keys(summary.outcomes).length === path.length
    && (summary.counterfactual_steps === undefined || Array.isArray(summary.counterfactual_steps) && !summary.counterfactual_steps.length)
    && sharedRecords?.length === path.length && sharedRecords.every(step => step && typeof step.behavior_id === "string" && Boolean(step.behavior_id.trim())
      && knownStatuses.has(summary.outcomes[step.step_id]!) && Object.hasOwn(summary.outcomes, step.step_id)
      && (step.execution_disposition === undefined || step.execution_disposition === summary.mode)
      && (summary.mode === "simulate" ? typeof step.simulation_id === "string" && Boolean(step.simulation_id.trim())
        && (step.action_id === null || typeof step.action_id === "string" && Boolean(step.action_id.trim()))
        : typeof step.action_id === "string" && Boolean(step.action_id.trim())))
    ? sharedRecords.map(step => ({ step_id: step!.step_id, behavior_id: step!.behavior_id, action_id: step!.action_id,
      simulation_id: summary.mode === "simulate" ? step!.simulation_id : null, mode: summary.mode, status: summary.outcomes[step!.step_id] })) : undefined;
  return { path, sharedPath, stopped: stoppedId ? present(stoppedId, savedBlock ?? stoppedSource ?? stoppedPath) : undefined };
}

export function ComparisonResult({ comparison, names = {}, createdAt = {}, catalog, runs = [], onExplain }: { comparison: ComparisonResponse; names?: Record<string, string>; createdAt?: Record<string, string | undefined>; catalog?: CatalogResponse; runs?: RunRecord[]; onExplain?: () => void }) {
  const baseline = comparison.summaries.find((item) => item.run_id === comparison.baseline_run_id) ?? comparison.summaries[0];
  const changed = comparison.deltas.filter(hasMaterialDelta).length;
  const comparedRuns = comparison.summaries.filter(item => item.run_id !== baseline?.run_id);
  const orderedRuns = baseline ? [baseline, ...comparedRuns] : comparison.summaries;
  const firstName = orderedRuns[0] ? names[orderedRuns[0].run_id] : undefined;
  const sharedName = firstName && orderedRuns.length > 1 && orderedRuns.every(run => names[run.run_id] === firstName) ? firstName : undefined;
  const stepPresentations = new Map<string, ReturnType<typeof comparisonStepPresentation>>(orderedRuns.map(summary => {
    const sources = runs.filter(run => run.run_id === summary.run_id);
    return [summary.run_id, comparisonStepPresentation(summary, catalog, sources.length === 1 ? sources[0] : undefined)];
  }));
  const sharedPath = baseline ? stepPresentations.get(baseline.run_id)?.sharedPath : undefined;
  const canSharePath = Boolean(sharedPath && orderedRuns.length > 1 && new Set(orderedRuns.map(run => run.run_id)).size === orderedRuns.length
    && baseline?.run_id === comparison.baseline_run_id && sameJson(orderedRuns.map(run => run.run_id), comparison.run_ids)
    && orderedRuns.every(run => sameJson(stepPresentations.get(run.run_id)?.sharedPath, sharedPath)));
  const pathViewKey = JSON.stringify([comparison.comparison_id, orderedRuns.map(run => run.run_id), sharedPath]);
  const [sideBySideKey, setSideBySideKey] = useState<string>();
  const showSharedPath = canSharePath && sideBySideKey !== pathViewKey;
  const pathUnit = (summary: ComparisonSummary) => new Set(summary.path).size < summary.path.length ? "attempts" : "steps";
  const comparedRunLabel = (runId: string) => {
    if (runId === baseline?.run_id) return "Baseline";
    const index = comparedRuns.findIndex(item => item.run_id === runId);
    return index < 0 ? "Run" : `Compared run ${index + 1}`;
  };
  const runReference = (runId: string) => <small className="comparison-run-reference">{createdAt[runId] ? <time dateTime={createdAt[runId]}>{formatRunTimestamp(createdAt[runId]!)}</time> : "Timestamp not reported"}</small>;
  const pathChanges = comparison.deltas.filter(delta => delta.first_path_divergence !== null && delta.first_path_divergence !== undefined && delta.first_path_divergence >= 0).length;
  const cleanupUnknown = orderedRuns.filter(summary => typeof summary.cleanup_success !== "boolean").length;
  const conclusion = comparisonConclusion(comparison, stepPresentations);
  const conclusionReportsSharedObjective = comparison.s3_access === undefined && orderedRuns.length > 1
    && baseline?.run_id === comparison.baseline_run_id && orderedRuns.length === comparison.summaries.length
    && orderedRuns.length === comparison.run_ids.length
    && new Set(orderedRuns.map(run => run.run_id)).size === orderedRuns.length
    && sameJson(orderedRuns.map(run => run.run_id), comparison.run_ids)
    && (baseline.mode === "simulate" || baseline.mode === "execute")
    && typeof baseline.objective_reached === "boolean"
    && comparison.deltas.length === orderedRuns.length - 1
    && comparison.deltas.every((delta, index) => delta.from_run_id === baseline.run_id
      && delta.to_run_id === orderedRuns[index + 1]?.run_id
      && (delta.objective_comparability === "comparable"
        || delta.objective_comparability === undefined && orderedRuns.every(run => !run.capability_objective)))
    && orderedRuns.every(run => run.mode === baseline.mode && run.objective_reached === baseline.objective_reached);
  const firstDifferenceIndex = (runId: string) => conclusion.differences.find(difference => difference.comparedRunId === runId)?.index
    ?? (orderedRuns.length === 2 ? conclusion.differences.find(difference => difference.baselineRunId === runId)?.index : undefined);
  const recordedPath = (summary: ComparisonSummary) => summary.path.length ? <ol>{summary.path.map((step, index) => {
    const labels = stepPresentations.get(summary.run_id)!.path[index]!;
    const firstDifference = firstDifferenceIndex(summary.run_id) === index;
    return <li key={`${step}-${index}`} className={firstDifference ? "comparison-first-difference" : undefined}
      style={firstDifference ? { background: "color-mix(in srgb, var(--blue) 6%, transparent)" } : undefined}
      data-status={labels.repeated ? "not_reported" : summary.outcomes[step] === "success" ? "succeeded" : summary.outcomes[step]}><span>{String(index + 1).padStart(2, "0")}</span><strong title={step}>{firstDifference ? <><small style={{ color: "var(--blue-soft)" }}>{orderedRuns.length > 2 ? "First recorded difference from baseline" : "First recorded difference"}</small><br/></> : null}{labels.name}{labels.method ? <><br/><small>{labels.method}</small></> : null}</strong><small>{labels.repeated ? "Unreported" : sentence(summary.outcomes[step] ?? "unknown")}</small></li>;
  })}</ol> : <p className="comparison-no-path">No path steps were reported.</p>;
  const [reportUrl, setReportUrl] = useState<string>();
  const reportContent = useMemo(() => comparisonReport(comparison, names, createdAt), [comparison, names, createdAt]);
  useEffect(() => {
    const url = URL.createObjectURL(new Blob([reportContent], { type: "text/markdown;charset=utf-8" }));
    setReportUrl(url);
    return () => URL.revokeObjectURL(url);
  }, [reportContent]);
  return <div className="comparison-results">
    <section className="comparison-conclusion" aria-label="Comparison conclusion">
      <div className="comparison-conclusion-icon"><GitCompareArrows aria-hidden="true" /></div>
      <div className="comparison-conclusion-copy"><p className="eyebrow">Recorded comparison</p><h2>{conclusion.title}</h2><p>{conclusion.detail}</p></div>
      <div className={`comparison-conclusion-metrics${changed === 0 && pathChanges === 0 && cleanupUnknown === 0 ? ` comparison-conclusion-metrics-quiet${onExplain ? " comparison-conclusion-metrics-has-action" : ""}` : ""}`}>
        {changed === 0 && pathChanges === 0 && cleanupUnknown === 0
          ? <div className="comparison-conclusion-zero-summary" aria-label="Comparison summary counts"><span><strong>{changed}</strong> compared runs changed</span><span><strong>{pathChanges}</strong> compared paths changed</span><span><strong>{cleanupUnknown}</strong> runs with cleanup unreported</span></div>
          : <><div><strong>{changed}</strong><span>compared runs changed</span></div><div><strong>{pathChanges}</strong><span>compared paths changed</span></div><div><strong>{cleanupUnknown}</strong><span>runs with cleanup unreported</span></div></>}
        {onExplain ? <Button size="small" variant="secondary" onClick={onExplain}>Explain comparison</Button> : null}
      </div>
    </section>
    <section className="comparison-run-overview" role="group" aria-label="Comparison run order">
      <header className="comparison-section-heading"><h2>{sharedName ?? "Baseline and compared runs"}</h2><div className="comparison-run-actions"><span>{comparison.run_ids.length} runs reviewed</span>{reportUrl ? <a className="button button-secondary button-small comparison-download" href={reportUrl} download="bluefire-comparison.md"><Download aria-hidden="true"/>Download report</a> : null}</div></header>
      <div className="compare-story">{orderedRuns.map(summary => <article className="compare-story-run" key={summary.run_id} aria-label={`${comparedRunLabel(summary.run_id)} result`}>
        <header>{sharedName ? <Link className="comparison-role-link" to={runReviewPath(summary.run_id)} aria-label={summary.run_id === baseline?.run_id ? "Review baseline run" : `Review ${comparedRunLabel(summary.run_id).toLowerCase()}`}><Badge tone={summary.run_id === baseline?.run_id ? "info" : "neutral"}>{comparedRunLabel(summary.run_id)}</Badge><ArrowUpRight aria-hidden="true"/></Link> : <Badge tone={summary.run_id === baseline?.run_id ? "info" : "neutral"}>{comparedRunLabel(summary.run_id)}</Badge>}<span>{summary.mode === "simulate" ? "Simulate · synthetic" : summary.mode ? sentence(summary.mode) : "Mode not reported"}</span></header>
        {!sharedName ? <h3><Link to={runReviewPath(summary.run_id)}>{names[summary.run_id] ?? "Run"}<ArrowUpRight aria-hidden="true"/></Link></h3> : null}{runReference(summary.run_id)}
        {!conclusionReportsSharedObjective ? <div className="compare-run-objective"><span>Objective</span><strong data-state={typeof summary.objective_reached !== "boolean" ? "unknown" : summary.objective_reached ? "achieved" : "unmet"}>{comparedObjectiveLabel(summary)}</strong></div> : null}
        <footer><span><GitBranch aria-hidden="true"/>{summary.path.length} recorded {pathUnit(summary)}</span><span><Eye aria-hidden="true"/>{reportedArrayCount(summary.evidence_details?.observed_artifacts, "observed artifact")}</span><details className="comparison-run-record"><summary>Run record</summary><code>{summary.run_id}</code></details></footer>
      </article>)}</div>
    </section>
    {comparison.s3_access ? <S3AccessComparisonResults result={comparison.s3_access} /> : null}
    <div className="comparison-main-grid">
    <Panel className="comparison-outcomes"><PanelHeader title="Recorded outcomes" detail="Objective, observations, and cleanup are separate results." />
      <div className="table-scroll" role="region" aria-label="Compared run outcomes" tabIndex={0}>
        <table><caption className="sr-only">Recorded outcomes for the selected runs. Missing values remain unreported.</caption><thead><tr><th scope="col">Result</th>{orderedRuns.map(summary => <th scope="col" key={summary.run_id}><Link to={runReviewPath(summary.run_id)} aria-label={summary.run_id === baseline?.run_id ? "Review baseline run summary" : `Review ${comparedRunLabel(summary.run_id).toLowerCase()} summary`}>{comparedRunLabel(summary.run_id)}<ArrowUpRight aria-hidden="true"/></Link></th>)}</tr></thead>
          <tbody>
            <tr><th scope="row">Mode</th>{orderedRuns.map(summary => <td key={summary.run_id}>{sentence(summary.mode ?? "not_reported")}</td>)}</tr>
            <tr><th scope="row">Objective</th>{orderedRuns.map(summary => <td key={summary.run_id}>{comparedObjectiveLabel(summary)}</td>)}</tr>
            {orderedRuns.some(summary => summary.capability_objective) ? <>
              <tr><th scope="row">Run-level completion</th>{orderedRuns.map(summary => <td key={summary.run_id}>{summary.capability_objective ? summary.graph_objective_reached === true ? "Met" : "Not met" : "Not applicable"}</td>)}</tr>
              <tr><th scope="row">Capability proof</th>{orderedRuns.map(summary => <td key={summary.run_id}>{summary.capability_objective ? summary.capability_objective.state === "verified" ? "Verified" : "Unavailable" : "Not applicable"}</td>)}</tr>
            </> : null}
            <tr><th scope="row">Observed artifacts</th>{orderedRuns.map(summary => <td key={summary.run_id}>{reportedArrayCount(summary.evidence_details?.observed_artifacts, "artifact")}</td>)}</tr>
            <tr><th scope="row">Evidence gaps</th>{orderedRuns.map(summary => <td key={summary.run_id}>{reportedArrayCount(summary.evidence_details?.evidence_gaps, "gap")}</td>)}</tr>
            <tr><th scope="row">First stopped step</th>{orderedRuns.map(summary => {
              const stopped = stepPresentations.get(summary.run_id)?.stopped;
              return <td key={summary.run_id}>{summary.first_blocked_step ? <span title={summary.first_blocked_step}>{stopped?.name}{stopped?.record && stopped.method ? <><br/><small>{stopped.method}</small></> : null}</span> : "None recorded"}</td>;
            })}</tr>
            <tr><th scope="row">Cleanup</th>{orderedRuns.map(summary => <td key={summary.run_id}>{comparisonCleanup(summary)}</td>)}</tr>
          </tbody>
        </table>
      </div><p className="comparison-boundary-note">A stopped step alone does not establish target prevention.{orderedRuns.some(summary => summary.capability_objective) ? " For composed runs, the objective uses verified capability proof; run-level completion records the graph and observations separately." : null}</p>
    </Panel>
    <section className="comparison-paths" aria-label="Recorded run paths"><header className="comparison-section-heading"><h2>Paths taken</h2>{canSharePath ? <Button size="small" variant="ghost" aria-pressed={!showSharedPath} onClick={() => setSideBySideKey(showSharedPath ? pathViewKey : undefined)}>{showSharedPath ? "Compare paths side by side" : "Show shared path"}</Button> : <GitBranch aria-hidden="true"/>}</header>
    {showSharedPath && baseline ? <div className="compare-lanes comparison-shared-path"><article aria-label="Same recorded path">
      <header><strong>Same recorded path</strong><small>{baseline.path.length} steps</small></header>
      <p className="comparison-shared-scope">Recorded methods and step results match for these runs.</p>
      <div className="comparison-path-participants" aria-label="Runs sharing this recorded path">{orderedRuns.map(summary => <Link key={summary.run_id} to={runReviewPath(summary.run_id)} aria-label={`Review ${comparedRunLabel(summary.run_id).toLowerCase()} shared path run`}><span>{comparedRunLabel(summary.run_id)}</span>{!sharedName && names[summary.run_id] ? <strong>{names[summary.run_id]}</strong> : null}<ArrowUpRight aria-hidden="true"/></Link>)}</div>
      {recordedPath(baseline)}
      {orderedRuns.some(summary => summary.replay_lineage?.defense_change_declared) ? <p className="comparison-change-note">Defense change declared; not independently verified. Review each run's context in the side-by-side view.</p> : null}
    </article></div> : <div className="compare-lanes">{orderedRuns.map((summary) => <article key={summary.run_id}>
      <header><Link to={runReviewPath(summary.run_id)} aria-label={`Review ${comparedRunLabel(summary.run_id).toLowerCase()} execution lane`}>{comparedRunLabel(summary.run_id)}<ArrowUpRight aria-hidden="true"/></Link><small>{summary.path.length} {pathUnit(summary)}</small></header>
      {recordedPath(summary)}
      {pathUnit(summary) === "attempts" ? <p className="field-note">Individual attempt results were not recorded.</p> : null}
      {summary.replay_lineage?.defense_change_declared ? <p className="comparison-change-note">Defense change declared; not independently verified.</p> : null}
      <details className="comparison-run-details"><summary>Run context and technical details</summary><DataList items={[
        { label: "Mode / profile", value: `${sentence(summary.mode ?? "not_reported")} / ${summary.profile_id ?? "Not reported"}` },
        { label: "Target scope", value: formatTargetScope(summary.target_scope) },
        { label: "Recorded run change", value: formatReplayLineage(summary.replay_lineage) },
        { label: "Objective", value: comparedObjectiveLabel(summary) },
        { label: "First block", value: stepPresentations.get(summary.run_id)?.stopped?.name ?? "None recorded" },
        { label: "First stopped step ID", value: summary.first_blocked_step ? <code>{summary.first_blocked_step}</code> : "None recorded" },
        { label: "Recorded path step IDs", value: summary.path.length ? <code>{summary.path.join(" → ")}</code> : "None recorded" },
        { label: "Recorded behavior IDs", value: <code>{stepPresentations.get(summary.run_id)!.path.map(step => step.record ? step.record.behavior_id ?? "Not recorded" : "Unavailable").join(" → ") || "None recorded"}</code> },
        { label: "Recorded method IDs", value: <code>{stepPresentations.get(summary.run_id)!.path.map(step => step.record ? step.record.action_id ?? step.record.simulation_id ?? "Not recorded" : "Unavailable").join(" → ") || "None recorded"}</code> },
        { label: "Final recorded results by step ID", value: <code>{Object.entries(summary.outcomes).map(([id, status]) => `${id}: ${typeof status === "string" ? sentence(status) : "Not reported"}`).join("; ") || "Not reported"}</code> },
        { label: "Cleanup", value: summary.cleanup_success === false ? "Outstanding" : summary.cleanup_success === true ? (summary.mode === "simulate" ? "No real effects (Simulate)" : "Reconciled") : "Not reported" },
        { label: "Duration", value: formatDuration(summary.duration_ms) },
        { label: "Outcomes", value: formatCountMap(summary.outcome_counts ?? countValues(Object.values(summary.outcomes)), "None reported") },
        { label: "Evidence provenance", value: formatCountMap(summary.evidence_provenance, "None reported") },
        { label: "Independent evidence", value: formatEvidenceDetails(summary.evidence_details) },
        { label: "Run-record candidate states", value: formatCountMap(summary.detection_states, "None reported") },
        { label: "Run-record candidate matches", value: formatReportedCount(summary.detection_matches) },
        { label: "Run-record benign matches", value: formatReportedCount(summary.benign_matches) },
        { label: "Policy decisions", value: formatCountMap(summary.policy_states, "None reported") },
        { label: "Telemetry", value: formatList(summary.telemetry) },
        { label: "Controls", value: formatList(summary.controls) },
        { label: "AI autonomy", value: summary.autonomy ? sentence(summary.autonomy) : "Not reported" },
        { label: "AI provider", value: summary.ai_provider_id ?? "None reported" },
        { label: "AI proposals", value: `${formatReportedCount(summary.ai_proposal_count)} · ${formatCountMap(summary.ai_applications, "No applications reported")}` },
        { label: "Remaining budgets", value: formatCountMap(summary.remaining_budgets, "None reported") },
        { label: "Counterfactual path", value: formatList(summary.counterfactual_steps, "None recorded") },
      ]} /></details>
    </article>)}</div>}</section>
    </div>
    <p className="comparison-provenance-note">Selection order does not establish a fresh retest or a changed environment. Review each run's recorded lineage and observations.</p>
    <div className="comparison-support-grid">
      <section className="comparison-support-card" aria-label="Changes between runs"><header><GitCompareArrows aria-hidden="true"/><h2>What changed</h2></header>{comparison.deltas.length ? comparison.deltas.map(delta => <article key={delta.to_run_id}><h3>{comparedRunLabel(delta.to_run_id)}</h3><ul>{comparisonChangeNotes(delta).map(note => <li key={note}>{note}</li>)}</ul></article>) : <p>No comparison delta was reported.</p>}</section>
      <section className="comparison-support-card" aria-label="Supporting observations"><header><Eye aria-hidden="true"/><h2>Supporting observations</h2></header>{orderedRuns.map(summary => <article key={summary.run_id}><h3>{comparedRunLabel(summary.run_id)}</h3><p>{Array.isArray(summary.evidence_details?.observed_artifacts) ? `${reportedArrayCount(summary.evidence_details.observed_artifacts, "artifact")} independently observed.` : "Independently observed artifacts not reported."}</p><small>{summary.mode === "simulate" ? "Run outcomes are synthetic." : "Runner-reported outcomes remain separate."}</small><p className="comparison-observation-types"><strong>{summary.mode === "simulate" ? "Synthetic step telemetry" : "Step-reported telemetry"}</strong>: {Array.isArray(summary.telemetry) ? formatList(summary.telemetry, "None recorded") : "Not reported"}</p></article>)}</section>
      <section className="comparison-support-card" aria-label="Cleanup and unknowns"><header><ShieldAlert aria-hidden="true"/><h2>Cleanup and unknowns</h2></header>{orderedRuns.map(summary => <article key={summary.run_id}><h3>{comparedRunLabel(summary.run_id)}<span data-state={summary.cleanup_success === false ? "attention" : "neutral"}>{comparisonCleanup(summary)}</span></h3><p>{Array.isArray(summary.evidence_details?.evidence_gaps) ? summary.evidence_details.evidence_gaps.length ? `${reportedArrayCount(summary.evidence_details.evidence_gaps, "gap")} recorded.` : "No evidence gaps recorded." : "Evidence gaps not reported."}</p>{summary.evidence_details?.evidence_gaps?.length ? <ul>{summary.evidence_details.evidence_gaps.map((gap, index) => <li key={index}>{typeof gap.reason === "string" ? sentence(gap.reason) : "Recorded evidence gap"}</li>)}</ul> : null}</article>)}</section>
    </div>
    <details className="comparison-detail"><summary>Detailed changes in evidence, policy, and runtime</summary>
    <div className="delta-grid">{comparison.deltas.map((delta) => {
      const assessment = delta.assessment ?? (hasMaterialDelta(delta) ? "material_change" : "no_material_change");
      const noPathDivergence = delta.first_path_divergence === null || delta.first_path_divergence === undefined || delta.first_path_divergence < 0;
      return <Panel key={delta.to_run_id}><PanelHeader title={`${comparedRunLabel(delta.from_run_id)} → ${comparedRunLabel(delta.to_run_id)}`} detail={`${sentence(assessment)} · ${formatList(delta.signals, "No assessment signals")}`} actions={<Badge tone={assessmentTone(assessment)}>{sentence(assessment)}</Badge>} />
        <div className="delta-summary"><div><span>{noPathDivergence ? <CheckCircle2/> : <ShieldAlert/>}</span><strong>Path divergence</strong><small>{noPathDivergence ? "No divergence" : `Node index ${delta.first_path_divergence! + 1}`}</small></div><div><span>{delta.objective_changed || delta.objective_comparability === "different_objectives" || delta.objective_comparability === "unverified" ? <ShieldAlert/> : <CheckCircle2/>}</span><strong>Objective</strong><small>{comparisonObjectiveChange(delta)}</small></div><div><span>{delta.first_blocked_changed ? <ShieldAlert/> : <CheckCircle2/>}</span><strong>First stopped step</strong><small>{formatChanged(delta.first_blocked_changed)}</small></div><div><span>{delta.cleanup_changed ? <ShieldAlert/> : <CheckCircle2/>}</span><strong>Cleanup</strong><small>{formatChanged(delta.cleanup_changed)}</small></div></div>
        <div className="delta-columns">
          <div><h3>Evidence, detections & outcomes</h3><DataList items={[
            { label: "Evidence delta", value: formatDeltaMap(delta.evidence_delta) },
            { label: "Observed artifact delta", value: formatObservedArtifactDelta(delta.evidence_detail_delta) },
            { label: "Evidence gap delta", value: formatEvidenceGapDelta(delta.evidence_detail_delta) },
            { label: "Detection lifecycle delta", value: formatDeltaMap(delta.detection_delta) },
            { label: "Detection match delta", value: formatSignedNumber(delta.detection_match_delta) },
            { label: "Benign match delta", value: formatSignedNumber(delta.benign_match_delta) },
            { label: "Outcome delta", value: formatDeltaMap(delta.outcome_delta) },
          ]} /></div>
          <div><h3>Policy, AI & runtime</h3><DataList items={[
            { label: "Assessment", value: sentence(assessment) },
            { label: "Signals", value: formatList(delta.signals, "No material signals") },
            { label: "Autonomy", value: formatChanged(delta.autonomy_changed) },
            { label: "AI provider", value: formatChanged(delta.ai_provider_changed) },
            { label: "AI proposal delta", value: formatSignedNumber(delta.ai_proposal_delta) },
            { label: "Target scope", value: formatChanged(delta.target_scope_changed) },
            { label: "Replay Variant", value: formatReplayDelta(delta.replay_lineage_delta) },
            { label: "Duration delta", value: formatDurationDelta(delta.duration_delta_ms) },
          ]} /></div>
          <div><h3>Telemetry & controls</h3><DataList items={[
            { label: "Telemetry added", value: formatList(delta.telemetry_added) },
            { label: "Telemetry removed", value: formatList(delta.telemetry_removed) },
            { label: "Controls added", value: formatList(delta.controls_added) },
            { label: "Controls removed", value: formatList(delta.controls_removed) },
          ]} /></div>
        </div>
        <details><summary>Show technical comparison delta</summary><pre aria-label={`Technical comparison delta ${delta.to_run_id}`}>{JSON.stringify(delta, null, 2)}</pre></details>
      </Panel>;
    })}</div>
    </details>
    <details className="comparison-identity"><summary>Comparison record</summary><code>{comparison.comparison_id}</code><p>Baseline: {baseline?.run_id ?? comparison.baseline_run_id}</p></details>
  </div>;
}

type ComparisonDeltaItem = ComparisonResponse["deltas"][number];

function comparisonCleanup(summary: ComparisonResponse["summaries"][number]) {
  return summary.cleanup_success === false ? "Needs attention" : summary.cleanup_success === true ? (summary.mode === "simulate" ? "No real effects" : "Complete") : "Not reported";
}

function comparisonChangeNotes(delta: ComparisonDeltaItem): string[] {
  const notes: string[] = [];
  if (delta.first_path_divergence !== null && delta.first_path_divergence !== undefined && delta.first_path_divergence >= 0) notes.push(`Path diverges at step ${delta.first_path_divergence + 1}.`);
  if (delta.dimensions?.implementation?.changed) notes.push("Implementation changed.");
  if (delta.material_configuration_changed) notes.push("Run configuration changed.");
  if (delta.objective_comparability === "different_objectives") notes.push("Objective checks differ across these runs; their results are not comparable.");
  else if (delta.objective_comparability === "unverified") notes.push("Objective change is unknown because result proof is unavailable.");
  else if (delta.objective_changed) notes.push("Objective result changed.");
  if (delta.first_blocked_changed) notes.push("First stopped step changed.");
  if (delta.cleanup_changed) notes.push("Cleanup result changed.");
  if (delta.evidence_detail_delta?.observed_artifacts_added?.length || delta.evidence_detail_delta?.observed_artifacts_removed?.length || delta.evidence_detail_delta?.observed_artifacts_changed?.length) notes.push("Observed artifacts changed.");
  if (!notes.length) notes.push(hasMaterialDelta(delta) ? "Recorded changes are available in the detailed comparison." : "No meaningful recorded change.");
  return notes;
}

function assessmentTone(value: string): "neutral" | "success" | "warning" | "danger" {
  return value === "improved" ? "success" : value === "regressed" ? "danger" : value === "no_material_change" ? "neutral" : "warning";
}

function formatChanged(value?: boolean) { return value === undefined ? "Not reported" : value ? "Changed" : "Stable"; }
function comparisonObjectiveChange(delta: ComparisonDeltaItem) {
  return delta.objective_comparability === "different_objectives" ? "Different objectives"
    : delta.objective_comparability === "unverified" ? "Proof unavailable" : formatChanged(delta.objective_changed);
}
function formatReportedCount(value?: number) { return value === undefined ? "Not reported" : new Intl.NumberFormat().format(value); }
function formatList(values?: string[], empty = "None") { return values?.length ? values.map(sentence).join(", ") : empty; }
function formatTargetScope(value?: ComparisonResponse["summaries"][number]["target_scope"]) {
  if (!value || value.state !== "bound") return "Not recorded";
  return `${formatReportedCount(value.scope_ref_count)} scope ref${value.scope_ref_count === 1 ? "" : "s"} · ${shortDigest(value.scope_digest)}`;
}
function formatReplayLineage(value?: ComparisonResponse["summaries"][number]["replay_lineage"]) {
  if (!value || value.state !== "replay") return "Original run";
  const variants = formatList(value.variant_types, "exact replay");
  const source = value.source_run_id ? ` from ${shortId(value.source_run_id)}` : "";
  const defense = value.defense_change_declared ? ` · defense change declared; digest ${shortDigest(value.defense_change_digest)} (not independently verified)` : "";
  return `${variants}${source}${defense}`;
}
function formatReplayDelta(value?: ComparisonDeltaItem["replay_lineage_delta"]) {
  if (!value || !value.changed) return "Stable";
  const variants = formatList(value.to_variant_types, "No Variant labels");
  const defense = value.defense_change_declared ? ` · defense change declared; digest ${shortDigest(value.defense_change_digest)} (not independently verified)` : "";
  return `${variants}${defense}`;
}
function formatEvidenceDetails(value?: { producer_counts?: Record<string, number>; observed_artifacts?: Array<Record<string, unknown>>; evidence_gaps?: Array<Record<string, unknown>> }) {
  if (!value) return "None reported";
  const observed = value.observed_artifacts?.length ?? 0;
  const gaps = value.evidence_gaps?.length ?? 0;
  const producers = formatCountMap(value.producer_counts, "no producers");
  return `${observed} observed artifact${observed === 1 ? "" : "s"} · ${gaps} gap${gaps === 1 ? "" : "s"} · ${producers}`;
}
function formatObservedArtifactDelta(value?: ComparisonDeltaItem["evidence_detail_delta"]) {
  if (!value) return "None";
  const added = value.observed_artifacts_added?.length ?? 0;
  const removed = value.observed_artifacts_removed?.length ?? 0;
  const changed = value.observed_artifacts_changed?.length ?? 0;
  return added || removed || changed ? `+${added} / -${removed} / ${changed} changed` : "Stable";
}
function formatEvidenceGapDelta(value?: ComparisonDeltaItem["evidence_detail_delta"]) {
  if (!value) return "None";
  const added = value.evidence_gaps_added?.length ?? 0;
  const removed = value.evidence_gaps_removed?.length ?? 0;
  return added || removed ? `+${added} / -${removed} gaps` : "Stable";
}
function countValues(values: string[]) { return values.reduce<Record<string, number>>((counts, value) => { counts[value] = (counts[value] ?? 0) + 1; return counts; }, {}); }
function formatCountMap(values?: Record<string, number>, empty = "None") { return values && Object.keys(values).length ? Object.entries(values).map(([key, value]) => `${sentence(key)}: ${new Intl.NumberFormat().format(value)}`).join(", ") : empty; }
function formatDeltaMap(values?: Record<string, number>) { return values && Object.keys(values).length ? Object.entries(values).map(([key, value]) => `${sentence(key)} ${value >= 0 ? "+" : ""}${value}`).join(", ") : "No delta"; }
function formatSignedNumber(value?: number) { return value === undefined ? "Not reported" : value === 0 ? "No delta" : `${value > 0 ? "+" : ""}${new Intl.NumberFormat().format(value)}`; }
function shortDigest(value?: string | null) { return value && value.length > 18 ? `${value.slice(0, 14)}…${value.slice(-6)}` : value ?? "No digest"; }
function formatDuration(value?: number | null) { if (value === undefined || value === null) return "Not reported"; return formatMilliseconds(value); }
function formatDurationDelta(value?: number | null) { if (value === undefined || value === null) return "Not comparable"; return value === 0 ? "No delta" : `${value > 0 ? "+" : "−"}${formatMilliseconds(Math.abs(value))}`; }
function formatMilliseconds(value: number) { return Math.abs(value) < 1_000 ? `${new Intl.NumberFormat().format(value)} ms` : `${(value / 1_000).toLocaleString(undefined, { maximumFractionDigits: 2 })} s`; }
function reportedArrayCount(value: unknown, noun: string) {
  if (!Array.isArray(value)) return "Not reported";
  return `${new Intl.NumberFormat().format(value.length)} ${noun}${value.length === 1 ? "" : "s"}`;
}
function runReviewPath(runId: string) { return `/runs/${encodeURIComponent(runId)}`; }
function shortId(value: string) { return value.length > 22 ? `${value.slice(0, 10)}…${value.slice(-8)}` : value; }
function formatRunTimestamp(value: string) {
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return "Timestamp not reported";
  return new Intl.DateTimeFormat(undefined, { year: "numeric", month: "short", day: "numeric", hour: "numeric", minute: "2-digit", second: "2-digit", timeZoneName: "short" }).format(date);
}
