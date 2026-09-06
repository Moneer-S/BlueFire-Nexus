import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, GitCompareArrows, RotateCcw, Search, ShieldAlert, ShieldCheck } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { api, buildReplayPayload, DEMO_MODE, type ReplayPreparation } from "../lib/api";
import { hasMaterialDelta } from "../lib/comparison-materiality";
import { readPendingReplay, storePendingReplay, clearPendingReplay } from "../lib/replay-submission";
import { sameJson } from "../lib/replay-review";
import { comparisonReport } from "../lib/comparison-report";
import { sourceRunParam } from "../lib/run-handoffs";
import { ReplayParameterEditor } from "../components/ReplayParameterEditor";
import { CanonicalPlanReview } from "../components/CanonicalPlanReview";
import { DetectorEvaluationComparison } from "../components/DetectorEvaluationComparison";
import type { AutonomyLevel, ComparisonResponse, PreflightReport, RunConfiguration, RunRecord, Scenario } from "../types";
import { Badge, Button, Callout, DataList, EmptyState, ErrorState, Field, LoadingState, PageHeader, Panel, PanelHeader, formatDate, sentence } from "../components/Primitives";

type ReplayStrategy = "exact" | "from_node" | "swap" | "parameters" | "setup";
const defaultParameterJson = "{}";
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
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();
  const submissionRef = useRef<ReplayAttempt | undefined>(undefined);
  const [restoredSubmission, setRestoredSubmission] = useState(readPendingReplay);
  const linkedSource = sourceRunParam(searchParams, "source");
  const linkedReplay = sourceRunParam(searchParams, "replay");
  const runsQuery = useQuery({ queryKey: ["runs"], queryFn: api.runs }); const catalogQuery = useQuery({ queryKey: ["catalog"], queryFn: api.catalog }); const client = useQueryClient();
  const [selected, setSelected] = useState<string[]>(() => [...new Set([linkedSource, linkedReplay].filter(Boolean))]); const [search, setSearch] = useState(""); const [comparison, setComparison] = useState<ComparisonResponse>(); const [sourceId, setSourceId] = useState(linkedSource); const [strategy, setStrategy] = useState<ReplayStrategy>("exact");
  const [fromStep, setFromStep] = useState(""); const [swapStep, setSwapStep] = useState(""); const [swapBehavior, setSwapBehavior] = useState(""); const [profile, setProfile] = useState(""); const [autonomy, setAutonomy] = useState<"preserve" | AutonomyLevel>("preserve"); const [provider, setProvider] = useState(""); const [defenseChange, setDefenseChange] = useState(""); const [parameterJson, setParameterJson] = useState(defaultParameterJson); const [targetScope, setTargetScope] = useState("");
  const [replayPreflight, setReplayPreflight] = useState<PreflightReport>(); const [replayConfirmed, setReplayConfirmed] = useState(false); const [approvedBy, setApprovedBy] = useState(""); const [localError, setLocalError] = useState<string>();
  const [preparation, setPreparation] = useState<ReplayPreparation>();
  const [parameterDraftValid, setParameterDraftValid] = useState(true);
  const parameterDraftValidRef = useRef(true);
  const preflightGeneration = useRef(0);
  const navigationGeneration = useRef(0);
  const comparisonGeneration = useRef(0);
  const resultsRef = useRef<HTMLDivElement>(null);
  useEffect(() => () => { navigationGeneration.current += 1; preflightGeneration.current += 1; comparisonGeneration.current += 1; }, []);
  useEffect(() => { if (comparison) { resultsRef.current?.focus({ preventScroll: true }); resultsRef.current?.scrollIntoView({ block: "start" }); } }, [comparison]);
  const detailQuery = useQuery({ queryKey: ["run", sourceId], queryFn: () => api.runDetail(sourceId), enabled: Boolean(sourceId) });
  const compareMutation = useMutation({ mutationFn: async (attempt: ComparisonAttempt) => {
    const result = await api.compare(attempt.runIds);
    if (JSON.stringify(result.summaries.map((run) => run.run_id)) !== JSON.stringify(attempt.runIds)) throw new Error("The returned comparison does not match the selected runs. Refresh the history and compare again.");
    return result;
  }, onSuccess: (result, attempt) => {
    if (attempt.generation === comparisonGeneration.current) setComparison(result);
  } });
  const source = detailQuery.data ?? runsQuery.data?.runs.find((run) => run.run_id === sourceId);
  const changeSelection = (runId: string, checked: boolean) => {
    comparisonGeneration.current += 1;
    setComparison(undefined);
    setSelected((items) => checked ? [...new Set([...items, runId])] : items.filter((id) => id !== runId));
  };
  const resetReview = () => { preflightGeneration.current += 1; setReplayPreflight(undefined); setPreparation(undefined); setReplayConfirmed(false); setApprovedBy(""); setLocalError(undefined); };
  useEffect(() => {
    navigationGeneration.current += 1;
    comparisonGeneration.current += 1;
    setSourceId(linkedSource);
    setSelected([...new Set([linkedSource, linkedReplay].filter(Boolean))]);
    setComparison(undefined);
    preflightGeneration.current += 1;
    setReplayPreflight(undefined); setPreparation(undefined); setReplayConfirmed(false); setApprovedBy("");
  }, [linkedSource, linkedReplay]);
  useEffect(() => {
    setStrategy("exact"); setFromStep(""); setSwapStep(""); setSwapBehavior("");
    setProfile(""); setAutonomy("preserve"); setProvider(""); setTargetScope("");
    setParameterJson(defaultParameterJson); parameterDraftValidRef.current = true; setParameterDraftValid(true); setDefenseChange(""); setLocalError(undefined);
  }, [linkedSource]);
  useEffect(() => { if (!detailQuery.data || detailQuery.data.mode !== "execute") return; const refs = executionScope(detailQuery.data); setTargetScope(refs.join(", ")); resetReview(); }, [detailQuery.data]);
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
    actionImplementations: source?.mode === "execute" && strategy !== "exact" ? actionImplementations : undefined });
  const preflightMutation = useMutation({ mutationFn: async (attempt: ReplayPreflightAttempt) => {
    assertReplayVariant(attempt.strategy, attempt.fromStep, attempt.swapStep, attempt.swapBehavior);
    if (!attempt.scopeRefs.length) throw new Error("Execute replay requires an exact target scope.");
    if (attempt.strategy === "parameters") parseParameterOverrides(attempt.parameterJson, attempt.sourceScenario);
    if (attempt.strategy === "from_node") return { generation: attempt.generation, report: await api.preflight(attempt.scenario, attempt.config), preparation: undefined };
    const prepared = await api.prepareReplay(attempt.sourceId, attempt.payload);
    if (prepared.schema_version !== "bluefire.replay-preparation.v1" || prepared.replay_extent !== "full" || prepared.binding.source.run_id !== attempt.sourceId ||
      !sameJson(prepared.replay_request, attempt.payload) || !sameJson(prepared.binding.replay_request, attempt.payload) || prepared.effects_started !== false || prepared.approval_created !== false)
      throw new Error("The returned review does not match this replay request. Prepare it again.");
    return { generation: attempt.generation, report: prepared.preflight, preparation: prepared };
  }, onSuccess: ({ generation, report, preparation: prepared }) => {
    if (generation !== preflightGeneration.current) return;
    setReplayPreflight(report); setPreparation(prepared); setReplayConfirmed(false); setApprovedBy(""); setLocalError(undefined);
  }, onError: (error, attempt) => {
    if (attempt.generation !== preflightGeneration.current) return;
    setReplayPreflight(undefined); setPreparation(undefined); setLocalError(error instanceof Error ? error.message : "Replay preparation failed.");
  } });
  const requestPreflight = () => {
    if (!replayScenario || !replayConfig || !variantReady || (strategy === "parameters" && !parameterDraftValidRef.current)) return;
    try {
      resetReview(); const generation = preflightGeneration.current;
      preflightMutation.mutate({ generation, sourceId, payload: structuredClone(currentReplayPayload()), scenario: structuredClone(replayScenario), config: structuredClone(replayConfig), strategy, fromStep, swapStep, swapBehavior, scopeRefs: [...scopeRefs], parameterJson, sourceScenario: source?.scenario ? structuredClone(source.scenario) : undefined });
    } catch (error) { setLocalError(error instanceof Error ? error.message : "Replay preparation failed."); }
  };
  const replayMutation = useMutation({
    mutationFn: async (attempt: ReplayAttempt) => {
      if (attempt.legacy) return { kind: "legacy" as const, run: await api.replay(attempt.sourceId, attempt.payload) };
      const prepared = attempt.preparation ?? await api.prepareReplay(attempt.sourceId, attempt.payload);
      if (prepared.schema_version !== "bluefire.replay-preparation.v1" || prepared.replay_extent !== "full" || prepared.binding?.source?.run_id !== attempt.sourceId || !sameJson(prepared.replay_request, attempt.payload) || !sameJson(prepared.binding.replay_request, attempt.payload) || prepared.effects_started !== false || prepared.approval_created !== false) throw new Error("The prepared replay does not match this submission.");
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
      setSelected([attempt.sourceId, run.run_id]); setComparison(undefined);
      setSearchParams({ source: attempt.sourceId, replay: run.run_id });
      setLocalError(undefined); setReplayPreflight(undefined); setPreparation(undefined); setReplayConfirmed(false); setApprovedBy("");
    },
    onError: (error, attempt) => {
      if (attempt.navigationGeneration !== navigationGeneration.current) return;
      setLocalError(error instanceof Error ? error.message : "Replay submission could not be confirmed.");
      if (!attempt.publicationStarted) { clearPendingReplay(attempt.submissionId); setRestoredSubmission(undefined); setReplayPreflight(undefined); setPreparation(undefined); submissionRef.current = undefined; }
    },
    onSettled: (_run, _error, attempt) => { if (attempt.navigationGeneration === navigationGeneration.current) { setReplayConfirmed(false); setApprovedBy(""); } },
  });
  const uncertainSubmission = replayMutation.isError && replayMutation.variables?.publicationStarted && replayMutation.variables.navigationGeneration === navigationGeneration.current ? replayMutation.variables : restoredSubmission ? { ...restoredSubmission, navigationGeneration: navigationGeneration.current, legacy: false, publicationStarted: true } : undefined;
  const requestReplay = () => {
    try {
      if (!detailQuery.isSuccess || !source || source.run_id !== sourceId) throw new Error("Select a source run.");
      assertReplayVariant(strategy, fromStep, swapStep, swapBehavior);
      if (!variantReady || (strategy === "parameters" && !parameterDraftValidRef.current)) throw new Error("Finish the parameter change before running the replay.");
      const execute = source.mode === "execute";
      if (execute && (!scopeRefs.length || !executeReviewReady(replayPreflight) || (strategy === "from_node" && (!replayConfirmed || !approvedBy.trim())))) throw new Error("Execute replay requires the displayed prospective review and a fresh explicit approval.");
      const current = currentReplayPayload();
      if (execute && strategy !== "from_node" && (!preparation || preparation.binding.source.run_id !== sourceId || !sameJson(preparation.replay_request, current))) throw new Error("Prepare the exact replay before approving it.");
      const payload = execute && strategy === "from_node" ? {
        ...(preparation ? preparation.replay_request : current),
        ...(preparation ? { preparation_id: preparation.preparation_id, preparation_context: preparation.preparation_context } : {}),
        approval: { confirmed: true, approved_by: approvedBy.trim() },
      } : current;
      const previous = submissionRef.current;
      const attempt = previous && previous.sourceId === sourceId && previous.navigationGeneration === navigationGeneration.current && sameJson(previous.payload, payload) && previous.preparation?.preparation_id === preparation?.preparation_id
        ? previous : { sourceId, navigationGeneration: navigationGeneration.current, payload: structuredClone(payload), preparation, submissionId: crypto.randomUUID(), legacy: strategy === "from_node" || DEMO_MODE };
      submissionRef.current = attempt;
      replayMutation.mutate(attempt);
    } catch (error) { setLocalError(error instanceof Error ? error.message : "Replay was refused."); }
  };
  if (runsQuery.isPending || catalogQuery.isPending) return <LoadingState label="Loading replay history" />;
  if (runsQuery.isError) return <ErrorState error={runsQuery.error} retry={() => runsQuery.refetch()} />;
  if (catalogQuery.isError) return <ErrorState error={catalogQuery.error} retry={() => catalogQuery.refetch()} />;
  const runs = runsQuery.data.runs.filter((run) => `${run.run_id} ${run.objective ?? ""} ${run.scenario_id ?? ""}`.toLowerCase().includes(search.toLowerCase())); const sourceSteps = source?.steps ?? []; const selectedSwapBehavior = sourceSteps.find((step) => step.step_id === swapStep)?.behavior_id; const sourceBehavior = catalogQuery.data.behaviors.find((item) => item.id === selectedSwapBehavior); const compatible = catalogQuery.data.behaviors.filter((candidate) => sourceBehavior && candidate.id !== sourceBehavior.id && JSON.stringify(candidate.inputs.map((item) => [item.type, item.required, item.multiple])) === JSON.stringify(sourceBehavior.inputs.map((item) => [item.type, item.required, item.multiple])) && JSON.stringify(candidate.outputs.map((item) => [item.type, item.multiple])) === JSON.stringify(sourceBehavior.outputs.map((item) => [item.type, item.multiple])));
  const execute = source?.mode === "execute"; const reviewReady = executeReviewReady(replayPreflight) && (strategy === "from_node" || Boolean(preparation)) && variantReady;
  return <div className="page compare-page"><PageHeader eyebrow="Replay & compare" title="Measure what changed" description="Compare what happened, inspect the evidence, and prepare the next run." actions={<Button variant="secondary" onClick={() => runsQuery.refetch()}><RotateCcw/>Refresh history</Button>} />
    {runsQuery.data.unavailable_run_count ? <Callout tone="warning" title="Unavailable run records excluded">{runsQuery.data.unavailable_run_count} in-flight, interrupted, or integrity-failed run record{runsQuery.data.unavailable_run_count === 1 ? " is" : "s are"} unavailable for replay and comparison. Refresh after finalization or recovery completes.</Callout> : null}
    {compareMutation.isError && compareMutation.variables?.generation === comparisonGeneration.current ? <ErrorState title="Comparison unavailable" error={compareMutation.error} /> : comparison ? <div className="comparison-workspace" ref={resultsRef} tabIndex={-1} role="region" aria-label="Comparison results"><ComparisonResult comparison={comparison} /><DetectorEvaluationComparison runIds={comparison.summaries.map((run) => run.run_id)} /></div> : null}
    <details className="compare-setup" open={!comparison}><summary>{comparison ? "Choose different runs or prepare a replay" : "Choose runs and prepare a replay"}</summary>
    <div className="compare-top-grid"><Panel className="history-panel"><PanelHeader eyebrow="Run history" title="Choose runs to compare" actions={<Badge>{selected.length} selected</Badge>} /><div className="history-search"><Search/><input aria-label="Search run history" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search run or objective"/></div><div className="run-select-list">{runs.map((run) => <label key={run.run_id}><input type="checkbox" checked={selected.includes(run.run_id)} onChange={(event) => changeSelection(run.run_id, event.target.checked)}/><span><strong>{run.scenario?.title ?? (source?.run_id === run.run_id ? source.scenario?.title : undefined) ?? run.scenario_id ?? run.objective ?? "Experiment"}</strong><code title={run.run_id}>{shortId(run.run_id)}</code><small>{formatDate(run.created_at)} · {run.steps.length} steps</small></span><span><Badge tone={run.mode === "execute" ? "warning" : "info"}>{sentence(run.mode)}</Badge><Badge tone={run.status === "completed" ? "success" : "neutral"} dot>{sentence(run.status)}</Badge></span></label>)}</div>{!runs.length ? <EmptyState title="No run records" description="Run an experiment to create your first result. Simulate is available without a lab." /> : null}<footer><Button variant="primary" onClick={() => compareMutation.mutate({ runIds: [...selected], generation: comparisonGeneration.current })} disabled={selected.length < 2 || compareMutation.isPending}><GitCompareArrows/>{compareMutation.isPending ? "Comparing" : "Compare selected"}</Button></footer></Panel>
      <Panel className="replay-panel"><PanelHeader title="Prepare another run" detail="Keep the original result and test the same experiment with a deliberate change." /><div className="replay-body"><fieldset className="replay-form" disabled={Boolean(uncertainSubmission) || replayMutation.isPending}><Field label="Source run"><select value={sourceId} onChange={(event) => setSearchParams(event.target.value ? { source: event.target.value } : {})} disabled={replayMutation.isPending}><option value="">Choose a completed run</option>{sourceId && !runsQuery.data.runs.some((run) => run.run_id === sourceId) ? <option value={sourceId}>{sourceId}</option> : null}{runsQuery.data.runs.map((run) => <option value={run.run_id} key={run.run_id}>{run.scenario?.title ?? (source?.run_id === run.run_id ? source.scenario?.title : undefined) ?? run.scenario_id ?? run.objective ?? "Experiment"} · {shortId(run.run_id)} · {sentence(run.mode)}</option>)}</select></Field>{sourceId && detailQuery.isError ? <ErrorState title="Source run unavailable" error={detailQuery.error} retry={() => detailQuery.refetch()} /> : null}{sourceId && detailQuery.isPending ? <LoadingState label="Loading the original experiment"/> : null}<Field label="What will change?"><select value={strategy} onChange={(event) => { setStrategy(event.target.value as ReplayStrategy); parameterDraftValidRef.current = true; setParameterDraftValid(true); resetReview(); }} disabled={!sourceId || replayMutation.isPending}>
          <option value="exact">Nothing — repeat the original run</option><option value="swap">Try another method</option><option value="parameters">Change step parameters</option><option value="setup">Change environment or AI setup</option><option value="from_node">Resume from a step</option>
        </select></Field>
        {strategy === "from_node" ? <Field label="Restart node"><select value={fromStep} onChange={(event) => { setFromStep(event.target.value); resetReview(); }}><option value="">Choose a step</option>{sourceSteps.map((step) => <option key={step.step_id} value={step.step_id}>{catalogQuery.data.behaviors.find((item) => item.id === step.behavior_id)?.title ?? step.step_id}</option>)}</select></Field> : null}
        {strategy === "swap" ? <div className="config-grid"><Field label="Substitute node"><select value={swapStep} onChange={(event) => { setSwapStep(event.target.value); setSwapBehavior(""); resetReview(); }}><option value="">Choose a step</option>{sourceSteps.map((step) => <option key={step.step_id} value={step.step_id}>{catalogQuery.data.behaviors.find((item) => item.id === step.behavior_id)?.title ?? step.step_id}</option>)}</select></Field><Field label="Compatible behavior"><select value={swapBehavior} onChange={(event) => { setSwapBehavior(event.target.value); resetReview(); }} disabled={!swapStep}><option value="">Choose a compatible method</option>{compatible.map((item) => <option value={item.id} key={item.id}>{item.title}</option>)}</select></Field></div> : null}
        {strategy === "setup" ? <fieldset><legend>Run setup</legend><div className="config-grid"><Field label="Profile override"><select value={profile} onChange={(event) => { setProfile(event.target.value); resetReview(); }}><option value="">Preserve original</option>{catalogQuery.data.runner_profiles.map((item) => <option key={item.id}>{item.id}</option>)}</select></Field><Field label="AI autonomy override"><select value={autonomy} onChange={(event) => { setAutonomy(event.target.value as typeof autonomy); resetReview(); }}><option value="preserve">Preserve original</option><option value="off">Off</option><option value="assist">Assist</option><option value="auto">Auto</option></select></Field><Field label="AI provider override"><select value={provider} onChange={(event) => { setProvider(event.target.value); resetReview(); }}><option value="">Preserve original</option>{(catalogQuery.data.ai.providers ?? []).map((item) => <option value={item.provider_id} key={item.provider_id}>{item.provider_id}</option>)}</select></Field></div></fieldset> : strategy !== "exact" ? <details className="replay-settings"><summary>Environment and AI settings</summary><div className="config-grid"><Field label="Profile override"><select value={profile} onChange={(event) => { setProfile(event.target.value); resetReview(); }}><option value="">Preserve original</option>{catalogQuery.data.runner_profiles.map((item) => <option key={item.id}>{item.id}</option>)}</select></Field><Field label="AI autonomy override"><select value={autonomy} onChange={(event) => { setAutonomy(event.target.value as typeof autonomy); resetReview(); }}><option value="preserve">Preserve original</option><option value="off">Off</option><option value="assist">Assist</option><option value="auto">Auto</option></select></Field><Field label="AI provider override"><select value={provider} onChange={(event) => { setProvider(event.target.value); resetReview(); }}><option value="">Preserve original</option>{(catalogQuery.data.ai.providers ?? []).map((item) => <option value={item.provider_id} key={item.provider_id}>{item.provider_id}</option>)}</select></Field></div></details> : null}
        {strategy === "parameters" ? <>
          {source?.scenario ? <ReplayParameterEditor scenario={source.scenario} behaviors={catalogQuery.data.behaviors} value={parameterOverrides} onChange={(next) => { setParameterJson(JSON.stringify(next, null, 2)); resetReview(); }} onValidityChange={changeParameterValidity} disabled={replayMutation.isPending}/> : <Callout title="Original graph unavailable">The original scenario is required to edit its parameters.</Callout>}
          <details className="replay-settings"><summary>Advanced parameter JSON</summary><Field label="Parameter overrides JSON" hint='Object keyed by step, then parameter. All values are validated before a replay.'><textarea rows={8} value={parameterJson} onChange={(event) => { setParameterJson(event.target.value); resetReview(); }} disabled={replayMutation.isPending} spellCheck={false}/></Field></details>
          {parameterError ? <Callout tone="danger" title="Parameter changes need attention">{parameterError}</Callout> : null}
        </> : null}{strategy !== "exact" ? <details className="replay-settings"><summary>Record a defense change</summary><Field label="Declared defense change" hint="Describe a change already applied in your lab. This note does not change a defense."><textarea rows={3} maxLength={500} value={defenseChange} onChange={(event) => { setDefenseChange(event.target.value); resetReview(); }} placeholder="For example: revised the receiver policy to require redacted records"/></Field></details> : null}
        {execute ? <><Callout tone="warning" title="Execute replay is a new effect authorization">{strategy === "from_node" ? "Resuming from a step currently uses a prospective base-plan check. The server resolves the replay lineage and restored inputs again before it accepts a fresh approval." : "Review the complete replay, including the original run, your changes, allowed effects, and cleanup. Preparing a replay does not approve it or start any effects."}</Callout><Field label="Exact target scope"><input value={targetScope} onChange={(event) => { setTargetScope(event.target.value); resetReview(); }} placeholder="sandbox.workspace"/></Field><Button variant="secondary" onClick={requestPreflight} disabled={!replayScenario || !variantReady || preflightMutation.isPending || !scopeRefs.length}><ShieldCheck/>{preflightMutation.isPending ? "Preparing review" : strategy === "from_node" ? "Run prospective base-plan check" : "Review Execute replay"}</Button>{replayPreflight ? <ReplayPreflight report={replayPreflight} preparation={preparation}/> : null}{strategy === "from_node" ? <><label className="check-row"><input type="checkbox" checked={replayConfirmed} onChange={(event) => setReplayConfirmed(event.target.checked)} disabled={!reviewReady}/><span><strong>I approve this reviewed Execute replay request once</strong><small>{preparation ? "Approval applies only to this prepared replay. Changed inputs or stale readiness require a new review." : "Unchecked by default; the server derives the exact replay binding and refuses any mismatch."}</small></span></label><Field label="Fresh replay operator identity"><input value={approvedBy} onChange={(event) => setApprovedBy(event.target.value)} disabled={!reviewReady} autoComplete="off" maxLength={128}/></Field></> : <p className="field-note">Continue to Runs to approve this exact review and follow the saved job. No effects start before approval.</p>}</> : null}
        {!variantReady && sourceId ? <Callout tone="warning" title="Replay variant incomplete">{strategy === "from_node" ? "Choose a restart step." : strategy === "swap" ? "Choose a step and its replacement method." : strategy === "setup" ? "Change an environment or AI setting, or record the defense change made in your lab." : "Change at least one step parameter."}</Callout> : null}{localError ? <Callout tone="danger" title="Replay refused">{localError}</Callout> : replayMutation.isSuccess && replayMutation.data.kind === "legacy" ? <Callout tone="success" title="Replay created"><code>{replayMutation.data.run.run_id}</code> is lineage-linked to <code>{replayMutation.variables?.sourceId}</code>.{linkedSource === replayMutation.variables?.sourceId && linkedReplay === replayMutation.data.run.run_id ? " The source and replay are selected for comparison." : " Your current source selection was preserved."}</Callout> : null}<Button variant="primary" className="button-full" onClick={requestReplay} disabled={!sourceId || !detailQuery.isSuccess || !variantReady || replayMutation.isPending || Boolean(execute && (!reviewReady || (strategy === "from_node" && (!replayConfirmed || !approvedBy.trim()))))}>{replayMutation.isPending ? "Submitting replay" : execute ? strategy === "from_node" ? "Create approved Execute replay" : "Continue to approval" : "Create Simulate replay"}</Button></fieldset>{uncertainSubmission ? <Callout tone="warning" title="Check this submission before starting another replay"><p>The response for original run <code>{uncertainSubmission.sourceId}</code> could not be confirmed. Retrying uses the same saved job identity and reviewed request, including after a reload.</p><details><summary>Saved replay request</summary><pre>{JSON.stringify(uncertainSubmission.payload, null, 2)}</pre></details><Button disabled={replayMutation.isPending} onClick={() => replayMutation.mutate(uncertainSubmission)}>Retry same submission</Button><Link className="button button-secondary button-medium" to={`/runs?job=job-${uncertainSubmission.submissionId.replaceAll("-", "")}`}>View submission status</Link></Callout> : null}</div></Panel>
    </div>
    </details>
    {!comparison && <Panel><EmptyState icon={<GitCompareArrows/>} title="Select at least two runs" description="The first selected run becomes the baseline. Compare what ran, the observations, and cleanup here." /></Panel>}
  </div>;
}

function ReplayPreflight({ report, preparation }: { report: PreflightReport; preparation?: ReplayPreparation }) {
  if (preparation) return <section aria-label="Prepared Execute replay">
    {report.plan ? <CanonicalPlanReview plan={report.plan} cleanup={report.cleanup} scope={report.scope} binding={report.approval_binding} envelope={report.approval_envelope}/> : null}
    <DataList items={[{ label: "Independent observers", value: report.collectors?.length ? report.collectors.join(", ") : "None reported" }]} />
    {report.findings?.length ? <Callout tone={executeReviewReady(report) ? "warning" : "danger"} title={executeReviewReady(report) ? "Review findings" : "Replay is blocked"}><ul>{report.findings.map((item, index) => <li key={index}>{typeof item === "string" ? item : item.message ?? item.code ?? "Finding"}</li>)}</ul></Callout> : null}
    <details><summary>Original run and replay identity</summary><p>Original run: <code>{preparation.binding.source.run_id}</code></p><pre>{JSON.stringify({ preparation_id: preparation.preparation_id, binding: preparation.binding, lineage: preparation.lineage, preflight: report }, null, 2)}</pre></details>
  </section>;
  const binding = report.approval_binding; const envelope = report.approval_envelope; const steps = Array.isArray(report.plan?.steps) ? report.plan.steps.filter((item): item is Record<string, unknown> => Boolean(item) && typeof item === "object") : [];
  return <section className={`preflight-result ${executeReviewReady(report) ? "approval-required" : "blocked"}`} aria-label="Prospective Execute replay check"><header><strong>{executeReviewReady(report) ? "Prospective base plan ready for review" : "Prospective check blocked"}</strong><Badge tone={executeReviewReady(report) ? "warning" : "danger"}>{sentence(report.status)}</Badge></header><Callout title="Not the replay binding">These digests cover this prospective base-plan compilation. Replay lineage, restart position, and source identity are bound only inside the replay request and may change or refuse the final authorization.</Callout><DataList items={[{ label: "Prospective state digest", value: binding ? <code>{binding.state_digest}</code> : "Not reported" }, { label: "Prospective plan digest", value: binding ? <code>{binding.plan_digest}</code> : "Not reported" }, { label: "Prospective scope digest", value: binding ? <code>{binding.target_scope_digest}</code> : "Not reported" }, { label: "Prospective envelope digest", value: envelope ? <code>{envelope.envelope_digest}</code> : "Not reported" }, { label: "Profile / tier", value: binding ? `${binding.profile_id} / ${sentence(binding.maximum_tier)}` : "Not reported" }, { label: "Cleanup", value: JSON.stringify(report.cleanup ?? {}) }]} />{steps.map((step) => <article className="replay-plan-step" key={String(step.step_id)}><strong>{String(step.step_id)}</strong><code>{String(step.behavior_id)}</code><Badge tone={step.action_id ? "warning" : "info"}>{String(step.action_id ?? step.simulation_id ?? "Unresolved")}</Badge><pre>{JSON.stringify(step.parameters ?? {}, null, 2)}</pre></article>)}{envelope ? <p className="field-note">{envelope.steps.reduce((count, step) => count + step.options.length, 0)} primary/alternate contract options appear in this prospective compilation.</p> : null}{report.findings?.length ? <ul>{report.findings.map((item, index) => <li key={index}>{typeof item === "string" ? item : item.message ?? item.code ?? "Finding"}</li>)}</ul> : null}</section>;
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

export function ComparisonResult({ comparison }: { comparison: ComparisonResponse }) {
  const baseline = comparison.summaries.find((item) => item.run_id === comparison.baseline_run_id) ?? comparison.summaries[0];
  const changed = comparison.deltas.filter(hasMaterialDelta).length;
  const [reportUrl, setReportUrl] = useState<string>();
  useEffect(() => {
    const url = URL.createObjectURL(new Blob([comparisonReport(comparison)], { type: "text/markdown;charset=utf-8" }));
    setReportUrl(url);
    return () => URL.revokeObjectURL(url);
  }, [comparison]);
  return <div className="comparison-results">
    <Panel className="comparison-outcomes">
      <PanelHeader title="Run outcomes" detail="Objective, observation, and cleanup are separate results. A stopped step alone does not establish target prevention." actions={reportUrl ? <a className="button button-secondary button-medium" href={reportUrl} download="bluefire-comparison.md">Download report</a> : null} />
      <div className="comparison-context"><span>{comparison.run_ids.length} runs</span><span className="comparison-changes">Material deltas <strong>{changed}</strong></span><span>{changed ? "Review the changes below" : "No material change reported"}</span></div>
      <div className="table-scroll" role="region" aria-label="Compared run outcomes" tabIndex={0}>
        <table><thead><tr><th scope="col">Run</th><th scope="col">Mode</th><th scope="col">Objective</th><th scope="col">Independent evidence</th><th scope="col">First stopped step</th><th scope="col">Cleanup</th></tr></thead>
          <tbody>{comparison.summaries.map((summary, index) => <tr key={summary.run_id}>
            <th scope="row"><Link to={runReviewPath(summary.run_id)} aria-label={summary.run_id === comparison.baseline_run_id ? "Review baseline run summary" : `Review variant ${index} run summary`}>{summary.run_id === comparison.baseline_run_id ? "Baseline" : `Variant ${index}`}</Link><small><code title={summary.run_id}>{shortId(summary.run_id)}</code></small></th>
            <td>{sentence(summary.mode ?? "not_reported")}</td>
            <td>{summary.objective_reached === true ? (summary.mode === "simulate" ? "Achieved (synthetic)" : "Achieved") : summary.objective_reached === false ? "Not achieved" : "Not established"}</td>
            <td>{Array.isArray(summary.evidence_details?.observed_artifacts) ? <>{summary.evidence_details.observed_artifacts.length} observed items<small>{Array.isArray(summary.evidence_details.evidence_gaps) ? `${summary.evidence_details.evidence_gaps.length} recorded evidence gaps` : "Evidence gaps not reported"}</small></> : "Not reported"}</td>
            <td>{summary.first_blocked_step ?? "None recorded"}</td>
            <td>{summary.cleanup_success === false ? "Needs attention" : summary.cleanup_success === true ? (summary.mode === "simulate" ? "No real effects" : "Complete") : "Not reported"}</td>
          </tr>)}</tbody>
        </table>
      </div>
      <details className="comparison-identity"><summary>Comparison record</summary><code>{comparison.comparison_id}</code><p>Baseline: {baseline?.run_id ?? comparison.baseline_run_id}</p></details>
    </Panel>
    <details className="comparison-detail"><summary>Step-by-step results and run details</summary>
    <Panel><PanelHeader eyebrow="Path overlay" title="Side-by-side execution lanes" detail="Human-readable outcomes come first; each run links back to its canonical review."/><div className="compare-lanes">{comparison.summaries.map((summary, laneIndex) => <article key={summary.run_id}>
      <header><Badge tone={laneIndex === 0 ? "info" : "neutral"}>{laneIndex === 0 ? "Baseline" : `Variant ${laneIndex}`}</Badge><Link to={runReviewPath(summary.run_id)} aria-label={`Review ${laneIndex === 0 ? "baseline" : `variant ${laneIndex}`} execution lane`}><code title={summary.run_id}>{shortId(summary.run_id)}</code></Link></header>
      <ol>{summary.path.map((step, index) => <li key={`${step}-${index}`} data-status={summary.outcomes[step] === "success" ? "succeeded" : summary.outcomes[step]}><span>{String(index + 1).padStart(2, "0")}</span><strong>{step}</strong><small>{sentence(summary.outcomes[step] ?? "unknown")}</small></li>)}</ol>
      <DataList items={[
        { label: "Mode / profile", value: `${sentence(summary.mode ?? "not_reported")} / ${summary.profile_id ?? "Not reported"}` },
        { label: "Target scope", value: formatTargetScope(summary.target_scope) },
        { label: "Replay Variant", value: formatReplayLineage(summary.replay_lineage) },
        { label: "Objective", value: summary.objective_reached === true ? "Reached" : summary.objective_reached === false ? "Not achieved" : "Not reported" },
        { label: "First block", value: summary.first_blocked_step ?? "None recorded" },
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
      ]} />
    </article>)}</div></Panel>
    </details>
    <details className="comparison-detail"><summary>Detailed changes in evidence, policy, and runtime</summary>
    <div className="delta-grid">{comparison.deltas.map((delta) => {
      const assessment = delta.assessment ?? (hasMaterialDelta(delta) ? "material_change" : "no_material_change");
      const noPathDivergence = delta.first_path_divergence === null || delta.first_path_divergence === undefined || delta.first_path_divergence < 0;
      return <Panel key={delta.to_run_id}><PanelHeader eyebrow="Delta assessment" title={`${shortId(delta.from_run_id)} → ${shortId(delta.to_run_id)}`} detail={`${sentence(assessment)} · ${formatList(delta.signals, "No assessment signals")}`} actions={<Badge tone={assessmentTone(assessment)}>{sentence(assessment)}</Badge>} />
        <div className="delta-summary"><div><span>{noPathDivergence ? <CheckCircle2/> : <ShieldAlert/>}</span><strong>Path divergence</strong><small>{noPathDivergence ? "No divergence" : `Node index ${delta.first_path_divergence! + 1}`}</small></div><div><span>{delta.objective_changed ? <ShieldAlert/> : <CheckCircle2/>}</span><strong>Objective</strong><small>{formatChanged(delta.objective_changed)}</small></div><div><span>{delta.first_blocked_changed ? <ShieldAlert/> : <CheckCircle2/>}</span><strong>First stopped step</strong><small>{formatChanged(delta.first_blocked_changed)}</small></div><div><span>{delta.cleanup_changed ? <ShieldAlert/> : <CheckCircle2/>}</span><strong>Cleanup</strong><small>{formatChanged(delta.cleanup_changed)}</small></div></div>
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
  </div>;
}

type ComparisonDeltaItem = ComparisonResponse["deltas"][number];

function assessmentTone(value: string): "neutral" | "success" | "warning" | "danger" {
  return value === "improved" ? "success" : value === "regressed" ? "danger" : value === "no_material_change" ? "neutral" : "warning";
}

function formatChanged(value?: boolean) { return value === undefined ? "Not reported" : value ? "Changed" : "Stable"; }
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
  const defense = value.defense_change_declared ? ` · defense note ${shortDigest(value.defense_change_digest)}` : "";
  return `${variants}${source}${defense}`;
}
function formatReplayDelta(value?: ComparisonDeltaItem["replay_lineage_delta"]) {
  if (!value || !value.changed) return "Stable";
  const variants = formatList(value.to_variant_types, "No Variant labels");
  const defense = value.defense_change_declared ? ` · defense note ${shortDigest(value.defense_change_digest)}` : "";
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
function runReviewPath(runId: string) { return `/runs/${encodeURIComponent(runId)}`; }
function shortId(value: string) { return value.length > 22 ? `${value.slice(0, 10)}…${value.slice(-8)}` : value; }
