import { createPortal } from "react-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowRight, Check, MessageSquareText, X } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { api, DEMO_MODE } from "../lib/api";
import { savedRunSource } from "../lib/run-assistance";
import { isGraphRequest, isGraphSelection, isSavedGraphRequest, isSavedRunSelection, isRunDetectionRequest, isRunDetectionSelection, isReceiverRequest } from "../lib/assistance";
import { checkedReceiverAssistanceContext, isReceiverSelection } from "../lib/receiver-assistance";
import { RunReference } from "./RunReference";
import { ReceiverAssistantProgress } from "./ReceiverAssistantProgress";
import { detectionCreationPath } from "../lib/detection-creation";
import { sameJson } from "../lib/replay-review";
import { readAssistanceHistory, rememberAssistanceRequest, readViewedAssistanceRequest, viewAssistanceRequest, assistanceActive, assistanceJobId, assistancePath, clearAssistanceReceipt, clearAssistanceRecovery, matchesAssistanceReceipt, readAssistanceReceipt, readAssistanceRecovery, storeAssistanceReceipt, storeAssistanceRecovery, type AssistanceEnvelope, type AssistanceRequest, type AssistanceStatus, type GraphSelection } from "../lib/assistance";
import { useAssistancePanel, useAssistanceSelection } from "../state/AssistanceContext";
import { useProduct } from "../state/ProductContext";
import type { CatalogResponse, DetectionCaseRole } from "../types";
import { Button, ErrorState, Field, sentence } from "./Primitives";
import "./ExperimentAssistant.css";

const labels: Record<AssistanceStatus, string> = {
  planning: "Planning the work", off: "AI is off", working: "Work in progress", awaiting_review: "Your review is needed",
  awaiting_execute_approval: "Execute approval is needed", ready_to_continue: "Next step needs attention", completed: "Work completed",
  blocked: "Work needs attention", cancelling: "Stopping · waiting for cleanup", cancelled: "Work stopped",
};
const triggerLabels: Record<AssistanceStatus, string> = {
  planning: "Planning", off: "Off", working: "Working", awaiting_review: "Review needed",
  awaiting_execute_approval: "Approval needed", ready_to_continue: "Recovery needed", completed: "Completed",
  blocked: "Needs attention", cancelling: "Stopping", cancelled: "Stopped",
};
const draftKey = "bluefire.assistance.draft.v1";
const graphOperationKey = "bluefire.assistance.graph-operation.v1";
function readDraft() {
  try { const value = sessionStorage.getItem(draftKey); return value && value.length <= 1000 ? value : ""; } catch { return ""; }
}

export function ExperimentAssistant({ providers }: { providers: NonNullable<CatalogResponse["ai"]["providers"]> }) {
  const [localOpen, setLocalOpen] = useState(false);
  const panel = useAssistancePanel();
  const open = panel?.open ?? localOpen;
  const setOpen = panel?.setOpen ?? setLocalOpen;
  const [ownedReceipt, setOwnedReceipt] = useState(readAssistanceReceipt);
  const [receipt, setReceiptState] = useState(readViewedAssistanceRequest);
  const [history, setHistory] = useState(readAssistanceHistory);
  const setReceipt = (value?: AssistanceRequest) => { setReceiptState(value); viewAssistanceRequest(value); };
  const remember = (value: AssistanceRequest) => {
    if (!rememberAssistanceRequest(value)) return false;
    setHistory(readAssistanceHistory()); return true;
  };
  const [message, setMessage] = useState(readDraft);
  const [caseRole, setCaseRole] = useState<DetectionCaseRole>("attack");
  const [localError, setLocalError] = useState<Error>();
  const [stopRequested, setStopRequested] = useState<string>();
  const [recovery, setRecovery] = useState(readAssistanceRecovery);
  const submissionLock = useRef(false);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const close = () => { setOpen(false); triggerRef.current?.focus(); };
  const requestedJobId = panel?.requestedJobId, requestedReceiverJobId = panel?.requestedReceiverJobId, finishOpenJob = panel?.finishOpenJob;
  useEffect(() => {
    if (!requestedJobId || !finishOpenJob) return;
    let current = true;
    void api.assistanceTurn(requestedJobId).then((value) => {
      if (!current) return;
      if (requestedReceiverJobId && (!value.turn.receiver_test?.owns_lifecycle || value.turn.receiver_test.owner_job_id !== requestedReceiverJobId)) throw new Error("This Assistant turn does not own the selected receiver test. The current request and test remain intact.");
      const original = value.job.request?.submitted_request as AssistanceRequest | undefined;
      if (!original || value.job.job_id !== requestedJobId || !matchesAssistanceReceipt(value, original) || !rememberAssistanceRequest(original)) throw new Error("This operation could not be restored safely. Its saved results remain available; check browser session storage and retry.");
      setHistory(readAssistanceHistory()); setReceiptState(original); viewAssistanceRequest(original);
      if (!ownedReceipt && value.turn.can_start_new_turn !== true) {
        if (!storeAssistanceReceipt(original)) throw new Error("The active operation could not be retained. No new work was started.");
        setOwnedReceipt(original);
      }
      setLocalError(undefined); finishOpenJob();
    }).catch((error: unknown) => { if (current) { setLocalError(error instanceof Error ? error : new Error("Saved Assistant work is unavailable.")); finishOpenJob(); } });
    return () => { current = false; };
  }, [requestedJobId, requestedReceiverJobId, finishOpenJob, ownedReceipt]);
  const selection = useAssistanceSelection();
  const graphSelection = selection && "kind" in selection && selection.kind === "graph" ? selection : undefined;
  const [graphOperation, setGraphOperation] = useState(() => {
    try { return sessionStorage.getItem(graphOperationKey) === "new" ? "new" : "edit_step"; } catch { return "edit_step"; }
  });
  const chooseGraphOperation = (operation: string) => {
    if (operation !== "new" && operation !== "edit_step") return;
    setGraphOperation(operation);
    try { sessionStorage.setItem(graphOperationKey, operation); } catch { /* Request receipts remain separately required. */ }
  };
  const graphRequestSelection = useMemo<GraphSelection | undefined>(() => graphSelection ? {
    kind: "graph", base_scenario: graphSelection.baseScenario,
    ...(graphOperation === "edit_step" && graphSelection.editStep ? { edit_step: graphSelection.editStep } : {}),
  } : undefined, [graphSelection, graphOperation]);
  const editingStep = graphRequestSelection?.edit_step;
  const wantsStepEdit = graphOperation === "edit_step" && Boolean(graphSelection?.editStep || graphSelection?.editUnavailable);
  const contextAvailable = !(wantsStepEdit && graphSelection?.editUnavailable);
  const savedGraphSelection = selection && "kind" in selection && selection.kind === "saved_graph" ? selection : undefined;
  const creationSelection = selection && "kind" in selection && selection.kind === "run_detection" ? selection : undefined;
  const receiverSelection = selection && "kind" in selection && selection.kind === "receiver" ? selection : undefined;
  const detectionSelection = selection && !("kind" in selection) ? selection : undefined;
  const { assistantPreferences, setAssistantPreferences } = useProduct();
  const client = useQueryClient();
  const jobId = receipt ? assistanceJobId(receipt.submission_id) : "";
  const key = ["assistance-turn", jobId];
  const context = useQuery({ queryKey: ["assistance-context", receiverSelection?.selected, creationSelection ? "run_detection" : savedGraphSelection ? "saved_graph" : graphSelection ? "graph" : "detection", creationSelection?.selected, savedGraphSelection?.selected, graphRequestSelection, detectionSelection?.runId, detectionSelection?.candidateId, detectionSelection?.resourceDigest],
    queryFn: async () => receiverSelection ? checkedReceiverAssistanceContext(await api.assistanceReceiverContext(receiverSelection.selected), receiverSelection.selected) : creationSelection ? api.assistanceDetectionContext(creationSelection.selected) : savedGraphSelection ? api.assistanceRunContext(savedGraphSelection.selected) : graphRequestSelection ? graphRequestSelection.edit_step ? api.assistanceGraphEditContext(graphRequestSelection) : api.assistanceGraphContext(graphRequestSelection.base_scenario) : api.assistanceContext(detectionSelection!.runId, detectionSelection!.candidateId),
    enabled: open && !receipt && Boolean(selection) && contextAvailable && !DEMO_MODE, retry: false });
  const validate = (value: AssistanceEnvelope, original: AssistanceRequest) => {
    if (!matchesAssistanceReceipt(value, original)) throw new Error("The saved work does not match this request. Its receipt is retained; no new operation was started.");
    return value;
  };
  const cache = (value: AssistanceEnvelope) => {
    client.setQueryData(["assistance-turn", value.job.job_id], value);
    if (value.turn.results.length) {
      void client.invalidateQueries({ queryKey: ["detections"] });
      void client.invalidateQueries({ queryKey: ["runs"] });
      void client.invalidateQueries({ queryKey: ["scenario-versions"] });
    }
  };
  const submit = useMutation({ mutationFn: async (body: AssistanceRequest) => validate(await api.submitAssistance(body), body),
    // A retained UUID can precede publication. Retire earlier reads before retrying
    // or caching a confirmed publication, even when their transport cannot abort.
    onMutate: (body) => client.cancelQueries({ queryKey: ["assistance-turn", assistanceJobId(body.submission_id)], exact: true }),
    onSuccess: async (value) => {
      await client.cancelQueries({ queryKey: ["assistance-turn", value.job.job_id], exact: true });
      cache(value);
    }, onSettled: () => { submissionLock.current = false; } });
  const operation = useQuery({ queryKey: key, queryFn: async () => validate(await api.assistanceTurn(jobId), receipt!), enabled: Boolean(receipt) && !submit.isPending && !DEMO_MODE, retry: false,
    refetchInterval: (query) => query.state.data && (assistanceActive(query.state.data.turn.status) || (query.state.data.turn.status === "blocked" && query.state.data.turn.can_start_new_turn !== true)) && !query.state.error ? 1500 : false });
  const ownedJobId = ownedReceipt ? assistanceJobId(ownedReceipt.submission_id) : "";
  const ownedOperation = useQuery({ queryKey: ["assistance-turn", ownedJobId],
    queryFn: async () => validate(await api.assistanceTurn(ownedJobId), ownedReceipt!),
    enabled: Boolean(ownedReceipt) && ownedJobId !== jobId && !submit.isPending && !DEMO_MODE, retry: false,
    refetchInterval: (query) => query.state.data?.turn.can_start_new_turn !== true && !query.state.error ? 1500 : false });
  const ownerStatus = ownedJobId === jobId ? operation : ownedOperation;
  const ownerBusy = Boolean(ownedReceipt && (ownerStatus.isError || ownerStatus.data?.turn.can_start_new_turn !== true));
  useEffect(() => {
    if (open && jobId && !submit.isPending) void client.invalidateQueries({ queryKey: ["assistance-turn", jobId] });
  }, [open, jobId, client, submit.isPending]);
  const recover = useMutation({ mutationFn: async (body: { submission_id: string; context_digest: string }) => validate(await api.continueAssistance(jobId, body), receipt!),
    onSuccess: cache });
  const cancel = useMutation({ mutationFn: async () => { setStopRequested(jobId); await client.cancelQueries({ queryKey: key, exact: true }); return api.controlJob(jobId, "cancel"); }, onSuccess: () => { void operation.refetch(); } });
  const turn = operation.data?.turn;
  const continuation = turn?.continuation;
  const triggerStatus = ownedReceipt && ownedJobId !== jobId ? ownerStatus.isError ? "Status unavailable" : ownerStatus.data ? triggerLabels[ownerStatus.data.turn.status] : "Checking status" : receipt ? operation.isError ? "Status unavailable" : turn ? triggerLabels[turn.status] : "Checking status" : undefined;
  const guidance = turn?.status === "ready_to_continue" ? turn.recovery : undefined;
  const guidancePath = assistancePath(guidance?.action.native_path);
  useEffect(() => {
    if (recovery && recovery.job_id === jobId && continuation?.submission_id === recovery.submission_id && continuation.context_digest === recovery.context_digest
      && ["completed", "failed", "cancelled", "interrupted"].includes(continuation.state) && clearAssistanceRecovery(recovery)) setRecovery(undefined);
  }, [recovery, jobId, continuation]);
  const active = turn ? turn.can_start_new_turn !== true : Boolean(receipt);
  const submittedRunIntent = receipt && isReceiverRequest(receipt) && receipt.selection.kind === "receiver_scenario" ? receipt.selection.run_intent : receipt && isSavedGraphRequest(receipt) ? receipt.selection.run_intent : undefined;
  const models = providers.filter((item) => item.kind !== "deterministic");
  const supportedModes = context.data?.capabilities.filter(item => item.available).flatMap(item => item.supported_autonomy) ?? [];
  const autonomy = assistantPreferences.autonomy === "auto" && context.data && !supportedModes.includes("auto") && supportedModes.includes("assist") ? "assist" : assistantPreferences.autonomy;
  const selectedProvider = models.find((item) => item.provider_id === assistantPreferences.provider);
  const selected = context.data?.selected;
  const current = Boolean(selected && (isReceiverSelection(selected) ? receiverSelection && sameJson(selected, receiverSelection.selected) : isRunDetectionSelection(selected) ? creationSelection && sameJson(selected, creationSelection.selected) : isSavedRunSelection(selected) ? savedGraphSelection && sameJson(selected, savedGraphSelection.selected) : isGraphSelection(selected) ? graphRequestSelection && sameJson(selected, graphRequestSelection)
    : detectionSelection && selected.run_id === detectionSelection.runId && selected.candidate_id === detectionSelection.candidateId && selected.candidate_resource_digest === detectionSelection.resourceDigest));
  const modeSupported = context.data?.capabilities.some((item) => item.available && item.supported_autonomy?.some((mode) => mode === autonomy));
  const ready = contextAvailable && !ownerBusy && !requestedJobId && current && !selection?.manualEdits && autonomy !== "off" && Boolean(selectedProvider) && Boolean(message.trim()) && modeSupported;
  const action = turn?.next_action;
  const stopping = stopRequested === jobId || turn?.status === "cancelling" || turn?.status === "cancelled";
  const actionPath = action?.kind === "wait" || action?.kind === "continue" || stopping ? undefined : assistancePath(action?.native_path);
  const actionLabel = action?.label ?? (action?.kind === "approve_execute" ? "Review and approve this Execute run" : action?.kind === "open_results" ? "Inspect saved receiver results" : "Open receiver preparation and review");
  const childPath = assistancePath(turn?.active_child?.native_path);
  const navigate = () => { /* Native review remains usable beside this panel. */ };
  const updateMessage = (value: string) => {
    setMessage(value);
    try { sessionStorage.setItem(draftKey, value); } catch { /* The required submission receipt is checked separately. */ }
  };
  const start = async () => {
    if (!ready || !context.data || !selection || receipt || submissionLock.current) return;
    const common = { submission_id: crypto.randomUUID(), context_digest: context.data.context_digest,
      message: message.trim(), autonomy, provider_id: assistantPreferences.provider };
    const request: AssistanceRequest = receiverSelection ? { ...common, selection: receiverSelection.selected } : creationSelection ? { ...common, selection: creationSelection.selected } : savedGraphSelection ? { ...common, selection: savedGraphSelection.selected } : graphRequestSelection ? { ...common, selection: graphRequestSelection }
      : { ...common, run_id: detectionSelection!.runId, candidate_id: detectionSelection!.candidateId, candidate_resource_digest: detectionSelection!.resourceDigest, case_role: caseRole };
    submissionLock.current = true;
    if (ownedReceipt) {
      const latest = await ownerStatus.refetch();
      if (latest.error || latest.data?.turn.can_start_new_turn !== true || !remember(ownedReceipt) || !clearAssistanceReceipt(ownedReceipt)) { submissionLock.current = false; setLocalError(new Error("Check the previous operation before starting more work.")); return; }
      setOwnedReceipt(undefined);
    }
    if (!storeAssistanceReceipt(request)) { submissionLock.current = false; setLocalError(new Error("Enable browser session storage before starting. The request must be retained so a disconnect cannot duplicate the work.")); return; }
    submissionLock.current = true;
    remember(request); setLocalError(undefined); setOwnedReceipt(request); setReceipt(request); submit.mutate(request);
  };
  const newRequest = async () => {
    if (!receipt || active || operation.isFetching) return;
    const latest = await operation.refetch();
    if (latest.error || !latest.data) { setLocalError(new Error("Check the saved operation before starting another request.")); return; }
    if (latest.data.turn.can_start_new_turn !== true) { setLocalError(new Error("This operation has work to settle. Open its native view or stop it before replacing the request.")); return; }
    if (!remember(receipt)) { setLocalError(new Error("The conversation could not be retained. Check browser session storage.")); return; }
    if (ownedReceipt?.submission_id === receipt.submission_id && !clearAssistanceReceipt(receipt)) { setLocalError(new Error("The saved receipt could not be cleared. Check browser session storage before starting another request.")); return; }
    if (ownedReceipt?.submission_id === receipt.submission_id) setOwnedReceipt(undefined);
    if (recovery?.job_id === jobId && clearAssistanceRecovery(recovery)) setRecovery(undefined);
    setReceipt(undefined); setStopRequested(undefined); setLocalError(undefined); submit.reset(); recover.reset(); cancel.reset();
  };
  return <>
    <button ref={triggerRef} aria-expanded={open} aria-controls="experiment-assistant" onClick={() => setOpen(!open)} className="assistant-trigger" aria-label={triggerStatus ? `Assistant: ${triggerStatus}` : "Assistant"}><MessageSquareText aria-hidden="true" /><span>Assistant</span>{triggerStatus ? <span className="assistant-trigger-status">{triggerStatus}</span> : null}</button>
    {open ? createPortal(<aside id="experiment-assistant" className="experiment-assistant" aria-labelledby="assistant-title" onKeyDown={event => { if (event.key === "Escape") { event.stopPropagation(); close(); } }}>
      <header className="assistant-header"><div><h2 id="assistant-title">Experiment assistant</h2><p>Review changes beside your experiment and results.</p></div><button onClick={close} className="assistant-close" aria-label="Close assistant"><X /></button></header>
      <div className={`assistant-body${!receipt && graphSelection ? " assistant-graph-composer" : ""}`}>
        {ownedReceipt || history.length ? <nav className="assistant-work-switcher" aria-label="Assistant workspace">
          <button type="button" aria-pressed={!receipt} onClick={() => { setReceipt(undefined); setLocalError(undefined); }}>Current selection</button>
          {ownedReceipt ? <button type="button" aria-pressed={receipt?.submission_id === ownedReceipt.submission_id} onClick={() => setReceipt(ownedReceipt)}>{ownerBusy ? "Return to active work" : "Recent operation"}</button> : null}
          {history.length ? <Field label="Saved conversations"><select value={receipt?.submission_id ?? ""} onChange={event => { const selected = history.find(item => item.submission_id === event.target.value); if (selected) { setReceipt(selected); setLocalError(undefined); } }}><option value="">Choose saved work</option>{history.map(item => <option key={item.submission_id} value={item.submission_id}>{item.message.slice(0, 100)}</option>)}</select></Field> : null}
        </nav> : null}
        {receipt && selection ? <p className="assistant-viewed-context">Workspace: {selection.title}. The saved request below keeps its original context.</p> : null}
        {!receipt && ownerBusy ? <p role="status">Your active operation is still running or waiting for review. You can inspect this selection and draft a follow-up; return to active work before starting another operation.</p> : null}
        {requestedJobId ? <p role="status">Opening the Assistant operation for this run…</p> : null}
        <p><Link onClick={navigate} to="/settings#model-connection">{models.length || receipt ? "Review model connection and usage authorization" : "Configure a provider in Settings"}</Link>{!models.length && !receipt ? " to use model assistance." : ". Restore an expired or unavailable connection here; saved work remains available."}</p>
        {receipt ? <section className="assistant-operation" aria-label="Saved assistant work">
          <p className="assistant-request">{receipt.message}</p>
          <div className="assistant-binding"><span>{sentence(receipt.autonomy)} · {receipt.provider_id ?? "No provider"}</span>{isReceiverRequest(receipt) ? <span>{receipt.selection.kind === "receiver_scenario" ? `New receiver test · version ${receipt.selection.selection.version}` : "Existing receiver test · analysis only"}</span> : isRunDetectionRequest(receipt) ? <Link onClick={navigate} to={detectionCreationPath(receipt.selection.run_id)}>New {sentence(receipt.selection.target_language)} rule · source evidence<ArrowRight aria-hidden="true" /></Link> : isSavedGraphRequest(receipt) ? <span>Saved experiment · version {savedRunSource(receipt.selection).version} · {sentence(receipt.selection.run_intent.mode)}</span> : isGraphRequest(receipt) ? <span>New experiment · saved separately</span> : <Link onClick={navigate} to={`/detection-lab?${new URLSearchParams({ run: receipt.run_id, candidate: receipt.candidate_id, candidate_scope: "registry" })}`}>Source rule and evidence <ArrowRight aria-hidden="true" /></Link>}</div>
          {isRunDetectionRequest(receipt) ? <RunReference runId={receipt.selection.run_id} label="Source observations" onNavigate={navigate}/> : !isReceiverRequest(receipt) && !isSavedGraphRequest(receipt) && !isGraphRequest(receipt) ? <RunReference runId={receipt.run_id} label="Source observations" onNavigate={navigate}/> : null}
          {isReceiverRequest(receipt) ? <p className="assistant-model-label">Assistant {sentence(receipt.autonomy)} interprets the evidence. AI during receiver runs stays Off; every preparation and Execute approval remains explicit.</p> : null}
          {submittedRunIntent ? <details className="assistant-details"><summary>Submitted run settings</summary><dl><dt>Runner profile</dt><dd>{submittedRunIntent.runner_profile_id ?? "Not selected"}</dd><dt>Scope</dt><dd>{submittedRunIntent.target_scope.scope_refs.join(", ")}</dd><dt>AI during the run</dt><dd>{sentence(submittedRunIntent.autonomy)} · {submittedRunIntent.ai_provider_id ?? "No provider"}</dd></dl></details> : null}
          {!turn && !operation.isError ? <p role="status">Finding the saved operation…</p> : null}
          {turn ? <>
            <h3 aria-live="polite">{labels[turn.status]}</h3>
            <p>{turn.message}</p>
            {turn.plan.length ? <ol className="assistant-plan">{turn.plan.map((step, index) => {
              const result = turn.results.find((item) => item.step_id === step.step_id && (item.kind !== "receiver_phase" && item.kind !== "receiver_inspection" || turn.status === "completed"));
              const isCurrent = turn.active_child?.step_id === step.step_id;
              return <li key={step.step_id} aria-current={isCurrent ? "step" : undefined}><span className="assistant-step-number" aria-label={result ? "Completed" : undefined}>{result ? <Check aria-hidden="true" /> : index + 1}</span><div><strong>{step.title}</strong><p>{step.reason}</p>{isCurrent && !result ? <small>{labels[turn.status]}</small> : null}{step.detector_ref === "revised" ? <small>Uses the saved revision from this operation</small> : null}</div></li>;
            })}</ol> : null}
            {actionPath ? <Link className="button button-primary button-medium" onClick={navigate} to={actionPath}>{actionLabel}<ArrowRight aria-hidden="true" /></Link> : null}
            {!actionPath && childPath ? <Link className="button button-secondary button-medium" onClick={navigate} to={childPath}>{stopping ? "Check saved work and cleanup" : "Open current work"}<ArrowRight aria-hidden="true" /></Link> : null}
            {guidance && guidancePath ? <section className="assistant-recovery" aria-label="Next step requirements">
              {turn.results.some((result) => result.kind === "detection_revision") ? <p><strong>Your rule revision and evaluation are saved.</strong></p> : null}
              {guidance.profile_id ? <p>Recorded runner: <strong>{guidance.profile_id}</strong></p> : null}
              <Link className="button button-secondary button-medium" onClick={navigate} to={guidancePath}>{guidance.action.label}<ArrowRight aria-hidden="true" /></Link>
              <p>{guidance.code === "receiver_review_required" ? "Recover only this saved evidence analysis. No receiver preparation, run or model planning request is repeated." : guidance.code === "runner_readiness_required" ? "Return to Assistant and resume this saved turn after checking setup. The original source and authority will be checked again; Execute still requires a separate approval." : "Review the selected objects before resuming. If the saved rule or evidence changed, stop this operation and start a new request; existing saved results remain available."}</p>
            </section> : null}
            {action?.kind === "continue" && !stopping ? <Button variant="primary" disabled={recover.isPending || cancel.isPending || operation.isError} onClick={() => {
              const saved = recovery ?? { job_id: jobId, submission_id: crypto.randomUUID(), context_digest: turn.context_digest };
              if (saved.job_id !== jobId || saved.context_digest !== turn.context_digest || !storeAssistanceRecovery(saved)) { setLocalError(new Error("The recovery request could not be retained. Check the saved operation before retrying.")); return; }
              setRecovery(saved); recover.mutate({ submission_id: saved.submission_id, context_digest: saved.context_digest });
            }}>{recover.isPending ? "Recovering saved work…" : isReceiverRequest(receipt) ? "Recover evidence analysis" : guidance ? "Resume saved turn" : action.label ?? "Continue saved work"}</Button> : null}
            {turn.receiver_test ? <ReceiverAssistantProgress progress={turn.receiver_test} onNavigate={navigate} showNativeLink={!actionPath && !childPath} /> : null}
            {turn.results.length && !turn.receiver_test ? <section className="assistant-results" aria-label="Saved results"><h4>Saved results</h4>{turn.results.map((result) => {
              const path = assistancePath(result.native_path);
              return <div key={`${result.step_id}:${result.kind}`}><strong>{result.kind === "run_inspected" ? "Run and evidence review" : result.kind === "graph_saved" ? "Experiment saved" : result.kind === "detection_created" ? "Rule saved and evaluated" : result.kind === "detection_revision" ? "Rule revision and evaluation" : "Method comparison"}</strong>{result.kind === "run_inspected" ? <p>{sentence(result.mode)} · {result.observed_records} independently observed records · {result.inspection_status === "insufficient" ? "Not enough evidence" : "Evidence reviewed"} · Cleanup: {sentence(result.cleanup_state)}{result.runtime_modified ? " · Includes reviewed runtime changes" : ""}</p> : result.kind === "graph_saved" ? <p>Version {result.version} · {result.operator_modified ? "Includes your edits · " : ""}Not run</p> : result.kind === "detection_created" ? <p>{result.backend_executed && result.match_count !== null ? `${result.match_count} matched records` : "Review evidence and backend limits"} · Development evidence{result.operator_modified ? " · Includes your edits" : ""}</p> : result.kind === "receiver_phase" ? <p>{sentence(result.phase)} · {sentence(result.decision)}</p> : result.kind === "receiver_inspection" ? <p>Retained evidence interpretation</p> : <p>{result.evaluation_ids.length} evaluation{result.evaluation_ids.length === 1 ? "" : "s"} · {result.run_ids.length} run{result.run_ids.length === 1 ? "" : "s"}</p>}{result.kind === "run_inspected" ? <RunReference runId={result.run_id} label="Reviewed run" onNavigate={navigate}/> : result.kind === "detection_created" ? <RunReference runId={result.run_id} label="Evaluated observations" onNavigate={navigate}/> : result.kind === "detection_revision" || result.kind === "method_comparison" ? [...new Set(result.run_ids)].map(runId => <RunReference key={runId} runId={runId} label={result.kind === "method_comparison" ? "Compared run" : "Evaluated observations"} onNavigate={navigate}/>) : null}{path && result.kind !== "run_inspected" ? <Link onClick={navigate} to={path}>{result.kind === "graph_saved" ? "Open saved experiment" : result.kind === "method_comparison" ? "Open method comparison" : "Review saved rule"}<ArrowRight aria-hidden="true" /></Link> : null}{result.kind === "graph_saved" ? <Link onClick={navigate} to={`/runs?graph_job=${encodeURIComponent(result.proposal_job_id)}`}>Run with Assistant<ArrowRight aria-hidden="true" /></Link> : result.kind === "run_inspected" ? <Link onClick={navigate} to={detectionCreationPath(result.run_id)}>Create a detection from this run<ArrowRight aria-hidden="true" /></Link> : null}</div>;
            })}</section> : null}
            {turn.limitations.length ? <details className="assistant-details"><summary>Scope and limitations</summary><ul>{turn.limitations.map((item, index) => <li key={index}>{item}</li>)}</ul></details> : null}
            {active ? <div className="assistant-stop"><p>{isReceiverRequest(receipt) && receipt.selection.kind === "receiver_test" ? "Stopping ends this analysis only. The independently created receiver test and its native work remain under their own controls." : "Closing this panel keeps the operation available. Stopping prevents further work and waits for any active cleanup."}</p><Button disabled={cancel.isPending || turn.status === "cancelling"} onClick={() => cancel.mutate()}>{cancel.isPending || turn.status === "cancelling" ? "Stop requested…" : "Stop this operation"}</Button></div> : <Button disabled={operation.isFetching} onClick={() => { void newRequest(); }}>Start another request</Button>}
          </> : null}
          {operation.isError && !submit.isPending ? <><ErrorState title="Saved work could not be checked" error={operation.error} retry={() => { void operation.refetch(); }} /><p>The original request and its {sentence(receipt.autonomy)} mode are retained. Retry that exact request to find or start the operation once.</p><Button disabled={submit.isPending || stopping} onClick={() => submit.mutate(receipt)}>Retry original request</Button></> : null}
        </section> : <>
          {DEMO_MODE ? <p className="assistant-empty">This preview cannot run assistant operations. Open the installed local service to plan an experiment or work from observed evidence.</p> : !selection ? <div className="assistant-empty"><h3>Choose where to start</h3><p>Describe a new experiment in Builder, or choose a source run in Detection Lab to create, improve, and compare detections.</p><Link className="button button-secondary button-medium" onClick={navigate} to="/builder">Open Builder<ArrowRight aria-hidden="true" /></Link><Link className="button button-ghost button-medium" onClick={navigate} to="/detection-lab">Open Detection Lab<ArrowRight aria-hidden="true" /></Link></div> : <>
            <section className="assistant-context" aria-label="Current selection"><small>{receiverSelection ? receiverSelection.selected.kind === "receiver_scenario" ? "Coordinate a receiver control test" : "Inspect an existing receiver test" : creationSelection ? "Create a detection from observed evidence" : savedGraphSelection ? "Run the saved experiment" : graphSelection ? wantsStepEdit ? "Edit the selected step" : "Build from an objective" : "Selected rule"}</small><strong>{graphSelection && !wantsStepEdit ? "New experiment" : selection.title}</strong>{receiverSelection ? <p>{receiverSelection.selected.kind === "receiver_scenario" ? `Version ${receiverSelection.selected.selection.version} · ${receiverSelection.selected.run_intent.runner_profile_id}. The exact selected experiment, scope and run settings are frozen for this request. Prepare and Execute require native review.` : "Analyse the verified evidence currently available in this test. This request cannot stop or take ownership of the receiver test."}</p> : creationSelection ? <><p>{sentence(creationSelection.selected.target_language)} · {sentence(creationSelection.selected.case_role)} development case. Review and edit the proposed source in Detection Lab before saving and evaluating it.</p><RunReference runId={creationSelection.selected.run_id} label="Source observations" onNavigate={navigate}/></> : savedGraphSelection ? <p>Version {savedRunSource(savedGraphSelection.selected).version} · {sentence(savedGraphSelection.selected.run_intent.mode)} · {savedGraphSelection.selected.run_intent.runner_profile_id || "Select a runner profile"}. The selected settings stay bound to this request. Review the plan before Assist submits it; Execute still needs fresh approval.</p> : graphSelection ? <>{graphSelection.editStep || graphSelection.editUnavailable ? <Field label="Assistant operation"><select value={graphOperation} onChange={event => chooseGraphOperation(event.target.value)}><option value="edit_step">Edit selected step</option><option value="new">New experiment</option></select></Field> : null}{wantsStepEdit && graphSelection.editUnavailable ? <p role="status">{graphSelection.editUnavailable}</p> : editingStep ? <><p className="assistant-action-summary">Change this step’s parameters. Review before saving a separate experiment; nothing runs.</p><details className="assistant-source-details"><summary>Experiment purpose and model data</summary><p><strong>{editingStep.scenario.title}</strong> · {editingStep.dirty ? "Unsaved working graph" : "Current working graph"}</p><p>Purpose: {editingStep.scenario.purpose}</p><p>The model receives your objective, this step’s parameters and their allowed schema. Other steps, inputs and routes stay in this product and cannot change.</p></details></> : <p>Create a separate experiment from registered steps. Your current graph stays in place. Review and edit the proposal in Builder before saving.</p>}</> : <RunReference runId={detectionSelection!.runId} label="Source observations" onNavigate={navigate}/>}</section>
            {context.isPending ? <p role="status">Checking evidence and available actions…</p> : null}
            {context.isError ? <ErrorState title="Context is unavailable" error={context.error} retry={() => { void context.refetch(); }} /> : null}
            {selected && !current ? <p role="alert">This selection changed. Reopen the saved object before starting.</p> : null}
            {selection.manualEdits ? <p role="alert">Save or restore your manual rule edits before starting assistant work.</p> : null}
          </>}
        </>}
        {!receipt ? <section className="assistant-composer" aria-label="Assistant controls">
          <div className="assistant-options"><Field label={savedGraphSelection || receiverSelection ? "Assistant mode" : "AI mode"}><select value={autonomy} disabled={Boolean(turn && active)} onChange={(event) => setAssistantPreferences({ ...assistantPreferences, autonomy: event.target.value as AssistanceRequest["autonomy"] })}><option value="off">Off</option><option value="assist">Assist · reviewed changes</option>{(!context.data || context.data.capabilities.some(item => item.available && item.supported_autonomy.includes("auto")) || autonomy === "auto") ? <option value="auto" disabled={Boolean(context.data && !context.data.capabilities.some(item => item.available && item.supported_autonomy.includes("auto")))}>Auto · permitted work</option> : null}</select></Field><Field label={savedGraphSelection || receiverSelection ? "Assistant provider" : "Provider"}><select value={selectedProvider?.provider_id ?? ""} disabled={Boolean(receipt)} onChange={(event) => { const model = models.find((item) => item.provider_id === event.target.value); if (model) setAssistantPreferences({ ...assistantPreferences, provider: model.provider_id, model: model.model }); }}><option value="" disabled>Select a configured provider</option>{models.map((item) => <option value={item.provider_id} key={item.provider_id}>{item.model} · {item.provider_id}</option>)}</select></Field></div>
          {autonomy === "off" ? <p>Off makes no new model requests. Manual tools remain available.</p> : <p>{autonomy === "assist" ? "Review proposed changes in their native views. " : "Only supported operations can continue automatically. "}Execute still requires its own valid approval.</p>}
          {assistantPreferences.autonomy === "auto" && autonomy === "assist" ? <p>This work uses Assist because its changes require review.</p> : null}
          {current && autonomy !== "off" && !modeSupported ? <p role="status">{autonomy === "auto" ? "The actions available for this selection require Assist review. Select Assist to continue; Auto is not supported for this workflow." : "No available action supports this mode for the current selection."}</p> : null}
          {!receipt ? <form onSubmit={(event) => { event.preventDefault(); void start(); }}><Field label="What would you like to do?"><textarea rows={graphSelection ? 3 : 4} maxLength={1000} value={message} onChange={(event) => updateMessage(event.target.value)} placeholder={receiverSelection ? receiverSelection.selected.kind === "receiver_scenario" ? "Guide the baseline, protected and restored phases, then explain the observed differences." : "Explain the verified receiver results and what evidence the next phase would add." : creationSelection ? "Draft a rule for this behavior from the selected observations, then evaluate the source I approve." : savedGraphSelection ? "Run this saved experiment with the selected settings, then explain its outcomes, observations, and cleanup." : graphSelection ? editingStep ? "Adjust this step’s parameters to meet the experiment objective." : "Build an experiment to discover the lab system, collect owned test records, and verify cleanup." : "Improve this rule from the selected run, then try another method and compare detections."} /></Field><div className="assistant-send-row">{!receiverSelection && !graphSelection && !savedGraphSelection && !creationSelection ? <Field label="Development activity"><select value={caseRole} onChange={(event) => setCaseRole(event.target.value as DetectionCaseRole)}><option value="attack">Attack</option><option value="benign">Benign</option></select></Field> : <p>{receiverSelection ? "Only bounded evidence analysis can continue automatically. Native effects stay explicitly reviewed." : creationSelection ? "Your selected behavior, language, and development case stay bound to this request. Saving waits for review." : savedGraphSelection ? "Use the settings selected in Runs. Evidence review follows the saved run." : "Proposal and validation only. Saving waits for your review."}</p>}<Button type="submit" variant="primary" disabled={!ready || submit.isPending || DEMO_MODE}>Start work<ArrowRight aria-hidden="true" /></Button></div></form> : null}
        </section> : null}
        {!receipt && context.data ? <details className="assistant-details"><summary>Available actions and evidence scope</summary><ul>{context.data.capabilities.map((item) => <li key={item.id}><strong>{item.title}</strong><p>{item.available ? item.id === "method.compare_same_detector" ? "Eligible · readiness checked before preparation" : "Available" : "Unavailable"}{item.reason ? ` · ${item.reason}` : ""}</p></li>)}</ul>{context.data.limitations.map((item, index) => <p key={index}>{item}</p>)}</details> : null}
        {localError || submit.error || recover.error || cancel.error ? <ErrorState title="Assistant needs attention" error={localError ?? submit.error ?? recover.error ?? cancel.error} /> : null}
      </div>
    </aside>, document.getElementById("assistant-dock") ?? document.body) : null}
  </>;
}
