import { createPortal } from "react-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowRight, ArrowUp, Check, ChevronRight, FileCheck2, History, Layers3, MessageSquareText, Settings2, Sparkles, Square, X } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { api, DEMO_MODE } from "../lib/api";
import { savedRunSetupPath, savedRunSource } from "../lib/run-assistance";
import { isGraphRequest, isGraphSelection, isSavedGraphRequest, isSavedRunSelection, isRunDetectionRequest, isRunDetectionSelection, isReceiverRequest, isAuditRequest, isFileAccessRequest, isFileAccessSelection, isComparisonSelection } from "../lib/assistance";
import { checkedReceiverAssistanceContext, isReceiverSelection } from "../lib/receiver-assistance";
import { auditAssistanceContext, auditReviewSourceHref, isAuditSelection } from "../lib/audit-assistance";
import { fileAccessAssistanceContext, type FileAccessAssistanceSummary } from "../lib/file-access-assistance";
import { comparisonAssistanceContext, type ComparisonAssistanceSummary } from "../lib/comparison-assistance";
import { RunReference } from "./RunReference";
import { ReceiverAssistantProgress } from "./ReceiverAssistantProgress";
import { detectionCreationPath, detectionCreationSelectionPath } from "../lib/detection-creation";
import { receiverScenarioSetupPath } from "../lib/receiver-navigation";
import { sameJson } from "../lib/replay-review";
import { providerChoiceLabel } from "../lib/provider-presentation";
import { readAssistanceHistory, rememberAssistanceRequest, readViewedAssistanceRequest, viewAssistanceRequest, assistanceActive, assistanceJobId, assistancePath, clearAssistanceReceipt, clearAssistanceRecovery, matchesAssistanceReceipt, readAssistanceReceipt, readAssistanceRecovery, storeAssistanceReceipt, storeAssistanceRecovery, isComparisonRequest, type AssistanceEnvelope, type AssistanceRequest, type AssistanceStatus, type GraphSelection } from "../lib/assistance";
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

function selectionReturnPath(selection: NonNullable<ReturnType<typeof useAssistanceSelection>>): string | undefined {
  if ("kind" in selection) {
    if (selection.kind === "graph") return "/builder";
    if (selection.kind === "saved_graph") return savedRunSetupPath(selection.selected);
    if (selection.kind === "run_detection") return detectionCreationSelectionPath(selection.selected);
    if (selection.kind === "receiver") return selection.selected.kind === "receiver_scenario"
      ? receiverScenarioSetupPath(selection.selected)
      : `/compare?receiver_job=${encodeURIComponent(selection.selected.receiver_job_id)}`;
    if (selection.kind === "audit") return auditReviewSourceHref(selection.selected);
    if (selection.kind === "file_access") return `/file-access?${new URLSearchParams({ control: selection.selected.control_owner_id })}`;
    if (selection.kind === "comparison") return `/compare?${new URLSearchParams({ snapshot: selection.selected.snapshot_id })}`;
  }
  return `/detection-lab?${new URLSearchParams({ run: selection.runId, candidate: selection.candidateId, candidate_scope: "registry" })}`;
}

export function ExperimentAssistant({ providers }: { providers: NonNullable<CatalogResponse["ai"]["providers"]> }) {
  const [localOpen, setLocalOpen] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const panel = useAssistancePanel();
  const open = panel?.open ?? localOpen;
  const setOpen = panel?.setOpen ?? setLocalOpen;
  const [ownedReceipt, setOwnedReceipt] = useState(readAssistanceReceipt);
  const [receipt, setReceiptState] = useState(readViewedAssistanceRequest);
  const [history, setHistory] = useState(readAssistanceHistory);
  const setReceipt = (value?: AssistanceRequest) => { setReceiptState(value); viewAssistanceRequest(value); setSettingsOpen(false); };
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
  const composerRef = useRef<HTMLTextAreaElement>(null);
  const settingsRef = useRef<HTMLDetailsElement>(null);
  const close = () => { setOpen(false); triggerRef.current?.focus(); };
  useEffect(() => {
    if (!open) return;
    const frame = window.requestAnimationFrame(() => {
      const workspace = document.getElementById("experiment-assistant");
      workspace?.focus({ preventScroll: true });
      if (window.matchMedia?.("(max-width: 900px)")?.matches) workspace?.scrollIntoView?.({ block: "start", behavior: "auto" });
    });
    return () => window.cancelAnimationFrame(frame);
  }, [open]);
  useEffect(() => {
    if (!open || !settingsOpen) return;
    const settings = settingsRef.current;
    const body = settings?.closest<HTMLElement>(".assistant-body");
    if (settings && body) {
      // Settings scroll within the work area without moving the dock or header.
      body.scrollTop += settings.getBoundingClientRect().top - body.getBoundingClientRect().top;
    }
  }, [open, settingsOpen]);
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
  const returnPath = selection ? selectionReturnPath(selection) : undefined;
  const selectionIsCurrent = panel?.selectionIsCurrent ?? true;
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
  const auditSelection = selection && "kind" in selection && selection.kind === "audit" ? selection : undefined;
  const fileAccessSelection = selection && "kind" in selection && selection.kind === "file_access" ? selection : undefined;
  const comparisonSelection = selection && "kind" in selection && selection.kind === "comparison" ? selection : undefined;
  const detectionSelection = selection && !("kind" in selection) ? selection : undefined;
  const { assistantPreferences, setAssistantPreferences } = useProduct();
  const client = useQueryClient();
  const jobId = receipt ? assistanceJobId(receipt.submission_id) : "";
  const key = ["assistance-turn", jobId];
  const context = useQuery({ queryKey: ["assistance-context", auditSelection?.selected, fileAccessSelection?.selected, comparisonSelection?.selected, receiverSelection?.selected, creationSelection ? "run_detection" : savedGraphSelection ? "saved_graph" : graphSelection ? "graph" : "detection", creationSelection?.selected, savedGraphSelection?.selected, graphRequestSelection, detectionSelection?.runId, detectionSelection?.candidateId, detectionSelection?.resourceDigest],
    queryFn: async () => auditSelection ? auditAssistanceContext(auditSelection.selected) : fileAccessSelection ? fileAccessAssistanceContext(fileAccessSelection.selected) : comparisonSelection ? comparisonAssistanceContext(comparisonSelection.selected) : receiverSelection ? checkedReceiverAssistanceContext(await api.assistanceReceiverContext(receiverSelection.selected), receiverSelection.selected) : creationSelection ? api.assistanceDetectionContext(creationSelection.selected) : savedGraphSelection ? api.assistanceRunContext(savedGraphSelection.selected) : graphRequestSelection ? graphRequestSelection.edit_step ? api.assistanceGraphEditContext(graphRequestSelection) : api.assistanceGraphContext(graphRequestSelection.base_scenario) : api.assistanceContext(detectionSelection!.runId, detectionSelection!.candidateId),
    enabled: open && !receipt && Boolean(selection) && selectionIsCurrent && contextAvailable && !DEMO_MODE, retry: false });
  const composerContext = selectionIsCurrent ? context.data : undefined;
  const referenceSummary = auditSelection && composerContext && "reference_summary" in composerContext
    ? composerContext.reference_summary : undefined;
  const auditProvenance = referenceSummary && typeof referenceSummary === "object"
    && "collection_provenance" in referenceSummary ? referenceSummary.collection_provenance : undefined;
  const auditDescription = auditSelection
    ? auditProvenance === "authenticated_source_retrieval"
      ? "Authenticated source retrieval. Integrity and delivery completeness are not established. Explanation only; no cloud operations or changes."
      : auditProvenance === "operator_import"
        ? "Operator-imported evidence. Collection is not independently verified. Explanation only; no cloud operations or changes."
        : "Saved audit evidence. Explanation only; no cloud operations or changes."
    : undefined;
  const fileAccessReference = fileAccessSelection && composerContext && "reference_summary" in composerContext
    ? composerContext.reference_summary as FileAccessAssistanceSummary : undefined;
  const comparisonReference = comparisonSelection && composerContext && "reference_summary" in composerContext
    ? composerContext.reference_summary as ComparisonAssistanceSummary : undefined;
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
  const analysisOnlySelection = Boolean((auditSelection || fileAccessSelection || comparisonSelection) && composerContext?.analysis_only);
  const supportedModes = analysisOnlySelection ? ["assist", "auto"] : composerContext?.capabilities.filter(item => item.available).flatMap(item => item.supported_autonomy) ?? [];
  const autonomy = assistantPreferences.autonomy === "auto" && composerContext && !supportedModes.includes("auto") && supportedModes.includes("assist") ? "assist" : assistantPreferences.autonomy;
  const selectedProvider = models.find((item) => item.provider_id === assistantPreferences.provider);
  const providerUnready = selectedProvider?.health?.credential_available === false || ["degraded", "unavailable"].includes(selectedProvider?.health?.state ?? "");
  const providerGuidance = providerUnready
    ? selectedProvider?.health?.message?.trim() || "Review the model connection and usage authorization in Settings."
    : selectedProvider && selectedProvider.health?.state !== "ready"
      ? "Model readiness is unknown. The service checks access and authorization before each request."
      : undefined;
  const selected = composerContext?.selected;
  const current = Boolean(selectionIsCurrent && selected && (isAuditSelection(selected) ? auditSelection && sameJson(selected, auditSelection.selected) : isFileAccessSelection(selected) ? fileAccessSelection && sameJson(selected, fileAccessSelection.selected) : isComparisonSelection(selected) ? comparisonSelection && sameJson(selected, comparisonSelection.selected) : isReceiverSelection(selected) ? receiverSelection && sameJson(selected, receiverSelection.selected) : isRunDetectionSelection(selected) ? creationSelection && sameJson(selected, creationSelection.selected) : isSavedRunSelection(selected) ? savedGraphSelection && sameJson(selected, savedGraphSelection.selected) : isGraphSelection(selected) ? graphRequestSelection && sameJson(selected, graphRequestSelection)
    : detectionSelection && selected.run_id === detectionSelection.runId && selected.candidate_id === detectionSelection.candidateId && selected.candidate_resource_digest === detectionSelection.resourceDigest));
  const modeSupported = analysisOnlySelection ? autonomy === "assist" || autonomy === "auto" : composerContext?.capabilities.some((item) => item.available && item.supported_autonomy?.some((mode) => mode === autonomy));
  const ready = selectionIsCurrent && contextAvailable && !ownerBusy && !requestedJobId && current && !selection?.manualEdits && autonomy !== "off" && Boolean(selectedProvider) && !providerUnready && Boolean(message.trim()) && modeSupported;
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
    if (!selectionIsCurrent || !ready || !composerContext || !selection || receipt || submissionLock.current) return;
    const common = { submission_id: crypto.randomUUID(), context_digest: composerContext.context_digest,
      message: message.trim(), autonomy, provider_id: assistantPreferences.provider };
    const request: AssistanceRequest = auditSelection ? { ...common, selection: auditSelection.selected } : fileAccessSelection ? { ...common, selection: fileAccessSelection.selected } : comparisonSelection ? { ...common, selection: comparisonSelection.selected } : receiverSelection ? { ...common, selection: receiverSelection.selected } : creationSelection ? { ...common, selection: creationSelection.selected } : savedGraphSelection ? { ...common, selection: savedGraphSelection.selected } : graphRequestSelection ? { ...common, selection: graphRequestSelection }
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
  const resume = () => {
    if (!turn) return;
    const saved = recovery ?? { job_id: jobId, submission_id: crypto.randomUUID(), context_digest: turn.context_digest };
    if (saved.job_id !== jobId || saved.context_digest !== turn.context_digest || !storeAssistanceRecovery(saved)) { setLocalError(new Error("The recovery request could not be retained. Check the saved operation before retrying.")); return; }
    setRecovery(saved); recover.mutate({ submission_id: saved.submission_id, context_digest: saved.context_digest });
  };
  const contextLabel = auditSelection ? "Explain saved audit evidence" : fileAccessSelection ? "Explain saved file-access evidence" : comparisonSelection ? "Explain saved comparison" : receiverSelection ? receiverSelection.selected.kind === "receiver_scenario" ? "Coordinate a receiver control test" : "Inspect an existing receiver test" : creationSelection ? "Create a detection from observed evidence" : savedGraphSelection ? "Run the saved experiment" : graphSelection ? wantsStepEdit ? "Edit the selected step" : "Build from an objective" : "Selected rule";
  const contextTitle = graphSelection && !wantsStepEdit ? "New experiment" : selection?.title;
  const dataScope = !receipt && !selection ? "Select an experiment or observed evidence to review the data for a request." : receipt
    ? isAuditRequest(receipt) ? "The selected saved audit review and its evidence references."
      : isFileAccessRequest(receipt) ? "The exact saved file-access control summary. It contains no raw records, file contents or file digests."
      : isComparisonRequest(receipt) ? "The minimized summary of one immutable saved comparison."
      : isReceiverRequest(receipt) ? "The captured receiver test and verified phase evidence."
        : isGraphRequest(receipt) ? receipt.selection.edit_step ? "The captured objective, selected step parameters, and allowed schema." : "Your objective and registered experiment steps."
          : isSavedGraphRequest(receipt) ? "The captured experiment, run settings, and resulting evidence."
            : "The captured detection source and selected observations."
    : auditSelection ? "The selected saved audit review and its evidence references."
      : fileAccessSelection ? "The exact saved file-access control summary. It contains no raw records, file contents or file digests."
      : comparisonSelection ? "The minimized summary of one immutable saved comparison."
      : receiverSelection ? "The selected receiver test and verified phase evidence."
        : editingStep ? "Your objective, this step’s parameters, and their allowed schema."
          : graphSelection ? "Your objective and registered experiment steps."
            : savedGraphSelection ? "The selected experiment, run settings, and resulting evidence."
              : "The selected detection source and observations.";
  const settingsProvider = receipt ? models.find(item => item.provider_id === receipt.provider_id) : selectedProvider;
  const displayedMode = receipt?.autonomy ?? autonomy;
  // Saved receipts capture the connection ID, not a model name from today's catalog.
  const modelSummary = receipt ? receipt.provider_id ?? "No provider" : selectedProvider?.model || "No model selected";
  const assistantState = triggerStatus ?? (autonomy === "off" ? "AI off" : !selectedProvider ? "Setup needed" : providerUnready ? "Connection needed" : "Ready to draft");
  const suggestions = comparisonSelection || fileAccessSelection ? [] : auditSelection ? [
    { title: "Explain the findings", detail: "Matched records and conflicting evidence", message: "Explain the matched records, conflicts, and missing evidence in this saved audit review." },
    { title: "Find the evidence gaps", detail: "What this review can and cannot establish", message: "Explain what the selected audit evidence establishes and which important questions remain unanswered." },
  ] : receiverSelection ? [
    { title: receiverSelection.selected.kind === "receiver_scenario" ? "Guide this control test" : "Explain these results", detail: "Baseline, protection, and restoration", message: receiverSelection.selected.kind === "receiver_scenario" ? "Guide the baseline, protected and restored phases, then explain the observed differences." : "Explain the verified receiver results and what evidence the next phase would add." },
    { title: "Review the evidence", detail: "Explain the observed differences", message: "Explain the receiver evidence, its limitations, and the next review needed for this test." },
  ] : creationSelection ? [
    { title: "Draft a detection", detail: "Use the selected observations", message: "Draft a rule for this behavior from the selected observations, then evaluate the source I approve." },
    { title: "Focus the rule", detail: "Capture the behavior in this evidence", message: "Draft a focused detection for the selected behavior and explain which observations support it." },
  ] : savedGraphSelection ? [
    { title: "Run and explain", detail: "Use the settings selected in Runs", message: "Run this saved experiment with the selected settings, then explain its outcomes, observations, and cleanup." },
    { title: "Check the cleanup evidence", detail: "Review the run’s final state", message: "Run this saved experiment with the selected settings and explain the observed results and cleanup evidence." },
  ] : graphSelection ? editingStep || wantsStepEdit ? [
    { title: "Refine this step", detail: "Propose a focused parameter change", message: "Adjust this step’s parameters to meet the experiment objective." },
  ] : [
    { title: "Draft an experiment", detail: "Start with an objective", message: "Build an experiment to discover the lab system, collect owned test records, and verify cleanup." },
    { title: "Compare collection methods", detail: "Create a proposal to review in Builder", message: "Draft an experiment to compare supported collection methods using owned test records and verify cleanup." },
  ] : [
    { title: "Improve this rule", detail: "Revise and evaluate from the evidence", message: "Improve this rule from the selected run, then evaluate the revision I approve." },
    { title: "Try another method", detail: "Compare against the same detector", message: "Improve this rule from the selected run, then try another method and compare detections." },
  ];
  const applySuggestion = (value: string) => { updateMessage(value); composerRef.current?.focus(); };
  return <>
    <button ref={triggerRef} aria-expanded={open} aria-controls="experiment-assistant" onClick={() => setOpen(!open)} className="assistant-trigger" aria-label={triggerStatus ? `Assistant: ${triggerStatus}` : "Assistant"}><MessageSquareText aria-hidden="true" /><span>Assistant</span>{triggerStatus ? <span className="assistant-trigger-status">{triggerStatus}</span> : null}</button>
    {open ? createPortal(<aside id="experiment-assistant" className="experiment-assistant" tabIndex={-1} aria-labelledby="assistant-title" onKeyDown={event => { if (event.key === "Escape") { event.stopPropagation(); close(); } }}>
      <header className="assistant-header">
        <Sparkles className="assistant-mark" aria-hidden="true" />
        <div><h2 id="assistant-title">BlueFire Assistant</h2><p className="assistant-state"><i aria-hidden="true" data-state={assistantState} />{assistantState}</p></div>
        <div className="assistant-header-actions"><button type="button" className="assistant-icon-button" aria-label="Assistant settings" aria-expanded={settingsOpen} aria-controls="assistant-settings" onClick={() => setSettingsOpen(!settingsOpen)}><Settings2 aria-hidden="true" /></button><button onClick={close} className="assistant-icon-button assistant-close" aria-label="Close assistant"><X aria-hidden="true" /></button></div>
      </header>
      <div className="assistant-body">
        {ownedReceipt || history.length ? <nav className="assistant-work-switcher" aria-label="Assistant workspace">
          <button type="button" aria-pressed={!receipt} onClick={() => { setReceipt(undefined); setLocalError(undefined); }}>Current selection</button>
          {ownedReceipt ? <button type="button" aria-pressed={receipt?.submission_id === ownedReceipt.submission_id} onClick={() => setReceipt(ownedReceipt)}>{ownerBusy ? "Return to active work" : "Recent operation"}</button> : null}
          {history.length ? <details className="assistant-history"><summary><History aria-hidden="true" /><span>Saved work</span></summary><Field label="Saved conversations"><select value={receipt?.submission_id ?? ""} onChange={event => { const selected = history.find(item => item.submission_id === event.target.value); if (selected) { setReceipt(selected); setLocalError(undefined); } }}><option value="">Choose saved work</option>{history.map(item => <option key={item.submission_id} value={item.submission_id}>{item.message.slice(0, 100)}</option>)}</select></Field></details> : null}
        </nav> : null}
        <details ref={settingsRef} id="assistant-settings" className="assistant-settings" open={settingsOpen} onToggle={event => setSettingsOpen(event.currentTarget.open)}>
          <summary className="assistant-settings-summary">Model, data, and permissions</summary>
          <div className="assistant-settings-content">
            <h3>Model and permissions</h3>
            {!receipt ? <div className="assistant-options">
              <Field label={savedGraphSelection || receiverSelection ? "Assistant mode" : "AI mode"}><select value={autonomy} onChange={event => setAssistantPreferences({ ...assistantPreferences, autonomy: event.target.value as AssistanceRequest["autonomy"] })}><option value="off">Off</option><option value="assist">{analysisOnlySelection ? "Assist · explanation only" : "Assist · reviewed changes"}</option>{(!composerContext || supportedModes.includes("auto") || autonomy === "auto") ? <option value="auto" disabled={Boolean(composerContext && !supportedModes.includes("auto"))}>{analysisOnlySelection ? "Auto · explanation only" : "Auto · permitted work"}</option> : null}</select></Field>
              <Field label={savedGraphSelection || receiverSelection ? "Assistant provider" : "Provider"}><select value={selectedProvider?.provider_id ?? ""} onChange={event => { const model = models.find(item => item.provider_id === event.target.value); if (model) setAssistantPreferences({ ...assistantPreferences, provider: model.provider_id, model: model.model }); }}><option value="" disabled>Select a configured provider</option>{models.map(item => <option value={item.provider_id} key={item.provider_id}>{providerChoiceLabel(item, models)}</option>)}</select></Field>
              {!auditSelection && !fileAccessSelection && !comparisonSelection && !receiverSelection && !graphSelection && !savedGraphSelection && !creationSelection ? <Field label="Development activity"><select value={caseRole} onChange={event => setCaseRole(event.target.value as DetectionCaseRole)}><option value="attack">Attack</option><option value="benign">Benign</option></select></Field> : null}
            </div> : <p>{sentence(receipt.autonomy)} · {modelSummary}. This request keeps its submitted settings.</p>}
            <dl className="assistant-settings-facts"><div><dt>Data shared</dt><dd>{dataScope}</dd></div><div><dt>Destination</dt><dd>{settingsProvider?.provider_id ?? receipt?.provider_id ?? "No connection selected"}. Review the configured endpoint in Settings.</dd></div><div><dt>Authorization</dt><dd>{displayedMode === "off" ? "Off makes no new model requests. Manual tools remain available." : "The service checks access and usage authorization before each model request."}</dd></div><div><dt>Delegation</dt><dd>{displayedMode === "off" ? "No model work is delegated." : (receipt && isAuditRequest(receipt)) || (!receipt && auditSelection) ? "Explanation only. No cloud operations or changes." : (receipt && isFileAccessRequest(receipt)) || (!receipt && fileAccessSelection) ? "Explanation only. No file-access operation, recovery or change is available." : (receipt && isComparisonRequest(receipt)) || (!receipt && comparisonSelection) ? "Explanation only. No experiment or control is rerun or changed." : displayedMode === "auto" ? "Supported work may continue automatically. Saving proposed changes and Execute still require their own review." : "Review proposed changes before they are saved. Execute requires its own valid approval."}</dd></div></dl>
            {assistantPreferences.autonomy === "auto" && autonomy === "assist" && !receipt ? <p>This work uses Assist because its changes require review.</p> : null}
            {!receipt && autonomy !== "off" && selectedProvider && providerGuidance ? <p role="status" aria-label="Model connection readiness">{providerGuidance}</p> : null}
            <Link onClick={navigate} to="/settings#model-connection">Review model connection and usage authorization<ArrowRight aria-hidden="true" /></Link>
            {!receipt && composerContext ? <details className="assistant-details"><summary>{analysisOnlySelection ? "Explanation scope and evidence limits" : "Available actions and evidence scope"}</summary>{composerContext.capabilities.length ? <ul>{composerContext.capabilities.map(item => <li key={item.id}><strong>{item.title}</strong><p>{item.available ? item.id === "method.compare_same_detector" ? "Eligible · readiness checked before preparation" : "Available" : "Unavailable"}{item.reason ? ` · ${item.reason}` : ""}</p></li>)}</ul> : null}{composerContext.limitations.map((item, index) => <p key={index}>{item}</p>)}</details> : null}
          </div>
        </details>
        {receipt && selection ? <p className="assistant-viewed-context">Workspace: {selection.title}. The saved request below keeps its original context.</p> : null}
        {!receipt && ownerBusy ? <p role="status">Your active operation is still running or waiting for review. You can inspect this selection and draft a follow-up; return to active work before starting another operation.</p> : null}
        {requestedJobId ? <p role="status">Opening the Assistant operation for this run…</p> : null}
        {receipt ? <section className="assistant-operation" aria-label="Saved assistant work">
          <section className="assistant-captured-context" aria-label="Captured request context"><Layers3 aria-hidden="true" /><div><small>Captured context</small><div className="assistant-binding">{isAuditRequest(receipt) ? <Link onClick={navigate} to={`/s3-access?exercise=${receipt.selection.workflow_job_id}`}>Saved cloud exercise<ArrowRight aria-hidden="true" /></Link> : isFileAccessRequest(receipt) ? <Link onClick={navigate} to={`/file-access?${new URLSearchParams({ control: receipt.selection.control_owner_id })}`}>Saved file-access control · revision {receipt.selection.control_revision}<ArrowRight aria-hidden="true" /></Link> : isComparisonRequest(receipt) ? <Link onClick={navigate} to={`/compare?${new URLSearchParams({ snapshot: receipt.selection.snapshot_id })}`}>Saved comparison<ArrowRight aria-hidden="true" /></Link> : isReceiverRequest(receipt) ? <span>{receipt.selection.kind === "receiver_scenario" ? `New receiver test · version ${receipt.selection.selection.version}` : "Existing receiver test · analysis only"}</span> : isRunDetectionRequest(receipt) ? <Link onClick={navigate} to={detectionCreationPath(receipt.selection.run_id)}>New {sentence(receipt.selection.target_language)} rule · source evidence<ArrowRight aria-hidden="true" /></Link> : isSavedGraphRequest(receipt) ? <span>Saved experiment · version {savedRunSource(receipt.selection).version} · {sentence(receipt.selection.run_intent.mode)}</span> : isGraphRequest(receipt) ? <span>{receipt.selection.edit_step ? `Selected step · ${receipt.selection.edit_step.scenario.title}` : "New experiment · saved separately"}</span> : <Link onClick={navigate} to={`/detection-lab?${new URLSearchParams({ run: receipt.run_id, candidate: receipt.candidate_id, candidate_scope: "registry" })}`}>Source rule and evidence <ArrowRight aria-hidden="true" /></Link>}</div></div></section>
          <article className="assistant-request-message"><small>You</small><p className="assistant-request">{receipt.message}</p></article>
          {isRunDetectionRequest(receipt) ? <RunReference runId={receipt.selection.run_id} label="Source observations" onNavigate={navigate}/> : !isAuditRequest(receipt) && !isFileAccessRequest(receipt) && !isComparisonRequest(receipt) && !isReceiverRequest(receipt) && !isSavedGraphRequest(receipt) && !isGraphRequest(receipt) ? <RunReference runId={receipt.run_id} label="Source observations" onNavigate={navigate}/> : null}
          {isReceiverRequest(receipt) ? <p className="assistant-model-label">Assistant {sentence(receipt.autonomy)} interprets the evidence. AI during receiver runs stays Off; every preparation and Execute approval remains explicit.</p> : null}
          {submittedRunIntent ? <details className="assistant-details"><summary>Submitted run settings</summary><dl><dt>Runner profile</dt><dd>{submittedRunIntent.runner_profile_id ?? "Not selected"}</dd><dt>Scope</dt><dd>{submittedRunIntent.target_scope.scope_refs.join(", ")}</dd><dt>AI during the run</dt><dd>{sentence(submittedRunIntent.autonomy)} · {submittedRunIntent.ai_provider_id ?? "No provider"}</dd></dl></details> : null}
          {!turn && !operation.isError ? <p role="status">Finding the saved operation…</p> : null}
          {turn ? <>
            <div className="assistant-response-heading"><Sparkles aria-hidden="true" /><h3 aria-live="polite">{labels[turn.status]}</h3></div>
            <p className="assistant-response-message">{turn.message}</p>
            {turn.plan.length ? <details className="assistant-work-plan" open={turn.status === "working" || turn.status === "planning"}><summary>Work plan <span>{turn.plan.length} steps</span></summary><ol className="assistant-plan">{turn.plan.map((step, index) => {
              const result = turn.results.find((item) => item.step_id === step.step_id && (item.kind !== "receiver_phase" && item.kind !== "receiver_inspection" || turn.status === "completed"));
              const isCurrent = turn.active_child?.step_id === step.step_id;
              return <li key={step.step_id} aria-current={isCurrent ? "step" : undefined}><span className="assistant-step-number" aria-label={result ? "Completed" : undefined}>{result ? <Check aria-hidden="true" /> : index + 1}</span><div><strong>{step.title}</strong><p>{step.reason}</p>{isCurrent && !result ? <small>{labels[turn.status]}</small> : null}{step.detector_ref === "revised" ? <small>Uses the saved revision from this operation</small> : null}</div></li>;
            })}</ol></details> : null}
            {guidance && guidancePath ? <section className="assistant-recovery" aria-label="Next step requirements">
              {turn.results.some((result) => result.kind === "detection_revision") ? <p><strong>Your rule revision and evaluation are saved.</strong></p> : null}
              {guidance.profile_id ? <p>Recorded runner: <strong>{guidance.profile_id}</strong></p> : null}
              <Link className="button button-secondary button-medium" onClick={navigate} to={guidancePath}>{guidance.action.label}<ArrowRight aria-hidden="true" /></Link>
              <p>{guidance.code === "receiver_review_required" ? "Recover only this saved evidence analysis. No receiver preparation, run or model planning request is repeated." : guidance.code === "runner_readiness_required" ? "Return to Assistant and resume this saved turn after checking setup. The original source and authority will be checked again; Execute still requires a separate approval." : "Review the selected objects before resuming. If the saved rule or evidence changed, stop this operation and start a new request; existing saved results remain available."}</p>
            </section> : null}
            {turn.receiver_test ? <ReceiverAssistantProgress progress={turn.receiver_test} onNavigate={navigate} showNativeLink={!actionPath && !childPath} /> : null}
            {turn.results.length && !turn.receiver_test ? <section className="assistant-results" aria-label="Saved results"><h4><FileCheck2 aria-hidden="true" />Saved results</h4>{turn.results.map((result) => {
              const path = assistancePath(result.native_path);
              return <div key={`${result.step_id}:${result.kind}`}><strong>{result.kind === "run_inspected" ? "Run and evidence review" : result.kind === "graph_saved" ? "Experiment saved" : result.kind === "detection_created" ? "Rule saved and evaluated" : result.kind === "detection_revision" ? "Rule revision and evaluation" : "Method comparison"}</strong>{result.kind === "run_inspected" ? <p>{sentence(result.mode)} · {result.observed_records} independently observed records · {result.inspection_status === "insufficient" ? "Not enough evidence" : "Evidence reviewed"} · Cleanup: {sentence(result.cleanup_state)}{result.runtime_modified ? " · Includes reviewed runtime changes" : ""}</p> : result.kind === "graph_saved" ? <p>Version {result.version} · {result.operator_modified ? "Includes your edits · " : ""}Not run</p> : result.kind === "detection_created" ? <p>{result.backend_executed && result.match_count !== null ? `${result.match_count} matched records` : "Review evidence and backend limits"} · Development evidence{result.operator_modified ? " · Includes your edits" : ""}</p> : result.kind === "receiver_phase" ? <p>{sentence(result.phase)} · {sentence(result.decision)}</p> : result.kind === "receiver_inspection" ? <p>Retained evidence interpretation</p> : <p>{result.evaluation_ids.length} evaluation{result.evaluation_ids.length === 1 ? "" : "s"} · {result.run_ids.length} run{result.run_ids.length === 1 ? "" : "s"}</p>}{result.kind === "run_inspected" ? <RunReference runId={result.run_id} label="Reviewed run" onNavigate={navigate}/> : result.kind === "detection_created" ? <RunReference runId={result.run_id} label="Evaluated observations" onNavigate={navigate}/> : result.kind === "detection_revision" || result.kind === "method_comparison" ? [...new Set(result.run_ids)].map(runId => <RunReference key={runId} runId={runId} label={result.kind === "method_comparison" ? "Compared run" : "Evaluated observations"} onNavigate={navigate}/>) : null}{path && result.kind !== "run_inspected" ? <Link onClick={navigate} to={path}>{result.kind === "graph_saved" ? "Open saved experiment" : result.kind === "method_comparison" ? "Open method comparison" : "Review saved rule"}<ArrowRight aria-hidden="true" /></Link> : null}{result.kind === "graph_saved" ? <Link onClick={navigate} to={`/runs?graph_job=${encodeURIComponent(result.proposal_job_id)}`}>Run with Assistant<ArrowRight aria-hidden="true" /></Link> : result.kind === "run_inspected" ? <Link onClick={navigate} to={detectionCreationPath(result.run_id)}>Create a detection from this run<ArrowRight aria-hidden="true" /></Link> : null}</div>;
            })}</section> : null}
            {turn.limitations.length ? <details className="assistant-details"><summary>Scope and limitations</summary><ul>{turn.limitations.map((item, index) => <li key={index}>{item}</li>)}</ul></details> : null}
          </> : null}
          {operation.isError && !submit.isPending ? <><ErrorState title="Saved work could not be checked" error={operation.error} retry={() => { void operation.refetch(); }} /><p>The original request and its {sentence(receipt.autonomy)} mode are retained. Retry that exact request to find or start the operation once.</p><Button disabled={submit.isPending || stopping} onClick={() => submit.mutate(receipt)}>Retry original request</Button></> : null}
        </section> : <>
          {DEMO_MODE ? <p className="assistant-empty">This preview cannot run assistant operations. Open the installed local service to plan an experiment or work from observed evidence.</p> : !selection ? <div className="assistant-empty"><div className="assistant-welcome-icon"><Sparkles aria-hidden="true" /></div><h3>What are you working on?</h3><p>Open an experiment or select observed evidence to start a request.</p><Link className="assistant-starter-link" onClick={navigate} to="/builder"><Layers3 aria-hidden="true" /><span>Open Builder<small>Create or improve an experiment</small></span><ChevronRight aria-hidden="true" /></Link><Link className="assistant-starter-link" onClick={navigate} to="/detection-lab"><FileCheck2 aria-hidden="true" /><span>Open Detection Lab<small>Work from observed evidence</small></span><ChevronRight aria-hidden="true" /></Link></div> : <>
            <section className="assistant-context" aria-label={selectionIsCurrent ? "Current selection" : "Previous selection"}>
              {!selectionIsCurrent ? <>
                <small>Previous selection</small><strong>{selection.title}</strong>
                <p>This selection is from another view. Reopen its source before starting new work. Your draft is preserved.</p>
                {returnPath ? <Link className="button button-secondary button-medium" onClick={navigate} to={returnPath}>Reopen source<ArrowRight aria-hidden="true" /></Link> : <p>This exact setup cannot be reopened. Your captured context and draft are preserved.</p>}
              </> : <>
                <small className="assistant-context-eyebrow"><Layers3 aria-hidden="true" />{contextLabel}</small><strong>{contextTitle}</strong>
                {graphSelection && (graphSelection.editStep || graphSelection.editUnavailable) ? <Field className="assistant-operation-choice" label="Assistant operation"><select value={graphOperation} onChange={event => chooseGraphOperation(event.target.value)}><option value="edit_step">Edit selected step</option><option value="new">New experiment</option></select></Field> : null}
                {auditSelection ? <p>{auditDescription}</p> : comparisonSelection && comparisonReference ? <ComparisonAssistanceEvidence summary={comparisonReference} /> : receiverSelection ? <p>{receiverSelection.selected.kind === "receiver_scenario" ? `Version ${receiverSelection.selected.selection.version} · ${receiverSelection.selected.run_intent.runner_profile_id}. Prepare and Execute require review.` : "Explain verified evidence. This request cannot stop or take ownership of the receiver test."}</p> : creationSelection ? <><p>{sentence(creationSelection.selected.target_language)} · {sentence(creationSelection.selected.case_role)} development case. Review in Detection Lab before saving.</p><RunReference runId={creationSelection.selected.run_id} label="Source observations" onNavigate={navigate}/></> : savedGraphSelection ? <p>Version {savedRunSource(savedGraphSelection.selected).version} · {sentence(savedGraphSelection.selected.run_intent.mode)} · {savedGraphSelection.selected.run_intent.runner_profile_id || "Select a runner profile"}. These run settings stay bound to your request.</p> : graphSelection ? <>{wantsStepEdit && graphSelection.editUnavailable ? <p role="status">{graphSelection.editUnavailable}</p> : editingStep ? <><p className="assistant-action-summary">Change this step’s parameters. Review before saving a separate experiment; nothing runs.</p><details className="assistant-source-details"><summary>Experiment purpose and model data</summary><p><strong>{editingStep.scenario.title}</strong> · {editingStep.dirty ? "Unsaved working graph" : "Current working graph"}</p><p>Purpose: {editingStep.scenario.purpose}</p><p>The model receives your objective, this step’s parameters and their allowed schema. Other steps, inputs and routes stay in this product and cannot change.</p></details></> : <p>Describe your objective. Review the proposed experiment in Builder before saving.</p>}</> : detectionSelection ? <RunReference runId={detectionSelection.runId} label="Source observations" onNavigate={navigate}/> : null}
                {fileAccessReference ? <FileAccessAssistanceEvidence summary={fileAccessReference} /> : null}
              </>}
            </section>
            {selectionIsCurrent && context.isPending ? <p role="status">Checking evidence and available actions…</p> : null}
            {selectionIsCurrent && context.isError ? <ErrorState title="Context is unavailable" error={context.error} retry={() => { void context.refetch(); }} /> : null}
            {selected && !current ? <p role="alert">This selection changed. Reopen the saved object before starting.</p> : null}
            {selection.manualEdits ? <p role="alert">Save or restore your manual rule edits before starting assistant work.</p> : null}
            {selectionIsCurrent && contextAvailable && !selection.manualEdits && suggestions.length ? <section className="assistant-starters" aria-label="Suggested requests"><h3>{editingStep ? "What should change?" : "Start with a request"}</h3><p>{editingStep ? "Describe the outcome you want from this step." : "Use a starting point, or write your own request below."}</p>{suggestions.map(item => <button type="button" key={item.title} className="assistant-starter" onClick={() => applySuggestion(item.message)}><span><strong>{item.title}</strong><small>{item.detail}</small></span><ChevronRight aria-hidden="true" /></button>)}</section> : null}
          </>}
        </>}
        {localError || submit.error || recover.error || cancel.error ? <ErrorState title="Assistant needs attention" error={localError ?? submit.error ?? recover.error ?? cancel.error} /> : null}
      </div>
      {!receipt ? <section className="assistant-composer" aria-label="Assistant controls">
        {!DEMO_MODE && (!selectedProvider || providerUnready || autonomy === "off") ? <div className="assistant-setup-note" data-ai-off={autonomy === "off"}>
          <span>{autonomy === "off" ? "AI is off. Your draft stays here." : providerUnready ? "Model connection needs attention." : "Choose a model to start work."}</span>
          {!models.length || providerUnready ? <Link onClick={navigate} to="/settings#model-connection">{providerUnready ? "Review connection" : "Set up a model"}</Link> : !selectedProvider ? <button type="button" onClick={() => setSettingsOpen(true)}>Choose model</button> : <button type="button" onClick={() => setAssistantPreferences({ ...assistantPreferences, autonomy: "assist" })}>Turn on Assist</button>}
        </div> : null}
        {current && autonomy !== "off" && !modeSupported ? <p className="assistant-composer-note" role="status">{autonomy === "auto" ? "This selection needs Assist review. Change the mode in Assistant settings." : "No available action supports this mode for the current selection."}</p> : null}
        <form onSubmit={event => { event.preventDefault(); void start(); }}>
          <Field className="assistant-message-field" label="What would you like to do?"><textarea ref={composerRef} rows={3} maxLength={1000} value={message} onChange={event => updateMessage(event.target.value)} placeholder={editingStep ? "Describe what should change…" : "Ask a question or describe the work…"} /></Field>
          <div className="assistant-send-row"><span>{analysisOnlySelection ? "Explanation only" : savedGraphSelection || receiverSelection ? "Execute requires approval" : "Review before saving"}</span><Button type="submit" variant="primary" className="assistant-send" aria-label="Start work" disabled={!ready || submit.isPending || DEMO_MODE}><ArrowUp aria-hidden="true" /></Button></div>
        </form>
        <button type="button" className="assistant-configuration" onClick={() => setSettingsOpen(!settingsOpen)} aria-expanded={settingsOpen} aria-controls="assistant-settings" aria-label="Review Assistant settings"><Settings2 aria-hidden="true" /><span>{sentence(autonomy)} <i aria-hidden="true">·</i> {modelSummary}</span><ChevronRight aria-hidden="true" /></button>
      </section> : <footer className="assistant-work-controls" aria-label="Saved work controls">
        {turn ? <>
          {actionPath ? <Link className="button button-primary button-medium assistant-next-action" onClick={navigate} to={actionPath}>{actionLabel}<ArrowRight aria-hidden="true" /></Link> : null}
          {!actionPath && childPath ? <Link className="button button-secondary button-medium assistant-next-action" onClick={navigate} to={childPath}>{stopping ? "Check saved work and cleanup" : "Open current work"}<ArrowRight aria-hidden="true" /></Link> : null}
          {action?.kind === "continue" && !stopping ? <Button variant="primary" className="assistant-next-action" disabled={recover.isPending || cancel.isPending || operation.isError} onClick={resume}>{recover.isPending ? "Recovering saved work…" : isReceiverRequest(receipt) ? "Recover evidence analysis" : guidance ? "Resume saved turn" : action.label ?? "Continue saved work"}<ArrowRight aria-hidden="true" /></Button> : null}
          {active ? <div className="assistant-stop"><p>{isComparisonRequest(receipt) ? "Stop ends this explanation only. The saved comparison remains unchanged." : isFileAccessRequest(receipt) ? "Stop ends this explanation only. The saved file-access control remains unchanged." : isReceiverRequest(receipt) && receipt.selection.kind === "receiver_test" ? "Stop ends this analysis only; the receiver test keeps its own controls." : "Work stays available when you close. Stop waits for active cleanup."}</p><Button size="small" variant="ghost" disabled={cancel.isPending || turn.status === "cancelling"} onClick={() => cancel.mutate()}><Square aria-hidden="true" />{cancel.isPending || turn.status === "cancelling" ? "Stop requested…" : "Stop this operation"}</Button></div> : <Button className="assistant-next-action" disabled={operation.isFetching} onClick={() => { void newRequest(); }}>Start another request<ArrowRight aria-hidden="true" /></Button>}
        </> : <p>Checking saved work…</p>}
        <button type="button" className="assistant-configuration" onClick={() => setSettingsOpen(!settingsOpen)} aria-expanded={settingsOpen} aria-controls="assistant-settings" aria-label="Review Assistant settings"><Settings2 aria-hidden="true" /><span>{sentence(displayedMode)} <i aria-hidden="true">·</i> {modelSummary}</span><ChevronRight aria-hidden="true" /></button>
      </footer>}
    </aside>, document.getElementById("assistant-dock") ?? document.body) : null}
  </>;
}

function FileAccessAssistanceEvidence({ summary }: { summary: FileAccessAssistanceSummary }) {
  const baseline = summary.baseline.recorded ? "Recorded: owner and non-owner reads allowed" : "Not recorded";
  const fresh = summary.fresh_result.recorded
    ? `Saved ${summary.fresh_result.operation} observation: non-owner ${sentence(summary.fresh_result.non_owner)}, owner allowed · ${summary.fresh_result.source === "verified_saved_task_observation" ? "saved task observation" : "saved paired read"}`
    : "No verified fresh task result recorded";
  const latest = summary.latest_operation
    ? `${sentence(summary.latest_operation.operation)} · ${sentence(summary.latest_operation.state)} · ${sentence(summary.latest_operation.outcome)}`
    : "No saved operation summary";
  return <details className="assistant-source-details">
    <summary>Saved file-access evidence</summary>
    <p>Platform: {sentence(summary.platform)} · control state: {sentence(summary.control_status)}</p>
    <p>Baseline reads: {baseline}</p>
    <p>Protection metadata: {sentence(summary.protection.value)} · effective access not proven by metadata</p>
    <p>Fresh task result: {fresh}</p>
    <p>Latest saved operation: {latest}</p>
    <p>Task access usage: {sentence(summary.task_access.usage_state)} · readiness: not assessed</p>
    <p>Only this saved control summary is sent to the Assistant. No raw file contents or file digests are included.</p>
  </details>;
}

function ComparisonAssistanceEvidence({ summary }: { summary: ComparisonAssistanceSummary }) {
  const integrity = summary.source_integrity.status === "verified"
    ? "All saved source bundles are currently verified."
    : `${summary.source_integrity.runs.filter(run => run.status !== "verified").length} source bundle(s) are missing, changed, or invalid. Historical comparison facts remain as saved; no runs were recomputed.`;
  const objective = (value: boolean | null) => value === null ? "not reported" : value ? "recorded as reached" : "recorded as not reached";
  const legitimateUse = summary.saved_comparison.legitimate_use;
  return <details className="assistant-source-details">
    <summary>Saved comparison evidence</summary>
    <p>{summary.saved_comparison.run_count} saved runs · run 1 is the recorded baseline. {integrity}</p>
    <ul>{summary.saved_comparison.runs.map(run => <li key={run.position}>Run {run.position}: {run.mode ? sentence(run.mode) : "mode not reported"}; objective {objective(run.objective_reached)}; {run.recorded_attempts === null ? "attempt count not reported" : `${run.recorded_attempts} recorded attempt${run.recorded_attempts === 1 ? "" : "s"}`}; {run.observations.evidence_records === null ? "evidence record counts not reported" : "evidence record populations retained separately"}.</li>)}</ul>
    {legitimateUse.state === "saved_s3_read_results" ? <><p>Saved S3 read results: {sentence(legitimateUse.comparison_state)} · change {sentence(legitimateUse.change_state)}. These rows do not establish effective access or defensive effectiveness.</p><ul>{legitimateUse.rows.map(row => <li key={`${row.reader}-${row.purpose}`}>{sentence(row.reader)} {sentence(row.purpose)}: baseline {sentence(row.baseline.state)} ({row.baseline.provenance ? sentence(row.baseline.provenance) : "provenance not reported"}); retest {sentence(row.retest.state)} ({row.retest.provenance ? sentence(row.retest.provenance) : "provenance not reported"}).</li>)}</ul></> : <p>Legitimate-use comparison: {legitimateUse.state === "not_recorded" ? "not recorded" : `unavailable · ${sentence(legitimateUse.reason)}`}.</p>}
    <p>Source integrity is separate from the historical saved comparison. Missing source bundles are not substituted.</p>
  </details>;
}
