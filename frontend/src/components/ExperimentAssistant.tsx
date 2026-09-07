import * as Dialog from "@radix-ui/react-dialog";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowRight, Check, MessageSquareText, X } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { api, DEMO_MODE } from "../lib/api";
import { assistanceActive, assistanceJobId, assistancePath, clearAssistanceReceipt, clearAssistanceRecovery, matchesAssistanceReceipt, readAssistanceReceipt, readAssistanceRecovery, storeAssistanceReceipt, storeAssistanceRecovery, type AssistanceEnvelope, type AssistanceRequest, type AssistanceStatus } from "../lib/assistance";
import { useAssistanceSelection } from "../state/AssistanceContext";
import { useProduct } from "../state/ProductContext";
import type { CatalogResponse, DetectionCaseRole } from "../types";
import { Button, ErrorState, Field, sentence } from "./Primitives";
import "./ExperimentAssistant.css";

const labels: Record<AssistanceStatus, string> = {
  planning: "Planning the work", off: "AI is off", working: "Work in progress", awaiting_review: "Your review is needed",
  awaiting_execute_approval: "Execute approval is needed", ready_to_continue: "Ready to recover", completed: "Work completed",
  blocked: "Work needs attention", cancelling: "Stopping · waiting for cleanup", cancelled: "Work stopped",
};
const draftKey = "bluefire.assistance.draft.v1";
function readDraft() {
  try { const value = sessionStorage.getItem(draftKey); return value && value.length <= 1000 ? value : ""; } catch { return ""; }
}

export function ExperimentAssistant({ providers }: { providers: NonNullable<CatalogResponse["ai"]["providers"]> }) {
  const [open, setOpen] = useState(false);
  const [receipt, setReceipt] = useState(readAssistanceReceipt);
  const [message, setMessage] = useState(readDraft);
  const [caseRole, setCaseRole] = useState<DetectionCaseRole>("attack");
  const [localError, setLocalError] = useState<Error>();
  const [recovery, setRecovery] = useState(readAssistanceRecovery);
  const submissionLock = useRef(false);
  const selection = useAssistanceSelection();
  const { runConfig, setRunConfig } = useProduct();
  const client = useQueryClient();
  const jobId = receipt ? assistanceJobId(receipt.submission_id) : "";
  const key = ["assistance-turn", jobId];
  const context = useQuery({ queryKey: ["assistance-context", selection?.runId, selection?.candidateId, selection?.resourceDigest],
    queryFn: () => api.assistanceContext(selection!.runId, selection!.candidateId),
    enabled: open && !receipt && Boolean(selection) && !DEMO_MODE, retry: false });
  const validate = (value: AssistanceEnvelope, original: AssistanceRequest) => {
    if (!matchesAssistanceReceipt(value, original)) throw new Error("The saved work does not match this request. Its receipt is retained; no new operation was started.");
    return value;
  };
  const operation = useQuery({ queryKey: key, queryFn: async () => validate(await api.assistanceTurn(jobId), receipt!), enabled: Boolean(receipt) && !DEMO_MODE, retry: false,
    refetchInterval: (query) => query.state.data && (assistanceActive(query.state.data.turn.status) || (query.state.data.turn.status === "blocked" && query.state.data.turn.can_start_new_turn !== true)) && !query.state.error ? 1500 : false });
  useEffect(() => {
    if (open && jobId) void client.invalidateQueries({ queryKey: ["assistance-turn", jobId] });
  }, [open, jobId, client]);
  const cache = (value: AssistanceEnvelope) => {
    client.setQueryData(["assistance-turn", value.job.job_id], value);
    if (value.turn.results.length) {
      void client.invalidateQueries({ queryKey: ["detections"] });
      void client.invalidateQueries({ queryKey: ["runs"] });
    }
  };
  const submit = useMutation({ mutationFn: async (body: AssistanceRequest) => validate(await api.submitAssistance(body), body),
    onSuccess: cache, onSettled: () => { submissionLock.current = false; } });
  const recover = useMutation({ mutationFn: async (body: { submission_id: string; context_digest: string }) => validate(await api.continueAssistance(jobId, body), receipt!),
    onSuccess: cache });
  const cancel = useMutation({ mutationFn: () => api.controlJob(jobId, "cancel"), onSuccess: () => { void operation.refetch(); } });
  const turn = operation.data?.turn;
  const continuation = turn?.continuation;
  useEffect(() => {
    if (recovery && recovery.job_id === jobId && continuation?.submission_id === recovery.submission_id && continuation.context_digest === recovery.context_digest
      && ["completed", "failed", "cancelled", "interrupted"].includes(continuation.state) && clearAssistanceRecovery(recovery)) setRecovery(undefined);
  }, [recovery, jobId, continuation]);
  const active = turn ? turn.can_start_new_turn !== true : Boolean(receipt);
  const models = providers.filter((item) => item.kind !== "deterministic");
  const selectedProvider = models.find((item) => item.provider_id === runConfig.provider);
  const selected = context.data?.selected;
  const current = Boolean(selection && selected && selected.run_id === selection.runId && selected.candidate_id === selection.candidateId && selected.candidate_resource_digest === selection.resourceDigest);
  const modeSupported = context.data?.capabilities.some((item) => item.available && item.supported_autonomy?.some((mode) => mode === runConfig.autonomy));
  const ready = current && !selection?.manualEdits && runConfig.autonomy !== "off" && Boolean(selectedProvider) && Boolean(message.trim()) && modeSupported;
  const action = turn?.next_action;
  const actionPath = assistancePath(action?.native_path);
  const childPath = assistancePath(turn?.active_child?.native_path);
  const navigate = () => setOpen(false);
  const updateMessage = (value: string) => {
    setMessage(value);
    try { sessionStorage.setItem(draftKey, value); } catch { /* The required submission receipt is checked separately. */ }
  };
  const start = () => {
    if (!ready || !context.data || !selection || receipt || submissionLock.current) return;
    const request: AssistanceRequest = { submission_id: crypto.randomUUID(), context_digest: context.data.context_digest,
      run_id: selection.runId, candidate_id: selection.candidateId, candidate_resource_digest: selection.resourceDigest,
      message: message.trim(), case_role: caseRole, autonomy: runConfig.autonomy, provider_id: runConfig.provider };
    if (!storeAssistanceReceipt(request)) { setLocalError(new Error("Enable browser session storage before starting. The request must be retained so a disconnect cannot duplicate the work.")); return; }
    submissionLock.current = true;
    setLocalError(undefined); setReceipt(request); submit.mutate(request);
  };
  const newRequest = async () => {
    if (!receipt || active || operation.isFetching) return;
    const latest = await operation.refetch();
    if (latest.error || !latest.data) { setLocalError(new Error("Check the saved operation before starting another request.")); return; }
    if (latest.data.turn.can_start_new_turn !== true) { setLocalError(new Error("This operation has work to settle. Open its native view or stop it before replacing the request.")); return; }
    if (!clearAssistanceReceipt(receipt)) { setLocalError(new Error("The saved receipt could not be cleared. Check browser session storage before starting another request.")); return; }
    if (recovery && clearAssistanceRecovery(recovery)) setRecovery(undefined);
    setReceipt(undefined); setLocalError(undefined); submit.reset(); recover.reset(); cancel.reset();
  };
  return <Dialog.Root open={open} onOpenChange={setOpen}>
    <Dialog.Trigger asChild><button className="assistant-trigger"><MessageSquareText aria-hidden="true" /><span>Assistant</span>{turn ? <span className="assistant-trigger-status">{turn.status === "awaiting_review" || turn.status === "awaiting_execute_approval" ? "Review needed" : active ? "Working" : "Saved work"}</span> : null}</button></Dialog.Trigger>
    <Dialog.Portal><Dialog.Overlay className="assistant-overlay" /><Dialog.Content className="experiment-assistant" aria-describedby="assistant-description">
      <header className="assistant-header"><div><Dialog.Title>Experiment assistant</Dialog.Title><Dialog.Description id="assistant-description">Work from your selected evidence. Inspect changes where you use them.</Dialog.Description></div><Dialog.Close asChild><button className="assistant-close" aria-label="Close assistant"><X /></button></Dialog.Close></header>
      <div className="assistant-body">
        {receipt ? <section className="assistant-operation" aria-label="Saved assistant work">
          <p className="assistant-request">{receipt.message}</p>
          <div className="assistant-binding"><span>{sentence(receipt.autonomy)} · {receipt.provider_id ?? "No provider"}</span><Link onClick={navigate} to={`/detection-lab?${new URLSearchParams({ run: receipt.run_id, candidate: receipt.candidate_id, candidate_scope: "registry" })}`}>Source rule and evidence <ArrowRight aria-hidden="true" /></Link></div>
          {!turn && !operation.isError ? <p role="status">Finding the saved operation…</p> : null}
          {turn ? <>
            <h3 aria-live="polite">{labels[turn.status]}</h3>
            <p>{turn.message}</p>
            {turn.plan.length ? <ol className="assistant-plan">{turn.plan.map((step, index) => {
              const result = turn.results.find((item) => item.step_id === step.step_id);
              const isCurrent = turn.active_child?.step_id === step.step_id;
              return <li key={step.step_id} aria-current={isCurrent ? "step" : undefined}><span className="assistant-step-number" aria-label={result ? "Completed" : undefined}>{result ? <Check aria-hidden="true" /> : index + 1}</span><div><strong>{step.title}</strong><p>{step.reason}</p>{isCurrent && !result ? <small>{labels[turn.status]}</small> : null}{step.detector_ref === "revised" ? <small>Uses the saved revision from this operation</small> : null}</div></li>;
            })}</ol> : null}
            {actionPath ? <Link className="button button-primary button-medium" onClick={navigate} to={actionPath}>{action!.label}<ArrowRight aria-hidden="true" /></Link> : null}
            {!actionPath && childPath ? <Link className="button button-secondary button-medium" onClick={navigate} to={childPath}>Open current work<ArrowRight aria-hidden="true" /></Link> : null}
            {action?.kind === "continue" ? <Button variant="primary" disabled={recover.isPending || cancel.isPending} onClick={() => {
              const saved = recovery ?? { job_id: jobId, submission_id: crypto.randomUUID(), context_digest: turn.context_digest };
              if (saved.job_id !== jobId || saved.context_digest !== turn.context_digest || !storeAssistanceRecovery(saved)) { setLocalError(new Error("The recovery request could not be retained. Check the saved operation before retrying.")); return; }
              setRecovery(saved); recover.mutate({ submission_id: saved.submission_id, context_digest: saved.context_digest });
            }}>{recover.isPending ? "Recovering saved work…" : action.label}</Button> : null}
            {turn.results.length ? <section className="assistant-results" aria-label="Saved results"><h4>Saved results</h4>{turn.results.map((result) => {
              const path = assistancePath(result.native_path);
              return <div key={`${result.step_id}:${result.kind}`}><strong>{result.kind === "detection_revision" ? "Rule revision and evaluation" : "Method comparison"}</strong><p>{result.evaluation_ids.length} evaluation{result.evaluation_ids.length === 1 ? "" : "s"} · {result.run_ids.length} run{result.run_ids.length === 1 ? "" : "s"}</p>{path ? <Link onClick={navigate} to={path}>Inspect saved result<ArrowRight aria-hidden="true" /></Link> : null}</div>;
            })}</section> : null}
            {turn.limitations.length ? <details className="assistant-details"><summary>Scope and limitations</summary><ul>{turn.limitations.map((item, index) => <li key={index}>{item}</li>)}</ul></details> : null}
            {active ? <div className="assistant-stop"><p>Closing this panel keeps the operation available. Stopping prevents further work and waits for any active cleanup.</p><Button disabled={cancel.isPending || turn.status === "cancelling"} onClick={() => cancel.mutate()}>{cancel.isPending || turn.status === "cancelling" ? "Stop requested…" : "Stop this operation"}</Button></div> : <Button disabled={operation.isFetching} onClick={() => { void newRequest(); }}>Start another request</Button>}
          </> : null}
          {operation.isError && !submit.isPending ? <><ErrorState title="Saved work could not be checked" error={operation.error} retry={() => { void operation.refetch(); }} /><p>The original request and its {sentence(receipt.autonomy)} mode are retained. Retry that exact request to find or start the operation once.</p><Button disabled={submit.isPending} onClick={() => submit.mutate(receipt)}>Retry original request</Button></> : null}
        </section> : <>
          {DEMO_MODE ? <p className="assistant-empty">This preview cannot run assistant operations. Open the installed local service and select a saved rule with observed evidence.</p> : !selection ? <div className="assistant-empty"><h3>Start with the evidence</h3><p>Select a saved rule and source run in Detection Lab. The assistant can revise the rule, evaluate it, and prepare another method for comparison.</p><Link className="button button-secondary button-medium" onClick={navigate} to="/detection-lab">Open Detection Lab<ArrowRight aria-hidden="true" /></Link></div> : <>
            <section className="assistant-context" aria-label="Current selection"><small>Selected rule</small><strong>{selection.title}</strong><Link onClick={navigate} to={`/runs/${encodeURIComponent(selection.runId)}`}>Inspect source observations<ArrowRight aria-hidden="true" /></Link></section>
            {context.isPending ? <p role="status">Checking evidence and available actions…</p> : null}
            {context.isError ? <ErrorState title="Context is unavailable" error={context.error} retry={() => { void context.refetch(); }} /> : null}
            {selected && !current ? <p role="alert">This rule changed since it was selected. Reopen its saved revision before starting.</p> : null}
            {selection.manualEdits ? <p role="alert">Save or restore your manual rule edits before starting assistant work.</p> : null}
            {context.data ? <details className="assistant-details"><summary>Available actions and evidence scope</summary><ul>{context.data.capabilities.map((item) => <li key={item.id}><strong>{item.title}</strong><p>{item.available ? "Available" : "Unavailable"}{item.reason ? ` · ${item.reason}` : ""}</p></li>)}</ul>{context.data.limitations.map((item, index) => <p key={index}>{item}</p>)}</details> : null}
          </>}
        </>}
        {!receipt ? <section className="assistant-composer" aria-label="Assistant controls">
          <div className="assistant-options"><Field label="AI mode"><select value={runConfig.autonomy} disabled={Boolean(turn && active)} onChange={(event) => setRunConfig({ ...runConfig, autonomy: event.target.value as AssistanceRequest["autonomy"] })}><option value="off">Off</option><option value="assist">Assist · reviewed changes</option><option value="auto">Auto · permitted work</option></select></Field><Field label="Provider"><select value={selectedProvider?.provider_id ?? ""} disabled={Boolean(receipt)} onChange={(event) => { const model = models.find((item) => item.provider_id === event.target.value); if (model) setRunConfig({ ...runConfig, provider: model.provider_id, model: model.model }); }}><option value="" disabled>Select a configured provider</option>{models.map((item) => <option value={item.provider_id} key={item.provider_id}>{item.model} · {item.provider_id}</option>)}</select></Field></div>
          {runConfig.autonomy === "off" ? <p>Off makes no new model requests. Manual tools remain available.</p> : <p>{runConfig.autonomy === "assist" ? "Review proposed changes in their native views. " : "Only supported operations can continue automatically. "}Execute still requires its own valid approval.</p>}
          {current && runConfig.autonomy !== "off" && !modeSupported ? <p role="status">{runConfig.autonomy === "auto" ? "The actions available for this selection require Assist review. Select Assist to continue; Auto is not supported for this workflow." : "No available action supports this mode for the current selection."}</p> : null}
          {!models.length ? <p><Link onClick={navigate} to="/settings">Configure a provider in Settings</Link> to use model assistance.</p> : null}
          {!receipt ? <form onSubmit={(event) => { event.preventDefault(); start(); }}><Field label="What would you like to do?"><textarea rows={4} maxLength={1000} value={message} onChange={(event) => updateMessage(event.target.value)} placeholder="Improve this rule from the selected run, then try another method and compare detections." /></Field><div className="assistant-send-row"><Field label="Evidence case"><select value={caseRole} onChange={(event) => setCaseRole(event.target.value as DetectionCaseRole)}><option value="attack">Attack</option><option value="benign">Benign</option><option value="replay">Replay</option><option value="heldout">Held-out</option></select></Field><Button type="submit" variant="primary" disabled={!ready || submit.isPending || DEMO_MODE}>Start work<ArrowRight aria-hidden="true" /></Button></div></form> : null}
        </section> : null}
        {localError || submit.error || recover.error || cancel.error ? <ErrorState title="Assistant needs attention" error={localError ?? submit.error ?? recover.error ?? cancel.error} /> : null}
      </div>
    </Dialog.Content></Dialog.Portal>
  </Dialog.Root>;
}
