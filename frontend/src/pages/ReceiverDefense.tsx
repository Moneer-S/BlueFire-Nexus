import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useAssistancePanel, usePublishReceiverSelection } from "../state/AssistanceContext";
import type { ReceiverAssistanceSelection } from "../lib/receiver-assistance";
import { api } from "../lib/api";
import { checkedReceiverTest, clearReceiverPending, phaseTitle, policyTitle, readReceiverPending, receiverJobId, receiverJobValid, receiverOutcome, receiverRequestConfirmed, storeReceiverPending, type ReceiverPending } from "../lib/receiver-defense";
import { Badge, Button, Callout, ErrorState, LoadingState, PageHeader } from "../components/Primitives";
import { ReceiverTestSetup } from "../components/ReceiverTestSetup";
import { ReceiverSavedTests } from "../components/ReceiverSavedTests";
import { ReceiverTestProgress } from "../components/ReceiverTestProgress";
import { RetainedReceiverControl } from "../components/RetainedReceiverControl";
import { ObjectiveContext } from "../components/ObjectiveContext";
import "./ReceiverDefense.css";

export function ReceiverDefensePage() {
  const [params, setParams] = useSearchParams();
  const client = useQueryClient();
  const [restored] = useState(() => { try { return { pending: readReceiverPending(), error: undefined }; } catch (error) { return { pending: undefined, error }; } });
  const [pending, setPending] = useState(restored.pending);
  const [localError, setLocalError] = useState<unknown>(restored.error);
  const locked = useRef(false);
  const id = params.get("receiver_job") ?? pending?.id ?? "";
  const [stopsRequested, setStopsRequested] = useState<string[]>([]);
  const stopRequestedRef = useRef(new Set<string>());
  const stopRequested = stopsRequested.includes(id);
  const focusSection = (sectionId: string) => {
    const target = document.getElementById(sectionId);
    if (!target) return;
    if (target instanceof HTMLDetailsElement) {
      target.open = true;
      target.querySelector("summary")?.focus({ preventScroll: true });
    } else {
      target.focus({ preventScroll: true });
    }
    const reducedMotion = window.matchMedia?.("(prefers-reduced-motion: reduce)")?.matches ?? false;
    target.scrollIntoView?.({ behavior: reducedMotion ? "auto" : "smooth", block: "start" });
  };
  const receiverJobHref = (jobId: string) => {
    const next = new URLSearchParams(params);
    next.delete("receiver");
    next.set("receiver_job", jobId);
    return `/compare?${next.toString()}`;
  };
  const compareRunsHref = () => {
    const next = new URLSearchParams(params);
    next.delete("receiver");
    next.delete("receiver_job");
    next.delete("goal");
    const query = next.toString();
    return query ? `/compare?${query}` : "/compare";
  };
  const write = useMutation({ mutationFn: async (operation: ReceiverPending) => {
    // Persist before every attempt, including retry after an earlier storage failure.
    storeReceiverPending(operation);
    await client.cancelQueries({ queryKey: ["receiver-test", operation.id], exact: true });
    const response = operation.kind === "create" ? await api.createReceiverTest(operation.body) : operation.kind === "prepare" ? await api.prepareReceiver(operation.id, operation.body) : operation.kind === "control" ? await api.rollbackReceiverControl(operation.id, operation.body) : await api.reviewReceiver(operation.id, operation.body);
    const envelope = checkedReceiverTest(response, operation.id);
    await client.cancelQueries({ queryKey: ["receiver-test", operation.id], exact: true });
    return envelope;
  }, onSuccess: (envelope) => {
    if (stopRequestedRef.current.has(envelope.job.job_id)) void client.invalidateQueries({ queryKey: ["receiver-test", envelope.job.job_id], exact: true });
    else client.setQueryData(["receiver-test", envelope.job.job_id], envelope);
    void client.invalidateQueries({ queryKey: ["active-jobs"] });
    void client.invalidateQueries({ queryKey: ["receiver-tests"] });
  }, onSettled: () => { locked.current = false; } });
  const query = useQuery({ queryKey: ["receiver-test", id], queryFn: async () => checkedReceiverTest(await api.receiverTest(id), id), enabled: receiverJobValid(id) && !write.isPending, retry: false,
    refetchInterval: (state) => state.state.data && ["active", "stopping"].includes(state.state.data.status) ? 1200 : false });
  const envelope = query.data;
  const workflowLabel = envelope?.context?.source_control ? "Fresh retest of retained redaction" : envelope?.context?.workflow === "retained_redaction" ? "Retain redaction and verify legitimate use" : "Compare baseline and restored policy";
  const statusTone = envelope?.status === "completed" ? "success" : envelope?.status === "blocked" || envelope?.status === "stopping" ? "warning" : envelope?.status === "stopped" ? "neutral" : "info";
  const assistant = useAssistancePanel();
  const assistantSelection = useMemo<ReceiverAssistanceSelection | undefined>(() => envelope?.schema_version === "bluefire.receiver-defense.v1" && envelope.admission.accepted && envelope.context && envelope.phases.some((phase) => phase.result)
    ? { kind: "receiver_test", receiver_job_id: envelope.job.job_id, receiver_context_digest: envelope.context.context_digest } : undefined, [envelope]);
  usePublishReceiverSelection(assistantSelection, envelope?.context?.scenario_title);
  const assistantOwner = envelope?.job.request?.assistance_turn as { parent_job_id?: string } | undefined;
  const assistantParentId = assistantOwner?.parent_job_id ?? "";

  const stop = useMutation({ mutationFn: async (ownerId: string) => {
    stopRequestedRef.current.add(ownerId); setStopsRequested((old) => [...new Set([...old, ownerId])]);
    await client.cancelQueries({ queryKey: ["receiver-test", ownerId], exact: true });
    return api.controlJob(ownerId, "cancel");
  }, onSuccess: async (_, ownerId) => {
    await client.cancelQueries({ queryKey: ["receiver-test", ownerId], exact: true });
    await client.fetchQuery({ queryKey: ["receiver-test", ownerId], staleTime: 0, queryFn: async () => checkedReceiverTest(await api.receiverTest(ownerId), ownerId) });
    void client.invalidateQueries({ queryKey: ["active-jobs"] });
  } });
  useEffect(() => {
    if (!pending || !envelope || !receiverRequestConfirmed(envelope, pending)) return;
    try { clearReceiverPending(pending); setPending(undefined); setLocalError(undefined); }
    catch (error) { setLocalError(error); }
  }, [envelope, pending]);
  useEffect(() => {
    if (id && !params.get("receiver_job")) setParams((old) => { const next = new URLSearchParams(old); next.set("receiver_job", id); return next; }, { replace: true });
  }, [id, params, setParams]);
  const submit = (operation: ReceiverPending) => {
    if (locked.current || pending || restored.error || (operation.kind !== "control" && stopRequestedRef.current.has(operation.id))) return;
    locked.current = true;
    setPending(operation);
    setParams((old) => { const next = new URLSearchParams(old); next.set("receiver_job", operation.id); return next; });
    setLocalError(undefined);
    write.mutate(operation);
  };
  const retry = () => { if (!pending || pending.id !== id || locked.current || (pending.kind !== "control" && stopRequestedRef.current.has(pending.id))) return; locked.current = true; write.mutate(pending); };
  const startAnother = () => {
    if (!envelope?.can_start_new_test || pending) return;
    setParams((old) => { const next = new URLSearchParams(old); next.delete("receiver_job"); next.set("receiver", "1"); return next; });
    write.reset(); stop.reset(); setLocalError(undefined);
  };
  return <div className="page receiver-defense-page">
    <Link className="receiver-back" to={compareRunsHref()}>← Compare runs</Link>
    <PageHeader eyebrow="Data handoff · receiver defense" title={envelope?.context?.scenario_title ?? (id ? "Saved receiver control test" : "Receiver defense")} description={envelope?.context ? `Version ${envelope.context.selection.version} · ${workflowLabel}` : "Set up a named control test for a saved experiment. Each phase uses a fresh receiver and separate review."} />
    <ObjectiveContext expected="data-handoff" />
    {envelope?.context ? <section className="receiver-overview" aria-label="Control test overview">
      <header className="receiver-overview-heading"><div><p className="eyebrow">Saved control test</p><h2>{workflowLabel}</h2></div><Badge tone={statusTone} dot>{envelope.status === "active" ? "In progress" : envelope.status.replaceAll("_", " ")}</Badge></header>
      <ul className="receiver-outcome-summary" aria-label="Recorded phase outcomes">{envelope.phases.map((phase) => <li key={phase.phase} className={phase.result ? `has-result receiver-result-${phase.result.decision}` : ""}><span>{phaseTitle[phase.phase]}</span><strong>{phase.result ? receiverOutcome(phase) : phase.status.replaceAll("_", " ")}</strong><small>{policyTitle[phase.policy_id]}</small></li>)}</ul>
      <nav className="receiver-section-nav" aria-label="Control test sections"><button type="button" onClick={() => focusSection("receiver-workflow")}>Phase workflow</button>{envelope.control ? <button type="button" onClick={() => focusSection("receiver-policy")}>Retained policy</button> : null}<button type="button" onClick={() => focusSection("receiver-provenance")}>Exact provenance</button></nav>
    </section> : null}
    {localError ? <ErrorState title="Request needs attention" error={localError} /> : null}
    {!id ? <><ReceiverSavedTests /><ReceiverTestSetup disabled={Boolean(restored.error)} onStart={(body) => submit({ kind: "create", id: receiverJobId(body.submission_id), body })} /></> : <>
      {!receiverJobValid(id) ? <ErrorState error={new Error("This control-test link is incomplete. Open the saved test from Runs.")} /> : query.isError ? <ErrorState title="Saved test status unavailable" error={query.error} retry={() => { void query.refetch(); }} /> : !envelope ? <LoadingState label={write.isPending ? "Saving the control test" : "Opening the control test"} /> : null}
      {pending ? <Callout title={write.isPending ? "Saving this request" : "Confirm this request before continuing"}>
        <p>{write.isPending ? "Keep working here or return to this saved test later." : "The original request is retained. Check its status or retry the same request; a retry keeps its identity and reviewed contents."}</p>
        {pending.id !== id ? <p>This retained request belongs to another test. <Link to={receiverJobHref(pending.id)}>Return to the retained control test</Link> to inspect and recover its exact request.</p> : !write.isPending ? <div className="receiver-actions">{!stopRequested || pending.kind === "control" ? <Button onClick={retry}>Retry this exact request</Button> : null}<Button onClick={() => { void query.refetch(); }}>Check saved status</Button>{envelope?.status === "stopped" && pending.kind !== "control" ? <Button onClick={() => { try { clearReceiverPending(pending); setPending(undefined); setLocalError(undefined); } catch (error) { setLocalError(error); } }}>Close retained request after confirmed stop</Button> : null}</div> : null}
        <details><summary>Retained request details</summary><pre>{JSON.stringify(pending, null, 2)}</pre></details>
      </Callout> : null}
      {write.error ? <ErrorState title="Request not confirmed" error={write.error} /> : null}
      {stopRequested && envelope?.status !== "stopped" && envelope?.status !== "completed" ? <Callout title="Stop requested"><p>New preparation and review stay unavailable while this stop is being reconciled. Check the saved status and cleanup; retry Stop if its response could not be confirmed.</p></Callout> : null}
      {envelope && !envelope.admission.accepted ? <Callout tone={envelope.admission.problem ? "warning" : "info"} title={envelope.admission.problem ? "This test needs a new review" : "Checking the reviewed experiment"}>
        <p>{envelope.admission.problem?.message ?? "BlueFire is checking the saved experiment and settings before any receiver can be prepared."}</p>
        {envelope.admission.problem ? <><p>This request did not authorize a receiver or run. Start a separate test to review the current state; the original request stays in history.</p><details><summary>Original request and current unreviewed context</summary><pre>{JSON.stringify({ submitted_request: envelope.job.request?.submitted_request, unreviewed_context: envelope.context }, null, 2)}</pre></details></> : null}
      </Callout> : null}
      {assistant && envelope?.schema_version === "bluefire.receiver-defense.v1" && (receiverJobValid(assistantParentId) || assistantSelection) ? <div className="receiver-assistant-entry">
        <h3>{receiverJobValid(assistantParentId) ? "This test has saved Assistant work" : "Understand the receiver evidence"}</h3>
        <p>{receiverJobValid(assistantParentId) ? "Return to the operation that coordinates this test and its phase analyses. Its submitted mode and provider stay bound." : "Ask for an interpretation of the verified phases. Analysis does not take ownership of this test or start another phase."}</p>
        <Button onClick={() => { if (receiverJobValid(assistantParentId)) assistant.openJob(assistantParentId, id); else assistant.setOpen(true); }}>{receiverJobValid(assistantParentId) ? "Open saved Assistant work" : "Analyse with Assistant"}</Button>
      </div> : null}
      {envelope?.admission.accepted && envelope.context ? <div id="receiver-workflow" tabIndex={-1} className="receiver-workflow-anchor"><ReceiverTestProgress key={id} envelope={{ ...envelope, context: envelope.context }} disabled={Boolean(pending) || write.isPending || stopRequested || Boolean(query.error)}
        onPrepare={(body) => submit({ kind: "prepare", id, body })} onReview={(body) => submit({ kind: "review", id, body })} /></div> : null}
      {envelope?.admission.accepted && envelope.context && envelope.control ? <div id="receiver-policy" tabIndex={-1} className="receiver-policy-anchor"><RetainedReceiverControl key={`${id}:${envelope.control.status}:${envelope.control.control_digest}`} envelope={{ ...envelope, context: envelope.context }} disabled={Boolean(pending) || write.isPending || (stopRequested && !["stopped", "completed"].includes(envelope.status)) || Boolean(query.error)} receiverJobHref={receiverJobHref} onStart={(body) => submit({ kind: "create", id: receiverJobId(body.submission_id), body })} onRollback={(ownerId, body) => submit({ kind: "control", id: ownerId, body })} /></div> : null}
      {envelope?.admission.accepted && envelope.context ? <details id="receiver-provenance" className="receiver-exact-provenance"><summary>Exact experiment, policy, and source provenance</summary><dl>
        <div><dt>Control test</dt><dd><code>{envelope.job.job_id}</code></dd></div>
        <div><dt>Context digest</dt><dd><code>{envelope.context.context_digest}</code></dd></div>
        <div><dt>Saved experiment</dt><dd><code>{envelope.context.selection.scenario_id}</code> · version {envelope.context.selection.version}</dd></div>
        <div><dt>Experiment digest</dt><dd><code>{envelope.context.selection.digest}</code></dd></div>
        {envelope.context.source_baseline ? <div><dt>Baseline lineage</dt><dd><code>{envelope.context.source_baseline.run_id}</code> · {envelope.context.source_baseline.artifact.sha256} · {envelope.context.source_baseline.artifact.size_bytes} bytes</dd></div> : null}
        {envelope.control ? <div><dt>Retained policy owner</dt><dd><code>{envelope.control.owner_job_id}</code> · control digest <code>{envelope.control.control_digest}</code></dd></div> : null}
      </dl><pre>{JSON.stringify({ submitted_request: envelope.job.request?.submitted_request, workflow: envelope.context.workflow ?? "comparison", selection: envelope.context.selection, source_baseline: envelope.context.source_baseline ?? null, source_control: envelope.context.source_control ?? null, policies: envelope.context.policies.map(({ policy_id, digest }) => ({ policy_id, digest })) }, null, 2)}</pre></details> : null}
      {envelope && envelope.status !== "completed" && envelope.status !== "stopped" ? <div className="receiver-stop"><Button variant="danger" disabled={stop.isPending} onClick={() => stop.mutate(id)}>{stop.isPending ? "Requesting stop" : "Stop control test"}</Button><p>Stop requests cancellation and receiver cleanup. The test stays open until shutdown is confirmed.</p></div> : null}
      {stop.error && stop.variables === id ? <ErrorState title="Stop not confirmed" error={stop.error} retry={() => stop.mutate(id)} /> : null}
      {envelope?.can_start_new_test ? <Button disabled={Boolean(pending)} onClick={startAnother}>Set up another control test</Button> : null}
    </>}
  </div>;
}
