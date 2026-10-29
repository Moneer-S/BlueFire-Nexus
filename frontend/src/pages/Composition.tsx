import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Ban, ChevronDown, ChevronUp, GitBranch, Pause, Play, RefreshCw, X } from "lucide-react";
import { api } from "../lib/api";
import { checkedCompositionContext, checkedCompositionList, checkedCompositionObjective, checkedCompositionProposal, clearCompositionPending, compositionApi, compositionConfirmed, compositionProposalActive, compositionJobId, compositionJobValid, compositionRecord, readCompositionPending, storeCompositionPending, type CompositionObjective, type CompositionPending, type CompositionProposal } from "../lib/composition";
import { Badge, Button, Callout, DataList, ErrorState, Field, IconButton, LoadingState, PageHeader, sentence } from "../components/Primitives";
import { CompositionCapabilities, CompositionSetup } from "../components/CompositionReview";
import { CompositionAttempts } from "../components/CompositionAttempts";
import { CompositionGraph } from "../components/CompositionGraph";
import "./Composition.css";
import { checkedCompositionEvidenceContext, compositionEvidenceKnowledge, type CompositionEvidenceContext } from "../lib/composition-evidence";
import type { CompositionKnowledge } from "../lib/composition-knowledge";
import { CompositionReconsiderationReview } from "../components/CompositionReconsiderationReview";
import { clearCompositionControl, compositionControlConfirmed, readCompositionControls, readCompositionProposals, rememberCompositionProposal, storeCompositionControl, type CompositionControl } from "../lib/composition";
import { clearCompositionCancellation, compositionCanRevise, compositionCancellationConfirmed, compositionEstablished, readCompositionCancellations, storeCompositionCancellation } from "../lib/composition";
import type { CompositionObjectiveState, CompositionReviewRequest } from "../lib/composition";
import { compositionControlValid, compositionPack, compositionRequestPack, FILE_ACCESS_PACK, MACOS_FILE_ACCESS_PACK, RECEIVER_PACK } from "../lib/composition";
import { checkedRetainedArtifacts, RECEIVER_RETAINED_PACK, RETAINED_MATERIALIZE_METHOD } from "../lib/composition-retained";
import { CompositionRetainedSources, retainedSourceLabel } from "../components/CompositionRetainedSources";
import { sameJson } from "../lib/replay-review";
import { checkedFileAccessControl, checkedFileAccessStatus, fileAccessApi, fileAccessCompositionPack, fileAccessJobActive, macOSFileAccessControlIdValid } from "../lib/file-access";

export function CompositionPage() {
  const [params, setParams] = useSearchParams();
  const client = useQueryClient();
  const [restored] = useState(() => { try { return { pending: readCompositionPending(), controls: readCompositionControls(), proposals: readCompositionProposals(), cancellations: readCompositionCancellations(), error: undefined }; } catch (error) { return { pending: undefined, controls: {}, proposals: {}, cancellations: {}, error }; } });
  const [pending, setPending] = useState(restored.pending);
  const [pendingControls, setPendingControls] = useState<Record<string, CompositionControl>>(restored.controls);
  const [recentProposals, setRecentProposals] = useState<Record<string, string>>(restored.proposals);
  const [cancellations, setCancellations] = useState<Record<string, string>>(restored.cancellations);
  const [localError, setLocalError] = useState<unknown>(restored.error);
  const [knowledgeSelections, setKnowledgeSelections] = useState<Record<string, CompositionKnowledge | null>>({});
  const [reviewSeed, setReviewSeed] = useState<CompositionReviewRequest>();
  const [expandedObjective, setExpandedObjective] = useState("");
  const [now, setNow] = useState(Date.now());
  const locked = useRef(false);
  const stoppedOwners = useRef(new Set<string>());
  const comparisonSection = useRef<HTMLLIElement>(null);
  const focusedComparison = useRef("");
  const id = params.get("objective") ?? pending?.owner ?? "";
  const stopped = Boolean(pendingControls[id]) || stoppedOwners.current.has(id);
  const control = params.get("control") ?? pending?.control ?? "";
  const requestedPack = params.get("pack");
  const invalidPack = requestedPack !== null && requestedPack !== FILE_ACCESS_PACK && requestedPack !== MACOS_FILE_ACCESS_PACK && requestedPack !== RECEIVER_PACK && requestedPack !== RECEIVER_RETAINED_PACK;
  const proposalId = cancellations[id] ?? params.get("proposal") ?? (pending?.kind === "proposal" && pending.owner === id ? pending.id : "");
  const navigate = (owner: string, proposal = "", nextPack?: ReturnType<typeof compositionPack>) => setParams(next => { const value = new URLSearchParams(next); value.set("control", control); if (nextPack === RECEIVER_RETAINED_PACK) value.set("pack", nextPack); else if (nextPack === RECEIVER_PACK) value.delete("pack"); if (owner !== id) value.delete("attempt"); if (owner) value.set("objective", owner); else value.delete("objective"); if (proposal) value.set("proposal", proposal); else value.delete("proposal"); return value; });
  const list = useQuery({ queryKey: ["composition-list", control], queryFn: async () => checkedCompositionList(await compositionApi.list(control)), enabled: compositionControlValid(control), retry: false });
  const write = useMutation({ mutationFn: async (operation: CompositionPending): Promise<CompositionProposal | CompositionObjectiveState> => {
    if (!currentMutationReady() || (macOSContext && (operation.kind === "proposal" || (operation.kind === "attempt" && Boolean(objective.data?.attempts.length))))) throw new Error("Current original workspace authority is required; saved requests are read-only.");
    storeCompositionPending(operation);
    await client.cancelQueries({ queryKey: ["composition-objective", operation.owner], exact: true });
    const value = await compositionApi.submit(operation);
    return operation.kind === "proposal" ? checkedCompositionProposal(value as CompositionProposal, operation.id, operation.owner) : checkedCompositionObjective(value as CompositionObjectiveState, operation.owner, operation.control, macOSFileAccessControlIdValid(operation.control) ? MACOS_FILE_ACCESS_PACK : undefined);
  }, onSuccess: (value, operation) => {
    if ("owner" in value && !stoppedOwners.current.has(operation.owner)) client.setQueryData(["composition-objective", operation.owner], value);
    else if ("owner" in value) void client.invalidateQueries({ queryKey: ["composition-objective", operation.owner] });
    else client.setQueryData(["composition-proposal", operation.id], value);
    void client.invalidateQueries({ queryKey: ["composition-list", operation.control] });
  }, onSettled: () => { locked.current = false; } });
  const objective = useQuery({ queryKey: ["composition-objective", id], queryFn: async () => checkedCompositionObjective(await compositionApi.objective(id), id, control || undefined, requestedPack === FILE_ACCESS_PACK || requestedPack === MACOS_FILE_ACCESS_PACK || requestedPack === RECEIVER_PACK || requestedPack === RECEIVER_RETAINED_PACK ? requestedPack : undefined), enabled: compositionJobValid(id) && !write.isPending && !invalidPack, retry: false, refetchInterval: state => state.state.data?.grant && !["revoked", "expired"].includes(state.state.data.grant.status) ? 1500 : false });
  const macOSContext = requestedPack === MACOS_FILE_ACCESS_PACK || macOSFileAccessControlIdValid(control) || objective.data?.grant?.document.pack === MACOS_FILE_ACCESS_PACK;
  const workspaceStatus = useQuery({ queryKey: ["file-access-status"], queryFn: async () => checkedFileAccessStatus(await fileAccessApi.status()), enabled: macOSContext, retry: false });
  const workspaceControl = useQuery({ queryKey: ["file-access-control", control], queryFn: async () => checkedFileAccessControl(await fileAccessApi.control(control), control), enabled: macOSContext && macOSFileAccessControlIdValid(control), retry: false });
  const mutationReady = !macOSContext || ((requestedPack === null || requestedPack === MACOS_FILE_ACCESS_PACK) && !workspaceStatus.isPending && !workspaceStatus.isFetching && !workspaceStatus.error
    && workspaceStatus.data?.platform === "macos" && workspaceStatus.data.available && Boolean(workspaceStatus.data.enrollment && workspaceStatus.data.enrollment.expires_at_ms > now)
    && !workspaceControl.isPending && !workspaceControl.isFetching && !workspaceControl.error && workspaceControl.data?.platform === "macos"
    && fileAccessCompositionPack(workspaceControl.data) === MACOS_FILE_ACCESS_PACK
    && !workspaceControl.data.operations.some(fileAccessJobActive)
    && (!objective.data?.grant || objective.data.grant.document.environment.control_digest === workspaceControl.data.control_digest));
  const currentMutationReady = () => {
    const observed = Date.now();
    return mutationReady && (!macOSContext || ((workspaceStatus.data?.enrollment?.expires_at_ms ?? 0) > observed
      && (!objective.data?.grant || objective.data.grant.document.expires_at_ms > observed)));
  };
  useEffect(() => {
    if (!macOSContext) return;
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [macOSContext]);
  const proposal = useQuery({ queryKey: ["composition-proposal", proposalId], queryFn: async () => checkedCompositionProposal(await compositionApi.proposal(proposalId), proposalId, id), enabled: !macOSContext && compositionJobValid(proposalId) && compositionJobValid(id) && !write.isPending, retry: false, refetchInterval: state => compositionProposalActive(state.state.data) ? 1200 : false });
  useEffect(() => {
    const savedControl = control || objective.data?.grant?.document.environment.control_owner_id || String(compositionRecord(compositionRecord(objective.data?.owner.progress.submitted_request).review).control_owner_id ?? "");
    if (!id || !savedControl || (params.get("objective") && params.get("control"))) return;
    setParams(previous => { const next = new URLSearchParams(previous); next.set("objective", id); next.set("control", savedControl); if (proposalId) next.set("proposal", proposalId); return next; }, { replace: true });
  }, [control, id, objective.data, params, proposalId, setParams]);
  useEffect(() => {
    const value = pending?.kind === "proposal" ? proposal.data : objective.data;
    if (!pending || !value || !compositionConfirmed(value, pending)) return;
    try { if (pending.kind === "proposal") { rememberCompositionProposal(pending.owner, pending.id); setRecentProposals(readCompositionProposals()); } clearCompositionPending(pending); setPending(undefined); setLocalError(undefined); }
    catch (error) { setLocalError(error); }
  }, [pending, objective.data, proposal.data]);
  useEffect(() => {
    const operation = pendingControls[id];
    if (!operation || !objective.data || !compositionControlConfirmed(objective.data, operation)) return;
    try { clearCompositionControl(id, operation); setPendingControls(readCompositionControls()); }
    catch (error) { setLocalError(error); }
  }, [id, pendingControls, objective.data]);
  useEffect(() => {
    const job = cancellations[id];
    if (!job || !proposal.data || !compositionCancellationConfirmed(proposal.data, id, job)) return;
    try { clearCompositionCancellation(id, job); setCancellations(readCompositionCancellations()); }
    catch (error) { setLocalError(error); }
  }, [id, cancellations, proposal.data]);
  useEffect(() => {
    if (!proposal.data || proposal.data.job.request.owner_id !== id || recentProposals[id] === proposal.data.job.job_id) return;
    try { rememberCompositionProposal(id, proposal.data.job.job_id); setRecentProposals(readCompositionProposals()); } catch (error) { setLocalError(error); }
  }, [id, proposal.data, recentProposals]);
  const send = (operation: CompositionPending) => {
    if (!currentMutationReady() || (macOSContext && (operation.kind === "proposal" || (operation.kind === "attempt" && Boolean(objective.data?.attempts.length)))) || pending || locked.current || localError || (stoppedOwners.current.has(operation.owner) && operation.kind !== "grant")) return;
    locked.current = true; setPending(operation); setLocalError(undefined); navigate(operation.owner, operation.kind === "proposal" ? operation.id : "", operation.kind === "grant" ? compositionRequestPack(compositionRecord(operation.body.review)) : undefined); write.mutate(operation);
  };
  const safety = useMutation({ mutationFn: async ({ owner, control: retainedControl, operation }: { owner: string; control: string; operation: CompositionControl }): Promise<CompositionObjectiveState> => {
    if ((operation === "continue" && !currentMutationReady()) || (macOSContext && !envelope)) throw new Error("Current original workspace authority is unavailable for this control request.");
    storeCompositionControl(owner, operation); setPendingControls(readCompositionControls());
    if (operation !== "continue") stoppedOwners.current.add(owner);
    await client.cancelQueries({ queryKey: ["composition-context", owner] });
    await client.cancelQueries({ queryKey: ["composition-evidence-context", owner] });
    await client.cancelQueries({ queryKey: ["composition-objective", owner], exact: true });
    return checkedCompositionObjective(await compositionApi.control(owner, operation), owner, retainedControl || undefined, macOSFileAccessControlIdValid(retainedControl) ? MACOS_FILE_ACCESS_PACK : undefined);
  }, onSuccess: (value, target) => { client.setQueryData(["composition-objective", target.owner], value); if (target.operation === "continue") stoppedOwners.current.delete(target.owner); void client.invalidateQueries({ queryKey: ["composition-list", target.control] }); void client.invalidateQueries({ queryKey: ["composition-context", target.owner], refetchType: "none" }); void client.invalidateQueries({ queryKey: ["composition-evidence-context", target.owner], refetchType: "none" }); void client.invalidateQueries({ queryKey: ["composition-proposal"] }); } });
  const recovery = useMutation({ mutationFn: async ({ owner, attempt, control: retainedControl }: { owner: string; attempt: string; control: string }) => { await client.cancelQueries({ queryKey: ["composition-objective", owner], exact: true }); return checkedCompositionObjective(await compositionApi.recover(owner, attempt), owner, retainedControl || undefined, MACOS_FILE_ACCESS_PACK); }, onSuccess: (value, target) => { client.setQueryData(["composition-objective", target.owner], value); void client.invalidateQueries({ queryKey: ["composition-list", target.control] }); } });
  const controlObjective = (operation: CompositionControl) => { if ((operation !== "continue" || currentMutationReady()) && (!macOSContext || envelope)) safety.mutate({ owner: id, control, operation }); };
  const cancel = useMutation({ mutationFn: async ({ owner, job }: { owner: string; job: string }) => {
    if (!mutationReady || macOSContext) throw new Error("The fixed macOS graph has no provider request to cancel.");
    storeCompositionCancellation(owner, job); setCancellations(readCompositionCancellations());
    await client.cancelQueries({ queryKey: ["composition-proposal", job], exact: true });
    return checkedCompositionProposal(await compositionApi.cancel(job), job, owner);
  }, onSuccess: value => client.setQueryData(["composition-proposal", value.job.job_id], value) });
  const savedEnvelope = objective.data?.grant ? objective.data : undefined;
  const envelope = savedEnvelope && !invalidPack && (!control || savedEnvelope.grant.document.environment.control_owner_id === control) && (!requestedPack || compositionPack(savedEnvelope.grant.document) === requestedPack) ? savedEnvelope : undefined;
  const savedRefusal = objective.data?.grant === null ? objective.data : undefined;
  const refusedReview = compositionRecord(compositionRecord(savedRefusal?.owner.progress.submitted_request).review);
  const refusal = savedRefusal && !invalidPack && (!control || refusedReview.control_owner_id === control) && (!requestedPack || compositionRequestPack(refusedReview) === requestedPack) ? savedRefusal : undefined;
  const pack = envelope ? compositionPack(envelope.grant.document) : requestedPack === RECEIVER_RETAINED_PACK || compositionRecord(pending?.body.review).pack === RECEIVER_RETAINED_PACK || refusedReview.pack === RECEIVER_RETAINED_PACK ? RECEIVER_RETAINED_PACK : requestedPack === RECEIVER_PACK ? RECEIVER_PACK : requestedPack === FILE_ACCESS_PACK ? FILE_ACCESS_PACK : macOSContext ? MACOS_FILE_ACCESS_PACK : compositionRecord(pending?.body.review).pack === FILE_ACCESS_PACK || compositionRecord(compositionRecord(refusal?.owner.progress.submitted_request).review).pack === FILE_ACCESS_PACK ? FILE_ACCESS_PACK : RECEIVER_PACK;
  const fileAccess = pack === FILE_ACCESS_PACK || pack === MACOS_FILE_ACCESS_PACK;
  const packQuery: Record<string, string> = fileAccess ? { pack } : {};
  const selectedAttempt = params.get("attempt");
  const selectedComparison = pack === FILE_ACCESS_PACK && selectedAttempt && envelope?.attempts.some(attempt => attempt.request.composition_attempt.attempt_id === selectedAttempt)
    ? `${id}:${selectedAttempt}` : "";
  const comparisonFirst = Boolean(selectedComparison && !pending && !pendingControls[id] && !cancellations[id]);
  useEffect(() => {
    if (!selectedAttempt) focusedComparison.current = "";
    if (!comparisonFirst || !comparisonSection.current || focusedComparison.current === selectedComparison) return;
    focusedComparison.current = selectedComparison;
    comparisonSection.current.focus({ preventScroll: true });
    comparisonSection.current.scrollIntoView?.({ block: "start", behavior: "instant" });
  }, [comparisonFirst, selectedAttempt, selectedComparison]);
  return <div className={`page composition-page${expandedObjective === id && id ? " composition-objective-expanded" : ""}`}>
    <Link to={fileAccess ? `/file-access${compositionControlValid(control, pack) ? `?control=${encodeURIComponent(control)}` : ""}` : compositionJobValid(control) ? `/compare?receiver_job=${encodeURIComponent(control)}` : "/compare"}>{fileAccess ? "Retained file-access control" : "Retained receiver control"}</Link>
    <PageHeader title={envelope?.grant.document.objective.question ?? "Composition workspace"} actions={compositionJobValid(id) && !refusal ? <div className="composition-actions">{envelope ? <IconButton label={expandedObjective === id ? "Collapse objective question" : "Show full objective question"} aria-expanded={expandedObjective === id} onClick={() => setExpandedObjective(expandedObjective === id ? "" : id)}>{expandedObjective === id ? <ChevronUp /> : <ChevronDown />}</IconButton> : null}<Button variant="danger" disabled={safety.isPending || (macOSContext && !envelope)} onClick={() => controlObjective("stop")}><Pause />Stop</Button><Button variant="danger" disabled={safety.isPending || (macOSContext && !envelope)} onClick={() => controlObjective("revoke")}><Ban />Revoke</Button></div> : undefined} />
    {localError ? <ErrorState title="Saved request needs attention" error={localError} /> : null}
    {macOSContext && !mutationReady ? <Callout title="Original macOS workspace is read-only">Saved objectives and evidence remain available. New operations require the current original hardened control and settled custody.</Callout> : null}
    {invalidPack ? <ErrorState error={new Error("This capability pack is not supported.")} /> : !compositionControlValid(control, pack) ? <Callout title="Select the original retained control"><Link to="/compare">Receiver control</Link> or <Link to="/file-access">effective file access</Link></Callout> : <>
      {comparisonFirst && envelope ? <div className="composition-selected-result"><CompositionAttempts objective={envelope} selectedAttemptRef={comparisonSection} onKnowledgeChange={knowledge => setKnowledgeSelections(previous => ({ ...previous, [envelope.owner.job_id]: knowledge }))} /></div> : null}
      <section className="composition-section" aria-label="Saved objectives"><div className="composition-heading"><h2>Saved objectives</h2><Button size="small" disabled={list.isFetching || (macOSContext && workspaceStatus.isFetching)} onClick={() => { void list.refetch(); if (macOSContext) { void workspaceStatus.refetch(); void workspaceControl.refetch(); } }}><RefreshCw />Refresh</Button></div>
        {list.error ? <ErrorState error={list.error} /> : list.isPending ? <LoadingState label="Opening saved objectives" /> : <div className="composition-objective-list">{list.data?.objectives.map(item => <Link aria-label={`Open objective: ${item.title}, ${sentence(item.status)}`} aria-current={item.owner_id === id ? "page" : undefined} key={item.owner_id} to={`/composition?${new URLSearchParams({ control, objective: item.owner_id, ...packQuery, ...(recentProposals[item.owner_id] ? { proposal: recentProposals[item.owner_id]! } : {}) })}`}><strong>{item.title}</strong><span>{sentence(item.status)}</span></Link>)}{!list.data?.objectives.length ? <p>No saved objectives for this control.</p> : null}</div>}
        {id ? <Button disabled={!mutationReady || Boolean(pending) || write.isPending} onClick={() => { setReviewSeed(undefined); navigate(""); }}>New objective</Button> : null}
      </section>
      {pending ? <Callout title={write.isPending ? "Saving exact request" : "Request confirmation pending"}>
        <p>{pending.kind === "attempt" ? "An attempt may already be running. Reconcile its saved identity before starting any other work." : "The exact submission is retained across reloads. No automatic effect retry is performed."}</p>
        <code>{pending.id}</code>
        {pending.owner !== id ? <Link to={`/composition?${new URLSearchParams({ control: pending.control, objective: pending.owner, ...packQuery, ...(pending.kind === "proposal" ? { proposal: pending.id } : {}) })}`}>Open the pending objective</Link> : <div className="composition-actions"><Button disabled={write.isPending} onClick={() => { void objective.refetch(); if (pending.kind === "proposal" && !macOSContext) void proposal.refetch(); }}>Check saved status</Button>{!macOSContext ? <Button disabled={!mutationReady || write.isPending || stopped || safety.isPending} onClick={() => { if (mutationReady && !locked.current) { locked.current = true; write.mutate(pending); } }}>Retry exact submission</Button> : null}{envelope && ["paused", "revoked", "expired"].includes(envelope.grant.status) ? <Button disabled={write.isPending} onClick={() => { try { clearCompositionPending(pending); setPending(undefined); } catch (error) { setLocalError(error); } }}>Close request after confirmed stop</Button> : null}</div>}
      </Callout> : null}
      {write.error ? <ErrorState title="Submission not confirmed" error={write.error} /> : null}
      {safety.error ? <ErrorState title="Control request not confirmed" error={safety.error} /> : null}
      {recovery.error ? <ErrorState title="Original close status not confirmed" error={recovery.error} /> : null}
      {pendingControls[id] ? <Callout title={`${sentence(pendingControls[id]!)} confirmation pending`}><p>New work remains disabled until this exact control request is reconciled.</p><div className="composition-actions"><Button disabled={safety.isPending || (pendingControls[id] === "continue" && !mutationReady) || (macOSContext && !envelope)} onClick={() => controlObjective(pendingControls[id]!)}>Retry exact control request</Button><Button onClick={() => { void objective.refetch(); }}>Check control state</Button></div></Callout> : null}
      {!id ? <CompositionSetup key={`${control}:${pack}`} control={control} pack={pack} disabled={!mutationReady || Boolean(pending) || Boolean(localError)} onSubmit={send} initialRequest={reviewSeed} /> : <>
        {!compositionJobValid(id) ? <ErrorState error={new Error("This objective link is incomplete.")} /> : objective.error ? <ErrorState title="Current objective unavailable" error={objective.error} retry={() => { void objective.refetch(); }} /> : !envelope && !refusal ? <LoadingState label="Opening objective" /> : null}
        {refusal ? <Callout title="Delegation refused"><p>{String(compositionRecord(compositionRecord(refusal.owner.progress.admission).problem).message)}</p><p>No capability grant or execution authority was issued.</p><Button disabled={!mutationReady || Boolean(pending) || Boolean(localError)} onClick={() => { setReviewSeed(compositionRecord(refusal.owner.progress.submitted_request).review as CompositionReviewRequest); navigate(""); }}><RefreshCw />Review again</Button></Callout> : null}
        {envelope ? <>
          <section className="composition-section" aria-label="Grant status"><div className="composition-heading"><h2>Capability grant</h2><Badge tone={envelope.grant.status === "active" ? "info" : "warning"}>{sentence(envelope.grant.status)}</Badge></div><DataList items={[{ label: "Expires", value: new Date(envelope.grant.document.expires_at_ms).toLocaleString() }, { label: "Reviewed by", value: envelope.grant.document.approved_by }, { label: "Cleanup state", value: typeof envelope.grant.cleanup_state === "string" ? sentence(envelope.grant.cleanup_state) : JSON.stringify(envelope.grant.cleanup_state) }]} />
            <h3>Cumulative reservations</h3><dl className="composition-limits">{Object.entries(envelope.grant.usage).map(([key, value]) => <div key={key}><dt>{key === "retained_metadata_bytes" ? "Metadata estimate charged" : sentence(key)}</dt><dd>{value.toLocaleString()} / {envelope.grant.document.limits[`max_${key}`]?.toLocaleString() ?? "not reported"}</dd></div>)}</dl>
            <details><summary>Reviewed capabilities and cumulative limits</summary><CompositionCapabilities review={envelope.grant.document} /></details>
            {envelope.grant.status === "paused" ? <><p>Continue preserves spent budgets and the original expiry. It does not replay an interrupted attempt.</p><Button disabled={!mutationReady || safety.isPending || Boolean(pending) || Boolean(pendingControls[id]) || Boolean(objective.error)} onClick={() => controlObjective("continue")}><Play />Continue objective</Button></> : null}
          </section>
          {!comparisonFirst ? <CompositionAttempts objective={envelope} onKnowledgeChange={knowledge => setKnowledgeSelections(previous => ({ ...previous, [envelope.owner.job_id]: knowledge }))} /> : null}
          {macOSContext ? envelope.attempts.filter(attempt => attempt.progress.settlement === "pending_cleanup").map(attempt => {
            const recoveryState = compositionRecord(attempt.progress.macos_recovery);
            const state = String(recoveryState.state ?? "");
            return <Callout key={attempt.job_id} title={state === "unavailable" || state === "unresolved" ? "Original attempt close needs review" : "Attempt closure pending"}>
              {state === "unavailable" ? <p>The original process authority is unavailable. No workspace was re-adopted and no new attempt was started.</p> : state === "unresolved" ? <p>The original close could not be verified. Review retained evidence before taking any further action.</p> : <><p>This action can only close the exact original attempt when its live workspace guard remains and no dispatch was recorded. It does not replay the graph.</p><Button disabled={recovery.isPending} onClick={() => recovery.mutate({ owner: id, control, attempt: attempt.request.composition_attempt.attempt_id })}>{recovery.isPending ? "Checking original close…" : "Close undispatched attempt"}</Button></>}
            </Callout>;
          }) : null}
          <CompositionPlanning key={id} knowledge={knowledgeSelections[id]} objective={envelope} proposal={proposal.data} proposalId={proposalId} pending={Boolean(pending)} disabled={!mutationReady || Boolean(objective.error) || Boolean(proposal.error) || proposal.isFetching || cancel.isPending || Boolean(cancellations[id]) || stopped || safety.isPending || write.isPending || Boolean(localError)} onSubmit={send} onProposal={(next) => navigate(id, next)} />
        </> : null}
        {proposal.error ? <ErrorState title="Proposal status unavailable" error={proposal.error} retry={() => { void proposal.refetch(); }} /> : null}
        {cancellations[id] ? <Callout title="Proposal cancellation pending">New dispatch remains disabled until the saved proposal is confirmed stopped.</Callout> : null}
        {!macOSContext && compositionJobValid(proposalId) ? <Button disabled={!mutationReady || cancel.isPending} onClick={() => cancel.mutate({ owner: id, job: proposalId })}><X />{cancellations[id] ? "Retry exact proposal cancellation" : "Cancel proposal"}</Button> : null}
        {cancel.error ? <ErrorState title="Proposal stop not confirmed" error={cancel.error} /> : null}
      </>}
    </>}
  </div>;
}

function CompositionPlanning({ objective, knowledge, proposal, proposalId, pending, disabled, onSubmit, onProposal }: { knowledge?: CompositionKnowledge | null; objective: CompositionObjective; proposal?: CompositionProposal; proposalId: string; pending: boolean; disabled: boolean; onSubmit: (value: CompositionPending) => void; onProposal: (id: string) => void }) {
  const planningClient = useQueryClient();
  const pack = compositionPack(objective.grant.document);
  const macOS = pack === MACOS_FILE_ACCESS_PACK;
  const [prior, setPrior] = useState("");
  const [provider, setProvider] = useState("");
  const [useInitial, setUseInitial] = useState(false);
  const [useHistory, setUseHistory] = useState(false);
  const historyChoiceMade = useRef(false);
  useEffect(() => {
    if (!historyChoiceMade.current && compositionRecord(proposal?.job.request.submitted_request).schema_version === "bluefire.composition-evidence-proposal-request.v1") {
      setUseHistory(true); historyChoiceMade.current = true;
    }
  }, [proposal]);
  const [showGraph, setShowGraph] = useState(false);
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    const requested = compositionRecord(proposal?.job.request.submitted_request).prior_attempt_id;
    if (!prior && typeof requested === "string" && objective.attempts.some(item => item.request.composition_attempt.attempt_id === requested)) setPrior(requested);
  }, [proposal, objective.attempts, prior]);
  useEffect(() => { const timer = window.setInterval(() => setNow(Date.now()), 1000); return () => window.clearInterval(timer); }, []);
  const grant = objective.grant.document;
  const owner = objective.owner.job_id;
  const established = compositionEstablished(objective);
  const proposing = compositionProposalActive(proposal);
  const active = !established && (!macOS || !objective.attempts.length) && objective.grant.status === "active" && grant.expires_at_ms > now && !disabled && !pending && !proposing;
  const priorValid = !objective.attempts.length ? prior === "" : objective.attempts.some(item => item.request.composition_attempt.attempt_id === prior && compositionCanRevise(item, objective));
  const retained = pack === RECEIVER_RETAINED_PACK;
  const capturedRetained = proposal?.proposal?.schema_version === "bluefire.composition-ai-result.v3" ? proposal.job.request.context as import("../lib/composition").CompositionContext : undefined;
  const capturedContext = proposal?.proposal?.reconsideration && ["bluefire.composition-ai-result.v2", "bluefire.composition-ai-result.v3"].includes(proposal.proposal.schema_version) ? proposal.job.request.context as CompositionEvidenceContext : undefined;
  const capturedKnowledge = capturedContext ? compositionEvidenceKnowledge(capturedContext, owner) : undefined;
  const selectedKnowledge = knowledge === undefined ? capturedKnowledge : knowledge;
  const validKnowledge = selectedKnowledge?.owner_id === owner && selectedKnowledge.attempts.every(saved => objective.attempts.some(attempt => attempt.job_id === saved.job_id && attempt.request.composition_attempt.attempt_id === saved.attempt_id && attempt.request.composition_attempt.run_id === saved.run_id)) ? selectedKnowledge : undefined;
  const frontier = [...objective.attempts].reverse().find(attempt => attempt.progress.settlement === "settled");
  useEffect(() => {
    if (useHistory && frontier && compositionCanRevise(frontier, objective) && prior !== frontier.request.composition_attempt.attempt_id) setPrior(frontier.request.composition_attempt.attempt_id);
  }, [frontier, objective, prior, useHistory]);
  const historyValid = (pack === RECEIVER_PACK || retained) && Boolean(frontier && compositionCanRevise(frontier, objective) && prior === frontier.request.composition_attempt.attempt_id && validKnowledge);
  const context = useQuery({ queryKey: ["composition-context", owner, prior, objective.attempts.map(item => `${item.job_id}:${item.state}:${item.progress.settlement}`).join("|")], queryFn: async () => { const value = checkedCompositionContext(await compositionApi.context(owner, prior || null), grant.grant_id, pack); if (retained) checkedRetainedArtifacts(value.retained_artifacts, objective); return value; }, enabled: active && priorValid && !useHistory, retry: false });
  const evidenceContext = useQuery({ queryKey: ["composition-evidence-context", owner, prior, validKnowledge?.knowledge_digest, validKnowledge?.attempts.map(attempt => attempt.attempt_id).join("|"), objective.attempts.map(item => `${item.job_id}:${item.state}:${item.progress.settlement}`).join("|")], queryFn: async () => { const value = checkedCompositionEvidenceContext(await compositionApi.evidenceContext(owner, prior, validKnowledge!), grant.grant_id, owner, validKnowledge!, prior); if (value.snapshot.pack !== pack) throw new Error("Historical context belongs to a different reviewed capability pack."); if (retained) checkedRetainedArtifacts(value.retained_artifacts, objective); return value; }, enabled: active && useHistory && historyValid, retry: false });
  const catalog = useQuery({ queryKey: ["catalog"], queryFn: api.catalog, enabled: !macOS, retry: false });
  const providers = (catalog.data?.ai.providers ?? []).filter(item => item.kind !== "deterministic");
  const planningContext = useHistory ? evidenceContext : context;
  const current = planningContext.data;
  const viewSnapshot = current?.snapshot ?? grant.snapshot;
  const candidate = useInitial ? current?.initial_proposal : macOS ? undefined : proposal?.proposal?.candidate;
  const scenario = useInitial ? current?.initial_scenario : macOS ? undefined : proposal?.proposal?.scenario;
  const sourceMatches = !retained || !candidate || candidate.steps.every(step => {
    if (step.behavior_id !== RETAINED_MATERIALIZE_METHOD) return true;
    const source = current?.retained_artifacts?.available_sources.find(item => item.source_ref === step.parameters.source_ref);
    const captured = capturedRetained?.retained_artifacts?.available_sources.find(item => item.source_ref === step.parameters.source_ref);
    return Boolean(source && (!capturedRetained || sameJson(source, captured)));
  });
  const matches = Boolean(current && sourceMatches && (useInitial ? !objective.attempts.length && candidate : proposal?.candidate_ready && proposal.proposal?.context_digest === current.context_digest && proposal.proposal.prior_attempt_id === (prior || null) && (useHistory ? proposal.proposal.schema_version === (retained ? "bluefire.composition-ai-result.v3" : "bluefire.composition-ai-result.v2") && proposal.proposal.knowledge_digest === validKnowledge?.knowledge_digest : proposal.proposal.schema_version === (retained ? "bluefire.composition-ai-result.v3" : "bluefire.composition-ai-result.v1") && (!retained || proposal.proposal.reconsideration === null))));
  const ready = active && priorValid && (!useHistory || historyValid) && !planningContext.isFetching && !planningContext.error && matches && candidate && scenario;
  const newRequest = (kind: "proposal" | "attempt", body: Record<string, unknown>) => { if (!active || (macOS && (kind !== "attempt" || objective.attempts.length || !useInitial))) return; const submission_id = crypto.randomUUID(); onSubmit({ kind, owner, control: grant.environment.control_owner_id, id: compositionJobId(submission_id), body: { submission_id, ...body } }); };
  if ((pack === FILE_ACCESS_PACK || macOS) && objective.attempts.length) return <section className="composition-section" aria-label="Graph planning"><h2>{established ? "Objective established" : "Control review"}</h2><p>{macOS ? established ? "A settled verified attempt meets the reviewed access and request-closure conditions. The original workers and resource remain retained." : "The fixed macOS graph has no alternate read path. The original attempt and its closure state remain recorded; no further attempt is available." : established ? "A settled verified attempt meets every reviewed access and cleanup condition." : "The fixed file-access pack has no different permitted read path. The current attempt and its cleanup remain recorded."}</p><Link to={`/file-access?control=${encodeURIComponent(grant.environment.control_owner_id)}`}>Review retained file-access control</Link></section>;
  return <section className="composition-section" aria-label="Graph planning"><h2>{objective.attempts.length ? "Evidence-driven revision" : "Initial graph"}</h2>
    {objective.attempts.length ? <Field label="Verified prior attempt"><select value={prior} disabled={pending || useHistory} onChange={event => { setPrior(event.target.value); setUseInitial(false); onProposal(""); }}><option value="">{retained ? "Select a settled attempt with a kept result and later failure" : "Select settled refusal evidence"}</option>{objective.attempts.map((item, index) => <option key={item.job_id} value={item.request.composition_attempt.attempt_id} disabled={!compositionCanRevise(item, objective)}>Attempt {index + 1}: {String(compositionRecord(compositionRecord(item.progress.verified_result).objective).established === true ? "established" : item.state)}{item.progress.settlement !== "settled" ? " / cleanup pending" : ""}</option>)}</select></Field> : null}
    {(pack === RECEIVER_PACK || retained) && objective.attempts.length ? <div className="composition-history-option"><label className="check-row"><input type="checkbox" checked={useHistory} disabled={pending || proposing} onChange={event => { historyChoiceMade.current = true; setUseHistory(event.target.checked); setUseInitial(false); if (event.target.checked && frontier && compositionCanRevise(frontier, objective)) setPrior(frontier.request.composition_attempt.attempt_id); }} /><span>Use selected historical findings to reconsider earlier choices</span></label><p>{validKnowledge ? `${validKnowledge.attempts.length} loaded attempt${validKnowledge.attempts.length === 1 ? "" : "s"} selected. Historical findings are model context; current facts are verified separately.` : "Load selected findings in Attempts to include recorded history."}</p>{useHistory ? <p>This receiver revision continues from the latest settled attempt. It requires the separate model purpose “{retained ? "Propose receiver graphs that keep and reuse generated results" : "Reconsider receiver graph choices using selected historical findings"}”.</p> : null}</div> : null}
    {established ? <Callout title="Objective established">A settled verified attempt meets every reviewed success condition. No new graph or attempt is available for this objective.</Callout> : !active ? <Callout title="New dispatch unavailable">{grant.expires_at_ms <= now ? "The original grant has expired." : proposing ? "The selected provider request is still active. Its saved result or confirmed cancellation remains pending." : "A current active grant, reconciled submissions and verified cleanup are required."}</Callout> : null}
    {active && priorValid && (!useHistory || historyValid) ? planningContext.isFetching ? <LoadingState label="Verifying current facts and capabilities" /> : planningContext.error ? <ErrorState error={planningContext.error} retry={() => { void planningContext.refetch(); }} /> : null : null}
    {retained && current?.retained_artifacts && (!capturedRetained || current.context_digest !== capturedRetained.context_digest || !sameJson(current.retained_artifacts, capturedRetained.retained_artifacts)) ? <CompositionRetainedSources artifacts={current.retained_artifacts} objective={objective} /> : null}
    {retained ? <><Button size="small" disabled={!active || !priorValid || (useHistory && !historyValid) || planningContext.isFetching} onClick={() => { void planningContext.refetch(); if (proposalId) void planningClient.invalidateQueries({ queryKey: ["composition-proposal", proposalId], exact: true }); }}><RefreshCw aria-hidden="true" />Refresh available results</Button><p>Keeping and reusing results requires separate authorization for “Propose receiver graphs that keep and reuse generated results”.</p></> : null}
    {!macOS ? <div className="composition-provider"><Field label="Configured model provider"><select value={provider} disabled={!active} onChange={event => setProvider(event.target.value)}><option value="">Select a provider</option>{providers.map(item => <option value={item.provider_id} key={item.provider_id}>{item.model} / {item.provider_id}</option>)}</select></Field><Link to="/settings#model-connection">Provider and model usage authorization</Link></div> : null}
    {!macOS && catalog.error ? <ErrorState error={catalog.error} /> : null}
    <div className="composition-actions">{!macOS ? <Button disabled={!active || !priorValid || !current || (useHistory && !historyValid) || planningContext.isFetching || Boolean(planningContext.error) || !providers.some(item => item.provider_id === provider)} onClick={() => { setUseInitial(false); newRequest("proposal", { ...(useHistory ? { schema_version: "bluefire.composition-evidence-proposal-request.v1", attempt_ids: validKnowledge!.attempts.map(attempt => attempt.attempt_id), knowledge_digest: validKnowledge!.knowledge_digest } : {}), provider_id: provider, context_digest: current!.context_digest, prior_attempt_id: prior || null }); }}>{objective.attempts.length ? <RefreshCw aria-hidden="true" /> : <GitBranch aria-hidden="true" />}{useHistory ? "Request history-aware revision" : objective.attempts.length ? "Request evidence-based revision" : "Request AI graph"}</Button> : null}{!objective.attempts.length && current?.initial_proposal ? <Button disabled={!active} aria-pressed={useInitial} onClick={() => { setUseInitial(true); onProposal(""); }}>Review established graph</Button> : null}</div>
    {!macOS ? <p>Only the selected provider is used, with no fallback. Model usage and data authorization are separate from execution authority.</p> : null}
    {!macOS && proposalId && proposal ? <Callout title={`Proposal: ${sentence(proposal.provider_outcome)}`}>{String(proposal.job.progress.operation_error ?? (proposal.candidate_ready ? "The candidate passed current compiler checks." : "No currently admissible candidate is available."))}</Callout> : null}
    {capturedRetained?.retained_artifacts ? <CompositionRetainedSources artifacts={capturedRetained.retained_artifacts} objective={objective} captured /> : null}
    {capturedContext && proposal?.proposal ? <CompositionReconsiderationReview context={capturedContext} proposal={proposal.proposal} objective={objective} /> : null}
    {candidate && scenario ? <>
      <h3>{candidate.title}</h3><p>{candidate.rationale}</p>
      <div className="composition-table" role="region" aria-label="Proposed graph steps" tabIndex={0}><table><thead><tr><th>Step</th><th>Method</th><th>Parameters</th></tr></thead><tbody>{candidate.steps.map(step => <tr key={step.id}><th scope="row">{step.id}</th><td>{viewSnapshot.methods.find(item => item.behavior_id === step.behavior_id)?.behavior.title ?? step.behavior_id}</td><td>{Object.entries(step.parameters).map(([key, value]) => <div key={key}>{key === "source_ref" && step.behavior_id === RETAINED_MATERIALIZE_METHOD ? (() => { const source = (capturedRetained?.retained_artifacts ?? current?.retained_artifacts)?.available_sources.find(item => item.source_ref === value); return source ? `Retained result: ${retainedSourceLabel(source, objective)}` : "Retained result source is not currently verified"; })() : <>{key}: {JSON.stringify(value)}</>}</div>)}</td></tr>)}</tbody></table></div>
      <h4>Evidence references</h4><ul>{candidate.evidence_refs.map(reference => { const fact = current?.facts.facts.find(item => item.fact_id === reference); return <li key={reference}><strong>{reference}</strong>: {fact ? `${sentence(fact.kind)} / ${JSON.stringify(fact.value)}` : "Not present in current verified facts"}</li>; })}</ul>
      <div className="composition-actions"><Button aria-expanded={showGraph} onClick={() => setShowGraph(value => !value)}><GitBranch />{showGraph ? "Close graph" : "Inspect graph"}</Button><Button variant="primary" disabled={!ready} onClick={() => { if (ready) newRequest("attempt", { proposal: candidate, prior_attempt_id: prior || null }); }}><Play />Start fresh attempt within grant</Button></div>
      {!matches && !established ? <Callout title="Candidate no longer matches current evidence">Request a fresh graph after the saved state and cleanup are reconciled.</Callout> : null}
      {showGraph ? <CompositionGraph scenario={scenario} snapshot={viewSnapshot} /> : null}
    </> : null}
  </section>;
}
