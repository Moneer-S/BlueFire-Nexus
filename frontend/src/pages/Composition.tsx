import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Ban, ChevronDown, ChevronUp, GitBranch, Pause, Play, RefreshCw, Sparkles, X } from "lucide-react";
import { api } from "../lib/api";
import { checkedCompositionContext, checkedCompositionList, checkedCompositionObjective, checkedCompositionProposal, clearCompositionPending, compositionApi, compositionConfirmed, compositionJobId, compositionJobValid, compositionRecord, readCompositionPending, storeCompositionPending, type CompositionObjective, type CompositionPending, type CompositionProposal } from "../lib/composition";
import { Badge, Button, Callout, DataList, ErrorState, Field, IconButton, LoadingState, PageHeader, sentence } from "../components/Primitives";
import { CompositionCapabilities, CompositionSetup } from "../components/CompositionReview";
import { CompositionAttempts } from "../components/CompositionAttempts";
import { CompositionGraph } from "../components/CompositionGraph";
import "./Composition.css";
import { clearCompositionControl, compositionControlConfirmed, readCompositionControls, readCompositionProposals, rememberCompositionProposal, storeCompositionControl, type CompositionControl } from "../lib/composition";
import { clearCompositionCancellation, compositionCanRevise, compositionCancellationConfirmed, compositionEstablished, readCompositionCancellations, storeCompositionCancellation } from "../lib/composition";
import type { CompositionObjectiveState, CompositionReviewRequest } from "../lib/composition";

export function CompositionPage() {
  const [params, setParams] = useSearchParams();
  const client = useQueryClient();
  const [restored] = useState(() => { try { return { pending: readCompositionPending(), controls: readCompositionControls(), proposals: readCompositionProposals(), cancellations: readCompositionCancellations(), error: undefined }; } catch (error) { return { pending: undefined, controls: {}, proposals: {}, cancellations: {}, error }; } });
  const [pending, setPending] = useState(restored.pending);
  const [pendingControls, setPendingControls] = useState<Record<string, CompositionControl>>(restored.controls);
  const [recentProposals, setRecentProposals] = useState<Record<string, string>>(restored.proposals);
  const [cancellations, setCancellations] = useState<Record<string, string>>(restored.cancellations);
  const [localError, setLocalError] = useState<unknown>(restored.error);
  const [reviewSeed, setReviewSeed] = useState<CompositionReviewRequest>();
  const [expandedObjective, setExpandedObjective] = useState("");
  const locked = useRef(false);
  const stoppedOwners = useRef(new Set<string>());
  const id = params.get("objective") ?? pending?.owner ?? "";
  const stopped = Boolean(pendingControls[id]) || stoppedOwners.current.has(id);
  const control = params.get("control") ?? pending?.control ?? "";
  const proposalId = cancellations[id] ?? params.get("proposal") ?? (pending?.kind === "proposal" && pending.owner === id ? pending.id : "");
  const navigate = (owner: string, proposal = "") => setParams(next => { const value = new URLSearchParams(next); value.set("control", control); if (owner) value.set("objective", owner); else value.delete("objective"); if (proposal) value.set("proposal", proposal); else value.delete("proposal"); return value; });
  const list = useQuery({ queryKey: ["composition-list", control], queryFn: async () => checkedCompositionList(await compositionApi.list(control)), enabled: compositionJobValid(control), retry: false });
  const write = useMutation({ mutationFn: async (operation: CompositionPending) => {
    storeCompositionPending(operation);
    await client.cancelQueries({ queryKey: ["composition-objective", operation.owner], exact: true });
    const value = await compositionApi.submit(operation);
    return operation.kind === "proposal" ? checkedCompositionProposal(value as CompositionProposal, operation.id, operation.owner) : checkedCompositionObjective(value as CompositionObjectiveState, operation.owner, operation.control);
  }, onSuccess: (value, operation) => {
    if ("owner" in value && !stoppedOwners.current.has(operation.owner)) client.setQueryData(["composition-objective", operation.owner], value);
    else if ("owner" in value) void client.invalidateQueries({ queryKey: ["composition-objective", operation.owner] });
    else client.setQueryData(["composition-proposal", operation.id], value);
    void client.invalidateQueries({ queryKey: ["composition-list", operation.control] });
  }, onSettled: () => { locked.current = false; } });
  const objective = useQuery({ queryKey: ["composition-objective", id], queryFn: async () => checkedCompositionObjective(await compositionApi.objective(id), id, control || undefined), enabled: compositionJobValid(id) && !write.isPending, retry: false, refetchInterval: state => state.state.data?.grant && !["revoked", "expired"].includes(state.state.data.grant.status) ? 1500 : false });
  const proposal = useQuery({ queryKey: ["composition-proposal", proposalId], queryFn: async () => checkedCompositionProposal(await compositionApi.proposal(proposalId), proposalId, id), enabled: compositionJobValid(proposalId) && compositionJobValid(id) && !write.isPending, retry: false, refetchInterval: state => state.state.data && ["pending", "requesting"].includes(state.state.data.provider_outcome) ? 1200 : false });
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
  const send = (operation: CompositionPending) => {
    if (pending || locked.current || localError || (stoppedOwners.current.has(operation.owner) && operation.kind !== "grant")) return;
    locked.current = true; setPending(operation); setLocalError(undefined); navigate(operation.owner, operation.kind === "proposal" ? operation.id : ""); write.mutate(operation);
  };
  const safety = useMutation({ mutationFn: async ({ owner, control: retainedControl, operation }: { owner: string; control: string; operation: CompositionControl }) => {
    storeCompositionControl(owner, operation); setPendingControls(readCompositionControls());
    if (operation !== "continue") stoppedOwners.current.add(owner);
    await client.cancelQueries({ queryKey: ["composition-context", owner] });
    await client.cancelQueries({ queryKey: ["composition-objective", owner], exact: true });
    return checkedCompositionObjective(await compositionApi.control(owner, operation), owner, retainedControl || undefined);
  }, onSuccess: (value, target) => { client.setQueryData(["composition-objective", target.owner], value); if (target.operation === "continue") stoppedOwners.current.delete(target.owner); void client.invalidateQueries({ queryKey: ["composition-list", target.control] }); void client.invalidateQueries({ queryKey: ["composition-context", target.owner], refetchType: "none" }); void client.invalidateQueries({ queryKey: ["composition-proposal"] }); } });
  const controlObjective = (operation: CompositionControl) => safety.mutate({ owner: id, control, operation });
  const cancel = useMutation({ mutationFn: async ({ owner, job }: { owner: string; job: string }) => {
    storeCompositionCancellation(owner, job); setCancellations(readCompositionCancellations());
    await client.cancelQueries({ queryKey: ["composition-proposal", job], exact: true });
    return checkedCompositionProposal(await compositionApi.cancel(job), job, owner);
  }, onSuccess: value => client.setQueryData(["composition-proposal", value.job.job_id], value) });
  const envelope = objective.data?.grant ? objective.data : undefined;
  const refusal = objective.data?.grant === null ? objective.data : undefined;
  return <div className={`page composition-page${expandedObjective === id && id ? " composition-objective-expanded" : ""}`}>
    <Link to={compositionJobValid(control) ? `/compare?receiver_job=${encodeURIComponent(control)}` : "/compare"}>Retained receiver control</Link>
    <PageHeader title={envelope?.grant.document.objective.question ?? "Composition workspace"} actions={compositionJobValid(id) && !refusal ? <div className="composition-actions">{envelope ? <IconButton label={expandedObjective === id ? "Collapse objective question" : "Show full objective question"} aria-expanded={expandedObjective === id} onClick={() => setExpandedObjective(expandedObjective === id ? "" : id)}>{expandedObjective === id ? <ChevronUp /> : <ChevronDown />}</IconButton> : null}<Button variant="danger" disabled={safety.isPending} onClick={() => controlObjective("stop")}><Pause />Stop</Button><Button variant="danger" disabled={safety.isPending} onClick={() => controlObjective("revoke")}><Ban />Revoke</Button></div> : undefined} />
    {localError ? <ErrorState title="Saved request needs attention" error={localError} /> : null}
    {!compositionJobValid(control) ? <Callout title="Select the original retained control">Open a completed retained receiver control to review its available composition capabilities.</Callout> : <>
      <section className="composition-section" aria-label="Saved objectives"><div className="composition-heading"><h2>Saved objectives</h2><Button size="small" disabled={list.isFetching} onClick={() => { void list.refetch(); }}><RefreshCw />Refresh</Button></div>
        {list.error ? <ErrorState error={list.error} /> : list.isPending ? <LoadingState label="Opening saved objectives" /> : <div className="composition-objective-list">{list.data?.objectives.map(item => <Link aria-label={`Open objective: ${item.title}, ${sentence(item.status)}`} aria-current={item.owner_id === id ? "page" : undefined} key={item.owner_id} to={`/composition?${new URLSearchParams({ control, objective: item.owner_id, ...(recentProposals[item.owner_id] ? { proposal: recentProposals[item.owner_id]! } : {}) })}`}><strong>{item.title}</strong><span>{sentence(item.status)}</span></Link>)}{!list.data?.objectives.length ? <p>No saved objectives for this control.</p> : null}</div>}
        {id ? <Button disabled={Boolean(pending) || write.isPending} onClick={() => { setReviewSeed(undefined); navigate(""); }}>New objective</Button> : null}
      </section>
      {pending ? <Callout title={write.isPending ? "Saving exact request" : "Request confirmation pending"}>
        <p>{pending.kind === "attempt" ? "An attempt may already be running. Reconcile its saved identity before starting any other work." : "The exact submission is retained across reloads. No automatic effect retry is performed."}</p>
        <code>{pending.id}</code>
        {pending.owner !== id ? <Link to={`/composition?${new URLSearchParams({ control: pending.control, objective: pending.owner, ...(pending.kind === "proposal" ? { proposal: pending.id } : {}) })}`}>Open the pending objective</Link> : <div className="composition-actions"><Button disabled={write.isPending} onClick={() => { void objective.refetch(); if (pending.kind === "proposal") void proposal.refetch(); }}>Check saved status</Button><Button disabled={write.isPending || stopped || safety.isPending} onClick={() => { if (!locked.current) { locked.current = true; write.mutate(pending); } }}>Retry exact submission</Button>{envelope && ["paused", "revoked", "expired"].includes(envelope.grant.status) ? <Button disabled={write.isPending} onClick={() => { try { clearCompositionPending(pending); setPending(undefined); } catch (error) { setLocalError(error); } }}>Close request after confirmed stop</Button> : null}</div>}
      </Callout> : null}
      {write.error ? <ErrorState title="Submission not confirmed" error={write.error} /> : null}
      {safety.error ? <ErrorState title="Control request not confirmed" error={safety.error} /> : null}
      {pendingControls[id] ? <Callout title={`${sentence(pendingControls[id]!)} confirmation pending`}><p>New work remains disabled until this exact control request is reconciled.</p><div className="composition-actions"><Button disabled={safety.isPending} onClick={() => controlObjective(pendingControls[id]!)}>Retry exact control request</Button><Button onClick={() => { void objective.refetch(); }}>Check control state</Button></div></Callout> : null}
      {!id ? <CompositionSetup control={control} disabled={Boolean(pending) || Boolean(localError)} onSubmit={send} initialRequest={reviewSeed} /> : <>
        {!compositionJobValid(id) ? <ErrorState error={new Error("This objective link is incomplete.")} /> : objective.error ? <ErrorState title="Current objective unavailable" error={objective.error} retry={() => { void objective.refetch(); }} /> : !envelope && !refusal ? <LoadingState label="Opening objective" /> : null}
        {refusal ? <Callout title="Delegation refused"><p>{String(compositionRecord(compositionRecord(refusal.owner.progress.admission).problem).message)}</p><p>No capability grant or execution authority was issued.</p><Button disabled={Boolean(pending) || Boolean(localError)} onClick={() => { setReviewSeed(compositionRecord(refusal.owner.progress.submitted_request).review as CompositionReviewRequest); navigate(""); }}><RefreshCw />Review again</Button></Callout> : null}
        {envelope ? <>
          <section className="composition-section" aria-label="Grant status"><div className="composition-heading"><h2>Capability grant</h2><Badge tone={envelope.grant.status === "active" ? "info" : "warning"}>{sentence(envelope.grant.status)}</Badge></div><DataList items={[{ label: "Expires", value: new Date(envelope.grant.document.expires_at_ms).toLocaleString() }, { label: "Reviewed by", value: envelope.grant.document.approved_by }, { label: "Cleanup state", value: typeof envelope.grant.cleanup_state === "string" ? sentence(envelope.grant.cleanup_state) : JSON.stringify(envelope.grant.cleanup_state) }]} />
            <h3>Cumulative reservations</h3><dl className="composition-limits">{Object.entries(envelope.grant.usage).map(([key, value]) => <div key={key}><dt>{key === "retained_metadata_bytes" ? "Metadata estimate charged" : sentence(key)}</dt><dd>{value.toLocaleString()} / {envelope.grant.document.limits[`max_${key}`]?.toLocaleString() ?? "not reported"}</dd></div>)}</dl>
            <details><summary>Reviewed capabilities and cumulative limits</summary><CompositionCapabilities review={envelope.grant.document} /></details>
            {envelope.grant.status === "paused" ? <><p>Continue preserves spent budgets and the original expiry. It does not replay an interrupted attempt.</p><Button disabled={safety.isPending || Boolean(pending) || Boolean(pendingControls[id]) || Boolean(objective.error)} onClick={() => controlObjective("continue")}><Play />Continue objective</Button></> : null}
          </section>
          <CompositionAttempts objective={envelope} />
          <CompositionPlanning key={id} objective={envelope} proposal={proposal.data} proposalId={proposalId} pending={Boolean(pending)} disabled={Boolean(objective.error) || Boolean(proposal.error) || proposal.isFetching || cancel.isPending || Boolean(cancellations[id]) || stopped || safety.isPending || write.isPending || Boolean(localError)} onSubmit={send} onProposal={(next) => navigate(id, next)} />
        </> : null}
        {proposal.error ? <ErrorState title="Proposal status unavailable" error={proposal.error} retry={() => { void proposal.refetch(); }} /> : null}
        {cancellations[id] ? <Callout title="Proposal cancellation pending">New dispatch remains disabled until the saved proposal is confirmed stopped.</Callout> : null}
        {compositionJobValid(proposalId) ? <Button disabled={cancel.isPending} onClick={() => cancel.mutate({ owner: id, job: proposalId })}><X />{cancellations[id] ? "Retry exact proposal cancellation" : "Cancel proposal"}</Button> : null}
        {cancel.error ? <ErrorState title="Proposal stop not confirmed" error={cancel.error} /> : null}
      </>}
    </>}
  </div>;
}

function CompositionPlanning({ objective, proposal, proposalId, pending, disabled, onSubmit, onProposal }: { objective: CompositionObjective; proposal?: CompositionProposal; proposalId: string; pending: boolean; disabled: boolean; onSubmit: (value: CompositionPending) => void; onProposal: (id: string) => void }) {
  const [prior, setPrior] = useState("");
  const [provider, setProvider] = useState("");
  const [useInitial, setUseInitial] = useState(false);
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
  const proposing = Boolean(proposal && ["pending", "requesting"].includes(proposal.provider_outcome));
  const active = !established && objective.grant.status === "active" && grant.expires_at_ms > now && !disabled && !pending && !proposing;
  const priorValid = !objective.attempts.length ? prior === "" : objective.attempts.some(item => item.request.composition_attempt.attempt_id === prior && compositionCanRevise(item, objective));
  const context = useQuery({ queryKey: ["composition-context", owner, prior, objective.attempts.map(item => `${item.job_id}:${item.state}:${item.progress.settlement}`).join("|")], queryFn: async () => checkedCompositionContext(await compositionApi.context(owner, prior || null), grant.grant_id), enabled: active && priorValid, retry: false });
  const catalog = useQuery({ queryKey: ["catalog"], queryFn: api.catalog, retry: false });
  const providers = (catalog.data?.ai.providers ?? []).filter(item => item.kind !== "deterministic");
  const current = context.data;
  const viewSnapshot = current?.snapshot ?? grant.snapshot;
  const candidate = useInitial ? current?.initial_proposal : proposal?.proposal?.candidate;
  const scenario = useInitial ? current?.initial_scenario : proposal?.proposal?.scenario;
  const matches = Boolean(current && (useInitial ? !objective.attempts.length && candidate : proposal?.candidate_ready && proposal.proposal?.context_digest === current.context_digest && proposal.proposal.prior_attempt_id === (prior || null)));
  const ready = active && priorValid && !context.isFetching && !context.error && matches && candidate && scenario;
  const newRequest = (kind: "proposal" | "attempt", body: Record<string, unknown>) => { const submission_id = crypto.randomUUID(); onSubmit({ kind, owner, control: grant.environment.control_owner_id, id: compositionJobId(submission_id), body: { submission_id, ...body } }); };
  return <section className="composition-section" aria-label="Graph planning"><h2>{objective.attempts.length ? "Evidence-driven revision" : "Initial graph"}</h2>
    {objective.attempts.length ? <Field label="Verified prior attempt"><select value={prior} disabled={pending} onChange={event => { setPrior(event.target.value); setUseInitial(false); onProposal(""); }}><option value="">Select settled refusal evidence</option>{objective.attempts.map((item, index) => <option key={item.job_id} value={item.request.composition_attempt.attempt_id} disabled={!compositionCanRevise(item, objective)}>Attempt {index + 1}: {String(compositionRecord(compositionRecord(item.progress.verified_result).objective).established === true ? "established" : item.state)}{item.progress.settlement !== "settled" ? " / cleanup pending" : ""}</option>)}</select></Field> : null}
    {established ? <Callout title="Objective established">A settled verified attempt meets every reviewed success condition. No new graph or attempt is available for this objective.</Callout> : !active ? <Callout title="New dispatch unavailable">{grant.expires_at_ms <= now ? "The original grant has expired." : proposing ? "The selected provider request is still active. Its saved result or confirmed cancellation remains pending." : "A current active grant, reconciled submissions and verified cleanup are required."}</Callout> : null}
    {active && priorValid ? context.isFetching ? <LoadingState label="Verifying current facts and capabilities" /> : context.error ? <ErrorState error={context.error} retry={() => { void context.refetch(); }} /> : null : null}
    <div className="composition-provider"><Field label="Configured model provider"><select value={provider} disabled={!active} onChange={event => setProvider(event.target.value)}><option value="">Select a provider</option>{providers.map(item => <option value={item.provider_id} key={item.provider_id}>{item.model} / {item.provider_id}</option>)}</select></Field><Link to="/settings#model-connection">Provider and model usage authorization</Link></div>
    {catalog.error ? <ErrorState error={catalog.error} /> : null}
    <div className="composition-actions"><Button disabled={!active || !priorValid || !current || context.isFetching || Boolean(context.error) || !providers.some(item => item.provider_id === provider)} onClick={() => { setUseInitial(false); newRequest("proposal", { provider_id: provider, context_digest: current!.context_digest, prior_attempt_id: prior || null }); }}><Sparkles />{objective.attempts.length ? "Request evidence-based revision" : "Request AI graph"}</Button>{!objective.attempts.length && current?.initial_proposal ? <Button disabled={!active} aria-pressed={useInitial} onClick={() => { setUseInitial(true); onProposal(""); }}>Review established graph</Button> : null}</div>
    <p>Only the selected provider is used, with no fallback. Model usage and data authorization are separate from execution authority.</p>
    {proposalId && proposal ? <Callout title={`Proposal: ${sentence(proposal.provider_outcome)}`}>{String(proposal.job.progress.operation_error ?? (proposal.candidate_ready ? "The candidate passed current compiler checks." : "No currently admissible candidate is available."))}</Callout> : null}
    {candidate && scenario ? <>
      <h3>{candidate.title}</h3><p>{candidate.rationale}</p>
      <div className="composition-table" role="region" aria-label="Proposed graph steps" tabIndex={0}><table><thead><tr><th>Step</th><th>Method</th><th>Parameters</th></tr></thead><tbody>{candidate.steps.map(step => <tr key={step.id}><th scope="row">{step.id}</th><td>{viewSnapshot.methods.find(item => item.behavior_id === step.behavior_id)?.behavior.title ?? step.behavior_id}</td><td>{Object.entries(step.parameters).map(([key, value]) => <div key={key}>{key}: {JSON.stringify(value)}</div>)}</td></tr>)}</tbody></table></div>
      <h4>Evidence references</h4><ul>{candidate.evidence_refs.map(reference => { const fact = current?.facts.facts.find(item => item.fact_id === reference); return <li key={reference}><strong>{reference}</strong>: {fact ? `${sentence(fact.kind)} / ${JSON.stringify(fact.value)}` : "Not present in current verified facts"}</li>; })}</ul>
      <div className="composition-actions"><Button aria-expanded={showGraph} onClick={() => setShowGraph(value => !value)}><GitBranch />{showGraph ? "Close graph" : "Inspect graph"}</Button><Button variant="primary" disabled={!ready} onClick={() => { if (ready) newRequest("attempt", { proposal: candidate, prior_attempt_id: prior || null }); }}><Play />Start fresh attempt within grant</Button></div>
      {!matches && !established ? <Callout title="Candidate no longer matches current evidence">Request a fresh graph after the saved state and cleanup are reconciled.</Callout> : null}
      {showGraph ? <CompositionGraph scenario={scenario} snapshot={viewSnapshot} /> : null}
    </> : null}
  </section>;
}
