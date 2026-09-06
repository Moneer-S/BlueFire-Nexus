import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, DEMO_MODE } from "../lib/api";
import { jobSettled, matchesMethodPending, methodJobId, methodProposal, methodResult, readMethodPending, settleMethodPending, storeMethodPending, type MethodDecision, type MethodPending, type MethodSource } from "../lib/method-comparison";
import { runLabel } from "../lib/run-presentation";
import { sameJson } from "../lib/replay-review";
import type { CatalogResponse, DetectionCaseRole, RunJob, RunRecord } from "../types";
import { CanonicalPlanReview } from "./CanonicalPlanReview";
import { MethodComparisonResult } from "./MethodComparisonResult";
import { Badge, Button, Callout, ErrorState, Field, LoadingState, sentence } from "./Primitives";

export function MethodComparison({ sourceId, runs, catalog }: { sourceId: string; runs: RunRecord[]; catalog: CatalogResponse }) {
  const [params, setParams] = useSearchParams(), client = useQueryClient();
  const [pending, setPending] = useState(readMethodPending);
  const jobId = params.get("method_job") ?? (pending ? methodJobId(pending.request.submission_id) : "");
  const [expanded, setExpanded] = useState(Boolean(jobId));
  const [mode, setMode] = useState("off"), [step, setStep] = useState(""), [candidateId, setCandidateId] = useState("");
  const [providerId, setProviderId] = useState(catalog.ai.active_provider ?? ""), [question, setQuestion] = useState("");
  const [caseRole, setCaseRole] = useState<DetectionCaseRole>("attack"), [reviewer, setReviewer] = useState("");
  const [localError, setLocalError] = useState<Error>();
  const [recoveryOverride, setRecoveryOverride] = useState<{ parentId: string; jobId: string }>();
  const heading = useRef<HTMLHeadingElement>(null);
  const models = (catalog.ai.providers ?? []).filter((item) => item.kind !== "deterministic");
  const context = useQuery({ queryKey: ["method-context", sourceId], queryFn: () => api.methodComparisonContext(sourceId), enabled: expanded && Boolean(sourceId) && !jobId && !DEMO_MODE, retry: false });
  const detectors = useQuery({ queryKey: ["detections"], queryFn: api.detections, enabled: expanded });
  const job = useQuery({ queryKey: ["job", jobId], queryFn: () => api.job(jobId), enabled: Boolean(jobId), retry: false,
    refetchInterval: (query) => {
      const value = query.state.data;
      if (!value || value.progress.comparison || value.progress.stopped || (value.progress.decision as MethodDecision | undefined)?.decision === "reject") return false;
      return !jobSettled(value) || (value.progress.decision as MethodDecision | undefined)?.decision === "accept" ? 1500 : false;
    } });
  const parent = job.data?.kind === "replay.ai.propose" ? job.data : undefined;
  const proposal = methodProposal(parent);
  const storedDecision = parent?.progress.decision as MethodDecision | undefined;
  const decision = proposal && storedDecision?.proposal_digest === proposal.proposal_digest ? { proposal_digest: storedDecision.proposal_digest, decision: storedDecision.decision, reviewed_by: storedDecision.reviewed_by } : undefined;
  const replayId = decision?.decision === "accept" && typeof parent?.request?.replay_submission_id === "string" ? methodJobId(parent.request.replay_submission_id) : "";
  const replay = useQuery({ queryKey: ["job", replayId], queryFn: () => api.job(replayId), enabled: Boolean(replayId), retry: false, refetchInterval: (query) => query.state.data && !jobSettled(query.state.data) ? 1000 : false });
  const recoveryId = recoveryOverride?.parentId === parent?.job_id ? recoveryOverride?.jobId ?? "" : typeof parent?.progress.comparison_recovery_job_id === "string" ? parent.progress.comparison_recovery_job_id : "";
  const recovery = useQuery({ queryKey: ["job", recoveryId], queryFn: () => api.job(recoveryId), enabled: Boolean(recoveryId), retry: false, refetchInterval: (query) => query.state.data && !jobSettled(query.state.data) ? 1000 : false });
  const replayJob = replay.data?.kind === "scenario.replay" && sameJson(replay.data.request?.method_comparison, { proposal_job_id: parent?.job_id, proposal_digest: proposal?.proposal_digest }) ? replay.data : undefined;
  const recoveryJob = recovery.data?.kind === "replay.comparison.recover" && recovery.data.request?.proposal_job_id === parent?.job_id && recovery.data.request?.replay_job_id === replayId ? recovery.data : undefined;
  const result = methodResult(parent, parent, proposal) ?? methodResult(replayJob, parent, proposal) ?? methodResult(recoveryJob, parent, proposal);
  const replaySource = (parent?.progress.replay_result as { source?: MethodSource } | undefined)?.source;
  const refetchJob = job.refetch;
  const boundDetector = detectors.data?.candidates.find((item) => item.id === proposal?.detector.candidate_id);
  const current = Boolean(proposal && sourceId === proposal.source_run.run_id && boundDetector?.digest === proposal.detector.resource_digest);
  const selectedDetector = detectors.data?.candidates.find((item) => item.id === candidateId);
  const choices = detectors.data?.candidates.filter((item) => ["sqlite", "sigma"].includes(item.document.target_language ?? "") && item.document.rule_source && item.document.state !== "rejected") ?? [];
  const steps = [...new Map((context.data?.options ?? []).map((option) => [option.step_id, option])).values()];
  const stopped = Boolean(parent?.progress.stopped);
  const activeAnalysis = Boolean(recoveryJob && !jobSettled(recoveryJob));
  const analysisTarget = recoveryJob ?? replayJob;
  const knownRun = replaySource?.run_id ?? (typeof replayJob?.result_ref === "string" ? replayJob.result_ref : undefined);
  const possibleRun = knownRun ?? (typeof replayJob?.progress.run_id === "string" ? replayJob.progress.run_id : undefined);
  const canRecover = Boolean(possibleRun && analysisTarget && jobSettled(analysisTarget) && !result && ["failed", "cancelled", "interrupted"].includes(analysisTarget.state));
  const canStartAgain = Boolean(parent && jobSettled(parent) && !pending && (result || decision?.decision === "reject" || (!decision && !proposal) || (stopped && (!replayJob || jobSettled(replayJob)) && !activeAnalysis)));
  const cacheJob = (value: RunJob) => client.setQueryData(["job", value.job_id], value);
  const viewJob = (id: string) => setParams((old) => { const next = new URLSearchParams(old); next.set("method_job", id); return next; });
  useEffect(() => { if (jobId) setExpanded(true); if (jobId && !params.get("method_job")) setParams((old) => { const next = new URLSearchParams(old); next.set("method_job", jobId); return next; }, { replace: true }); }, [jobId, params, setParams]);
  useEffect(() => { if (job.data && settleMethodPending(job.data)) setPending(undefined); }, [job.data]);
  useEffect(() => { setReviewer(""); }, [jobId]);
  useEffect(() => { if (proposal?.proposal_digest) heading.current?.focus(); }, [proposal?.proposal_digest]);
  useEffect(() => { setStep(""); }, [sourceId]);
  useEffect(() => { if (result && !replaySource) void refetchJob(); }, [result, replaySource, refetchJob]);
  const submit = useMutation({ mutationFn: async (saved: MethodPending) => { const response = await api.suggestMethodComparison(saved.sourceId, saved.request); if (!matchesMethodPending(response.job, saved)) throw new Error("The response does not match the saved request. Keep this request and check its status."); return response.job; }, onSuccess: (value) => { cacheJob(value); if (settleMethodPending(value)) setPending(undefined); } });
  const review = useMutation({ mutationFn: async ({ id, body }: { id: string; body: MethodDecision }) => {
    const response = await api.decideMethodComparison(id, body);
    if (response.proposal_job.job_id !== id || response.proposal_job.kind !== "replay.ai.propose" || response.decision.proposal_digest !== body.proposal_digest || response.decision.decision !== body.decision) throw new Error("The decision response did not match. Check the saved operation before continuing.");
    return response;
  }, onSuccess: (response) => { cacheJob(response.proposal_job); if (response.replay_job) cacheJob(response.replay_job); }, onSettled: (_data, _error, input) => { void client.invalidateQueries({ queryKey: ["job", input.id] }); } });
  const cancel = useMutation({ mutationFn: (id: string) => api.controlJob(id, "cancel"), onSuccess: (value) => { cacheJob(value); void client.invalidateQueries({ queryKey: ["job"] }); } });
  const recover = useMutation({ mutationFn: async ({ source, parentId, childId }: { source: RunJob; parentId: string; childId: string }) => {
    const response = await api.retryJob(source.job_id);
    if (response.job.kind !== "replay.comparison.recover" || response.job.request?.proposal_job_id !== parentId || response.job.request?.replay_job_id !== childId || response.job.request?.retry_of_job_id !== source.job_id) throw new Error("The response was not the requested comparison-only recovery. Check saved work before retrying.");
    return response.job;
  }, onSuccess: (value, input) => { cacheJob(value); setRecoveryOverride({ parentId: input.parentId, jobId: value.job_id }); void client.invalidateQueries({ queryKey: ["job", input.parentId] }); } });
  const start = () => {
    if (!context.data || context.data.source_run.run_id !== sourceId || !selectedDetector || !["assist", "auto"].includes(mode) || pending) return;
    const saved: MethodPending = { sourceId, request: { submission_id: crypto.randomUUID(), source_binding_digest: context.data.source_binding_digest, selected_step_id: step, candidate_id: selectedDetector.id, candidate_resource_digest: selectedDetector.digest, question: question.trim(), source_case_role: caseRole, provider_id: providerId, autonomy: mode as "assist" | "auto" } };
    if (!storeMethodPending(saved)) { setLocalError(new Error("The original request could not be retained. Enable browser session storage before starting this operation.")); return; }
    setLocalError(undefined); setPending(saved); viewJob(methodJobId(saved.request.submission_id)); submit.mutate(saved);
  };
  const ready = !DEMO_MODE && context.data?.schema_version === "bluefire.method-comparison-context.v1" && context.data.source_run.run_id === sourceId && steps.some((item) => item.step_id === step) && selectedDetector && models.some((item) => item.provider_id === providerId) && ["assist", "auto"].includes(mode) && question.trim() && !/[\r\n]/.test(question) && !pending;
  const errorText = (value: RunJob | undefined) => (value?.progress.operation_error as { message?: string } | undefined)?.message ?? value?.error?.message;
  const boundLink = proposal ? `/compare?source=${encodeURIComponent(proposal.source_run.run_id)}&method_job=${encodeURIComponent(jobId)}` : undefined;
  return <section className="method-comparison" aria-label="Guided method comparison">
    <header><div><h2>Test a different method</h2><p>Ask AI to choose a registered alternative, then replay and evaluate the same saved rule on both runs.</p></div><Button aria-expanded={expanded} onClick={() => setExpanded(!expanded)}>{expanded ? "Hide method test" : jobId ? "Resume method test" : "Set up method test"}</Button></header>
    {expanded ? <div className="method-comparison-body">
      {pending && jobId !== methodJobId(pending.request.submission_id) ? <Callout title="An earlier request needs confirmation"><Button onClick={() => viewJob(methodJobId(pending.request.submission_id))}>Resume original method request</Button></Callout> : null}
      {!jobId ? <>
        <div className="config-grid"><Field label="Method test source run"><select value={sourceId} onChange={(event) => { const value = event.target.value; setParams((old) => { const next = new URLSearchParams(old); if (value) next.set("source", value); else next.delete("source"); return next; }); }}><option value="">Choose an observed run</option>{runs.map((run) => <option key={run.run_id} value={run.run_id}>{runLabel(run)} · {sentence(run.mode)} · {run.created_at ? new Date(run.created_at).toLocaleString() : run.run_id}</option>)}</select></Field><Field label="Method AI mode"><select value={mode} onChange={(event) => setMode(event.target.value)}><option value="off">Off · no model requests</option><option value="assist">Assist · review the proposed method</option><option value="auto">Auto · apply an allowed method</option></select></Field></div>
        <p>Every test repeats the full experiment in its original scope with runtime AI off. Execute always stops for a fresh approval. Both runs are evaluated with one unchanged rule.</p>
        {DEMO_MODE ? <Callout title="Connect a local workspace">A method test needs a saved run with independent observations.</Callout> : sourceId && context.isPending ? <LoadingState label="Finding compatible methods" /> : context.isError ? <ErrorState title="Method test unavailable" error={context.error} retry={() => { void context.refetch(); }} /> : null}
        {context.data && !steps.length ? <Callout title="No compatible alternative">This run has no registered method swap that preserves its original scope, profile and observers.</Callout> : null}
        <div className="config-grid"><Field label="Step to vary"><select value={step} onChange={(event) => setStep(event.target.value)}><option value="">Choose a compatible step</option>{steps.map((item) => <option key={item.step_id} value={item.step_id}>{item.title_from} · {item.step_id}</option>)}</select></Field><Field label="Saved rule to evaluate"><select value={candidateId} onChange={(event) => setCandidateId(event.target.value)}><option value="">Choose a SQLite or Sigma rule</option>{choices.map((item) => <option key={item.id} value={item.id}>{item.document.title} · Revision {item.document.revision ?? 1}</option>)}</select></Field><Field label="Method model provider"><select value={providerId} onChange={(event) => setProviderId(event.target.value)}><option value="">Choose a configured model</option>{models.map((item) => <option key={item.provider_id} value={item.provider_id}>{item.provider_id} · {item.model}</option>)}</select></Field><Field label="Original case context"><select value={caseRole} onChange={(event) => setCaseRole(event.target.value as DetectionCaseRole)}><option value="attack">Attack case</option><option value="benign">Benign activity</option><option value="replay">Replay</option><option value="heldout">Previously withheld · becomes development input</option></select></Field></div>
        {detectors.isError ? <ErrorState title="Saved rules unavailable" error={detectors.error} retry={() => { void detectors.refetch(); }} /> : null}
        {!choices.length && detectors.isSuccess ? <p><Link to={`/detection-lab?run=${encodeURIComponent(sourceId)}`}>Save and validate a rule in Detection Lab</Link> before comparing its results.</p> : null}
        <Field label="Question for this method test"><input maxLength={1000} value={question} onChange={(event) => setQuestion(event.target.value)} placeholder="Does this rule detect the same behavior through another collection method?" /></Field>
        <Button variant="primary" disabled={!ready || submit.isPending} onClick={start}>{mode === "auto" ? "Start bounded method test" : "Propose method test"}</Button>
      </> : <>
        {pending && !parent ? <Callout title="Keep the original request"><p>The response is not confirmed. Retry this exact request or check its saved status before starting another.</p><Button disabled={submit.isPending} onClick={() => submit.mutate(pending)}>Retry original method request</Button><Button onClick={() => { void job.refetch(); }}>Check method request status</Button></Callout> : null}
        {job.isPending ? <LoadingState label="Finding your method test" /> : job.isError ? <ErrorState title="Method test unavailable" error={job.error} retry={() => { void job.refetch(); }} /> : job.data && !parent ? <Callout title="Different operation">This job is not a guided method comparison.</Callout> : null}
        {parent ? <>
          <p role="status">{result ? "Method test completed" : activeAnalysis ? "Evaluating the retained runs" : stopped ? "Method test stopped" : decision?.decision === "reject" ? "Proposed method rejected" : replayJob?.state === "awaiting_approval" ? "Replay ready for fresh approval" : decision?.decision === "accept" ? `Replay and comparison: ${replayJob ? sentence(replayJob.state) : "finding saved work"}` : proposal ? "Proposed method ready for review" : sentence(parent.state)}</p>
          {!result && decision?.decision !== "reject" && (!stopped || activeAnalysis) ? <Button disabled={cancel.isPending} onClick={() => cancel.mutate(parent.job_id)}>Stop method test</Button> : null}
          {errorText(parent) ? <Callout tone="warning" title="Method test needs attention">{errorText(parent)}</Callout> : null}
          {proposal ? <>
            <h3 ref={heading} tabIndex={-1}>Review the method change</h3><p>{proposal.reason}</p>
            <div className="method-change"><div><span>Original method</span><strong>{proposal.option.title_from}</strong></div><span aria-hidden="true">→</span><div><span>Proposed method</span><strong>{proposal.option.title}</strong></div></div>
            <ol className="method-sequence"><li>Replay the full experiment with this method.</li><li>Evaluate the same saved rule on the original and replay observations.</li><li>Save the comparison and both evaluation records.</li></ol>
            <p><Badge>{sentence(proposal.source_run.mode)}</Badge> {proposal.profile.id ?? "Original profile"} · {proposal.scope.scope_refs?.join(", ") || "No effect scope in Simulate"}. Runtime AI: {proposal.changes.runtime_autonomy.from === "off" ? "remains off" : `${sentence(proposal.changes.runtime_autonomy.from)} → Off`}.</p>
            <p>Rule: {boundDetector?.document.title ?? proposal.detector.candidate_id}. Method proposed by {proposal.provider.model} · {proposal.provider.provider_id}.</p>
            <ul>{[...proposal.limitations, ...proposal.comparison_limitations].map((item, index) => <li key={index}>{item}</li>)}</ul>
            {!current && !result ? <Callout title="Review context changed"><p>The selected source or saved rule differs from this proposal. Its original binding is retained.</p>{boundLink ? <Link className="button button-secondary button-medium" to={boundLink}>Open the bound source and method test</Link> : null}</Callout> : null}
            <details><summary>Full replay plan, effects and identities</summary>{proposal.replay_preparation.preflight.plan ? <CanonicalPlanReview plan={proposal.replay_preparation.preflight.plan} scope={proposal.replay_preparation.preflight.scope} cleanup={proposal.replay_preparation.preflight.cleanup} binding={proposal.replay_preparation.preflight.approval_binding} envelope={proposal.replay_preparation.preflight.approval_envelope} /> : null}<pre>{JSON.stringify({ proposal_job_id: parent.job_id, proposal }, null, 2)}</pre></details>
            {!decision && !stopped ? <><Field label="Method reviewed by"><input value={reviewer} maxLength={200} autoComplete="off" onChange={(event) => setReviewer(event.target.value)} /></Field><div className="candidate-actions"><Button variant="primary" disabled={!current || !reviewer.trim() || review.isPending} onClick={() => review.mutate({ id: parent.job_id, body: { proposal_digest: proposal.proposal_digest, decision: "accept", reviewed_by: reviewer.trim() } })}>{proposal.source_run.mode === "execute" ? "Accept method and prepare approval" : "Accept method and replay"}</Button><Button disabled={!reviewer.trim() || review.isPending} onClick={() => review.mutate({ id: parent.job_id, body: { proposal_digest: proposal.proposal_digest, decision: "reject", reviewed_by: reviewer.trim() } })}>Reject method</Button></div></> : null}
            {decision?.decision === "accept" && !result ? <>
              {replayJob ? <Link className="button button-primary button-medium" to={`/runs?job=${encodeURIComponent(replayJob.job_id)}`}>{replayJob.state === "awaiting_approval" ? "Review and approve this replay" : "Open saved replay job"}</Link> : <Callout title="Accepted method needs recovery"><p>Find or publish the same reserved replay request. Execute still needs its own approval.</p><Button disabled={review.isPending || stopped} onClick={() => review.mutate({ id: parent.job_id, body: decision })}>Recover accepted method</Button></Callout>}
              {replay.isError ? <ErrorState title="Replay status unavailable" error={replay.error} retry={() => { void replay.refetch(); }} /> : null}
              {errorText(analysisTarget) ? <Callout tone="warning" title="Comparison incomplete">{errorText(analysisTarget)}</Callout> : null}
              {knownRun ? <p>The finalized replay is retained. <Link to={`/runs/${encodeURIComponent(knownRun)}`}>Inspect its observations and cleanup</Link>.</p> : null}
              {!knownRun && canRecover ? <p>This job recorded a run handle. Recovery must first verify that its finalization and cleanup are complete.</p> : null}
              {canRecover && analysisTarget ? <Button disabled={recover.isPending} onClick={() => recover.mutate({ source: analysisTarget, parentId: parent.job_id, childId: replayId })}>Recover comparison only</Button> : null}
              {canRecover ? <p>Recovery evaluates the existing runs. It cannot run the experiment again.</p> : null}
              {recovery.isError ? <ErrorState title="Comparison recovery status unavailable" error={recovery.error} retry={() => { void recovery.refetch(); }} /> : null}
            </> : null}
            {result ? replaySource?.run_id === result.child_run_id ? <MethodComparisonResult receipt={result} proposal={proposal} replaySource={replaySource} /> : <LoadingState label="Verifying the saved replay evidence binding" /> : null}
          </> : null}
          {canStartAgain ? <Button onClick={() => { setParams((old) => { const next = new URLSearchParams(old); next.delete("method_job"); return next; }); submit.reset(); review.reset(); cancel.reset(); recover.reset(); setLocalError(undefined); }}>Set up another method test</Button> : null}
        </> : null}
      </>}
      {localError ? <ErrorState title="Request not sent" error={localError} /> : null}
      {submit.isError ? <ErrorState title="Method request not confirmed" error={submit.error} /> : null}
      {review.isError ? <ErrorState title="Method decision not confirmed" error={review.error} /> : null}
      {cancel.isError ? <ErrorState title="Stop not confirmed" error={cancel.error} /> : null}
      {recover.isError ? <ErrorState title="Comparison recovery not confirmed" error={recover.error} /> : null}
    </div> : null}
  </section>;
}
