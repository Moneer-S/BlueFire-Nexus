import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api } from "../lib/api";
import { detectionApplication, detectionJobActive, detectionJobId, detectionProposal, matchesDetectionAIReceipt, matchesDetectionRetry, proposalIsCurrent, readDetectionAIReceipt, settleDetectionAIReceipt, storeDetectionAIReceipt, type DetectionAIDecision, type DetectionAIReceipt } from "../lib/detection-ai";
import { sourceObservedRecords } from "../lib/run-handoffs";
import type { CatalogResponse, DetectionCaseRole, DetectionResource, RunJob, RunRecord } from "../types";
import { Button, Callout, ErrorState, Field, LoadingState, sentence } from "./Primitives";

export function DetectionAIRevision({ resource, sourceRun, providers, defaultProvider, manualEdits }: {
  resource?: DetectionResource;
  sourceRun?: RunRecord;
  providers: NonNullable<CatalogResponse["ai"]["providers"]>;
  defaultProvider?: string;
  manualEdits: boolean;
}) {
  const client = useQueryClient();
  const [params, setParams] = useSearchParams();
  const [receipt, setReceipt] = useState(readDetectionAIReceipt);
  const jobId = params.get("ai_job") ?? (receipt ? detectionJobId(receipt.request.submission_id) : "");
  const [expanded, setExpanded] = useState(Boolean(jobId));
  const [autonomy, setAutonomy] = useState("off");
  const [provider, setProvider] = useState(defaultProvider ?? "");
  const [question, setQuestion] = useState("");
  const [role, setRole] = useState<DetectionCaseRole>("attack");
  const [reviewer, setReviewer] = useState("");
  const [error, setError] = useState<Error>();
  const [applicationOverride, setApplicationOverride] = useState<{ proposalId: string; jobId: string }>();
  const heading = useRef<HTMLHeadingElement>(null);
  const currentContext = useRef("");
  currentContext.current = JSON.stringify([jobId, resource?.id, sourceRun?.run_id]);
  const models = providers.filter((item) => item.kind !== "deterministic");
  const sourceCount = sourceObservedRecords(sourceRun).length;
  const job = useQuery({ queryKey: ["job", jobId], queryFn: () => api.job(jobId), enabled: Boolean(jobId), retry: false,
    refetchInterval: (query) => query.state.data && detectionJobActive(query.state.data) ? 1000 : false });
  const proposalJob = job.data?.kind === "detection.ai.propose" ? job.data : undefined;
  const proposal = detectionProposal(proposalJob);
  const retainedDecision = proposalJob?.progress.decision as DetectionAIDecision | undefined;
  const decision = retainedDecision ? { proposal_digest: retainedDecision.proposal_digest, parent_resource_digest: retainedDecision.parent_resource_digest, decision: retainedDecision.decision, reviewed_by: retainedDecision.reviewed_by } : undefined;
  const applicationId = applicationOverride?.proposalId === proposalJob?.job_id ? applicationOverride?.jobId ?? "" : decision?.decision === "accept" && typeof proposalJob?.request?.application_submission_id === "string"
    ? detectionJobId(proposalJob.request.application_submission_id) : "";
  const applicationJob = useQuery({ queryKey: ["job", applicationId], queryFn: () => api.job(applicationId), enabled: Boolean(applicationId), retry: false,
    refetchInterval: (query) => !query.state.data || detectionJobActive(query.state.data) ? 1000 : false });
  const applied = detectionApplication(applicationJob.data, proposalJob, proposal) ?? detectionApplication(proposalJob, proposalJob, proposal);
  const current = proposal && proposalIsCurrent(proposal, resource, sourceRun?.run_id);
  const active = proposalJob && detectionJobActive(proposalJob);
  const errorMessage = proposalJob?.progress.operation_error as { message?: string } | undefined;
  const applicationError = applicationJob.data?.progress.operation_error as { message?: string } | undefined;
  const applicationTerminal = applicationJob.data && ["failed", "cancelled", "interrupted"].includes(applicationJob.data.state);
  const bindJob = (value: RunJob) => client.setQueryData(["job", value.job_id], value);
  const viewJob = (id: string) => setParams((old) => { const next = new URLSearchParams(old); next.set("ai_job", id); return next; });

  useEffect(() => {
    if (jobId && !params.get("ai_job")) setParams((old) => { const next = new URLSearchParams(old); next.set("ai_job", jobId); return next; }, { replace: true });
  }, [jobId, params, setParams]);
  useEffect(() => {
    if (job.data && settleDetectionAIReceipt(job.data)) setReceipt(undefined);
  }, [job.data]);
  useEffect(() => { setReviewer(""); }, [jobId]);
  useEffect(() => {
    if (proposal?.proposal_digest) heading.current?.focus();
  }, [proposal?.proposal_digest]);
  useEffect(() => {
    if (!applied?.candidate_id) return;
    void client.invalidateQueries({ queryKey: ["detections"] });
    void client.invalidateQueries({ queryKey: ["detection-evaluations", applied.candidate_id] });
  }, [applied, client]);

  const submit = useMutation({
    mutationFn: async (saved: DetectionAIReceipt) => {
      const response = await api.suggestDetectionRevision(saved.candidateId, saved.request);
      if (!matchesDetectionAIReceipt(response.job, saved)) throw new Error("The returned job does not match this request. Keep the original request and check its status.");
      return response.job;
    },
    onSuccess: (value) => { bindJob(value); if (settleDetectionAIReceipt(value)) setReceipt(undefined); },
  });
  const review = useMutation({
    mutationFn: ({ id, body }: { id: string; body: DetectionAIDecision }) => api.decideDetectionRevision(id, body),
    onSuccess: (response) => { bindJob(response.proposal_job); if (response.application_job) { bindJob(response.application_job); setApplicationOverride({ proposalId: response.proposal_job.job_id, jobId: response.application_job.job_id }); } },
    onSettled: (_data, _error, submitted) => { void client.invalidateQueries({ queryKey: ["job", submitted.id] }); },
  });
  const control = useMutation({ mutationFn: (id: string) => api.controlJob(id, "cancel"), onSuccess: bindJob });
  const retry = useMutation({ mutationFn: async ({ source }: { source: RunJob; context: string }) => { const response = await api.retryJob(source.job_id); if (!matchesDetectionRetry(response, source)) throw new Error("The retry does not match the original detection request."); return response; }, onSuccess: (response, submitted) => { bindJob(response.job); if (currentContext.current === submitted.context) viewJob(response.job.job_id); } });
  const retryApplication = useMutation({ mutationFn: async ({ source }: { source: RunJob; proposalId: string }) => { const response = await api.retryJob(source.job_id); if (!matchesDetectionRetry(response, source)) throw new Error("The save retry does not match the accepted proposal."); return response; }, onSuccess: (response, submitted) => { bindJob(response.job); setApplicationOverride({ proposalId: submitted.proposalId, jobId: response.job.job_id }); } });
  const start = () => {
    setError(undefined);
    if (!resource || !sourceRun || autonomy !== "assist" || manualEdits || receipt) return;
    const saved: DetectionAIReceipt = { candidateId: resource.id, request: { submission_id: crypto.randomUUID(), run_id: sourceRun.run_id, parent_resource_digest: resource.digest,
      question: question.trim(), case_role: role, provider_id: provider, autonomy: "assist" } };
    if (!storeDetectionAIReceipt(saved)) { setError(new Error("The original request could not be saved for recovery. Check browser storage before sending a model request.")); return; }
    setReceipt(saved);
    viewJob(detectionJobId(saved.request.submission_id));
    submit.mutate(saved);
  };
  const decide = (choice: "accept" | "reject") => {
    if (!proposal || !proposalJob) return;
    review.mutate({ id: proposalJob.job_id, body: { proposal_digest: proposal.proposal_digest, parent_resource_digest: proposal.parent.resource_digest, decision: choice, reviewed_by: reviewer.trim() } });
  };
  const canStart = resource && ["sqlite", "sigma"].includes(resource.document.target_language ?? "") && resource.document.rule_source && sourceRun?.finalized_at && sourceCount > 0 && !sourceRun.is_demo && !manualEdits && autonomy === "assist" && models.some((item) => item.provider_id === provider) && question.trim() && !/[\r\n]/.test(question) && !receipt;
  const boundLink = proposal ? `/detection-lab?candidate=${encodeURIComponent(proposal.parent.candidate_id)}&candidate_scope=registry&run=${encodeURIComponent(proposal.source_run.run_id)}&ai_job=${encodeURIComponent(jobId)}` : undefined;
  return <section className={`detection-assistance${expanded ? " is-open" : ""}`} aria-label="Detection assistance">
    <div className="detection-assistance-heading"><div><h3>Improve this rule with AI</h3><p>Propose a change from the selected evidence, review it here, then test the saved revision.</p></div><Button aria-expanded={expanded} aria-controls="detection-assistance-content" onClick={() => setExpanded(!expanded)}>{expanded ? "Hide assistance" : jobId ? "Resume AI work" : "Open assistance"}</Button></div>
    {expanded ? <div id="detection-assistance-content">
      {receipt && jobId !== detectionJobId(receipt.request.submission_id) ? <Callout title="Another request still needs confirmation">Your earlier request is retained. Resolve it before starting another model request.<Button onClick={() => viewJob(detectionJobId(receipt.request.submission_id))}>Resume pending request</Button></Callout> : null}
      {!jobId ? <>
        <div className="detection-ai-setup"><Field label="Detection AI mode"><select value={autonomy} onChange={(event) => setAutonomy(event.target.value)}><option value="off">Off · no model requests</option><option value="assist">Assist · review every change</option></select></Field><Field label="Detection model provider"><select value={provider} onChange={(event) => setProvider(event.target.value)}><option value="">Choose configured provider</option>{models.map((item) => <option value={item.provider_id} key={item.provider_id}>{item.provider_id} · {item.model}</option>)}</select></Field></div>
        <Field label="What should this rule detect better?" hint="Use the selected run as a development case. Independent benign and withheld cases still need separate evaluation."><input maxLength={1000} value={question} onChange={(event) => setQuestion(event.target.value)} placeholder="Explain the missed behavior or false positive to investigate" /></Field>
        <Field label="Development case context"><select value={role} onChange={(event) => setRole(event.target.value as DetectionCaseRole)}><option value="attack">Attack case</option><option value="benign">Benign activity</option><option value="replay">Replay</option><option value="heldout">Previously withheld case · becomes development input</option></select></Field>
        {!resource?.document.rule_source || !["sqlite", "sigma"].includes(resource.document.target_language ?? "") ? <p>Save and validate a SQLite or Sigma rule before requesting a revision.</p> : !sourceRun?.finalized_at || !sourceCount ? <p>Select a completed run with independent observations in Source run and evidence above.</p> : <p>{sourceCount} independent observations from the selected run will inform this request. The configured provider controls whether bounded, redacted content or field metadata is included.</p>}
        {manualEdits ? <Callout title="Unsaved manual changes">Save your rule edits first, or restore the saved source before requesting AI changes.</Callout> : null}
        {!models.length ? <p><Link to="/ai-planner">Configure a model provider</Link> to use detection assistance.</p> : null}
        <Button variant="primary" disabled={!canStart || submit.isPending} onClick={start}>Propose rule revision</Button>
      </> : <>
        {receipt && !proposalJob ? <Callout title="Keep the original request">The submission is retained until its matching job is found. Retrying uses the same request and cannot create a second job.<div className="candidate-actions"><Button disabled={submit.isPending} onClick={() => submit.mutate(receipt)}>{submit.isPending ? "Sending original request" : "Retry original request"}</Button><Button onClick={() => { void job.refetch(); }}>Check request status</Button></div></Callout> : null}
        {job.isPending ? <LoadingState label="Finding your detection work" /> : job.isError ? <ErrorState title="Detection job unavailable" error={job.error} retry={() => { void job.refetch(); }} /> : job.data && !proposalJob ? <Callout tone="warning" title="Different job type">This link does not refer to a detection revision request.</Callout> : null}
        {proposalJob ? <>
          <p role="status">{applied ? "Revision saved and evaluated" : decision?.decision === "reject" ? "Proposed change rejected" : applicationTerminal ? `Save and evaluation ${applicationJob.data!.state} · no saved result confirmed` : decision?.decision === "accept" ? "Change accepted · saving and evaluating" : proposal ? "Proposed change ready for review" : proposalJob.state === "completed" ? "Proposal unavailable for review" : sentence(proposalJob.state)}</p>
          {active ? <Button disabled={proposalJob.state === "cancelling" || control.isPending} onClick={() => control.mutate(proposalJob.job_id)}>{proposalJob.state === "cancelling" ? "Cancellation requested" : "Cancel AI work"}</Button> : null}
          {["failed", "cancelled", "interrupted"].includes(proposalJob.state) ? <Callout tone="warning" title={sentence(proposalJob.state)}>{errorMessage?.message ?? proposalJob.error?.message ?? "This request did not produce an applied revision."}{proposalJob.state === "interrupted" ? <Button disabled={retry.isPending} onClick={() => retry.mutate({ source: proposalJob, context: currentContext.current })}>Retry interrupted work</Button> : null}</Callout> : null}
          {proposal ? <>
            <h4 ref={heading} tabIndex={-1}>Review the proposed rule</h4>
            <p>{proposal.reason}</p>
            <div className="detection-source-comparison"><div><h5>Original saved source</h5><pre aria-label="Original rule source">{proposal.parent.source}</pre></div><div><h5>Proposed revision</h5><pre aria-label="Proposed rule source">{proposal.source}</pre></div></div>
            <p>{proposal.source_run.observed_count} independent observation{proposal.source_run.observed_count === 1 ? " was" : "s were"} supplied; the proposal cites {proposal.evidence_refs.length}. <Link to={`/runs/${encodeURIComponent(proposal.source_run.run_id)}`}>Inspect source observations</Link></p>
            <p>Generated by {proposal.provider.model} · {proposal.provider.provider_id}. Acceptance saves an immutable revision and evaluates this development case. It does not deploy a rule or prove independent coverage.</p>
            {proposal.limitations.length ? <ul>{proposal.limitations.map((item, index) => <li key={index}>{item}</li>)}</ul> : null}
            {!current || manualEdits ? <Callout tone="warning" title="Review context changed"><p>{manualEdits ? "There are unsaved manual edits. Save or restore them before accepting this proposal." : "The selected rule or source run differs from this proposal. Its original binding remains unchanged."}</p>{boundLink ? <Link className="button button-secondary button-medium" to={boundLink}>Open this proposal's rule and source</Link> : null}</Callout> : null}
            {!decision ? <><Field label="Reviewed by"><input maxLength={200} value={reviewer} onChange={(event) => setReviewer(event.target.value)} autoComplete="off" /></Field><div className="candidate-actions"><Button variant="primary" disabled={!current || manualEdits || !reviewer.trim() || review.isPending} onClick={() => decide("accept")}>Accept, save and evaluate</Button><Button disabled={!reviewer.trim() || review.isPending} onClick={() => decide("reject")}>Reject proposed change</Button></div></> : null}
            {decision?.decision === "accept" && !applied ? <>
              {applicationJob.isError ? <Callout title="Accepted change needs recovery">The decision is retained. Retry the same decision to find or create its one application job.<Button disabled={review.isPending} onClick={() => review.mutate({ id: proposalJob.job_id, body: decision })}>Recover accepted change</Button></Callout> : null}
              {applicationJob.data ? <p role="status">Save and evaluation: {sentence(applicationJob.data.state)}{applicationError?.message ?? applicationJob.data.error?.message ? ` · ${applicationError?.message ?? applicationJob.data.error?.message}` : ""}</p> : null}
              {applicationJob.data && detectionJobActive(applicationJob.data) ? <Button disabled={control.isPending || applicationJob.data.state === "cancelling"} onClick={() => control.mutate(applicationJob.data!.job_id)}>Cancel save and evaluation</Button> : null}
              {applicationJob.data?.state === "interrupted" ? <div className="candidate-actions"><Button onClick={() => retryApplication.mutate({ source: applicationJob.data!, proposalId: proposalJob.job_id })} disabled={retryApplication.isPending}>Retry interrupted save</Button><Button onClick={() => review.mutate({ id: proposalJob.job_id, body: decision })} disabled={review.isPending}>Find latest saved work</Button></div> : null}
            </> : null}
            {applied ? <Callout title="Saved revision and evaluation are ready"><Link to={`/detection-lab?candidate=${encodeURIComponent(applied.candidate_id)}&candidate_scope=registry&run=${encodeURIComponent(applied.run_id)}`}>Open saved revision and its evaluations</Link><p>Repeat on separate benign and withheld cases before judging improvement.</p></Callout> : null}
            <details><summary>AI request and evidence bindings</summary><pre>{JSON.stringify({ job_id: proposalJob.job_id, proposal, decision, application: applied }, null, 2)}</pre></details>
          </> : null}
          {!receipt && !active && (applied || decision?.decision === "reject" || ["failed", "cancelled"].includes(proposalJob.state) || applicationJob.data && ["failed", "cancelled"].includes(applicationJob.data.state)) ? <Button onClick={() => { setParams((old) => { const next = new URLSearchParams(old); next.delete("ai_job"); return next; }); submit.reset(); review.reset(); setError(undefined); }}>Start another request</Button> : null}
        </> : null}
      </>}
      {error ? <ErrorState title="Request not sent" error={error} /> : null}
      {submit.isError ? <ErrorState title="Submission not confirmed" error={submit.error} /> : null}
      {review.isError ? <ErrorState title="Decision not confirmed" error={review.error} /> : null}
      {control.isError ? <ErrorState title="Cancellation not confirmed" error={control.error} /> : null}
      {retry.isError ? <ErrorState title="Retry not confirmed" error={retry.error} /> : null}
      {retryApplication.isError ? <ErrorState title="Save retry not confirmed" error={retryApplication.error} /> : null}
    </div> : null}
  </section>;
}
