import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { LockKeyhole } from "lucide-react";
import { memo, useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { Link, Navigate, useSearchParams } from "react-router-dom";
import { CanonicalPlanReview } from "../components/CanonicalPlanReview";
import { continuationApprovalPreflight } from "../lib/approvalReview";
import { ProposalReviewWorkspace } from "../components/ProposalReview";
import { api } from "../lib/api";
import { useAssistancePanel } from "../state/AssistanceContext";
import { useProduct } from "../state/ProductContext";
import { useApprovalDeadline } from "../state/useApprovalDeadline";
import type { AIProposalDecisionResult, AIProposalReview, RunJob } from "../types";
import { Badge, Button, Callout, DataList, Field, LoadingState, PageHeader, Panel, PanelHeader, sentence } from "../components/Primitives";

export function AIPlannerPage() {
  const [search] = useSearchParams();
  const audit = search.get("view") === "audit";
  const setAssistantOpen = useAssistancePanel()?.setOpen;
  const { activeRun } = useProduct();
  const [notice, setNotice] = useState<string>();
  useEffect(() => { if (!audit) setAssistantOpen?.(true); }, [audit, setAssistantOpen]);
  if (!audit) return <Navigate to="/builder" replace />;
  const decisions = activeRun?.planner_decisions ?? [];
  return <div className="page ai-page">
    <PageHeader title="Runtime proposal audit" description="Inspect durable runtime decisions and their original approval review." actions={<Link className="button button-secondary button-medium" onClick={() => setAssistantOpen?.(true)} to="/builder">Plan with Assistant</Link>} />
    {notice ? <Callout title="Proposal review">{notice}</Callout> : null}
    <PlannerJobReview setNotice={setNotice}><Panel><PanelHeader title="Completed run decisions"/>{decisions.length ? <div className="detail-body">{decisions.map((decision, index) => <details key={index}><summary>Decision {index + 1}</summary><pre>{JSON.stringify(decision, null, 2)}</pre></details>)}</div> : <Callout title="No completed run selected">Open a run to inspect its decisions. New experiment drafting and saved proposal review are available in Builder with Assistant.</Callout>}</Panel></PlannerJobReview>
  </div>;
}

// Keep approval typing independent from unchanged review presentation.
// These wrappers skip unchanged presentation only; the approval validator below
// still checks the current request; the shared deadline hook handles idle expiry.
const StableProposalReviewWorkspace = memo(ProposalReviewWorkspace);
const StableCanonicalPlanReview = memo(CanonicalPlanReview);

function PlannerJobReview({ children, setNotice }: { children: ReactNode; setNotice: (notice: string) => void }) {
  const client = useQueryClient();
  const [reviewJobId, setReviewJobId] = useState(""); const [acceptedReview, setAcceptedReview] = useState<AIProposalReview>(); const [approvalConfirmed, setApprovalConfirmed] = useState(false); const [approvalOperator, setApprovalOperator] = useState("");
  const currentReviewJobId = useRef("");
  const [settledReviewJobId, setSettledReviewJobId] = useState("");
  const lookupTimer = useRef<number | undefined>(undefined);
  const lookupIsCurrent = Boolean(reviewJobId) && settledReviewJobId === reviewJobId;
  useEffect(() => () => window.clearTimeout(lookupTimer.current), []);
  const changeReviewJob = useCallback((value: string) => {
    const jobId = value.trim();
    currentReviewJobId.current = jobId;
    setReviewJobId(jobId); setSettledReviewJobId("");
    setAcceptedReview(undefined); setApprovalConfirmed(false); setApprovalOperator("");
    window.clearTimeout(lookupTimer.current);
    lookupTimer.current = window.setTimeout(() => {
      lookupTimer.current = undefined;
      setSettledReviewJobId(jobId);
    }, 200);
  }, []);
  const jobQuery = useQuery({ queryKey: ["job", "planner-review", reviewJobId], queryFn: async () => { const job = await api.job(reviewJobId); if (job.job_id !== reviewJobId) throw new Error("The job response did not match the requested job."); return job; }, enabled: lookupIsCurrent, refetchInterval: (query) => query.state.data?.state === "awaiting_approval" ? 1000 : false });
  // Editing hides the old job immediately; only the read-only lookup waits.
  const selectedJob = lookupIsCurrent ? jobQuery.data : undefined;
  const handleReviewLoaded = useCallback((review: AIProposalReview | undefined) => {
    setAcceptedReview(review?.status === "accepted" ? review : undefined);
  }, []);
  const approveContinuation = useMutation({
    mutationFn: async ({ jobId, operator }: { jobId: string; operator: string }) => {
      const result = await api.approveJob(jobId, operator);
      if (result.job.job_id !== jobId) throw new Error("The approval response did not match the submitted job.");
      return result;
    },
    onSuccess: (result, { jobId }) => {
      client.setQueryData(["job", "planner-review", jobId], result.job);
      if (currentReviewJobId.current !== jobId) return;
      setNotice(`The fresh proposal-continuation envelope for ${jobId} was approved once and released.`);
    },
    onError: (error, { jobId }) => {
      if (currentReviewJobId.current !== jobId) return;
      setNotice(error instanceof Error ? error.message : "The fresh Execute approval was refused.");
    },
    onSettled: (_result, _error, { jobId }) => {
      if (currentReviewJobId.current !== jobId) return;
      setApprovalConfirmed(false); setApprovalOperator("");
    },
  });
  useEffect(() => { setApprovalConfirmed(false); setApprovalOperator(""); }, [acceptedReview?.execute_approval_review?.approval_request_id, acceptedReview?.execute_approval_review?.preflight.approval_envelope?.envelope_digest, selectedJob?.approval_request?.status]);
  const handleProposalDecision = useCallback((result: AIProposalDecisionResult, review: AIProposalReview) => { if (result.job.job_id !== reviewJobId) return; client.setQueryData(["job", "planner-review", reviewJobId], { ...result.job, approval_request: result.approval_request ?? result.job.approval_request }); setAcceptedReview(result.proposal ?? review); setApprovalConfirmed(false); setApprovalOperator(""); setNotice(result.job.progress.approval_kind === "ai_proposal_execute" ? "Proposal accepted. Execute remains stopped at a separate fresh one-time approval envelope shown below." : `Proposal ${result.proposal.status}; job is ${sentence(result.job.state)}.`); }, [client, reviewJobId, setNotice]);
  return <>
    <div className="two-column"><Panel><PanelHeader eyebrow="Run lookup" title="Durable proposal record" detail="Enter the exact local durable job ID; identities and approvals are never stored."/><div className="detail-body"><Field label="Job ID"><input value={reviewJobId} onChange={(event) => changeReviewJob(event.target.value)} placeholder="job-…" autoComplete="off"/></Field>{lookupIsCurrent && jobQuery.isError ? <Callout tone="danger" title="Job unavailable">{jobQuery.error.message}</Callout> : reviewJobId && (!lookupIsCurrent || jobQuery.isPending) ? <LoadingState label={lookupIsCurrent ? "Loading durable job" : "Waiting for job ID"}/> : selectedJob ? <DataList items={[{ label: "State", value: sentence(selectedJob.state) }, { label: "Approval kind", value: sentence(String(selectedJob.progress.approval_kind ?? "none")) }, { label: "Run reference", value: String(selectedJob.result_ref ?? selectedJob.progress.run_id ?? "Not available") }]} /> : <Callout title="No job selected">Use the Runs workspace for a live job, or paste a durable job ID here for proposal audit.</Callout>}</div></Panel>{children}</div>
    {selectedJob ? <StableProposalReviewWorkspace job={selectedJob} onDecision={handleProposalDecision} onReviewLoaded={handleReviewLoaded}/> : null}
    {selectedJob?.state === "awaiting_approval" && selectedJob.progress.approval_kind === "ai_proposal_execute" ? selectedJob.approval_request && acceptedReview ? <PlannerContinuationApproval job={selectedJob} request={selectedJob.approval_request!} review={acceptedReview} confirmed={approvalConfirmed} operator={approvalOperator} pending={approveContinuation.isPending} onConfirmed={setApprovalConfirmed} onOperator={setApprovalOperator} onApprove={() => approveContinuation.mutate({ jobId: reviewJobId, operator: approvalOperator.trim() })}/> : <Callout tone="danger" title="Fresh Execute envelope is not loaded">This job is waiting for a proposal-continuation approval, but the nonce-free public binding or accepted proposal review is unavailable. Approval is intentionally disabled; never approve a job whose fresh digests are not displayed.</Callout> : null}
  </>;
}

function PlannerContinuationApproval({ job, request, review, confirmed, operator, pending, onConfirmed, onOperator, onApprove }: { job: RunJob; request: Record<string, unknown>; review: AIProposalReview; confirmed: boolean; operator: string; pending: boolean; onConfirmed: (value: boolean) => void; onOperator: (value: string) => void; onApprove: () => void }) {
  const continuation = review.resolution?.continuation && typeof review.resolution.continuation === "object" ? review.resolution.continuation as Record<string, unknown> : undefined;
  const deadline = useApprovalDeadline(request.expires_at);
  const preflight = continuationApprovalPreflight(job, review, request, { forDisplayOnly: true });
  const ready = Boolean(preflight && deadline.current);
  return <Panel><PanelHeader eyebrow="Separate effect authorization" title="Fresh Execute approval after proposal acceptance" detail="Accepting the registered behavior did not authorize runner effects." actions={<Badge tone="warning">Awaiting one-time approval</Badge>}/>{!deadline.current ? <Callout tone="warning" title={deadline.valid ? "Approval review expired" : "Approval deadline unavailable"}><p>{deadline.valid ? "This one-time approval has expired." : "This approval has no valid expiry time."} The saved plan remains available, but its pending actions cannot be released. No approval is renewed automatically.</p><Link to={`/runs?job=${encodeURIComponent(job.job_id)}`}>Open this job in Runs to inspect or cancel</Link><p>After cancellation, confirm cleanup before returning to setup for a fresh review.</p></Callout> : null}{preflight?.plan ? <><StableCanonicalPlanReview plan={preflight.plan} cleanup={preflight.cleanup} scope={preflight.scope} binding={preflight.approval_binding} envelope={preflight.approval_envelope}/><DataList items={[{ label: "Approval request", value: <code>{String(request.approval_id)}</code> }, { label: "Proposal record", value: <code>{review.proposal_record_id}</code> }, { label: "State digest", value: <code>{String(request.state_digest)}</code> }, { label: "Plan digest", value: <code>{String(request.plan_digest)}</code> }, { label: "Scope digest", value: <code>{String(request.target_scope_digest)}</code> }, { label: "Profile / tier", value: `${String(request.profile_id)} / ${sentence(String(request.maximum_tier))}` }, { label: "Continuation binding", value: <code>{String(continuation?.execute_approval_binding_digest)}</code> }, { label: "Selected behavior", value: <code>{String(continuation?.selected_behavior_id ?? review.record.proposal?.selected_behavior_id ?? "Not reported")}</code> }]} /><Callout tone="warning" title="Proposal, policy, and approval remain distinct">The server will reconstruct policy and plan state, compare this fresh binding, atomically consume it, and refuse reuse of the original Execute approval.</Callout><label className="check-row"><input type="checkbox" checked={confirmed} onChange={(event) => onConfirmed(event.target.checked)} disabled={!ready || pending}/><span><strong>I approve this exact proposal-continuation envelope once</strong><small>Unchecked by default and never persisted</small></span></label><Field label="Operator identity for fresh Execute approval"><input value={operator} onChange={(event) => onOperator(event.target.value)} autoComplete="off" maxLength={128} disabled={!ready || pending}/></Field><Button variant="primary" onClick={() => { if (deadline.recheck()) onApprove(); }} disabled={!ready || !confirmed || !operator.trim() || pending}><LockKeyhole/>{pending ? "Applying fresh approval" : "Approve and release continuation"}</Button></> : <Callout tone="danger" title="Exact continuation review unavailable">Approval remains disabled until the full canonical plan and envelope match this job’s exact pending approval request.</Callout>}</Panel>;
}
