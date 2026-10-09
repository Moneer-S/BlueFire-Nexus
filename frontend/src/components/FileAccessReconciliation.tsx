import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { RefreshCw, ShieldCheck } from "lucide-react";
import { checkedFileAccessOperation, checkedFileAccessReconciliation, clearFileAccessReconciliationPending, fileAccessApi, fileAccessReconciliationConfirmed, storeFileAccessReconciliationPending, type FileAccessOperationEnvelope, type FileAccessReconciliationPending, type FileAccessSubmission } from "../lib/file-access";
import { Button, Callout, ErrorState, Field } from "./Primitives";
import { sameJson } from "../lib/replay-review";

export function FileAccessReconciliation({ operation, pending, disabled, onPending, onError }: {
  operation?: FileAccessOperationEnvelope; pending?: FileAccessReconciliationPending; disabled: boolean;
  onPending: (value: FileAccessReconciliationPending | undefined) => void; onError: (error: unknown) => void;
}) {
  const client = useQueryClient();
  const [review, setReview] = useState<string>();
  const locked = useRef(false);
  const receipt = useQuery({ queryKey: ["file-access-reconciliation", pending?.operation_job_id, pending?.body.submission_id], queryFn: async () => checkedFileAccessReconciliation(await fileAccessApi.reconciliation(pending!.operation_job_id, pending!.body.submission_id), pending!.operation_job_id, pending!.body.submission_id), enabled: Boolean(pending), retry: false, refetchInterval: state => state.state.data?.receipt.state === "pending" ? 1500 : false });
  useEffect(() => {
    if (!pending || !receipt.data || !fileAccessReconciliationConfirmed(receipt.data.receipt, pending)) return;
    try {
      clearFileAccessReconciliationPending(pending); onPending(undefined);
      void client.invalidateQueries({ queryKey: ["file-access-operation", pending.operation_job_id] });
      void client.invalidateQueries({ queryKey: ["file-access-control", pending.control_owner_id], exact: true });
    } catch (error) { onError(error); }
  }, [client, pending, receipt.data, onPending, onError]);
  const write = useMutation({ mutationFn: async (target: FileAccessReconciliationPending) => {
    storeFileAccessReconciliationPending(target);
    const response = checkedFileAccessOperation(await fileAccessApi.reconcile(target.operation_job_id, target.body), target.operation_job_id);
    const saved = response.reconciliation_receipt;
    if (!saved || saved.submission_id !== target.body.submission_id || !sameJson(saved.submitted_request, target.body)) throw new Error("The reconciliation receipt does not acknowledge the original evidence request.");
    return response;
  }, onSuccess: (value, target) => {
    client.setQueryData(["file-access-reconciliation", target.operation_job_id, target.body.submission_id], { schema_version: "bluefire.file-access-reconciliation.v1", operation_job_id: target.operation_job_id, receipt: value.reconciliation_receipt });
    void client.invalidateQueries({ queryKey: ["file-access-operation", target.operation_job_id] });
  }, onSettled: () => { locked.current = false; } });
  const send = (target: FileAccessReconciliationPending) => {
    if (locked.current) return;
    try { storeFileAccessReconciliationPending(target); locked.current = true; onPending(target); setReview(undefined); write.mutate(target); }
    catch (error) { locked.current = false; onError(error); }
  };
  const digest = operation?.reconciliation?.outcome_digest;
  const identity = operation && digest ? `${operation.job.job_id}:${digest}` : "";
  return <>
    {pending ? <Callout title="Evidence request confirmation pending"><p>The original task is not redispatched. The saved request identity is unchanged.</p><Link to={`/file-access?${new URLSearchParams({ control: pending.control_owner_id, operation: pending.operation_job_id })}`}>Open original operation</Link><div className="file-access-actions"><Button disabled={receipt.isFetching || write.isPending} onClick={() => { void receipt.refetch(); }}><RefreshCw />Check saved reconciliation</Button><Button disabled={write.isPending || disabled} onClick={() => send(pending)}>Resubmit original evidence request</Button></div></Callout> : null}
    {receipt.error ? <ErrorState title="Reconciliation receipt unavailable" error={receipt.error} /> : null}
    {write.error ? <ErrorState title="Evidence request not confirmed" error={write.error} /> : null}
    {operation?.reconciliation_receipt?.problem ? <Callout title="Reconciliation outcome">{operation.reconciliation_receipt.problem.message}</Callout> : null}
    {operation?.reconciliation?.available && !pending ? <section className="file-access-section" aria-label="Original task reconciliation"><h2>Uncertain operation</h2><p>The original effect remains unresolved.</p><Button disabled={disabled || write.isPending} onClick={() => setReview(identity)}><RefreshCw />Review original task evidence</Button>
      {review === identity ? <EvidenceReview key={identity} operation={operation} disabled={disabled || write.isPending} onSubmit={send} onCancel={() => setReview(undefined)} /> : null}
    </section> : null}
  </>;
}

function EvidenceReview({ operation, disabled, onSubmit, onCancel }: { operation: FileAccessOperationEnvelope; disabled: boolean; onSubmit: (pending: FileAccessReconciliationPending) => void; onCancel: () => void }) {
  const [actor, setActor] = useState("");
  const [acknowledged, setAcknowledged] = useState(false);
  const submitted = operation.job.progress.submitted_request as FileAccessSubmission;
  return <>
    <p>Read authenticated evidence for the original task. This does not repeat its mutation, release an unresolved cleanup obligation, or infer success from a missing response.</p>
    <Field label="Evidence review by"><input value={actor} maxLength={128} autoComplete="off" disabled={disabled} onChange={event => setActor(event.target.value)} /></Field>
    <label className="check-row"><input type="checkbox" checked={acknowledged} disabled={disabled} onChange={event => setAcknowledged(event.target.checked)} /><span>I authorize this bounded read of the original task evidence.</span></label>
    <div className="file-access-actions"><Button disabled={disabled || !actor.trim() || !acknowledged} onClick={() => onSubmit({ operation_job_id: operation.job.job_id, control_owner_id: submitted.review.control_owner_id ?? operation.job.job_id, body: { submission_id: crypto.randomUUID(), expected_outcome_digest: operation.reconciliation!.outcome_digest, reviewed_by: actor.trim() } })}><ShieldCheck />Read original task evidence</Button><Button disabled={disabled} onClick={onCancel}>Cancel evidence review</Button></div>
  </>;
}
