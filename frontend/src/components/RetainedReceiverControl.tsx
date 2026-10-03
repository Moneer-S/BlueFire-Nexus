import { useQuery } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../lib/api";
import { checkedReceiverContext, policyTitle } from "../lib/receiver-defense";
import type { ReceiverContext, ReceiverContextRequest, ReceiverControlDecision, ReceiverDefenseEnvelope } from "../lib/receiver-defense-types";
import { Button, Callout, DataList, ErrorState, Field, LoadingState } from "./Primitives";

type StartRequest = ReceiverContextRequest & { submission_id: string; context_digest: string };

export function RetainedReceiverControl({ envelope, disabled, onStart, onRollback }: {
  envelope: ReceiverDefenseEnvelope & { context: ReceiverContext }; disabled: boolean;
  onStart: (body: StartRequest) => void; onRollback: (ownerId: string, body: ReceiverControlDecision) => void;
}) {
  const control = envelope.control!;
  const [review, setReview] = useState<"retest" | "rollback" | null>(null);
  const [acknowledged, setAcknowledged] = useState(false);
  const [reviewer, setReviewer] = useState("");
  const request = useMemo<ReceiverContextRequest>(() => ({
    selection: envelope.context.selection, run_intent: envelope.context.run_intent, workflow: "retained_redaction",
    source_control: { job_id: control.owner_job_id, control_digest: control.control_digest },
  }), [envelope.context.selection, envelope.context.run_intent, control.owner_job_id, control.control_digest]);
  const context = useQuery({ queryKey: ["receiver-context", request], queryFn: async () => checkedReceiverContext(await api.receiverContext(request), request), enabled: review === "retest" && control.can_retest && !disabled, retry: false });
  const openReview = (next: "retest" | "rollback") => { setAcknowledged(false); setReviewer(""); setReview(next); };
  const ready = context.data?.eligible && context.data.availability.ready && context.data.availability.supported;
  return <section className="receiver-retained-control" aria-label="Retained receiver policy">
    <h2>Saved control policy</h2>
    <DataList items={[
      { label: "Desired policy", value: policyTitle[control.desired_policy_id] },
      { label: "Policy state", value: control.status.replaceAll("_", " ") },
      { label: "Receiver state", value: control.receiver_state === "stopped" ? "Stopped; no active receiver" : control.receiver_state === "active" ? "Active bounded receiver" : "Shutdown not verified" },
    ]} />
    <p>The policy applies to this saved control test and its linked fresh retests in the exact reviewed environment. Independently created tests do not inherit it. Retaining a policy does not leave a receiver running.</p>
    {envelope.context.source_control ? <p>Fresh retest of <Link to={`/compare?receiver_job=${encodeURIComponent(control.owner_job_id)}`}>the retained policy</Link>. The <Link to={`/runs/${encodeURIComponent(envelope.context.source_baseline!.run_id)}`}>original baseline</Link> is lineage; only this test's new runs establish its outcomes.</p> : null}
    {control.status === "rolled_back" ? <Callout title="Retained policy rolled back">The desired policy is now the prior reviewed-records policy. Previous prevention and legitimate-use evidence remains historical.</Callout> : null}
    <div className="receiver-actions">
      {control.can_retest ? <Button disabled={disabled} onClick={() => openReview("retest")}>Review fresh retest</Button> : null}
      {control.can_rollback ? <Button disabled={disabled} onClick={() => openReview("rollback")}>Review policy rollback</Button> : null}
    </div>
    {review === "retest" && control.can_retest ? <div className="receiver-control-review">
      <h3>Fresh policy retest</h3>
      {context.isPending ? <LoadingState label="Checking the retained policy and environment" /> : context.error ? <ErrorState error={context.error} retry={() => { void context.refetch(); }} /> : context.data ? <>
        <p>Retest the original staged bytes, then verify legitimate redacted use. Both phases require new receiver preparation, review, and Execute approval.</p>
        {!ready ? <Callout title="Retest is not ready"><ul>{context.data.reasons.map((reason) => <li key={reason.code}>{reason.message}</li>)}</ul>{context.data.availability.reason ? <p>{context.data.availability.reason}</p> : null}</Callout> : null}
        <label className="check-row"><input type="checkbox" checked={acknowledged} disabled={disabled || !ready || context.isFetching} onChange={(event) => setAcknowledged(event.target.checked)} /><span>I reviewed the retained policy, original baseline lineage, and this retest's scope.</span></label>
        <div className="receiver-actions"><Button variant="primary" disabled={disabled || !ready || context.isFetching || !acknowledged} onClick={() => { if (context.data && ready && acknowledged) onStart({ ...request, context_digest: context.data.context_digest, submission_id: crypto.randomUUID() }); }}>Save fresh retest</Button><Button disabled={disabled} onClick={() => setReview(null)}>Cancel</Button></div>
      </> : null}
    </div> : null}
    {review === "rollback" && control.can_rollback ? <div className="receiver-control-review">
      <h3>Roll back the desired policy</h3>
      <p>Change this saved control test's desired policy from redacted-only to reviewed-records. This records a policy decision after all linked receiver work has settled; it does not execute the experiment.</p>
      <label className="check-row"><input type="checkbox" checked={acknowledged} disabled={disabled} onChange={(event) => setAcknowledged(event.target.checked)} /><span>I reviewed the rollback to the prior policy.</span></label>
      <Field label="Rollback reviewed by"><input autoComplete="off" maxLength={128} value={reviewer} disabled={disabled} onChange={(event) => setReviewer(event.target.value)} /></Field>
      <div className="receiver-actions"><Button variant="danger" disabled={disabled || !acknowledged || !reviewer.trim()} onClick={() => onRollback(control.owner_job_id, { submission_id: crypto.randomUUID(), control_digest: control.control_digest, decision: "rollback", reviewed_by: reviewer.trim() })}>Roll back retained policy</Button><Button disabled={disabled} onClick={() => setReview(null)}>Cancel</Button></div>
    </div> : null}
  </section>;
}
