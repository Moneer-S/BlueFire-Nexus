import { useQuery } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { RefreshCw, ShieldCheck, X } from "lucide-react";
import { checkedFileAccessReview, fileAccessApi, fileAccessOperationLabels, type FileAccessReview as Review, type FileAccessReviewRequest, type FileAccessSubmission } from "../lib/file-access";
import { Button, Callout, DataList, ErrorState, Field, LoadingState } from "./Primitives";

export function FileAccessReview({ request, disabled, onSubmit, onClose }: {
  request: FileAccessReviewRequest; disabled: boolean; onSubmit: (body: FileAccessSubmission) => void; onClose: () => void;
}) {
  const review = useQuery({ queryKey: ["file-access-review", request], queryFn: async () => checkedFileAccessReview(await fileAccessApi.review(request), request), retry: false, staleTime: 0, refetchOnWindowFocus: false });
  return <section className="file-access-section" aria-label="File-access operation review">
    <div className="file-access-heading"><h2>{fileAccessOperationLabels[request.operation]}</h2><Button disabled={disabled} onClick={onClose}><X />Cancel review</Button></div>
    {review.isFetching ? <LoadingState label="Checking current resource and enrollment" /> : null}
    {review.error ? <ErrorState error={review.error} retry={() => { void review.refetch(); }} /> : null}
    {review.data && !review.error ? <ConfirmedReview key={review.data.review_digest} review={review.data} request={request} disabled={disabled || review.isFetching} onSubmit={onSubmit} /> : null}
    <Button disabled={disabled || review.isFetching} onClick={() => { void review.refetch(); }}><RefreshCw />Refresh operation review</Button>
  </section>;
}

function ConfirmedReview({ review, request, disabled, onSubmit }: { review: Review; request: FileAccessReviewRequest; disabled: boolean; onSubmit: (body: FileAccessSubmission) => void }) {
  const [actor, setActor] = useState("");
  const [acknowledged, setAcknowledged] = useState(false);
  const [now, setNow] = useState(Date.now());
  useEffect(() => { const timer = window.setInterval(() => setNow(Date.now()), 1000); return () => window.clearInterval(timer); }, []);
  const expired = now >= review.expires_at_ms;
  return <>
    <p>{review.effect}</p>
    <DataList items={[{ label: "Review expires", value: new Date(review.expires_at_ms).toLocaleString() }, { label: "Enrollment binding", value: <code>{review.enrollment_digest}</code> }, ...(review.control_digest ? [{ label: "Current control binding", value: <code>{review.control_digest}</code> }] : [])]} />
    {expired ? <Callout title="Review expired">A fresh review is required. Nothing has been submitted.</Callout> : null}
    <Field label="Operation reviewed by"><input value={actor} maxLength={128} autoComplete="off" disabled={disabled || expired} onChange={event => setActor(event.target.value)} /></Field>
    <label className="check-row"><input type="checkbox" checked={acknowledged} disabled={disabled || expired} onChange={event => setAcknowledged(event.target.checked)} /><span>I authorize this exact operation on the enrolled generated resource and its stated cleanup obligations.</span></label>
    <Button variant={request.operation === "reset" || request.operation === "rollback" ? "danger" : "primary"} disabled={disabled || expired || !actor.trim() || !acknowledged} onClick={() => onSubmit({ submission_id: crypto.randomUUID(), review: request, review_digest: review.review_digest, reviewed_by: actor.trim() })}><ShieldCheck />{fileAccessOperationLabels[request.operation]}</Button>
  </>;
}
