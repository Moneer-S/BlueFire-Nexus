import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useEffect } from "react";
import { api, DEMO_MODE } from "../lib/api";
import { runnerLifecycleFailure } from "../lib/runner-diagnostics";
import { canReviewRunnerUpgrade, isReviewedRunnerUpgrade } from "../lib/runner-upgrade";
import type { RunnerUpgradeIdentity } from "../lib/runner-upgrade";
import type { RunnerLifecycleStatus } from "../types";
import { Button, DataList, ErrorState } from "./Primitives";

interface Props {
  profileId?: string;
  status?: RunnerLifecycleStatus;
  disabled?: boolean;
  onBusy: (busy: boolean) => void;
}

export function RunnerUpgradeReview({ profileId, status, disabled = false, onBusy }: Props) {
  const client = useQueryClient();
  const statusBinding = JSON.stringify(status ?? null);
  const review = useMutation({ mutationFn: ({ profileId: selected, binding }: { profileId: string; binding: string }) => {
    void binding;
    return api.reviewRunnerUpgrade(selected);
  } });
  const { reset: resetReview } = review;
  useEffect(() => resetReview(), [profileId, resetReview]);
  const apply = useMutation({
    mutationFn: ({ profileId: selected, digest }: { profileId: string; digest: string }) => api.bootstrapRunner(selected, true, digest),
    onSettled: () => {
      void client.invalidateQueries({ queryKey: ["runner-lifecycle"] });
      void client.invalidateQueries({ queryKey: ["catalog"] });
    },
  });
  const busy = review.isPending || apply.isPending;
  useEffect(() => { onBusy(busy); return () => onBusy(false); }, [busy, onBusy]);
  const reviewMatches = review.variables?.profileId === profileId && review.variables?.binding === statusBinding;
  const reviewed = reviewMatches && review.data && status && isReviewedRunnerUpgrade(review.data, status.runner_id) ? review.data : undefined;
  const canReview = !DEMO_MODE && !disabled && !busy && canReviewRunnerUpgrade(profileId, status);
  const applyMatches = apply.variables?.profileId === profileId;
  const failure = review.variables?.profileId === profileId && review.error || applyMatches && apply.error;
  const invalidReview = Boolean(reviewMatches && review.data && !reviewed);
  const staleReview = Boolean(review.data && !reviewMatches && review.variables?.profileId === profileId);
  const currentLabel = reviewed?.recovery_required ? "Previously installed runner" : "Currently installed";
  if (!profileId || (!canReviewRunnerUpgrade(profileId, status) && !review.variables && !apply.variables)) return null;
  return <section className="detail-section" aria-label="Runner upgrade review">
    <h3>Update runner and keep history</h3>
    <p>Review the candidate and retained history before applying the runner update.</p>
    <Button size="small" variant="secondary" disabled={!canReview} onClick={() => { apply.reset(); review.mutate({ profileId, binding: statusBinding }); }}>{review.isPending ? "Checking upgrade…" : reviewed || failure || invalidReview || staleReview ? "Refresh upgrade review" : "Review runner upgrade"}</Button>
    {busy ? <p role="status">{apply.isPending ? applyMatches ? "Applying reviewed runner upgrade…" : "Finishing the upgrade for the previous profile…" : "Verifying the candidate and retained history…"}</p> : null}
    {reviewed ? <>
      {reviewed.recovery_required ? <p role="status">An interrupted upgrade must be completed. Review and apply this exact transition. No experiment execution has started.</p> : null}
      <DataList items={[
        { label: "Completed executions retained", value: reviewed.history.completed_executions },
        { label: "Undispatched executions retained", value: reviewed.history.undispatched_executions },
        { label: "Durable results retained", value: reviewed.history.durable_results },
      ]}/>
      <div className="table-scroll"><table><thead><tr><th>Runner</th><th>Version</th><th>Platform</th></tr></thead><tbody>{[[currentLabel, reviewed.current], ["Verified candidate", reviewed.candidate]].map(([label, value]) => {
        const identity = value as RunnerUpgradeIdentity;
        return <tr key={String(label)}><th scope="row">{String(label)}</th><td>{identity.runner_version}{label === "Verified candidate" ? <div className="field-note">{reviewed.current.binary_digest === identity.binary_digest ? "Same artifact" : "Different verified artifact"}</div> : null}</td><td>{identity.platform} · {identity.architecture}</td></tr>;
      })}</tbody></table></div>
      <details><summary>Exact artifacts and history binding</summary><p>The candidate has been verified. Activation has not completed, and no experiment execution has started. The sandbox, enrollment, permitted profiles and protocol contracts match. The old binary, recovery ledger, durable results and product history will be preserved. This upgrade grants no new experiment authority.</p>{[[currentLabel, reviewed.current], ["Verified candidate", reviewed.candidate]].map(([label, value]) => {
        const identity = value as RunnerUpgradeIdentity;
        return <div key={String(label)}><h4>{String(label)}</h4><p>Artifact: <code>{identity.binary_digest.replace(/^sha256:/, "").slice(0, 12)}</code></p><DataList items={Object.entries(identity).map(([key, item]) => ({ label: key.replaceAll("_", " "), value: <code>{item}</code> }))}/></div>;
      })}<DataList items={[{ label: "Ledger rows", value: reviewed.history.total_rows }, { label: "Execute rows", value: reviewed.history.execute_rows }, { label: "Ledger generation", value: reviewed.history.ledger_generation ?? "No ledger generation recorded" }, { label: "History digest", value: <code>{reviewed.history.history_digest}</code> }, { label: "Review digest", value: <code>{reviewed.review_digest}</code> }]}/></details>
      <div className="button-row"><Button variant="primary" disabled={!canReview} onClick={() => { const digest = reviewed.review_digest; review.reset(); apply.mutate({ profileId, digest }); }}>Apply reviewed runner upgrade</Button><Button variant="ghost" disabled={busy} onClick={() => review.reset()}>Close review</Button></div>
    </> : null}
    {invalidReview ? <p role="alert">The upgrade review is incomplete or does not match this runner. Refresh the review before applying an upgrade.</p> : null}
    {staleReview ? <p role="status">Runner status changed after this review. Request a fresh review before applying an upgrade.</p> : null}
    {failure ? <><ErrorState title="Runner upgrade needs attention" error={failure}/>{runnerLifecycleFailure(failure).map((detail, index) => <p key={index}>{detail}</p>)}<p>Keep the runner stopped when upgrade is refused. Resolve the reported blocker, then request a fresh review. No automatic retry was made.</p></> : null}
    {apply.isSuccess && applyMatches ? apply.data.profile_id === profileId && apply.data.state === "stopped" && apply.data.enrollment === "active" ? <p role="status">Runner updated. History retained.</p> : <p role="alert">The upgrade returned an unexpected runner status. Check this profile's current status before continuing.</p> : null}
  </section>;
}
