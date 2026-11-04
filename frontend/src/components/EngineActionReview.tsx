import * as Dialog from "@radix-ui/react-dialog";
import { useEffect, useRef, useState } from "react";
import { ApiError } from "../lib/api";
import { engineExperimentApi } from "../lib/engine-experiment-api";
import { engineActionLabels, type EngineActionAcceptance, type PreparedEngineAction } from "../lib/engine-actions";
import type { EngineExperiment } from "../lib/engine-experiment";
import { Button, Callout, DataList, formatDate } from "./Primitives";

export function EngineActionReview({ open, onClose, experiment, onAccepted }: { open: boolean; onClose: () => void; experiment: EngineExperiment; onAccepted: (receipt: EngineActionAcceptance) => void }) {
  const [review, setReview] = useState<{ prepared: PreparedEngineAction; workspace: EngineExperiment }>();
  const [acknowledged, setAcknowledged] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const [uncertain, setUncertain] = useState(false);
  const [refused, setRefused] = useState(false);
  const [now, setNow] = useState(Date.now());
  const lock = useRef(false);
  const opener = useRef<HTMLElement | null>(null);
  const uncertainRef = useRef(false);
  useEffect(() => {
    if (!open) return;
    opener.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    setAcknowledged(false); setNow(Date.now());
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    let cancelled = false;
    if (!uncertainRef.current) {
      setReview(undefined); setError(undefined); setRefused(false); setBusy(true);
      void (async () => {
        try {
          const canonical = await engineExperimentApi.workspace(experiment.experiment_id);
          if (canonical.revision !== experiment.revision || canonical.experiment_digest !== experiment.experiment_digest) throw new Error("The workspace changed. Close this review and reload before continuing.");
          const prepared = await engineExperimentApi.prepare(canonical);
          if (!cancelled) setReview({ prepared, workspace: canonical });
        } catch (failure) { if (!cancelled) setError(failure instanceof Error ? failure.message : "The action could not be prepared."); }
        finally { if (!cancelled) setBusy(false); }
      })();
    }
    return () => { window.clearInterval(timer); cancelled = true; };
    // A review captures its opening revision. Later updates must invalidate it, not silently replace it.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, experiment.experiment_id]);
  const prepared = review?.prepared;
  const stale = Boolean(prepared && (experiment.revision !== prepared.revision || experiment.experiment_digest !== prepared.experiment_digest));
  const expired = Boolean(prepared && now >= Date.parse(prepared.expires_at));
  const approvalUnavailable = Boolean(prepared?.requires_approval && !["pending", "approved"].includes(prepared.approval.state));
  const submit = async () => {
    if (!prepared || !acknowledged || lock.current || refused || !uncertain && (stale || expired || approvalUnavailable)) return;
    lock.current = true; setBusy(true); setError(undefined);
    let dispatched = false;
    try {
      if (!uncertain) {
        const current = await engineExperimentApi.workspace(prepared.experiment_id);
        if (current.workspace_digest !== prepared.workspace_digest || current.revision !== prepared.revision || current.experiment_digest !== prepared.experiment_digest || Date.now() >= Date.parse(prepared.expires_at)) {
          setRefused(true); throw new Error("This review is stale or expired. Close it and review the current workspace.");
        }
      }
      dispatched = true;
      const receipt = await engineExperimentApi.submit(prepared);
      uncertainRef.current = false; setUncertain(false);
      onClose(); onAccepted(receipt);
    } catch (failure) {
      const ambiguous = dispatched && !(failure instanceof ApiError && failure.status && failure.status >= 400 && failure.status < 500);
      if (ambiguous) { uncertainRef.current = true; setUncertain(true); }
      else if (dispatched) { uncertainRef.current = false; setUncertain(false); setRefused(true); }
      setError(ambiguous ? "Acceptance is unconfirmed. Check the workspace, or retry this exact prepared request to recover its saved acceptance. Closing this dialog does not cancel submitted work." : failure instanceof Error ? failure.message : "The prepared action was refused.");
    } finally { lock.current = false; setBusy(false); }
  };
  const close = () => { if (!lock.current) onClose(); };
  return <Dialog.Root open={open} onOpenChange={value => { if (!value) close(); }}><Dialog.Portal><Dialog.Overlay className="dialog-overlay engine-action-overlay" /><Dialog.Content className="dialog-content engine-action-review" onEscapeKeyDown={event => { if (lock.current) event.preventDefault(); }} onPointerDownOutside={event => { if (lock.current) event.preventDefault(); }} onCloseAutoFocus={event => { event.preventDefault(); opener.current?.focus(); }}>
    <Dialog.Title>{prepared ? engineActionLabels[prepared.action_kind] : "Review next experiment action"}</Dialog.Title>
    <Dialog.Description>Review the exact effect and limits before accepting this controller-prepared action.</Dialog.Description>
    {busy && !prepared ? <p role="status">Preparing the current action…</p> : null}
    {prepared && review ? <>
      <Callout title="Intended outcome"><p>{prepared.effect.summary}</p></Callout>
      <DataList items={[
        { label: "Effect", value: prepared.effect.changes_target ? "Changes the authorized target" : prepared.effect.uses_external_engine ? "Starts bounded external-engine work" : "Trusted controller operation" },
        { label: "Target", value: review.workspace.current_target?.display_name ?? "Current target not established; controller reconciliation only" },
        { label: "Environment", value: `${review.workspace.environment.display_name} · disposable` },
        { label: "Engine", value: prepared.effect.uses_external_engine ? `${review.workspace.engine_setup.engine.display_name} ${review.workspace.engine_setup.engine.version}` : "Trusted BlueFire controller" },
        { label: "Model", value: prepared.effect.uses_external_engine ? `${review.workspace.engine_setup.model.provider} · ${review.workspace.engine_setup.model.id}${review.workspace.engine_setup.model.test_provider ? " · labeled test provider" : ""}` : "No model invocation" },
        { label: "Data destination", value: prepared.effect.uses_external_engine ? review.workspace.engine_setup.model.data_destination : "Local controller" },
        { label: "Finite limits", value: prepared.limits.wall_clock_seconds !== null ? `${prepared.limits.wall_clock_seconds}s · ${prepared.limits.action_limit} actions · ${prepared.limits.artifact_byte_limit?.toLocaleString()} artifact bytes · ${prepared.limits.cost_limit_microunits?.toLocaleString()} cost microunits · ${prepared.limits.maximum_tier} tier` : "One exact controller action; no external-engine authorization" },
        { label: "Review expires", value: formatDate(prepared.expires_at) },
      ]} />
      <details><summary>Exact identities and review binding</summary><DataList items={[
        { label: "Experiment", value: <code>{prepared.experiment_id}</code> }, { label: "Revision", value: prepared.revision },
        { label: "Experiment digest", value: <code>{prepared.experiment_digest}</code> }, { label: "Workspace digest", value: <code>{prepared.workspace_digest}</code> },
        { label: "Preparation", value: <code>{prepared.preparation_id}</code> }, { label: "Protected request", value: <code>{prepared.protected_request_ref}</code> },
        { label: "Target snapshot", value: <code>{review.workspace.current_target?.snapshot_ref ?? "Unavailable"}</code> },
        { label: "Environment reference", value: <code>{review.workspace.environment.environment_ref}</code> },
        { label: "Scope", value: <code>{prepared.limits.target_scope_digest ?? review.workspace.authorization.scope_ref}</code> },
        { label: "Engine source revision", value: <code>{review.workspace.engine_setup.engine.revision}</code> },
        { label: "Engine build", value: <code>{review.workspace.engine_setup.engine.package_digest}</code> },
        { label: "Sandbox image", value: <code>{review.workspace.engine_setup.engine.sandbox_image_digest}</code> },
        { label: "Model authorization", value: <code>{review.workspace.engine_setup.model.authorization_digest}</code> },
        { label: "Approval state", value: prepared.approval.state }, { label: "Approval binding", value: <code>{prepared.approval.review_binding_digest ?? "Not required"}</code> },
        { label: "Submission identity", value: <code>{prepared.submission?.submission_id ?? "Controller transition"}</code> },
        { label: "Submission intent", value: <code>{prepared.submission?.intent_digest ?? "No job submission"}</code> },
      ]} /></details>
      {!uncertain && (stale || expired || approvalUnavailable) ? <p role="alert">{stale ? "The workspace changed." : expired ? "This review expired." : "This approval is unavailable."} Close this review and reload the workspace.</p> : null}
      <label className="engine-action-ack"><input type="checkbox" checked={acknowledged} onChange={event => setAcknowledged(event.target.checked)} disabled={busy} /><span>I reviewed this effect, target, destination, and limits and authorize this exact action.</span></label>
    </> : null}
    {error ? <p role="alert">{error}</p> : null}
    {busy && prepared ? <p role="status">Confirming durable acceptance…</p> : null}
    <div className="dialog-actions"><Button type="button" variant="ghost" onClick={close} disabled={busy && Boolean(prepared)}>Cancel</Button><Button type="button" variant="primary" disabled={!prepared || !acknowledged || busy || refused || !uncertain && (stale || expired || approvalUnavailable)} onClick={() => void submit()}>{busy && prepared ? "Confirming acceptance…" : uncertain ? "Retry exact prepared request" : prepared ? engineActionLabels[prepared.action_kind] : "Accept action"}</Button></div>
  </Dialog.Content></Dialog.Portal></Dialog.Root>;
}
