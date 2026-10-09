import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { FileLock2, RefreshCw } from "lucide-react";
import { compositionJobId, compositionJobValid, FILE_ACCESS_PACK } from "../lib/composition";
import { checkedFileAccessControl, checkedFileAccessList, checkedFileAccessOperation, checkedFileAccessStatus, clearFileAccessPending, fileAccessApi, fileAccessConfirmed, fileAccessJobActive, fileAccessOperationLabels, readFileAccessPending, readFileAccessReconciliationPending, storeFileAccessPending, type FileAccessControl, type FileAccessObservation, type FileAccessPending, type FileAccessReviewRequest, type FileAccessSubmission } from "../lib/file-access";
import { FileAccessReview } from "../components/FileAccessReview";
import { FileAccessReconciliation } from "../components/FileAccessReconciliation";
import { Badge, Button, Callout, DataList, ErrorState, LoadingState, PageHeader, sentence } from "../components/Primitives";
import "./FileAccess.css";

export function FileAccessPage() {
  const client = useQueryClient();
  const [params, setParams] = useSearchParams();
  const [restored] = useState(() => { try { return { pending: readFileAccessPending(), reconciliation: readFileAccessReconciliationPending(), error: undefined }; } catch (error) { return { pending: undefined, reconciliation: undefined, error }; } });
  const [pending, setPending] = useState(restored.pending);
  const [reconciliation, setReconciliation] = useState(restored.reconciliation);
  const [localError, setLocalError] = useState<unknown>(restored.error);
  const [review, setReview] = useState<FileAccessReviewRequest>();
  const [now, setNow] = useState(Date.now());
  const locked = useRef(false);
  const restoredNavigation = useRef(false);
  const pendingOwner = pending ? pending.body.review.control_owner_id ?? pending.id : reconciliation?.control_owner_id ?? "";
  const owner = params.get("control") ?? pendingOwner;
  const operationId = params.get("operation") ?? (owner === pendingOwner ? pending?.id ?? reconciliation?.operation_job_id : "") ?? "";
  const status = useQuery({ queryKey: ["file-access-status"], queryFn: async () => checkedFileAccessStatus(await fileAccessApi.status()), retry: false });
  const list = useQuery({ queryKey: ["file-access-list"], queryFn: async () => checkedFileAccessList(await fileAccessApi.list()), retry: false });
  const control = useQuery({ queryKey: ["file-access-control", owner], queryFn: async () => checkedFileAccessControl(await fileAccessApi.control(owner), owner), enabled: compositionJobValid(owner), retry: false, refetchInterval: state => state.state.data && state.state.data.usage_state !== "settled" ? 1500 : false });
  const operation = useQuery({ queryKey: ["file-access-operation", operationId, owner], queryFn: async () => checkedFileAccessOperation(await fileAccessApi.operation(operationId), operationId, owner), enabled: compositionJobValid(operationId), retry: false, refetchInterval: state => state.state.data && fileAccessJobActive(state.state.data.job) ? 1500 : false });
  useEffect(() => { const timer = window.setInterval(() => setNow(Date.now()), 1000); return () => window.clearInterval(timer); }, []);
  useEffect(() => {
    if (restoredNavigation.current) return;
    restoredNavigation.current = true;
    if ((!pending && !reconciliation) || params.get("operation") || params.get("control")) return;
    setParams({ control: pendingOwner, operation: operationId }, { replace: true });
  }, [pending, reconciliation, pendingOwner, operationId, params, setParams]);
  useEffect(() => {
    if (!pending || !operation.data || !fileAccessConfirmed(operation.data, pending)) return;
    try { clearFileAccessPending(pending); setPending(undefined); setLocalError(undefined); }
    catch (error) { setLocalError(error); }
  }, [pending, operation.data]);
  useEffect(() => {
    const saved = operation.data?.control;
    if (saved) void client.invalidateQueries({ queryKey: ["file-access-control", saved.control_owner_id], exact: true });
    if (operation.data) {
      void client.invalidateQueries({ queryKey: ["file-access-list"] });
      void client.invalidateQueries({ queryKey: ["file-access-status"] });
    }
  }, [client, operation.data]);
  const write = useMutation({ mutationFn: async (value: FileAccessPending) => {
    storeFileAccessPending(value);
    const response = checkedFileAccessOperation(await fileAccessApi.submit(value.body), value.id);
    if (!fileAccessConfirmed(response, value)) throw new Error("The saved operation does not match the exact submitted review. Confirmation remains pending.");
    return response;
  }, onSuccess: (value, submitted) => {
    client.setQueryData(["file-access-operation", submitted.id, submitted.body.review.control_owner_id ?? submitted.id], value);
    if (value.control) void client.invalidateQueries({ queryKey: ["file-access-control", value.control.control_owner_id], exact: true });
    void client.invalidateQueries({ queryKey: ["file-access-list"] });
    void client.invalidateQueries({ queryKey: ["file-access-status"] });
  }, onSettled: () => { locked.current = false; } });
  const send = (body: FileAccessSubmission) => {
    if (pending || reconciliation || locked.current || localError) return;
    const value = { id: compositionJobId(body.submission_id), body };
    try {
      storeFileAccessPending(value); locked.current = true; setPending(value); setReview(undefined);
      setParams({ control: body.review.control_owner_id ?? value.id, operation: value.id });
      write.mutate(value);
    } catch (error) { locked.current = false; setLocalError(error); }
  };
  const ready = status.data?.available === true && !status.error && Boolean(status.data.enrollment && status.data.enrollment.expires_at_ms > now);
  const activeOperation = Boolean(operation.data && fileAccessJobActive(operation.data.job));
  const blocked = Boolean(pending) || Boolean(reconciliation) || Boolean(localError) || write.isPending || activeOperation;
  const displayedReview = review && (review.control_owner_id === null ? !owner : review.control_owner_id === owner) ? review : undefined;
  const reviewAvailable = displayedReview && (displayedReview.operation === "create"
    ? ready && status.data?.allowed_operations.includes("create")
    : !control.error && !control.isFetching && control.data?.allowed_operations.includes(displayedReview.operation)
      && (!(["baseline", "harden"].includes(displayedReview.operation)) || ready));
  const observation = operation.data?.job.progress.verified_observation as FileAccessObservation | undefined;
  const recoveredObservation = Boolean(observation && operation.data?.job.state !== "completed" && operation.data?.reconciliation?.state === "complete");
  const refresh = () => { void status.refetch(); void list.refetch(); if (owner) void control.refetch(); if (operationId) void operation.refetch(); };
  return <div className="page file-access-page">
    <PageHeader title="Effective file access" actions={<Button disabled={status.isFetching || control.isFetching || operation.isFetching} onClick={refresh}><RefreshCw />Refresh state</Button>} />
    {localError ? <ErrorState title="Saved operation needs attention" error={localError} /> : null}
    <section className="file-access-section" aria-label="File-access enrollment">
      <div className="file-access-heading"><h2>Prepared session</h2><Badge tone={ready ? "info" : "warning"}>{ready ? "Enrolled" : "Unavailable"}</Badge></div>
      {status.isPending ? <LoadingState label="Checking enrolled principals and resource scope" /> : status.error ? <ErrorState error={status.error} /> : null}
      {status.data?.enrollment ? <DataList items={[
        { label: "Enrollment", value: <code>{status.data.enrollment.enrollment_id}</code> },
        { label: "Product owner UID", value: status.data.enrollment.owner_uid }, { label: "Non-owner probe UID", value: status.data.enrollment.probe_uid },
        { label: "Enrollment expires", value: new Date(status.data.enrollment.expires_at_ms).toLocaleString() },
      ]} /> : null}
      {!ready && status.data ? <Callout title="Live setup is not ready">{status.data.problem?.message ?? "No current verified enrollment is available."}</Callout> : null}
      {!owner && status.data?.allowed_operations.includes("create") ? <Button disabled={!ready || blocked} onClick={() => setReview({ operation: "create", control_owner_id: null })}><FileLock2 />Review generated resource</Button> : null}
    </section>
    <section className="file-access-section" aria-label="Saved file-access controls"><h2>Saved controls</h2>
      {list.error ? <ErrorState error={list.error} /> : list.isPending ? <LoadingState label="Opening saved controls" /> : <div className="file-access-list">{list.data?.controls.map(item => <div key={item.control_owner_id}><Link aria-label={`Open generated file access, ${sentence(item.status)}, revision ${item.revision}, reference ${item.control_owner_id.slice(-8)}`} aria-current={owner === item.control_owner_id ? "page" : undefined} to={`/file-access?control=${encodeURIComponent(item.control_owner_id)}`}><strong>Generated file access</strong><span>{sentence(item.status)} / revision {item.revision}</span></Link><details><summary>Control reference</summary><code>{item.control_owner_id}</code></details></div>)}{!list.data?.controls.length ? <p>No saved controls.</p> : null}</div>}
      {owner ? <Link to="/file-access">Enrollment and resource review</Link> : null}
    </section>
    {pending ? <Callout title="Operation confirmation pending"><p>The original request is retained. Resubmission uses its unchanged identity, not a new operation. No automatic effect retry is performed.</p><details><summary>Original submission reference</summary><code>{pending.id}</code></details>
      {operationId !== pending.id ? <Link to={`/file-access?${new URLSearchParams({ control: pending.body.review.control_owner_id ?? pending.id, operation: pending.id })}`}>Open pending operation</Link> : <div className="file-access-actions"><Button disabled={operation.isFetching || write.isPending} onClick={() => { void operation.refetch(); }}><RefreshCw />Check saved operation</Button><Button disabled={write.isPending || locked.current} onClick={() => { if (!locked.current) { locked.current = true; write.mutate(pending); } }}>Resubmit original request</Button></div>}
    </Callout> : null}
    {write.error ? <ErrorState title="Operation not confirmed" error={write.error} /> : null}
    <FileAccessReconciliation operation={operation.error ? undefined : operation.data} pending={reconciliation} disabled={Boolean(pending) || Boolean(localError) || write.isPending} onPending={setReconciliation} onError={setLocalError} />
    {operationId ? !compositionJobValid(operationId) ? <ErrorState error={new Error("This operation link is incomplete.")} /> : operation.error ? <ErrorState title="Saved operation unavailable" error={operation.error} retry={() => { void operation.refetch(); }} /> : operation.data ? <section className="file-access-section" aria-label="Saved operation"><h2>{fileAccessOperationLabels[(operation.data.job.progress.submitted_request as FileAccessSubmission).review.operation]}</h2><DataList items={[{ label: "Job state", value: sentence(operation.data.job.state) }, { label: "Operation", value: <code>{operation.data.job.job_id}</code> }]} />{activeOperation ? <Callout title="Operation unsettled">New control operations remain unavailable.</Callout> : null}{operation.data.job.error ? <ErrorState error={operation.data.job.error} /> : null}</section> : <LoadingState label="Opening exact operation" /> : null}
    {operation.data?.reconciliation?.state === "settled_partial" && !operation.error ? <Callout title="Partial operation settled">The original operation did not complete.</Callout> : null}
    {observation && !operation.error ? <section className="file-access-section" aria-label="Verified operation reads"><h2>{recoveredObservation ? observation.operation === "rollback" ? "Recovered restored-access evidence" : "Recovered baseline-read evidence" : observation.operation === "rollback" ? "Verified restored access" : "Verified baseline reads"}</h2><DataList items={[
      { label: recoveredObservation ? "Recovered non-owner read" : "Fresh non-owner read", value: "Allowed" }, { label: recoveredObservation ? "Recovered owner read" : "Fresh owner read", value: "Allowed" },
      { label: "Observed at", value: new Date(observation.observed_at_ms).toLocaleString() }, { label: "Observed mode", value: <code>{observation.mode}</code> },
      { label: "Resource generation", value: <code>{observation.resource_generation}</code> }, { label: "Verified records", value: observation.record_count },
      { label: "Observed content", value: <code>{observation.sha256}</code> }, { label: "Source binding", value: <code>{observation.source_digest}</code> },
    ]} /></section> : null}
    {owner ? !compositionJobValid(owner) ? <ErrorState error={new Error("This control link is incomplete.")} /> : control.error ? <ErrorState title="Retained control unavailable" error={control.error} retry={() => { void control.refetch(); }} /> : control.data ? <RetainedFileAccess control={control.data} disabled={blocked || control.isFetching} ready={ready} onReview={setReview} /> : <LoadingState label="Opening retained file-access control" /> : null}
    {displayedReview ? <FileAccessReview key={`${displayedReview.control_owner_id}:${displayedReview.operation}`} request={displayedReview} disabled={blocked || !reviewAvailable} onSubmit={send} onClose={() => setReview(undefined)} /> : null}
  </div>;
}

function RetainedFileAccess({ control, disabled, ready, onReview }: { control: FileAccessControl; disabled: boolean; ready: boolean; onReview: (request: FileAccessReviewRequest) => void }) {
  const running = control.operations.some(fileAccessJobActive);
  const canCompose = control.status === "hardened" && control.usage_state === "settled" && control.resource?.mode === "0600" && control.baseline && !running;
  return <section className="file-access-section" aria-label="Retained file-access control">
    <div className="file-access-heading"><h2>Retained control</h2><Badge tone={control.status === "uncertain" || control.status === "recovery_required" ? "warning" : "neutral"}>{sentence(control.status)}</Badge></div>
    <DataList items={[{ label: "Revision", value: control.revision }, { label: "Usage settlement", value: sentence(control.usage_state) }, { label: "Control binding", value: <code>{control.control_digest}</code> }]} />
    {control.resource ? <DataList items={[
      { label: "Resource generation", value: <code>{control.resource.resource_generation}</code> }, { label: "Observed mode", value: <code>{control.resource.mode}</code> },
      { label: "Generated records", value: control.resource.record_count }, { label: "Bytes", value: control.resource.size }, { label: "Content digest", value: <code>{control.resource.sha256}</code> },
    ]} /> : <p>{control.status === "recovery_required" ? "No completed generated resource is reported." : "No current retained resource is reported."}</p>}
    {control.baseline ? <><h3>Verified baseline</h3><DataList items={[{ label: "Non-owner read", value: "Allowed" }, { label: "Owner read", value: "Allowed" }, { label: "Records", value: control.baseline.record_count }, { label: "Baseline content", value: <code>{control.baseline.sha256}</code> }]} /><p>Baseline reads are historical. Mode inspection alone does not establish a fresh access outcome.</p></> : <Callout title="Baseline not established">Fresh non-owner and owner reads have not both been verified.</Callout>}
    {control.status === "uncertain" || control.usage_state !== "settled" ? <Callout title="Unsettled control or usage">Rollback and reset require independently reconciled resource and cleanup evidence.</Callout> : null}
    {control.status === "recovery_required" ? <Callout title="Reset required">Only a reviewed reset is available for this retained control.</Callout> : null}
    <div className="file-access-actions">{control.allowed_operations.map(operation => <Button key={operation} disabled={disabled || running || ((operation === "baseline" || operation === "harden") && !ready)} onClick={() => onReview({ operation, control_owner_id: control.control_owner_id })}><FileLock2 />Review {fileAccessOperationLabels[operation].toLowerCase()}</Button>)}
      {control.baseline ? <Link className="button button-secondary button-medium" to={`/composition?${new URLSearchParams({ control: control.control_owner_id, pack: FILE_ACCESS_PACK })}`}>{canCompose && !disabled && ready ? "Open composition workspace" : "Inspect composition history"}</Link> : null}
    </div>
    {control.operations.length ? <details><summary>Saved control operations</summary><ol className="file-access-history">{control.operations.map((job, index) => { const submitted = job.progress.submitted_request as FileAccessSubmission | undefined; return <li key={job.job_id}><div><Link to={`/file-access?${new URLSearchParams({ control: control.control_owner_id, operation: job.job_id })}`}>Operation {index + 1}: {submitted?.review?.operation ? fileAccessOperationLabels[submitted.review.operation] : "Control operation"}</Link><span>{sentence(job.state)}</span></div><details><summary>Operation reference</summary><code>{job.job_id}</code></details></li>; })}</ol></details> : null}
  </section>;
}
