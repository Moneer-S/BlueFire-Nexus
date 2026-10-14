import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { FileLock2, RefreshCw } from "lucide-react";
import { compositionJobId, compositionJobValid, FILE_ACCESS_PACK } from "../lib/composition";
import { checkedFileAccessControl, checkedFileAccessList, checkedFileAccessOperation, checkedFileAccessStatus, clearFileAccessPending, fileAccessApi, fileAccessConfirmed, fileAccessControlIdValid, fileAccessJobActive, fileAccessOperationLabels, readFileAccessPending, readFileAccessReconciliationPending, storeFileAccessPending, type FileAccessObservation, type FileAccessPending, type FileAccessReviewRequest, type FileAccessSubmission, type LinuxFileAccessControl, type WindowsFileAccessControl, type WindowsPairedFileAccessControl, type WindowsSetupFileAccessControl } from "../lib/file-access";
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
  const control = useQuery({ queryKey: ["file-access-control", owner], queryFn: async () => checkedFileAccessControl(await fileAccessApi.control(owner), owner), enabled: fileAccessControlIdValid(owner), retry: false, refetchInterval: state => state.state.data && (state.state.data.platform === "windows" ? state.state.data.schema_version === "bluefire.windows-file-access-control.v2" && state.state.data.task_usage_state === "unresolved" : state.state.data.usage_state !== "settled") ? 1500 : false });
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
  const setupImport = useMutation({
    mutationFn: async (selection: { enrollment_id: string; enrollment_digest: string }) =>
      checkedFileAccessControl(await fileAccessApi.importSetup(selection), undefined, selection) as WindowsFileAccessControl,
    onSuccess: saved => {
      client.setQueryData(["file-access-control", saved.control_owner_id], saved);
      void client.invalidateQueries({ queryKey: ["file-access-list"] });
      void client.invalidateQueries({ queryKey: ["file-access-status"] });
      setParams({ control: saved.control_owner_id });
    },
  });
  const send = (body: FileAccessSubmission) => {
    if (pending || reconciliation || locked.current || localError) return;
    const value = { id: compositionJobId(body.submission_id), body };
    try {
      storeFileAccessPending(value); locked.current = true; setPending(value); setReview(undefined);
      setParams({ control: body.review.control_owner_id ?? value.id, operation: value.id });
      write.mutate(value);
    } catch (error) { locked.current = false; setLocalError(error); }
  };
  const windowsSetup = status.data?.setup;
  const currentWindowsSetup = Boolean(windowsSetup && !status.error && windowsSetup.expires_at_ms > now);
  const ready = !windowsSetup && status.data?.available === true && !status.error && Boolean(status.data.enrollment && status.data.enrollment.expires_at_ms > now);
  const canCreate = Boolean(ready && status.data && !("setup" in status.data) && status.data.allowed_operations.includes("create"));
  const activeOperation = Boolean(operation.data && fileAccessJobActive(operation.data.job));
  const blocked = Boolean(pending) || Boolean(reconciliation) || Boolean(localError) || write.isPending || activeOperation;
  const displayedReview = review && (review.control_owner_id === null ? !owner : review.control_owner_id === owner) ? review : undefined;
  const reviewAvailable = displayedReview && (displayedReview.operation === "create"
    ? canCreate
    : !control.error && !control.isFetching && (control.data?.platform === "windows"
      ? control.data.schema_version === "bluefire.windows-file-access-control.v2" && displayedReview.operation === "baseline" && !status.error && !status.isFetching
        && control.data.allowed_operations.includes("baseline") && currentWindowsSetup && status.data?.available === true
        && windowsSetup?.enrollment_id === control.data.provenance.enrollment_id
        && windowsSetup?.enrollment_digest === control.data.provenance.enrollment_digest
      : control.data?.allowed_operations.includes(displayedReview.operation)
      && (!(["baseline", "harden"].includes(displayedReview.operation)) || ready)));
  const observation = operation.data?.job.progress.verified_observation as FileAccessObservation | undefined;
  const recoveredObservation = Boolean(observation && operation.data?.job.state !== "completed" && operation.data?.reconciliation?.state === "complete");
  const refresh = () => { void status.refetch(); void list.refetch(); if (owner) void control.refetch(); if (operationId) void operation.refetch(); };
  return <div className="page file-access-page">
    <PageHeader title="Effective file access" actions={<Button disabled={status.isFetching || control.isFetching || operation.isFetching} onClick={refresh}><RefreshCw />Refresh state</Button>} />
    {localError ? <ErrorState title="Saved operation needs attention" error={localError} /> : null}
    <section className="file-access-section" aria-label="File-access enrollment">
      {status.isPending ? <LoadingState label="Checking protected file-access setup" /> : status.error ? <ErrorState error={status.error} /> : null}
      <div className="file-access-heading"><h2>{windowsSetup ? "Windows protected setup" : "Prepared session"}</h2><Badge tone={currentWindowsSetup || ready ? "info" : "warning"}>{currentWindowsSetup ? "Setup verified" : ready ? "Enrolled" : "Unavailable"}</Badge></div>
      {windowsSetup ? <DataList items={[
        { label: "Setup reference", value: <code>{windowsSetup.enrollment_id}</code> },
        { label: "Setup digest", value: <code>{windowsSetup.enrollment_digest}</code> },
        { label: "Original expiry", value: new Date(windowsSetup.expires_at_ms).toLocaleString() },
      ]} /> : null}
      {status.data?.enrollment ? <DataList items={[
        { label: "Enrollment", value: <code>{status.data.enrollment.enrollment_id}</code> },
        { label: "Product owner UID", value: status.data.enrollment.owner_uid }, { label: "Non-owner probe UID", value: status.data.enrollment.probe_uid },
        { label: "Enrollment expires", value: new Date(status.data.enrollment.expires_at_ms).toLocaleString() },
      ]} /> : null}
      {windowsSetup ? <Callout title={currentWindowsSetup ? status.data?.available ? "Paired setup is ready for review" : "Windows task access is unavailable" : "Setup needs fresh verification"}>{currentWindowsSetup ? status.data?.available ? "A saved paired control can review its baseline. Other file-access operations remain unavailable." : "Baseline reads and other file-access operations are not available." : "The last setup observation is no longer current."}</Callout> : !ready && status.data ? <Callout title="Live setup is not ready">{status.data.problem?.message ?? "No current verified enrollment is available."}</Callout> : null}
      {windowsSetup && currentWindowsSetup ? <Button disabled={setupImport.isPending || blocked || status.isFetching} onClick={() => setupImport.mutate({ enrollment_id: windowsSetup.enrollment_id, enrollment_digest: windowsSetup.enrollment_digest })}><FileLock2 />Save verified setup</Button> : null}
      {setupImport.error ? <ErrorState title="Setup save was not confirmed" error={setupImport.error} /> : null}
      {!owner && canCreate ? <Button disabled={!ready || blocked} onClick={() => setReview({ operation: "create", control_owner_id: null })}><FileLock2 />Review generated resource</Button> : null}
    </section>
    <section className="file-access-section" aria-label="Saved file-access controls"><h2>Saved controls</h2>
      {list.error ? <ErrorState error={list.error} /> : list.isPending ? <LoadingState label="Opening saved controls" /> : <div className="file-access-list">{list.data?.controls.map(item => <div key={item.control_owner_id}><Link aria-label={`Open ${item.platform === "windows" ? "Windows protected setup" : "generated file access"}, ${sentence(item.status)}, revision ${item.revision}, reference ${item.control_owner_id.slice(-8)}`} aria-current={owner === item.control_owner_id ? "page" : undefined} to={`/file-access?control=${encodeURIComponent(item.control_owner_id)}`}><strong>{item.platform === "windows" ? "Windows protected setup" : "Generated file access"}</strong><span>{sentence(item.status)} / revision {item.revision}</span></Link><details><summary>Control reference</summary><code>{item.control_owner_id}</code></details></div>)}{!list.data?.controls.length ? <p>No saved controls.</p> : null}</div>}
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
    {owner ? !fileAccessControlIdValid(owner) ? <ErrorState error={new Error("This control link is incomplete.")} /> : control.error ? <ErrorState title="Retained control unavailable" error={control.error} retry={() => { void control.refetch(); }} /> : control.data?.platform === "windows" ? <SavedWindowsSetup control={control.data} disabled={blocked || control.isFetching} baselineReviewAvailable={!status.error && !status.isFetching && currentWindowsSetup && status.data?.available === true && status.data.setup?.enrollment_id === control.data.provenance.enrollment_id && status.data.setup?.enrollment_digest === control.data.provenance.enrollment_digest} onReview={setReview} /> : control.data ? <RetainedFileAccess control={control.data as LinuxFileAccessControl} disabled={blocked || control.isFetching} ready={ready} onReview={setReview} /> : <LoadingState label="Opening retained file-access control" /> : null}
    {displayedReview ? <FileAccessReview key={`${displayedReview.control_owner_id}:${displayedReview.operation}`} request={displayedReview} disabled={blocked || !reviewAvailable} onSubmit={send} onClose={() => setReview(undefined)} /> : null}
  </div>;
}

function SavedWindowsSetup({ control, disabled, baselineReviewAvailable, onReview }: { control: WindowsFileAccessControl; disabled: boolean; baselineReviewAvailable: boolean; onReview: (request: FileAccessReviewRequest) => void }) {
  if (control.schema_version === "bluefire.windows-file-access-control.v2") return <SavedWindowsPairControl control={control} disabled={disabled} baselineReviewAvailable={baselineReviewAvailable} onReview={onReview} />;
  const setup = control as WindowsSetupFileAccessControl;
  const expired = setup.expires_at_ms <= Date.now();
  return <section className="file-access-section" aria-label="Saved Windows protected setup">
    <div className="file-access-heading"><h2>Saved Windows setup</h2><Badge tone={expired ? "warning" : "info"}>{expired ? "Historical" : "Setup verified"}</Badge></div>
    <DataList items={[
      { label: "Setup reference", value: <code>{setup.provenance.enrollment_id}</code> },
      { label: "Original expiry", value: new Date(setup.expires_at_ms).toLocaleString() },
      { label: "Setup receipt", value: <code>{setup.provenance.setup_receipt_digest}</code> },
      { label: "Resource generation", value: <code>{setup.resource.resource_generation}</code> },
      { label: "Expected setup digest", value: <code>{setup.resource.expected_sha256}</code> },
      { label: "Resource size", value: setup.resource.size_bytes },
      { label: "Declared access", value: "Reader-readable" },
      { label: "Task usage", value: "None" },
      { label: "Account and object cleanup", value: "Required" },
    ]} />
    <Callout title="Baseline not established">No baseline read has been verified. This saved setup does not enable a task or prove resource contents.</Callout>
  </section>;
}

function SavedWindowsPairControl({ control, disabled, baselineReviewAvailable, onReview }: { control: WindowsPairedFileAccessControl; disabled: boolean; baselineReviewAvailable: boolean; onReview: (request: FileAccessReviewRequest) => void }) {
  const expired = control.expires_at_ms <= Date.now();
  const baseline = control.baseline;
  return <section className="file-access-section" aria-label="Saved Windows paired control">
    <div className="file-access-heading"><h2>Saved Windows paired control</h2><Badge tone={control.status === "uncertain" || expired ? "warning" : "info"}>{expired ? "Historical" : sentence(control.status)}</Badge></div>
    <DataList items={[
      { label: "Setup reference", value: <code>{control.provenance.enrollment_id}</code> },
      { label: "Original expiry", value: new Date(control.expires_at_ms).toLocaleString() },
      { label: "Control revision", value: control.revision },
      { label: "Task usage", value: sentence(control.task_usage_state) },
      { label: "Account and object cleanup", value: "Required" },
      { label: "Resource generation", value: <code>{control.resource.resource_generation}</code> },
      { label: "Expected resource digest", value: <code>{control.resource.expected_sha256}</code> },
      { label: "Resource size", value: control.resource.size_bytes },
    ]} />
    {baseline ? <>
      <h3>Recorded paired baseline</h3>
      <DataList items={[
        { label: "Non-owner read", value: "Allowed" }, { label: "Owner read", value: "Allowed" },
        { label: "Observed at", value: new Date(baseline.observed_at).toLocaleString() },
        { label: "Observed bytes", value: baseline.size_bytes }, { label: "Observed content digest", value: <code>{baseline.sha256}</code> },
        { label: "Observed resource generation", value: <code>{baseline.resource_generation}</code> },
        { label: "Native cleanup", value: sentence(baseline.native_cleanup) }, { label: "Owned-job cleanup", value: sentence(baseline.owned_job_cleanup) },
        { label: "Independent observation", value: "No" }, { label: "Baseline record digest", value: <code>{baseline.baseline_digest}</code> },
      ]} />
      <Callout title="Saved baseline evidence">This is the recorded paired baseline for this control, not independent telemetry. Other file-access operations remain unavailable.</Callout>
    </> : control.status === "uncertain" ? <Callout title="Original baseline attempt is unresolved">The saved operation and its cleanup remain unresolved. Review only the original operation; a new baseline is unavailable.</Callout>
      : control.operations.length ? <Callout title="Baseline not established">The saved attempt did not establish a baseline. This one-shot control cannot be submitted again.</Callout>
        : <Callout title="Baseline not established">No paired baseline is recorded for this saved setup.</Callout>}
    {control.allowed_operations.includes("baseline") && !expired ? <div className="file-access-actions"><Button disabled={disabled || !baselineReviewAvailable} onClick={() => onReview({ operation: "baseline", control_owner_id: control.control_owner_id })}><FileLock2 />Review paired baseline</Button></div> : null}
    {control.operations.length ? <details><summary>Saved baseline operations</summary><ol className="file-access-history">{control.operations.map((job, index) => <li key={job.job_id}><div><Link to={`/file-access?${new URLSearchParams({ control: control.control_owner_id, operation: job.job_id })}`}>Baseline operation {index + 1}</Link><span>{sentence(job.state)}</span></div><details><summary>Operation reference</summary><code>{job.job_id}</code></details></li>)}</ol></details> : null}
  </section>;
}

function RetainedFileAccess({ control, disabled, ready, onReview }: { control: LinuxFileAccessControl; disabled: boolean; ready: boolean; onReview: (request: FileAccessReviewRequest) => void }) {
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
