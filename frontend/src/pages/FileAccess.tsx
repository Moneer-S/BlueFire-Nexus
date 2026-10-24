import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState, type ReactNode, type RefObject } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { ArrowRight, CheckCircle2, CircleDashed, FileLock2, FolderLock, RefreshCw, ShieldCheck } from "lucide-react";
import { compositionJobId, compositionJobValid, FILE_ACCESS_PACK, MACOS_FILE_ACCESS_PACK } from "../lib/composition";
import { checkedFileAccessControl, checkedFileAccessList, checkedFileAccessOperation, checkedFileAccessStatus, clearFileAccessPending, fileAccessApi, fileAccessCompositionPack, fileAccessConfirmed, fileAccessControlIdValid, fileAccessJobActive, fileAccessOperationLabels, macOSFileAccessControlIdValid, readFileAccessPending, readFileAccessReconciliationPending, storeFileAccessPending, type FileAccessObservation, type FileAccessPending, type FileAccessReviewRequest, type FileAccessSubmission, type LinuxFileAccessControl, type MacOSFileAccessControl, type WindowsFileAccessControl, type WindowsPairedFileAccessControl, type WindowsSetupFileAccessControl } from "../lib/file-access";
import { FileAccessReview } from "../components/FileAccessReview";
import { FileAccessReconciliation } from "../components/FileAccessReconciliation";
import { ObjectiveContext } from "../components/ObjectiveContext";
import { WindowsFileAccessCorrection } from "../components/WindowsFileAccessCorrection";
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
  const requirementsRef = useRef<HTMLDetailsElement>(null);
  const restoredNavigation = useRef(false);
  const pendingOwner = pending ? pending.body.review.control_owner_id ?? pending.id : reconciliation?.control_owner_id ?? "";
  const fileAccessPath = (values: Record<string, string>, remove: string[] = ["operation"]) => {
    const next = new URLSearchParams(params);
    remove.forEach(key => next.delete(key));
    Object.entries(values).forEach(([key, value]) => next.set(key, value));
    const query = next.toString();
    return "/file-access" + (query ? "?" + query : "");
  };
  const owner = params.get("control") ?? pendingOwner;
  const operationId = params.get("operation") ?? (owner === pendingOwner ? pending?.id ?? reconciliation?.operation_job_id : "") ?? "";
  const status = useQuery({ queryKey: ["file-access-status"], queryFn: async () => checkedFileAccessStatus(await fileAccessApi.status()), retry: false });
  const statusCurrent = !status.isFetching && !status.isPending && !status.error;
  const list = useQuery({ queryKey: ["file-access-list"], queryFn: async () => checkedFileAccessList(await fileAccessApi.list()), retry: false });
  const control = useQuery({ queryKey: ["file-access-control", owner], queryFn: async () => checkedFileAccessControl(await fileAccessApi.control(owner), owner), enabled: fileAccessControlIdValid(owner), retry: false, refetchInterval: state => state.state.data && (state.state.data.platform === "windows" ? state.state.data.task_usage_state === "unresolved" : state.state.data.usage_state !== "settled") ? 1500 : false });
  const operation = useQuery({ queryKey: ["file-access-operation", operationId, owner], queryFn: async () => checkedFileAccessOperation(await fileAccessApi.operation(operationId), operationId, owner), enabled: compositionJobValid(operationId), retry: false, refetchInterval: state => state.state.data && fileAccessJobActive(state.state.data.job) ? 1500 : false });
  useEffect(() => { const timer = window.setInterval(() => setNow(Date.now()), 1000); return () => window.clearInterval(timer); }, []);
  useEffect(() => {
    if (restoredNavigation.current) return;
    restoredNavigation.current = true;
    if ((!pending && !reconciliation) || params.get("operation") || params.get("control")) return;
    setParams(current => {
      const next = new URLSearchParams(current);
      next.set("control", pendingOwner);
      next.set("operation", operationId);
      return next;
    }, { replace: true });
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
    if (!statusCurrent) throw new Error("Wait for the current prepared-session status before submitting an operation.");
    if (status.data?.platform === "macos" && !macOSFileAccessControlIdValid(value.body.review.control_owner_id)) throw new Error("Saved operations from another platform are read-only in this macOS workspace.");
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
    mutationFn: async (selection: { enrollment_id: string; enrollment_digest: string; platform: "windows" | "macos" }) => {
      if (!statusCurrent) throw new Error("Wait for the current prepared-session status before saving setup.");
      if (status.data?.platform === "macos" && selection.platform !== "macos") throw new Error("Setup from another platform is read-only in this macOS workspace.");
      const request = { enrollment_id: selection.enrollment_id, enrollment_digest: selection.enrollment_digest };
      const saved = checkedFileAccessControl(await fileAccessApi.importSetup(request), undefined, request);
      if (saved.platform !== selection.platform) throw new Error("The saved setup belongs to a different platform.");
      return saved;
    },
    onSuccess: saved => {
      client.setQueryData(["file-access-control", saved.control_owner_id], saved);
      void client.invalidateQueries({ queryKey: ["file-access-list"] });
      void client.invalidateQueries({ queryKey: ["file-access-status"] });
      setParams(current => {
        const next = new URLSearchParams(current);
        next.delete("operation");
        next.set("control", saved.control_owner_id);
        return next;
      });
    },
  });
  const send = (body: FileAccessSubmission) => {
    if (!statusCurrent || pending || reconciliation || locked.current || localError
      || (status.data?.platform === "macos" && !macOSFileAccessControlIdValid(body.review.control_owner_id))) return;
    const value = { id: compositionJobId(body.submission_id), body };
    try {
      storeFileAccessPending(value); locked.current = true; setPending(value); setReview(undefined);
      setParams(current => {
        const next = new URLSearchParams(current);
        next.set("control", body.review.control_owner_id ?? value.id);
        next.set("operation", value.id);
        return next;
      });
      write.mutate(value);
    } catch (error) { locked.current = false; setLocalError(error); }
  };
  const windowsSetup = status.data?.setup;
  const macOSStatus = status.data?.platform === "macos" ? status.data : undefined;
  const macOSEnrollment = macOSStatus?.enrollment;
  const currentWindowsSetup = Boolean(windowsSetup && !status.error && windowsSetup.expires_at_ms > now);
  const ready = !windowsSetup && status.data?.available === true && !status.error && Boolean(status.data.enrollment && status.data.enrollment.expires_at_ms > now);
  const macOSReady = Boolean(macOSStatus && ready && statusCurrent);
  const canCreate = Boolean(statusCurrent && ready && !macOSStatus && status.data && !("setup" in status.data) && status.data.allowed_operations.some(operation => operation === "create"));
  const activeOperation = Boolean(operation.data && fileAccessJobActive(operation.data.job));
  const blocked = Boolean(pending) || Boolean(reconciliation) || Boolean(localError) || write.isPending || activeOperation;
  const displayedReview = review && (review.control_owner_id === null ? !owner : review.control_owner_id === owner) ? review : undefined;
  const reviewAvailable = statusCurrent && displayedReview && (!macOSStatus || macOSFileAccessControlIdValid(displayedReview.control_owner_id)) && (displayedReview.operation === "create"
    ? canCreate
    : !control.error && !control.isFetching && (control.data?.platform === "windows"
      ? ((control.data.schema_version === "bluefire.windows-file-access-control.v2" && displayedReview.operation === "baseline")
        || (control.data.schema_version === "bluefire.windows-file-access-control.v3" && displayedReview.operation === "harden")) && !status.error && !status.isFetching
        && control.data.allowed_operations.includes(displayedReview.operation) && control.data.expires_at_ms > now && currentWindowsSetup && status.data?.available === true
        && windowsSetup?.enrollment_id === control.data.provenance.enrollment_id
        && windowsSetup?.enrollment_digest === control.data.provenance.enrollment_digest
      : control.data?.platform === "macos" ? macOSReady && control.data.usage_state === "settled"
        && control.data.allowed_operations.some(operation => operation === displayedReview.operation)
      : control.data?.allowed_operations.includes(displayedReview.operation)
      && (!(["baseline", "harden"].includes(displayedReview.operation)) || ready)));
  const observation = operation.data?.job.progress.verified_observation as FileAccessObservation | undefined;
  const recoveredObservation = Boolean(observation && operation.data?.job.state !== "completed" && operation.data?.reconciliation?.state === "complete");
  const refresh = () => { void status.refetch(); void list.refetch(); if (owner) void control.refetch(); if (operationId) void operation.refetch(); };
  const setupCurrent = statusCurrent && (currentWindowsSetup || ready);
  const taskAccess = setupCurrent && status.data?.available === true;
  const availabilityTitle = !statusCurrent ? "Checking current task access" : windowsSetup ? currentWindowsSetup ? taskAccess ? "Paired setup is ready for review" : "Windows task access is unavailable" : "Setup needs fresh verification"
    : taskAccess ? "Prepared for reviewed operations" : "Live setup is not ready";
  const availabilityDetail = windowsSetup ? currentWindowsSetup ? taskAccess ? "Save the verified setup or open its saved control to review the next allowed operation." : "The protected setup can be saved, but baseline reads and other file-access operations cannot run. Saving setup does not enable task access."
    : "The last setup observation is no longer current. Existing controls and evidence remain available."
    : taskAccess ? "The prepared session is current. Review the next allowed operation before it runs; saved controls retain its results." : status.data?.problem?.message ?? "No current verified enrollment is available. Saved work is retained.";
  const startGuidance = localError ? "Resolve the saved-operation warning before starting new work. Existing evidence stays available."
    : !statusCurrent ? "Check current setup before preparing a new test. You can still inspect saved work."
      : !taskAccess ? "Task access is unavailable. Review the environment requirements, or open saved work to inspect its original test."
        : windowsSetup && currentWindowsSetup ? "Use Save verified setup above, then open its saved control to review the next allowed operation."
          : macOSEnrollment && macOSReady ? "Use Save original workspace setup above, then open its saved control."
            : canCreate ? "Use Review generated resource above to prepare a new test, or reopen saved work."
              : "Open saved work to review its next allowed operation. This session offers no new resource setup action.";
  return <div className="page file-access-page">
    <PageHeader title="Effective file access" description="Test identity access, preserve application access, and compare fresh results." actions={<Button disabled={status.isFetching || control.isFetching || operation.isFetching} onClick={refresh}><RefreshCw />Refresh state</Button>} />
    <ObjectiveContext expected="file-access" />
    {localError ? <ErrorState title="Saved operation needs attention" error={localError} /> : null}
    <section className="file-access-readiness" aria-label="File-access enrollment">
      {status.isPending ? <LoadingState label="Checking protected file-access setup" /> : status.error ? <ErrorState title={windowsSetup ? "Setup needs fresh verification" : "Task access could not be checked"} error={status.error} /> : null}
      {status.data && !status.error ? <>
        <div className="file-access-readiness-heading">
          <span className="file-access-symbol"><FolderLock aria-hidden="true" /></span>
          <div><p className="file-access-kicker">{windowsSetup ? "Windows protected setup" : macOSStatus ? "macOS protected workspace" : "Prepared session"}</p><h2>{availabilityTitle}</h2><p>{availabilityDetail}</p></div>
          <Badge tone={!statusCurrent ? "neutral" : taskAccess ? "info" : "warning"}>{!statusCurrent ? "Checking access" : taskAccess ? "Review required" : "Execution unavailable"}</Badge>
        </div>
        <dl className="file-access-readiness-facts" aria-label="Setup and task readiness">
          <div><ShieldCheck aria-hidden="true" /><dt>Protected setup</dt><dd>{!statusCurrent ? "Checking" : setupCurrent ? "Verified" : "Not current"}</dd></div>
          <div>{taskAccess ? <CheckCircle2 aria-hidden="true" /> : <CircleDashed aria-hidden="true" />}<dt>Task access</dt><dd>{!statusCurrent ? "Checking" : taskAccess ? "Available for review" : "Unavailable"}</dd></div>
          <div><FileLock2 aria-hidden="true" /><dt>Saved work</dt><dd>{list.isPending ? "Loading" : list.error ? "Check history" : `${list.data?.controls.length ?? 0} ${list.data?.controls.length === 1 ? "control" : "controls"}`}</dd></div>
        </dl>
        <div className="file-access-actions">
          {windowsSetup && currentWindowsSetup ? <Button variant="primary" disabled={setupImport.isPending || blocked || status.isFetching} onClick={() => setupImport.mutate({ enrollment_id: windowsSetup.enrollment_id, enrollment_digest: windowsSetup.enrollment_digest, platform: "windows" })}><FileLock2 />Save verified setup</Button> : null}
          {macOSEnrollment && macOSReady ? <Button variant="primary" disabled={setupImport.isPending || blocked} onClick={() => setupImport.mutate({ enrollment_id: macOSEnrollment.enrollment_id, enrollment_digest: macOSEnrollment.enrollment_digest, platform: "macos" })}><FileLock2 />Save original workspace setup</Button> : null}
          {!owner && canCreate ? <Button variant="primary" disabled={!ready || blocked} onClick={() => setReview({ operation: "create", control_owner_id: null })}><FileLock2 />Review generated resource</Button> : null}
        </div>
        {!taskAccess ? <>
          <FileAccessDetails title="Task access requirements" detailsRef={requirementsRef}>
            <p>{windowsSetup ? "Task access requires the original disposable Windows host, its matching packaged runner, a current protected setup, and the original owner's non-elevated session. Saving a receipt cannot supply missing native task access."
              : macOSStatus ? "Task access requires the original protected macOS workspace, prepared owner and reader identities, and its live private channel. A saved control cannot recreate that workspace."
              : "Task access requires an explicitly prepared disposable environment with separate owner and test identities, a generated resource, and a current protected session. This page does not provision that environment."}</p>
            <p>Do not repeat setup to recover an uncertain operation. Preserve the original environment and inspect its saved operation and cleanup state.</p>
            <p className="file-access-retention-note">Rechecking setup does not replace saved controls, replay operations, or discard evidence.</p>
            <div className="file-access-setup-guides">
              {!macOSStatus ? <a href="https://github.com/Moneer-S/BlueFire-Nexus/blob/main/docs/WINDOWS_FILE_ACCESS_BASELINE.md" target="_blank" rel="noreferrer">Windows setup guide <ArrowRight aria-hidden="true" /></a> : null}
              {!windowsSetup ? <a href="https://github.com/Moneer-S/BlueFire-Nexus/blob/main/docs/MACOS_FILE_ACCESS.md" target="_blank" rel="noreferrer">macOS workspace requirements <ArrowRight aria-hidden="true" /></a> : null}
              {!windowsSetup && !macOSStatus ? <a href="https://github.com/Moneer-S/BlueFire-Nexus/blob/main/docs/PREPARED_LINUX_LAB.md" target="_blank" rel="noreferrer">Prepared Linux lab guide <ArrowRight aria-hidden="true" /></a> : null}
            </div>
          </FileAccessDetails>
        </> : null}
      </> : null}
      {windowsSetup ? <FileAccessDetails title="Protected setup details"><DataList items={[
        { label: "Setup reference", value: <code>{windowsSetup.enrollment_id}</code> },
        { label: "Setup digest", value: <code>{windowsSetup.enrollment_digest}</code> },
        { label: "Original expiry", value: new Date(windowsSetup.expires_at_ms).toLocaleString() },
      ]} /></FileAccessDetails> : null}
      {status.data?.enrollment ? <FileAccessDetails title="Prepared session details"><DataList items={[
        { label: "Enrollment", value: <code>{status.data.enrollment.enrollment_id}</code> },
        { label: "Product owner UID", value: status.data.enrollment.owner_uid }, { label: "Non-owner probe UID", value: status.data.enrollment.probe_uid },
        { label: "Enrollment expires", value: new Date(status.data.enrollment.expires_at_ms).toLocaleString() },
      ]} /></FileAccessDetails> : null}
      {setupImport.error ? <ErrorState title="Setup save was not confirmed" error={setupImport.error} /> : null}
    </section>
    <div className="file-access-workspace">
    <section className="file-access-section file-access-saved" aria-label="Saved file-access controls"><div className="file-access-heading"><div><h2>Saved access work</h2><p>Reopen a test and its recorded operations.</p></div>{list.data && !list.error ? <span className="file-access-count">{list.data.controls.length} saved</span> : null}</div>
      {list.error ? <ErrorState error={list.error} /> : list.isPending ? <LoadingState label="Opening saved controls" /> : <div className="file-access-list">{list.data?.controls.map(item => { const label = item.platform === "windows" ? "Windows" : item.platform === "macos" ? "macOS" : "Generated records"; const purpose = savedAccessPurpose(item.status, item.platform); return <div key={item.control_owner_id} className={owner === item.control_owner_id ? "is-selected" : undefined}><Link aria-label={`${purpose}, ${label}, ${sentence(item.status)}, revision ${item.revision}, reference ${item.control_owner_id.slice(-8)}`} aria-current={owner === item.control_owner_id ? "page" : undefined} to={fileAccessPath({ control: item.control_owner_id })}><FileLock2 aria-hidden="true" /><span><strong>{purpose}</strong><small>{label} / revision {item.revision}</small></span><span className="file-access-saved-state">{sentence(item.status)}<ArrowRight aria-hidden="true" /></span></Link><details><summary>Control reference</summary><code>{item.control_owner_id}</code></details></div>; })}{!list.data?.controls.length ? <div className="file-access-empty"><FolderLock aria-hidden="true" /><div><h3>No saved control is available yet</h3><p>Saved setups and retained generated resources appear here.</p></div></div> : null}</div>}
      {owner ? <Link to={fileAccessPath({}, ["control", "operation"])}>Enrollment and resource review</Link> : null}
    </section>
    <div className="file-access-work-detail">
    {!owner && !pending && !reconciliation && !operationId && !displayedReview ? <section className="file-access-next" aria-labelledby="file-access-next-heading">
      <span className="file-access-next-icon"><FileLock2 aria-hidden="true" /></span>
      <div><h2 id="file-access-next-heading">{taskAccess ? "Review an access test" : "Prepare task access"}</h2><p>{startGuidance}</p>
        {!taskAccess && status.data && !status.error ? <Button size="small" variant="secondary" className="file-access-requirements-action" onClick={() => {
          const details = requirementsRef.current;
          if (details) { details.open = true; details.querySelector("summary")?.focus(); details.scrollIntoView({ block: "nearest" }); }
        }}>Review task access requirements<ArrowRight aria-hidden="true" /></Button> : null}
      </div>
      <FileAccessDetails title="How access validation works"><ol><li><span>1</span><div><strong>Establish the baseline</strong><p>Record actual owner and non-owner reads.</p></div></li><li><span>2</span><div><strong>Review the change</strong><p>Keep its scope, approval, and original recovery state together.</p></div></li><li><span>3</span><div><strong>Retest and compare</strong><p>Distinguish new read results from saved evidence.</p></div></li></ol><p className="file-access-next-note">Available operations depend on the selected platform and saved control. Open saved work to see its next allowed action.</p></FileAccessDetails>
    </section> : null}
    {pending ? <Callout title="Operation confirmation pending"><p>{macOSStatus || macOSFileAccessControlIdValid(pending.body.review.control_owner_id) ? "The original request is retained for status checks only in this workspace. No operation is replayed." : "The original request is retained. Resubmission uses its unchanged identity, not a new operation. No automatic effect retry is performed."}</p><details><summary>Original submission reference</summary><code>{pending.id}</code></details>
      {operationId !== pending.id ? <Link to={fileAccessPath({ control: pending.body.review.control_owner_id ?? pending.id, operation: pending.id })}>Open pending operation</Link> : <div className="file-access-actions"><Button disabled={operation.isFetching || write.isPending} onClick={() => { void operation.refetch(); }}><RefreshCw />Check saved operation</Button>{statusCurrent && !macOSStatus && !macOSFileAccessControlIdValid(pending.body.review.control_owner_id) ? <Button disabled={write.isPending || locked.current} onClick={() => { if (!locked.current) { locked.current = true; write.mutate(pending); } }}>Resubmit original request</Button> : null}</div>}
    </Callout> : null}
    {write.error ? <ErrorState title="Operation not confirmed" error={write.error} /> : null}
    {statusCurrent && !macOSStatus && !macOSFileAccessControlIdValid(owner) ? <FileAccessReconciliation operation={operation.error ? undefined : operation.data} pending={reconciliation} disabled={Boolean(pending) || Boolean(localError) || write.isPending} fileAccessPath={fileAccessPath} onPending={setReconciliation} onError={setLocalError} /> : null}
    {macOSStatus && reconciliation ? <Callout title="Saved evidence request is read-only"><p>This request belongs to another prepared platform. It cannot be resubmitted or reconciled in this macOS workspace.</p><Link to={fileAccessPath({ control: reconciliation.control_owner_id, operation: reconciliation.operation_job_id })}>Open original operation</Link></Callout> : null}
    {operationId ? !compositionJobValid(operationId) ? <ErrorState error={new Error("This operation link is incomplete.")} /> : operation.error ? <ErrorState title="Saved operation unavailable" error={operation.error} retry={() => { void operation.refetch(); }} /> : operation.data ? <section className="file-access-section" aria-label="Saved operation"><h2>{fileAccessOperationLabels[(operation.data.job.progress.submitted_request as FileAccessSubmission).review.operation]}</h2><DataList items={[{ label: "Job state", value: sentence(operation.data.job.state) }]} /><FileAccessDetails title="Operation reference"><code>{operation.data.job.job_id}</code></FileAccessDetails>{activeOperation ? <Callout title="Operation unsettled">New control operations remain unavailable.</Callout> : null}{operation.data.job.error ? <ErrorState error={operation.data.job.error} /> : null}</section> : <LoadingState label="Opening exact operation" /> : null}
    {operation.data?.reconciliation?.state === "settled_partial" && !operation.error ? <Callout title="Partial operation settled">The original operation did not complete.</Callout> : null}
    {observation && !operation.error ? <section className="file-access-section" aria-label="Verified operation reads"><h2>{recoveredObservation ? observation.operation === "rollback" ? "Recovered restored-access evidence" : "Recovered baseline-read evidence" : observation.operation === "rollback" ? "Verified restored access" : "Verified baseline reads"}</h2><DataList items={[
      { label: recoveredObservation ? "Recovered non-owner read" : "Fresh non-owner read", value: "Allowed" }, { label: recoveredObservation ? "Recovered owner read" : "Fresh owner read", value: "Allowed" },
      { label: "Observed at", value: new Date(observation.observed_at_ms).toLocaleString() }, { label: "Observed mode", value: <code>{observation.mode}</code> },
      { label: "Verified records", value: observation.record_count },
    ]} /><FileAccessDetails title="Observation provenance"><DataList items={[
      { label: "Resource generation", value: <code>{observation.resource_generation}</code> },
      { label: "Observed content", value: <code>{observation.sha256}</code> }, { label: "Source binding", value: <code>{observation.source_digest}</code> },
    ]} /></FileAccessDetails></section> : null}
    {macOSStatus && control.data && control.data.platform !== "macos" ? <Callout title="Saved control is read-only">This control belongs to another prepared platform. Its history remains available, but its operations are unavailable in this macOS workspace.</Callout> : null}
    {owner ? !fileAccessControlIdValid(owner) ? <ErrorState error={new Error("This control link is incomplete.")} /> : control.error ? <ErrorState title="Retained control unavailable" error={control.error} retry={() => { void control.refetch(); }} /> : control.data?.platform === "windows" ? <SavedWindowsSetup control={control.data} disabled={blocked || control.isFetching || !statusCurrent || Boolean(macOSStatus)} baselineReviewAvailable={statusCurrent && currentWindowsSetup && status.data?.available === true && status.data.setup?.enrollment_id === control.data.provenance.enrollment_id && status.data.setup?.enrollment_digest === control.data.provenance.enrollment_digest} fileAccessPath={fileAccessPath} onReview={setReview} /> : control.data?.platform === "macos" ? <SavedMacOSControl control={control.data} disabled={blocked || control.isFetching || !macOSReady} fileAccessPath={fileAccessPath} onReview={setReview} /> : control.data ? <RetainedFileAccess control={control.data} disabled={blocked || control.isFetching || !statusCurrent} readOnly={Boolean(macOSStatus) || !statusCurrent} ready={ready} fileAccessPath={fileAccessPath} onReview={setReview} /> : <LoadingState label="Opening retained file-access control" /> : null}
    {displayedReview ? <FileAccessReview key={`${displayedReview.control_owner_id}:${displayedReview.operation}`} request={displayedReview} expectedControlDigest={control.data?.platform === "macos" || control.data?.schema_version === "bluefire.windows-file-access-control.v3" ? control.data.control_digest : undefined} expectedEnrollmentDigest={control.data?.platform === "macos" ? macOSEnrollment?.enrollment_digest : undefined} disabled={blocked || !reviewAvailable} onSubmit={send} onClose={() => setReview(undefined)} /> : null}
    </div>
    </div>
  </div>;
}

type FileAccessPath = (values: Record<string, string>, remove?: string[]) => string;

function FileAccessDetails({ title, children, detailsRef }: { title: string; children: ReactNode; detailsRef?: RefObject<HTMLDetailsElement | null> }) {
  return <details ref={detailsRef} className="file-access-details"><summary>{title}</summary><div>{children}</div></details>;
}

function savedAccessPurpose(status: string, platform?: string) {
  if (status === "uncertain" || status === "recovery_required") return "Recover the original access test";
  if (status === "hardened") return "Retest retained permission changes";
  if (status === "rolled_back") return "Review restored application records";
  if (status === "baseline_verified") return "Compare the recorded access baseline";
  if (status === "setup_verified") return "Establish the Windows access baseline";
  if (status === "reset") return "Review completed resource cleanup";
  return platform === "macos" ? "Validate application workspace access" : "Validate generated-record access";
}

function SavedMacOSControl({ control, disabled, fileAccessPath, onReview }: { control: MacOSFileAccessControl; disabled: boolean; fileAccessPath: FileAccessPath; onReview: (request: FileAccessReviewRequest) => void }) {
  const unsettled = control.usage_state !== "settled" || control.status === "uncertain";
  const running = control.operations.some(fileAccessJobActive);
  const canCompose = !disabled && !running && fileAccessCompositionPack(control) === MACOS_FILE_ACCESS_PACK;
  return <section className="file-access-section" aria-label="Saved macOS workspace control">
    <div className="file-access-heading"><h2>Saved macOS workspace control</h2><Badge tone={unsettled ? "warning" : "neutral"}>{sentence(control.status)}</Badge></div>
    <DataList items={[
      { label: "Revision", value: control.revision }, { label: "Usage settlement", value: sentence(control.usage_state) },
      { label: "Generated records", value: control.resource.record_count }, { label: "Bytes", value: control.resource.size },
    ]} />
    <FileAccessDetails title="Workspace resource and provenance"><DataList items={[
      { label: "Control binding", value: <code>{control.control_digest}</code> },
      { label: "Resource generation", value: <code>{control.resource.resource_generation}</code> },
      { label: "Recorded mode", value: <code>{control.resource.mode}</code> },
      { label: "Content digest", value: <code>{control.resource.sha256}</code> },
    ]} /></FileAccessDetails>
    {control.baseline ? <><h3>Recorded baseline</h3><DataList items={[
      { label: "Non-owner read", value: "Allowed" }, { label: "Owner read", value: "Allowed" },
      { label: "Records", value: control.baseline.record_count },
    ]} /><FileAccessDetails title="Baseline provenance"><DataList items={[
      { label: "Baseline content", value: <code>{control.baseline.sha256}</code> },
      { label: "Baseline record digest", value: <code>{control.baseline.baseline_digest}</code> },
    ]} /></FileAccessDetails><p>Baseline reads are historical. The recorded mode does not establish a fresh access outcome.</p></> : <Callout title="Baseline not established">No verified baseline is recorded for this workspace.</Callout>}
    {unsettled ? <Callout title="Workspace custody is unresolved">This control is read-only. The original operation cannot be replayed or reconciled here.</Callout>
      : !control.allowed_operations.length ? <Callout title="Original workspace unavailable">Saved evidence remains available. New operations require the original live protected workspace.</Callout> : null}
    {!unsettled ? <div className="file-access-actions">{control.allowed_operations.map(operation => <Button key={operation} disabled={disabled || running} onClick={() => onReview({ operation, control_owner_id: control.control_owner_id })}><FileLock2 />Review {fileAccessOperationLabels[operation].toLowerCase()}</Button>)}</div> : null}
    {canCompose ? <Link className="button button-secondary button-medium" to={`/composition?${new URLSearchParams({ control: control.control_owner_id, pack: MACOS_FILE_ACCESS_PACK })}`}>Open composition workspace</Link> : null}
    {control.operations.length ? <details><summary>Saved macOS control operations</summary><ol className="file-access-history">{control.operations.map((job, index) => { const submitted = job.progress.submitted_request as FileAccessSubmission; return <li key={job.job_id}><div><Link to={fileAccessPath({ control: control.control_owner_id, operation: job.job_id })}>Operation {index + 1}: {fileAccessOperationLabels[submitted.review.operation]}</Link><span>{sentence(job.state)}</span></div><details><summary>Operation reference</summary><code>{job.job_id}</code></details></li>; })}</ol></details> : null}
  </section>;
}

function SavedWindowsSetup({ control, disabled, baselineReviewAvailable, fileAccessPath, onReview }: { control: WindowsFileAccessControl; disabled: boolean; baselineReviewAvailable: boolean; fileAccessPath: FileAccessPath; onReview: (request: FileAccessReviewRequest) => void }) {
  if (control.schema_version === "bluefire.windows-file-access-control.v3") return <WindowsFileAccessCorrection control={control} disabled={disabled} reviewAvailable={baselineReviewAvailable} fileAccessPath={fileAccessPath} onReview={onReview} />;
  if (control.schema_version === "bluefire.windows-file-access-control.v2") return <SavedWindowsPairControl control={control} disabled={disabled} baselineReviewAvailable={baselineReviewAvailable} fileAccessPath={fileAccessPath} onReview={onReview} />;
  const setup = control as WindowsSetupFileAccessControl;
  const expired = setup.expires_at_ms <= Date.now();
  return <section className="file-access-section" aria-label="Saved Windows protected setup">
    <div className="file-access-heading"><h2>Saved Windows setup</h2><Badge tone="neutral">{expired ? "Historical" : "Setup only"}</Badge></div>
    <p className="file-access-section-lead">The protected setup is retained. It does not establish baseline access or authorize a task.</p>
    <DataList items={[
      { label: "Original expiry", value: new Date(setup.expires_at_ms).toLocaleString() },
      { label: "Resource size", value: setup.resource.size_bytes },
      { label: "Declared access", value: "Reader-readable" },
      { label: "Task usage", value: "None" },
      { label: "Account and object cleanup", value: "Required" },
    ]} />
    <Callout title="Baseline not established">No baseline read has been verified. This saved setup does not enable a task or prove resource contents.</Callout>
    <FileAccessDetails title="Saved setup provenance"><DataList items={[
      { label: "Setup reference", value: <code>{setup.provenance.enrollment_id}</code> },
      { label: "Setup receipt", value: <code>{setup.provenance.setup_receipt_digest}</code> },
      { label: "Resource generation", value: <code>{setup.resource.resource_generation}</code> },
      { label: "Expected setup digest", value: <code>{setup.resource.expected_sha256}</code> },
    ]} /></FileAccessDetails>
  </section>;
}

function SavedWindowsPairControl({ control, disabled, baselineReviewAvailable, fileAccessPath, onReview }: { control: WindowsPairedFileAccessControl; disabled: boolean; baselineReviewAvailable: boolean; fileAccessPath: FileAccessPath; onReview: (request: FileAccessReviewRequest) => void }) {
  const expired = control.expires_at_ms <= Date.now();
  const baseline = control.baseline;
  return <section className="file-access-section" aria-label="Saved Windows paired control">
    <div className="file-access-heading"><h2>Saved Windows paired control</h2><Badge tone={control.status === "uncertain" || expired ? "warning" : "info"}>{expired ? "Historical" : sentence(control.status)}</Badge></div>
    <DataList items={[
      { label: "Original expiry", value: new Date(control.expires_at_ms).toLocaleString() },
      { label: "Control revision", value: control.revision },
      { label: "Task usage", value: sentence(control.task_usage_state) },
      { label: "Account and object cleanup", value: "Required" },
      { label: "Resource size", value: control.resource.size_bytes },
    ]} />
    <FileAccessDetails title="Saved setup provenance"><DataList items={[
      { label: "Setup reference", value: <code>{control.provenance.enrollment_id}</code> },
      { label: "Resource generation", value: <code>{control.resource.resource_generation}</code> },
      { label: "Expected resource digest", value: <code>{control.resource.expected_sha256}</code> },
    ]} /></FileAccessDetails>
    {baseline ? <>
      <h3>Recorded paired baseline</h3>
      <DataList items={[
        { label: "Non-owner read", value: "Allowed" }, { label: "Owner read", value: "Allowed" },
        { label: "Observed at", value: new Date(baseline.observed_at).toLocaleString() },
        { label: "Observed bytes", value: baseline.size_bytes },
        { label: "Native cleanup", value: sentence(baseline.native_cleanup) }, { label: "Owned-job cleanup", value: sentence(baseline.owned_job_cleanup) },
        { label: "Independent observation", value: "No" },
      ]} />
      <Callout title="Saved baseline evidence">This is the recorded paired baseline for this control, not independent telemetry. Other file-access operations remain unavailable.</Callout>
      <FileAccessDetails title="Baseline provenance"><DataList items={[
        { label: "Observed content digest", value: <code>{baseline.sha256}</code> },
        { label: "Observed resource generation", value: <code>{baseline.resource_generation}</code> },
        { label: "Baseline record digest", value: <code>{baseline.baseline_digest}</code> },
      ]} /></FileAccessDetails>
    </> : control.status === "uncertain" ? <Callout title="Original baseline attempt is unresolved">The saved operation and its cleanup remain unresolved. Review only the original operation; a new baseline is unavailable.</Callout>
      : control.operations.length ? <Callout title="Baseline not established">The saved attempt did not establish a baseline. This one-shot control cannot be submitted again.</Callout>
        : <Callout title="Baseline not established">No paired baseline is recorded for this saved setup.</Callout>}
    {control.allowed_operations.includes("baseline") && !expired ? <div className="file-access-actions"><Button disabled={disabled || !baselineReviewAvailable} onClick={() => onReview({ operation: "baseline", control_owner_id: control.control_owner_id })}><FileLock2 />Review paired baseline</Button></div> : null}
    {control.operations.length ? <details><summary>Saved baseline operations</summary><ol className="file-access-history">{control.operations.map((job, index) => <li key={job.job_id}><div><Link to={fileAccessPath({ control: control.control_owner_id, operation: job.job_id })}>Baseline operation {index + 1}</Link><span>{sentence(job.state)}</span></div><details><summary>Operation reference</summary><code>{job.job_id}</code></details></li>)}</ol></details> : null}
  </section>;
}

function RetainedFileAccess({ control, disabled, ready, readOnly, fileAccessPath, onReview }: { control: LinuxFileAccessControl; disabled: boolean; ready: boolean; readOnly: boolean; fileAccessPath: FileAccessPath; onReview: (request: FileAccessReviewRequest) => void }) {
  const running = control.operations.some(fileAccessJobActive);
  const canCompose = control.status === "hardened" && control.usage_state === "settled" && control.resource?.mode === "0600" && control.baseline && !running;
  return <section className="file-access-section" aria-label="Retained file-access control">
    <div className="file-access-heading"><h2>Retained control</h2><Badge tone={control.status === "uncertain" || control.status === "recovery_required" ? "warning" : "neutral"}>{sentence(control.status)}</Badge></div>
    <DataList items={[{ label: "Revision", value: control.revision }, { label: "Usage settlement", value: sentence(control.usage_state) }]} />
    {control.resource ? <DataList items={[
      { label: "Observed mode", value: <code>{control.resource.mode}</code> },
      { label: "Generated records", value: control.resource.record_count }, { label: "Bytes", value: control.resource.size },
    ]} /> : <p>{control.status === "recovery_required" ? "No completed generated resource is reported." : "No current retained resource is reported."}</p>}
    <FileAccessDetails title="Retained resource provenance"><DataList items={[
      { label: "Control binding", value: <code>{control.control_digest}</code> },
      ...(control.resource ? [{ label: "Resource generation", value: <code>{control.resource.resource_generation}</code> }, { label: "Content digest", value: <code>{control.resource.sha256}</code> }] : []),
    ]} /></FileAccessDetails>
    {control.baseline ? <><h3>Verified baseline</h3><DataList items={[{ label: "Non-owner read", value: "Allowed" }, { label: "Owner read", value: "Allowed" }, { label: "Records", value: control.baseline.record_count }]} /><p>Baseline reads are historical. Mode inspection alone does not establish a fresh access outcome.</p><FileAccessDetails title="Baseline provenance"><DataList items={[{ label: "Baseline content", value: <code>{control.baseline.sha256}</code> }]} /></FileAccessDetails></> : <Callout title="Baseline not established">Fresh non-owner and owner reads have not both been verified.</Callout>}
    {!readOnly && (control.status === "uncertain" || control.usage_state !== "settled") ? <Callout title="Unsettled control or usage">Rollback and reset require independently reconciled resource and cleanup evidence.</Callout> : null}
    {!readOnly && control.status === "recovery_required" ? <Callout title="Reset required">Only a reviewed reset is available for this retained control.</Callout> : null}
    {!readOnly ? <div className="file-access-actions">{control.allowed_operations.map(operation => <Button key={operation} disabled={disabled || running || ((operation === "baseline" || operation === "harden") && !ready)} onClick={() => onReview({ operation, control_owner_id: control.control_owner_id })}><FileLock2 />Review {fileAccessOperationLabels[operation].toLowerCase()}</Button>)}
      {control.baseline ? <Link className="button button-secondary button-medium" to={`/composition?${new URLSearchParams({ control: control.control_owner_id, pack: FILE_ACCESS_PACK })}`}>{canCompose && !disabled && ready ? "Open composition workspace" : "Inspect composition history"}</Link> : null}
    </div> : null}
    {control.operations.length ? <details><summary>Saved control operations</summary><ol className="file-access-history">{control.operations.map((job, index) => { const submitted = job.progress.submitted_request as FileAccessSubmission | undefined; return <li key={job.job_id}><div><Link to={fileAccessPath({ control: control.control_owner_id, operation: job.job_id })}>Operation {index + 1}: {submitted?.review?.operation ? fileAccessOperationLabels[submitted.review.operation] : "Control operation"}</Link><span>{sentence(job.state)}</span></div><details><summary>Operation reference</summary><code>{job.job_id}</code></details></li>; })}</ol></details> : null}
  </section>;
}
