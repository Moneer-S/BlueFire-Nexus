import { FileLock2 } from "lucide-react";
import { Link } from "react-router-dom";
import { type FileAccessReviewRequest, type FileAccessSubmission, type WindowsCorrectionFileAccessControl } from "../lib/file-access";
import { Badge, Button, Callout, DataList, sentence } from "./Primitives";

export function WindowsFileAccessCorrection({ control, disabled, reviewAvailable, fileAccessPath, onReview }: {
  control: WindowsCorrectionFileAccessControl; disabled: boolean; reviewAvailable: boolean;
  fileAccessPath: (values: Record<string, string>, remove?: string[]) => string;
  onReview: (request: FileAccessReviewRequest) => void;
}) {
  const expired = control.expires_at_ms <= Date.now();
  const baseline = control.baseline;
  const retest = control.retest;
  const unsettled = control.task_usage_state === "unresolved";
  return <section className="file-access-section" aria-label="Windows file-access correction">
    <div className="file-access-heading"><h2>Windows file-access control</h2><Badge tone={unsettled || expired ? "warning" : "info"}>{expired ? "Historical" : sentence(control.status)}</Badge></div>
    <DataList items={[
      { label: "Control revision", value: control.revision },
      { label: "Protection", value: sentence(control.resource.protection) },
      { label: "Task usage", value: sentence(control.task_usage_state) },
      { label: "Original expiry", value: new Date(control.expires_at_ms).toLocaleString() },
      { label: "Account and object cleanup", value: "Required" },
    ]} />
    {unsettled ? <Callout title="Original attempt is unresolved">Protection is unknown. No further change is available.</Callout> : null}
    <h3>Recorded paired baseline</h3>
    <DataList items={[
      { label: "Baseline non-owner read", value: "Allowed" }, { label: "Baseline owner read", value: "Allowed" },
      { label: "Baseline observed at", value: new Date(baseline.observed_at).toLocaleString() },
      { label: "Baseline native cleanup", value: sentence(baseline.native_cleanup) },
      { label: "Baseline owned-job cleanup", value: sentence(baseline.owned_job_cleanup) },
    ]} />
    {retest && control.correction ? <>
      <h3>Recorded correction and retest</h3>
      <DataList items={[
        { label: "Retest non-owner data access", value: "Denied" },
        { label: "Retest owner read", value: "Allowed, content unchanged" },
        { label: "Retest observed at", value: new Date(retest.observed_at).toLocaleString() },
        { label: "Control-worker cleanup", value: sentence(control.correction.owned_control_cleanup) },
        { label: "Retest native cleanup", value: sentence(retest.native_cleanup) },
        { label: "Retest owned-job cleanup", value: sentence(retest.owned_job_cleanup) },
      ]} />
    </> : <p>No successful correction and retest is recorded.</p>}
    <DataList items={[
      { label: "Verified bytes", value: baseline.size_bytes },
      { label: "Independent observation", value: "No" },
    ]} />
    <details><summary>Evidence references</summary><DataList items={[
      { label: "Resource generation", value: <code>{control.resource.resource_generation}</code> },
      { label: "Content digest", value: <code>{baseline.sha256}</code> },
      { label: "Baseline record", value: <code>{baseline.baseline_digest}</code> },
      { label: "Control binding", value: <code>{control.control_digest}</code> },
      ...(retest && control.correction ? [
        { label: "Previous DACL", value: <code>{control.correction.before_descriptor_sha256}</code> },
        { label: "Changed DACL", value: <code>{control.correction.after_descriptor_sha256}</code> },
        { label: "Retest evidence", value: <code>{retest.evidence_digest}</code> },
      ] : []),
    ]} /></details>
    {control.allowed_operations.includes("harden") && !expired ? <div className="file-access-actions"><Button disabled={disabled || !reviewAvailable} onClick={() => onReview({ operation: "harden", control_owner_id: control.control_owner_id })}><FileLock2 />Review Windows access change</Button></div> : null}
    <details><summary>Saved control operations</summary><ol className="file-access-history">{control.operations.map(job => {
      const operation = (job.progress.submitted_request as FileAccessSubmission).review.operation;
      return <li key={job.job_id}><div><Link to={fileAccessPath({ control: control.control_owner_id, operation: job.job_id })}>{operation === "baseline" ? "Baseline attempt" : "Access-change attempt"}</Link><span>{sentence(job.state)}</span></div><details><summary>Operation reference</summary><code>{job.job_id}</code></details></li>;
    })}</ol></details>
  </section>;
}
