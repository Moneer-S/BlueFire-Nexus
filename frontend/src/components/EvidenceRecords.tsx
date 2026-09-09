import type { EvidenceRecord } from "../types";
import { Badge, sentence } from "./Primitives";
import "./EvidenceRecords.css";

type FileObservation = { path: string; bytes: number; digest: string; counts?: { container: string; total: number; redacted: number; retained: number; empty: number } };
const isObject = (value: unknown): value is Record<string, unknown> => Boolean(value && typeof value === "object" && !Array.isArray(value));
const count = (value: unknown): value is number => typeof value === "number" && Number.isSafeInteger(value) && value >= 0;

/** Recognize only the recorded built-in observation contracts, never action output. */
function fileObservation(record: EvidenceRecord): FileObservation | undefined {
  const content = record.content;
  if (record.provenance !== "observed" || !content) return;
  const semantics = record.producer === "collector.collection-semantics.sandbox.v1"
    && content.artifact_type === "collector_observation" && content.observation_kind === "collection_semantics";
  const metadata = (record.producer === "collector.filesystem.sandbox.v1"
    && content.artifact_type === "collector_observation" && content.observation_kind === "filesystem")
    || (record.producer === "sandbox-observer.v1" && content.artifact_type === "file_observation");
  if (!semantics && !metadata) return;
  if (typeof content.path !== "string" || !content.path || content.path.length > 1000
    || !count(content.size_bytes) || typeof content.sha256 !== "string" || !/^[0-9a-f]{64}$/.test(content.sha256)) return;
  const fields = semantics ? ["path", "size_bytes", "sha256", "container", "record_count", "redacted_record_count", "retained_record_count", "empty_record_count"] : ["path", "size_bytes", "sha256"];
  const observedFields = content.observed_fields;
  if (content.artifact_type === "collector_observation" && (!isObject(observedFields)
    || fields.some(name => observedFields[name] !== content[name]))) return;
  const result: FileObservation = { path: content.path, bytes: content.size_bytes, digest: content.sha256 };
  if (semantics) {
    const { record_count: total, redacted_record_count: redacted, retained_record_count: retained, empty_record_count: empty } = content;
    if (!count(total) || total < 1 || total > 100 || !count(redacted) || !count(retained) || !count(empty)
      || redacted + retained + empty !== total || !["jsonl", "ustar", "gzip"].includes(String(content.container))) return;
    result.counts = { container: String(content.container), total, redacted, retained, empty };
  }
  return result;
}

export function EvidenceRecords({ records }: { records: EvidenceRecord[] }) {
  return <div className="record-grid evidence-records">{records.map((record, index) => {
    const content = record.content ?? record.fields;
    const observation = fileObservation(record);
    const counts = observation?.counts;
    const summary = record.summary ?? (typeof content?.summary === "string" ? content.summary : undefined);
    const confidence = typeof record.confidence === "number" && Number.isFinite(record.confidence) && record.confidence >= 0 && record.confidence <= 1 ? `${Math.round(record.confidence * 100)}%` : "Not reported";
    return <article key={record.evidence_id ?? record.id ?? index}>
      <header><Badge tone={record.provenance === "observed" ? "success" : record.provenance === "control_blocked" ? "warning" : record.provenance === "counterfactual" ? "violet" : "info"}>{sentence(record.provenance)}</Badge><span>Step <code>{record.step_id ?? "unattributed"}</code></span></header>
      <strong className="evidence-record-title">{observation ? counts ? "Collection contents observed" : "File metadata observed" : record.kind ?? record.behavior_id ?? "Evidence record"}</strong>
      {observation ? <>
        <p>{counts ? `${counts.total} synthetic records inspected in ${counts.container === "jsonl" ? "JSONL" : counts.container === "ustar" ? "a USTAR archive" : "a gzip stream"}.` : "The observer recorded this file’s path, size and SHA-256 digest."}</p>
        <dl className="evidence-measurements"><div><dt>File</dt><dd><code>{observation.path}</code></dd></div><div><dt>Size</dt><dd>{observation.bytes.toLocaleString("en-US")} bytes</dd></div>
          {counts ? <><div><dt>Records inspected</dt><dd>{counts.total}</dd></div><div><dt>Redacted values</dt><dd>{counts.redacted}</dd></div><div><dt>Original values retained</dt><dd>{counts.retained}</dd></div><div><dt>Empty values</dt><dd>{counts.empty}</dd></div></> : null}
          <div className="evidence-digest"><dt>SHA-256</dt><dd><code>{observation.digest}</code></dd></div></dl>
        <p className="evidence-measurement-boundary">{counts ? "These are aggregate counts of the reviewed synthetic fixture values. Individual values were not retained as evidence." : "This metadata observation does not establish record counts or whether values were redacted."}</p>
        {summary ? <p>Recorded summary: {summary}</p> : null}
      </> : <p>{summary ?? "No readable summary is available for this evidence format. Open the recorded content below."}</p>}
      <div className="evidence-meta"><span>Producer <code>{record.producer ?? "Not reported"}</code></span><span>Behavior <code>{record.behavior_id ?? "Not reported"}</code></span><span>Action <code>{record.action_id ?? "None"}</code></span></div>
      <p className="evidence-confidence">Reported confidence: {confidence}. {observation ? "This score applies to the recorded observation; it does not measure detection accuracy or broader coverage." : "This is the producer’s score for this record, not a measure of detection accuracy or coverage."}</p>
      {content ? <details><summary>Show technical evidence content</summary><pre aria-label={`Evidence content ${record.evidence_id ?? record.id ?? index + 1}`}>{JSON.stringify(content, null, 2)}</pre></details> : null}
      {record.limitations?.length ? <div className="evidence-limitations"><strong>Limitations</strong><ul>{record.limitations.map((item) => <li key={item}>{item}</li>)}</ul></div> : null}
    </article>;
  })}</div>;
}
