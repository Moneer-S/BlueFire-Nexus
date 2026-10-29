import { ChevronDown, ChevronUp, Files, RefreshCw } from "lucide-react";
import { useEffect, useId, useRef, useState } from "react";
import { Link } from "react-router-dom";
import type { CompositionObjective } from "../lib/composition";
import { compositionKnowledgeApi, type CompositionFinding, type CompositionKnowledge } from "../lib/composition-knowledge";
import { Button, DataList, ErrorState, formatDate, sentence } from "./Primitives";
import "./CompositionKnowledge.css";

const findingTitles: Record<CompositionFinding["semantic_kind"], string> = {
  observed_filesystem: "File observation",
  observed_collection: "Collected content",
  observed_process_snapshot: "Process snapshot",
  observed_receiver_binding: "Receiver observation",
  runner_result: "Action result",
  evidence_gap: "Observation gap",
  record_metadata: "Recorded evidence",
};
const sourceLabels: Record<CompositionFinding["provenance"], string> = {
  observed: "Observed", executed: "Runner-reported", synthetic: "Simulation",
  control_blocked: "Product refusal", counterfactual: "Counterfactual", unknown: "Unclassified source",
};
const displayValue = (value: string | number | boolean) => typeof value === "boolean" ? value ? "Yes" : "No" : String(value);
const summaryPriority = ["runner_status", "reported_outcome", "reported_reader", "permission_mode_octal", "reported_mode", "mode", "record_count", "reported_record_count", "size_bytes", "bytes_received", "container", "effective_access", "permission_status", "process_id", "parent_process_id", "platform", "receiver_process_id"];
const fieldPriority = (key: string) => { const priority = summaryPriority.indexOf(key); return priority < 0 ? summaryPriority.length : priority; };

function Finding({ finding }: { finding: CompositionFinding }) {
  const fields = Object.entries(finding.summary).sort(([left], [right]) => fieldPriority(left) - fieldPriority(right));
  return <li className="composition-finding">
    <div className="composition-finding-heading"><h5>{findingTitles[finding.semantic_kind]}</h5><span>{sourceLabels[finding.provenance]}</span></div>
    <p className="composition-finding-time">Step {finding.step_id} · {formatDate(finding.observed_at)}</p>
    {fields.length ? <DataList items={fields.slice(0, 4).map(([label, value]) => ({ label: sentence(label), value: displayValue(value) }))} />
      : <p className="composition-knowledge-muted">The source record has no summary fields.</p>}
    <details className="composition-finding-source"><summary>{fields.length > 4 ? `Source details and ${fields.length - 4} more fields` : "Source details"}</summary>
      {fields.length > 4 ? <DataList items={fields.slice(4).map(([label, value]) => ({ label: sentence(label), value: displayValue(value) }))} /> : null}
      <DataList items={[
        { label: "Method", value: <code>{finding.behavior_id}</code> },
        ...(finding.action_id ? [{ label: "Action", value: <code>{finding.action_id}</code> }] : []),
        { label: "Finding", value: <code>{finding.finding_id}</code> },
        { label: "Evidence", value: <code>{finding.evidence_id}</code> },
        { label: "Objective", value: <code>{finding.record_ref.owner_id}</code> },
        { label: "Attempt", value: <code>{finding.record_ref.attempt_id}</code> },
        { label: "Execution job", value: <code>{finding.record_ref.job_id}</code> },
        { label: "Run", value: <code>{finding.record_ref.run_id}</code> },
        { label: "Content digest", value: <code>{finding.content_hash}</code> },
        { label: "Record digest", value: <code>{finding.record_hash}</code> },
        { label: "Source binding", value: <code>{finding.record_ref.source_binding_digest}</code> },
        { label: "Applicability", value: "Historical finding; current resource state has not been checked." },
      ]} />
    </details>
  </li>;
}

type ReadState = { status: "idle" } | { status: "loading" } | { status: "error"; error: unknown } | { status: "ready"; data: CompositionKnowledge; binding: string };

function KnowledgeWorkspace({ objective }: { objective: CompositionObjective }) {
  const contentId = useId();
  const requestGeneration = useRef(0);
  const [open, setOpen] = useState(false);
  const [selection, setSelection] = useState(() => objective.attempts.slice(-8).map(attempt => attempt.request.composition_attempt.attempt_id));
  const [read, setRead] = useState<ReadState>({ status: "idle" });
  useEffect(() => () => { requestGeneration.current += 1; }, []);
  const available = new Map(objective.attempts.map((attempt, index) => [attempt.request.composition_attempt.attempt_id, { attempt, number: index + 1 }]));
  const selected = selection.filter(id => available.has(id));
  const currentBinding = JSON.stringify(objective.attempts.map(attempt => [attempt.request.composition_attempt.attempt_id, attempt.job_id, attempt.request.composition_attempt.run_id]));
  const loaded = read.status === "ready" && read.binding === currentBinding ? read.data : undefined;
  const load = async () => {
    if (!selected.length || selected.length > 8) return;
    const generation = ++requestGeneration.current;
    const binding = currentBinding;
    setRead({ status: "loading" });
    try {
      const data = await compositionKnowledgeApi.read(objective, selected);
      if (requestGeneration.current === generation) setRead({ status: "ready", data, binding });
    } catch (error) {
      if (requestGeneration.current === generation) setRead({ status: "error", error });
    }
  };
  const toggle = () => {
    if (open) { requestGeneration.current += 1; setRead({ status: "idle" }); }
    else void load();
    setOpen(!open);
  };
  const changeSelection = (id: string, checked: boolean) => {
    requestGeneration.current += 1;
    setRead({ status: "idle" });
    setSelection(previous => checked ? [...previous.filter(item => available.has(item)), id] : previous.filter(item => item !== id));
  };
  return <div className={`composition-knowledge${open ? " is-open" : ""}`}>
    <Button size="small" variant="ghost" onClick={toggle} aria-expanded={open} aria-controls={contentId} disabled={!objective.attempts.length}>
      <Files aria-hidden="true" />{open ? "Hide findings" : "Findings across attempts"}{open ? <ChevronUp aria-hidden="true" /> : <ChevronDown aria-hidden="true" />}
    </Button>
    {open ? <section id={contentId} aria-label="Findings across attempts" className="composition-knowledge-content">
      <header className="composition-knowledge-heading"><div><h3>Findings across attempts</h3><p>Useful records remain available even when an approach did not succeed. Recheck mutable resources before relying on their current state.</p></div><span className="composition-knowledge-history">Recorded history</span></header>
      <div className="composition-knowledge-controls">
        <details className="composition-knowledge-picker"><summary>Choose attempts <span>{selected.length} selected</span></summary>
          <fieldset><legend>Choose up to eight attempts to inspect together</legend><div className="composition-knowledge-options">{objective.attempts.map((attempt, index) => {
            const id = attempt.request.composition_attempt.attempt_id;
            return <label key={id}><input type="checkbox" checked={selected.includes(id)} disabled={!selected.includes(id) && selected.length >= 8} onChange={event => changeSelection(id, event.target.checked)} /><span>Attempt {index + 1}<small>{sentence(attempt.state)}</small></span></label>;
          })}</div></fieldset>
        </details>
        <Button size="small" disabled={!selected.length || read.status === "loading"} onClick={() => { void load(); }}><RefreshCw aria-hidden="true" />{loaded ? "Refresh findings" : "Load selected findings"}</Button>
      </div>
      {read.status === "loading" ? <p role="status" className="composition-knowledge-muted">Opening recorded findings…</p> : null}
      {read.status === "error" ? <ErrorState title="Saved findings unavailable" error={read.error} retry={() => { void load(); }} /> : null}
      {read.status === "idle" || read.status === "ready" && !loaded ? <p className="composition-knowledge-muted">{selected.length ? "Load the selected attempts to inspect their findings together." : "Choose at least one attempt."}</p> : null}
      {loaded ? <div className="composition-knowledge-results">{loaded.attempts.map(attempt => <section key={attempt.attempt_id} className="composition-knowledge-attempt" aria-label={`Findings from attempt ${available.get(attempt.attempt_id)?.number}`}>
        <header><div><h4>Attempt {available.get(attempt.attempt_id)?.number}</h4><span>{sentence(attempt.run_status ?? attempt.job_state)}</span></div>{attempt.source_status === "verified" ? <Link to={`/runs/${encodeURIComponent(attempt.run_id)}`}>Open source run</Link> : null}</header>
        {attempt.source_status === "unavailable" ? <div className="composition-knowledge-unavailable"><p>Saved source could not be verified. The original attempt remains in history.</p><details><summary>Source status</summary><p>{sentence(attempt.problem ?? "Source unavailable")}</p><code>{attempt.run_id}</code></details></div>
          : attempt.findings.length ? <ul className="composition-findings">{attempt.findings.map(finding => <Finding key={finding.finding_id} finding={finding} />)}</ul>
            : <p className="composition-knowledge-muted">This finalized attempt has no summarized findings.</p>}
        {attempt.findings_truncated ? <p className="composition-knowledge-muted">Showing {attempt.findings.length} of {attempt.findings_total} findings. Open the source run for all records.</p> : null}
      </section>)}<details className="composition-knowledge-identity"><summary>Snapshot identity</summary><code>{loaded.knowledge_digest}</code></details></div> : null}
    </section> : null}
  </div>;
}

export function CompositionKnowledge({ objective }: { objective: CompositionObjective }) {
  return <KnowledgeWorkspace key={objective.owner.job_id} objective={objective} />;
}
