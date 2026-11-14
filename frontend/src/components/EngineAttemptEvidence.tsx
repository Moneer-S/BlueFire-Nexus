import { Activity, FileText, SearchCheck, ShieldCheck, TriangleAlert } from "lucide-react";
import { useId } from "react";
import type { EngineAttempt, EngineEvidenceCategory } from "../lib/engine-experiment";
import { Badge, Panel, sentence } from "./Primitives";

const categoryLabel: Record<EngineEvidenceCategory, string> = {
  engine_assertion: "Engine assertion",
  tool_result: "Tool result",
  independent_target_effect: "Independent target effect",
  independent_security_outcome: "Checked security outcome",
  legitimate_use: "Legitimate-use result",
};

const categoryTone = (category: EngineEvidenceCategory): "info" | "neutral" | "violet" =>
  category === "engine_assertion" ? "violet" : category === "tool_result" ? "neutral" : "info";

export function EngineAttemptEvidence({ attempt }: { attempt: EngineAttempt }) {
  const headingPrefix = useId();
  const independent = attempt.observations.filter(item => ["independent_target_effect", "independent_security_outcome", "legitimate_use"].includes(item.category));
  return <div className="engine-attempt-evidence">
    <section aria-labelledby={`${headingPrefix}-findings`}>
      <header className="engine-section-heading"><div><span>Engine-reported</span><h3 id={`${headingPrefix}-findings`}>Findings</h3></div><Badge tone="neutral">{attempt.findings.length}</Badge></header>
      {attempt.findings.length ? <div className="engine-finding-grid">{attempt.findings.map(finding => <Panel className="engine-finding" key={finding.finding_id}>
        <header><Badge tone={finding.severity === "critical" || finding.severity === "high" ? "danger" : finding.severity === "medium" ? "warning" : "neutral"}>{sentence(finding.severity)}</Badge></header>
        <h4>{finding.title}</h4><p>{finding.summary}</p>
        <details><summary>Finding identity and mechanism</summary><dl><div><dt>Finding</dt><dd><code>{finding.finding_id}</code></dd></div><div><dt>Status</dt><dd>{sentence(finding.status)}</dd></div><div><dt>Mechanism</dt><dd><code>{finding.mechanism_digest}</code></dd></div><div><dt>Source artifact</dt><dd><code>{finding.source_artifact_id}</code></dd></div><div><dt>Linked evidence</dt><dd>{finding.evidence_ids.length ? finding.evidence_ids.map(id => <code key={id}>{id}</code>) : "None recorded"}</dd></div></dl></details>
      </Panel>)}</div> : <div className="engine-empty-evidence"><SearchCheck aria-hidden="true" /><div><strong>No finding recorded in this attempt</strong><p>{attempt.state === "completed" && attempt.completeness === "complete" ? "Review the search limits and independent observations. This does not prove the target has no remaining path." : "The attempt is incomplete or bounded. Absence of a finding is inconclusive."}</p></div></div>}
    </section>

    <section aria-labelledby={`${headingPrefix}-observations`}>
      <header className="engine-section-heading"><div><span>Evidence-backed</span><h3 id={`${headingPrefix}-observations`}>Observations</h3></div><Badge tone={independent.length ? "success" : "warning"}>{independent.length} independent</Badge></header>
      {attempt.observations.length && !independent.length ? <p className="engine-evidence-note is-warning">Target effect and security outcome remain unverified by an independent observer.</p> : null}
      {attempt.observations.length ? <div className="engine-observation-list">{attempt.observations.map(observation => <article key={observation.evidence_id}>
        <div className="engine-observation-icon" aria-hidden="true">{observation.category === "engine_assertion" ? <Activity /> : observation.category === "tool_result" ? <FileText /> : observation.category === "legitimate_use" ? <ShieldCheck /> : <SearchCheck />}</div>
        <div><header><Badge tone={categoryTone(observation.category)}>{categoryLabel[observation.category]}</Badge></header><strong>{observation.summary}</strong>
          <details><summary>Evidence identity and limits</summary><dl><div><dt>Evidence</dt><dd><code>{observation.evidence_id}</code></dd></div><div><dt>Provenance</dt><dd>{sentence(observation.provenance)}</dd></div><div><dt>Producer</dt><dd><code>{observation.producer}</code></dd></div><div><dt>Recorded</dt><dd>{new Date(observation.timestamp).toLocaleString()}</dd></div></dl>{observation.limitations.length ? <ul>{observation.limitations.map(item => <li key={item}>{item}</li>)}</ul> : <p>No additional limitation was recorded for this item.</p>}</details>
        </div>
      </article>)}</div> : <div className="engine-empty-evidence is-warning"><TriangleAlert aria-hidden="true" /><div><strong>No observation is available</strong><p>The engine report cannot establish a target effect or security outcome by itself.</p></div></div>}
    </section>

    <section aria-labelledby={`${headingPrefix}-artifacts`}>
      <header className="engine-section-heading"><div><span>Retained source material</span><h3 id={`${headingPrefix}-artifacts`}>Artifacts</h3></div><Badge>{attempt.artifacts.length}</Badge></header>
      {attempt.artifacts.length ? <ul className="engine-artifact-list">{attempt.artifacts.map(artifact => <li key={artifact.artifact_id}><FileText aria-hidden="true" /><div><strong>{artifact.name}</strong><span>{artifact.bytes.toLocaleString()} bytes · {artifact.media_type} · {sentence(artifact.access)}</span></div><details><summary>Identity</summary><dl><div><dt>Artifact</dt><dd><code>{artifact.artifact_id}</code></dd></div><div><dt>Digest</dt><dd><code>{artifact.sha256}</code></dd></div></dl></details></li>)}</ul> : <p className="engine-evidence-note">No bounded source artifact has been retained yet.</p>}
      <p className="engine-evidence-note">Upstream reports and proof text are untrusted content. BlueFire displays normalized summaries and inert artifact identity without executing imported content.</p>
    </section>
  </div>;
}
