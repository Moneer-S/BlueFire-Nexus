import { Activity, FileText, SearchCheck, ShieldCheck, TriangleAlert } from "lucide-react";
import { useId, useState } from "react";
import type { EngineArtifact, EngineAttempt, EngineEvidenceCategory } from "../lib/engine-experiment";
import { engineExperimentApi, type EngineArtifactReview } from "../lib/engine-experiment-api";
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

function ArtifactInspector({ experimentId, attempt, artifact }: { experimentId: string; attempt: EngineAttempt; artifact: EngineArtifact }) {
  const [review, setReview] = useState<EngineArtifactReview | null>(null);
  const [loading, setLoading] = useState(false);
  const [failed, setFailed] = useState(false);
  const resultId = useId();
  const inspect = async () => {
    setLoading(true);
    setFailed(false);
    setReview(null);
    try {
      setReview(await engineExperimentApi.reviewArtifact(experimentId, attempt, artifact));
    } catch {
      setFailed(true);
    } finally {
      setLoading(false);
    }
  };
  return <div className="engine-artifact-inspector">
    <button type="button" onClick={() => void inspect()} disabled={loading} aria-controls={resultId}>
      {loading ? "Checking retained source…" : review ? "Check retained source again" : "Inspect retained source"}
    </button>
    <div id={resultId} role="status" aria-live="polite">
      {loading ? <p>Checking the protected source and saved identity.</p> : failed ? <p>Source inspection is unavailable. The saved inventory alone does not verify current source bytes.</p> : review?.availability === "unavailable" ? <p>{review.reason === "reader_not_configured" ? "This service has no protected source reader. The saved inventory remains historical." : "The protected source is missing, changed, or could not be verified. The saved inventory remains historical."}</p> : review?.summary ? <div>
        <p>Protected source verified at inspection time. {review.access === "private" ? "Its body remains private; this outline contains no source words or values." : "Text is shown only for an explicitly reviewable, bounded item."}</p>
        <dl><div><dt>Format</dt><dd>{sentence(review.summary.kind)}</dd></div>
          {review.summary.line_count !== null ? <div><dt>Lines</dt><dd>{review.summary.line_count.toLocaleString()}</dd></div> : null}
          {review.summary.root ? <div><dt>JSON root</dt><dd>{review.summary.root}</dd></div> : null}
          {review.summary.field_count !== null ? <div><dt>Top-level fields</dt><dd>{review.summary.field_count.toLocaleString()}</dd></div> : null}
          {review.summary.item_count !== null ? <div><dt>Items</dt><dd>{review.summary.item_count.toLocaleString()}</dd></div> : null}
          {review.summary.recognized_fields.length ? <div><dt>Recognized sections</dt><dd>{review.summary.recognized_fields.join(", ")}</dd></div> : null}</dl>
        {review.text !== null ? <details><summary>Show verified text excerpt</summary><pre>{review.text}</pre></details> : null}
      </div> : null}
    </div>
  </div>;
}

export function EngineAttemptEvidence({ attempt, experimentId }: { attempt: EngineAttempt; experimentId?: string }) {
  const headingPrefix = useId();
  const independent = attempt.observations.filter(item => ["independent_target_effect", "independent_security_outcome", "legitimate_use"].includes(item.category));
  const toolEvents = attempt.tool_events;
  const findings = attempt.findings;
  const artifacts = attempt.artifacts;
  return <div className="engine-attempt-evidence">
    <section aria-labelledby={`${headingPrefix}-tools`}>
      <header className="engine-section-heading"><div><span>Controller-normalized</span><h3 id={`${headingPrefix}-tools`}>Tool activity</h3></div><Badge tone={toolEvents === null ? "warning" : toolEvents.length ? "info" : "neutral"}>{toolEvents === null ? "Unavailable" : toolEvents.length}</Badge></header>
      {toolEvents === null ? <div className="engine-empty-evidence is-warning"><TriangleAlert aria-hidden="true" /><div><strong>Tool execution is unverified</strong><p>This saved run has no controller-bound inventory of installed Strix tool invocations.</p></div></div> : toolEvents.length ? <ul className="engine-tool-event-list">{toolEvents.map(event => <li key={event.event_id}><Activity aria-hidden="true" /><div><strong>{event.tool_name}</strong><span>{sentence(event.state)} · <time dateTime={event.occurred_at}>{new Date(event.occurred_at).toLocaleString()}</time></span></div><Badge tone={event.state === "completed" ? "success" : event.state === "failed" ? "danger" : "warning"}>{sentence(event.state)}</Badge><details><summary>Invocation receipt</summary><dl><div><dt>Event</dt><dd><code>{event.event_id}</code></dd></div><div><dt>Receipt</dt><dd><code>{event.receipt_ref}</code></dd></div></dl></details></li>)}</ul> : <div className="engine-empty-evidence"><SearchCheck aria-hidden="true" /><div><strong>No tool invocation was recorded</strong><p>The installed runtime proof does not establish that Strix executed a tool.</p></div></div>}
    </section>

    <section aria-labelledby={`${headingPrefix}-findings`}>
      <header className="engine-section-heading"><div><span>Engine-reported</span><h3 id={`${headingPrefix}-findings`}>Findings</h3></div><Badge tone="neutral">{findings === null ? "Unavailable" : findings.length}</Badge></header>
      {findings === null ? <div className="engine-empty-evidence is-warning"><TriangleAlert aria-hidden="true" /><div><strong>Normalized findings are unavailable</strong><p>The saved attempt does not establish a finding count. Review the retained observations{attempt.artifact_manifest_ref ? " and protected source manifest" : " and saved run"} without treating this as zero findings.</p></div></div> : findings.length ? <div className="engine-finding-grid">{findings.map(finding => <Panel className="engine-finding" key={finding.finding_id}>
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
      <header className="engine-section-heading"><div><span>Retained source material</span><h3 id={`${headingPrefix}-artifacts`}>Artifacts</h3></div><Badge>{artifacts === null ? "Unavailable" : artifacts.length}</Badge></header>
      {artifacts === null ? <div className="engine-empty-evidence is-warning"><TriangleAlert aria-hidden="true" /><div><strong>Artifact inventory is unavailable</strong><p>{attempt.artifact_manifest_ref ? "A protected artifact manifest was retained, but this view does not establish its item count or contents." : "This view does not establish whether the attempt retained bounded source artifacts."}</p></div></div> : artifacts.length ? <ul className="engine-artifact-list">{artifacts.map(artifact => <li key={artifact.artifact_id}><FileText aria-hidden="true" /><div><strong>{artifact.name}</strong><span>{artifact.bytes.toLocaleString()} bytes · {artifact.media_type} · {sentence(artifact.access)}</span>{experimentId ? <ArtifactInspector key={`${attempt.attempt_id}:${artifact.artifact_id}`} experimentId={experimentId} attempt={attempt} artifact={artifact} /> : null}</div><details><summary>Identity</summary><dl><div><dt>Artifact</dt><dd><code>{artifact.artifact_id}</code></dd></div><div><dt>Digest</dt><dd><code>{artifact.sha256}</code></dd></div></dl></details></li>)}</ul> : <p className="engine-evidence-note">No bounded source artifact was recorded for this attempt.</p>}
      {attempt.artifact_manifest_ref ? <details><summary>Protected manifest identity</summary><dl><div><dt>Manifest</dt><dd><code>{attempt.artifact_manifest_ref}</code></dd></div></dl></details> : null}
      <p className="engine-evidence-note">Upstream reports and proof text are untrusted content. Source inspection rechecks protected bytes on demand; private bodies remain withheld.</p>
    </section>
  </div>;
}
