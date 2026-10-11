import { FileJson2 } from "lucide-react";
import { Badge, DataList, sentence } from "../components/Primitives";
import type { S3Exercise } from "../lib/s3-access";
import type { FixtureReview, FixtureState, ResourceDisposition } from "../lib/s3-fixtures";

const states: Record<FixtureState, string> = { not_prepared: "Not prepared", owned: "Verified present", partial: "Mixed object state", uncertain: "Needs reconciliation", drift: "Changed externally", absent: "Verified absent" };
export const resourceNames: Record<ResourceDisposition, string> = { not_prepared: "Not prepared", retained: "Retained", cleanup_required: "Needs reconciliation", removed: "Removed" };

export function S3Fixtures({ value }: { value: S3Exercise }) {
  if (value.schema_version !== "bluefire.s3-exercise.v2" || !value.fixtures || !value.fixture_state) return null;
  return <section className="s3-band" aria-label="Generated test objects">
    <div className="s3-operation-heading"><h2>Test objects</h2><Badge tone={["partial", "uncertain", "drift"].includes(value.fixture_state) ? "warning" : "neutral"}>{states[value.fixture_state]}</Badge></div>
    <div className="s3-fixture-list">{value.fixtures.map(row => <article key={row.purpose}>
      <FileJson2 aria-hidden="true" size={20} />
      <div><h3>{row.purpose === "primary" ? "Sample records" : "Legitimate-use canary"}</h3><p className="s3-object-key">{row.key}</p><span>{row.size_bytes.toLocaleString()} bytes</span></div>
      <div className="s3-fixture-status"><strong>{states[row.state]}</strong><small>{row.provenance === "synthetic" ? "Synthetic observation" : row.provenance === "runner_reported" ? "Runner reported" : "Not observed"}</small></div>
    </article>)}</div>
    {value.policy_retention ? <div className="s3-policy-retention"><strong>Policy retained</strong><span>{sentence(value.policy_retention.policy_state)} at the accepted cleanup review</span></div> : null}
  </section>;
}

export function S3FixtureReview({ value, cleanup }: { value: FixtureReview; cleanup: boolean }) {
  return <div aria-label="Test object review">
    <DataList items={[{ label: "Policy", value: `${sentence(value.policy_state)}; retained` }, { label: "Objects", value: value.objects.length }]} />
    {cleanup ? <p>Only these test objects will be removed. The current policy is retained.</p> : null}
    {value.objects.map(row => <details key={row.purpose}>
      <summary>{row.purpose === "primary" ? "Sample records" : "Legitimate-use canary"} · {row.size_bytes.toLocaleString()} bytes</summary>
      <p className="s3-object-key">{row.key}</p><pre>{row.payload_preview}</pre>
    </details>)}
  </div>;
}
