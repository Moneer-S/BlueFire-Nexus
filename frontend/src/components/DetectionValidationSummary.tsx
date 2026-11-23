import type { DetectionResource } from "../types";
import { recordedDetectionSummary } from "../lib/detection-validation-summary";
import { Button } from "./Primitives";

export function DetectionValidationSummary({ resource, selectedId, sourceEdited, onFixtures }: {
  resource?: DetectionResource;
  selectedId: string;
  sourceEdited: boolean;
  onFixtures: () => void;
}) {
  const result = recordedDetectionSummary(resource, selectedId);
  return <section className="detection-validation-summary" aria-label="Recorded validation summary">
    <header><strong>{result.revision ? `Saved revision checks · v${result.revision}` : "Recorded checks"}</strong><Button variant="ghost" size="small" onClick={onFixtures}>Review fixtures</Button></header>
    <dl><div><dt>Parser</dt><dd>{result.parser}</dd></div><div><dt>Malicious fixtures</dt><dd>{result.malicious}</dd></div><div><dt>Benign fixtures</dt><dd>{result.benign}</dd></div></dl>
    <p>{!result.revision ? "An attributed saved revision is required for these checks." : sourceEdited ? "Saved revision only; current rule edits are not covered." : "Synthetic fixture checks, separate from recorded run evaluations."}</p>
  </section>;
}
