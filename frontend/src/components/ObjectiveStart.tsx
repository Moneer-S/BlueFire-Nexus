import { ArrowRight } from "lucide-react";
import { Link, useSearchParams } from "react-router-dom";
import { Badge, Button, DataList, Field } from "./Primitives";
import "./ObjectiveStart.css";

const objectives = [
  {
    id: "data-handoff", label: "Controlled data handoff", to: "/compare?receiver=1",
    question: "Can a redaction requirement stop unredacted records while allowing legitimate redacted use?",
    environment: "Prepared Linux lab and authenticated receiver",
    data: "Generated records and redacted variants",
    change: "Retained receiver redaction policy",
  },
  {
    id: "file-access", label: "Excess file access", to: "/file-access",
    question: "Can we remove a test identity's file access while preserving the application's access?",
    environment: "Enrolled Linux session with a dedicated non-owner test identity",
    data: "Generated application file",
    change: "File permission correction",
  },
  {
    id: "ad-access", label: "Excess domain access", to: "/ad-smb",
    question: "Can we remove the probe identity's share access while preserving legitimate domain reads?",
    environment: "Enrolled Windows domain, member, client and protected credential channel",
    data: "Generated primary and health files on a disposable share",
    change: "Scoped share permission correction",
  },
  {
    id: "s3-access", label: "Excess S3 access", to: "/s3-access",
    question: "Can we remove the probe role's S3 access while preserving legitimate reads?",
    environment: "Authorized AWS account, region, bucket and dedicated test roles",
    data: "Generated primary and health objects",
    change: "Scoped bucket-policy correction",
  },
] as const;

export function ObjectiveStart() {
  const [params, setParams] = useSearchParams();
  const requested = params.get("goal");
  const selected = objectives.find(item => item.id === requested);
  const choose = (value: string) => setParams(previous => {
    const next = new URLSearchParams(previous);
    if (value) next.set("goal", value);
    else next.delete("goal");
    return next;
  }, { replace: true });

  return <section className="objective-start" aria-labelledby="objective-start-title">
    <div className="objective-start-choice">
      <h2 id="objective-start-title">Choose an objective</h2>
      <Field label="Objective">
        <select value={selected?.id ?? ""} onChange={event => choose(event.target.value)}>
          <option value="">Select a question</option>
          {objectives.map(item => <option key={item.id} value={item.id}>{item.label}</option>)}
        </select>
      </Field>
      {requested && !selected ? <p role="alert">This objective is unavailable. Select a supported question.</p> : null}
      {selected ? <Link className="button button-primary button-medium" to={selected.to}>Review environment <ArrowRight aria-hidden="true" /></Link> : <Button variant="primary" disabled>Review environment <ArrowRight aria-hidden="true" /></Button>}
    </div>
    {selected ? <div className="objective-start-scope" aria-live="polite">
      <h3>{selected.question}</h3>
      <DataList items={[
        { label: "Environment", value: selected.environment },
        { label: "Test data", value: selected.data },
        { label: "Defensive change", value: selected.change },
        { label: "Access", value: <Badge tone="warning">Not checked</Badge> },
      ]} />
    </div> : null}
  </section>;
}
